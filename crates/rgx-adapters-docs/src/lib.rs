// SPDX-License-Identifier: Apache-2.0

//! Long-tail adapters: external tools only.
//!
//! The external-tool adapters delegate to binaries already on the machine
//! (soffice, tesseract). Each detects its binary on PATH in `available()`;
//! when the tool is missing the adapter is skipped entirely, so a minimal
//! machine still gets the full in-process adapter set. Nothing here is
//! spawned unless a matching file is actually found.
//!
//! A third tool is used the same way but not for the claim: poppler's
//! `pdftoppm` rasterises a page that carries no picture of its own, so a
//! PDF whose content is *drawn* can be handed to the OCR tool as a page
//! instead of being left without one. It is asked for only when there is
//! nothing else to hand over, and its absence is named in the answer
//! rather than hidden.

use rgx_core::Adapter;
#[cfg(any(feature = "soffice", feature = "ocr"))]
use rgx_core::{bail, Context, Outcome, Result};
#[cfg(any(feature = "soffice", feature = "ocr"))]
use std::io::Read;
#[cfg(feature = "ocr")]
use std::io::Write;
#[cfg(any(feature = "soffice", feature = "ocr"))]
use std::process::{Command, Stdio};
#[cfg(any(feature = "soffice", feature = "ocr"))]
use std::sync::{mpsc, Arc, Mutex};
#[cfg(any(feature = "soffice", feature = "ocr"))]
use std::thread;
#[cfg(any(feature = "soffice", feature = "ocr"))]
use std::time::{Duration, Instant};

/// Wall-clock limit on a single tool invocation. Soffice can spend tens
/// of seconds on a multi-hundred-page document; tesseract normally
/// finishes in one or two, but a hostile image can spin forever. Thirty
/// seconds is enough headroom for both while still bounding the user.
#[cfg(any(feature = "soffice", feature = "ocr"))]
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub fn adapters() -> Vec<Box<dyn Adapter>> {
    vec![
        #[cfg(feature = "soffice")]
        Box::new(Soffice),
        #[cfg(feature = "ocr")]
        Box::new(ocr()),
    ]
}

/// Adapter that pipes bytes to a tool's stdin and captures stdout.
#[cfg(feature = "ocr")]
pub struct ProcAdapter {
    name: &'static str,
    /// candidate binary names, first hit on PATH wins
    binaries: &'static [&'static str],
    /// argv built from the original path (informational — data goes via stdin)
    args: fn(&str) -> Vec<String>,
    exts: &'static [&'static str],
    /// optional post-processing of captured stdout
    post: fn(Vec<u8>) -> Vec<u8>,
    /// Turn one input into the inputs the tool can actually read.
    ///
    /// `None` means the bytes go over as they are. `Some(v)` means run the
    /// tool once per element and join the answers. It exists for one reason:
    /// a tool that reads images cannot read a PDF, and a scanned PDF *is* a
    /// set of images, so what is worth handing over is the pages and not the
    /// container.
    ///
    /// The second argument is the tool that rasterises a page, when the
    /// machine has one: a page that carries no picture of its own has to be
    /// rendered before an OCR engine can read it.
    preprocess: fn(&[u8], Option<&str>) -> Option<Prepared>,
    /// wall-clock budget per invocation; a run that exceeds it is killed
    timeout: Duration,
    /// The tool that rasterises a page, when the machine has one.
    ///
    /// It is not part of the claim: the adapter is there when the OCR tool
    /// is, and a document that carries a page image of its own never needs
    /// the other one.
    rasteriser: Option<&'static str>,
}

/// What a [`ProcAdapter::preprocess`] hook produced.
#[cfg(feature = "ocr")]
pub struct Prepared {
    /// The payloads the tool will be run on, one invocation each.
    pub inputs: Vec<Vec<u8>>,
    /// What was found and *not* turned into an input, with the reason. A
    /// scan stored as CCITT G4 is content the file has and this reader
    /// cannot render; naming it is the difference between a user knowing
    /// why and a user wondering.
    pub skipped: Vec<String>,
    /// What the answer has to say about itself.
    ///
    /// A page the file carries and the adapter cannot hand over is a fact
    /// about the file, and a fact that is not written down reads like
    /// silence: this is where "the rasteriser is not installed" and "the
    /// rasteriser refused the file" are said out loud.
    pub notes: Vec<String>,
}

#[cfg(any(feature = "soffice", feature = "ocr"))]
fn which(binary: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    // The PATH does not change during a run: probe each candidate binary
    // once. Without this cache, `available()` costs ~20 filesystem stats
    // per adapter per file — that dominated whole-corpus searches.
    static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(&hit) = cache.lock().unwrap().get(binary) {
        return hit;
    }
    let found = which_uncached(binary);
    cache.lock().unwrap().insert(binary.to_string(), found);
    found
}

#[cfg(any(feature = "soffice", feature = "ocr"))]
fn which_uncached(binary: &str) -> bool {
    // explicit path separators → check directly
    if binary.contains('/') || binary.contains('\\') {
        return std::path::Path::new(binary).exists();
    }
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| {
        // `mut` is exercised only by the Windows extension probing below;
        // on any other target it is a warning on every build.
        #[cfg_attr(not(windows), allow(unused_mut))]
        let mut p = dir.join(binary);
        if p.is_file() {
            return true;
        }
        // Windows: also try .exe / .bat / .cmd
        #[cfg(windows)]
        {
            for ext in ["exe", "bat", "cmd", "ps1"] {
                p.set_extension(ext);
                if p.is_file() {
                    return true;
                }
            }
        }
        false
    })
}

#[cfg(any(feature = "soffice", feature = "ocr"))]
fn temp_path() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "rgx-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    p
}

/// Drains the child's stdout and stderr on background threads, waits for
/// it to exit on a third, and kills it if `timeout` elapses first. The
/// drainers are necessary: leaving the pipes unread would let a child
/// block on a full pipe buffer and never reach `wait()`.
#[cfg(any(feature = "soffice", feature = "ocr"))]
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let child = Arc::new(Mutex::new(Some(child)));

    fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> Option<thread::JoinHandle<Vec<u8>>> {
        pipe.map(|mut s| {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf);
                buf
            })
        })
    }
    let stdout_handle = drain(stdout);
    let stderr_handle = drain(stderr);

    let (tx, rx) = mpsc::channel::<std::io::Result<std::process::ExitStatus>>();
    let child_w = Arc::clone(&child);
    let waiter = thread::spawn(move || {
        let result = {
            let mut guard = child_w.lock().unwrap();
            match guard.as_mut() {
                Some(c) => c.wait(),
                None => Err(std::io::Error::other("child vanished")),
            }
        };
        let _ = tx.send(result);
    });

    let start = Instant::now();
    let poll = Duration::from_millis(100);
    let status = loop {
        match rx.recv_timeout(poll) {
            Ok(Ok(s)) => break Ok(s),
            Ok(Err(e)) => break Err(e),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if start.elapsed() >= timeout {
                    if let Some(c) = child.lock().unwrap().as_mut() {
                        let _ = c.kill();
                    }
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("process exceeded {}s timeout", timeout.as_secs()),
                    ));
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err(std::io::Error::other("waiter disconnected"));
            }
        }
    };

    let _ = waiter.join();
    let stdout = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stderr = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();

    Ok(std::process::Output {
        status: status?,
        stdout,
        stderr,
    })
}

#[cfg(feature = "ocr")]
impl Adapter for ProcAdapter {
    fn name(&self) -> &'static str {
        self.name
    }

    fn extensions(&self) -> &'static [&'static str] {
        self.exts
    }

    fn available(&self) -> bool {
        self.binaries.iter().any(|b| which(b))
    }

    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        let binary = self
            .binaries
            .iter()
            .copied()
            .find(|b| which(b))
            .context("binary vanished between detection and spawn")?;
        let argv: Vec<String> = (self.args)(path);

        let split = (self.preprocess)(data, self.rasteriser);
        if let Some(ref p) = split {
            if p.inputs.is_empty() {
                let mut why = Vec::new();
                if !p.skipped.is_empty() {
                    why.push(format!(
                        "{} page image(s) not renderable: {}",
                        p.skipped.len(),
                        p.skipped.join(", ")
                    ));
                }
                why.extend(p.notes.iter().cloned());
                let why = if why.is_empty() {
                    "no page image in it".to_string()
                } else {
                    why.join("; ")
                };
                bail!("{binary} was handed nothing: {why}");
            }
        }
        let payloads: Vec<&[u8]> = match split {
            Some(ref p) => p.inputs.iter().map(|x| x.as_slice()).collect(),
            None => vec![data],
        };

        let mut stdout = Vec::new();
        for payload in payloads {
            let mut cmd = Command::new(binary);
            cmd.args(&argv)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => return Err(e).context("spawn failed"),
            };
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(payload);
            }
            let out = match wait_with_timeout(child, self.timeout) {
                Ok(o) => o,
                Err(e) => return Err(e).context("wait failed"),
            };
            if !out.status.success() || out.stdout.is_empty() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let stderr = stderr.trim();
                if stderr.is_empty() {
                    bail!("{} exited with {}", binary, out.status);
                }
                bail!(
                    "{} exited with {}: {}",
                    binary,
                    out.status,
                    stderr.lines().next().unwrap_or("")
                );
            }
            if stdout.last() != Some(&b'\n') && !stdout.is_empty() {
                stdout.push(b'\n');
            }
            stdout.extend_from_slice(&out.stdout);
        }

        let mut stdout = (self.post)(stdout);
        // The reasons the pages were not all handed over are part of the
        // answer: a page that was not rasterised is a fact about the file,
        // and a fact that is not written down reads like silence.
        let notes: Vec<String> = split.as_ref().map(|p| p.notes.clone()).unwrap_or_default();
        if stdout.is_empty() {
            if notes.is_empty() {
                bail!("{} produced no text", binary);
            }
            bail!("{} produced no text: {}", binary, notes.join("; "));
        }
        for note in &notes {
            if stdout.last() != Some(&b'\n') {
                stdout.push(b'\n');
            }
            stdout.extend_from_slice(b"[rgx: ocr: ");
            stdout.extend_from_slice(note.as_bytes());
            stdout.extend_from_slice(b"]\n");
        }
        Ok(Outcome::Text(stdout))
    }
}

#[cfg(feature = "ocr")]
const IDENTITY: fn(Vec<u8>) -> Vec<u8> = |b| b;

// ffmpeg/ffprobe used to cover avi/ts/mpg/mpeg/wmv/flv here; the media
// crate's in-process adapters own all of them now (avi/asf/flv/mpeg
// readers), and .srt is plain text for raw search —
// so the external adapter is gone.

// legacy .doc used to live here (antiword); the office crate's in-process
// FIB + piece-table reader owns .doc now, so the external adapter is gone.

/// LibreOffice headless (fallback for formats nothing else reads well).
/// Custom `Adapter` impl: soffice converts *to a file* in --outdir rather
/// than stdout, so we point it at a scratch dir and read the flat ODF back.
#[cfg(feature = "soffice")]
pub struct Soffice;
#[cfg(feature = "soffice")]
impl Adapter for Soffice {
    fn name(&self) -> &'static str {
        "soffice"
    }
    fn extensions(&self) -> &'static [&'static str] {
        // the whole legacy-office surface is in-process now (office crate:
        // ppt/pptx/xls/xlsx/ods/odp + binary Visio .vsd); what remains for
        // soffice is the one format nothing else reads: MS Publisher (.pub)
        &["pub"]
    }
    fn available(&self) -> bool {
        which("soffice") || which("libreoffice")
    }
    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        let binary = if which("soffice") {
            "soffice"
        } else {
            "libreoffice"
        };
        let ext = rgx_core::extension_of(path);
        let src = temp_path();
        let src = src.with_extension(&*ext);
        let outdir = temp_path();
        std::fs::create_dir_all(&outdir)?;
        std::fs::write(&src, data)?;
        // Flat ODF, not `txt:Text`. LibreOffice imports MS Publisher as a
        // *Draw* document, and Draw ships no text export filter, so the txt
        // target aborted with "no export filter ... found" before writing a
        // byte -- this adapter claimed `pub` and could never return text for
        // the one extension it owns. `fodg` is the Draw export that is plain
        // XML, and the office crate already owns the XML → text pass over it.
        let out_flat = outdir.join(src.with_extension("fodg").file_name().unwrap());
        let mut cmd = Command::new(binary);
        cmd.args([
            "--headless".into(),
            "--convert-to".into(),
            "fodg".into(),
            "--outdir".into(),
            outdir.to_string_lossy().into_owned(),
            src.to_string_lossy().into_owned(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        let child = cmd.spawn().context("spawn soffice")?;
        let output = wait_with_timeout(child, DEFAULT_TIMEOUT).context("wait soffice")?;
        let status = output.status;
        let _ = std::fs::remove_file(&src);
        let flat = std::fs::read(&out_flat).unwrap_or_default();
        let _ = std::fs::remove_file(&out_flat);
        let _ = std::fs::remove_dir(&outdir);
        if !status.success() || flat.is_empty() {
            bail!("soffice exited with {status}");
        }
        let text = rgx_adapters_office::xml_to_text(&flat).into_bytes();
        if text.is_empty() {
            bail!("soffice wrote a flat ODF with no readable text");
        }
        Ok(Outcome::Text(text))
    }
}

/// OCR for scanned documents. Claims `*.ocr.*` double extensions only, so an
/// ordinary photo never triggers a run — and the dotted declaration is what
/// makes the second component reachable at all: `extension_candidates` offers
/// `scan.ocr.jpg` as `ocr.jpg` first and `jpg` second, so this runs before the
/// media adapter that claims the `jpg` alone.
#[cfg(feature = "ocr")]
pub fn ocr() -> ProcAdapter {
    ProcAdapter {
        name: "ocr",
        binaries: &["tesseract"],
        args: |_| vec!["stdin".into(), "stdout".into(), "--psm".into(), "3".into()],
        exts: &[
            "ocr.jpg", "ocr.jpeg", "ocr.png", "ocr.tiff", "ocr.tif", "ocr.pdf",
        ],
        post: IDENTITY,
        preprocess: pages_of_a_pdf,
        timeout: DEFAULT_TIMEOUT,
        rasteriser: rasteriser(),
    }
}

/// The tools that can rasterise a page, in the order they are tried.
///
/// `pdftoppm` and `pdftocairo` are poppler's two page renderers, and both
/// write one PNG per page, numbered after the page: `prefix-1.png` is the
/// first page. The first one on PATH wins, the same rule the OCR tool
/// itself follows.
#[cfg(feature = "ocr")]
const RASTERISERS: &[&str] = &["pdftoppm", "pdftocairo"];

/// The resolution the pages are rasterised at, in DPI.
///
/// 300 is the resolution tesseract's own documentation asks for, and the
/// one a scanned page usually carries; poppler's own default is 150, which
/// halves the height of the glyphs and costs accuracy.
#[cfg(feature = "ocr")]
const RASTER_DPI: u32 = 300;

/// Wall-clock limit on one rasterisation.
///
/// The whole document is one invocation, and a hundred pages at 300 dpi is
/// not a one-second job. The OCR that follows costs more than this, so the
/// limit is here to bound a file that never ends rather than to be tight.
#[cfg(feature = "ocr")]
const RASTER_TIMEOUT: Duration = Duration::from_secs(120);

/// The first rasteriser on PATH, if the machine has one.
#[cfg(feature = "ocr")]
fn rasteriser() -> Option<&'static str> {
    RASTERISERS.iter().copied().find(|b| which(b))
}

/// A scanned PDF's pages, when the input is a PDF.
///
/// tesseract reads images and refuses a PDF with `Pdf reading is not
/// supported` unless its build was made with PDF support -- a property of
/// that build, not of this file. So a PDF that claims `ocr.pdf` is opened
/// here and its page images handed over instead, which makes the claim
/// work on any tesseract.
///
/// A page becomes an input when it can be turned into an image the tool can
/// read: a `/DCTDecode` page hands over the JPEG its stored bytes already
/// are, and a `/CCITTFaxDecode` or `/JBIG2Decode` page hands over a PNG this
/// crate built from the decoded scan. Anything else is reported by its filter
/// rather than passed along to fail the same way a second time.
///
/// A page that carries no picture at all -- a page whose content is
/// *drawn* -- has nothing to hand over, and then the page is rasterised by
/// an external tool (`pdftoppm`, or `pdftocairo`), which is the only way to
/// put ink on it. The tool is asked for only when there is nothing else to
/// hand over, and when the machine has none the answer says so rather than
/// pretending the page was rendered.
#[cfg(feature = "ocr")]
fn pages_of_a_pdf(data: &[u8], rasteriser: Option<&str>) -> Option<Prepared> {
    if !data.starts_with(b"%PDF-") {
        return None;
    }
    let mut inputs = Vec::new();
    let mut skipped = Vec::new();
    for img in rgx_adapters_pdf::all_page_images(data) {
        if let Some(bytes) = img.jpeg {
            inputs.push(bytes);
        } else if let Some(bytes) = img.png {
            inputs.push(bytes);
        } else {
            skipped.push(if img.filter.is_empty() {
                format!("{}x{} with no filter", img.width, img.height)
            } else {
                format!("{}x{} {}", img.width, img.height, img.filter)
            });
        }
    }
    let mut notes = Vec::new();
    if inputs.is_empty() {
        // The document has no page image this adapter can hand over. The
        // page is still a page, so it is rasterised -- and when the machine
        // has no rasteriser, the answer says that instead of leaving the
        // user with a file that cannot be read.
        let what = if skipped.is_empty() {
            "the document carries no page image".to_string()
        } else {
            format!(
                "no page image of the document could be handed over ({})",
                skipped.join(", ")
            )
        };
        match rasteriser {
            None => notes.push(format!(
                "{what}, and no rasteriser ({}) is on PATH, so its pages were not rasterised",
                RASTERISERS.join(" or ")
            )),
            Some(binary) => {
                let (pages, failure) = rasterise_in(data, binary, &temp_path());
                if pages.is_empty() {
                    let reason =
                        failure.unwrap_or_else(|| format!("{binary} rasterised no page of it"));
                    notes.push(format!(
                        "{what}, and its pages could not be rasterised with {binary}: {reason}"
                    ));
                } else {
                    notes.push(format!(
                        "{what}, so {} page(s) of it were rasterised with {binary} at {RASTER_DPI} dpi",
                        pages.len()
                    ));
                    if let Some(reason) = failure {
                        notes.push(format!("the rasteriser did not finish: {reason}"));
                    }
                    inputs = pages;
                }
            }
        }
    }
    Some(Prepared {
        inputs,
        skipped,
        notes,
    })
}

/// The pages of a PDF, rasterised by an external tool.
///
/// The tools write files and not stdout, so the PDF goes into `workdir` as
/// a file, the tool writes one PNG per page beside it, and each PNG is read
/// back and removed. `workdir` itself is removed before this returns: the
/// pages are handed to a subprocess and thrown away.
///
/// The second half of the answer is the reason: `None` when the tool was
/// happy, and the tool's own message when it was not. A file the rasteriser
/// cannot open is reported, never skipped.
#[cfg(feature = "ocr")]
fn rasterise_in(
    data: &[u8],
    binary: &str,
    workdir: &std::path::Path,
) -> (Vec<Vec<u8>>, Option<String>) {
    let src = workdir.join("input.pdf");
    let prefix = workdir.join("page");
    if let Err(e) = std::fs::create_dir_all(workdir) {
        return (
            Vec::new(),
            Some(format!("{binary} had no directory to write into: {e}")),
        );
    }
    if let Err(e) = std::fs::write(&src, data) {
        let _ = std::fs::remove_dir_all(workdir);
        return (
            Vec::new(),
            Some(format!("the PDF could not be written for {binary}: {e}")),
        );
    }
    let mut cmd = Command::new(binary);
    cmd.args([
        "-png".to_string(),
        "-r".to_string(),
        RASTER_DPI.to_string(),
        src.to_string_lossy().into_owned(),
        prefix.to_string_lossy().into_owned(),
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_dir_all(workdir);
            return (
                Vec::new(),
                Some(format!("{binary} could not be started: {e}")),
            );
        }
    };
    let out = match wait_with_timeout(child, RASTER_TIMEOUT) {
        Ok(o) => o,
        Err(e) => {
            let _ = std::fs::remove_dir_all(workdir);
            return (Vec::new(), Some(format!("{binary} did not finish: {e}")));
        }
    };
    let pages = read_rasterised_pages(workdir);
    let _ = std::fs::remove_dir_all(workdir);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let line = stderr
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("");
        let reason = if line.is_empty() {
            format!("{binary} exited with {}", out.status)
        } else {
            format!("{binary} exited with {}: {line}", out.status)
        };
        return (pages, Some(reason));
    }
    (pages, None)
}

/// The PNGs a rasteriser wrote, in page order.
///
/// The tools number their output after the page (`page-1.png`), so the
/// number in the name is the page the file holds. Each file is read and
/// removed as it is read: the pages are handed to a subprocess and thrown
/// away.
#[cfg(feature = "ocr")]
fn read_rasterised_pages(workdir: &std::path::Path) -> Vec<Vec<u8>> {
    let Ok(entries) = std::fs::read_dir(workdir) else {
        return Vec::new();
    };
    let mut pages: Vec<(u32, Vec<u8>)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(page) = page_of(name) else {
            continue;
        };
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        let _ = std::fs::remove_file(entry.path());
        pages.push((page, bytes));
    }
    pages.sort_by_key(|(page, _)| *page);
    pages.into_iter().map(|(_, bytes)| bytes).collect()
}

/// The page a rasteriser's output file holds, from its name.
///
/// `page-7.png` is the seventh page. A name that does not say that is not
/// a page this reader can place, so it is left out.
#[cfg(feature = "ocr")]
fn page_of(name: &str) -> Option<u32> {
    let number = name.strip_prefix("page-")?.strip_suffix(".png")?;
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    number.parse().ok()
}

// openssl x509 used to live here (pem/crt/cer/der/cert); the inspect
// crate's in-process DER/PEM walker (reduced port of upstream x509) owns
// certificates now, so the external adapter is gone.

// catdoc's xls2csv used to cover legacy .xls; the office crate's
// in-process BIFF reader owns it now, so the external adapter is gone.

// exiftool used to cover gif/bmp images here; the media crate's
// in-process imgmeta adapters own them
// now, so the external adapter is gone.

#[cfg(all(test, any(feature = "soffice", feature = "ocr")))]
mod tests {
    use super::*;

    #[test]
    fn which_finds_something() {
        // every machine has at least one of these; smoke test of PATH scanning
        let found = ["sh", "cmd.exe", "ffmpeg"].iter().any(|b| which(b));
        assert!(found, "PATH scan should find at least one shell");
    }

    #[test]
    fn wait_with_timeout_kills_a_hung_child() {
        // A shell that sleeps past the deadline: wait_with_timeout must
        // return a TimedOut error and never block past the deadline
        // (a loose 30s cap is plenty of headroom for OS process cleanup;
        // the win is going from "infinite" to "bounded").
        let shell = if cfg!(windows) { "cmd.exe" } else { "sh" };
        let arg = if cfg!(windows) { "/c" } else { "-c" };
        let mut cmd = Command::new(shell);
        cmd.args([
            arg,
            if cfg!(windows) {
                "ping -n 5 127.0.0.1 > nul"
            } else {
                "sleep 5"
            },
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let child = cmd.spawn().expect("shell should spawn");
        let start = std::time::Instant::now();
        let out = wait_with_timeout(child, Duration::from_millis(500)).unwrap_err();
        let elapsed = start.elapsed();
        assert_eq!(out.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            elapsed < Duration::from_secs(30),
            "wait_with_timeout must not block past 30s, took {elapsed:?}"
        );
    }

    #[test]
    fn wait_with_timeout_returns_a_clean_result_for_a_normal_child() {
        let shell = if cfg!(windows) { "cmd.exe" } else { "sh" };
        let arg = if cfg!(windows) { "/c" } else { "-c" };
        let mut cmd = Command::new(shell);
        cmd.args([arg, "echo hi"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = cmd.spawn().expect("shell should spawn");
        let out = wait_with_timeout(child, Duration::from_secs(5)).unwrap();
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("hi"));
    }

    /// A PDF whose pages are *drawn*: vectors and text, and no image
    /// XObject anywhere.
    ///
    /// This is the case the rasteriser exists for -- a page with no
    /// picture of its own has nothing to hand to an OCR engine. The file
    /// is written here rather than borrowed from a fixture, so what the
    /// reader sees is what this test put in it.
    #[cfg(feature = "ocr")]
    fn drawn_pdf(pages: usize) -> Vec<u8> {
        let mut objs: Vec<Vec<u8>> = Vec::new();
        objs.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
        let kids: Vec<String> = (0..pages).map(|i| format!("{} 0 R", 3 + 2 * i)).collect();
        objs.push(
            format!(
                "<< /Type /Pages /Kids [{}] /Count {pages} >>",
                kids.join(" ")
            )
            .into_bytes(),
        );
        for i in 0..pages {
            objs.push(
                format!(
                    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
                     /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 \
                     /BaseFont /Helvetica >> >> >> /Contents {} 0 R >>",
                    4 + 2 * i
                )
                .into_bytes(),
            );
            let content = format!(
                "1 0 0 RG 4 w 50 50 m 562 742 l S\n\
                 BT /F1 48 Tf 72 600 Td (PAGE {}) Tj ET\n",
                i + 1
            );
            objs.push(
                format!("<< /Length {} >>\nstream\n", content.len())
                    .into_bytes()
                    .into_iter()
                    .chain(content.as_bytes().iter().copied())
                    .chain(b"\nendstream".iter().copied())
                    .collect(),
            );
        }

        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, body) in objs.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref = out.len();
        out.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes(),
        );
        for off in &offsets {
            out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objs.len() + 1
            )
            .as_bytes(),
        );
        out
    }

    /// A one-page PDF whose page draws one image stored as a JPEG.
    ///
    /// The bytes are not a real JPEG: what matters is that the reader
    /// hands over the *stored* image and does not rasterise the page.
    #[cfg(feature = "ocr")]
    fn pdf_with_a_jpeg_page() -> Vec<u8> {
        let jpeg = [0xffu8, 0xd8, b'R', b'G', b'X', 0xff, 0xd9];
        let mut image = format!(
            "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 \
             /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /DCTDecode \
             /Length {} >>\nstream\n",
            jpeg.len()
        )
        .into_bytes();
        image.extend_from_slice(&jpeg);
        image.extend_from_slice(b"\nendstream");

        let content = b"q 612 0 0 792 0 0 cm /Im0 Do Q";

        let objs: Vec<Vec<u8>> = vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
              /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>"
                .to_vec(),
            image,
            format!("<< /Length {} >>\nstream\n", content.len())
                .into_bytes()
                .into_iter()
                .chain(content.iter().copied())
                .chain(b"\nendstream".iter().copied())
                .collect(),
        ];

        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, body) in objs.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref = out.len();
        out.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes(),
        );
        for off in &offsets {
            out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objs.len() + 1
            )
            .as_bytes(),
        );
        out
    }

    /// The size a PNG declares, in pixels.
    ///
    /// The IHDR chunk carries it: the width at byte 16 and the height at
    /// byte 20, both big-endian.
    #[cfg(feature = "ocr")]
    fn png_size(png: &[u8]) -> (u32, u32) {
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "not a PNG");
        (
            u32::from_be_bytes([png[16], png[17], png[18], png[19]]),
            u32::from_be_bytes([png[20], png[21], png[22], png[23]]),
        )
    }

    /// One page of a PDF, rendered by the tool itself.
    ///
    /// This is the oracle: the same tool, the same options, the same
    /// page -- so the bytes can be compared with the ones the adapter
    /// holds for that page.
    #[cfg(feature = "ocr")]
    fn render_one_page(pdf: &[u8], binary: &str, page: u32) -> Vec<u8> {
        let dir = temp_path();
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let src = dir.join("input.pdf");
        std::fs::write(&src, pdf).expect("the PDF is written");
        let out = dir.join("page");
        let status = Command::new(binary)
            .args([
                "-png".to_string(),
                "-r".to_string(),
                RASTER_DPI.to_string(),
                "-f".to_string(),
                page.to_string(),
                "-l".to_string(),
                page.to_string(),
                "-singlefile".to_string(),
            ])
            .arg(&src)
            .arg(&out)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("the tool runs");
        assert!(status.success(), "{binary} rendered page {page}");
        let bytes = std::fs::read(dir.join("page.png")).expect("the tool wrote the page");
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }

    /// The argv a tool is run with.
    #[cfg(feature = "ocr")]
    type ToolArgs = fn(&str) -> Vec<String>;

    /// The OCR adapter with a tool that stands in for tesseract.
    ///
    /// It answers with one line, which is enough to read the adapter's
    /// own plumbing on a machine with no OCR engine installed.
    #[cfg(feature = "ocr")]
    fn echo_adapter(tool: Option<&'static str>) -> ProcAdapter {
        #[cfg(windows)]
        let (binaries, args): (&'static [&'static str], ToolArgs) = (&["cmd.exe"], |_| {
            vec!["/c".into(), "echo".into(), "page".into()]
        });
        #[cfg(not(windows))]
        let (binaries, args): (&'static [&'static str], ToolArgs) =
            (&["sh"], |_| vec!["-c".into(), "echo page".into()]);
        ProcAdapter {
            name: "ocr",
            binaries,
            args,
            exts: &["ocr.pdf"],
            post: IDENTITY,
            preprocess: pages_of_a_pdf,
            timeout: DEFAULT_TIMEOUT,
            rasteriser: tool,
        }
    }

    /// A drawn page is rasterised, and the page that comes out is the
    /// page that was asked for.
    ///
    /// The oracle is the tool itself: the same page rendered on its own
    /// has to be the same bytes, and a letter page at 300 dpi is 2550 by
    /// 3300 pixels.
    #[cfg(feature = "ocr")]
    #[test]
    fn a_drawn_page_is_rasterised_into_the_page_it_is() {
        let Some(binary) = rasteriser() else {
            // The tool is not installed. A test that needs it must not
            // fail over it, and there is nothing to compare against.
            eprintln!("no rasteriser on PATH: the rasteriser is not exercised here");
            return;
        };
        let pdf = drawn_pdf(2);
        let prepared = pages_of_a_pdf(&pdf, Some(binary)).expect("a PDF");
        assert!(
            prepared.skipped.is_empty(),
            "a drawn page carries no image to skip: {:?}",
            prepared.skipped
        );
        assert_eq!(
            prepared.inputs.len(),
            2,
            "one page per page of the document"
        );
        for page in &prepared.inputs {
            assert_eq!(&page[..8], b"\x89PNG\r\n\x1a\n", "the tool writes a PNG");
            assert_eq!(
                png_size(page),
                (2550, 3300),
                "a letter page at {RASTER_DPI} dpi"
            );
        }
        assert_ne!(
            prepared.inputs[0], prepared.inputs[1],
            "the two pages are not the same picture"
        );
        assert_eq!(
            prepared.inputs[1],
            render_one_page(&pdf, binary, 2),
            "the second page is the second page"
        );
        assert!(
            prepared.notes.iter().any(|n| n.contains("rasterised")),
            "the answer says what it did: {:?}",
            prepared.notes
        );
    }

    /// A machine without a rasteriser says the page was not rasterised.
    ///
    /// The tool is absent, and the answer has to say so: a page that was
    /// not rendered must not read as a page that was.
    #[cfg(feature = "ocr")]
    #[test]
    fn a_machine_without_a_rasteriser_says_the_page_was_not_rasterised() {
        let pdf = drawn_pdf(1);
        let prepared = pages_of_a_pdf(&pdf, None).expect("a PDF");
        assert!(prepared.inputs.is_empty(), "there is no page to hand over");
        assert_eq!(
            prepared.notes.len(),
            1,
            "the answer says why: {:?}",
            prepared.notes
        );
        let note = &prepared.notes[0];
        assert!(note.contains("no page image"), "{note}");
        assert!(note.contains("not rasterised"), "{note}");
        assert!(
            note.contains("pdftoppm"),
            "the note names the tool that is missing: {note}"
        );
    }

    /// A rasteriser that cannot be started is reported, not passed over.
    ///
    /// The binary named here does not exist, which is the state a
    /// machine with a broken installation is in.
    #[cfg(feature = "ocr")]
    #[test]
    fn a_rasteriser_that_cannot_be_started_is_reported() {
        let pdf = drawn_pdf(1);
        let prepared = pages_of_a_pdf(&pdf, Some("rgx-no-such-rasteriser")).expect("a PDF");
        assert!(prepared.inputs.is_empty(), "no page came back");
        assert_eq!(
            prepared.notes.len(),
            1,
            "the answer says why: {:?}",
            prepared.notes
        );
        assert!(
            prepared.notes[0].contains("could not be started"),
            "{:?}",
            prepared.notes
        );
    }

    /// A page with a picture of its own is handed over as it is, and
    /// nothing is rasterised.
    ///
    /// The rasteriser is asked for only when there is nothing else to
    /// hand over, and this is the test that says so: the tool named here
    /// would fail if it ran, and the page still comes back.
    #[cfg(feature = "ocr")]
    #[test]
    fn a_stored_page_image_is_handed_over_unchanged() {
        let pdf = pdf_with_a_jpeg_page();
        let prepared = pages_of_a_pdf(&pdf, Some("rgx-no-such-rasteriser")).expect("a PDF");
        assert_eq!(prepared.inputs.len(), 1, "the stored image is handed over");
        assert_eq!(
            &prepared.inputs[0][..2],
            &[0xff, 0xd8],
            "the stored JPEG, as it is"
        );
        assert!(
            prepared.notes.is_empty(),
            "nothing was rasterised, so nothing is said: {:?}",
            prepared.notes
        );
    }

    /// The rasteriser leaves nothing behind.
    ///
    /// The pages are handed to a subprocess and thrown away, so the
    /// directory that held them is gone when the call returns.
    #[cfg(feature = "ocr")]
    #[test]
    fn the_rasteriser_leaves_nothing_behind() {
        let Some(binary) = rasteriser() else {
            eprintln!("no rasteriser on PATH: the rasteriser is not exercised here");
            return;
        };
        let dir = temp_path();
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let work = dir.join("work");
        let (pages, failure) = rasterise_in(&drawn_pdf(1), binary, &work);
        assert!(failure.is_none(), "{failure:?}");
        assert_eq!(pages.len(), 1, "one page of one document");
        assert!(
            !work.exists(),
            "the working directory is gone: {:?}",
            std::fs::read_dir(&dir).map(|d| d.count())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file the rasteriser cannot open is reported, not skipped.
    #[cfg(feature = "ocr")]
    #[test]
    fn a_file_the_rasteriser_cannot_open_is_reported() {
        let Some(binary) = rasteriser() else {
            eprintln!("no rasteriser on PATH: the rasteriser is not exercised here");
            return;
        };
        let prepared = pages_of_a_pdf(b"%PDF-1.4", Some(binary)).expect("a PDF");
        assert!(prepared.inputs.is_empty(), "no page came back");
        assert_eq!(
            prepared.notes.len(),
            1,
            "the answer says why: {:?}",
            prepared.notes
        );
        assert!(
            prepared.notes[0].contains("could not be rasterised"),
            "{:?}",
            prepared.notes
        );
    }

    /// The answer says that the page was not rasterised.
    ///
    /// The tool here is not an OCR engine but stands in for one, so the
    /// adapter's own plumbing can be read on a machine with no tesseract.
    #[cfg(feature = "ocr")]
    #[test]
    fn the_answer_says_that_the_page_was_not_rasterised() {
        let adapter = echo_adapter(None);
        let err = match adapter.extract(&drawn_pdf(1), "scan.ocr.pdf") {
            Ok(_) => panic!("nothing was handed over, so there is no answer"),
            Err(e) => e,
        };
        let message = format!("{err:#}");
        assert!(message.contains("no page image"), "{message}");
        assert!(message.contains("not rasterised"), "{message}");
    }

    /// The answer says that the page was rasterised.
    #[cfg(feature = "ocr")]
    #[test]
    fn the_answer_says_that_the_page_was_rasterised() {
        let Some(binary) = rasteriser() else {
            eprintln!("no rasteriser on PATH: the rasteriser is not exercised here");
            return;
        };
        let adapter = echo_adapter(Some(binary));
        let Outcome::Text(text) = adapter
            .extract(&drawn_pdf(1), "scan.ocr.pdf")
            .expect("the tool answers")
        else {
            panic!("the answer is text");
        };
        let text = String::from_utf8_lossy(&text);
        assert!(
            text.contains("[rgx: ocr:"),
            "the note is in the answer: {text}"
        );
        assert!(text.contains("rasterised with pdftoppm"), "{text}");
    }
}
