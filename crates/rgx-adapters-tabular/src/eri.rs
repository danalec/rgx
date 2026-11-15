// SPDX-License-Identifier: Apache-2.0

//! Everything-Rs Index (`.eri`) — an NTFS path index rendered as one
//! path per line.
//!
//! **What this is not.** It is not a query engine and it does not open
//! a volume. An `.eri` is a flat table of
//! `(frn, parent, name, path, size, attrs)` records produced by
//! `everything-rs save <volume> <file>`, which reads the MFT once
//! with Administrator rights. This adapter only decodes those bytes,
//! so it runs unprivileged, on any platform, and needs no NTFS.
//!
//! ## Streaming walk, not the writer's own reader
//!
//! The producer materialises six `HashMap`s keyed by FRN so it can
//! resolve parents into paths. A consumer of the text does not need
//! any of that: the format stores the resolved path on every record,
//! already built. This walks the record stream once, copies the
//! `path` bytes straight into the output buffer and skips
//! everything else, so peak memory is the output itself rather than
//! the output plus a hash table per record. On a 4 TB volume that
//! is the difference between a few hundred megabytes and several
//! gigabytes.
//!
//! ## Line framing
//!
//! One path per `\n`. This is safe because NTFS forbids control bytes in
//! filenames: a name containing `\n` cannot come from a real volume, so a
//! record that carries one is a corrupt file rather than a path to print. Those
//! are refused rather than sanitised — see [`scan`].
//!
//! ## Why a control byte is refused rather than escaped
//!
//! `Outcome::Text` hands back one `Vec<u8>` whose `Found::via`
//! labels it as binary for the searcher's `BinaryDetection::Quit`
//! rule. `Quit` reports *nothing at all* once a NUL appears in the
//! first 64 KiB — not the lines before it, none of them — so a
//! single stray NUL would drop every path in the file out of `-c`,
//! `-l` and the exit status while printing nothing to explain it.
//! Escaping would hide the corruption; refusing surfaces it.
//! Refusing also keeps `\n` out of the output, which is what makes
//! the one-path-per-line framing above mean anything.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use rgx_core::{bail, decline, Result};
use rgx_core::{Adapter, Outcome};

const ERI_MAGIC: &[u8; 4] = b"ERI1";
const ERI_VERSION: u32 = 1;

/// Bytes of fixed-width fields preceding each record's `name_len`.
const REC_FIXED: usize = 8 + 8 + 8 + 4 + 1;

/// Ceiling on the rendered output. `Outcome::Text` hands back one `Vec<u8>`, so
/// a whole-volume index is materialised in full — 5.15 M paths is roughly 300 MB
/// of text. The budget is a refusal, not a truncation: a silently shortened path
/// list is indistinguishable from a complete one, and a caller that cannot tell
/// those apart is worse off than one that is told no.
const MAX_OUT: usize = 256 << 20;

pub struct Eri;

impl Adapter for Eri {
    fn name(&self) -> &'static str {
        "eri"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["eri"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(scan(data)?))
    }
}

/// Bounds-checked LE reads. These bail rather than panic: the input is a file
/// whose length is attacker-controlled, and an adapter that panics takes the
/// search down with it.
fn u16le(d: &[u8], o: usize) -> Result<u16> {
    match d.get(o..o + 2) {
        Some(b) => Ok(u16::from_le_bytes([b[0], b[1]])),
        None => bail!(
            "eri: truncated at offset {o} (wanted 2 bytes, {} left)",
            d.len().saturating_sub(o)
        ),
    }
}

fn u32le(d: &[u8], o: usize) -> Result<u32> {
    match d.get(o..o + 4) {
        Some(b) => Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        None => bail!(
            "eri: truncated at offset {o} (wanted 4 bytes, {} left)",
            d.len().saturating_sub(o)
        ),
    }
}

fn u64le(d: &[u8], o: usize) -> Result<u64> {
    match d.get(o..o + 8) {
        Some(b) => Ok(u64::from_le_bytes(b.try_into().unwrap())),
        None => bail!(
            "eri: truncated at offset {o} (wanted 8 bytes, {} left)",
            d.len().saturating_sub(o)
        ),
    }
}

fn take(d: &[u8], o: usize, n: usize) -> Result<&[u8]> {
    match d.get(o..o + n) {
        Some(b) => Ok(b),
        None => bail!(
            "eri: truncated at offset {o} (wanted {n} bytes, {} left)",
            d.len().saturating_sub(o)
        ),
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Emit `s` as one line, escaping any byte that would corrupt the framing or
/// trip the binary heuristic. Returns `false` once the output budget is spent,
/// which stops the record walk rather than failing it.
///
/// This escapes rather than refusing, and the reason is a measured failure.
/// Refusing was the first implementation — `bail!` on a control byte — and at
/// the CLI it produces **total silence**. `bail!` arrives at `process` as `Err`,
/// which falls back to the file's own bytes; those bytes are the binary `.eri`,
/// `RgxBinaryDetection::Quit(0)` sees a NUL immediately, and `Quit` reports
/// nothing at all — not the lines before it. The user gets exit 1 and no
/// output, with the adapter's own explanation discarded along the way. A
/// corrupt index that matches nothing and says nothing is worse than a wrong
/// one, because nothing about it looks wrong.
///
/// Escaping keeps the output printable, keeps `\n` from forging a second line,
/// and leaves the corruption *visible* as `\x00` inside a path that is visibly
/// not a real one — which is the whole signal the reader needs.
fn push_path(out: &mut Vec<u8>, path: &[u8], cap: usize) -> bool {
    if out.len().saturating_add(path.len()).saturating_add(5) > cap {
        return false;
    }
    for &b in path {
        if b < 0x20 || b == 0x7F {
            out.extend_from_slice(b"\\x");
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0F) as usize]);
        } else {
            out.push(b);
        }
    }
    out.push(b'\n');
    true
}

fn scan(data: &[u8]) -> Result<Vec<u8>> {
    scan_capped(data, MAX_OUT)
}

/// `cap` is a parameter only so the truncation branch is reachable from a test;
/// production always passes [`MAX_OUT`].
fn scan_capped(data: &[u8], cap: usize) -> Result<Vec<u8>> {
    if data.len() < 4 || &data[0..4] != ERI_MAGIC {
        decline!("not an ERI index (bad magic)");
    }
    let version = u32le(data, 4)?;
    if version != ERI_VERSION {
        bail!("unsupported ERI version {version} (this build reads {ERI_VERSION})");
    }

    let root_len = u16le(data, 8)? as usize;
    let root = take(data, 10, root_len)?;
    let mut out = Vec::with_capacity(root_len + 1024);
    push_path(&mut out, root, cap);

    let mut p = 10 + root_len;
    let count = u64le(data, p)?;
    p += 8;

    // The count is read from the file, so it bounds nothing on its own. The
    // reserve is clamped for the same reason the tabular readers clamp theirs:
    // a 21-byte file claiming four billion records must not ask for gigabytes
    // up front, it must fail on the first read that runs off the end.
    out.reserve((count as usize).min(1 << 20).saturating_mul(48));

    let mut truncated_at: Option<u64> = None;
    for i in 0..count {
        p += REC_FIXED;
        let name_len = u16le(data, p)? as usize;
        p += 2;
        p += name_len;
        let path_len = u16le(data, p)? as usize;
        p += 2;
        let path = take(data, p, path_len)?;
        if !push_path(&mut out, path, cap) {
            truncated_at = Some(i);
            break;
        }
        p += path_len;
    }

    // An incomplete list is only honest if it says so. This is the difference
    // from the `bail!` version: the caller still gets its paths, and the last
    // line names what is missing rather than leaving the reader to assume the
    // index was small.
    if let Some(i) = truncated_at {
        let notice = String::from("\n[rgx: eri: stopped after ");
        out.extend_from_slice(notice.as_bytes());
        out.extend_from_slice(i.to_string().as_bytes());
        out.extend_from_slice(
            format!(
                " of {count} paths — {cap}-byte budget reached; this list is \
                 INCOMPLETE, index a subtree not a whole volume]\n"
            )
            .as_bytes(),
        );
    }
    Ok(out)
}

/// Build an `.eri` byte image from `(name, path_bytes)` pairs, for tests. The
/// path argument is raw bytes rather than `&str` so a case can plant a NUL or a
/// newline in one and see what the adapter does with it.
#[cfg(test)]
fn fixture(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(ERI_MAGIC);
    b.extend_from_slice(&ERI_VERSION.to_le_bytes());
    let root = b"C:\\";
    b.extend_from_slice(&(root.len() as u16).to_le_bytes());
    b.extend_from_slice(root);
    b.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (name, path) in entries {
        b.extend_from_slice(&100u64.to_le_bytes()); // frn
        b.extend_from_slice(&5u64.to_le_bytes()); // parent_frn
        b.extend_from_slice(&42u64.to_le_bytes()); // size
        b.extend_from_slice(&0x20u32.to_le_bytes()); // attrs
        b.push(0); // is_dir
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        b.extend_from_slice(&(path.len() as u16).to_le_bytes());
        b.extend_from_slice(path);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};

    fn render(data: &[u8]) -> String {
        let out = Eri.extract(data, "x.eri").unwrap();
        let Outcome::Text(t) = out else {
            panic!("expected Text")
        };
        String::from_utf8(t).expect("utf8")
    }

    /// `Outcome` is not `Debug`, so `expect_err` is unavailable; match instead.
    fn err_of(data: &[u8]) -> String {
        match Eri.extract(data, "x.eri") {
            Ok(_) => panic!("expected an error, rendered successfully"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn every_record_becomes_one_line_with_the_root_first() {
        let s = render(&fixture(&[
            ("notes.txt", b"C:\\Users\\dana\\notes.txt"),
            ("a.rs", b"C:\\src\\a.rs"),
        ]));
        assert_eq!(
            s, "C:\\\nC:\\Users\\dana\\notes.txt\nC:\\src\\a.rs\n",
            "got {s:?}"
        );
    }

    #[test]
    fn an_empty_index_renders_just_the_root() {
        assert_eq!(render(&fixture(&[])), "C:\\\n");
    }

    #[test]
    fn a_bad_magic_is_declined_not_answered() {
        let mut d = fixture(&[("a", b"C:\\a")]);
        d[0] = b'X';
        assert!(err_of(&d).contains("magic"));
    }

    #[test]
    fn a_future_version_is_named_rather_than_guessed_at() {
        let mut d = fixture(&[("a", b"C:\\a")]);
        d[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(err_of(&d).contains("99"));
    }

    #[test]
    fn a_truncated_record_is_an_error_not_a_partial_list() {
        let d = fixture(&[("notes.txt", b"C:\\Users\\dana\\notes.txt")]);
        for cut in [11, 20, 40, d.len() - 1] {
            assert!(
                Eri.extract(&d[..cut], "x.eri").is_err(),
                "a file cut at {cut} rendered instead of failing"
            );
        }
    }

    #[test]
    fn a_record_count_larger_than_the_file_cannot_preallocate_its_way_out() {
        // The header's count is attacker-controlled. A 21-byte file claiming
        // four billion records must fail on the read that runs off the end, not
        // abort the process reserving gigabytes first.
        let mut d = fixture(&[]);
        let n = d.len();
        d[n - 8..n].copy_from_slice(&4_000_000_000u64.to_le_bytes());
        assert!(Eri.extract(&d, "x.eri").is_err());
    }

    #[test]
    fn a_nul_in_a_path_is_escaped_because_refusing_it_is_silent() {
        // The measured failure that decided this. `bail!` here fell back to the
        // file's own binary bytes, `Quit(0)` hit the NUL on the first byte, and
        // the CLI printed *nothing* with exit 1 — the adapter's own error
        // message discarded. Escaping keeps the output printable and leaves
        // the corruption visible instead of invisible.
        let mut d = fixture(&[("a", b"C:\\src\\needle")]);
        let n = d.len();
        d[n - 1] = 0x00;
        let s = render(&d);
        assert_eq!(s, "C:\\\nC:\\src\\needl\\x00\n", "got {s:?}");
        assert!(!s.contains('\0'), "no raw NUL may reach the output");
    }

    #[test]
    fn an_embedded_newline_is_escaped_so_framing_cannot_be_forged() {
        // One path per line is only sound because no path can contain \n. A
        // record carrying one would split into two paths that do not exist.
        let mut d = fixture(&[("a", b"C:\\src\\a")]);
        let n = d.len();
        d[n - 4] = b'\n';
        let s = render(&d);
        assert_eq!(s.lines().count(), 2, "one root plus one path: {s:?}");
        assert!(s.contains("\\x0a"), "got {s:?}");
    }

    #[test]
    fn a_budget_stop_truncates_with_a_notice_instead_of_failing() {
        // The other half of the same lesson: a refusal here would also fall back
        // to raw binary search and read as "no match". An incomplete list that
        // names itself incomplete is the honest outcome.
        let d = fixture(&[
            ("a", b"C:\\src\\alpha.rs"),
            ("b", b"C:\\src\\beta.rs"),
            ("c", b"C:\\src\\gamma.rs"),
        ]);
        // Room for the root and one path, not three.
        let out = scan_capped(&d, 24).expect("truncation is not a parse error");
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("alpha.rs"), "got {s:?}");
        assert!(!s.contains("gamma.rs"), "got {s:?}");
        assert!(
            s.contains("INCOMPLETE"),
            "the notice must be present: {s:?}"
        );
        assert!(
            s.contains("of 3 paths"),
            "the notice must name the total: {s:?}"
        );
    }

    #[test]
    fn non_ascii_paths_survive_intact() {
        let s = render(&fixture(&[(
            "a.txt",
            "C:\\Users\\dana\\\u{6587}\u{6863}\u{6587}\\caf\u{e9}.txt".as_bytes(),
        )]));
        assert_eq!(
            s, "C:\\\nC:\\Users\\dana\\\u{6587}\u{6863}\u{6587}\\caf\u{e9}.txt\n",
            "got {s:?}"
        );
    }

    #[cfg(feature = "std")]
    mod fuzz {
        use super::*;

        #[test]
        fn eri_never_panics_on_arbitrary_bytes() {
            let good = fixture(&[
                ("notes.txt", b"C:\\Users\\dana\\notes.txt"),
                ("a.rs", b"C:\\src\\a.rs"),
            ]);
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("valid", good),
                    ("magic-only", b"ERI1".to_vec()),
                    ("magic+version", b"ERI1\x01\x00\x00\x00".to_vec()),
                    ("empty", vec![]),
                    ("nul-in-path", {
                        let mut d = fixture(&[("a", b"C:\\a")]);
                        let n = d.len();
                        d[n - 4] = 0;
                        d
                    }),
                ],
                2000,
                "eri",
                |data| {
                    let _ = Eri.extract(data, "fuzz.eri");
                },
            );
        }
    }
}
