// SPDX-License-Identifier: Apache-2.0

//! The plotter drawing, the graphics metafile and the two bilevel rasters,
//! checked against the real binary.
//!
//! **What this pins.** For each format, three things at once: the adapter
//! that must answer for it, a pattern the *rendering* carries and the file
//! does not, and a pattern the file's own bytes carry. Two halves of one
//! claim, and the second half is the half that can rot silently.
//!
//! **Two different reaches, one test.** The plotter drawing is text, so it
//! is **rendered**: under the default `Policy::Source` the adapter is not
//! consulted at all and the file is searched as it lies on disk, and the
//! default run must report `"adapter":"raw"` and find the raw pattern — rgx
//! stays a superset of ripgrep on it. The metafile and the two rasters are
//! binary, so they are **revealed**: there the adapter *is* the answer, and
//! the default run reports the adapter's name. The test carries the reach
//! in the case, because the two halves are different claims.
//!
//! **Why a binary and not the adapters.** The adapters are unit-tested where
//! they live. This test asks the question the user asks: run `rgx` over a
//! file of this format and tell me what comes back. The answer has to
//! survive the registry, the policy, the walk and the output layer, and
//! only the binary knows all four.
//!
//! **The fixtures are real files** in the crate's `testdata` directory, not
//! builders here: they are the same files the adapters' own tests use, so a
//! fixture that rots breaks in both places at once.

use std::path::PathBuf;
use std::process::Command;

mod common;

/// How an adapter answers for its format.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// The file is text: the rendering is a second view, asked for
    /// explicitly, and the file's own bytes stay the default answer.
    Render,
    /// The file is binary: the adapter's answer *is* the answer.
    Reveal,
}

/// One format: the file that stands for it, the adapter that must answer
/// for it, the reach, and the patterns the two views carry.
struct Case {
    /// What the format is called in the README's table.
    format: &'static str,
    /// The fixture, relative to the repository root.
    fixture: &'static str,
    /// The adapter that must answer for the file.
    adapter: &'static str,
    /// How the adapter answers.
    reach: Reach,
    /// A pattern the rendering carries and the file does not — the entity
    /// and its values on one line, which is the whole point of the format.
    rendered: &'static str,
    /// A pattern the file's own bytes carry, when it carries one. A binary
    /// file need not carry any text at all, and then this is `None`.
    raw: Option<&'static str>,
}

const CASES: &[Case] = &[
    Case {
        format: "PLT (HP-GL)",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.plt",
        adapter: "plt",
        reach: Reach::Render,
        rendered: "polyline (0,11181) (230,11507)",
        raw: Some("PA0,11181"),
    },
    Case {
        format: "CGM",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.cgm",
        adapter: "cgm",
        reach: Reach::Reveal,
        rendered: "polyline: (100,100) (200,200) (300,50)",
        raw: Some("ProfileId:WebCGM"),
    },
    Case {
        format: "CALS Raster",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.cal",
        adapter: "cals",
        reach: Reach::Reveal,
        rendered: "cals: type 1, 1728x2200 pels at 200 dpi",
        raw: Some("srcdocid"),
    },
    Case {
        format: "JEDMICS C4",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.c4",
        adapter: "edmics-c4",
        reach: Reach::Reveal,
        rendered: "c4: 1728x2200 pixels (216 bytes wide), 200 dpi, 20 tiles",
        // A C4 file is a header of numbers and a G4 raster: there is no
        // text in it to find.
        raw: None,
    },
];

/// The repository root: the directory the manifest sits in.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn scratch_dir() -> PathBuf {
    common::scratch("graphics-test")
}

/// The adapter that answered, read out of the machine-readable output.
///
/// The JSON stream names the adapter on every match, which is the only
/// place that says *who* answered rather than *what* was found.
fn adapter_of(json: &str) -> Option<String> {
    for line in json.lines() {
        if let Some(rest) = line.split_once("\"adapter\":\"") {
            let (name, _) = rest.1.split_once('"')?;
            return Some(name.to_string());
        }
    }
    None
}

/// Run rgx over one file with one pattern, under one policy, and return the
/// machine-readable output.
///
/// `view` is `None` for the default policy: the ambient environment is not
/// this test's to inherit, or a `RGX_ADAPTER_VIEW=render` run in the
/// developer's shell would assert the wrong policy.
fn run(view: Option<&str>, pattern: &str, file: &std::path::Path) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rgx"));
    // The needles are literal strings, not patterns: a rendering carries
    // parentheses, and a regex would read them as a group.
    cmd.args(["--json", "--no-heading", "--fixed-strings", pattern])
        .arg(file);
    match view {
        Some(v) => cmd.env("RGX_ADAPTER_VIEW", v),
        None => cmd.env_remove("RGX_ADAPTER_VIEW"),
    };
    let out = cmd.output().expect("failed to spawn rgx");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The bytes of a file, and whether they carry a pattern.
///
/// The check is on the bytes, not on the text: a binary fixture is not
/// valid UTF-8, and reading it as a string would make the check vacuous
/// exactly where it matters most.
fn bytes_carry(path: &std::path::Path, needle: &str) -> bool {
    let bytes = std::fs::read(path).unwrap();
    let needle = needle.as_bytes();
    !needle.is_empty() && bytes.windows(needle.len()).any(|w| w == needle)
}

/// The default view of a text drawing is the file's own bytes.
///
/// The adapter is not consulted under `Policy::Source`, so the file is
/// searched raw and the answer is ripgrep's answer. This is the half of the
/// claim that keeps rgx a superset, and it is the half a rendering adapter
/// can break without failing anything.
#[test]
fn the_default_view_of_a_text_drawing_is_its_own_bytes() {
    let dir = scratch_dir();
    let root = repo_root();
    let mut failures = Vec::new();

    for case in CASES.iter().filter(|c| c.reach == Reach::Render) {
        let src = root.join(case.fixture);
        assert!(
            src.exists(),
            "{}: the fixture {} is missing",
            case.format,
            case.fixture
        );
        let dst = dir.join(src.file_name().unwrap());
        std::fs::copy(&src, &dst).unwrap();

        let raw = case.raw.expect("a text format carries a raw pattern");
        let stdout = run(None, raw, &dst);
        match adapter_of(&stdout) {
            Some(adapter) if adapter == "raw" => {
                if !stdout.contains(raw) {
                    failures.push(format!(
                        "{}: the raw view did not find {:?}",
                        case.format, raw
                    ));
                }
            }
            Some(adapter) => failures.push(format!(
                "{}: the default view was answered by '{}', expected 'raw'",
                case.format, adapter
            )),
            None => failures.push(format!(
                "{}: the default view found nothing ({:?})",
                case.format, raw
            )),
        }
    }

    std::fs::remove_dir_all(&dir).ok();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The rendering is reachable, and it holds what the file cannot hold.
///
/// The pattern is one the *file* does not contain: the entity's name beside
/// its values, on one line, where the file has them apart. If the rendering
/// answered but did not carry it, the adapter would be a rendering for
/// nothing.
#[test]
fn the_rendering_of_a_text_drawing_holds_what_the_file_cannot() {
    let dir = scratch_dir();
    let root = repo_root();
    let mut failures = Vec::new();

    for case in CASES.iter().filter(|c| c.reach == Reach::Render) {
        let src = root.join(case.fixture);
        let dst = dir.join(src.file_name().unwrap());
        std::fs::copy(&src, &dst).unwrap();

        // The file itself must not carry the pattern: if it did, the
        // rendering would be proving nothing.
        if bytes_carry(&dst, case.rendered) {
            failures.push(format!(
                "{}: the file carries {:?}, so the rendering proves nothing",
                case.format, case.rendered
            ));
        }

        let stdout = run(Some("render"), case.rendered, &dst);
        match adapter_of(&stdout) {
            Some(adapter) if adapter == case.adapter => {
                if !stdout.contains(case.rendered) {
                    failures.push(format!(
                        "{}: the adapter '{}' answered but the answer does not carry {:?}",
                        case.format, adapter, case.rendered
                    ));
                }
            }
            Some(adapter) => failures.push(format!(
                "{}: answered by '{}', expected '{}'",
                case.format, adapter, case.adapter
            )),
            None => failures.push(format!(
                "{}: nothing answered the rendering ({:?})",
                case.format, case.rendered
            )),
        }
    }

    std::fs::remove_dir_all(&dir).ok();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Both views report both: the rendering is a second view, not a deletion.
///
/// `Policy::Both` unions the file's own bytes with the rendering. The
/// rendering's own pattern is found, and the file's own pattern is still
/// found: the two views are a union, and neither replaces the other.
#[test]
fn both_views_report_the_file_and_the_rendering() {
    let dir = scratch_dir();
    let root = repo_root();
    let mut failures = Vec::new();

    for case in CASES.iter().filter(|c| c.reach == Reach::Render) {
        let src = root.join(case.fixture);
        let dst = dir.join(src.file_name().unwrap());
        std::fs::copy(&src, &dst).unwrap();

        let raw = case.raw.expect("a text format carries a raw pattern");
        for (what, needle) in [("the rendering", case.rendered), ("the file", raw)] {
            let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
                .args(["--no-heading", "--fixed-strings", needle])
                .arg(&dst)
                .env("RGX_ADAPTER_VIEW", "both")
                .output()
                .expect("failed to spawn rgx");
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.trim().is_empty() {
                failures.push(format!(
                    "{}: under the both policy, {} did not answer {:?}",
                    case.format, what, needle
                ));
            }
        }
    }

    std::fs::remove_dir_all(&dir).ok();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A binary format is answered by its adapter, under the default policy.
///
/// There is no raw answer for a metafile or a fax raster: `rg` finds
/// nothing in the bytes, and the adapter's rendering is the answer. The
/// pattern is one the file cannot hold.
#[test]
fn a_binary_format_is_answered_by_its_adapter() {
    let dir = scratch_dir();
    let root = repo_root();
    let mut failures = Vec::new();

    for case in CASES.iter().filter(|c| c.reach == Reach::Reveal) {
        let src = root.join(case.fixture);
        assert!(
            src.exists(),
            "{}: the fixture {} is missing",
            case.format,
            case.fixture
        );
        let dst = dir.join(src.file_name().unwrap());
        std::fs::copy(&src, &dst).unwrap();

        // The file itself must not carry the pattern: if it did, the
        // rendering would be proving nothing.
        if bytes_carry(&dst, case.rendered) {
            failures.push(format!(
                "{}: the file carries {:?}, so the rendering proves nothing",
                case.format, case.rendered
            ));
        }

        let stdout = run(None, case.rendered, &dst);
        match adapter_of(&stdout) {
            Some(adapter) if adapter == case.adapter => {
                if !stdout.contains(case.rendered) {
                    failures.push(format!(
                        "{}: the adapter '{}' answered but the answer does not carry {:?}",
                        case.format, adapter, case.rendered
                    ));
                }
            }
            Some(adapter) => failures.push(format!(
                "{}: answered by '{}', expected '{}'",
                case.format, adapter, case.adapter
            )),
            None => failures.push(format!(
                "{}: nothing answered ({:?})",
                case.format, case.rendered
            )),
        }
    }

    std::fs::remove_dir_all(&dir).ok();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
