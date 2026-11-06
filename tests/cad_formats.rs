// SPDX-License-Identifier: Apache-2.0

//! The text CAD formats, checked against the real binary.
//!
//! **What this pins.** For each format, three things at once: the adapter
//! that must answer for it, a pattern the *rendering* carries and the file
//! does not, and a pattern the file's own bytes carry. Two halves of one
//! claim, and the second half is the half that can rot silently.
//!
//! **The default view is the file's own bytes.** These five declare
//! `Reach::Render`: under the default `Policy::Source` the adapter is not
//! consulted at all and the file is searched as it lies on disk. So the
//! default run must report `"adapter":"raw"` and find the raw pattern —
//! rgx stays a superset of ripgrep on these files, and the rendering is a
//! second view asked for explicitly, never a replacement.
//!
//! **Why a binary and not the adapters.** The adapters are unit-tested where
//! they live, against fixtures they build themselves. This test asks the
//! question the user asks: run `rgx` over a file of this format and tell me
//! what comes back. The answer has to survive the registry, the policy, the
//! walk and the output layer, and only the binary knows all four.
//!
//! **The fixtures are real files** in the crate's `testdata` directory, not
//! builders here: they are the same files the adapters' own tests use, so a
//! fixture that rots breaks in both places at once.

use std::path::PathBuf;
use std::process::Command;

mod common;

/// One format: the file that stands for it, the adapter that must answer
/// for it, and the two patterns the two views carry.
struct Case {
    /// What the format is called in the README's table.
    format: &'static str,
    /// The fixture, relative to the repository root.
    fixture: &'static str,
    /// The adapter that must answer for the file under the render policy.
    adapter: &'static str,
    /// A pattern the rendering carries and the file does not — the entity
    /// and its values on one line, which is the whole point of the format.
    rendered: &'static str,
    /// A pattern the file's own bytes carry.
    raw: &'static str,
}

const CASES: &[Case] = &[
    Case {
        format: "DXF",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.dxf",
        adapter: "dxf",
        rendered: "entity: LINE on layer",
        raw: "Contrato ACME",
    },
    Case {
        format: "IFC/STEP",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.stp",
        adapter: "step",
        rendered: "#7: IFCWALL",
        raw: "Contrato ACME",
    },
    Case {
        format: "IGES",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.igs",
        adapter: "iges",
        rendered: "entity: 110 (Line)",
        raw: "sample.igs",
    },
    Case {
        format: "ACIS .sat",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.sat",
        adapter: "acis-sat",
        rendered: "entity: transform",
        raw: "transform",
    },
    Case {
        format: "STL",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.stl",
        adapter: "stl",
        rendered: "facet 1: normal",
        raw: "facet",
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
    common::scratch("cad-test")
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
    // The needles are literal strings, not patterns: an entity's heading
    // carries parentheses, and a regex would read them as a group.
    cmd.args(["--json", "--no-heading", "--fixed-strings", pattern])
        .arg(file);
    match view {
        Some(v) => cmd.env("RGX_ADAPTER_VIEW", v),
        None => cmd.env_remove("RGX_ADAPTER_VIEW"),
    };
    let out = cmd.output().expect("failed to spawn rgx");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The default view of a text CAD file is the file's own bytes.
///
/// The adapter is not consulted under `Policy::Source`, so the file is
/// searched raw and the answer is ripgrep's answer. This is the half of the
/// claim that keeps rgx a superset, and it is the half a rendering adapter
/// can break without failing anything.
#[test]
fn the_default_view_of_a_text_cad_file_is_its_own_bytes() {
    let dir = scratch_dir();
    let root = repo_root();
    let mut failures = Vec::new();

    for case in CASES {
        let src = root.join(case.fixture);
        assert!(
            src.exists(),
            "{}: the fixture {} is missing",
            case.format,
            case.fixture
        );
        let dst = dir.join(src.file_name().unwrap());
        std::fs::copy(&src, &dst).unwrap();

        let stdout = run(None, case.raw, &dst);
        match adapter_of(&stdout) {
            Some(adapter) if adapter == "raw" => {
                if !stdout.contains(case.raw) {
                    failures.push(format!(
                        "{}: the raw view did not find {:?}",
                        case.format, case.raw
                    ));
                }
            }
            Some(adapter) => failures.push(format!(
                "{}: the default view was answered by '{}', expected 'raw'",
                case.format, adapter
            )),
            None => failures.push(format!(
                "{}: the default view found nothing ({:?})",
                case.format, case.raw
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
fn the_rendering_of_a_text_cad_file_holds_what_the_file_cannot() {
    let dir = scratch_dir();
    let root = repo_root();
    let mut failures = Vec::new();

    for case in CASES {
        let src = root.join(case.fixture);
        let dst = dir.join(src.file_name().unwrap());
        std::fs::copy(&src, &dst).unwrap();

        // The file itself must not carry the pattern: if it did, the
        // rendering would be proving nothing.
        let raw_file = std::fs::read_to_string(&dst).unwrap_or_default();
        if raw_file.contains(case.rendered) {
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

    for case in CASES {
        let src = root.join(case.fixture);
        let dst = dir.join(src.file_name().unwrap());
        std::fs::copy(&src, &dst).unwrap();

        for (what, needle) in [("the rendering", case.rendered), ("the file", case.raw)] {
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
