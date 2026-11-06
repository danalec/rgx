// SPDX-License-Identifier: Apache-2.0

//! The raster formats, checked against the real binary.
//!
//! **What this pins.** For each format, the adapter that must answer for
//! it and a string the answer must contain. The check is not "the file
//! was found": a file that no adapter claims is still searched, as raw
//! bytes, and a raw search over a JPEG finds the occasional ASCII run in
//! the header. The check is that the *adapter* answered, and that what
//! it answered with says what the file says.
//!
//! **Why a binary and not the adapters.** The adapters are unit-tested
//! where they live, against fixtures they build themselves. This test
//! asks the question the user asks: run `rgx` over a file of this format
//! and tell me what comes back. The answer has to survive the registry,
//! the policy, the walk and the output layer, and only the binary knows
//! all four.
//!
//! **The fixtures are real files** in the crates' `testdata` directories,
//! not builders here: they are the same files the adapters' own tests
//! use, so a fixture that rots breaks in both places at once.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

/// One format: the file that stands for it, the adapter that must answer
/// for it, and a string its answer must carry.
struct Case {
    /// What the format is called in the README's table.
    format: &'static str,
    /// The fixture, relative to the repository root.
    fixture: &'static str,
    /// The adapter that must answer for the file.
    adapter: &'static str,
    /// A string the answer must carry — the part of the file a person
    /// would search for.
    needle: &'static str,
}

const CASES: &[Case] = &[
    Case {
        format: "JPEG",
        fixture: "crates/rgx-adapters-media/testdata/exif_sample.jpg",
        adapter: "exif",
        needle: "KADANE",
    },
    Case {
        format: "TIFF",
        fixture: "crates/rgx-adapters-media/testdata/exif_sample.tiff",
        adapter: "tiff",
        needle: "KADANE",
    },
    Case {
        format: "PNG",
        fixture: "crates/rgx-adapters-media/testdata/exif_sample.png",
        adapter: "exif",
        needle: "KADANE",
    },
    Case {
        format: "WEBP",
        fixture: "crates/rgx-adapters-media/testdata/exif_sample.webp",
        adapter: "exif",
        needle: "KADANE",
    },
    Case {
        format: "GIF",
        fixture: "crates/rgx-adapters-media/testdata/sample.gif",
        adapter: "gif",
        needle: "a comment from the fixture",
    },
    Case {
        format: "BMP",
        fixture: "crates/rgx-adapters-media/testdata/sample.bmp",
        adapter: "bmp",
        needle: "bpp: 24",
    },
    Case {
        format: "PSD",
        fixture: "crates/rgx-adapters-media/testdata/sample.psd",
        adapter: "psd",
        needle: "Contrato ACME",
    },
    Case {
        // The large document: the same header, version 2, and the reader says
        // so instead of reporting it as a plain PSD.
        format: "PSB",
        fixture: "crates/rgx-adapters-media/testdata/sample.psb",
        adapter: "psd",
        needle: "Photoshop Large Document",
    },
    Case {
        format: "JPEG 2000 (container)",
        fixture: "crates/rgx-adapters-media/testdata/sample.jp2",
        adapter: "jpeg2000",
        needle: "Contrato ACME",
    },
    Case {
        format: "JPEG 2000 (codestream)",
        fixture: "crates/rgx-adapters-media/testdata/sample.j2k",
        adapter: "jpeg2000",
        needle: "components: 3",
    },
    Case {
        format: "JPEG XL",
        fixture: "crates/rgx-adapters-media/testdata/sample.jxl",
        adapter: "jpegxl",
        needle: "brand: jxl",
    },
    Case {
        format: "OpenEXR",
        fixture: "crates/rgx-adapters-media/testdata/sample.exr",
        adapter: "openexr",
        needle: "scanlineimage",
    },
    Case {
        format: "HEIF",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.heif",
        adapter: "isobmff",
        needle: "HEIF image",
    },
    Case {
        format: "HEIC",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.heic",
        adapter: "isobmff",
        needle: "HEIC",
    },
    Case {
        format: "AVIF",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.avif",
        adapter: "isobmff",
        needle: "AVIF image",
    },
    Case {
        format: "camera RAW (CR2)",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.cr2",
        adapter: "tiff-pages",
        needle: "RGX Cameras",
    },
    Case {
        format: "DNG",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.dng",
        adapter: "tiff-pages",
        needle: "RGX Cameras",
    },
    Case {
        // Panasonic's RW2 is a TIFF whose magic number is 0x55, so a reader that
        // only knows 0x2A declines it and the file falls back to the raw search
        // without a word. The answer has to name the container it read.
        format: "camera RAW (RW2)",
        fixture: "crates/rgx-adapters-inspect/testdata/sample.rw2",
        adapter: "tiff-pages",
        needle: "TIFF (RW2",
    },
    Case {
        format: "PDF",
        fixture: "crates/rgx-adapters-pdf/fixtures/reportlab.pdf",
        adapter: "pdf",
        needle: "segunda",
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
    common::scratch("raster-test")
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

#[test]
fn every_raster_format_is_answered_by_its_own_adapter() {
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
        let name = src.file_name().unwrap();
        let dst = dir.join(name);
        std::fs::copy(&src, &dst).unwrap();

        let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
            // The needles are literal strings, not patterns: one of them carries
            // a parenthesis, and a regex would read it as a group.
            .args(["--json", "--no-heading", "--fixed-strings", case.needle])
            .arg(&dst)
            .output()
            .expect("failed to spawn rgx");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();

        match adapter_of(&stdout) {
            Some(adapter) if adapter == case.adapter => {
                if !stdout.contains(case.needle) {
                    failures.push(format!(
                        "{}: the adapter '{}' answered but the answer does not carry {:?}",
                        case.format, adapter, case.needle
                    ));
                }
            }
            Some(adapter) => failures.push(format!(
                "{}: answered by '{}', expected '{}'",
                case.format, adapter, case.adapter
            )),
            None => failures.push(format!(
                "{}: nothing answered (exit {:?})",
                case.format,
                out.status.code()
            )),
        }
    }

    std::fs::remove_dir_all(&dir).ok();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The formats that are claimed but whose *content* is not decoded are
/// still searched: the claim is what the adapter says it can do, and the
/// answer has to be the one it promised.
#[test]
fn a_claimed_format_is_never_silently_raw() {
    let dir = scratch_dir();
    let root = repo_root();
    for case in CASES {
        let src = root.join(case.fixture);
        let dst = dir.join(src.file_name().unwrap());
        std::fs::copy(&src, &dst).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
            .args(["--json", case.needle])
            .arg(&dst)
            .output()
            .expect("failed to spawn rgx");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            !stdout.contains("\"adapter\":\"raw\""),
            "{}: the file was searched raw, not by its adapter",
            case.format
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// The directory a case's fixture lives in, for a reader who wants to
/// look at it.
#[allow(dead_code)]
fn fixture_dir(case: &Case) -> PathBuf {
    repo_root()
        .join(Path::new(case.fixture))
        .parent()
        .unwrap()
        .to_path_buf()
}
