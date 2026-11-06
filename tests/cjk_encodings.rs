// SPDX-License-Identifier: Apache-2.0

//! The multi-byte CJK encodings, checked against the real binary.
//!
//! **What this pins.** A file that *says* what its bytes mean -- a MIME
//! part's `charset=`, an HTML `<meta charset>` -- used to be read as Latin-1
//! when the encoding was one of the multi-byte CJK ones, because the tables
//! were not there. The high half of those bytes is a *pair* of bytes, and
//! reading them one at a time does not read them differently: it reads them
//! *wrongly*, and the characters a search is for are not in the answer.
//!
//! **Every row checks a real search.** The needle is a word of the text, in
//! the characters the file was written in, and the assertion is that rgx
//! finds it. A table that is right and a decoder that reads it wrong are two
//! different bugs, and only the search tells them apart.
//!
//! **The last row keeps the fix honest.** The same bytes without the
//! declaration are not readable, and they must not have become readable by
//! accident: what is honoured is the declaration, not the bytes.
//!
//! **The fixtures are the reference implementation's own encoding** of the
//! text, written by `scripts/gen_charset_mb_tables.py`, and kept in the
//! core's `testdata` directory.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

/// One encoding: the label a file declares it with, the bytes, and the text.
struct Case {
    /// What the encoding is, in the words of the standard.
    format: &'static str,
    /// The label the file declares the encoding with.
    label: &'static str,
    /// The encoded bytes.
    encoded: &'static [u8],
    /// The text those bytes hold.
    text: &'static str,
    /// A word of the text, in the characters it was written in.
    needle: &'static str,
}

const CASES: &[Case] = &[
    Case {
        format: "Shift_JIS",
        label: "Shift_JIS",
        encoded: include_bytes!("../crates/rgx-core/testdata/charset/shift_jis.bin"),
        text: include_str!("../crates/rgx-core/testdata/charset/shift_jis.expected"),
        needle: "こんにちは、世界。",
    },
    Case {
        format: "EUC-JP",
        label: "EUC-JP",
        encoded: include_bytes!("../crates/rgx-core/testdata/charset/euc_jp.bin"),
        text: include_str!("../crates/rgx-core/testdata/charset/euc_jp.expected"),
        needle: "こんにちは、世界。",
    },
    Case {
        format: "Big5",
        label: "Big5",
        encoded: include_bytes!("../crates/rgx-core/testdata/charset/big5.bin"),
        text: include_str!("../crates/rgx-core/testdata/charset/big5.expected"),
        needle: "你好，世界。",
    },
    Case {
        format: "EUC-KR",
        label: "EUC-KR",
        encoded: include_bytes!("../crates/rgx-core/testdata/charset/euc_kr.bin"),
        text: include_str!("../crates/rgx-core/testdata/charset/euc_kr.expected"),
        needle: "안녕하세요, 세계。",
    },
    Case {
        format: "GB18030",
        label: "GB18030",
        encoded: include_bytes!("../crates/rgx-core/testdata/charset/gb18030.bin"),
        text: include_str!("../crates/rgx-core/testdata/charset/gb18030.expected"),
        needle: "你好，世界。",
    },
];

/// A directory of its own, so two runs never see each other's files.
///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn scratch() -> PathBuf {
    common::scratch("cjk-test")
}

/// The output of a run over one file.
fn run(pattern: &str, file: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
        .args(["-a", "-F", "-n", pattern])
        .arg(file)
        .output()
        .expect("rgx runs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The same run with the rendering view on, which is what a text format's
/// adapter answers with.
fn run_rendered(pattern: &str, file: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
        .env("RGX_ADAPTER_VIEW", "render")
        .args(["-a", "-F", "-n", pattern])
        .arg(file)
        .output()
        .expect("rgx runs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A MIME message whose body is the encoded bytes and whose part says what
/// they are.
fn message(case: &Case, charset: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"From: sender@example.com\r\n");
    out.extend_from_slice(b"To: receiver@example.com\r\n");
    out.extend_from_slice(b"Subject: a message in another encoding\r\n");
    match charset {
        Some(label) => out.extend_from_slice(
            format!("Content-Type: text/plain; charset={label}\r\n\r\n").as_bytes(),
        ),
        None => out.extend_from_slice(b"Content-Type: text/plain\r\n\r\n"),
    }
    out.extend_from_slice(case.encoded);
    out
}

/// A file that declares its encoding is read in the characters it was
/// written in, and a search finds them.
///
/// **Every line of the text is searched for.** The answer holds only the
/// lines that matched, so a decoder that finds one character and loses the
/// next would satisfy a search of the first line alone.
#[test]
fn a_declared_multi_byte_encoding_is_read_in_its_own_characters() {
    for case in CASES {
        let dir = scratch();
        let eml = dir.join("message.eml");
        std::fs::write(&eml, message(case, Some(case.label))).unwrap();

        for line in case.text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let out = run(line, &eml);
            assert!(
                out.contains(line),
                "{}: the line {:?} was not found:\n{out}",
                case.format,
                line
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// The same bytes in an HTML document, where the declaration is a meta tag
/// and the answer is a rendering.
#[test]
fn a_declared_multi_byte_encoding_is_read_in_an_html_document() {
    for case in CASES {
        let dir = scratch();
        let html = dir.join("page.html");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            format!("<html><head><meta charset=\"{}\"></head><body>", case.label).as_bytes(),
        );
        bytes.extend_from_slice(case.encoded);
        bytes.extend_from_slice(b"</body></html>\n");
        std::fs::write(&html, &bytes).unwrap();

        let out = run_rendered(case.needle, &html);
        assert!(
            out.contains(case.needle),
            "{}: the needle {:?} was not found:\n{out}",
            case.format,
            case.needle
        );
        for line in case.text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let out = run_rendered(line, &html);
            assert!(
                out.contains(line),
                "{}: the line {:?} was not found:\n{out}",
                case.format,
                line
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// Without the declaration the bytes are still there and still searchable as
/// bytes, but they are not the characters: what is honoured is the
/// declaration, not the byte pattern.
#[test]
fn without_the_declaration_the_characters_are_not_recovered() {
    for case in CASES {
        let dir = scratch();
        let eml = dir.join("message.eml");
        std::fs::write(&eml, message(case, None)).unwrap();

        let out = run(case.needle, &eml);
        assert!(
            !out.contains(case.needle),
            "{}: the needle {:?} was found without a declaration:\n{out}",
            case.format,
            case.needle
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
