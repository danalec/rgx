// SPDX-License-Identifier: Apache-2.0

//! WinRAR black-box oracle conformance runner.
//!
//! Gated on environment variables so the normal gate stays green:
//!
//!   RGX_WINRAR_ORACLE=<goldens dir>          forward decode conformance:
//!                                            the RAR 7.20 matrix, RAR5 only
//!   RGX_WINRAR_ORACLE_RAR4=<goldens dir>     the same matrix rebuilt by
//!                                            Rar.exe 6.24, plus RAR4 and
//!                                            RAR4-PPMd cases
//!   RGX_UNRAR=<path to UnRAR.exe>            reverse writer check
//!
//! Forward: for every (archive, member) row in an oracle's `golden.h`, the
//! archive is hashed, opened with `rar_codec::Archive`, the member extracted,
//! and its SHA-256 compared to the golden. Rows the codec refuses by design
//! (encryption) are reported as `unsupported` with the reason, never skipped
//! silently. The test fails only on `fail` rows. Every set oracle directory
//! is run and summarised separately.
//!
//! Reverse: store-only archives written by `rar_codec::ArchiveBuilder` are
//! extracted by the genuine UnRAR.exe and the bytes compared, including the
//! 0/1/2-byte edge shapes and a multi-member archive.
//!
//! Two corpora, complementary by construction. One is the RAR 7.20 matrix
//! (RAR5 only — RAR 7.x has no `-ma4`, so its three RAR4 cases were skipped
//! at build time). The other is the same matrix rebuilt by `Rar.exe` 6.24
//! plus RAR4 and RAR4-PPMd cases, extracted with the same genuine
//! UnRAR 7.20.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

// ------------------------------------------------------------------ SHA-256
//
// Test-only, so the crate keeps zero dependencies. Verified against the
// FIPS 180-4 vectors before any oracle comparison trusts it.

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl Sha256 {
    fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_len = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0]);
        }
        // Length block is not counted in `total`; feed it past the counter.
        self.total = 0;
        let mut lenb = [0u8; 8];
        lenb.copy_from_slice(&bit_len.to_be_bytes());
        self.update(&lenb);
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        #[rustfmt::skip]
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut h = self.state;
        for i in 0..64 {
            let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);
            let ch = (h[4] & h[5]) ^ ((!h[4]) & h[6]);
            let t1 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
            let maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            let t2 = s0.wrapping_add(maj);
            h[7] = h[6];
            h[6] = h[5];
            h[5] = h[4];
            h[4] = h[3].wrapping_add(t1);
            h[3] = h[2];
            h[2] = h[1];
            h[1] = h[0];
            h[0] = t1.wrapping_add(t2);
        }
        for (s, &v) in self.state.iter_mut().zip(h.iter()) {
            *s = s.wrapping_add(v);
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finish())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// FIPS 180-4 check vectors. If these fail, every mismatch below is a false
/// alarm in the harness, not in the decoder.
fn verify_sha256_impl() {
    let cases: &[(&[u8], &str)] = &[
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (input, want) in cases {
        let got = sha256_hex(input);
        assert_eq!(&got, want, "sha256 self-check failed for {input:?}");
    }
}

// ------------------------------------------------------------- golden.h rows

#[derive(Debug)]
struct GoldenRow {
    id: String,
    archive: String,
    archive_sha256: String,
    archive_size: u64,
    member: String,
    member_sha256: String,
    member_size: u64,
    encrypted: bool,
    #[allow(dead_code)]
    password: Option<String>,
    #[allow(dead_code)]
    expected_exit: i64,
    method: String,
}

#[derive(Debug)]
enum Field {
    Str(String),
    Int(i64),
    Null,
}

/// Scan one `{...}` row of the `oracle_cases` initialiser.
fn parse_row_fields(src: &str) -> Vec<Field> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                let mut s = String::new();
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        let n = bytes[i + 1];
                        s.push(match n {
                            b'n' => '\n',
                            b'r' => '\r',
                            b't' => '\t',
                            b'0' => '\0',
                            other => other as char,
                        });
                        i += 2;
                    } else {
                        s.push(bytes[i] as char);
                        i += 1;
                    }
                }
                i += 1;
                out.push(Field::Str(s));
            }
            b'N' if src[i..].starts_with("NULL") => {
                i += 4;
                out.push(Field::Null);
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                if bytes[i] == b'-' {
                    i += 1;
                }
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                // Trailing ULL / U / L suffixes in the C source.
                while i < bytes.len() && matches!(bytes[i], b'U' | b'u' | b'L' | b'l') {
                    i += 1;
                }
                let n: i64 = src[start..i]
                    .trim_end_matches(['U', 'u', 'L', 'l'])
                    .parse()
                    .expect("integer literal in golden.h");
                out.push(Field::Int(n));
            }
            _ => i += 1,
        }
    }
    out
}

fn parse_golden(src: &str) -> Vec<GoldenRow> {
    let mut rows = Vec::new();
    // Rows live between `oracle_cases[...] = {` and the closing `};`.
    let body_start = src
        .find("oracle_cases")
        .and_then(|p| src[p..].find('{').map(|q| p + q))
        .expect("oracle_cases initialiser present");
    let body = &src[body_start..];
    let mut rest = body;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        // The struct-init row is closed by `},` or `}` at depth zero; the
        // rows contain no nested braces, so the first `}` closes it.
        let close = after.find('}').expect("row terminator");
        let row_src = &after[..close];
        let f = parse_row_fields(row_src);
        assert!(
            f.len() >= 11,
            "golden row has {} fields: {row_src}",
            f.len()
        );
        let get_str = |i: usize| -> String {
            match &f[i] {
                Field::Str(s) => s.clone(),
                other => panic!("field {i} is not a string: {other:?}"),
            }
        };
        let get_int = |i: usize| -> i64 {
            match &f[i] {
                Field::Int(n) => *n,
                other => panic!("field {i} is not an integer: {other:?}"),
            }
        };
        rows.push(GoldenRow {
            id: get_str(0),
            archive: get_str(1),
            archive_sha256: get_str(2),
            archive_size: get_int(3) as u64,
            member: get_str(4),
            member_sha256: get_str(5),
            member_size: get_int(6) as u64,
            encrypted: get_int(7) != 0,
            password: match &f[8] {
                Field::Null => None,
                Field::Str(s) => Some(s.clone()),
                other => panic!("field 8 is not NULL/string: {other:?}"),
            },
            expected_exit: get_int(9),
            method: get_str(10),
        });
        rest = &after[close + 1..];
    }
    rows
}

/// The `#define ORACLE_N_CASES N` the generator wrote; the row list must
/// agree with it, or the parse dropped or invented rows.
fn parse_declared_case_count(src: &str) -> usize {
    let line = src
        .lines()
        .find(|l| l.trim_start().starts_with("#define ORACLE_N_CASES"))
        .expect("ORACLE_N_CASES define present");
    line.split_whitespace()
        .last()
        .expect("count token")
        .parse()
        .expect("integer case count")
}

// --------------------------------------------------------------- forward run

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Fail,
    Unsupported,
}

struct CaseResult {
    id: String,
    member: String,
    method: String,
    status: Status,
    archive_sha_ok: bool,
    reason: String,
}

fn oracle_dir() -> Option<PathBuf> {
    std::env::var_os("RGX_WINRAR_ORACLE").map(PathBuf::from)
}

fn oracle_dir_rar4() -> Option<PathBuf> {
    std::env::var_os("RGX_WINRAR_ORACLE_RAR4").map(PathBuf::from)
}

/// Every oracle directory the caller named, with the variable that named it.
/// Both are optional; zero of them means the forward test skips.
fn oracle_dirs() -> Vec<(&'static str, PathBuf)> {
    let mut v = Vec::new();
    if let Some(d) = oracle_dir() {
        v.push(("RGX_WINRAR_ORACLE", d));
    }
    if let Some(d) = oracle_dir_rar4() {
        v.push(("RGX_WINRAR_ORACLE_RAR4", d));
    }
    v
}

fn unrar_exe() -> Option<PathBuf> {
    std::env::var_os("RGX_UNRAR").map(PathBuf::from)
}

fn run_forward(dir: &Path) -> Vec<CaseResult> {
    let golden_src = std::fs::read_to_string(dir.join("golden.h")).expect("read golden.h");
    let rows = parse_golden(&golden_src);
    let declared = parse_declared_case_count(&golden_src);
    assert_eq!(
        rows.len(),
        declared,
        "golden.h declares {declared} rows but {} parsed",
        rows.len()
    );

    // One extraction per unique archive, then every row of that archive is
    // checked against the extracted map. Solid groups decode in entry order
    // so the shared window stays in sync.
    let mut extracted: BTreeMap<String, BTreeMap<String, Result<Vec<u8>, String>>> =
        BTreeMap::new();
    let mut archive_sha_ok: BTreeMap<String, bool> = BTreeMap::new();

    for row in &rows {
        if extracted.contains_key(&row.archive) {
            continue;
        }
        let path = dir.join(&row.archive);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", row.archive));
        let got_sha = sha256_hex(&bytes);
        let sha_ok = got_sha == row.archive_sha256 && bytes.len() as u64 == row.archive_size;
        archive_sha_ok.insert(row.archive.clone(), sha_ok);
        if !sha_ok {
            // Wrong bytes on disk: every member of this archive is a fail
            // with the archive hash as the first divergence.
            extracted.insert(row.archive.clone(), BTreeMap::new());
            continue;
        }

        let mut members: BTreeMap<String, Result<Vec<u8>, String>> = BTreeMap::new();
        let opened = rar_codec::Archive::open(&bytes);
        match opened {
            Err(e) => {
                // A refusal to open is an unsupported only when the codec
                // names the feature; a parse/CRC error is a real failure.
                let msg = e.to_string();
                let kind = match &e {
                    rar_codec::Error::Unsupported(what) => {
                        format!("archive open refused: unsupported {what}")
                    }
                    _ => format!("archive open error: {msg}"),
                };
                for r in rows.iter().filter(|r| r.archive == row.archive) {
                    members.insert(r.member.clone(), Err(kind.clone()));
                }
            }
            Ok(arc) => {
                for entry in arc.entries() {
                    if entry.kind != rar_codec::EntryKind::File {
                        continue;
                    }
                    let res = match arc.extract(entry) {
                        Ok(b) => Ok(b),
                        Err(rar_codec::Error::Unsupported(what)) => {
                            Err(format!("unsupported {what}"))
                        }
                        Err(e) => Err(format!("extract error: {e}")),
                    };
                    members.insert(entry.name.to_string(), res);
                }
                // Golden members the parser never produced (e.g. header
                // encryption left the listing empty).
                for r in rows.iter().filter(|r| r.archive == row.archive) {
                    members
                        .entry(r.member.clone())
                        .or_insert_with(|| Err("member not present in parsed archive".to_string()));
                }
            }
        }
        extracted.insert(row.archive.clone(), members);
    }

    let mut results = Vec::new();
    for row in &rows {
        let sha_ok = archive_sha_ok[&row.archive];
        let got = extracted[&row.archive].get(&row.member);
        let (status, reason) = if !sha_ok {
            (
                Status::Fail,
                "archive sha256 mismatch — not the oracle bytes".to_string(),
            )
        } else {
            match got {
                None => (
                    Status::Fail,
                    "member missing from extraction map".to_string(),
                ),
                Some(Err(msg)) => {
                    if msg.starts_with("unsupported") {
                        (Status::Unsupported, msg.clone())
                    } else {
                        (Status::Fail, msg.clone())
                    }
                }
                Some(Ok(bytes)) => {
                    if bytes.len() as u64 != row.member_size {
                        (
                            Status::Fail,
                            format!(
                                "member size mismatch: got {} want {}",
                                bytes.len(),
                                row.member_size
                            ),
                        )
                    } else {
                        let got_sha = sha256_hex(bytes);
                        if got_sha != row.member_sha256 {
                            (
                                Status::Fail,
                                format!(
                                    "member sha256 mismatch: got {got_sha} want {}",
                                    row.member_sha256
                                ),
                            )
                        } else {
                            (Status::Pass, String::new())
                        }
                    }
                }
            }
        };
        // A golden row that is encrypted is unsupported whenever the bytes
        // did not come back correct: rar-codec has no decryption path at all.
        // The refusal surface differs by case (data-only encryption names
        // `Unsupported("encrypted payload")`; header encryption fails inside
        // parse as Truncated/BadCrc because the listing is unreadable), and
        // both are the same missing feature, not a decode mismatch.
        let (status, reason) = if row.encrypted && status != Status::Pass {
            (
                Status::Unsupported,
                format!("no decryption implemented (row is encrypted); codec said: {reason}"),
            )
        } else {
            (status, reason)
        };
        results.push(CaseResult {
            id: row.id.clone(),
            member: row.member.clone(),
            method: row.method.clone(),
            status,
            archive_sha_ok: sha_ok,
            reason,
        });
    }
    results
}

// --------------------------------------------------------------- reverse run

/// One writer round-trip: build with rar-codec, extract with real UnRAR.
struct ReverseCase {
    id: &'static str,
    members: Vec<(String, Vec<u8>)>,
}

fn run_reverse(dir: &Path, unrar: &Path) -> Vec<(String, Status, String)> {
    let corpus = dir.join("corpus");
    let read = |name: &str| std::fs::read(corpus.join(name)).expect("read corpus file");

    let cases = vec![
        ReverseCase {
            id: "rev_empty_0b",
            members: vec![("empty".to_string(), read("empty"))],
        },
        ReverseCase {
            id: "rev_single_1b",
            members: vec![("single".to_string(), read("single"))],
        },
        ReverseCase {
            id: "rev_tiny_2b",
            members: vec![("tiny2".to_string(), read("tiny2"))],
        },
        ReverseCase {
            id: "rev_multi_mixed",
            members: vec![
                ("empty".to_string(), read("empty")),
                ("single".to_string(), read("single")),
                ("tiny2".to_string(), read("tiny2")),
                ("text_40k".to_string(), read("text_40k")),
                ("zeros_64k".to_string(), read("zeros_64k")),
            ],
        },
        ReverseCase {
            id: "rev_nested_path",
            members: vec![
                ("tree/a/b/deep1.bin".to_string(), read("tree/a/b/deep1.bin")),
                ("tree/top3.bin".to_string(), read("tree/top3.bin")),
            ],
        },
    ];

    let out_root = std::env::temp_dir().join(format!("rgx-winrar-rev-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_root);
    std::fs::create_dir_all(&out_root).expect("create reverse out root");

    let mut out = Vec::new();
    for case in cases {
        // rar-codec writes the archive.
        let mut w = rar_codec::ArchiveBuilder::new();
        for (name, data) in &case.members {
            w.add_stored(name, data)
                .unwrap_or_else(|e| panic!("{}: add_stored({name}): {e}", case.id));
        }
        let archive_bytes = w.finish();
        let arc_path = out_root.join(format!("{}.rar", case.id));
        std::fs::write(&arc_path, &archive_bytes).expect("write archive");

        // Genuine UnRAR extracts it.
        let dest = out_root.join(format!("{}-out", case.id));
        std::fs::create_dir_all(&dest).expect("create dest");
        let dest_arg = format!("{}{}", dest.display(), std::path::MAIN_SEPARATOR);
        let output = Command::new(unrar)
            .args(["x", "-o+", "-idq"])
            .arg(&arc_path)
            .arg(&dest_arg)
            .output()
            .expect("spawn UnRAR.exe");
        let code = output.status.code().unwrap_or(-1);
        if code != 0 {
            out.push((
                case.id.to_string(),
                Status::Fail,
                format!(
                    "UnRAR exit {code}: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
            continue;
        }
        // Compare every member.
        let mut ok = true;
        let mut why = String::new();
        for (name, data) in &case.members {
            // UnRAR keeps the forward-slash path as nested directories.
            let got_path = dest.join(name);
            let got = match std::fs::read(&got_path) {
                Ok(b) => b,
                Err(e) => {
                    ok = false;
                    why = format!("extracted member {name} missing: {e}");
                    break;
                }
            };
            if &got != data {
                ok = false;
                why = format!(
                    "member {name} content mismatch (got {} bytes want {})",
                    got.len(),
                    data.len()
                );
                break;
            }
            if sha256_hex(&got) != sha256_hex(data) {
                ok = false;
                why = format!("member {name} sha256 mismatch");
                break;
            }
        }
        out.push((
            case.id.to_string(),
            if ok { Status::Pass } else { Status::Fail },
            if ok {
                format!("{} member(s)", case.members.len())
            } else {
                why
            },
        ));
    }
    let _ = std::fs::remove_dir_all(&out_root);
    out
}

// ------------------------------------------------------------------ the gate

#[test]
fn sha256_self_check() {
    verify_sha256_impl();
}

#[test]
fn winrar_oracle_forward() {
    let dirs = oracle_dirs();
    if dirs.is_empty() {
        eprintln!("skip: neither RGX_WINRAR_ORACLE nor RGX_WINRAR_ORACLE_RAR4 is set");
        return;
    }
    verify_sha256_impl();
    let mut total_fail = 0;
    for (label, dir) in &dirs {
        let results = run_forward(dir);

        let mut pass = 0;
        let mut fail = 0;
        let mut unsup = 0;
        eprintln!(
            "--- winrar oracle forward [{label}]: {} rows ---",
            results.len()
        );
        eprintln!(
            "{:<16} {:<8} {:<44} {:<12} {:<6} REASON",
            "ID", "METHOD", "MEMBER", "STATUS", "ARC_SHA"
        );
        for r in &results {
            match r.status {
                Status::Pass => pass += 1,
                Status::Fail => fail += 1,
                Status::Unsupported => unsup += 1,
            }
            eprintln!(
                "{:<16} {:<8} {:<44} {:<12} {:<6} {}",
                r.id,
                r.method,
                truncate(&r.member, 44),
                match r.status {
                    Status::Pass => "pass",
                    Status::Fail => "FAIL",
                    Status::Unsupported => "unsupported",
                },
                if r.archive_sha_ok { "ok" } else { "BAD" },
                r.reason
            );
        }
        eprintln!("--- forward summary [{label}]: pass={pass} fail={fail} unsupported={unsup} ---");
        total_fail += fail;
    }
    assert_eq!(
        total_fail, 0,
        "winrar oracle reported {total_fail} failing case(s); see tables above"
    );
}

#[test]
fn winrar_oracle_reverse_writer() {
    let Some(unrar) = unrar_exe() else {
        eprintln!("skip: RGX_UNRAR is not set");
        return;
    };
    let Some((_, dir)) = oracle_dirs().into_iter().next() else {
        eprintln!("skip: neither RGX_WINRAR_ORACLE nor RGX_WINRAR_ORACLE_RAR4 is set");
        return;
    };
    verify_sha256_impl();
    let results = run_reverse(&dir, &unrar);
    let mut pass = 0;
    let mut fail = 0;
    eprintln!("--- winrar oracle reverse (rar-codec writer -> UnRAR) ---");
    for (id, status, reason) in &results {
        match status {
            Status::Pass => pass += 1,
            Status::Fail => fail += 1,
            Status::Unsupported => {}
        }
        eprintln!(
            "{:<20} {:<12} {}",
            id,
            match status {
                Status::Pass => "pass",
                Status::Fail => "FAIL",
                Status::Unsupported => "unsupported",
            },
            reason
        );
    }
    eprintln!("--- reverse summary: pass={pass} fail={fail} ---");
    assert_eq!(fail, 0, "reverse writer check reported {fail} failure(s)");
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}
