// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests: run the real `rgx` binary against a fixture tree.
//!
//! Fixtures are built in a unique temp dir at runtime: a plain text file, a
//! gzipped text file (archive adapter) and a MIME message with an 8-bit
//! text/plain attachment (mail adapter). No network, no external tools.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

const NEEDLE: &str = "needle";

fn rgx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rgx"))
}

///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn fixture_dir() -> PathBuf {
    let dir = common::scratch("cli-test");

    std::fs::write(dir.join("hello.txt"), "hello needle world\nsecond line\n").unwrap();

    let gz_path = dir.join("packed.gz");
    let gz_file = std::fs::File::create(&gz_path).unwrap();
    let mut enc = flate2::write::GzEncoder::new(gz_file, flate2::Compression::fast());
    enc.write_all(b"compressed needle payload\n").unwrap();
    enc.finish().unwrap();

    // MIME message: plain body + 8-bit text/plain attachment (no base64 so
    // the test needs no decoder and exercises the raw 8bit path)
    let eml = "From: lab@example.org\r\n\
               To: ops@example.org\r\n\
               Subject: calibration\r\n\
               MIME-Version: 1.0\r\n\
               Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
               \r\n\
               --BOUND\r\n\
               Content-Type: text/plain; charset=utf-8\r\n\
               \r\n\
               body without the term\r\n\
               --BOUND\r\n\
               Content-Type: text/plain; charset=utf-8\r\n\
               Content-Disposition: attachment; filename=\"reading.txt\"\r\n\
               \r\n\
               attachment holds the needle value\r\n\
               --BOUND--\r\n";
    std::fs::write(dir.join("mail.eml"), eml).unwrap();

    // binary file: match only *before* the first NUL — must affect exit
    // code, -l and -c, but produce no line output
    let mut bin = b"HEADER needle before nul".to_vec();
    bin.push(0);
    bin.extend_from_slice(b"TAIL without term");
    std::fs::write(dir.join("blob.bin"), &bin).unwrap();

    dir
}

fn run(dir: &Path, args: &[&str]) -> (i32, String) {
    let out = rgx()
        .args(args)
        .arg(dir)
        .output()
        .expect("failed to spawn rgx");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// The same run, with the error stream: a filter that does not parse is
/// reported on stderr and not on stdout.
fn run_stderr(dir: &Path, args: &[&str]) -> (i32, String) {
    let out = rgx()
        .args(args)
        .arg(dir)
        .output()
        .expect("failed to spawn rgx");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// UTF-16 in the byte order named, with the mark ripgrep acts on.
fn utf16(text: &str, big_endian: bool) -> Vec<u8> {
    let mut out = vec![if big_endian { 0xfe } else { 0xff }];
    out.push(if big_endian { 0xff } else { 0xfe });
    for unit in text.encode_utf16() {
        out.extend_from_slice(&if big_endian {
            unit.to_be_bytes()
        } else {
            unit.to_le_bytes()
        });
    }
    out
}

/// A UTF-16 PowerShell data file is searched, not mistaken for a binary.
///
/// **This is the reported `.psd1` divergence, at the level it was reported.** The
/// NUL heuristic is applied by rgx in a head sniff that runs before the
/// searcher, and it ran on the RAW file. UTF-16LE interleaves `00` after every
/// ASCII character, so a data file holding an ordinary hashtable is `00`-dense
/// from its first byte; the sniff called it binary, the printer suppressed line
/// output, and `rgx` printed nothing at all where ripgrep printed the line.
/// `-c` and `-l` were right, which is why it read as a count divergence.
///
/// rg's own binary detection runs inside its searcher, after the byte-order
/// mark has been decoded, so it sees text where rgx saw `00`. The fixture
/// carries an ordinary mix -- ASCII, accented Latin, CJK, an emoji outside the
/// BMP, a blank line and no final newline -- because any of those can produce
/// the interleaving that tripped the sniff.
#[test]
fn a_utf16_power_shell_data_file_is_not_treated_as_binary() {
    let dir = fixture_dir();
    let text = "@{\r\n    Name = 'Registry.Settings'\r\n\r\n    \
                Résumé = \"valeur accentuée\"\r\n    \
                Emoji = \"\u{1f600} tail\"\r\n    CJK = \"\u{4f60}\u{597d}\"\r\n}";

    for (name, big_endian) in [("settings.psd1", false), ("settings-be.psd1", true)] {
        let path = dir.join(name);
        std::fs::write(&path, utf16(text, big_endian)).unwrap();

        // The file really is `00`-dense, so this is the shape that tripped it.
        let raw = std::fs::read(&path).unwrap();
        assert!(
            raw.windows(2).any(|w| w == [0x00, 0x00] || w[0] == 0x00),
            "[{name}] the fixture must contain NUL bytes or it proves nothing"
        );

        let out = rgx().args([NEEDLE_PATTERN]).arg(&path).output().unwrap();
        let got = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "[{name}] nothing matched");
        assert!(
            got.contains("Registry.Settings"),
            "[{name}] UTF-16 file was treated as binary; line output suppressed. got={got:?}"
        );

        // The accented line and the one outside the BMP, which is where a
        // decode that lost a surrogate would show.
        let out = rgx().args(["Résumé"]).arg(&path).output().unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("accentuée"),
            "[{name}] the accented line must be searchable"
        );
        let out = rgx().args(["\u{1f600}"]).arg(&path).output().unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("\u{1f600} tail"),
            "[{name}] a surrogate pair must survive the decode"
        );

        // And the counts ripgrep agrees with, so the shape of the answer is
        // pinned and not just the presence of one line.
        let out = rgx().args(["-c", "^"]).arg(&path).output().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "7",
            "[{name}] the decoded text has seven lines"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// **A payload with a NUL in it is the shape every decompressor fixture was
/// missing, and its absence is why a whole format family was unsearchable.**
///
/// `unit_searcher` (`src/main.rs`) picks the binary rule from `Found::via`,
/// and a single-file decompressor cannot reach any other answer: `Decompress`
/// returns `Members` with one member named after the stripped stem, `process`
/// recurses into it, no adapter claims an extensionless name, and the
/// decompressed bytes come back labelled `"raw"` — the file's own bytes, as
/// far as `via` was concerned. The searcher then applied the on-disk NUL
/// heuristic to the *decoded* payload and used `BinaryDetection::Quit`, which
/// reports nothing at all once a NUL sits in the first 64 KiB, not even the
/// lines before it. So `rgx -c hello brotli_big_q0.br` printed nothing where
/// the same payload uncompressed printed 20 — and `.gz`, `.zst`, `.xz` and
/// `.bz2` all did it too, from the same three lines.
///
/// `brotli_big.plain` is code, a repeated pattern, a run, then 40 KB of
/// random bytes: its first NUL is at offset 305. `brotli_text`, `brotli_rep`
/// and `brotli_utf8` have no NUL at all, which is why every fixture written
/// before this one decoded and searched identically, and why the adapter test
/// that claimed to cover "rgx can search a .br" stayed green.
///
/// The NUL is placed at byte 100 rather than at the front, so the test also
/// says the *early* lines are found and not only the late ones: a fix that
/// simply widened the search window would pass a NUL-at-zero fixture and
/// still drop everything after it.
#[test]
fn a_decoded_payload_containing_a_nul_is_still_searched() {
    let dir = fixture_dir();
    let path = dir.join("packed_with_nul.gz");

    let mut payload = b"head needle before the nul\n".to_vec();
    payload.extend(std::iter::repeat_n(0u8, 100));
    payload.extend_from_slice(b"\ntail needle after the nul\n");
    let gz = std::fs::File::create(&path).unwrap();
    let mut enc = flate2::write::GzEncoder::new(gz, flate2::Compression::fast());
    enc.write_all(&payload).unwrap();
    enc.finish().unwrap();
    // the same bytes uncompressed, so the expected count is not a literal
    std::fs::write(dir.join("packed_with_nul.txt"), &payload).unwrap();

    let out = rgx().args(["-c", NEEDLE]).arg(&path).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "2",
        "the NUL inside the decoded payload ate the file"
    );

    // A file the walk turned up, which is where a NUL in the FILE's own bytes
    // is correctly suppressed. The container is not the file, so the payload
    // is still found; `packed_with_nul.txt` sits beside it and must be
    // dropped, which is what makes this a distinction and not a blanket
    // relaxation of the rule.
    let (code, stdout) = run(&dir, &["-c", NEEDLE]);
    let listing: Vec<&str> = stdout.lines().collect();
    assert!(
        listing.iter().any(|l| l.contains("packed_with_nul.gz")),
        "the decompressed payload was dropped on a walk:\n{stdout}"
    );
    assert!(
        !listing.iter().any(|l| l.contains("packed_with_nul.txt")),
        "a binary file on disk must still be suppressed like rg:\n{stdout}"
    );
    assert_eq!(code, 0, "exit status:\n{stdout}");

    std::fs::remove_dir_all(&dir).ok();
}

/// The same shape, on the corpus fixture it was reported from.
///
/// `brotli_big_q11.br` is the reference `brotli` 1.2.0 vector behind
/// `testdata/brotli_README.md`; its payload is `brotli_big.plain` and it is
/// the file `rgx -c hello` reported nothing for. It is committed, so the
/// provenance the README insists on is kept, and the assertion is against the
/// payload rather than a hard-coded count, so it cannot drift with the corpus.
///
/// The archive crate's `every_reference_brotli_stream_through_the_adapter`
/// asserts byte-identity for this very vector and stayed green through the
/// whole defect, because it calls `Decompress.extract` and stops: the loss
/// was downstream of the adapter, in the searcher's choice of binary rule,
/// which only a real `rgx` invocation reaches. That is the gap this test
/// closes, and it is why the assertion is here and not there.
#[test]
fn a_brotli_stream_whose_payload_holds_a_nul_is_found_by_the_real_binary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let testdata = root.join("crates/rgx-adapters-archive/testdata");
    let br = testdata.join("brotli_big_q11.br");
    let plain = testdata.join("brotli_big.plain");
    assert!(
        br.is_file() && plain.is_file(),
        "the corpus fixture moved; this test is the only thing pinning it"
    );

    // The shape, stated rather than assumed: this payload is what carries a
    // NUL, and it is why the fixture set looked adequate and was not.
    let payload = std::fs::read(&plain).unwrap();
    let nul = payload
        .iter()
        .position(|&b| b == 0)
        .expect("no NUL in payload");
    assert!(
        nul < 64 * 1024,
        "a NUL at {nul} is past the window that hid the defect"
    );

    let count = |p: &Path| -> String {
        let out = rgx().args(["-c", "hello"]).arg(p).output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let want = count(&plain);
    assert_eq!(want, "20", "the payload no longer has 20 occurrences");
    assert_eq!(
        count(&br),
        want,
        "the brotli stream must answer the same as its own payload"
    );
}

const NEEDLE_PATTERN: &str = "Registry";

#[test]
fn finds_text_archive_and_mail_attachment() {
    let dir = fixture_dir();
    let (code, stdout) = run(&dir, &[NEEDLE]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("hello.txt"), "stdout:\n{stdout}");
    assert!(stdout.contains("packed.gz!"), "gz member path:\n{stdout}");
    assert!(
        stdout.contains("mail.eml!"),
        "eml attachment path:\n{stdout}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The structured filter: a file the filter rejects is not in the corpus,
/// and a filter that does not parse is an error rather than a filter that
/// matches nothing.
#[test]
fn a_filter_keeps_only_the_files_that_satisfy_it() {
    let dir = fixture_dir();
    let (code, stdout) = run(&dir, &["--filter", "ext:txt", NEEDLE]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("hello.txt"), "stdout:\n{stdout}");
    assert!(!stdout.contains("packed.gz"), "stdout:\n{stdout}");

    // The same search with the other extension finds nothing.
    let (code, stdout) = run(&dir, &["--filter", "ext:zip", NEEDLE]);
    assert_eq!(code, 1, "stdout:\n{stdout}");
    assert!(stdout.trim().is_empty(), "stdout:\n{stdout}");

    // `NOT` and the two facts together.
    let (code, stdout) = run(&dir, &["--filter", "NOT ext:txt", NEEDLE]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(!stdout.contains("hello.txt"), "stdout:\n{stdout}");
    assert!(stdout.contains("packed.gz"), "stdout:\n{stdout}");

    // A filter that does not parse says so.
    let (code, stderr) = run_stderr(&dir, &["--filter", "ext:txt AND", NEEDLE]);
    assert_ne!(code, 0);
    assert!(stderr.contains("invalid --filter"), "stderr:\n{stderr}");
    std::fs::remove_dir_all(&dir).ok();
}

/// The filter over what the adapters know about a file: the facts a
/// predicate matches on are the ones the adapter reported, and the
/// members of a container inherit the container's.
#[test]
fn a_filter_matches_what_the_adapters_know_about_the_file() {
    let dir = fixture_dir();

    // A real PDF, with a real Info dictionary.
    let pdf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/rgx-adapters-pdf/fixtures/reportlab.pdf");
    std::fs::copy(&pdf, dir.join("report.pdf")).unwrap();

    // A model with one tensor.
    let header = r#"{"model.weight":{"dtype":"F32","shape":[2,3],"data_offsets":[0,24]}}"#;
    let mut model = (header.len() as u64).to_le_bytes().to_vec();
    model.extend_from_slice(header.as_bytes());
    model.extend_from_slice(&[0u8; 24]);
    std::fs::write(dir.join("model.safetensors"), &model).unwrap();

    // A source file, for the language its extension says.
    std::fs::write(dir.join("main.rs"), "fn main() { let needle = 1; }\n").unwrap();

    // A photo with a real EXIF block, GPS included.
    let jpg = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/rgx-adapters-media/testdata/exif_sample.jpg");
    std::fs::copy(&jpg, dir.join("photo.jpg")).unwrap();

    // A zip with a python file inside it.
    let mut zipf = zip::ZipWriter::new(std::fs::File::create(dir.join("bundle.zip")).unwrap());
    zipf.start_file::<_, ()>("script.py", zip::write::FileOptions::default())
        .unwrap();
    zipf.write_all(b"import os\nprint('needle')\n").unwrap();
    zipf.finish().unwrap();

    // The PDF, asked for by its type and then by its author.
    let (code, stdout) = run(&dir, &["--filter", "mime:pdf", "segunda"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("report.pdf"), "stdout:\n{stdout}");

    let (code, stdout) = run(&dir, &["--filter", "author:anonymous", "segunda"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("report.pdf"), "stdout:\n{stdout}");

    // A PDF with another author is another file.
    let (code, stdout) = run(&dir, &["--filter", "author:nobody", "segunda"]);
    assert_eq!(code, 1, "stdout:\n{stdout}");

    // The message, asked for by its sender, its subject and its
    // attachments.
    let (code, stdout) = run(&dir, &["--filter", "mail:from:\"lab@example.org\"", NEEDLE]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("mail.eml"), "stdout:\n{stdout}");

    let (code, stdout) = run(&dir, &["--filter", "mail:subject:calibration", NEEDLE]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("mail.eml"), "stdout:\n{stdout}");

    let (code, stdout) = run(&dir, &["--filter", "has:attachments", NEEDLE]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("mail.eml"), "stdout:\n{stdout}");

    // The model, asked for by its tensor.
    let (code, stdout) = run(&dir, &["--filter", "tensor:name", "model.weight"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("model.safetensors"), "stdout:\n{stdout}");

    // The photo, asked for by the GPS it carries and by the camera.
    // The pattern is the camera's own model, which the photo holds and
    // nothing else in the tree does.
    let (code, stdout) = run(&dir, &["--filter", "exif:gps", "RGX-CAM"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("photo.jpg"), "stdout:\n{stdout}");

    let (code, stdout) = run(&dir, &["--filter", "exif:camera", "RGX-CAM"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("photo.jpg"), "stdout:\n{stdout}");

    // The photo is the only file that holds the model, and it has the
    // GPS: denying the GPS denies the file.
    let (code, stdout) = run(&dir, &["--filter", "NOT exif:gps", "RGX-CAM"]);
    assert_eq!(code, 1, "stdout:\n{stdout}");

    // The source file, asked for by its language.
    let (code, stdout) = run(&dir, &["--filter", "lang:rust", NEEDLE]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("main.rs"), "stdout:\n{stdout}");

    // The member of the zip, asked for by the container it is in and by
    // its own language.
    let (code, stdout) = run(&dir, &["--filter", "container:zip", NEEDLE]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("bundle.zip!script.py"), "stdout:\n{stdout}");

    let (code, stdout) = run(&dir, &["--filter", "lang:python", NEEDLE]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("bundle.zip!script.py"), "stdout:\n{stdout}");

    // And the two together, which is the shape the flag is for.
    let (code, stdout) = run(&dir, &["--filter", "container:zip AND lang:python", NEEDLE]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("bundle.zip!script.py"), "stdout:\n{stdout}");

    // A member of a zip is not a file of the tree: asking for the
    // archive's own extension finds nothing, because the unit that is
    // searched is the member.
    let (code, stdout) = run(&dir, &["--filter", "ext:zip", NEEDLE]);
    assert_eq!(code, 1, "stdout:\n{stdout}");

    std::fs::remove_dir_all(&dir).ok();
}

/// Regression: a ZIP renamed to `.bin` used to land on the torch adapter,
/// which listed member *names* without recursing — content was invisible
/// to search. Torch must return Members so the pipeline searches inside.
#[test]
fn zip_renamed_to_bin_is_content_searchable() {
    let dir = fixture_dir();
    let mut zip = std::io::Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut zip);
        let opts: zip::write::SimpleFileOptions = Default::default();
        zw.start_file("note.txt", opts).unwrap();
        zw.write_all(b"hidden needle inside renamed archive\n")
            .unwrap();
        zw.finish().unwrap();
    }
    std::fs::write(dir.join("mystery.bin"), zip.into_inner()).unwrap();

    let (code, stdout) = run(&dir, &[NEEDLE, "mystery.bin"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("mystery.bin!"), "member path:\n{stdout}");
    assert!(stdout.contains("note.txt"), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

/// The new-format wave: hdf5, wasm, blend, 3ds and woff adapters all
/// surface their names through a real binary invocation.
#[test]
fn new_format_adapters_are_searchable() {
    let dir = fixture_dir();
    // hdf5 v2 superblock + a name in the object-header window
    let mut h5 = b"\x89HDF\r\n\x1a\n\x02\x08\x08\x00".to_vec();
    h5.extend_from_slice(&[0u8; 8]); // base + extension addr
    h5.extend_from_slice(&4096u64.to_le_bytes()); // eof
    h5.extend_from_slice(&96u64.to_le_bytes()); // root object header addr
    while h5.len() < 96 {
        h5.push(0);
    }
    h5.extend_from_slice(b"dataset_ZIRCALOY_grid\0");
    std::fs::write(dir.join("data.h5"), h5).unwrap();

    // wasm: header + export section
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    wasm.push(7); // export section
    wasm.push(1 + 1 + 13 + 1 + 1);
    wasm.push(1);
    wasm.push(13);
    wasm.extend_from_slice(b"solve_ZIRCALOY");
    wasm.push(0);
    wasm.push(0);
    std::fs::write(dir.join("m.wasm"), wasm).unwrap();

    // blend: header + one OB block + ENDB
    let mut blend = b"BLENDER-v293".to_vec();
    let body = {
        let mut b = vec![0u8; 32];
        b.extend_from_slice(b"Cube_ZIRCALOY\0");
        b
    };
    blend.extend_from_slice(b"OB\0\0");
    blend.extend_from_slice(&(body.len() as u32).to_le_bytes());
    blend.extend_from_slice(&[0u8; 8]);
    blend.extend_from_slice(&0u32.to_le_bytes());
    blend.extend_from_slice(&1u32.to_le_bytes());
    blend.extend_from_slice(&body);
    blend.extend_from_slice(b"ENDB");
    blend.extend_from_slice(&[0u8; 16]);
    std::fs::write(dir.join("s.blend"), blend).unwrap();

    // 3ds: 4D4D main chunk with a 4000 object chunk
    let mut obj = Vec::new();
    obj.extend_from_slice(&0x4000u16.to_le_bytes());
    obj.extend_from_slice(&((6 + 14 + 1 + 6) as u32).to_le_bytes());
    obj.extend_from_slice(b"turbine_ZIRCALOY");
    obj.push(0);
    obj.extend_from_slice(&0x4100u16.to_le_bytes());
    obj.extend_from_slice(&6u32.to_le_bytes());
    let mut ds = 0x4D4Du16.to_le_bytes().to_vec();
    ds.extend_from_slice(&((6 + obj.len()) as u32).to_le_bytes());
    ds.extend_from_slice(&obj);
    std::fs::write(dir.join("m.3ds"), ds).unwrap();

    // woff2: header + custom-tag directory entry (flags 63 = raw 4-byte tag)
    let mut woff2 = b"wOF2".to_vec();
    woff2.extend_from_slice(b"OTTO");
    woff2.extend_from_slice(&49u32.to_be_bytes());
    woff2.extend_from_slice(&1u16.to_be_bytes());
    woff2.extend_from_slice(&0u16.to_be_bytes());
    for _ in 0..8 {
        woff2.extend_from_slice(&0u32.to_be_bytes());
    }
    woff2.push(63); // custom tag follows
    woff2.extend_from_slice(b"ZIRC");
    woff2.push(120); // UIntBase128 length
    std::fs::write(dir.join("f.woff2"), woff2).unwrap();

    let (code, stdout) = run(&dir, &["ZIR"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    for f in ["data.h5", "m.wasm", "s.blend", "m.3ds", "f.woff2"] {
        assert!(stdout.contains(f), "{f} missing:\n{stdout}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn no_match_exits_one() {
    let dir = fixture_dir();
    let (code, stdout) = run(&dir, &["term-that-does-not-exist"]);
    assert_eq!(code, 1, "stdout:\n{stdout}");
    assert!(stdout.is_empty(), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn json_reports_adapter_provenance() {
    let dir = fixture_dir();
    let file = dir.join("hello.txt");
    let out = rgx()
        .args(["--json", NEEDLE])
        .arg(&file)
        .output()
        .expect("failed to spawn rgx");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"adapter\":\"raw\""), "stdout:\n{stdout}");
    assert!(stdout.contains("\"submatches\":["), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn binary_match_counts_but_prints_no_lines() {
    let dir = fixture_dir();
    let bin = dir.join("blob.bin");

    // Not silence. rg prints one line saying the file is binary and where
    // the NUL was, and the two are different answers: a binary file that
    // matched and a binary file that did not used to look the same. The
    // LINES are still suppressed, which is what this test is named for.
    let out = rgx().args([NEEDLE]).arg(&bin).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains(NEEDLE),
        "binary line output must be suppressed: {stdout}"
    );
    assert!(
        stdout.contains("binary file matches"),
        "and rg says which file and where the NUL was: {stdout}"
    );

    let out = rgx().args(["-l", NEEDLE]).arg(&bin).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("blob.bin"));

    let out = rgx().args(["-c", NEEDLE]).arg(&bin).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1");

    let out = rgx().args(["-a", NEEDLE]).arg(&bin).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("needle"));
    std::fs::remove_dir_all(&dir).ok();
}

fn run_stdin(args: &[&str], input: &[u8]) -> (i32, String) {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = rgx()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn rgx");
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn stdin_is_searched_when_piped() {
    let (code, stdout) = run_stdin(&[NEEDLE], b"hello needle from stdin\nno hit here\n");
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(
        stdout.contains("hello needle from stdin"),
        "stdout:\n{stdout}"
    );
    assert!(!stdout.contains("no hit here"), "stdout:\n{stdout}");

    // explicit '-' path selects stdin as well
    let (code, stdout) = run_stdin(&[NEEDLE, "-"], b"needle via dash\n");
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("needle via dash"), "stdout:\n{stdout}");

    // no match on the stream -> exit 1
    let (code, _) = run_stdin(&["zzz-no-match"], b"nothing to see\n");
    assert_eq!(code, 1);
}

/// `rgx PATTERN` with no path searches the current directory unless stdin is
/// something to search. `!is_terminal()` answered "read stdin" for the NUL
/// device and for an inherited console handle as well as for a pipe, so a
/// script or a CI step got "no matches" where `rg PATTERN` walked the tree.
/// rg's question is "is the handle a pipe or a file", and so is
/// `readable_stdin` in `src/main.rs`.
#[test]
fn no_path_searches_the_directory_when_stdin_is_not_input() {
    let dir = fixture_dir();
    // Stdio::null() is the CI case: a handle that is open, empty, and is not
    // a pipe. Before this, rgx read it and reported no matches at all.
    let out = rgx()
        .arg(NEEDLE)
        .current_dir(&dir)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to spawn rgx");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(0), "stdout:\n{stdout}");
    assert!(stdout.contains("hello needle world"), "stdout:\n{stdout}");

    // An empty pipe IS input: it is searched, finds nothing, exits 1. The
    // two cases are the same `is_terminal` answer and different answers here.
    let (code, stdout) = run_stdin(&[NEEDLE], b"");
    assert_eq!(code, 1, "an empty pipe is stdin, not a walk: {stdout}");
    assert!(stdout.is_empty(), "{stdout}");

    std::fs::remove_dir_all(&dir).ok();
}

/// `-M 0` is a legal limit -- rg answers it by skipping every non-empty
/// file -- and it used to reach `set_budget`'s `assert!(bytes >= 1)` and
/// abort with a panic. A zero limit is enforced entirely by the walk, which
/// compares it against the file length, so no producer budget is involved.
#[test]
fn max_filesize_zero_is_a_limit_not_a_panic() {
    let dir = fixture_dir();
    let out = rgx()
        .args(["-M", "0", "-l", NEEDLE])
        .arg(&dir)
        .output()
        .expect("failed to spawn rgx");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!stderr.contains("panicked"), "stderr:\n{stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        stdout.is_empty(),
        "every file is over a 0-byte cap:\n{stdout}"
    );
    assert_eq!(out.status.code(), Some(1), "stderr:\n{stderr}");
    std::fs::remove_dir_all(&dir).ok();
}

/// A bad `-M` names the input and the shape it wanted, and reports itself as
/// an error rather than as a search that matched nothing. The raw parse error
/// ("cannot parse float from empty string") described the split the parser
/// made of `huge`, not anything the user typed.
#[test]
fn bad_max_filesize_says_what_a_size_looks_like() {
    for bad in ["huge", ""] {
        let out = rgx()
            .args(["-M", bad, NEEDLE])
            .stdin(std::process::Stdio::null())
            .output()
            .expect("failed to spawn rgx");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(stderr.contains("invalid size"), "-M {bad:?}: {stderr}");
        assert!(stderr.contains("100K"), "-M {bad:?}: {stderr}");
        assert_eq!(
            out.status.code(),
            Some(2),
            "-M {bad:?} is an error, not a miss: {stderr}"
        );
    }
}

/// Every error path exits 2, as rg does and as AGENTS.md promises. Returning
/// the error from `main` exited 1, which is the status a script reads as
/// "searched and found nothing" -- so `rgx` with no arguments looked like a
/// miss rather than a usage error.
#[test]
fn errors_exit_two_and_not_the_miss_status() {
    let no_args = rgx()
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to spawn rgx");
    let stderr = String::from_utf8_lossy(&no_args.stderr).into_owned();
    assert!(stderr.contains("no pattern given"), "stderr:\n{stderr}");
    assert_eq!(no_args.status.code(), Some(2), "stderr:\n{stderr}");

    // ... while a real miss keeps its 1. It runs in an empty fixture: with
    // no path the search covers the working directory, and the pattern below
    // is spelled out in this very file.
    let dir = fixture_dir();
    let miss = rgx()
        .args(["zzz-no-match-here"])
        .current_dir(&dir)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("failed to spawn rgx");
    assert_eq!(miss.status.code(), Some(1));
    std::fs::remove_dir_all(&dir).ok();
}

/// Flags whose help names a closed set of values reject anything outside it,
/// the way `--engine` and `--completions` already did. Silently accepting
/// `--color purple` made it resolve to "never" with nothing saying so.
#[test]
fn closed_value_sets_are_validated() {
    for (flag, value, want) in [
        ("--color", "purple", "auto, always, ansi, never"),
        ("--sort", "size", "path"),
        ("--sortr", "size", "path"),
        ("-E", "utf-32", "utf-8, utf-16le, utf-16be"),
    ] {
        let out = rgx()
            .args([flag, value, NEEDLE])
            .stdin(std::process::Stdio::null())
            .output()
            .expect("failed to spawn rgx");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(stderr.contains("Invalid value"), "{flag} {value}: {stderr}");
        assert!(stderr.contains(want), "{flag} {value}: {stderr}");
        assert_eq!(out.status.code(), Some(2), "{flag} {value}: {stderr}");
    }
}

#[test]
fn invert_match_selects_non_matching_lines() {
    let dir = fixture_dir();
    let (code, stdout) = run(&dir, &["-v", NEEDLE]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("second line"), "stdout:\n{stdout}");
    assert!(!stdout.contains("hello needle world"), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn max_count_stops_after_num_matches() {
    let dir = fixture_dir();
    std::fs::write(
        dir.join("multi.txt"),
        "needle one\nneedle two\nneedle three\nnone\n",
    )
    .unwrap();
    let (code, stdout) = run(&dir, &["-m", "2", NEEDLE, "multi.txt"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("needle one"), "stdout:\n{stdout}");
    assert!(stdout.contains("needle two"), "stdout:\n{stdout}");
    assert!(!stdout.contains("needle three"), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn only_matching_prints_match_text() {
    let dir = fixture_dir();
    let file = dir.join("hello.txt");
    let out = rgx().args(["-o", NEEDLE]).arg(&file).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), NEEDLE);

    // -o -r prints each replaced match on its own line
    let out = rgx()
        .args(["-o", "-r", "pin", NEEDLE])
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "pin");
    std::fs::remove_dir_all(&dir).ok();
}
/// grep-searcher hands back the line terminator as part of the line, and
/// the printer adds its own with writeln!. The two together put a blank
/// line between every result, and doubled the newline inside the JSON
/// `text` field, which appends one of its own. Both are invisible to a
/// test that trims or uses `contains`, so the bytes are pinned here.
#[test]
fn output_lines_carry_exactly_one_terminator() {
    let dir = fixture_dir();
    let file = dir.join("hello.txt");
    let out = rgx().args([NEEDLE]).arg(&file).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout, "hello needle world\n", "one match, one newline");

    // Two matches on separate lines must not be separated by a blank one.
    let two = dir.join("two.txt");
    std::fs::write(&two, "needle one\nneedle two\n").unwrap();
    let out = rgx().args([NEEDLE]).arg(&two).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "needle one\nneedle two\n",
        "no blank line between matches"
    );

    // CRLF input is one terminator, not a stray carriage return.

    // And the JSON text field, which appends a newline of its own, so a
    // surviving terminator would show up here as a doubled escape.
    let out = rgx().args(["--json", NEEDLE]).arg(&file).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.contains("\"type\":\"match\""))
        .unwrap();
    assert!(
        line.contains(r#""text":"hello needle world\n""#),
        "json text must hold exactly one newline: {line}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// `-n` was missing from the grammar, so `rgx -n pattern` died with
/// "Unknown argument" while the output printed line numbers anyway --
/// there was no way to ask for them and no way to turn them off.
#[test]
fn line_numbers_follow_the_rg_default_and_both_flags() {
    let dir = fixture_dir();
    let file = dir.join("hello.txt");
    // hello.txt holds: first line, then the needle line, then second line

    // One explicit file, output captured rather than a terminal: no number.
    let out = rgx().args([NEEDLE]).arg(&file).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.trim(),
        "hello needle world",
        "piped single file: {stdout}"
    );

    // -n asks for it.
    let out = rgx().args(["-n", NEEDLE]).arg(&file).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "1:hello needle world"
    );

    // --line-number is the same flag, spelled out.
    let out = rgx()
        .args(["--line-number", NEEDLE])
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "1:hello needle world"
    );

    // A directory is still not a terminal: rg shows no number, and the
    // path prefix is what tells the files apart. Checked against
    // ripgrep 15 rather than assumed -- "several files implies numbers"
    // is the intuitive rule and it is the wrong one.
    let out = rgx().args([NEEDLE]).arg(&dir).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello.txt:hello needle world"),
        "a piped directory search has no line numbers: {stdout}"
    );

    // -n turns them on there too, path and number together.
    let out = rgx().args(["-n", NEEDLE]).arg(&dir).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello.txt:1:hello needle world"),
        "-n applies to a directory search: {stdout}"
    );

    // --no-line-number takes them back off.
    let out = rgx()
        .args(["-n", "--no-line-number", NEEDLE])
        .arg(&dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello.txt:hello needle world"),
        "--no-line-number must win over -n: {stdout}"
    );

    // --no-line-number wins over -n, so a script can switch the number
    // off without knowing what the default would have been.
    let out = rgx()
        .args(["-n", "--no-line-number", NEEDLE])
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "hello needle world"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn replace_substitutes_match_text() {
    let dir = fixture_dir();
    let file = dir.join("hello.txt");
    let out = rgx()
        .args(["-r", "pin", NEEDLE])
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("hello pin world"), "stdout:\n{stdout}");
    assert!(!stdout.contains("needle"), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn files_without_match_lists_them() {
    let dir = fixture_dir();
    // Long-only, as in ripgrep 15: rg moved `--follow` onto `-L` and left
    // `--files-without-match` without a short form. This test used to pass
    // `-L`; the flag it was fixing was the flag that was wrong.
    // "second line" only exists in hello.txt — everything else must be listed
    let (code, stdout) = run(&dir, &["--files-without-match", "second line"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(!stdout.contains("hello.txt"), "stdout:\n{stdout}");
    assert!(stdout.contains("mail.eml"), "stdout:\n{stdout}");
    // blob.bin is NOT listed, and used to be. A binary file the walk turned
    // up is skipped rather than reported as a miss: rg suppresses it before
    // it is ever a candidate, so there is no "no match" to list. Counting it
    // as a miss made `--files-without-match` on any tree containing a binary
    // file enumerate every one of them. See
    // `a_binary_file_found_by_the_walk_is_suppressed_like_rg`.
    assert!(!stdout.contains("blob.bin"), "stdout:\n{stdout}");

    // pattern nowhere at all -> every file listed
    let (code, stdout) = run(&dir, &["--files-without-match", "zzz-no-such-term"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("hello.txt"), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

/// `-L` means `--follow`, and `--files-without-match` has no short flag.
///
/// rgx read `-L` as `--files-without-match`, which ripgrep has not meant
/// since 14: rg 14 moved `--follow` onto `-L`, and rg 15 — the version this
/// project measures itself against — takes `--files-without-match` as a long
/// flag only. The old reading was pinned by a committed test
/// (`files_without_match_lists_them`), which is what made the divergence
/// look like a choice: a test that pins a spelling ripgrep abandoned is a
/// wrong behaviour written down as a test. The flag audit is what found it,
/// and that test now asks for the long spelling.
///
/// Checked against ripgrep 15.0.0 rather than asserted from the grammar. The
/// fixture tree has no symlinks, so `--follow` is a no-op here on purpose:
/// what is pinned is which flag `-L` reaches, and both tools have to answer
/// that the same way.
#[test]
fn dash_capital_l_is_follow_and_files_without_match_is_long_only() {
    let dir = fixture_dir();
    // A plain-text tree, so the comparison is about the flag and not about
    // rgx's adapters: rgx searches inside the `.eml` and the `.gz`, which is
    // the documented product difference, and it would show up here as a
    // difference in *which files matched* rather than in what `-L` means.
    let plain = dir.join("plain");
    std::fs::create_dir_all(&plain).unwrap();
    std::fs::write(plain.join("hit.txt"), "needle here\n").unwrap();
    std::fs::write(plain.join("miss.txt"), "nothing to see here\n").unwrap();

    let norm = |s: &str| -> Vec<String> {
        let mut v: Vec<String> = s
            .replace('\\', "/")
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        v.sort();
        v
    };
    let theirs = |args: &[&str]| {
        Command::new("rg")
            .args(args)
            .arg(&plain)
            .output()
            .expect("ripgrep must be installed: tests/cli.rs is a parity suite")
    };
    let mine = |args: &[&str]| {
        norm(&String::from_utf8_lossy(
            &rgx().args(args).arg(&plain).output().unwrap().stdout,
        ))
    };

    // `-L` is --follow for both.
    let followed = mine(&["-L", NEEDLE]);
    assert!(!followed.is_empty(), "rgx -L printed nothing");
    assert_eq!(
        followed,
        norm(&String::from_utf8_lossy(&theirs(&["-L", NEEDLE]).stdout)),
        "rgx -L disagrees with rg 15's -L"
    );
    assert!(
        followed.iter().any(|l| l.contains("hit.txt")),
        "-L must still find the matching file: {followed:?}"
    );

    // --files-without-match is long-only in rg 15, and rgx agrees on both
    // halves: the long flag works, and the two tools list the same files.
    let without = mine(&["--files-without-match", NEEDLE]);
    assert_eq!(
        without,
        vec![format!("{}/miss.txt", plain.display()).replace('\\', "/")]
    );
    assert_eq!(
        without,
        norm(&String::from_utf8_lossy(
            &theirs(&["--files-without-match", NEEDLE]).stdout
        )),
        "rgx --files-without-match disagrees with rg 15"
    );

    // And `-L` is no longer that other flag: it prints matches, not the file
    // that lacks them.
    assert_ne!(
        without, followed,
        "-L is still reading as --files-without-match"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn files_lists_searchable_files() {
    let dir = fixture_dir();
    let (code, stdout) = run(&dir, &["--files"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    for f in ["hello.txt", "mail.eml", "blob.bin", "packed.gz"] {
        assert!(stdout.contains(f), "missing {f}:\n{stdout}");
    }

    // globs apply to listings too
    let (code, stdout) = run(&dir, &["--files", "-g", "*.gz"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("packed.gz"), "stdout:\n{stdout}");
    assert!(!stdout.contains("hello.txt"), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

/// Document with one match in the middle paragraph, far paragraphs around
/// it — the chunk must cover the match paragraph but not the far ones.
fn paragraph_fixture(dir: &Path) -> PathBuf {
    let para_a: String = "lorem ipsum dolor sit amet consectetur. ".repeat(5); // ~200 chars
    let para_b = "the middle paragraph holds the needle value and some trailing words\n";
    let para_c: String = "ZEBRA distant paragraph that must not leak into the chunk. ".repeat(4);
    let doc = format!("{para_a}\n\n{para_b}\n\n{para_c}\n");
    let p = dir.join("doc.txt");
    std::fs::write(&p, doc).unwrap();
    p
}

#[test]
fn chunk_mode_emits_paragraph_window() {
    let dir = fixture_dir();
    let doc = paragraph_fixture(&dir);
    let out = rgx()
        .args(["--chunk", "160", NEEDLE])
        .arg(&doc)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("=== "), "header:\n{stdout}");
    assert!(stdout.contains("needle value"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("middle paragraph"),
        "context missing:\n{stdout}"
    );
    assert!(!stdout.contains("ZEBRA"), "far paragraph leaked:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn chunk_mode_merges_nearby_matches() {
    let dir = fixture_dir();
    let p = dir.join("near.txt");
    std::fs::write(&p, "needle one and needle two in the same paragraph\n").unwrap();
    let out = rgx()
        .args(["--chunk", "400", NEEDLE])
        .arg(&p)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.matches("=== ").count(), 1, "must merge:\n{stdout}");

    // -c still reports the match count in chunk mode (rg: lines, not hits)
    let out = rgx()
        .args(["-c", "--chunk", "400", NEEDLE])
        .arg(&p)
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn chunk_mode_respects_max_count() {
    let dir = fixture_dir();
    let filler = "x".repeat(300);
    let p = dir.join("spread.txt");
    std::fs::write(&p, format!("needle first\n{filler}\nneedle second\n")).unwrap();
    let out = rgx()
        .args(["-m", "1", "--chunk", "80", NEEDLE])
        .arg(&p)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.matches("=== ").count(),
        1,
        "one chunk only:\n{stdout}"
    );
    assert!(stdout.contains("needle first"), "stdout:\n{stdout}");
    assert!(!stdout.contains("needle second"), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn chunk_mode_works_on_stdin() {
    let (code, stdout) = run_stdin(
        &["--chunk", "64", NEEDLE],
        b"intro\n\nneedle from the pipe\n\noutro\n",
    );
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("=== <stdin>:"), "stdout:\n{stdout}");
    assert!(stdout.contains("needle from the pipe"), "stdout:\n{stdout}");
}

/// A match sitting in a single line longer than the chunk budget must not
/// drag the whole line into the chunk. `build_chunks` cuts to a paragraph,
/// then to a line boundary, then hard at the budget edge -- and that third
/// cut is the only one that can fire here, because there is no earlier line
/// and no blank line to snap to. Without it a one-line multi-megabyte file
/// would emit the entire file around one match.
#[test]
fn chunk_mode_hard_cuts_a_single_line_longer_than_the_budget() {
    let dir = fixture_dir();
    let p = dir.join("oneline.txt");
    // One line of 4000 bytes with the needle in the middle, no blank lines
    // and no terminator until the very end.
    let mut s = "x".repeat(2000);
    s.push_str(NEEDLE);
    s.push_str(&"y".repeat(1990));
    std::fs::write(&p, &s).unwrap();

    let out = rgx()
        .args(["--chunk", "200", NEEDLE])
        .arg(&p)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(NEEDLE),
        "the match must be in the chunk:\n{stdout}"
    );
    // The chunk body is the text between the `===` headers. It must be
    // bounded by the budget (200) plus the two header lines, nowhere near
    // the 4000-byte line.
    let body: String = stdout
        .lines()
        .skip(1)
        .filter(|l| !l.starts_with("=== "))
        .collect();
    assert!(
        body.len() < 400,
        "the chunk was not hard-cut: {} bytes of body for a 200-byte budget",
        body.len()
    );
    assert!(
        !stdout.contains(&"x".repeat(200)),
        "the whole line leaked:\n{stdout}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn serve_mode_answers_queries_until_eof() {
    let dir = fixture_dir();
    // JSON argv-array queries, one per line; forward-slash the path so the
    // JSON needs no backslash escaping
    let d = dir.display().to_string().replace('\\', "/");
    let queries = format!(
        "[\"{NEEDLE}\", \"{d}\"]\n\
         [\"zzz-no-match-xyz\", \"{d}\"]\n\
         this is not json\n\
         [\"{NEEDLE}\"]\n"
    );

    let dir = fixture_dir();
    let mut child = rgx()
        .arg("--serve")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn rgx --serve");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(queries.as_bytes())
        .unwrap();
    // closing stdin ends the daemon
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"rgx\":\"ready\""), "stdout:\n{stdout}");
    // query 1: match -> status 0, result lines framed between begin and end
    assert!(
        stdout.contains("\"rgx\":\"begin\",\"seq\":1"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("\"rgx\":\"end\",\"seq\":1")
            && stdout.contains("\"status\":0,\"matched\":true"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("hello needle world"), "stdout:\n{stdout}");
    // query 2: no match -> status 1
    assert!(
        stdout.contains("\"rgx\":\"end\",\"seq\":2")
            && stdout.contains("\"status\":1,\"matched\":false"),
        "stdout:\n{stdout}"
    );
    // query 3: invalid JSON -> status 2 with an error message
    assert!(
        stdout.contains("\"rgx\":\"end\",\"seq\":3") && stdout.contains("\"status\":2"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("invalid JSON query"), "stdout:\n{stdout}");
    // query 4: no paths would mean stdin search, rejected in serve mode
    assert!(
        stdout.contains("\"rgx\":\"end\",\"seq\":4") && stdout.contains("\"status\":2"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("stdin"), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

/// The MCP server, through the real binary: JSON-RPC 2.0 on stdin, one
/// object per line, answers on stdout.
///
/// The unit tests in `crates/rgx-core/src/mcp.rs` cover the protocol
/// layer in the crate. This one covers the thing a client actually
/// spawns: that `rgx --mcp` reads the protocol off stdin, answers on
/// stdout, and does not print anything of its own in between.
#[test]
fn mcp_mode_answers_the_protocol_over_stdio() {
    let dir = fixture_dir();
    let d = dir.display().to_string().replace('\\', "/");
    let requests = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{}}}}\n\
         {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}}\n\
         {{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{{\"name\":\"search\",\"arguments\":{{\"pattern\":\"{NEEDLE}\",\"path\":\"{d}\"}}}}}}\n\
         {{not json\n\
         {{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"no/such/method\"}}\n"
    );
    let mut child = rgx()
        .arg("--mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn rgx --mcp");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(requests.as_bytes())
        .unwrap();
    // closing stdin ends the server
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    // The notification produced no line; the other five produced one each.
    assert_eq!(lines.len(), 5, "stdout:\n{stdout}");
    // every answer is a JSON-RPC object
    for line in &lines {
        assert!(
            line.starts_with("{\"jsonrpc\":\"2.0\","),
            "the answer is not a JSON-RPC object: {line}"
        );
    }
    assert!(stdout.contains("\"protocolVersion\""), "stdout:\n{stdout}");
    assert!(stdout.contains("\"serverInfo\""), "stdout:\n{stdout}");
    assert!(stdout.contains("\"name\":\"search\""), "stdout:\n{stdout}");
    assert!(stdout.contains("\"name\":\"facts\""), "stdout:\n{stdout}");
    assert!(stdout.contains(NEEDLE), "stdout:\n{stdout}");
    // the broken line is answered with a parse error, and the session
    // carries on: the method after it is still answered
    assert!(stdout.contains("\"code\":-32700"), "stdout:\n{stdout}");
    assert!(stdout.contains("\"code\":-32601"), "stdout:\n{stdout}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mcp_mode_refuses_a_query_of_its_own() {
    let out = rgx()
        .args(["--mcp", "pattern", "somepath"])
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--mcp"), "stderr:\n{stderr}");
    assert!(stderr.contains("stdin"), "stderr:\n{stderr}");
}

#[test]
fn help_never_resurrects_the_old_tagline() {
    // "rg extended" was retired from every description surface; the clippy
    // gate can't see string literals, so this pins the user-visible ones.
    // Extend BANNED as new stale phrases appear.
    const BANNED: &[&str] = &["rg extended", "rg extended:"];
    for flag in ["--help", "--version", "-h"] {
        let out = rgx().arg(flag).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        for phrase in BANNED {
            assert!(
                !stdout.contains(phrase),
                "`rgx {flag}` stdout resurrected banned phrase {phrase:?}:\n{stdout}"
            );
            assert!(
                !stderr.contains(phrase),
                "`rgx {flag}` stderr resurrected banned phrase {phrase:?}:\n{stderr}"
            );
        }
    }
}

/// A context line is not a match line, and rg says so twice: the colon
/// after the path becomes a dash, and the number is joined the same way.
///
/// This needs more than one file, because with a single file there is
/// no path and the shape that is wrong is invisible. Every -A/-B/-C
/// printer -- plain, -o and -r -- went through the same helper.
#[test]
fn context_lines_dash_where_matches_colon() {
    let dir = fixture_dir();
    std::fs::write(dir.join("a.txt"), format!("{NEEDLE}\nafter\n")).unwrap();
    std::fs::write(dir.join("b.txt"), format!("{NEEDLE}\nafter\n")).unwrap();

    // With -n the context line is `a.txt-2-after`; without it, the
    // number is gone and only the path's dash remains.
    let cases: &[(&[&str], &str)] = &[
        (&["-A1", "-n", NEEDLE], "a.txt-2-after"),
        (&["-A1", NEEDLE], "a.txt-after"),
        (&["-A1", "-o", "-n", NEEDLE], "a.txt-2-after"),
        (&["-A1", "-r", "P", "-n", NEEDLE], "a.txt-2-after"),
    ];
    for (args, expect) in cases {
        let out = rgx().args(*args).arg(&dir).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(expect),
            "context line should look like {expect}, args {args:?}:
{stdout}"
        );
        // The match line, by contrast, keeps its colon -- whatever -r
        // put there in place of the match.
        assert!(
            stdout.lines().any(|l| l.contains("a.txt:")),
            "match line must colon the path, args {args:?}:
{stdout}"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// `-N` is ripgrep's short form of `--no-line-number`. Adding the long
/// flag alone left `rgx -N` failing with exactly the "Unknown argument"
/// that adding -n was meant to end.
#[test]
fn short_form_of_no_line_number_is_accepted() {
    let dir = fixture_dir();
    let file = dir.join("hello.txt");
    let out = rgx().args(["-N", NEEDLE]).arg(&file).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "hello needle world"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Four divergences from rg that an adversarial pass found, each checked
/// against ripgrep 15 rather than assumed.
#[test]
fn matches_rg_on_separator_o_count_inverted_only_and_binary() {
    let dir = fixture_dir();
    let nl = format!("{}", '\n');

    // Two matches seven lines apart, so the after-context groups do not
    // touch and rg has a group to separate.
    let gap = dir.join("gap.txt");
    let gap_text = [NEEDLE, "1", "2", "3", "4", "5", NEEDLE].join(&nl) + &nl;
    std::fs::write(&gap, &gap_text).unwrap();

    // One line with two matches plus a second line: -o -c counts three.
    let two = dir.join("two.txt");
    let two_text = format!("a {0} b {0} c{1}plain line{1}{0}{1}", NEEDLE, nl);
    std::fs::write(&two, &two_text).unwrap();

    // A NUL before the match, under a name no adapter claims.
    let bin = dir.join("noext");
    let mut bytes = format!("head{0}", nl).into_bytes();
    bytes.push(0);
    bytes.extend_from_slice(format!("binary{0}{1}", NEEDLE, nl).as_bytes());
    std::fs::write(&bin, &bytes).unwrap();

    // rg puts `--` between context groups that are not contiguous.
    let out = rgx()
        .args(["-A", "1", "-n", NEEDLE])
        .arg(&gap)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let want = format!("1:{0}{1}2-1{1}--{1}7:{0}{1}", NEEDLE, nl);
    assert_eq!(stdout, want, "group separator");

    // And none when no context flag asked about one.
    let out = rgx().args(["-n", NEEDLE]).arg(&gap).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("--"),
        "no separator without context: {stdout}"
    );

    // -o -c counts matches; counting lines said two where rg says three.
    let out = rgx().args(["-o", "-c", NEEDLE]).arg(&two).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "3");

    // -v -o prints the non-matching lines instead of nothing at all.
    let out = rgx().args(["-v", "-o", NEEDLE]).arg(&two).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "plain line", "-v -o: {stdout}");

    // A NUL suppresses line output, not the count. The old head sniff
    // searched only the prefix before the first NUL, so a match after it
    // counted zero and `-l` listed nothing.
    let out = rgx().args(["-c", NEEDLE]).arg(&bin).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "1",
        "binary count"
    );
    let out = rgx().args(["-l", NEEDLE]).arg(&bin).output().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("noext"),
        "binary listing"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A NUL past the head sniff used to delete the rest of a file the user named.
///
/// The sniff that decides "this file is binary" reads the first 64 KiB, which
/// is where ripgrep's own detection window sits, and rgx used it as the WHOLE
/// of the decision. So a NUL at byte 100,000 read as "not binary", the file
/// went to the ordinary `quit` searcher, and every match after the NUL was
/// dropped: `rg -c` said 200 and rgx said 0.
///
/// ripgrep does not do that. `BinaryDetection::from_low_args` (ripgrep 15.0.0)
/// gives `convert` for a path named on the command line and `quit` for one the
/// walk turned up, and `convert` keeps going past the NUL while still
/// reporting where the binary data began. The count is the whole file; the
/// line output is suppressed. This is that rule, on both halves.
#[test]
fn a_nul_past_the_sniff_window_still_counts_the_whole_named_file() {
    let dir = fixture_dir();
    let path = dir.join("late.dat");

    // 200 lines, then a NUL well past 64 KiB, then 200 more. Every line has
    // the needle, so the count is 400 whether or not the tail was searched.
    let nl = "
";
    let mut bytes = Vec::new();
    for i in 0..200 {
        bytes.extend_from_slice(format!("head {i} {NEEDLE}{nl}").as_bytes());
    }
    bytes.resize(80 * 1024, b'x');
    let cut = bytes.len();
    bytes.push(0);
    for i in 0..200 {
        bytes.extend_from_slice(format!("tail {i} {NEEDLE}{nl}").as_bytes());
    }
    assert!(cut > 64 * 1024, "the NUL has to be past the sniff window");
    std::fs::write(&path, &bytes).unwrap();

    let out = rgx().args(["-c", NEEDLE]).arg(&path).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "400",
        "the matches after the NUL were dropped"
    );

    // `-l` and the exit status follow the count, as they do for rg.
    let out = rgx().args(["-l", NEEDLE]).arg(&path).output().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("late.dat"),
        "-l dropped a file rg lists"
    );
    let out = rgx().args([NEEDLE]).arg(&path).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "exit status");

    // But the line output is still suppressed: the file is binary and rg
    // prints no lines for it either.
    let out = rgx().args([NEEDLE]).arg(&path).output().unwrap();
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains(NEEDLE),
        "line output for a binary file is not rg's behaviour"
    );

    // `-a` is `--text`, and there the lines are what rg prints.
    let out = rgx().args(["-a", NEEDLE]).arg(&path).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.contains(NEEDLE))
            .count(),
        400,
        "-a lost lines"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// The one line rg prints INSTEAD of the lines of a binary file that matched.
///
/// rgx printed nothing at all, which is a different answer and a worse one:
/// `rgx PATTERN some.dat` and `rgx PATTERN some.txt` were both silent, and
/// only one of them had nothing to say. rg's sentence is
/// `write_binary_message` in `printer/src/standard.rs`, and the wording and
/// the offset are its.
#[test]
fn a_matched_binary_file_says_so_instead_of_saying_nothing() {
    let dir = fixture_dir();
    let nl = "
";
    let mut body = Vec::new();
    for i in 0..200 {
        body.extend_from_slice(format!("line {i} {NEEDLE}{nl}").as_bytes());
    }
    let cut = body.len() / 2;
    let mut bytes = body.clone();
    bytes.insert(cut, 0);
    let path = dir.join("blob.dat");
    std::fs::write(&path, &bytes).unwrap();

    let out = rgx().arg(NEEDLE).arg(&path).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let want = format!(
        r#"binary file matches (found "\0" byte around offset {})"#,
        cut
    );
    assert_eq!(stdout.trim(), want, "not rg's sentence: {stdout}");
    // A single file is not multi, so there is no path in front of it.
    assert!(
        !stdout.contains("blob.dat"),
        "path leaked into the sentence"
    );

    // With two files the path is back, and rg separates it with a space.
    let other = dir.join("other.dat");
    std::fs::write(&other, &bytes).unwrap();
    let out = rgx().arg(NEEDLE).arg(&path).arg(&other).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.lines().count(),
        2,
        "one line per file:
{stdout}"
    );
    for line in stdout.lines() {
        assert!(
            line.contains(": binary file matches ("),
            "missing the space rg puts after the path: {line}"
        );
    }

    // `-a` is `--text`, and there the lines are what both print.
    let out = rgx().args(["-a", NEEDLE]).arg(&path).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).lines().count(),
        200,
        "-a should print the lines"
    );

    // `-c` and `-l` are the count and the listing, and the sentence is not
    // either of them.
    let out = rgx().args(["-c", NEEDLE]).arg(&path).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "200");
    let out = rgx().args(["-l", NEEDLE]).arg(&path).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("blob.dat"));

    std::fs::remove_dir_all(&dir).ok();
}

/// Every generator target a user can ask for, run as the real binary.
/// The flag list is not written out here — it is read back out of
/// `--help`, so a flag added to the argument table has to be in the
/// generated scripts or this goes red.
#[test]
fn completions_cover_every_flag_the_help_lists() {
    let help = rgx().arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout).to_string();

    let mut flags: Vec<String> = Vec::new();
    for line in help.lines() {
        let trimmed = line.trim_start();
        for token in trimmed.split(|c: char| c == ',' || c.is_whitespace()) {
            if let Some(long) = token.strip_prefix("--") {
                if !long.is_empty() && long.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    flags.push(format!("--{long}"));
                }
            }
        }
    }
    // `--help` itself, and the usage line's `--files`; both are real.
    assert!(
        flags.len() > 30,
        "parsed only {} flags from help",
        flags.len()
    );

    for shell in ["bash", "zsh", "fish", "powershell"] {
        let out = rgx().args(["--completions", shell]).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{shell} exit");
        let script = String::from_utf8_lossy(&out.stdout);
        assert!(!script.is_empty(), "{shell} produced nothing");
        for flag in &flags {
            let token = if shell == "fish" {
                flag.trim_start_matches('-').to_string()
            } else {
                flag.clone()
            };
            assert!(
                script.contains(&token),
                "{shell} completion is missing {flag}"
            );
        }
    }
}

#[test]
fn a_shell_it_cannot_generate_is_an_error_not_a_blank_script() {
    let out = rgx().args(["--completions", "tcsh"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("tcsh"), "{err}");
    assert!(err.contains("bash, zsh, fish, powershell"), "{err}");
}

/// A file with more matching lines than the old 1000-line buffer held must
/// print all of them.
///
/// `HitSink` used to cap its per-file line buffer at 1000 for every mode that
/// prints lines. rg has no such cap -- it streams each line straight to its
/// writer -- so the ceiling silently truncated `rgx -n`, `rgx -o` and
/// `rgx --json` on any file big enough to reach it, not only `-v`. Measured
/// against ripgrep 15.0.0 on a 20k-line file before the fix:
///
/// ```text
/// $ rgx -v ZZZ big.txt | wc -l    # 1000
/// $ rg  -v ZZZ big.txt | wc -l    # 20000
/// ```
///
/// 2500 lines is comfortably past the old cap and still cheap to build. The
/// expectations are derived from the fixture rather than hardcoded, so a change
/// to the cap cannot make the test pass by agreeing with itself.
#[test]
fn every_matching_line_is_printed_not_a_capped_prefix() {
    let dir = fixture_dir();
    let lines = 2500;
    let mut text = String::with_capacity(lines * 12);
    for i in 0..lines {
        if i % 2 == 0 {
            text.push_str(&format!("hit {i}\n"));
        } else {
            text.push_str(&format!("miss {i}\n"));
        }
    }
    let big = dir.join("big.txt");
    std::fs::write(&big, &text).unwrap();

    let hits = (0..lines).filter(|i| i % 2 == 0).count();
    let misses = lines - hits;
    let printed = |args: &[&str]| -> usize {
        let out = rgx().args(args).arg(&big).output().unwrap();
        String::from_utf8_lossy(&out.stdout).lines().count()
    };

    // -v: the mode the cap was aimed at, and the one whose output is largest.
    assert_eq!(printed(&["-v", "miss"]), hits, "-v truncated");
    // plain: the cap hit every printing mode, not only the inverted one.
    assert_eq!(printed(&["miss"]), misses, "plain output truncated");
    assert_eq!(printed(&["-n", "miss"]), misses, "-n output truncated");
    // -o prints one line per match, and every `miss` line holds one number.
    assert_eq!(printed(&["-o", r"miss \d+"]), misses, "-o output truncated");
    // --json prints one record per matching line -- and, since the schema
    // was fixed to be rg's, also a `begin`, an `end` and a `summary`. Those
    // three are not matches, so counting every line would report three extra
    // and call the output truncated when it is not. Counting the `match`
    // records is what this test is actually about.
    let json_matches = |args: &[&str]| -> usize {
        let out = rgx().args(args).arg(&big).output().unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| rgx_core::djson::parse(l).ok())
            .filter(|arena| {
                let v = arena.root();
                v.get(arena, "type").and_then(|t| t.as_str(arena)) == Some("match")
            })
            .count()
    };
    assert_eq!(
        json_matches(&["--json", "miss"]),
        misses,
        "--json truncated"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// `--json` must be parseable JSON, and must carry rg's byte offsets.
///
/// Two things were wrong, both in the same printer. `json_esc` escaped `\\`
/// and `"` and nothing else, so a tab in a source file -- and the CR in every
/// CRLF file on Windows -- was written raw into a JSON string, where the
/// grammar forbids it: the record simply ended mid-token at the CR, and no
/// parser could read it. Separately, `absolute_offset` was a literal `0` baked
/// into the format string instead of the line's real position in the file.
///
/// The oracle for "parseable" is `rgx_core::json`, which rejects an unescaped
/// control character in a string (`crates/rgx-core/src/json/parser.rs`), and
/// the oracle for the offsets is rg's own `--json` on the same fixture. The
/// file is CRLF with a tab and a C0 control byte in it, so `text`, the
/// submatch offsets and the absolute offsets are all exercised past line 1.
/// `--json` must speak rg's schema, not a subset of it.
///
/// `begin` and `end` used to be emitted only when `multi` was true, `end`
/// carried a path and nothing else, there was no `summary`, and `adapter`
/// was injected inside `data` — so a single named file, which is the case a
/// human or an agent runs most, got a stream rg cannot read. The parity
/// test did not catch any of it because it filtered to `match` and
/// `context` and threw the rest away.
#[test]
fn json_emits_the_record_sequence_rg_emits() {
    // Its own subdirectory: `fixture_dir()` is shared with the other tests
    // in this binary, so walking it would count their files too.
    let dir = fixture_dir().join("json-seq");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let one = dir.join("one.txt");
    std::fs::write(
        &one,
        "alpha needle
beta
needle gamma
",
    )
    .unwrap();
    let two = dir.join("two.txt");
    std::fs::write(
        &two,
        "delta needle
",
    )
    .unwrap();

    let kinds = |out: &[u8]| -> Vec<String> {
        String::from_utf8_lossy(out)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let arena = rgx_core::djson::parse(l).unwrap_or_else(|e| {
                    panic!(
                        "--json emitted invalid JSON: {e}
{l:?}"
                    )
                });
                let v = arena.root();
                v.get(&arena, "type")
                    .and_then(|t| t.as_str(&arena))
                    .unwrap_or("")
                    .to_string()
            })
            .collect()
    };
    let run = |p: &std::path::Path| {
        let out = rgx()
            .args(["--json", "needle"])
            .arg(p)
            .output()
            .expect("spawn rgx");
        assert!(out.status.success(), "rgx failed on {}", p.display());
        kinds(&out.stdout)
    };

    // A SINGLE file gets the full sequence. It is the case the old `multi`
    // gate threw away, and it is not a subset of rg's format, it is a
    // different format.
    let single = run(&one);
    assert_eq!(
        single.iter().filter(|k| *k == "begin").count(),
        1,
        "one file, one begin: {single:?}"
    );
    assert_eq!(
        single.last().map(String::as_str),
        Some("summary"),
        "{single:?}"
    );
    assert_eq!(
        single.first().map(String::as_str),
        Some("begin"),
        "{single:?}"
    );

    // Two files: begin/end per file, one summary last.
    let multi = run(&dir);
    assert_eq!(
        multi.iter().filter(|k| *k == "begin").count(),
        2,
        "{multi:?}"
    );
    assert_eq!(multi.iter().filter(|k| *k == "end").count(), 2, "{multi:?}");
    assert_eq!(
        multi.iter().filter(|k| *k == "summary").count(),
        1,
        "{multi:?}"
    );
    assert_eq!(
        multi.last().map(String::as_str),
        Some("summary"),
        "{multi:?}"
    );

    // `end` carries rg's `binary_offset` and `stats`; `summary` carries
    // `elapsed_total` and `stats`. Their presence is the schema.
    let out = rgx()
        .args(["--json", "needle"])
        .arg(&one)
        .output()
        .expect("spawn rgx");
    let text = String::from_utf8_lossy(&out.stdout);
    let end = text
        .lines()
        .filter_map(|l| rgx_core::djson::parse(l).ok())
        .find(|arena| {
            arena
                .root()
                .get(arena, "type")
                .and_then(|t| t.as_str(arena))
                == Some("end")
        })
        .expect("an end record");
    let end_v = end.root();
    let d = end_v.get(&end, "data").expect("end has data");
    for k in ["path", "binary_offset", "stats"] {
        assert!(d.get(&end, k).is_some(), "end.data is missing {k}: {end:?}");
    }
    let summary = text
        .lines()
        .filter_map(|l| rgx_core::djson::parse(l).ok())
        .find(|arena| {
            arena
                .root()
                .get(arena, "type")
                .and_then(|t| t.as_str(arena))
                == Some("summary")
        })
        .expect("a summary record");
    let sd = summary
        .root()
        .get(&summary, "data")
        .expect("summary has data");
    for k in ["elapsed_total", "stats"] {
        assert!(
            sd.get(&summary, k).is_some(),
            "summary.data is missing {k}: {summary:?}"
        );
    }

    // And `adapter` sits beside `type`, never inside `data`: a consumer
    // reading rg's documented shape must see exactly rg's fields.
    let match_rec = text
        .lines()
        .filter_map(|l| rgx_core::djson::parse(l).ok())
        .find(|arena| {
            arena
                .root()
                .get(arena, "type")
                .and_then(|t| t.as_str(arena))
                == Some("match")
        })
        .expect("a match record");
    let match_v = match_rec.root();
    assert!(
        match_v.get(&match_rec, "adapter").is_some(),
        "the adapter name is the one thing worth adding, and it must still be there: {match_rec:?}"
    );
    let md = match_v.get(&match_rec, "data").expect("match has data");
    assert!(
        md.get(&match_rec, "adapter").is_none(),
        "adapter leaked back into data, breaking rg's shape: {match_rec:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn json_output_is_valid_and_carries_rg_offsets() {
    let dir = fixture_dir();
    let body = "alpha\r\nbeta\tneedle\r\ngamma\x1fneedle\r\ndelta needle\r\n";
    let path = dir.join("mixed.txt");
    std::fs::write(&path, body).unwrap();

    // (type, lines.text, line_number, absolute_offset, submatch spans)
    type Row = (String, String, u64, u64, Vec<(u64, u64)>);

    let rows = |out: &[u8], what: &str| -> Vec<Row> {
        let text = String::from_utf8_lossy(out);
        let mut rows = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let arena = rgx_core::djson::parse(line)
                .unwrap_or_else(|e| panic!("{what} produced invalid JSON: {e}\n{line:?}"));
            let v = arena.root();
            let kind = v
                .get(&arena, "type")
                .and_then(|t| t.as_str(&arena))
                .unwrap_or("")
                .to_string();
            // NOT filtering to match/context. The filter was here, and it
            // is why `begin`, `end` and `summary` could be missing or
            // malformed for the whole life of `--json` without a single test
            // failing: the parity test could not see the records it was
            // supposed to be checking. A parity test that discards the
            // records most likely to differ is not a parity test.
            if kind != "match" && kind != "context" {
                continue;
            }
            let d = v
                .get(&arena, "data")
                .expect("a match/context record has data");
            // The fallback `Value::Null` is `Copy`, so the closure hands
            // back a handle, not a borrow, and the `arena` borrow lives
            // long enough for the chain of `.as_str(&arena)` calls below.
            let field = |k: &str| d.get(&arena, k).unwrap_or(rgx_core::djson::Value::Null);
            rows.push((
                kind,
                field("lines")
                    .get(&arena, "text")
                    .and_then(|t| t.as_str(&arena))
                    .unwrap_or_default()
                    .to_string(),
                field("line_number").as_u64().unwrap_or(u64::MAX),
                field("absolute_offset").as_u64().unwrap_or(u64::MAX),
                field("submatches")
                    .as_array(&arena)
                    .unwrap_or(&[])
                    .iter()
                    .map(|&s| {
                        (
                            s.get(&arena, "start")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(u64::MAX),
                            s.get(&arena, "end")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(u64::MAX),
                        )
                    })
                    .collect(),
            ));
        }
        rows
    };

    for flags in [vec!["--json"], vec!["--json", "-A1"]] {
        let mine = rgx()
            .args(&flags)
            .arg("needle")
            .arg(&path)
            .output()
            .unwrap();
        let theirs = Command::new("rg")
            .args(&flags)
            .arg("needle")
            .arg(&path)
            .output()
            .expect("ripgrep must be installed: tests/cli.rs is a parity suite");

        let got = rows(&mine.stdout, &format!("rgx {flags:?}"));
        let want = rows(&theirs.stdout, &format!("rg {flags:?}"));
        assert!(!got.is_empty(), "{flags:?} produced no records");
        assert_eq!(got, want, "{flags:?} disagrees with rg --json");
        // A regression back to a literal 0 would still "match" a one-line
        // fixture, so require at least one genuinely non-zero offset.
        assert!(
            got.iter().any(|r| r.3 > 0),
            "{flags:?} reported absolute_offset 0 for every line"
        );
    }
    // A last line with no terminator must not be given one. rg reports the
    // line as it sits in the file; the printer here strips the terminator
    // because every other mode adds its own, and `--json` used to put a `\n`
    // back unconditionally -- so an unterminated final line came back with a
    // newline rg never printed.
    for (name, body) in [
        ("unterminated", "alpha\nneedle tail"),
        ("terminated", "alpha\nneedle tail\n"),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        let mine = rgx()
            .args(["--json", "needle"])
            .arg(&path)
            .output()
            .unwrap();
        let theirs = Command::new("rg")
            .args(["--json", "needle"])
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(
            rows(&mine.stdout, name),
            rows(&theirs.stdout, name),
            "lines.text for a {name} file disagrees with rg"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// rg's binary rule turns on where the path came from, and rgx applied the
/// wrong half of it to walked files.
///
/// rg searches a path the user named as if it were text: `-c` counts it, `-l`
/// lists it, the exit status is set, and only the line output is suppressed. A
/// binary file the *walk* turned up is dropped whole instead. rgx counted it
/// either way, so `rgx -c` and `rg -c` disagreed on every binary file in a
/// tree, and rgx reported a match where rg exits 1.
///
/// `binary_match_counts_but_prints_no_lines` above already covers the
/// explicit-path half and is unchanged by this; what was missing is the walk.
/// The fixture is one NUL-bearing file beside two ordinary ones in the same
/// directory, so the only thing separating the two answers is the policy.
#[test]
fn a_binary_file_found_by_the_walk_is_suppressed_like_rg() {
    let dir = fixture_dir();
    let mut blob = b"before needle".to_vec();
    blob.push(0);
    blob.extend_from_slice(b"\nafter needle\n");
    std::fs::write(dir.join("walked.bin"), &blob).unwrap();
    std::fs::write(dir.join("plain-a.txt"), "needle here\n").unwrap();
    std::fs::write(dir.join("plain-b.txt"), "needle there\n").unwrap();

    let out = |args: &[&str]| -> String {
        let o = rgx().args(args).arg(&dir).output().unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    };

    let c = out(&["-c", "needle"]);
    assert!(
        !c.contains("walked.bin"),
        "walk -c counted the binary file:\n{c}"
    );
    assert!(
        c.contains("plain-a.txt") && c.contains("plain-b.txt"),
        "{c}"
    );

    let l = out(&["-l", "needle"]);
    assert!(
        !l.contains("walked.bin"),
        "walk -l listed the binary file:\n{l}"
    );

    let lx = out(&["--files-without-match", "needle"]);
    assert!(
        !lx.contains("walked.bin"),
        "walk --files-without-match listed the binary file as a miss:\n{lx}"
    );

    // -a clears it, exactly as rg's --text does.
    let a = out(&["-a", "-c", "needle"]);
    assert!(a.contains("walked.bin"), "-a must search it as text:\n{a}");

    // An explicit path is the other half of rg's rule and must survive.
    //
    // The three runs below carry their own diagnostics, because this test
    // fails intermittently and "Expected 2, got empty" says nothing about
    // which of the binary's three searchers ran or what it exited with.
    //
    // **The defect, as far as it is pinned.** Rate: one run in twenty to
    // twenty-eight of this suite. Signature, captured with these
    // diagnostics: `args=["-l", "needle"]`, `stdout=""`, `stderr=""`,
    // `exit=1` — rgx found nothing in a named binary file with two matches and
    // said so with its own exit code, which is a false negative, the one class
    // this project's gate exists for. Two different assertions have caught it
    // (the count below and the sentence further down); both times stdout was
    // empty, which is the same event from two angles.
    //
    // Ruled out by inspection, so nobody spends a turn on it: the external-tool
    // adapter claims `pub` (soffice) — and the OCR adapter beside it claims
    // `ocr.jpg` and friends — neither ever claims `.bin`. `which()` is a
    // PATH scan, memoised, and spawns nothing.
    //
    // **What it is not.** Not the command: seven hundred standalone
    // invocations of the exact failing command — three hundred serial, four
    // hundred while forty rgx processes ran at once — produced the right answer
    // every time. Not the machine, then, and not the file, and not the
    // concurrency. It needs the test *process*, which sets no environment
    // variable and changes no working directory. The locus is the named-path
    // search in `src/main.rs` (default / text / convert searchers feeding
    // `HitSink::into_hit`), which this work does not touch.
    //
    // **Not fixed, not attributed.** Recorded so the next occurrence is one
    // command away from a reproduction rather than a bisect.
    let bin = dir.join("walked.bin");
    let run = |args: &[&str]| {
        let o = rgx().args(args).arg(&bin).output().unwrap();
        let out_s = String::from_utf8_lossy(&o.stdout).into_owned();
        let err_s = String::from_utf8_lossy(&o.stderr).into_owned();
        let where_ = format!(
            "args={args:?}\nstdout={out_s:?}\nstderr={err_s:?}\nexit={:?}",
            o.status.code()
        );
        (out_s, where_)
    };

    let (c_out, c_where) = run(&["-c", "needle"]);
    assert_eq!(c_out.trim(), "2", "named binary file, -c:\n{c_where}");
    let (l_out, l_where) = run(&["-l", "needle"]);
    assert!(
        l_out.contains("walked.bin"),
        "named binary file, -l:\n{l_where}"
    );
    let (so, s_where) = run(&["needle"]);
    assert!(
        !so.contains("needle"),
        "binary line output must be suppressed:\n{s_where}"
    );
    // Silence was the wrong shape of the right answer. rg prints one line
    // saying the file is binary and where the NUL was, and a binary file
    // that matched has to look different from one that did not.
    assert!(
        so.contains("binary file matches ("),
        "rg's sentence is missing:\n{s_where}"
    );
    let o = rgx().args(["needle"]).arg(&bin).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "named binary file must exit 0");

    // A walk whose only match sits in a binary file exits 1, as rg does.
    let only = dir.join("only-binary");
    std::fs::create_dir_all(&only).unwrap();
    std::fs::write(only.join("x.bin"), &blob).unwrap();
    let o = rgx().args(["-c", "needle"]).arg(&only).output().unwrap();
    assert_eq!(o.status.code(), Some(1), "rgx reported a match rg does not");
    assert!(
        String::from_utf8_lossy(&o.stdout).trim().is_empty(),
        "rgx printed a count for a suppressed binary file"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A binary file the user NAMED is searched as text, so a file that was
/// looked at and did not match is a miss, and `--files-without-match` lists
/// it.
///
/// The walk's rule is the other half: a binary file the walk turned up is
/// dropped whole and is not a miss (`a_binary_file_found_by_the_walk_is_
/// suppressed_like_rg`). A named file is searched with rg's convert rule --
/// the whole buffer, the NUL reported -- so rg looked at it, and rg lists
/// it. rgx did not: the convert rule reports the NUL, and the report was
/// read as "rg would never have looked at this", which is the walked file's
/// verdict and not the named one's.
#[test]
fn a_named_binary_file_is_listed_as_a_miss_like_rg() {
    let dir = fixture_dir();
    let mut blob = b"no term in this half".to_vec();
    blob.push(0);
    blob.extend_from_slice(b"\nnor in this one\n");
    let bin = dir.join("named-nomatch.bin");
    std::fs::write(&bin, &blob).unwrap();

    let o = rgx()
        .args(["--files-without-match", "needle"])
        .arg(&bin)
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        out.contains("named-nomatch.bin"),
        "a named binary file was looked at, so a miss is a miss:\n{out}"
    );

    // And the walk's half is untouched: the same file inside a directory is
    // dropped whole, and it is not a miss either.
    let only = dir.join("only-named");
    std::fs::create_dir_all(&only).unwrap();
    std::fs::write(only.join("x.bin"), &blob).unwrap();
    let o = rgx()
        .args(["--files-without-match", "needle"])
        .arg(&only)
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        !out.contains("x.bin"),
        "a walked binary file is not a miss:\n{out}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Every tracked file that is binary must sit under a path `.gitattributes`
/// marks `-text`.
///
/// This is the `reportlab.pdf` defect stated as the invariant it violated:
/// `crates/rgx-adapters-pdf/fixtures/` was not covered by the `testdata/`
/// rule, so a checkout under `core.autocrlf=true` rewrote a PDF from 1400
/// bytes to 1468 -- 68 CRs inserted into a PDF stream -- and failed
/// `reportlab_real_file` on the machine that cloned the repo and nowhere
/// else. The same audit turned up a second unprotected binary directory,
/// `crates/rgx-core/fuzz/corpus/`, whose seeds are read byte for byte by a
/// decompressor and a model loader.
///
/// "Binary" is judged two ways, because the two defects hid differently. A
/// NUL byte is how git itself decides, and it is what the fuzz seeds have.
/// `reportlab.pdf` has no NUL at all -- it is a small, simple PDF -- so only
/// the extension list catches it, and a content-only audit would have
/// reported this fixed while the bug was live.
///
/// Skipped when `git` is missing or the tree is not a work tree, so it cannot
/// become a spurious failure somewhere else.
#[test]
fn every_tracked_binary_file_is_marked_no_text() {
    /// Extensions that are never line-ending-converted anywhere.
    const BINARY_EXT: &[&str] = &[
        "pdf",
        "zip",
        "gz",
        "zst",
        "7z",
        "bz2",
        "xz",
        "lz4",
        "lzma",
        "br",
        "tar",
        "rar",
        "jpg",
        "jpeg",
        "png",
        "gif",
        "webp",
        "tiff",
        "tif",
        "bmp",
        "ico",
        "mp3",
        "mp4",
        "wav",
        "docx",
        "xlsx",
        "pptx",
        "doc",
        "xls",
        "ppt",
        "rtf",
        "odt",
        "exe",
        "dll",
        "so",
        "dylib",
        "o",
        "a",
        "wasm",
        "bin",
        "class",
        "pyc",
        "ttf",
        "otf",
        "woff",
        "woff2",
        "safetensors",
        "onnx",
        "rten",
        "npy",
        "npz",
        "pkl",
        "db",
        "sqlite",
        "eml",
        "mbox",
    ];

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Ok(listed) = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
    else {
        eprintln!("git unavailable; skipping the .gitattributes audit");
        return;
    };
    if !listed.status.success() {
        eprintln!("not a git work tree; skipping the .gitattributes audit");
        return;
    }

    let files: Vec<&str> = std::str::from_utf8(&listed.stdout)
        .expect("git ls-files emits utf-8")
        .split('\0')
        .filter(|s| !s.is_empty())
        .collect();
    assert!(!files.is_empty(), "git ls-files returned nothing");

    let mut unprotected = Vec::new();
    for rel in &files {
        let Ok(bytes) = std::fs::read(root.join(rel)) else {
            continue;
        };
        let ext = rel.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        let is_binary = bytes.contains(&0) || BINARY_EXT.contains(&&*ext);
        if !is_binary {
            continue;
        }
        let attr = Command::new("git")
            .args(["check-attr", "text", "--", rel])
            .current_dir(root)
            .output()
            .expect("git check-attr");
        if !attr.status.success() {
            // A locked or contended index makes `check-attr` fail, and a
            // failure here would otherwise read as "unprotected". Skipping is
            // the honest reading: the audit did not get an answer.
            eprintln!("git check-attr failed for {rel}; skipping the audit");
            return;
        }
        if !String::from_utf8_lossy(&attr.stdout).contains("text: unset") {
            unprotected.push(rel.to_string());
        }
    }

    assert!(
        unprotected.is_empty(),
        "these tracked binary files are not marked `-text` in .gitattributes, so a \
         checkout with core.autocrlf=true rewrites their bytes:\n{}",
        unprotected.join("\n")
    );
}

#[test]
fn every_file_carries_its_spdx_header() {
    /// The licence expression a file in this tree may carry. There is one:
    /// rgx's own licence, and no second one to choose from. A file that
    /// names anything else fails this audit, and so does a file with no
    /// header at all. The provenance of the few layouts that were learned
    /// from third-party implementations is recorded in `NOTICE`.
    const ALLOWED: &[&str] = &["// SPDX-License-Identifier: Apache-2.0"];
    /// The licence this repository used to offer in parallel, spelled in two
    /// pieces so that this file does not trip its own audit.
    const RETIRED: &str = concat!("MIT OR ", "Apache-2.0");

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Ok(listed) = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
    else {
        eprintln!("git unavailable; skipping the SPDX audit");
        return;
    };
    if !listed.status.success() {
        eprintln!("not a git work tree; skipping the SPDX audit");
        return;
    }

    let files: Vec<&str> = std::str::from_utf8(&listed.stdout)
        .expect("git ls-files emits utf-8")
        .split('\0')
        .filter(|s| !s.is_empty())
        .collect();
    assert!(!files.is_empty(), "git ls-files returned nothing");

    let mut audited = 0usize;
    let mut unmarked = Vec::new();
    let mut retired = Vec::new();
    for rel in &files {
        if !rel.ends_with(".rs") {
            continue;
        }
        audited += 1;
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            // An unreadable file is not an answer, and reporting it as
            // unmarked would blame the license rather than the filesystem.
            eprintln!("cannot read {rel}; skipping it in the SPDX audit");
            continue;
        };
        if !ALLOWED.contains(&text.lines().next().unwrap_or("")) {
            unmarked.push(rel.to_string());
        }
        if text.contains(RETIRED) {
            retired.push(rel.to_string());
        }
    }

    // The file list comes from git, so the audit cannot pass on an empty
    // match — but the assertion is here because a change that made the
    // filter match nothing would otherwise look like a clean tree.
    assert!(
        audited > 0,
        "the SPDX audit matched no Rust file at all; the file list is stale"
    );
    assert!(
        unmarked.is_empty(),
        "these files do not start with one of the allowed SPDX expressions \
         ({:?}), so the claim COPYING makes about them is false:\n{}",
        ALLOWED,
        unmarked.join("\n")
    );
    assert!(
        retired.is_empty(),
        "these files still name a licence this repository no longer offers, \
         which is what COPYING says it does:\n{}",
        retired.join("\n")
    );
}

/// The name of a test's temporary directory is the rule of one file, and
/// this is the audit that keeps it there.
///
/// The rule used to live in nineteen files, and the copies drifted: one of
/// them did not compile, and the others made the directory with
/// `create_dir_all`, which reuses a directory that is already there --
/// silently -- so a directory left behind by a killed run was adopted as if
/// it were fresh. The house had already fixed it in `tests/cache.rs` and
/// never carried the fix to the others. The rule now lives in
/// `tests/common/mod.rs`, and a second copy of it is the defect this audit
/// names.
#[test]
fn one_file_owns_the_name_of_a_temporary_directory() {
    /// The file that owns the name. Every other file asks it for a
    /// directory instead of building one.
    const OWNER: &str = "tests/common/mod.rs";
    /// The call this audit looks for, spelled in two pieces so that this
    /// file does not trip its own audit -- the way the licence audit spells
    /// the licence it retired.
    const NEEDLE: &str = concat!("temp_", "dir()");

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Ok(listed) = Command::new("git")
        .args(["ls-files", "-z", "--", "tests/"])
        .current_dir(root)
        .output()
    else {
        eprintln!("git unavailable; skipping the temporary-directory audit");
        return;
    };
    if !listed.status.success() {
        eprintln!("not a git work tree; skipping the temporary-directory audit");
        return;
    };

    let files: Vec<&str> = std::str::from_utf8(&listed.stdout)
        .expect("git ls-files emits utf-8")
        .split('\0')
        .filter(|s| s.ends_with(".rs"))
        .collect();
    assert!(!files.is_empty(), "git ls-files returned nothing");

    let mut offenders = Vec::new();
    for rel in files {
        if rel == OWNER {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            // An unreadable file is not an answer, and reporting it as an
            // offender would blame the file rather than the filesystem.
            eprintln!("cannot read {rel}; skipping it in the audit");
            continue;
        };
        if text.contains(NEEDLE) {
            offenders.push(rel.to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "these files build a temporary directory of their own, and {OWNER} \
         owns that name: a second copy of the rule is a copy that drifts, \
         and the copy that drifts is the copy that breaks:\n{}",
        offenders.join("\n")
    );
}

/// A `.docx` member budget that `-M` reaches, and a truncation note the
/// search can find.
///
/// The office adapter read its zip container through
/// `rgx_core::zip::ZipReader::new`, which pins the decode ceiling to
/// `default_byte_limit()` — `Ctx::default().max_file_size`, 1 GiB
/// (`crates/rgx-core/src/zip.rs:48`) — while the archive crate's own zip
/// adapter reads `budget::budget().bytes`, which is what `-M` sets
/// (`src/main.rs:1534`). So `-M` was reaching every other container and
/// neither `.docx` nor the model-file zips, and a part one of them dropped
/// was dropped without a word.
///
/// The parts are deflated so the container is ~1 kB on disk and can sit
/// under `-M 50K` while its members expand past it: the walker's own
/// `Ctx::max_file_size` check is against the compressed length, so a stored
/// part would be filtered out before the adapter ever ran and this would
/// prove nothing.
fn deflated_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    fn crc32(b: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in b {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let offset = out.len() as u32;
        let crc = crc32(data);
        let nlen = name.len() as u16;
        let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).unwrap();
        let packed = enc.finish().unwrap();
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&8u16.to_le_bytes()); // method: deflate
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&packed);
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes()); // version made by
        central.extend_from_slice(&20u16.to_le_bytes()); // version needed
        central.extend_from_slice(&0u16.to_le_bytes()); // flags
        central.extend_from_slice(&8u16.to_le_bytes()); // method
        central.extend_from_slice(&0u16.to_le_bytes()); // time
        central.extend_from_slice(&0u16.to_le_bytes()); // date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&nlen.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra length
        central.extend_from_slice(&0u16.to_le_bytes()); // comment length
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with the directory
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out
}

/// rgx on one named file, and nothing else.
fn run_file(path: &Path, args: &[&str]) -> (i32, String) {
    let out = rgx()
        .args(args)
        .arg(path)
        .output()
        .expect("failed to spawn rgx");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn a_docx_capped_by_dash_m_says_it_was_truncated() {
    let dir = fixture_dir();
    let body = br#"<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>the summary line</w:t></w:r></w:p></w:body></w:document>"#;
    let header = format!(
        "<?xml version=\"1.0\"?><w:hdr><w:p>{}BULKHEADER{}</w:p></w:hdr>",
        "filler words here ".repeat(30_000),
        "tail "
    );
    let docx = dir.join("report.docx");
    std::fs::write(
        &docx,
        deflated_zip(&[
            ("word/document.xml", body),
            ("word/header1.xml", header.as_bytes()),
        ]),
    )
    .unwrap();
    assert!(
        std::fs::metadata(&docx).unwrap().len() < 50_000,
        "the fixture has to fit under -M 50K, or the walker skips it first"
    );

    // The part that fits is still searched.
    let (code, stdout) = run_file(&docx, &["-M", "50K", "summary line"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("the summary line"), "stdout:\n{stdout}");

    // The part that does not fit is capped, and the cap is searchable:
    // `rgx: archive truncated`, the same note every other container emits.
    let (code, stdout) = run_file(&docx, &["-M", "50K", "archive truncated"]);
    assert_eq!(code, 0, "a cap with no note is a silent one:\n{stdout}");
    assert!(
        stdout.contains("rgx: archive truncated"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("member byte budget"), "stdout:\n{stdout}");

    // And the capped part really is gone, not merely labelled.
    let (code, stdout) = run_file(&docx, &["-M", "50K", "BULKHEADER"]);
    assert_eq!(code, 1, "the header expanded past the cap:\n{stdout}");

    // Without `-M` the whole document is searchable and nothing is claimed.
    let (code, stdout) = run_file(&docx, &["BULKHEADER"]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    let (code, stdout) = run_file(&docx, &["archive truncated"]);
    assert_eq!(code, 1, "a note on an uncapped document:\n{stdout}");

    std::fs::remove_dir_all(&dir).ok();
}

/// `-M` is `--max-filesize` in rgx and `--max-columns` in ripgrep 15 — kept
/// deliberately, and pinned here so it cannot drift unnoticed.
///
/// The flag audit against `rg 15.0.0` found exactly one short flag whose long
/// name disagrees, once `-L` was fixed. In rg, `-M NUM` is `--max-columns`
/// (a display cap) and the byte cap is long-only: `--max-filesize`. rgx has
/// no `--max-columns` at all, and `-M` is the knob the byte budget is set
/// from — the one `-M 20G` reaches every decompressor through, and the one
/// the truncation note tells a user to raise. Following rg here would mean
/// deleting the short form of a flag rgx implements in order to reserve the
/// letter for one it does not, so the divergence is conscious and recorded in
/// `benchmark/status.md` rather than closed.
#[test]
fn dash_capital_m_is_max_filesize_and_stays_that_way() {
    let dir = fixture_dir();
    let big = dir.join("big.txt");
    std::fs::write(&big, "needle\n".repeat(500)).unwrap();
    assert!(
        std::fs::metadata(&big).unwrap().len() > 1024,
        "fixture must exceed 1K"
    );

    let out = |args: &[&str]| {
        let o = rgx().args(args).arg(&dir).output().unwrap();
        // Sorted: the walk is parallel and promises no order, so two runs of
        // the same flag list are not the same string unless sorted.
        let mut lines: Vec<String> = String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(str::to_string)
            .collect();
        lines.sort();
        lines.join("\n")
    };

    // `-M` is the file-size cap: a file over it is not searched at all.
    let c = out(&["-M", "1K", "-c", NEEDLE]);
    assert!(!c.contains("big.txt"), "-M did not cap the file size:\n{c}");
    let l = out(&["-M", "1K", "-l", NEEDLE]);
    assert!(!l.contains("big.txt"), "-M did not cap the file size:\n{l}");

    // The short and long spellings are one flag.
    assert_eq!(out(&["--max-filesize", "1K", "-l", NEEDLE]), l);

    // Without the cap it is searched like any other file.
    let all = out(&["-l", NEEDLE]);
    assert!(all.contains("big.txt"), "{all}");

    // And `--help` pairs the letter with the name it means here.
    let help = rgx().arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout).to_string();
    assert!(help.contains("-M, --max-filesize"), "{help}");

    std::fs::remove_dir_all(&dir).ok();
}

/// `--max-filesize` caps what the walk opens and does not apply to a path
/// named on the command line, as rg does not. Naming a file is an
/// instruction to search it; the cap exists so the walk does not open things
/// nobody asked for. Both halves are pinned on one fixture, so a change to
/// either shows up.
#[test]
fn max_filesize_caps_the_walk_and_not_a_named_path() {
    let dir = fixture_dir();
    let big = dir.join("big.txt");
    std::fs::write(&big, "needle\n".repeat(500)).unwrap();
    assert!(
        std::fs::metadata(&big).unwrap().len() > 1024,
        "fixture must exceed 1K"
    );

    // named on the command line: searched whatever its size
    let out = rgx()
        .args(["-M", "1K", "-l", NEEDLE])
        .arg(&big)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        stdout.contains("big.txt"),
        "a named path is searched:\n{stdout}"
    );
    assert_eq!(out.status.code(), Some(0), "{stdout}");

    // discovered by the walk: skipped
    let out = rgx()
        .args(["-M", "1K", "-l", NEEDLE])
        .arg(&dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        !stdout.contains("big.txt"),
        "the walk honours the cap:\n{stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// `-j`/`--threads` is the flag ripgrep 15 has and rgx did not, and its
/// absence is not cosmetic: ripgrep caps its own default at
/// `available_parallelism().min(12)` while rgx used the uncapped count,
/// so every wall-clock comparison the two projects published was made at
/// 32 threads against 12. Measured on the 56k-file cargo registry, best
/// of 3, thread-matched:
///
///     -j 1   rgx 7007 ms   rg 7178 ms
///     -j 8   rgx 1516 ms   rg 1520 ms
///     -j 16  rgx 1006 ms   rg 1014 ms
///     -j 32  rgx  721 ms   rg  760 ms
///
/// and with defaults, rgx 811 ms against rg 1208 ms. The 1.49x was the
/// thread count, not the code.
///
/// This test checks the flag exists, accepts both spellings, accepts
/// `0` as "ask the OS" the way ripgrep does, rejects a non-number the
/// way ripgrep does, and — the part that would be easy to get wrong —
/// produces the same output at every thread count.
#[test]
fn dash_j_sets_the_thread_count_and_the_answer_does_not_depend_on_it() {
    let dir = fixture_dir();
    let plain = dir.join("plain");
    std::fs::create_dir_all(&plain).unwrap();
    for i in 0..12 {
        std::fs::write(plain.join(format!("f{i}.txt")), "needle here\n").unwrap();
        std::fs::write(plain.join(format!("g{i}.txt")), "nothing here\n").unwrap();
    }
    let norm = |s: &str| -> Vec<String> {
        let mut v: Vec<String> = s
            .replace(char::from(b'\\'), "/")
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        v.sort();
        v
    };
    let out = |args: &[&str]| {
        let o = rgx().args(args).arg(&plain).output().unwrap();
        assert_eq!(
            o.status.code(),
            Some(0),
            "rgx {args:?} failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        norm(&String::from_utf8_lossy(&o.stdout))
    };

    let base = out(&["-c", NEEDLE]);
    assert!(!base.is_empty(), "the fixture must match something");

    for n in ["0", "1", "2", "8"] {
        assert_eq!(
            out(&["-j", n, "-c", NEEDLE]),
            base,
            "-j {n} changed the answer"
        );
        assert_eq!(
            out(&["--threads", n, "-c", NEEDLE]),
            base,
            "--threads {n} changed the answer"
        );
    }
    assert_eq!(out(&["-j", "2", "-c", NEEDLE]), base);

    // bundled short flag, the grammar ripgrep inherits from clap
    assert_eq!(out(&["-j2", "-c", NEEDLE]), base, "-j2 changed the answer");

    // a non-number is an error, not a silent fallback to the default
    let bad = rgx().args(["-j", "banana", "-c", NEEDLE]).output().unwrap();
    assert_ne!(
        bad.status.code(),
        Some(0),
        "a non-numeric -j must be rejected: {}",
        String::from_utf8_lossy(&bad.stdout)
    );

    // and it is in --help, which the completions test reads
    let help = rgx().arg("--help").output().unwrap();
    assert!(
        String::from_utf8_lossy(&help.stdout).contains("--threads"),
        "--help does not list --threads"
    );
}

#[test]
fn pack_store_cli_and_auto_detector() {
    let dir = common::scratch("tv-cli-test");
    std::fs::write(dir.join("a.rs"), "pub fn alpha() { let needle = 1; }\n").unwrap();
    std::fs::write(dir.join("b.rs"), "pub fn beta() { let needle = 2; }\n").unwrap();
    std::fs::write(dir.join("c.rs"), "pub fn gamma() { let other = 3; }\n").unwrap();

    let store_dir = dir.join("store");

    // 1. Unindexed directory without store: auto detector selects rgx
    let out_unindexed = rgx()
        .args(["needle", "--explain-engine", "-c"])
        .arg(&dir)
        .output()
        .expect("spawn rgx");
    let stderr_unindexed = String::from_utf8_lossy(&out_unindexed.stderr);
    assert!(
        stderr_unindexed.contains("selected engine: rgx"),
        "expected rgx direct engine on unindexed directory: {stderr_unindexed}"
    );

    // 2. Build pack store
    let out_build = rgx()
        .args(["--tv-build"])
        .arg(&dir)
        .args(["--tv-store"])
        .arg(&store_dir)
        .output()
        .expect("spawn rgx --tv-build");
    assert_eq!(out_build.status.code(), Some(0), "tv-build failed");
    assert!(
        store_dir.join("manifest.tvm").is_file(),
        "manifest.tvm missing"
    );

    // 3. Query with explicit --tv-store: auto detector selects tv
    let out_tv = rgx()
        .args(["needle", "--tv-store"])
        .arg(&store_dir)
        .args(["--explain-engine", "-c"])
        .output()
        .expect("spawn rgx --tv-store");
    assert_eq!(out_tv.status.code(), Some(0));
    let stderr_tv = String::from_utf8_lossy(&out_tv.stderr);
    let stdout_tv = String::from_utf8_lossy(&out_tv.stdout);
    assert!(
        stderr_tv.contains("selected engine: tv"),
        "expected tv engine with --tv-store: {stderr_tv}"
    );
    assert_eq!(
        stdout_tv.lines().count(),
        2,
        "expected 2 matching files in tv store: {stdout_tv}"
    );

    // 4. Single file target: auto detector selects rgx (sub-millisecond direct latency)
    let single_file = dir.join("a.rs");
    let out_single = rgx()
        .args(["needle", "--explain-engine", "-c"])
        .arg(&single_file)
        .output()
        .expect("spawn rgx single file");
    let stderr_single = String::from_utf8_lossy(&out_single.stderr);
    assert!(
        stderr_single.contains("selected engine: rgx"),
        "expected rgx engine on single file: {stderr_single}"
    );
    assert!(
        stderr_single.contains("single regular file"),
        "expected single regular file rationale: {stderr_single}"
    );

    // 5. Explicit --engine tv override (no pack store present -> still resolves tv but cannot read)
    let out_tv = rgx()
        .args(["needle", "--engine", "tv", "--explain-engine", "-c"])
        .arg(&dir)
        .output()
        .expect("spawn rgx --engine tv");
    let stderr_tv = String::from_utf8_lossy(&out_tv.stderr);
    assert!(
        stderr_tv.contains("selected engine: tv") || stderr_tv.is_empty(),
        "expected tv engine override: {stderr_tv}"
    );

    // 6. Line output parity between direct and TV pack store
    let lines_direct = rgx()
        .args(["needle", "-n"])
        .arg(&dir)
        .output()
        .expect("spawn rgx direct -n");
    let lines_tv = rgx()
        .args(["needle", "-n", "--tv-store"])
        .arg(&store_dir)
        .output()
        .expect("spawn rgx tv -n");

    let stdout_direct = String::from_utf8_lossy(&lines_direct.stdout);
    let stdout_tv_lines = String::from_utf8_lossy(&lines_tv.stdout);
    assert_eq!(
        stdout_direct.lines().count(),
        stdout_tv_lines.lines().count(),
        "line count mismatch between direct and tv"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A file an adapter *renders* is still a file ripgrep reads, so the bytes on
/// disk have to stay the answer.
///
/// The reported case: `tarpaulin-report.html`, a coverage report that is JSON
/// wrapped in HTML. `rg -c 'pub fn'` counts the two lines inside the `<script>`
/// block; the markup adapter strips the tags, drops the `<script>` body with
/// them, and rgx printed nothing at all -- not for `pub fn`, not for `var`, not
/// for anything else in the file, and `-a` did not help, because nothing was
/// being refused. rgx had *transformed* the file and lost what ripgrep reads.
///
/// This pins the property, not one file: for every extension a rendering
/// adapter claims, a line that lives only in the markup -- inside `<script>`,
/// in a Markdown comment, in a LaTeX control word, in an RTF destination group
/// -- has to count the way ripgrep counts it, and `-a` must not change it.
#[test]
fn a_markup_file_is_still_counted_the_way_ripgrep_counts_it() {
    // This one pins the *default* policy, so it is the only one of the three
    // that stands down when the run is exercising the escape hatch; the other
    // two name the policy they need on the command they build. Without this
    // a `RGX_ADAPTER_VIEW=render` run reports a red test for behaviour it was
    // asked to switch off.
    if let Some(v) = std::env::var_os("RGX_ADAPTER_VIEW") {
        eprintln!(
            "skipped: RGX_ADAPTER_VIEW={} selects a non-default policy",
            v.to_string_lossy()
        );
        return;
    }
    let dir = common::scratch("render-fallback");

    // Each fixture puts the needle where the renderer throws it away and one
    // more line where it survives, so the test can tell "the source was
    // searched" apart from "the rendering was searched" and apart from
    // "nothing matched". The two counts are the two ends of that: what rg
    // counts in the raw bytes, and what the extractor would have left.
    let fixtures: &[(&str, &str, &str, &str, &str)] = &[
        (
            "tarpaulin-report.html",
            concat!(
                "<!DOCTYPE html>\n<html><head><title>Tarpaulin Report</title>\n",
                "<style>.c{color:#333}</style></head><body>\n",
                "<h1>Coverage</h1>\n",
                "<script>\n",
                "pub fn line_one() {}\n",
                "pub fn line_two() {}\n",
                "</script>\n",
                "<p>visible error line</p>\n",
            ),
            "pub fn",
            "2",
            "pub fn line_one() {}",
        ),
        (
            "notes.md",
            concat!(
                "# Notes\n\n",
                "<!-- a comment mentioning the needle -->\n\n",
                "See [the spec](https://example.invalid/needle).\n\n",
                "visible error line\n",
            ),
            "needle",
            "2",
            "comment mentioning the needle",
        ),
        (
            "paper.tex",
            concat!(
                "\\documentclass{article}\n",
                "\\begin{document}\n",
                "\\section{Intro}\n",
                "\\newcommand{\\needlename}{x}\n",
                "visible error line\n",
                "\\end{document}\n",
            ),
            "\\needlename",
            "1",
            "\\newcommand{\\needlename}",
        ),
        (
            "memo.rtf",
            concat!(
                "{\\rtf1\\ansi{\\fonttbl{\\f0 Arial;}}\n",
                "\\pard visible error line\\par\n",
                "{\\*\\fldinst {\\field{\\*\\fldinst needle}}}\n",
                "}\n",
            ),
            "needle",
            "1",
            "\\field{\\*\\fldinst needle}",
        ),
    ];

    for (name, body, ..) in fixtures {
        std::fs::write(dir.join(name), body).unwrap();
    }

    for (name, _body, needle, want_lines, want_text) in fixtures {
        let file = dir.join(name);
        let count = |extra: &[&str]| -> String {
            let out = rgx()
                .args(["-F", "-c"])
                .args(extra)
                .arg(needle)
                .arg(&file)
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        // -a used to be the thing people reached for when rgx printed
        // nothing, and it changed nothing: the file was not being refused.
        assert_eq!(
            count(&[]),
            *want_lines,
            "{name}: the markup-only lines must count"
        );
        assert_eq!(
            count(&["-a"]),
            *want_lines,
            "{name}: -a must agree with the default"
        );

        let out = rgx().args(["-F"]).arg(needle).arg(&file).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(want_text),
            "{name}: the line ripgrep prints is missing from rgx:\n{stdout}"
        );
        // The prose is not lost either -- that is the part the renderer was
        // built for, and the part that has to survive losing the markup.
        let out = rgx().arg("visible error line").arg(&file).output().unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("visible error line"),
            "{name}: the rendered text must still be searchable"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// The rendering is still built, and still reachable -- it is a policy choice
/// (`RGX_ADAPTER_VIEW`), not a deletion. Under `render` the markup adapter
/// takes the file again, which is what the adapter is for; under `both` the two
/// views are reported side by side and the same line arrives twice.
#[test]
fn the_rendering_is_a_policy_and_both_policies_still_reach_it() {
    let dir = common::scratch("render-policy");
    let file = dir.join("tarpaulin-report.html");
    std::fs::write(
        &file,
        "<html><body>\n<p>visible error line</p>\n<script>\nneedle in a script\n</script>\n</body></html>\n",
    )
    .unwrap();

    // `None` means the default policy, and says so explicitly: the ambient
    // environment is not this test's to inherit, or a `RGX_ADAPTER_VIEW=render`
    // run would assert the wrong policy.
    let adapter_of = |view: Option<&str>| -> String {
        let mut cmd = rgx();
        cmd.args(["--json", "error"]);
        match view {
            Some(v) => cmd.env("RGX_ADAPTER_VIEW", v),
            None => cmd.env_remove("RGX_ADAPTER_VIEW"),
        };
        let out = cmd.arg(&file).output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    // Default: the file's own bytes, provenance `raw`.
    let default_json = adapter_of(None);
    assert!(
        default_json.contains("\"adapter\":\"raw\""),
        "the default view is the file's own bytes:\n{default_json}"
    );
    assert!(!default_json.contains("needle in a script"));

    // `render`: the adapter takes it, the script body is gone again.
    let render_json = adapter_of(Some("render"));
    assert!(
        render_json.contains("\"adapter\":\"markup\""),
        "the rendering is still reachable:\n{render_json}"
    );
    assert!(
        !render_json.contains("needle in a script"),
        "and the rendering still drops what it dropped"
    );

    // `both`: two units, so `-c` prints the path twice.
    let out = rgx()
        .args(["-c", "error"])
        .env("RGX_ADAPTER_VIEW", "both")
        .arg(&file)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout.lines().count(),
        2,
        "the union reports the source and the rendering:\n{stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// An adapter that finds nothing must not take the file with it.
///
/// Every extractor declines with `bail!`, and `bail!` reaches `process` as
/// `Err` rather than as `Outcome::Bail`, so "this file has no EXIF" and "this
/// container is corrupt" arrived at the same arm — which pushed a one-line
/// note in place of the file and returned. The comment above that arm said it
/// kept the corpus searchable; it did the opposite. Over the registry corpus
/// that was 1,387 of 4,881 claimed files, 14,251 lines ripgrep reported and
/// rgx did not, and it reached the same strict-subset property the rendering
/// adapters had by a different door.
///
/// Both fixtures are files ripgrep reads: a `.docx` that is not a zip, and a
/// `.tex` with no preamble for the TeX heuristic to recognise. The note must
/// still be there — it is the record of what happened — and the file's own
/// bytes must be there too.
#[test]
fn a_file_no_adapter_could_read_is_still_searchable() {
    let dir = common::scratch("err-fallback");

    // claims to be an OOXML container, is plain text
    std::fs::write(
        dir.join("fake.docx"),
        b"not a zip at all, just bytes\nand the needle is right here\n",
    )
    .unwrap();
    // a real TeX encoding table: no \documentclass, no \begin{, no \section,
    // which is the whole of the TeX adapter's cheap "does this look like TeX"
    // test. Measured on the corpus, this shape is `tex__1250-t1.tex`.
    std::fs::write(
        dir.join("plain.tex"),
        b"%%% The encoding table, v.Sep.1997\n\
          %%% input: CP1250, internal TeX: Cork\n\
          \n\
          \\input encmacro  \\input t1macro\n\
          \n\
          % a comment holding the needle\n",
    )
    .unwrap();

    // `None` means the default policy, named explicitly rather than inherited
    // from the environment this test happens to run in.
    let count = |file: &str, pat: &str, view: Option<&str>| -> String {
        let mut cmd = rgx();
        cmd.args(["-F", "-c"]).arg(pat).arg(dir.join(file));
        match view {
            Some(v) => cmd.env("RGX_ADAPTER_VIEW", v),
            None => cmd.env_remove("RGX_ADAPTER_VIEW"),
        };
        let out = cmd.output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    // the docx adapter runs in every policy: it declines on the bad magic,
    // and the file is still searched
    assert_eq!(count("fake.docx", "needle", None), "1", "a declined .docx");
    assert_eq!(
        count("fake.docx", "needle", Some("render")),
        "1",
        "a declined .docx"
    );
    // and there is no note: an adapter that steps aside did not fail, so
    // nothing about the step-aside belongs in the corpus. A note here put
    // a line in the output that was not in the file, and made a search for
    // "[rgx:" match a document that had never been opened.
    assert_eq!(
        count("fake.docx", "[rgx: adapter", None),
        "",
        "a decline must not leave a note behind"
    );

    // the tex adapter only runs under `render`; under the default policy the
    // file is its own bytes anyway, which is the other half of the property
    assert_eq!(count("plain.tex", "needle", None), "1", "a declined .tex");
    assert_eq!(
        count("plain.tex", "needle", Some("render")),
        "1",
        "a declined .tex, with the adapter in the chain"
    );
    assert_eq!(
        count("plain.tex", "[rgx: adapter", Some("render")),
        "",
        "a decline must not leave a note behind under the adapter policy"
    );

    // and the line output, not just the count
    let out = rgx()
        .arg("needle")
        .arg(dir.join("fake.docx"))
        .env_remove("RGX_ADAPTER_VIEW")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("and the needle is right here"),
        "the line ripgrep prints is missing:\n{stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A file named `.gz` that is not gzip must still be a file ripgrep reads.
///
/// This is the same contract as the test above, reached through the decoder
/// instead of the pipeline. `GzipReader::decode_bounded` walks
/// `while pos < len && is_gzip(rest)`, so bytes that are not gzip leave that
/// loop unentered and come back `Ok` carrying *nothing* — no error, because
/// nothing went wrong from the decoder's own point of view. `Decompress` then
/// answered `Members([(inner, [])])`, the recursion into that member found no
/// extension and emitted nothing, and the file the walk had found became
/// unsearchable: no match, no reason, exit 1, which is indistinguishable from
/// "the pattern is not in this file".
#[test]
fn a_file_whose_name_promises_a_compression_it_does_not_have_is_still_searchable() {
    let dir = common::scratch("fake-gz");

    // plain text wearing a .gz name
    std::fs::write(
        dir.join("fake.gz"),
        b"not a gzip stream, just bytes\nthe needle is right here\n",
    )
    .unwrap();

    let count = |pat: &str| -> String {
        let out = rgx()
            .args(["-F", "-c"])
            .arg(pat)
            .arg(dir.join("fake.gz"))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    assert_eq!(
        count("needle"),
        "1",
        "the file's own bytes must survive the decoder finding nothing"
    );
    // A decoder that finds nothing in a file it was handed has declined,
    // not failed. The file's own bytes are searched instead, and nothing
    // is added to the corpus that was not in it: a note here made the
    // search for "[rgx:" match a gzip file that was never a gzip.
    assert_eq!(
        count("[rgx: adapter"),
        "",
        "a decline must not leave a note behind"
    );

    let out = rgx()
        .args(["-F"])
        .arg("needle")
        .arg(dir.join("fake.gz"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("the needle is right here"),
        "the line ripgrep prints is missing:\n{stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A decline is silent, and a failure is not.
///
/// The two are different events, and the corpus has to be able to tell them
/// apart — that is the whole point of the `decline!` macro and of
/// `Outcome::Bail`.
///
/// An adapter that steps aside — "this file is not mine" — leaves nothing
/// behind. Every line in the output is then a line the file actually has,
/// which is what makes rgx a drop-in for ripgrep: a search for a string
/// that happens to appear in a diagnostic message cannot match a file that
/// was never opened.
///
/// An adapter that tried and failed — "this file IS mine and I could not
/// read it" — leaves a note beside the file's own bytes, so the failure is
/// visible without the file leaving the corpus.
///
/// The two fixtures are chosen so that only the outcome differs: the `.ts`
/// is TypeScript and the mpeg adapter steps aside, while the `.der` opens
/// with the SEQUENCE tag that makes it a certificate and then overruns, so
/// the x509 adapter has claimed it and failed on it.
#[test]
fn a_decline_leaves_no_note_and_a_failure_leaves_one() {
    let dir = common::scratch("decline-vs-failure");

    std::fs::write(dir.join("app.ts"), b"export const needle = 1;\n").unwrap();
    // 0x30 is the SEQUENCE tag every DER certificate opens with, and the
    // length that follows says more bytes are coming than the file holds.
    std::fs::write(
        dir.join("broken.der"),
        [0x30u8, 0x82, 0xFF, 0xFF, 0x41, 0x42],
    )
    .unwrap();

    let count = |file: &str, pat: &str| -> String {
        let out = rgx()
            .args(["-F", "-c"])
            .arg(pat)
            .arg(dir.join(file))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    // The decline: the file's own bytes are searchable, and nothing that is
    // not in the file is.
    assert_eq!(
        count("app.ts", "needle"),
        "1",
        "a declined file is searchable"
    );
    assert_eq!(
        count("app.ts", "[rgx: adapter"),
        "",
        "a decline must not leave a note behind"
    );
    assert_eq!(
        count("app.ts", "not an MPEG"),
        "",
        "the reason for a decline is not in the corpus either"
    );

    // The failure: the note is there, and the file's own bytes are too.
    assert_eq!(
        count("broken.der", "[rgx: adapter"),
        "1",
        "a failure must leave a note behind"
    );
    assert_eq!(
        count("broken.der", "AB"),
        "1",
        "the file's own bytes must survive a failing adapter"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// The control half of the test above: a real `.gz` is read through its
/// decoded member, and the member is named by stripping the suffix. Without
/// it, a fallback that served raw bytes unconditionally would make the test
/// above pass for the wrong reason.
#[test]
fn a_real_gzip_is_still_read_through_its_decoded_member() {
    let dir = common::scratch("real-gz");

    let gz = rgx_core::compress::GzipWriter::new().encode(b"the needle survives the round trip\n");
    assert!(
        rgx_core::compress::gzip::GzipReader::is_gzip(&gz),
        "the fixture must really be gzip, or this test proves nothing"
    );
    std::fs::write(dir.join("real.gz"), &gz).unwrap();

    let out = rgx()
        .args(["-F", "--json"])
        .arg("needle")
        .arg(dir.join("real.gz"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("the needle survives the round trip"),
        "the decoded payload must be searched:\n{stdout}"
    );
    // The payload is reported under `real.gz!real` — the suffix stripped and
    // the member re-entered through the pipeline — which is what separates
    // "the decoder ran" from "the raw file happened to contain the text".
    // The unit's own `adapter` is `raw` at that point: the member has no
    // compression extension left, so nothing claims it and it falls through.
    assert!(
        stdout.contains("real.gz!real"),
        "the member must be named by stripping the suffix:\n{stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A pack store must never silently shrink what the same query finds.
///
/// What this holds down: `rgx --tv-build .` is a setup command the README
/// recommends, and it used to change the *answer* of the next
/// `rgx PATTERN .` -- the member inside a `.gz` simply stopped being
/// reported, with nothing on stdout or stderr saying so. The store indexes
/// the corpus verbatim, so the slice a worker searches is the file the
/// direct path would have read; `run_tv_query` now runs the adapter
/// pipeline on that slice, and the admission rule that used to decline the
/// store is gone because the reason for it is. A pack answer and a direct
/// answer must agree on the same corpus -- not in count but in content,
/// member paths included.
#[test]
fn a_pack_store_answers_what_the_direct_path_answers() {
    let dir = common::scratch("tv-adapter-equivalence");
    let inner = dir.join("inner");
    std::fs::create_dir_all(&inner).unwrap();

    std::fs::write(
        dir.join("a.txt"),
        b"needle in a plain file
",
    )
    .unwrap();
    std::fs::write(
        inner.join("b.txt"),
        b"needle in a plain file
",
    )
    .unwrap();

    // A real gzip member, so the archive adapter has something to claim.
    // Built with the flate2 that rgx-adapters-archive already depends on
    // rather than shelling out, so the test does not need an external tool.
    let gz = {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(
            b"needle only inside the compressed member
",
        )
        .unwrap();
        enc.finish().unwrap()
    };
    std::fs::write(inner.join("b.txt.gz"), &gz).unwrap();

    // `-F -c` first: the count is the cheapest thing that can disagree.
    let count = |extra: &[&str]| -> String {
        let out = rgx()
            .args(["-F", "-c"])
            .args(extra)
            .arg("needle")
            .arg(&dir)
            .env_remove("RGX_ADAPTER_VIEW")
            .output()
            .expect("spawn rgx");
        // Sorted for the reason the line set below is sorted: `-c` prints one
        // line per file, the walker's order is not deterministic, and the pack
        // store answers in pack order. The comparison is about the SET of
        // per-file counts, and an unsorted comparison of a set is a
        // comparison that fails on a machine that walked the tree in another
        // order -- which is what a Linux runner does.
        let mut v: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        v.sort();
        v.join("\n")
    };
    // Sorted before it is returned. The comparison this test exists for is
    // "the pack store answers what the direct path answers", which is a
    // question about the SET of lines, not their order.
    //
    // Two separate order sources had to be handled. The walker is parallel,
    // so the direct path's order is not deterministic run to run. And the
    // pack store does NOT honour `--sort path` at all -- it answers in pack
    // order -- so asking the binary to sort fixes only half of it. Sorting
    // here handles both, and dropping `--sort path` keeps the test on the
    // default behaviour it is meant to describe.
    let lines = |extra: &[&str]| -> Vec<String> {
        let out = rgx()
            .args(["-F", "-n"])
            .args(extra)
            .arg("needle")
            .arg(&dir)
            .env_remove("RGX_ADAPTER_VIEW")
            .output()
            .expect("spawn rgx");
        let mut v: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        v.sort();
        v
    };

    let before_count = count(&[]);
    assert!(
        before_count != "0" && !before_count.is_empty(),
        "the fixture must be findable before any store exists, got {before_count:?}"
    );
    let before_lines = lines(&[]);
    assert!(
        before_lines.iter().any(|l| l.contains("b.txt.gz!b.txt")),
        "the fixture's gz member must be reported by the direct path:
{before_lines:#?}"
    );

    let build = rgx()
        .arg("--tv-build")
        .arg(&dir)
        .output()
        .expect("spawn rgx");
    assert!(
        build.status.success(),
        "--tv-build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    assert!(
        dir.join(".rgx-tv").is_dir(),
        "--tv-build did not leave a store where the detector looks for one"
    );

    // The regression, three ways. Same command, same corpus, one setup step
    // in between -- detected, forced, and line-for-line.
    assert_eq!(
        count(&[]),
        before_count,
        "building a pack store changed the count of the same query"
    );
    assert_eq!(
        lines(&[]),
        before_lines,
        "building a pack store changed the lines of the same query"
    );
    assert_eq!(
        count(&["--tv"]),
        before_count,
        "an explicit --tv must answer what the direct path answers, now that          the pack searcher runs the adapters"
    );
    assert_eq!(
        lines(&["--tv"]),
        before_lines,
        "an explicit --tv must print the same lines, member paths included"
    );

    // The detector promotes rather than declines, and says so.
    let explained = rgx()
        .args(["-F", "-c", "--explain-engine"])
        .arg("needle")
        .arg(&dir)
        .output()
        .expect("spawn rgx");
    let stderr = String::from_utf8_lossy(&explained.stderr);
    assert!(
        stderr.contains("selected engine: tv"),
        "--explain-engine must say the pack engine ran:
{stderr}"
    );
    assert!(
        !stderr.contains("does not run adapters"),
        "the pack searcher runs adapters now; the old warning is a lie:
{stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// The n-gram filter must never prune a file the query would print.
///
/// What this holds down: the pack query rejects a file whose stored
/// signature lacks a bit the pattern's holds, before reading its bytes.
/// That is only sound while the bytes searched ARE the bytes signed, so
/// the corpus here is built from the shapes where they are not: a regex
/// alternation where each file holds one branch, a quantified byte, a
/// folded spelling, an inverted query (`-v` owes output to files that hold
/// NO literal), a gzip member (the adapter's text, not the compressed
/// bytes), and a UTF-16LE file (the searcher decodes the mark, so the
/// signature must cover the decoded text). Every query is compared
/// line-for-line against the direct path on the same tree, and the plain
/// literal case must show the filter actually pruning -- a filter that
/// stands down for everything would pass every comparison silently.
#[test]
fn the_n_gram_filter_never_prunes_a_file_the_query_prints() {
    let dir = common::scratch("tv-ngram-soundness");
    std::fs::create_dir_all(dir.join("inner")).unwrap();

    // One branch of the alternation per file, and a file the quantified
    // pattern matches without the quantified byte.
    std::fs::write(dir.join("alt.txt"), b"xx efgh yy\n").unwrap();
    std::fs::write(dir.join("alt2.txt"), b"xx abcd yy\n").unwrap();
    std::fs::write(dir.join("quant.txt"), b"zz abcefgh yy\n").unwrap();
    std::fs::write(dir.join("upper.txt"), b"xx NEEDLE yy\n").unwrap();
    std::fs::write(dir.join("nolit.txt"), b"just ordinary words\n").unwrap();
    std::fs::write(dir.join("plain.txt"), b"xx needle yy\n").unwrap();

    // A gzip member: the compressed bytes hold no ASCII run of the needle,
    // and the match lives in the adapter's output. A filter that looked at
    // the stored signature without standing down for claimed extensions
    // would delete this file from the answer.
    let gz = {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(b"needle only inside the compressed member\n")
            .unwrap();
        enc.finish().unwrap()
    };
    std::fs::write(dir.join("inner/b.txt.gz"), &gz).unwrap();
    // And one whose member does NOT match: under `--files-without-match` it
    // is a miss and must be listed -- the pack path answers claimed files
    // itself and, without a listing of its own, dropped such files from the
    // answer while the direct path listed them.
    let gz_miss = {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(b"nothing to find in this member\n").unwrap();
        enc.finish().unwrap()
    };
    std::fs::write(dir.join("inner/c.txt.gz"), &gz_miss).unwrap();

    // UTF-16LE under a mark: the searcher matches in the decoded text, so
    // the stored signature must cover that text and not the raw bytes.
    let mut utf16 = vec![0xff, 0xfe];
    for b in b"xx needle yy\n" {
        utf16.push(*b);
        utf16.push(0x00);
    }
    std::fs::write(dir.join("utf16.txt"), &utf16).unwrap();

    // One runner, stdout only: every comparison below is full output,
    // because a count can agree while a file's lines or name do not.
    let run = |args: &[&str], pat: &str| -> String {
        let out = rgx()
            .args(args)
            .arg(pat)
            .arg(&dir)
            .env_remove("RGX_ADAPTER_VIEW")
            .output()
            .expect("spawn rgx");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    // The traps first, on the direct path, so the fixture is proven
    // findable before any store exists.
    let queries: &[(&[&str], &str)] = &[
        (&["-n", "--sort", "path"], "abcd|efgh"),
        (&["-n", "--sort", "path"], "abcd?efgh"),
        (&["-n", "--sort", "path"], "(?i)needle"),
        (&["-i", "-n", "--sort", "path"], "needle"),
        (&["-v", "-n", "--sort", "path"], "needle"),
        (&["--files-without-match", "--sort", "path"], "needle"),
        (&["-n", "--sort", "path"], "needle"),
    ];
    let mut before = Vec::new();
    for (args, pat) in queries {
        let out = run(args, pat);
        assert!(
            !out.is_empty(),
            "query {pat:?} {args:?} must find something on the direct path, got nothing"
        );
        before.push(out);
    }
    // The alternation must be one branch per file, or the trap is nothing.
    assert!(
        before[0].contains("alt.txt") && before[0].contains("alt2.txt"),
        "each alternation branch must be found in its own file:\n{}",
        before[0]
    );

    let build = rgx()
        .arg("--tv-build")
        .arg(&dir)
        .output()
        .expect("spawn rgx");
    assert!(
        build.status.success(),
        "--tv-build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    for (i, (args, pat)) in queries.iter().enumerate() {
        let mut tv_args = vec!["--tv"];
        tv_args.extend_from_slice(args);
        assert_eq!(
            run(&tv_args, pat),
            before[i],
            "--tv answered a different thing for {pat:?} {args:?}"
        );
        assert_eq!(
            run(args, pat),
            before[i],
            "the detected engine answered a different thing for {pat:?} {args:?}"
        );
    }

    // The filter must actually prune on this store: a query that stands
    // down for every file would pass every comparison above and mean
    // nothing. `needle` is a plain literal over files that hold it and
    // files that do not, and none of them is adapter-claimed except the gz.
    let out = rgx()
        .args(["-F", "-c", "--tv"])
        .arg("needle")
        .arg(&dir)
        .env_remove("RGX_ADAPTER_VIEW")
        .env("RGX_NGRAM_STATS", "1")
        .output()
        .expect("spawn rgx");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let pruned = stderr
        .split("pruned ")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(
        pruned >= 1,
        "the filter pruned nothing on a corpus built to be prunable; \
         the wiring is inert:\n{stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A declared `-E` encoding decodes every input surface, or the flag means
/// nothing.
///
/// What this holds down: `-E utf-16le` reached no decode at all -- not for a
/// named file, not for a walked one, not through a store -- so `rg` found
/// the line and `rgx` exited 1 on the same bytes. The decode now lives in
/// the searcher (`Config::forced_bom`), which is where the byte-order-mark
/// decode already lived, so every raw-input surface gets it once: a named
/// file, a walked one, the streaming reader, stdin. The binary heuristic
/// asks the DECODED view (`binary_cut`'s forced arm), because NUL-dense
/// UTF-16 is binary before that decode and text after it -- the same rule
/// the mark arm has always applied. And the pack store must answer what the
/// direct path answers under the same flag.
#[test]
fn a_declared_encoding_decodes_every_input_surface() {
    let dir = common::scratch("forced-encoding");

    let text = "xx needle yy\n";
    // UTF-16LE, NO mark: only a declared encoding can decode it. The raw
    // bytes interleave a NUL after every ASCII byte, so the NUL heuristic
    // calls it binary and no ASCII run of the needle exists in it.
    let mut le = Vec::new();
    for c in text.chars() {
        let b = (c as u32).to_le_bytes();
        le.push(b[0]);
        le.push(b[1]);
    }
    std::fs::write(dir.join("u16le.txt"), &le).unwrap();
    // UTF-16BE, no mark: the same claim the other way.
    let mut be = Vec::new();
    for c in text.chars() {
        let b = (c as u32).to_be_bytes();
        be.push(b[2]);
        be.push(b[3]);
    }
    std::fs::write(dir.join("u16be.txt"), &be).unwrap();
    std::fs::write(dir.join("plain.txt"), text).unwrap();

    let run = |args: &[&str]| -> (String, i32) {
        let out = rgx()
            .arg("needle")
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn rgx");
        (
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
            out.status.code().unwrap_or(-1),
        )
    };

    // The fixture proves itself undecodable without the flag: the raw bytes
    // hold no ASCII run of the needle.
    let (out, code) = run(&["-c", &dir.join("u16le.txt").to_string_lossy()]);
    assert_eq!(code, 1, "without -E the UTF-16 file must not match: {out}");

    // A named file, per encoding. This is the case rg answers and rgx
    // answered with nothing.
    for (enc, name) in [("utf-16le", "u16le.txt"), ("utf-16be", "u16be.txt")] {
        let f = dir.join(name).to_string_lossy().to_string();
        let (out, code) = run(&["-E", enc, &f]);
        assert_eq!(code, 0, "-E {enc} on {name} must match: {out}");
        assert!(
            out.contains("xx needle yy"),
            "-E {enc} on {name} must print the decoded line: {out}"
        );
    }

    // A walked file. The binary heuristic runs before anything decodes, so
    // it must ask the decoded view or this file is dropped as binary and
    // never searched at all.
    let (out, code) = run(&["-E", "utf-16le", "-c", &dir.to_string_lossy()]);
    assert_eq!(code, 0, "the walk must find the decoded file: {out}");
    assert!(
        out.contains("u16le.txt:1"),
        "the walked UTF-16LE file must be counted: {out}"
    );
    assert!(
        !out.contains("plain.txt"),
        "-E utf-16le decodes every file; plain.txt's ASCII is not UTF-16: {out}"
    );

    // stdin is raw input like any other.
    let mut child = rgx()
        .args(["-E", "utf-16le", "needle"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn rgx");
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(&le).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "stdin must decode too");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("xx needle yy"),
        "stdin must print the decoded line: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // And the pack store answers what the direct path answers, flag and
    // all. This also exercises the n-gram filter standing down for `-E`.
    let build = rgx()
        .arg("--tv-build")
        .arg(&dir)
        .output()
        .expect("spawn rgx");
    assert!(
        build.status.success(),
        "--tv-build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let dir_s = dir.to_string_lossy().to_string();
    for extra in [
        &["-E", "utf-16le", "-n", "--sort", "path"][..],
        &["-n", "--sort", "path"][..],
    ] {
        let mut direct_args = extra.to_vec();
        direct_args.push(&dir_s);
        let d = run(&direct_args);
        let mut tv_args = vec!["--tv"];
        tv_args.extend_from_slice(extra);
        tv_args.push(&dir_s);
        let t = run(&tv_args);
        assert_eq!(
            t, d,
            "--tv answered a different thing than the direct path for {extra:?}"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// A store the filesystem has moved is answered through the overlay.
///
/// What this holds down: automatic promotion used to answer from bytes the
/// filesystem had already replaced -- edit a file after `--tv-build`, and
/// `rgx -c changed` said "no match" while the direct path found it, with
/// nothing on either stream naming the store. The decline that fixed the
/// wrong answer threw the whole store away for one changed file; the
/// dirty-file overlay keeps both properties at once: the changed files are
/// re-read off disk and answered from the bytes there, the rest from the
/// store, so the automatic answer IS the direct answer while the store
/// still pays for its share. `--explain-engine` names the count and the
/// mechanism, explicit `--tv` warns aloud, and `--tv-build` repairs. The
/// one shape the check cannot see is a file added after the build -- that
/// needs the walk the store exists to avoid -- and the documentation names
/// that boundary rather than pretending otherwise.
#[test]
fn a_store_the_filesystem_has_moved_is_answered_through_the_overlay() {
    let dir = common::scratch("stale-store");
    std::fs::write(dir.join("a.txt"), b"hello world\n").unwrap();
    std::fs::write(dir.join("b.txt"), b"second file\n").unwrap();

    let build = rgx()
        .arg("--tv-build")
        .arg(&dir)
        .output()
        .expect("spawn rgx");
    assert!(
        build.status.success(),
        "--tv-build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    // A clean store still promotes.
    let explain = rgx()
        .arg("--explain-engine")
        .arg("hello")
        .arg(&dir)
        .output()
        .expect("spawn rgx");
    let explain = String::from_utf8_lossy(&explain.stderr).to_string();
    assert!(
        explain.contains("selected engine: tv") && explain.contains("fresh against the filesystem"),
        "a clean store must promote and say it is fresh:\n{explain}"
    );

    // Mutate: change one file's content and length.
    std::fs::write(dir.join("a.txt"), b"hello changed world of stale bytes\n").unwrap();

    let run = |args: &[&str]| -> (String, String, i32) {
        let out = rgx()
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn rgx");
        (
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
            out.status.code().unwrap_or(-1),
        )
    };

    // The core property: the automatic answer is the direct answer.
    let (auto_out, auto_err, auto_code) = run(&["-c", "changed", &dir.to_string_lossy()]);
    let (direct_out, _, direct_code) =
        run(&["--engine", "rgx", "-c", "changed", &dir.to_string_lossy()]);
    assert_eq!(
        auto_code, direct_code,
        "the automatic answer must have the direct answer's status:\n{auto_err}"
    );
    assert_eq!(
        auto_out, direct_out,
        "the automatic answer must be the direct answer after a mutation:\n{auto_err}"
    );
    assert!(
        auto_out.contains("a.txt:1"),
        "the mutated file's match must be found:\n{auto_out}"
    );

    // And the overlay is named, not silent.
    let (_, explain_err, _) = run(&["--explain-engine", "-c", "changed", &dir.to_string_lossy()]);
    assert!(
        explain_err.contains("changed since it was built")
            && explain_err.contains("selected engine: tv")
            && explain_err.contains("dirty-file overlay"),
        "--explain-engine must name the staleness and the overlay:\n{explain_err}"
    );

    // Explicit --tv is the user's trade: honoured, warned aloud, and no
    // longer a snapshot -- the overlay answers the changed file from disk.
    let (tv_out, tv_err, tv_code) = run(&["--tv", "-c", "changed", &dir.to_string_lossy()]);
    assert_eq!(
        tv_code, 0,
        "the overlay must find the mutated file's match under --tv too: {tv_out}"
    );
    assert_eq!(
        tv_out, direct_out,
        "explicit --tv must answer what the direct path answers after a mutation:\n{tv_err}"
    );
    assert!(
        tv_err.contains("changed since this store was built"),
        "explicit --tv must warn about the drift:\n{tv_err}"
    );

    // --tv-build repairs, and the automatic path promotes again.
    let rebuild = rgx()
        .arg("--tv-build")
        .arg(&dir)
        .output()
        .expect("spawn rgx");
    assert!(rebuild.status.success());
    let (fixed_out, _, fixed_code) = run(&["-c", "changed", &dir.to_string_lossy()]);
    assert_eq!(
        (fixed_out.as_str(), fixed_code),
        (direct_out.as_str(), direct_code),
        "after a refresh the automatic answer is the direct answer again"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// An incremental update of a pack store adds new files, tombstones
/// removed ones, and packs modified files into new packs without
/// rewriting the unchanged ones. The whole path -- `update_store` in
/// `rgx-core/src/tv_runtime/update.rs` + the in-house adapter pipeline
/// at search time -- has to agree with the direct-path query at every
/// step.
#[test]
fn an_incremental_update_keeps_the_pack_store_in_sync() {
    // A fresh tree (not `fixture_dir()`, which carries hello.txt /
    // packed.gz / mail.eml and would have its own needle counts).
    let dir = common::scratch("tv-incremental");

    // Three files, only the first has the needle.
    std::fs::write(dir.join("a.txt"), "first a needle\n").unwrap();
    std::fs::write(dir.join("b.txt"), "b without the word\n").unwrap();
    std::fs::write(dir.join("c.txt"), "c without the word\n").unwrap();

    // Build the first generation.
    let build = rgx()
        .args(["--tv-build"])
        .arg(&dir)
        .output()
        .expect("spawn rgx --tv-build");
    assert!(
        build.status.success(),
        "--tv-build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    // `-n` writes a line per hit; `lines.count()` is the answer in both
    // the direct and the pack-search directions.
    let count_at = |extra: &[&str]| -> usize {
        let out = rgx()
            .args(["-F", "-n"])
            .args(extra)
            .arg(NEEDLE)
            .arg(&dir)
            .output()
            .expect("spawn rgx");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .count()
    };
    assert_eq!(count_at(&["--tv"]), 1, "first build: a.txt only");

    // Add a new file that matches; modify an existing one to add the
    // needle; delete a file that did not.
    std::fs::write(dir.join("d.txt"), "needle in d\n").unwrap();
    std::fs::write(
        dir.join("a.txt"),
        "first a needle\nrewritten with the needle\n",
    )
    .unwrap();
    std::fs::remove_file(dir.join("b.txt")).unwrap();

    // Run an incremental update via the same `--tv-build` flag --
    // `build_or_update_store_with_extractor` sees the manifest already
    // exists and routes to `update_store`. The fingerprint of the new
    // walk (same flags, same root) has to match what the build wrote,
    // otherwise update_store refuses.
    let update = rgx()
        .args(["--tv-build"])
        .arg(&dir)
        .output()
        .expect("spawn rgx --tv-build (update)");
    assert!(
        update.status.success(),
        "--tv-build update failed: {}",
        String::from_utf8_lossy(&update.stderr)
    );

    // After the update: a.txt (modified, now hits twice) and d.txt (new)
    // both match; b.txt is tombstoned and never appears; c.txt was
    // unchanged.
    assert_eq!(
        count_at(&["--tv"]),
        3,
        "after update: a.txt (modified, 2 hits) + d.txt (new)"
    );

    // The direct path agrees the search path.
    assert_eq!(count_at(&[]), 3);

    // The detector still picks the pack store on the post-update tree:
    // an unchanged c.txt and a tombstoned b.txt both stay in the
    // manifest, so the store has to be the same shape as before.
    let explained = rgx()
        .args(["--explain-engine", "-F", "-c"])
        .arg(NEEDLE)
        .arg(&dir)
        .output()
        .expect("spawn rgx --explain-engine");
    let stderr = String::from_utf8_lossy(&explained.stderr);
    assert!(
        stderr.contains("selected engine: tv"),
        "the detector should pick the pack engine after an update, got: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn type_filter_includes_only_named_types() {
    let dir = common::scratch("type-test");
    std::fs::write(dir.join("a.rs"), "fn main() { let needle = 1; }\n").unwrap();
    std::fs::write(dir.join("b.py"), "def main():\n    needle = 1\n").unwrap();
    std::fs::write(
        dir.join("c.go"),
        "package main\nfunc main() { needle := 1 }\n",
    )
    .unwrap();
    std::fs::write(dir.join("d.js"), "console.log('needle')\n").unwrap();

    // 1. -t rust restricts to .rs only
    let out_rust = rgx()
        .args(["needle", "-t", "rust", "--files"])
        .arg(&dir)
        .output()
        .expect("spawn rgx -t rust --files");
    let stdout = String::from_utf8_lossy(&out_rust.stdout);
    assert!(stdout.contains("a.rs"), "rust filter missed a.rs: {stdout}");
    assert!(
        !stdout.contains("b.py"),
        "rust filter leaked b.py: {stdout}"
    );
    assert!(
        !stdout.contains("c.go"),
        "rust filter leaked c.go: {stdout}"
    );
    assert!(
        !stdout.contains("d.js"),
        "rust filter leaked d.js: {stdout}"
    );

    // 2. -t rust -t python accepts both, drops the others
    let out_two = rgx()
        .args(["needle", "-t", "rust", "-t", "python", "--files"])
        .arg(&dir)
        .output()
        .expect("spawn rgx -t rust -t python --files");
    let stdout = String::from_utf8_lossy(&out_two.stdout);
    assert!(stdout.contains("a.rs"));
    assert!(stdout.contains("b.py"));
    assert!(!stdout.contains("c.go"));

    // 3. -T python excludes python files, keeps the rest
    let out_excl = rgx()
        .args(["needle", "-T", "python", "--files"])
        .arg(&dir)
        .output()
        .expect("spawn rgx -T python --files");
    let stdout = String::from_utf8_lossy(&out_excl.stdout);
    assert!(!stdout.contains("b.py"), "exclude missed b.py: {stdout}");
    assert!(stdout.contains("a.rs"));

    // 4. --type-add extends the table; a new .foo type is recognised.
    std::fs::write(dir.join("e.foo"), "needle in a custom type\n").unwrap();
    let out_add = rgx()
        .args([
            "needle",
            "-t",
            "madeup",
            "--type-add",
            "madeup:foo",
            "--files",
        ])
        .arg(&dir)
        .output()
        .expect("spawn rgx --type-add madeup:foo --files");
    let stdout = String::from_utf8_lossy(&out_add.stdout);
    assert!(
        stdout.contains("e.foo"),
        "--type-add did not pick up e.foo: {stdout}"
    );

    // 5. --type-list prints every registered type and exits 0
    let out_list = rgx()
        .arg("--type-list")
        .output()
        .expect("spawn rgx --type-list");
    let stdout = String::from_utf8_lossy(&out_list.stdout);
    assert!(
        stdout.contains("rust"),
        "--type-list missing rust: {stdout}"
    );
    assert!(
        stdout.contains("python"),
        "--type-list missing python: {stdout}"
    );
    assert!(out_list.status.success(), "--type-list exit non-zero");

    // 6. Body match: search through the type filter actually walks only the
    // matching file, so the count line is one entry (b.py) rather than three.
    let out_search = rgx()
        .args(["needle", "-t", "python", "-c"])
        .arg(&dir)
        .output()
        .expect("spawn rgx -t python -c");
    let stdout = String::from_utf8_lossy(&out_search.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected one matching file via -t python: {stdout}"
    );
    assert!(
        lines[0].ends_with("b.py:1"),
        "expected b.py:1 line: {stdout}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A file can be several types at once, and the last type flag that matches
/// it decides.
///
/// `lib.min.js` is a `.js` file and a `minified` one, so `-t javascript`
/// keeps it and `-t minified` keeps it too. The order of the flags is what
/// decides between them: `-t javascript -T minified` drops the file, and
/// `-T minified -t javascript` keeps it. That is ripgrep's rule, and it is
/// the rule the `ignore` crate implements.
#[test]
fn a_file_matches_every_type_it_satisfies_and_the_last_flag_decides() {
    let dir = common::scratch("type-order");
    std::fs::write(dir.join("lib.min.js"), "needle\n").unwrap();
    std::fs::write(dir.join("plain.js"), "needle\n").unwrap();

    let listed = |args: &[&str]| -> Vec<String> {
        let out = rgx()
            .args(args)
            .arg(&dir)
            .output()
            .expect("spawn rgx --files");
        assert!(
            out.status.success(),
            "rgx {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        stdout
            .lines()
            .map(|l| l.trim_start_matches("./").to_string())
            .filter(|l| !l.is_empty())
            .collect()
    };

    // The overlap: a .min.js file is a javascript file.
    let js = listed(&["--files", "-t", "javascript"]);
    assert!(
        js.iter().any(|p| p.ends_with("lib.min.js")),
        "-t javascript must keep a .min.js file: {js:?}"
    );

    // The exclusion last: it decides.
    let excluded = listed(&["--files", "-t", "javascript", "-T", "minified"]);
    assert!(
        !excluded.iter().any(|p| p.ends_with("lib.min.js")),
        "-t javascript -T minified must drop the .min.js file: {excluded:?}"
    );
    assert!(
        excluded.iter().any(|p| p.ends_with("plain.js")),
        "-t javascript -T minified must keep the plain .js file: {excluded:?}"
    );

    // The inclusion last: it decides, and the file comes back.
    let included = listed(&["--files", "-T", "minified", "-t", "javascript"]);
    assert!(
        included.iter().any(|p| p.ends_with("lib.min.js")),
        "-T minified -t javascript must keep the .min.js file: {included:?}"
    );

    // The name ripgrep uses for the type is another name for the same
    // type, so a flag written out of rg's habit works.
    let alias = listed(&["--files", "-t", "js"]);
    assert_eq!(
        alias, js,
        "-t js must select the same files as -t javascript"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A type name the table does not have is refused, the way rg refuses it.
///
/// A filter that matches nothing is indistinguishable from a search that
/// found nothing: the user asked for `rust` and got silence, which reads as
/// "there is no Rust here" instead of "there is no type called `rust`". rg
/// answers `rg: unrecognized file type: X` and exits 2; so must rgx.
///
/// The table the check reads is the one the flags describe, so a type the
/// user added on the same command line is a type rgx knows, and a type
/// `--type-clear` wiped is a type rgx refuses.
#[test]
fn an_unknown_type_name_is_refused() {
    let dir = common::scratch("unknown-type");
    std::fs::write(dir.join("a.rs"), "fn main() { let needle = 1; }\n").unwrap();

    for args in [
        ["needle", "-t", "nosuchtype"].as_slice(),
        ["needle", "-T", "nosuchtype"].as_slice(),
        ["needle", "-t", "rust", "-T", "nosuchtype"].as_slice(),
        ["needle", "-t", "Rust"].as_slice(),
        ["needle", "--type-clear", "-t", "rust"].as_slice(),
    ] {
        let (code, stderr) = run_stderr(&dir, args);
        assert_eq!(code, 2, "rgx {args:?} exited {code}, stderr: {stderr}");
        assert!(
            stderr.contains("unrecognized file type:"),
            "rgx {args:?} did not name the unknown type: {stderr}"
        );
        assert!(
            !stderr.is_empty(),
            "rgx {args:?} refused the type without saying which: {stderr}"
        );
    }

    // A type added on the same command line is a type the table has, so the
    // same flag that was refused above is accepted here.
    let out = rgx()
        .args([
            "needle",
            "-t",
            "madeup",
            "--type-add",
            "madeup:rs",
            "--files",
        ])
        .arg(&dir)
        .output()
        .expect("spawn rgx --type-add madeup:rs --files");
    assert!(
        out.status.success(),
        "a type added on the same line must be accepted: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("a.rs"),
        "the added type did not match a.rs: {stdout}"
    );

    // And a type the table does have still works, so the check is not
    // refusing everything.
    let (code, stdout) = run(&dir, &["needle", "-t", "rust", "--files"]);
    assert_eq!(code, 0, "-t rust failed: {stdout}");
    assert!(stdout.contains("a.rs"), "-t rust missed a.rs: {stdout}");

    std::fs::remove_dir_all(&dir).ok();
}

/// `-0` / `--null` swaps the file-list separator from `\n` to `\0`,
/// the shape `xargs -0` and `find -print0` expect. The default
/// stays `\n` so existing pipelines keep working.
#[test]
fn null_flag_terminates_file_list_with_nul() {
    // Build a unique temp dir under the system temp dir; the test
    // suite avoids a `tempfile` dev-dep by constructing the path
    // itself and removing the directory at the end.
    let dir = common::scratch("null-flag");
    std::fs::write(dir.join("a.txt"), "needle here\n").unwrap();
    std::fs::write(dir.join("b.txt"), "needle also\n").unwrap();

    // Default: newline-separated, exactly two entries.
    let (code, nl) = run(&dir, &["needle", "-l"]);
    assert_eq!(code, 0, "default -l failed: {nl}");
    let nl_entries: Vec<&str> = nl
        .split_terminator('\n')
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(
        nl_entries.len(),
        2,
        "expected two paths, got {nl_entries:?}"
    );

    // With `-0`: NUL-separated; the printable form splits on a NUL,
    // and the entries are the same two paths.
    let (code0, nul) = run(&dir, &["needle", "-l", "-0"]);
    assert_eq!(code0, 0, "-0 -l failed: {nul:?}");
    let nul_entries: Vec<&str> = nul
        .split_terminator('\0')
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(
        nul_entries.len(),
        2,
        "expected two NUL-separated paths, got {nul_entries:?}"
    );
    for entry in &nul_entries {
        assert!(
            !entry.contains('\n'),
            "NUL output must not contain LF: {entry:?}"
        );
    }
    assert!(nul.ends_with('\0'), "last byte must be NUL: {nul:?}");

    // Same shape via `--files` (the other file-list flag): the
    // separator is the same and `-0` works there too.
    let (codef, files_nul) = run(&dir, &["--files", "-0"]);
    assert_eq!(codef, 0, "--files -0 failed: {files_nul:?}");
    let files_entries: Vec<&str> = files_nul
        .split_terminator('\0')
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(
        files_entries.len(),
        2,
        "expected two --files NUL-separated paths, got {files_entries:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--heading` prints the file path only on the first match line of a
/// file; subsequent lines use the single-file `{line}:` shape. The
/// default (with stdout piped under cargo test) is no-heading, so
/// `--heading` is the change to assert.
#[test]
fn heading_prints_the_path_only_on_the_first_line() {
    let dir = common::scratch("heading");
    std::fs::write(dir.join("a.txt"), "needle one\nneedle two\nneedle three\n").unwrap();
    std::fs::write(dir.join("b.txt"), "needle here\n").unwrap();

    // --heading: the path appears once per file (before the first match
    // line); subsequent lines start at the line number.
    let (code_h, headed) = run(&dir, &["needle", "--heading"]);
    assert_eq!(code_h, 0, "--heading failed: {headed}");
    let lines: Vec<&str> = headed.lines().collect();
    assert_eq!(lines.len(), 4, "four match lines expected, got {lines:?}");
    let with_path = lines.iter().filter(|l| l.contains(".txt:")).count();
    let without_path = lines.iter().filter(|l| !l.contains(".txt:")).count();
    assert_eq!(
        with_path, 2,
        "expected exactly two heading lines, got {lines:?}"
    );
    assert_eq!(
        without_path, 2,
        "expected exactly two sublines, got {lines:?}"
    );

    // --no-heading forces the default shape: every line carries the path.
    let (code_n, no_headed) = run(&dir, &["needle", "--no-heading"]);
    assert_eq!(code_n, 0, "--no-heading failed: {no_headed}");
    let no_lines: Vec<&str> = no_headed.lines().collect();
    assert_eq!(no_lines.len(), 4);
    assert!(
        no_lines.iter().all(|l| l.contains(".txt:")),
        "every line must carry the path with --no-heading, got {no_lines:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--sort path` and `--sortr path` emit the file list in deterministic
/// order regardless of how the parallel walk produced them. Without the
/// flag the output order is whichever thread finished first.
#[test]
fn sort_path_emits_deterministic_order() {
    let dir = common::scratch("sort");
    std::fs::create_dir_all(dir.join("inner")).unwrap();
    // Names deliberately out of filesystem order so the unsorted case
    // would shuffle them.
    for n in ["z.txt", "a.txt", "m.txt", "b.txt"] {
        std::fs::write(dir.join(n), "x\n").unwrap();
    }
    // A nested name that sorts BEFORE its siblings' directory entry:
    // `inner/b.txt` sorts after `a.txt`, but a parallel walk discovers
    // `inner/` first and its contents before it comes back to `a.txt`.
    // This is the shape `--sort path` on SEARCH output has to fix; the
    // flat listing above never exercises it because listing already
    // sorted through `SortedSink`.
    std::fs::write(dir.join("inner").join("b.txt"), "x\n").unwrap();

    let (_c1, asc) = run(&dir, &["--files", "--sort", "path"]);
    let asc_lines: Vec<&str> = asc.lines().collect();
    let mut sorted = asc_lines.clone();
    sorted.sort();
    assert_eq!(
        asc_lines, sorted,
        "--sort path must produce ascending order"
    );

    let (_c2, desc) = run(&dir, &["--files", "--sortr", "path"]);
    let desc_lines: Vec<&str> = desc.lines().collect();
    // `--sortr` reverses the ascending order, so the output should be
    // the ascending list reversed.
    let expected: Vec<&str> = sorted.iter().copied().rev().collect();
    assert_eq!(
        desc_lines, expected,
        "--sortr path must produce descending order"
    );

    // SEARCH output, not just `--files`. Before the fix `args.sort` was
    // read only by the listing path, so `--sort path` on a query printed
    // walk order and the flag's help text was true of one mode and false
    // of the other. Assert on ORDER -- a set comparison would pass either
    // way, which is why the original test missed this.
    let search = |extra: &[&str]| -> Vec<String> {
        let out = rgx()
            .args(["-F", "-n"])
            .args(extra)
            .arg("x")
            .arg(&dir)
            .output()
            .expect("spawn rgx");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect()
    };
    let search_asc = search(&["--sort", "path"]);
    let mut search_sorted = search_asc.clone();
    search_sorted.sort();
    assert_eq!(
        search_asc, search_sorted,
        "--sort path must sort SEARCH output, not just --files:\n{search_asc:#?}"
    );
    // The nested file must actually be in the answer, or the assertion
    // above is vacuously true over a one-element list.
    assert!(
        search_asc.iter().any(|l| l.contains("inner")),
        "the nested fixture must be in the answer:\n{search_asc:#?}"
    );
    let search_desc = search(&["--sortr", "path"]);
    let search_expected: Vec<String> = search_sorted.iter().rev().cloned().collect();
    assert_eq!(
        search_desc, search_expected,
        "--sortr path must reverse SEARCH output"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--sort path` orders SEARCH output for the modes that do not go through
/// the default text renderer, too. Those modes take a different `Msg`
/// variant (`Hit` rather than `Text`), so each one can drift independently
/// of the others -- and `--count` / `-l` are one line per file, which is
/// the shape a set comparison would silently accept in any order.
#[test]
fn sort_path_orders_count_and_files_with_matches() {
    let dir = common::scratch("sortmodes");
    std::fs::create_dir_all(dir.join("inner")).unwrap();
    std::fs::write(dir.join("a.txt"), "needle\n").unwrap();
    std::fs::write(dir.join("inner").join("b.txt"), "needle\n").unwrap();
    // A name that sorts BEFORE `a.txt` is in a directory that sorts AFTER
    // it, so walk order and sorted order disagree.
    std::fs::write(dir.join("inner").join("0-first.txt"), "needle\n").unwrap();

    let ordered = |extra: &[&str]| -> Vec<String> {
        let out = rgx()
            .args(["-F", "needle"])
            .args(extra)
            .arg(&dir)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect()
    };

    for mode in [
        ["--sort", "path", "--count"],
        ["--sort", "path", "-l"],
        ["--sortr", "path", "--count"],
    ] {
        let got = ordered(&mode);
        let mut want = got.clone();
        if mode.contains(&"--sortr") {
            want.sort();
            want.reverse();
        } else {
            want.sort();
        }
        assert_eq!(
            got, want,
            "{mode:?} must emit paths in sorted order:\n{got:#?}"
        );
        assert!(
            got.len() >= 3,
            "{mode:?} must cover all three files, got {got:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--sort path` on `--json` and `--chunk`, the two modes that emit a block
/// per file rather than a line. Each block's path must arrive in sorted
/// order -- a set comparison of the blocks would pass in any order, which is
/// how `--sort path` on the text path survived so long.
#[test]
fn sort_path_orders_json_and_chunk_blocks() {
    let dir = common::scratch("sortblocks");
    std::fs::create_dir_all(dir.join("inner")).unwrap();
    std::fs::write(dir.join("a.txt"), "needle\n").unwrap();
    std::fs::write(dir.join("inner").join("b.txt"), "needle\n").unwrap();
    std::fs::write(dir.join("inner").join("0-first.txt"), "needle\n").unwrap();

    // --json: each file's block starts with a `begin` record naming the
    // path. The path is the only stable key that identifies the block.
    let out = rgx()
        .args(["-F", "--json", "--sort", "path", "needle"])
        .arg(&dir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let json_paths: Vec<String> = text
        .lines()
        .filter_map(|l| {
            // `"type":"begin"` records carry `"path":{"text":"..."}`.
            let l = l.trim();
            if !(l.starts_with('{') && l.contains("\"begin\"")) {
                return None;
            }
            let marker = "\"path\":{\"text\":\"";
            let i = l.find(marker)?;
            let rest = &l[i + marker.len()..];
            let j = rest.find('"')?;
            Some(rest[..j].to_string())
        })
        .collect();
    assert_eq!(
        json_paths.len(),
        3,
        "three json blocks expected, got {json_paths:?}"
    );
    let mut json_sorted = json_paths.clone();
    json_sorted.sort();
    assert_eq!(
        json_paths, json_sorted,
        "--json must emit blocks in path order:\n{json_paths:#?}"
    );

    // --chunk: each block starts with `=== path:line ===`.
    let out = rgx()
        .args(["-F", "--chunk", "80", "--sort", "path", "needle"])
        .arg(&dir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let chunk_paths: Vec<String> = text
        .lines()
        .filter_map(|l| {
            l.strip_prefix("=== ")
                .and_then(|r| r.split_once(':'))
                .map(|(p, _)| p.to_string())
        })
        .collect();
    assert_eq!(
        chunk_paths.len(),
        3,
        "three chunk headers expected, got {chunk_paths:?}"
    );
    let mut chunk_sorted = chunk_paths.clone();
    chunk_sorted.sort();
    assert_eq!(
        chunk_paths, chunk_sorted,
        "--chunk must emit blocks in path order:\n{chunk_paths:#?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `-E utf-16le` / `-E utf-16be` decode the input before searching, so a
/// search of "needle" finds a hit in a UTF-16 file that lacks a BOM.
#[test]
fn encoding_flag_decodes_utf16le_and_utf16be() {
    let dir = common::scratch("encoding");
    let needle_le: Vec<u8> = "needle".encode_utf16().flat_map(u16::to_le_bytes).collect();
    std::fs::write(dir.join("le.bin"), needle_le).unwrap();
    let needle_be: Vec<u8> = "needle".encode_utf16().flat_map(u16::to_be_bytes).collect();
    std::fs::write(dir.join("be.bin"), needle_be).unwrap();

    let (_c_le, hit_le) = run(&dir, &["needle", "-E", "utf-16le"]);
    assert!(
        hit_le.contains("le.bin"),
        "expected UTF-16LE file to be hit, got {hit_le:?}"
    );

    let (_c_be, hit_be) = run(&dir, &["needle", "-E", "utf-16be"]);
    assert!(
        hit_be.contains("be.bin"),
        "expected UTF-16BE file to be hit, got {hit_be:?}"
    );

    // Without -E, a UTF-16 file with no BOM is not decoded and the
    // literal "needle" (alternating ascii/nul bytes) does not appear.
    let (_c_no, miss) = run(&dir, &["needle"]);
    assert!(
        !miss.contains("le.bin") && !miss.contains("be.bin"),
        "without -E the UTF-16 files must not match, got {miss:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `-t pdf` must match an extensionless file whose first bytes are the
/// PDF signature. Extension-based classification alone would skip it.
#[test]
fn type_filter_uses_magic_bytes_for_extensionless_files() {
    let dir = common::scratch("magic");
    // extensionless PDF
    std::fs::write(dir.join("report"), b"%PDF-1.7\nneedle here\n").unwrap();
    // a plain text file with no extension: must NOT match -t pdf.
    std::fs::write(dir.join("notes"), b"just plain text with needle\n").unwrap();
    // a junk file with .pdf extension but no PDF signature: matches by
    // extension only, which is what the user asked for. (rg's `-t pdf`
    // behaves the same way.)
    std::fs::write(dir.join("fake.pdf"), b"not actually a pdf, has needle\n").unwrap();

    let (_c, only_pdf) = run(&dir, &["needle", "-t", "pdf"]);
    assert!(
        only_pdf.contains("report"),
        "extensionless PDF must match -t pdf via magic bytes, got {only_pdf:?}"
    );
    assert!(
        only_pdf.contains("fake.pdf"),
        "fake.pdf must match -t pdf via extension, got {only_pdf:?}"
    );
    assert!(
        !only_pdf.contains("notes"),
        "plain notes must NOT match -t pdf, got {only_pdf:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Like [`run`], but also hands back stderr — which is where a bad pattern's
/// complaint has to land for this test to mean anything.
fn run_err(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = rgx()
        .args(args)
        .arg(dir)
        .output()
        .expect("failed to spawn rgx");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A pattern the in-house engine cannot compile is a bad question, not a
/// search with no answer.
///
/// `build_byte` answers `None` outside the byte-mode subset and every caller
/// reads that as "no matcher", so the search returns exit 1 with nothing on
/// stdout and nothing on stderr — indistinguishable from a file that does not
/// contain the text. rg exits 2 and names the error. The two must not look the
/// same: a user who mistypes a class is told the file has no match, and goes
/// looking in the file.
#[test]
fn an_uncompilable_pattern_is_named_rather_than_answered_as_no_match() {
    let dir = common::scratch("badpat");
    let file = dir.join("f.txt");
    std::fs::write(&file, "hello\nworld\n").unwrap();

    let (code, out, err) = run_err(&dir, &["[", "f.txt"]);
    assert_eq!(code, 2, "rg exits 2 on a bad pattern; stderr was: {err}");
    assert!(out.is_empty(), "nothing should reach stdout: {out}");
    assert!(
        err.contains("regex parse error"),
        "the error must name itself rather than read as 'no match': {err}"
    );

    // And the check must not fire on patterns that DO compile: this is the
    // half that would turn a fix into a regression.
    for ok in ["pub fn", "a.b", "[a-z]+", "\\d+", "^pub", "a|b"] {
        let (c, _o, e) = run_err(&dir, &[ok, "f.txt"]);
        assert_ne!(c, 2, "{ok:?} was rejected as uncompilable: {e}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--files` lists a PATH, and a path is not a pattern.
///
/// `--files` and `--tv-build` take a bare token the parser files under
/// `pattern`, and `fixup_args` moves it. Run the pattern check before that
/// move and it compiles a PATH as a regex, which on Windows kills any
/// directory component starting with an escape introducer (`p`, `x`, `d`,
/// `w`, `1`-`9`). `--files` with no path was always fine — `pattern` was
/// `None` and nothing compiled — which is why it hid.
///
/// See `benchmark/files-path-as-regex.md`.
#[test]
fn files_mode_does_not_compile_a_path_as_a_pattern() {
    let dir = common::scratch("filespath");
    // The trap directory name: `p` after a separator is `\p` to the byte engine.
    // A generated name dodges it and the test passes against the very bug it
    // exists to catch.
    let trap = dir.join("p0");
    std::fs::create_dir_all(&trap).unwrap();
    std::fs::write(trap.join("needle.txt"), "needle\n").unwrap();

    // Spelled with the platform separator, which on Windows is the `\p`.
    let spelled = trap.to_string_lossy().into_owned();
    for args in [
        vec!["--files".to_string(), spelled.clone()],
        vec![
            "--files".to_string(),
            spelled.clone(),
            "-g".to_string(),
            "*.txt".to_string(),
        ],
        vec![
            "--files".to_string(),
            "--no-ignore".to_string(),
            spelled.clone(),
        ],
    ] {
        let out = rgx().args(&args).output().expect("failed to spawn rgx");
        let code = out.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_ne!(
            code,
            2,
            "`rgx {}` rejected a PATH as a pattern: {stderr}",
            args.join(" ")
        );
        assert!(
            stdout.contains("needle.txt"),
            "`rgx {}` did not list the file: {stdout:?}",
            args.join(" ")
        );
        assert!(
            !stderr.contains("regex parse error"),
            "a path must never reach the regex compiler: {stderr}"
        );
    }

    // The other half: a genuine bad PATTERN must still be refused. Without
    // this the fix could have been "stop checking patterns under --files",
    // which would turn the test above green and this line red.
    let bad = rgx().args([r"\p0"]).output().expect("spawn");
    assert_eq!(
        bad.status.code().unwrap_or(-1),
        2,
        "a real pattern is still a pattern and must still be checked"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Build an `.eri` (Everything-Rs Index) image from `(name, path)` pairs.
///
/// The layout is the writer's: `ERI1` | u32 version | u16 root_len | root |
/// u64 count, then per record frn/parent/size/attrs/is_dir, u16 name_len +
/// name, u16 path_len + path.
fn eri_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"ERI1");
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&3u16.to_le_bytes());
    b.extend_from_slice(b"C:\\");
    b.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (i, (name, path)) in entries.iter().enumerate() {
        b.extend_from_slice(&(100 + i as u64).to_le_bytes());
        b.extend_from_slice(&5u64.to_le_bytes());
        b.extend_from_slice(&42u64.to_le_bytes());
        b.extend_from_slice(&0x20u32.to_le_bytes());
        b.push(0);
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        b.extend_from_slice(&(path.len() as u16).to_le_bytes());
        b.extend_from_slice(path);
    }
    b
}

/// What the `.eri` adapter must do at the CLI, which its unit tests cannot see.
///
/// `rgx-adapters-tabular`'s tests call `Eri::extract` directly, so they bypass
/// the Registry and the CLI entirely. Two things are only observable here:
///
/// 1. The decoded paths really print as lines. `Outcome::Text` reuses the
///    walked file's own path, so this unit is searched with the *binary*
///    searcher (`RgxBinaryDetection::Quit(0)`) rather than the text one. A NUL
///    in the first 64 KiB makes `Quit` report nothing at all — not the lines
///    before it — so a decoded index is one stray byte away from matching zero
///    paths with no error anywhere.
/// 2. A corrupt index surfaces as the adapter-failure note rather than as a
///    silent fallback to raw search over binary bytes.
#[test]
fn an_eri_path_index_is_searchable_and_a_corrupt_one_says_so() {
    let dir = common::scratch("eri");

    std::fs::write(
        dir.join("index.eri"),
        eri_bytes(&[
            ("notes.txt", b"C:\\Users\\dana\\needle-notes.txt"),
            ("a.rs", b"C:\\src\\needle-main.rs"),
            ("b.rs", b"C:\\src\\unrelated.rs"),
        ]),
    )
    .unwrap();

    let out = rgx()
        .args(["-F", "needle"])
        .arg(dir.join("index.eri"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("needle-notes.txt"), "got {stdout:?}");
    assert!(stdout.contains("needle-main.rs"), "got {stdout:?}");
    assert!(!stdout.contains("unrelated"), "got {stdout:?}");
    // The rendered paths are the payload; they must not be prefixed with the
    // container path the way `Outcome::Members` would build them.
    assert!(!stdout.contains("index.eri/"), "got {stdout:?}");

    // -c counts the matching paths, so a silent binary bail would read 0.
    let counted = rgx()
        .args(["-F", "-c", "needle"])
        .arg(dir.join("index.eri"))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&counted.stdout).trim(),
        "2",
        "the index must count 2 matching paths"
    );

    // A NUL inside a path is escaped rather than refused. Refusing was the
    // first implementation and it produced **no output at all**: the refusal
    // falls back to the file's own bytes, those are binary, `Quit(0)` stops
    // on the first one, and the adapter's own explanation is discarded with
    // them. The path must still print, with the NUL visible as an escape.
    let corrupt = dir.join("corrupt.eri");
    std::fs::write(&corrupt, eri_bytes(&[("a", b"C:\\src\\needle-tail.rs")])).unwrap();
    {
        let mut bytes = std::fs::read(&corrupt).unwrap();
        let last = bytes.len() - 1;
        bytes[last - 4] = 0x00; // inside the path, not the length prefix
        std::fs::write(&corrupt, &bytes).unwrap();
    }
    let bad = rgx().args(["-F", "needle"]).arg(&corrupt).output().unwrap();
    let text = String::from_utf8_lossy(&bad.stdout).to_string();
    assert!(
        text.contains("\\x00"),
        "a NUL must be escaped and visible, not silently dropped: got {text:?}"
    );
    assert!(
        text.contains("needle"),
        "the path must still print despite the corruption: got {text:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A pattern x corpus x flag matrix against ripgrep, diffing the line lists.
///
/// The single highest-signal suite in this file: every real engine bug in
/// `rgx-core` since the differential was removed came from comparing against
/// `rg` at the CLI, and nothing did that systematically. This does. It would
/// have caught `--sort path` immediately -- a line-list diff cannot hide an
/// order divergence behind a set comparison, and neither can it hide one
/// behind "both are non-deterministic" once the lists are sorted the same
/// way on both sides.
///
/// The corpus is plain text ON PURPOSE. rgx searches inside archives, Office
/// documents and mail; rg does not. That is the product difference and it
/// would show up here as a difference in WHICH files matched, which is not
/// what this test is about. The patterns are ASCII for the same reason:
/// rgx is a byte engine and its `-i` does not fold non-ASCII case, which is
/// a documented boundary rather than a defect.
///
/// Known and deliberately excluded: `--sort` (covered by its own test),
/// `--json` (the record shape is rgx's own), and `--chunk` (no rg
/// equivalent).
#[test]
fn the_cli_agrees_with_ripgrep_on_a_pattern_corpus_flag_matrix() {
    let dir = common::scratch("rg-matrix");
    std::fs::create_dir_all(dir.join("nested")).unwrap();
    // Shapes a line-oriented searcher gets wrong: a line with several
    // matches, a match at the start and at the end, a blank line, a line
    // with no terminator, CRLF, and a long line.
    std::fs::write(
        dir.join("a.txt"),
        "needle one\nneedle needle three\n\nfour needle\n",
    )
    .unwrap();
    std::fs::write(dir.join("b.txt"), "needle at start\nmiddle\nend needle").unwrap();
    std::fs::write(
        dir.join("nested").join("c.txt"),
        "only needle here\nsecond needle line\n",
    )
    .unwrap();
    std::fs::write(dir.join("cr.txt"), "crlf needle\r\nsecond needle\r\n").unwrap();
    std::fs::write(
        dir.join("long.txt"),
        format!("{}needle{}\n", "x".repeat(500), "y".repeat(500)),
    )
    .unwrap();

    let patterns: &[&str] = &[
        "needle",
        "n.edle",
        "^needle",
        "needle$",
        "needle|second",
        "n(ee)dle",
        "\\bneedle\\b",
        "[nN]eedle",
    ];
    let flagsets: &[&[&str]] = &[
        &[],
        &["-n"],
        &["-c"],
        &["-l"],
        &["-L"],
        &["-o"],
        &["-i"],
        &["-v"],
        &["-w"],
        &["-F"],
        &["--no-filename"],
        &["-A", "1"],
        &["-B", "1"],
        &["-C", "1"],
    ];

    let norm = |s: &str| -> Vec<String> {
        let mut v: Vec<String> = s
            .replace('\\', "/")
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        v.sort();
        v
    };

    let rg = Command::new("rg")
        .args(["--no-config", "--color", "never"])
        .arg(dir.as_os_str())
        .output()
        .expect("ripgrep must be installed: tests/cli.rs is a parity suite");
    assert!(rg.status.code().is_some(), "rg must be runnable");

    let mut disagreements = Vec::new();
    let mut checked = 0usize;
    for pattern in patterns {
        for flags in flagsets {
            let mut ours_args = vec!["--color", "never"];
            ours_args.extend_from_slice(flags);
            ours_args.push(pattern);
            // rg has `--no-config`; rgx's equivalent is pointing
            // `RGX_CONFIG_PATH` at nothing, so a `.rgxrc` on the test
            // machine cannot quietly add flags to one side only.
            let ours = rgx()
                .args(&ours_args)
                .arg(&dir)
                .env("RGX_CONFIG_PATH", "nonexistent-rgxrc-for-matrix")
                .output()
                .unwrap();
            let mut theirs_args = vec!["--no-config", "--color", "never"];
            theirs_args.extend_from_slice(flags);
            theirs_args.push(pattern);
            let theirs = Command::new("rg")
                .args(&theirs_args)
                .arg(&dir)
                .output()
                .unwrap();

            // Both tools exit 0 on a match and 1 on no match; a parse error
            // is 2 and would mean the flag set is not shared, which is a bug
            // in this test rather than a disagreement.
            if ours.status.code() == Some(2) || theirs.status.code() == Some(2) {
                disagreements.push(format!(
                    "[{pattern} {flags:?}] one tool refused the arguments: rgx={:?} rg={:?}",
                    ours.status.code(),
                    theirs.status.code()
                ));
                continue;
            }
            let a = norm(&String::from_utf8_lossy(&ours.stdout));
            let b = norm(&String::from_utf8_lossy(&theirs.stdout));
            if a != b {
                disagreements.push(format!("[{pattern} {flags:?}]\n  rgx={a:?}\n  rg ={b:?}"));
            } else {
                checked += 1;
            }
        }
    }

    assert!(
        disagreements.is_empty(),
        "{} of {checked} matrix cells disagree with ripgrep:\n\n{}",
        disagreements.len(),
        disagreements.join("\n\n")
    );
    assert!(
        checked >= 80,
        "only {checked} cells were compared; the matrix has degenerated"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A file the raw path skips must not label the next file's hit.
///
/// The skip returns (`--max-filesize` over the cap, the binary cut before
/// a NUL) used to end their file without disarming the streaming sink.
/// A file that arrives through the pre-read route — the adapter path ran
/// on extension alone and totally bailed, so the walk kept the bytes it
/// read and searched them from memory — has no `begin_file` of its own,
/// and its hit streamed under the SKIPPED file's path. The archive
/// fixtures' `-i` battery caught it as a one-line diff: `zstd_noise.bin`'s
/// only hit printed as `zstd_longrange.plain`, and the file that really
/// matched went unreported as itself.
///
/// Each dir pins one natural name order (the walker visits a `-j1` dir in
/// one), and every assertion is a label/content pairing, so the test
/// cannot fail on a correct build whatever order the walker visits.
#[test]
fn a_skipped_file_does_not_label_the_next_files_hit() {
    for (poison_name, hit_name) in [("a_skip.plain", "b_hit.bin"), ("b_skip.plain", "a_hit.bin")] {
        let dir = common::scratch(&format!("stream-label-{hit_name}"));
        // The poison: `.plain` is claimed by no adapter, so it takes the
        // walked raw route (`begin_file` + `raw_search`), and the NUL in
        // the sniff window cuts it as binary — the skip that used to
        // leave the stream armed with this file's path. It never matches.
        std::fs::write(dir.join(poison_name), b"xx\x00yy without term").unwrap();
        // The victim: `.bin` IS claimed (extension alone), the adapter
        // bails on plain bytes, and the hit is searched from the memory
        // the probe left behind — the pre-read route, which never called
        // `begin_file`.
        std::fs::write(dir.join(hit_name), b"UNIQUE needle line\n").unwrap();

        let (code, out) = run(&dir, &["-j1", "needle"]);
        assert_eq!(code, 0, "expected one match, got exit {code}: {out}");
        let lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 1, "expected exactly one line: {out}");
        assert!(
            lines[0].contains(&format!("{hit_name}:")) && lines[0].contains("UNIQUE needle line"),
            "the hit must carry its own file's label, got: {}",
            lines[0]
        );
        assert!(
            !lines[0].contains(poison_name),
            "the hit was labelled with the skipped file's path: {}",
            lines[0]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A scratch directory of one file, cleaned up after the test.
fn one_file_dir(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = common::scratch("cli-fix");
    std::fs::write(dir.join(name), bytes).unwrap();
    dir
}

/// A `-U` match spans lines, and `-o` used to slice each printed line
/// with spans that belonged to the whole match: the offsets ran past
/// the one line and the printer panicked. The spans are rebased onto
/// each line, and one that crosses the newline is cut at it.
#[test]
fn multiline_only_matching_prints_each_line_part() {
    let dir = one_file_dir("up.txt", b"one\nTWO\nthree\n");
    let out = rgx()
        .args(["-U", "-o", "one\\nTWO"])
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("one"), "{text}");
    assert!(text.contains("TWO"), "{text}");
    assert!(!text.contains("three"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The stdin search used to build its sink without the submatch
/// regex, so `-o` printed nothing at all — an empty answer with
/// exit 0, which reads as "not here" rather than "not searched".
#[test]
fn stdin_only_matching_prints_the_matches() {
    let (code, stdout) = run_stdin(&["-o", "foo"], b"foo bar\nfoo baz\n");
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(stdout.matches("foo").count(), 2, "{stdout}");
    assert!(!stdout.contains("bar"), "{stdout}");
    assert!(!stdout.contains("baz"), "{stdout}");
}

/// A type wiped by `--type-clear` is refused under its own name; the
/// alias used to resolve to the wiped type and silently match nothing,
/// which is the answer "there is no Rust here" given to a question
/// that was really "there is no type called rust".
#[test]
fn a_cleared_type_is_refused_by_its_alias_too() {
    let dir = one_file_dir("a.js", b"let needle = 1;\n");
    let (code, _out, err) = run_err(&dir, &["--type-clear", "javascript", "-t", "js", "needle"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("unrecognized file type"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--chunk` used to read the whole file with no size cap: the check
/// that moved out of the walker lives in the line path, and the chunk
/// branch never went through it.
#[test]
fn chunk_mode_respects_max_filesize() {
    let mut big = vec![b'.'; 200_000];
    big[..6].copy_from_slice(b"needle");
    let dir = one_file_dir("bigfile", &big);
    let (code, out) = run(&dir, &["--chunk=512", "-M", "100K", "needle"]);
    assert_eq!(code, 1, "the over-cap file is skipped, got: {out}");
    assert!(out.is_empty(), "{out}");
    // Under the cap the same file is chunk-searched and found.
    let (code, out) = run(&dir, &["--chunk=512", "-M", "1M", "needle"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("needle"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}
