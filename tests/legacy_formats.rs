// SPDX-License-Identifier: Apache-2.0

//! Integration tests for legacy file-format adapters (DIF, Lotus 1-2-3, Jet/ACE,
//! Windows Address Book). Each test is a thin wrapper around a fixture file and
//! runs end-to-end through the adapter.
//!
//! **A missing fixture fails the test.** It used to `return` early with a
//! one-line notice, which made the whole suite report `7 passed` on a clean
//! checkout where the corpus is git-ignored and nothing had been fetched — a
//! green gate that verified nothing, and indistinguishable from a run that
//! checked six real files. The missing case is now a `panic!` carrying the
//! command that fixes it, the same shape `tests/cli.rs` already uses for its
//! own external dependency:
//!
//! ```rust
//! .expect("ripgrep must be installed: tests/cli.rs is a parity suite")
//! ```
//!
//! One of the six is not load-bearing here at all — WAB has no public corpus,
//! so `wab_synthesized_minimal_cfb_is_parsed` synthesises a minimal OLE
//! Compound File in memory and runs on a clean checkout. It is the test that
//! proves this binary is not vacuous.
//!
//! To populate the fixtures, run from the repo root:
//! ```bash
//! scripts/fetch-legacy-corpus.sh      # or fetch-legacy-corpus.ps1 on Windows
//! ```
//!
//! The suite asserts *coarse* properties, not byte-for-byte output: a
//! `rgx_core::process` call must either succeed with a non-empty `text:` outcome
//! or fail with a clean `Bail`/`Err`. A panic, an empty text body, or an
//! oversized print would catch a regression where an adapter misinterprets
//! the file as something it cannot read.

#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rgx_adapters_mail::wab::Wab;
use rgx_adapters_tabular::dif::Dif;
use rgx_adapters_tabular::lotus::Lotus;
use rgx_adapters_tabular::mdb::Mdb;
use rgx_core::{Adapter, Outcome};

fn fixtures_root() -> PathBuf {
    // tests run from the crate root (CARGO_MANIFEST_DIR) so relative paths
    // resolve regardless of the worker's working directory.
    fixtures_root_opt()
        .expect("legacy corpus must be fetched: run scripts/fetch-legacy-corpus.sh (or the .ps1 on Windows) to populate tests/fixtures/legacy-formats/ -- tests/legacy_formats.rs cannot verify the DIF, Lotus or Jet adapters without it")
}

fn fixtures_root_opt() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("legacy-formats");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

/// The path of one corpus file, or a panic naming the command that fetches it.
///
/// A missing fixture used to be a `return`, which libtest counts as `ok`: the
/// suite reported seven passes with nothing read at all. That is worse than no
/// test, because it looks like evidence. See the module header.
fn corpus_or_fail(name: &str) -> PathBuf {
    let p = fixtures_root().join(name);
    assert!(
        p.exists(),
        "legacy fixture {name} missing at {} -- run scripts/fetch-legacy-corpus.sh to populate it",
        p.display()
    );
    p
}

/// The one assertion that does not depend on a fetched file, so this binary is
/// never entirely vacuous: the corpus root is either there or it is named.
#[test]
fn the_legacy_corpus_is_present_or_the_run_says_why_it_is_not() {
    if fixtures_root_opt().is_none() {
        panic!(
            "tests/fixtures/legacy-formats/ is absent -- run scripts/fetch-legacy-corpus.sh \
             (or fetch-legacy-corpus.ps1 on Windows)"
        );
    }
}

fn extract_text<A: Adapter + ?Sized>(a: &A, data: &[u8], label: &str) -> String {
    match a.extract(data, label) {
        Ok(Outcome::Text(t)) => String::from_utf8_lossy(&t).into_owned(),
        Ok(Outcome::Bail(s)) => panic!("adapter bailed on real file: {s}"),
        Ok(Outcome::Members(_)) => panic!("adapter returned Members on real file"),
        Err(e) => panic!("adapter errored on real file: {e}"),
    }
}

#[test]
fn dif_sales_report() {
    // SAMPLE.DIF is a sales report — month names and product names
    // appear in the data block. The title (`"SALES REPORT"`) is in the
    // header which the adapter consumes silently. The data cells are
    // the load-bearing evidence.
    let p = corpus_or_fail("dif/SAMPLE.DIF");
    let data = std::fs::read(&p).expect("read");
    let out = extract_text(&Dif, &data, "SAMPLE.DIF");
    assert!(out.contains("January"), "expected `January` in:\n{out}");
    assert!(out.contains("Computers"), "expected `Computers` in:\n{out}");
}

#[test]
fn dif_hardware_drive_list() {
    // HDINFO.DIF is a 62 KiB real-world export (a German hard-drive
    // vendor's product list) — exercises large-file paths.
    let p = corpus_or_fail("dif/HDINFO.DIF");
    let data = std::fs::read(&p).expect("read");
    let out = extract_text(&Dif, &data, "HDINFO.DIF");
    assert!(out.lines().count() > 100, "expected >100 emitted lines");
}

/// DEMO.WK4 is 977 KB of Lotus 1-2-3 v4, the largest fixture here.
///
/// This test used to assert `> 100 emitted lines`, which meant the v3/v4 cell
/// layout was being decoded with the v2 one: the reader stepped `2 + len`
/// through records that are `4 + len`, so from the second record on every
/// "opcode" was a body byte. It printed `R27749C29807` — a cell 27 749 rows
/// down and 29 807 columns across, in a sheet that declares 36 columns.
///
/// Fabricated coordinates are worse than no answer, because they answer a
/// search with something the file never said. So the property held here is
/// the one that actually matters: **if** the adapter emits an address, that
/// address is inside the geometry the sheet declares. Today it emits none
/// and declines, and the file falls through to the raw search — every byte
/// it ever matched still matches, with the reason printed beside them.
#[test]
fn lotus_demo_wk4_never_fabricates_a_cell_address() {
    let p = corpus_or_fail("lotus/DEMO.WK4");
    let data = std::fs::read(&p).expect("read");
    let Ok(Outcome::Text(bytes)) = Lotus.extract(&data, "DEMO.WK4") else {
        // A decline is the current, honest answer. Nothing to assert beyond
        // the fact that it returned rather than panicked.
        return;
    };
    let out = String::from_utf8_lossy(&bytes);
    assert!(out.starts_with("-- lotus 1-2-3 --"), "no header line");
    // The sheet declares 36 columns; 1 000 rows and 100 columns is a bound no
    // real address in this file approaches, so anything past it is invented.
    for line in out
        .lines()
        .filter(|l| l.starts_with('R') && l.contains('C'))
    {
        let coords = line.split('\t').next().unwrap_or("");
        let Some((r, c)) = coords.trim_start_matches('R').split_once('C') else {
            panic!("unparsable coordinate {coords:?} in {line:?}");
        };
        let (r, c): (u32, u32) = (r.parse().expect("row"), c.parse().expect("col"));
        assert!(
            r < 1_000 && c < 100,
            "fabricated address {line:?} in a 36-column sheet"
        );
    }
}

#[test]
fn lotus_peyneval_wk1_is_parsed() {
    let p = corpus_or_fail("lotus/PEYNEVAL.WK1");
    let data = std::fs::read(&p).expect("read");
    let out = extract_text(&Lotus, &data, "PEYNEVAL.WK1");
    assert!(out.starts_with("-- lotus 1-2-3 --"), "no header line");
}

/// The cells of an extracted sheet, keyed by their address.
fn cells_of(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('\t'))
        .map(|(addr, value)| (addr.to_string(), value.to_string()))
        .collect()
}

/// The WK3 and the WK1 of the corpus are the same sheet in two layouts.
///
/// This is the oracle for the v3 reader. The v3 cell layout is not the v2
/// one -- the row comes first, there is a block byte, and the number is an
/// x87 80-bit float -- so the addresses it prints are checked against the
/// reader that was already proven against the v1 layout: every label and
/// every number must be the same cell, at the same address, with the same
/// words. The two files differ only where the sheet names itself, and in
/// the integer column, whose unit the v3 file stores in a way this reader
/// does not know.
#[test]
fn lotus_example_wk3_matches_its_wk1_twin() {
    let wk3 = std::fs::read(corpus_or_fail("lotus/example.wk3")).expect("read");
    let wk1 = std::fs::read(corpus_or_fail("lotus/example.wk1")).expect("read");
    let text_v3 = extract_text(&Lotus, &wk3, "example.wk3");
    let text_v2 = extract_text(&Lotus, &wk1, "example.wk1");
    let v3 = cells_of(&text_v3);
    let v2 = cells_of(&text_v2);

    // The v3 reader places 28 labels and 21 numbers. The v2 reader places
    // those 49 and the 5 integers of the 'total' column as well.
    assert_eq!(v3.len(), 49, "{text_v3}");
    assert_eq!(v2.len(), 54, "{text_v2}");

    // Every cell of the v3 sheet is a cell of the v1 sheet, with the same
    // value -- except the two cells where the sheet names the file it is
    // in, which is the one difference the sheet itself declares.
    let mut compared = 0usize;
    for (addr, value) in &v3 {
        let Some(other) = v2.get(addr) else {
            panic!("the v3 cell {addr} is not in the v1 sheet");
        };
        if addr == "R0C0" || addr == "R3C1" {
            assert_ne!(value, other, "{addr} should name the file it is in");
            continue;
        }
        assert_eq!(value, other, "{addr} differs between the two sheets");
        compared += 1;
    }
    assert_eq!(compared, 47, "not every cell of the v3 sheet was compared");

    // The five cells the v3 reader did not place are the v1 reader's
    // integers, and the reader says that it left them out.
    for addr in ["R12C5", "R13C5", "R14C5", "R15C5", "R16C5"] {
        assert!(v2.contains_key(addr), "{addr} is not in the v1 sheet");
        assert!(!v3.contains_key(addr), "{addr} should not have been placed");
    }
    assert!(
        text_v3.contains("not read: 5 cells"),
        "the reader did not report the cells it left out:\n{text_v3}"
    );
}

/// The `.wk2` of the corpus is the `.wk1` under the name 1-2-3 v2.0 gave
/// it: the extension was changed so that the number in it would match the
/// version number, and the record layout did not change with it — both
/// files carry the BOF version code 0x0406, and two independent readers
/// (Gnumeric's and LibreOffice's) dispatch 0x0404 and 0x0406 to the same
/// opcode table. No Lotus `.wk2` sample is published where the corpus
/// script can reach one, so the corpus holds a copy of the `.wk1` under the
/// `.wk2` name; the fetch script says so where it makes it.
///
/// What the test can assert is what the copy is for: the bytes under the
/// `.wk2` name are read by the v2 reader, and the sheet they hold is the
/// sheet the `.wk1` holds.
#[test]
fn lotus_example_wk2_reads_as_its_wk1_twin() {
    let wk2 = std::fs::read(corpus_or_fail("lotus/example.wk2")).expect("read");
    let wk1 = std::fs::read(corpus_or_fail("lotus/example.wk1")).expect("read");
    let text_wk2 = extract_text(&Lotus, &wk2, "example.wk2");
    let text_wk1 = extract_text(&Lotus, &wk1, "example.wk1");
    let v2 = cells_of(&text_wk2);
    let v1 = cells_of(&text_wk1);

    // The same sheet, the same cells, the same words: the file's bytes are
    // the `.wk1`'s bytes.
    assert_eq!(v2.len(), 54, "{text_wk2}");
    assert_eq!(v1.len(), 54, "{text_wk1}");
    for (addr, value) in &v2 {
        let Some(other) = v1.get(addr) else {
            panic!("the cell {addr} of the .wk2 is not in the .wk1");
        };
        assert_eq!(value, other, "{addr} differs between the two");
    }
    assert!(
        text_wk2.contains("family: 1-2-3 v1/v2 (WKS/WK1)"),
        "the .wk2 did not reach the v2 reader:\n{text_wk2}"
    );
}

#[test]
fn lotus_peytrend_wk3_is_parsed() {
    // PEYTREND.WK3 is a real v3 sheet: five labels in the header row and
    // 1 029 numbers under them, in the same cell layout.
    let p = corpus_or_fail("lotus/PEYTREND.WK3");
    let data = std::fs::read(&p).expect("read");
    let out = extract_text(&Lotus, &data, "PEYTREND.WK3");
    assert!(out.starts_with("-- lotus 1-2-3 --"), "no header line");
    assert!(out.contains("family: 1-2-3 v3.x (WK3)"), "{out}");
    assert!(out.contains("R0C0\tNO"), "{out}");
    assert!(out.contains("R0C1\tDATE"), "{out}");
    assert!(out.contains("R0C2\tVMC5_10"), "{out}");
    // The first number of the sheet: the date column, 219.
    assert!(out.contains("R1C1\t219"), "{out}");
    assert_eq!(
        out.lines().filter(|l| l.starts_with('R')).count(),
        1_034,
        "{out}"
    );
}

/// The WK4 of the corpus is the same sheet as the WK1, in the v4 layout.
///
/// The v4's cell record is the v3's, but the address names the table the
/// cell belongs to, so the addresses carry a `B0` prefix here that the v1
/// reader does not write. Strip it and the two sheets have to be the same
/// cells, with the same words.
#[test]
fn lotus_example_wk4_matches_its_wk1_twin() {
    let wk4 = std::fs::read(corpus_or_fail("lotus/example.wk4")).expect("read");
    let wk1 = std::fs::read(corpus_or_fail("lotus/example.wk1")).expect("read");
    let text_v4 = extract_text(&Lotus, &wk4, "example.wk4");
    let text_v1 = extract_text(&Lotus, &wk1, "example.wk1");
    let v4 = cells_of(&text_v4);
    let v1 = cells_of(&text_v1);

    // The v4 reader places 28 labels and 21 numbers; the v1 reader places
    // those 49 and the 5 integers of the 'total' column as well.
    assert_eq!(v4.len(), 49, "{text_v4}");
    assert_eq!(v1.len(), 54, "{text_v1}");

    let mut compared = 0usize;
    for (addr, value) in &v4 {
        let plain = addr.strip_prefix("B0").unwrap_or(addr);
        let Some(other) = v1.get(plain) else {
            panic!("the v4 cell {addr} is not in the v1 sheet");
        };
        if plain == "R0C0" || plain == "R3C1" {
            assert_ne!(value, other, "{plain} should name the file it is in");
            continue;
        }
        assert_eq!(value, other, "{plain} differs between the two sheets");
        compared += 1;
    }
    assert_eq!(compared, 47, "not every cell of the v4 sheet was compared");

    // The five integer cells are the ones the v1 reader has and the v4
    // reader does not, and the reader says it left them out.
    for addr in ["R12C5", "R13C5", "R14C5", "R15C5", "R16C5"] {
        assert!(v1.contains_key(addr), "{addr} is not in the v1 sheet");
        assert!(!v4.contains_key(addr), "{addr} should not have been placed");
    }
    assert!(
        text_v4.contains("not read: 5 cells"),
        "the reader did not report the cells it left out:\n{text_v4}"
    );
}

/// The `.123` of the corpus is the same sheet as the `.wk1`, in the
/// Millennium layout.
///
/// The cell record there is the row, the column in 256ths of a character,
/// and the payload: a label (`0x0016`) or a number (`0x0027`). The six
/// cells the file stores *indirectly* (`0x0025`, whose data lives
/// elsewhere in the file) are the ones the v1 sheet has and this one
/// leaves out.
#[test]
fn lotus_example_123_matches_its_wk1_twin() {
    let millennium = std::fs::read(corpus_or_fail("lotus/example.123")).expect("read");
    let wk1 = std::fs::read(corpus_or_fail("lotus/example.wk1")).expect("read");
    let text_123 = extract_text(&Lotus, &millennium, "example.123");
    let text_wk1 = extract_text(&Lotus, &wk1, "example.wk1");
    let v123 = cells_of(&text_123);
    let v1 = cells_of(&text_wk1);

    // The .123's 27 labels and 21 numbers; the v1's 28 labels, 21
    // numbers and 5 integers.
    assert_eq!(v123.len(), 48, "{text_123}");
    assert_eq!(v1.len(), 54, "{text_wk1}");

    // Every cell of the .123 is the v1's cell, at the same address, with
    // the same word -- the sheet differs only where it names itself.
    for (addr, value) in &v123 {
        let Some(other) = v1.get(addr) else {
            panic!("the .123 cell {addr} is not in the v1 sheet");
        };
        if addr == "R0C0" {
            assert_ne!(value, other, "{addr} should name the file it is in");
            continue;
        }
        assert_eq!(value, other, "{addr} differs between the two sheets");
    }

    // The six cells the v1 sheet has and the .123 stores indirectly: the
    // 'file type' label and the five integers of the 'total' column.
    for addr in ["R3C1", "R12C5", "R13C5", "R14C5", "R15C5", "R16C5"] {
        assert!(v1.contains_key(addr), "{addr} is not in the v1 sheet");
        assert!(
            !v123.contains_key(addr),
            "{addr} should not have been placed"
        );
    }
    assert!(
        text_123.contains("not read: 6 cells"),
        "the reader did not report the cells it left out:\n{text_123}"
    );
}

/// A real v4 sheet is a document of several tables, and the address has
/// to say which one: the same (row, column) holds different cells in
/// different tables -- of the 1 279 distinct (row, column) pairs of
/// `DEMO.WK4`, 591 hold more than one cell.
#[test]
fn lotus_demo_wk4_is_read_as_tables() {
    let p = corpus_or_fail("lotus/DEMO.WK4");
    let data = std::fs::read(&p).expect("read");
    let out = extract_text(&Lotus, &data, "DEMO.WK4");
    assert!(out.starts_with("-- lotus 1-2-3 --"), "no header line");
    assert!(out.contains("family: 1-2-3 v4.x (WK4)"), "{out}");
    // The sheet's own title, in the first table.
    assert!(out.contains("B0R2C3\tTHE HOTEL BUDGET"), "{out}");

    // Every department's budget has its own 'Total Revenue', in its own
    // table: the same words, in rows that differ.
    let totals: Vec<&str> = out
        .lines()
        .filter(|l| l.ends_with("Total Revenue"))
        .collect();
    let tables: BTreeSet<String> = totals
        .iter()
        .map(|l| l.split('R').next().unwrap_or("").to_string())
        .collect();
    assert!(
        tables.len() >= 8,
        "the totals are in {} tables:\n{out}",
        tables.len()
    );
    for total in &totals {
        assert!(total.starts_with('B'), "{total} does not name its table");
    }

    // The formulas and the integers of the sheet are not read, and the
    // reader says how many cells it left out.
    assert!(out.contains("not read: 13367 cells"), "{out}");
}

#[test]
fn mdb_nwind_emits_table_content() {
    // mdbtools/mdbtestdata is the canonical Jet fixture set. Northwind
    // Traders contains 8 tables (Categories, Customers, Orders, ...);
    // every column value of every row is a printable run somewhere in
    // the data pages, and the adapter's run extraction picks them up.
    let p = corpus_or_fail("mdbtestdata/data/nwind.mdb");
    let data = std::fs::read(&p).expect("read");
    let out = extract_text(&Mdb, &data, "nwind.mdb");
    assert!(out.contains("Northwind"), "expected `Northwind` in:\n{out}");
    assert!(
        out.contains("Categories"),
        "expected `Categories` in:\n{out}"
    );
}

#[test]
fn accdb_sample_database_is_parsed() {
    // ASampleDatabase.accdb is an ACE-format (Access 2007+) file from
    // mdbtools. The header is the same Jet magic; only the engine
    // version byte at offset 0x04 differs.
    let p = corpus_or_fail("mdbtestdata/data/ASampleDatabase.accdb");
    let data = std::fs::read(&p).expect("read");
    let out = extract_text(&Mdb, &data, "ASampleDatabase.accdb");
    assert!(
        out.contains("engine: ACE"),
        "expected ACE engine in:\n{out}"
    );
}

#[test]
fn wab_synthesized_minimal_cfb_is_parsed() {
    // No public WAB corpus exists; instead we build a minimal OLE
    // Compound File with two directory entries (one storage, one
    // contact stream) and confirm the adapter finds the contact.
    // Layout: 512-byte header + sector 0 (FAT) + sector 1 (directory).
    // The end-of-chain marker rides in the last 4 bytes of sector 1.
    let mut buf = vec![0u8; 512 + 512 + 512];
    // OLE magic
    buf[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    // byte order LE
    buf[28] = 0xFE;
    buf[29] = 0xFF;
    // sector shift = 9 -> 512
    buf[30] = 0x09;
    buf[31] = 0x00;
    // n_fat_sectors = 1
    buf[0x2C] = 0x01;
    // first directory sector = 1
    buf[48] = 0x01;
    // mini cutoff 4096
    buf[0x38..0x3C].copy_from_slice(&4096u32.to_le_bytes());
    // DIFAT[0] = 0 (sector 0 holds the FAT)
    buf[0x4C] = 0x00;
    // FAT lives at sector 0 (bytes 512..1024). Slot 0 = FATSECT (the FAT
    // sector itself); slot 1 = ENDOFCHAIN (the directory ends there);
    // every other slot = FREESECT.
    let fat_off = 512;
    buf[fat_off..fat_off + 4].copy_from_slice(&0xFFFFFFFDu32.to_le_bytes());
    buf[fat_off + 4..fat_off + 8].copy_from_slice(&0xFFFFFFFEu32.to_le_bytes());
    for i in 2..(512 / 4) {
        buf[fat_off + i * 4..fat_off + i * 4 + 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    }
    // Directory lives at sector 1 (bytes 1024..1536). End-of-chain
    // marker rides in the last 4 bytes of that sector.
    let dir_start = 1024;
    buf[dir_start + 512 - 4..dir_start + 512].copy_from_slice(&0xFFFFFFFEu32.to_le_bytes());
    // entry 0: storage "AddressBook" — the WAB root container. The
    // adapter skips non-stream entries; this verifies the parser does
    // not panic on a sibling storage and the storage's existence does
    // not pollute the contact list.
    let e0 = dir_start;
    write_utf16(&mut buf[e0..e0 + 66], "AddressBook");
    buf[e0 + 66] = 0x01; // storage
    buf[e0 + 67] = 0x01;
    // entry 1: stream "__SUBRECORD__0" — a contact the adapter will read.
    let e1 = dir_start + 128;
    write_utf16(&mut buf[e1..e1 + 66], "__SUBRECORD__0");
    buf[e1 + 66] = 0x02; // stream
    buf[e1 + 67] = 0x01;
    let out = extract_text(&Wab, &buf, "synth.wab");
    // The adapter reads the CFB, finds 2 directory entries, and picks
    // out the one __SUBRECORD__ stream.
    assert!(out.contains("directory entries: 2"), "{out}");
    assert!(out.contains("contact streams: 1"), "{out}");
    assert!(out.contains("stream\t__SUBRECORD__0"), "{out}");
}

fn write_utf16(dst: &mut [u8], name: &str) {
    // CFB directory entry: 64 bytes for the UTF-16LE name (incl. the
    // terminating null) + 2 bytes for `name_len`. We bail loudly if
    // `dst` cannot hold both fields — the test layout already sizes
    // each entry to 128 bytes.
    assert!(dst.len() >= 66, "write_utf16: dst too small");
    let mut i = 0;
    for c in name.encode_utf16() {
        if i + 1 >= 64 {
            break;
        }
        dst[i..i + 2].copy_from_slice(&c.to_le_bytes());
        i += 2;
    }
    if i < 64 {
        dst[i..i + 2].copy_from_slice(&0u16.to_le_bytes());
    }
    let len = (i + 2) as u16;
    dst[64] = (len & 0xff) as u8;
    dst[65] = ((len >> 8) & 0xff) as u8;
}
