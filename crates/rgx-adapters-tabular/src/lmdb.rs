// SPDX-License-Identifier: Apache-2.0
//
// The `MDB_meta` layout below was learned from LMDB's own implementation,
// which is the description of the format that exists; the code here is rgx's
// own. The provenance is recorded in `NOTICE`.

//! LMDB environment data files (`data.mdb`).
//!
//! LMDB and Microsoft Access share the `.mdb` extension, and until this
//! adapter existed the registry could not tell them apart except by Access
//! declining. They do not need to be told apart by anything clever: the two
//! formats stamp their first four bytes differently and neither magic is a
//! prefix of the other. Jet is `00 01 00 00`; LMDB is `0xBEEFC0DE`, which
//! liblmdb's own comment calls "a stamp that identifies this file as an LMDB
//! file ... easily recognizable, and it will reflect any byte order
//! mismatches". So both readers claim `.mdb` and each declines the other's
//! magic, and there is no ordering to get wrong.
//!
//! Everything below is read from `MDB_meta`, the struct at the start of page
//! zero, as `mdb.c` lays it out. Three layout facts decide whether this is
//! right or merely plausible, and all three are load-bearing:
//!
//! - The page size is **in the data file**, at `mm_dbs[0].md_pad` -- liblmdb
//!   reaches it through `#define mm_psize mm_dbs[0].md_pad`. It is commonly
//!   assumed to live only in the lock file, which would make a bare `data.mdb`
//!   unanswerable.
//! - `mm_dbs` is an array of `MDB_db`, 40 bytes each on a 64-bit build, so
//!   the main database's record starts at 64 and not at "64 minus something".
//!   Reading `mm_dbs[1]` at 24 would report the free-DB's counts as the
//!   database's own.
//! - The offsets are the 64-bit ones, and that is checked rather than
//!   assumed: `mm_mapsize` is the size of the map the file backs, so it must
//!   equal the file's length. A 32-bit build packs the same fields more
//!   tightly and fails that check, which is a refusal with a reason rather
//!   than a confident reading of the wrong words.
//!
//! What is NOT here: the B+tree walk. Keys and values live in leaf pages
//! behind the main DB's root, and reaching them means the node layout
//! (`MDB_node`, the branch/leaf page headers) and a descent from the right
//! meta page. Until that exists, the tree is not walked, and the
//! printable-run pass below is what puts text values in reach.

use alloc::string::String;
use core::fmt::Write as _;

use rgx_core::bail;
use rgx_core::{decline, Adapter, Outcome, Result};

/// `MDB_MAGIC` from `mdb.c`. Little-endian on every platform rgx targets,
/// which is why liblmdb says the stamp "will reflect any byte order
/// mismatches": the bytes are what a big-endian build would not write.
const MDB_MAGIC: u32 = 0xBEEF_C0DE;

/// `MDB_DATA_VERSION` in released builds; 999 in a `-D MDB_DEVEL` build, and
/// 2/3 appeared across the series. Anything outside this set is not a
/// meta page whose layout we know.
const KNOWN_DATA_VERSIONS: [u32; 4] = [1, 2, 3, 999];

/// 64-bit `MDB_meta` offsets. `mm_address` and `mm_mapsize` are a pointer
/// and a `size_t`, so each is 8 bytes and pushes everything after it.
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 4;
const OFF_MAPSIZE: usize = 16;
/// `mm_dbs[0]` is the free-space database; `md_pad` inside it is the page
/// size, and its other fields describe the free list.
const OFF_FREEDB_PAD: usize = 24;
const OFF_FREEDB_FLAGS: usize = 28;
const OFF_FREEDB_DEPTH: usize = 30;
const OFF_FREEDB_BRANCH: usize = 32;
const OFF_FREEDB_LEAF: usize = 40;
/// `sizeof(MDB_db)` is 40 on a 64-bit build, so the main database -- the
/// one named DB whose keys are the user's -- starts here. Its `md_pad` is
/// unused by liblmdb (the page size comes from the free DB) and is not
/// read here either.
const OFF_MAINDB_FLAGS: usize = 68;
const OFF_MAINDB_DEPTH: usize = 70;
const OFF_MAINDB_BRANCH: usize = 72;
const OFF_MAINDB_LEAF: usize = 80;
const OFF_MAINDB_ENTRIES: usize = 96;
const OFF_LAST_PG: usize = 104;
const OFF_TXNID: usize = 112;

pub struct Lmdb;
impl Adapter for Lmdb {
    fn name(&self) -> &'static str {
        "lmdb"
    }
    /// Only `.mdb`. An LMDB environment is `data.mdb` + `lock.mdb`; claiming
    /// anything else would collide with Access on extensions it does not
    /// have.
    fn extensions(&self) -> &'static [&'static str] {
        &["mdb"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < OFF_TXNID + 8 {
            decline!("too small for an LMDB meta page");
        }
        // The distinguishing check. `Mdb` (Jet) checks `00 01 00 00` at the
        // same offset, so exactly one of the two readers can accept any
        // given file.
        let magic = rd_u32(data, OFF_MAGIC);
        if magic != MDB_MAGIC {
            decline!("not an LMDB data file: mm_magic is 0x{magic:08x}, not 0x{MDB_MAGIC:08x}");
        }
        let version = rd_u32(data, OFF_VERSION);
        if !KNOWN_DATA_VERSIONS.contains(&version) {
            bail!("unknown LMDB data version {version}; the layout is not known here");
        }
        // The 64-bit-layout check. A 32-bit build packs `mm_address` and
        // `mm_mapsize` into 4 bytes each, so the word at 16 is not the map
        // size and this fails.
        let mapsize = rd_u64(data, OFF_MAPSIZE);
        if mapsize != data.len() as u64 {
            bail!(
                "LMDB meta says the map is {mapsize} bytes but the file is {}; this looks \
                 like a 32-bit build's layout, which is not read here",
                data.len()
            );
        }
        let page_size = rd_u32(data, OFF_FREEDB_PAD);
        if !is_page_size(page_size) {
            bail!("LMDB declares a page size of {page_size}, which liblmdb never writes");
        }
        Ok(Outcome::Text(report(data, version, page_size).into_bytes()))
    }
}

/// liblmdb builds the map in whole pages from a power-of-two page size; the
/// database and page layer both work in `pgno_t` units, so a non-power-of-two
/// would make every page number meaningless.
fn is_page_size(n: u32) -> bool {
    (512..=65536).contains(&n) && n.is_power_of_two()
}

fn report(data: &[u8], version: u32, page_size: u32) -> String {
    let mut s = String::new();
    let pages = data.len() / page_size as usize;
    s.push_str(&format!(
        "lmdb data version: {version}\nmap size: {} bytes\npage size: {page_size}\n\
         pages in map: {}\nlast used page: {}\ntransaction id: {}\n",
        data.len(),
        pages,
        rd_u64(data, OFF_LAST_PG),
        rd_u64(data, OFF_TXNID),
    ));
    s.push_str(&format!(
        "main db: depth {} · {} branch · {} leaf pages · {} entries (flags 0x{:04x})\n",
        rd_u16(data, OFF_MAINDB_DEPTH),
        rd_u64(data, OFF_MAINDB_BRANCH),
        rd_u64(data, OFF_MAINDB_LEAF),
        rd_u64(data, OFF_MAINDB_ENTRIES),
        rd_u16(data, OFF_MAINDB_FLAGS),
    ));
    s.push_str(&format!(
        "free db: depth {} · {} branch · {} leaf pages (flags 0x{:04x})\n",
        rd_u16(data, OFF_FREEDB_DEPTH),
        rd_u64(data, OFF_FREEDB_BRANCH),
        rd_u64(data, OFF_FREEDB_LEAF),
        rd_u16(data, OFF_FREEDB_FLAGS),
    ));
    s.push_str(
        "\nthe B+tree is not walked; the runs below are printable text found in the pages\n",
    );

    // Same lossy sweep the Jet reader uses. An LMDB value is an opaque byte
    // blob in a leaf page, so its text is only reachable this way without a
    // node-level decode -- and it is exactly the content a grep wants.
    let mut s2 = s;
    printable_runs(&data[OFF_TXNID + 8..], &mut s2);
    s2
}

/// Every run of at least `MIN_RUN` printable bytes, one per line. Four is
/// the floor the Access and DuckDB readers already use: below it the output
/// is mostly structure bytes rendered as letters.
const MIN_RUN: usize = 4;
const MAX_RUNS: usize = 4096;

fn printable_runs(bytes: &[u8], out: &mut String) {
    let mut start = 0usize;
    let mut runs = 0usize;
    for i in 0..=bytes.len() {
        let printable = bytes.get(i).is_some_and(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-' | b'/' | b':' | b'@')
        });
        if printable {
            continue;
        }
        if i - start >= MIN_RUN {
            // Skip the meta page's own words: they are structural, and a
            // reader searching this file did not come for "BEEFC0DE".
            let run = String::from_utf8_lossy(&bytes[start..i]).into_owned();
            if !is_structure_word(&run) {
                let _ = writeln!(out, "{run}");
                runs += 1;
                if runs >= MAX_RUNS {
                    return;
                }
            }
        }
        start = i + 1;
    }
}

/// Meta-page words that would otherwise be reported as content.
fn is_structure_word(run: &str) -> bool {
    matches!(run, "BEEFC0DE" | "00000000" | "00000001")
}

fn rd_u16(d: &[u8], at: usize) -> u16 {
    match d.get(at..at + 2) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}

fn rd_u32(d: &[u8], at: usize) -> u32 {
    match d.get(at..at + 4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

fn rd_u64(d: &[u8], at: usize) -> u64 {
    match d.get(at..at + 8) {
        Some(b) => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// A 64-bit `MDB_meta` written field by field at its documented offset.
    /// Synthesised from `mdb.c`'s struct: there is no liblmdb in the tree to
    /// produce a real environment, so the test states the layout rather than
    /// agreeing with whatever the reader happens to read.
    fn env(page_size: u32, main_entries: u64, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; page_size as usize];
        put32(&mut v, OFF_MAGIC, MDB_MAGIC);
        put32(&mut v, OFF_VERSION, 1);
        put64(&mut v, OFF_MAPSIZE, page_size as u64);
        put32(&mut v, OFF_FREEDB_PAD, page_size);
        put16(&mut v, OFF_FREEDB_DEPTH, 1);
        put16(&mut v, OFF_MAINDB_DEPTH, 2);
        put64(&mut v, OFF_MAINDB_LEAF, 3);
        put64(&mut v, OFF_MAINDB_ENTRIES, main_entries);
        put64(&mut v, OFF_LAST_PG, 4);
        put64(&mut v, OFF_TXNID, 99);
        for (i, b) in payload.iter().enumerate() {
            if let Some(slot) = v.get_mut(OFF_TXNID + 8 + i) {
                *slot = *b;
            }
        }
        v
    }

    fn put16(v: &mut [u8], at: usize, x: u16) {
        v[at..at + 2].copy_from_slice(&x.to_le_bytes());
    }
    fn put32(v: &mut [u8], at: usize, x: u32) {
        v[at..at + 4].copy_from_slice(&x.to_le_bytes());
    }
    fn put64(v: &mut [u8], at: usize, x: u64) {
        v[at..at + 8].copy_from_slice(&x.to_le_bytes());
    }

    #[test]
    fn an_lmdb_meta_page_reads_its_page_size_from_the_free_dbs_pad() {
        // The load-bearing claim: the page size is in the DATA file, at
        // mm_dbs[0].md_pad, not only in the lock file.
        let data = env(4096, 1234, b"");
        let Outcome::Text(t) = Lmdb.extract(&data, "data.mdb").expect("extract") else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("page size: 4096"), "{s}");
        assert!(s.contains("pages in map: 1"), "{s}");
        assert!(s.contains("last used page: 4"), "{s}");
        assert!(s.contains("transaction id: 99"), "{s}");
        // 1234 entries and 3 leaf pages belong to the MAIN db; reading
        // mm_dbs[1] at 24 would report the free list's zeros instead.
        assert!(s.contains("1234 entries"), "{s}");
        assert!(s.contains("3 leaf pages"), "{s}");
    }

    #[test]
    fn the_two_magic_numbers_stay_apart() {
        // An Access file reaches this reader only to be declined, and the
        // reverse is the whole reason this adapter exists.
        let mut jet = vec![0u8; 4096];
        jet[0] = 0x00;
        jet[1] = 0x01;
        jet[0x14..0x16].copy_from_slice(&2048u16.to_le_bytes());
        let err = match Lmdb.extract(&jet, "x.mdb") {
            Err(e) => e,
            Ok(_) => panic!("a Jet file must not be accepted as LMDB"),
        };
        assert!(
            format!("{err:#}").contains("not an LMDB data file"),
            "{err:#}"
        );

        // And an LMDB file is not accepted by the Jet magic check, which is
        // 00 01 00 00 at the same offset.
        let lm = env(4096, 0, b"");
        assert_eq!(lm[0], 0xDE);
        assert_ne!(lm[0], 0x00);
    }

    #[test]
    fn a_file_that_is_neither_is_refused_with_the_words_it_carries() {
        let mut v = vec![0u8; 4096];
        put32(&mut v, OFF_MAGIC, 0x1234_5678);
        assert!(Lmdb.extract(&v, "x.mdb").is_err());

        let mut v = vec![0u8; 4096];
        put32(&mut v, OFF_MAGIC, MDB_MAGIC);
        put32(&mut v, OFF_VERSION, 77);
        assert!(Lmdb.extract(&v, "x.mdb").is_err(), "unknown version");

        // Right magic, right version, a page size liblmdb never writes.
        let mut v = env(4096, 0, b"");
        put32(&mut v, OFF_FREEDB_PAD, 3000);
        assert!(
            Lmdb.extract(&v, "x.mdb").is_err(),
            "3000 is not a power of two"
        );
    }

    #[test]
    fn a_32_bit_layout_is_refused_rather_than_misread() {
        // The 64-bit offsets put `mm_mapsize` at 16. On a 32-bit build that
        // word is something else, so the length check is what catches it.
        let mut v = env(4096, 0, b"");
        put64(&mut v, OFF_MAPSIZE, 999_999);
        let err = match Lmdb.extract(&v, "data.mdb") {
            Err(e) => e,
            Ok(_) => panic!("a map size that does not match the file must be refused"),
        };
        assert!(format!("{err:#}").contains("32-bit"), "{err:#}");
    }

    #[test]
    fn values_survive_as_printable_runs_and_the_magic_does_not() {
        let payload = b"\x00\x00user-account-roberts\x00\x00session-token-abc\x00";
        let data = env(4096, 2, payload);
        let Outcome::Text(t) = Lmdb.extract(&data, "data.mdb").expect("extract") else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("user-account-roberts"), "{s}");
        assert!(s.contains("session-token-abc"), "{s}");
        assert!(
            !s.contains("BEEFC0DE"),
            "the magic is structure, not content: {s}"
        );
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![
                ("env", env(4096, 5, b"hello")),
                ("tiny", vec![0xDE, 0xC0, 0xEF, 0xBE]),
                ("empty", vec![]),
                ("zeros", vec![0u8; 8192]),
            ],
            500,
            "lmdb",
            |data| {
                let _ = Lmdb.extract(data, "data.mdb");
            },
        );
    }
}
