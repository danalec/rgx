// SPDX-License-Identifier: Apache-2.0

//! Firebird and InterBase page files (`.fdb`, `.gdb`).
//!
//! A Firebird database is a single file of fixed-size pages. The engine
//! decides what it is by reading the first 1024 bytes — the header page —
//! rather than by matching an ASCII signature, and so does this reader: the
//! three things a header page always carries are the page-type byte, the
//! page-checksum word that has been the constant `12345` since checksums
//! were dropped, and a page size that is a power of two in the set the
//! engine accepts. Those three together are what a false positive would have
//! to collide with all of at once.
//!
//! The layout below is the `struct header_page` from Firebird's `ods.h` as
//! documented by IBExpert, cross-checked against the field list in the
//! Firebird manual. Two facts about it are load-bearing and easy to get
//! wrong:
//!
//! - `hdr_ods_version` is the ODS major version **ANDed with `0x8000`**, the
//!   "this file was written by Firebird" flag. Reading it as a bare version
//!   prints 32779 for ODS 11.
//! - The minor version is a *separate* field (`hdr_ods_minor`), so "ODS
//!   11.2" is assembled from two words 44 bytes apart, not parsed from one.
//!
//! This reports the header page only. The rows live in data pages reached
//! through the pointer pages named by `hdr_PAGES`, and following that chain
//! to the system tables is a second format reader; what is here is the part
//! that can be stated from the file without guessing.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rgx_core::{decline, Adapter, Outcome, Result};

/// Page-type byte for the database header page (`pag_header` in `ods.h`).
const PAG_HEADER: u8 = 1;
/// The checksum word is no longer a checksum; it is this constant, and it is
/// the strongest single signal that a page is really a Firebird page.
const PAGE_CHECKSUM: u16 = 12345;
/// The Firebird-written flag ORed into `hdr_ods_version`.
const ODS_FIREBIRD_FLAG: u16 = 0x8000;

/// Offsets into the header page. The first five are the standard 16-byte
/// page header (`hdr_header`) that every page in the file carries.
const OFF_PAGE_SIZE: usize = 16;
const OFF_ODS_VERSION: usize = 18;
const OFF_PAGES: usize = 20;
const OFF_NEXT_PAGE: usize = 24;
const OFF_NEXT_TXN: usize = 36;
const OFF_SEQUENCE: usize = 40;
const OFF_FLAGS: usize = 42;
const OFF_CREATION_DATE: usize = 44;
const OFF_IMPLEMENTATION: usize = 60;
const OFF_ODS_MINOR: usize = 62;
const OFF_ODS_MINOR_ORIGINAL: usize = 64;
const OFF_PAGE_BUFFERS: usize = 68;

pub struct Firebird;
impl Adapter for Firebird {
    fn name(&self) -> &'static str {
        "firebird"
    }
    /// `.gdb` is InterBase, which is Firebird's ancestor and the same page
    /// layout at an older ODS. Reading both with one reader is the honest
    /// description: the format did not change, the version stamp did.
    fn extensions(&self) -> &'static [&'static str] {
        &["fdb", "gdb"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // The signature check has to happen here, not only in the tests: a
        // bare page-size comparison accepts every page-aligned file that
        // happens to carry a plausible number at offset 16, and this
        // adapter's whole claim is that it can tell one from the other.
        if !looks_like_firebird(data) {
            decline!(
                "not a Firebird/InterBase page file: page type {} and checksum word {} do not \
                 identify one",
                data.first().copied().unwrap_or(0),
                rd_u16(data, 2),
            );
        }
        let page_size = rd_u16(data, OFF_PAGE_SIZE);
        // The engine reads a whole page before it trusts any of this, so a
        // file smaller than the page it claims is not a database whatever
        // its first bytes say.
        if data.len() < page_size as usize {
            decline!(
                "not a Firebird page file: claims a {page_size}-byte page but the file is \
                 {} bytes",
                data.len()
            );
        }
        Ok(Outcome::Text(report(data, page_size).into_bytes()))
    }
}

fn report(data: &[u8], page_size: u16) -> String {
    let mut s = String::new();
    let ods_major = rd_u16(data, OFF_ODS_VERSION);
    let ods_minor = rd_u16(data, OFF_ODS_MINOR);
    s.push_str(&format!(
        "firebird ods: {}.{} (minor at creation: {})\n",
        ods_major & !ODS_FIREBIRD_FLAG,
        ods_minor,
        rd_u16(data, OFF_ODS_MINOR_ORIGINAL),
    ));
    s.push_str(&format!("page size: {page_size}\n"));
    let pages = data.len() / page_size as usize;
    s.push_str(&format!(
        "pages: {pages} ({} bytes)\n",
        data.len() / page_size as usize * page_size as usize
    ));
    s.push_str(&format!(
        "implementation: {}\n",
        rd_u16(data, OFF_IMPLEMENTATION)
    ));
    // `hdr_sequence` is this file's index in a multi-file database; zero with
    // no `hdr_next_page` is the ordinary single-file shape.
    let sequence = rd_u16(data, OFF_SEQUENCE);
    let next = rd_u32(data, OFF_NEXT_PAGE);
    s.push_str(&format!(
        "file sequence: {sequence}{}\n",
        if next == 0 {
            ""
        } else {
            " (multi-file: next header page follows)"
        }
    ));
    s.push_str(&format!(
        "next transaction: {}\n",
        rd_u32(data, OFF_NEXT_TXN)
    ));
    s.push_str(&format!(
        "page buffers: {}\n",
        rd_u32(data, OFF_PAGE_BUFFERS)
    ));
    s.push_str(&format!(
        "RDB$PAGES pointer page: {}\n",
        rd_u32(data, OFF_PAGES)
    ));
    // A field that cannot be decoded is printed as what it is, and the
    // report continues. Propagating it instead would make the whole header
    // unanswerable over four bytes of a 96-byte page -- and an all-zero
    // creation date is not corrupt at all, it is what a file whose clock
    // field was never set carries.
    s.push_str(&format!(
        "created: {}\n",
        fb_time(rd_u32(data, OFF_CREATION_DATE))
    ));

    let flags = rd_u16(data, OFF_FLAGS);
    let mut named: Vec<&str> = Vec::new();
    for (bit, name) in FLAG_NAMES {
        if flags & bit != 0 {
            named.push(name);
        }
    }
    s.push_str(&format!(
        "flags: 0x{flags:04x}{}\n",
        if named.is_empty() {
            String::new()
        } else {
            alloc::format!(" ({})", named.join(", "))
        }
    ));
    s.push_str(
        "the rows are not walked: they live in data pages reached through \
         RDB$PAGES, which is a second reader\n",
    );
    s
}

/// `hdr_flags`, from the IBExpert header-page reference. Read as a `u16` at
/// offset 42 — the field is two bytes even though the table that documents
/// it names bit 16, which does not exist in a `USHORT`.
const FLAG_NAMES: &[(u16, &str)] = &[
    (0x0001, "active shadow"),
    (0x0002, "force write"),
    (0x0004, "short journal"),
    (0x0008, "long journal"),
    (0x0010, "no checksums"),
    (0x0020, "no reserved space"),
    (0x0040, "disable cache"),
    (0x0080, "shutdown"),
    (0x0100, "SQL dialect 3"),
    (0x0200, "read only"),
    (0x0400, "no blob filtering"),
    (0x0800, "read/write clash"),
    (0x1000, "version 3"),
];

/// Whether `data` starts a Firebird/InterBase page file.
///
/// Kept separate from `extract` because this is the predicate that has to be
/// right: it is what separates a database from any other page-aligned file
/// handed to the registry under the same extension.
pub fn looks_like_firebird(data: &[u8]) -> bool {
    data.first() == Some(&PAG_HEADER)
        && rd_u16(data, 2) == PAGE_CHECKSUM
        && is_page_size(rd_u16(data, OFF_PAGE_SIZE))
}

/// The page sizes Firebird accepts. A power of two alone would also admit 2
/// and 32768, which no engine produces. 65536 is absent because
/// `hdr_page_size` is a `USHORT` and cannot hold it: a header page that
/// claims it would be reporting a value the field cannot represent.
fn is_page_size(n: u16) -> bool {
    matches!(n, 1024 | 2048 | 4096 | 8192 | 16384 | 32768)
}

/// Firebird's timestamp: a day count from 17 November 1858 (the
/// modified-Julian epoch) in the top 16 bits, and the fraction of that day
/// in the low 16 bits, in units of 1/10000 of a day -- 10 microseconds each,
/// so 8.64 seconds per unit. Reading the fraction as a fraction of an *hour*
/// shifts every timestamp by more than a factor of eight.
///
/// The day count is sixteen bits, so every value in the field is a real date
/// between 1858 and 2038. There is no "this is not a timestamp" case to
/// refuse, which is why this returns a `String` and not an `Option`: an
/// undecodable branch here would be unreachable, not defensive.
fn fb_time(raw: u32) -> String {
    let days = (raw >> 16) as i64;
    let frac = raw & 0xFFFF;
    // Julian day 2400001 is 1858-11-17; 2440588 is 1970-01-01. Walk between
    // them rather than carrying a day count through the arithmetic. This is
    // negative for anything before 1970, which is most of the range.
    let unix_days = days + 2_400_001 - 2_440_588;
    let seconds = frac * 86_400 / 10_000;
    let (y, mo, d) = civil_from_days(unix_days);
    format!(
        "{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

/// Howard Hinnant's `civil_from_days`, which is the same day-number
/// algorithm the other Firebird pieces are derived from. Kept here rather
/// than pulled in: the crate is `no_std` + `alloc` and this is nine lines.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 2024-03-17 12:00:00, spelled out rather than computed by the inverse of
    /// the decoder, because a test that builds its expectation with the same
    /// arithmetic agrees with a decoder that is wrong.
    ///
    /// 60386 days from 1858-11-17 is 19799 days from 1970-01-01, which is
    /// 2024-03-17. Noon is deliberate: the fraction counts 10000 units to the
    /// day, and 5000 units is exactly half a day, so this instant survives the
    /// quantisation intact. 09:30:00 does not — it is 3958.33 units, and the
    /// format stores 3958, which decodes back to 09:29:57.
    const CREATED_2024_03_17: u32 = (60_386 << 16) | 5_000;

    /// A header page built to the documented offsets. Written field by field
    /// at its real position rather than as a literal blob, because the whole
    /// defect this format invites is reading a field one slot early.
    fn header_page(page_size: u16, ods: u16) -> Vec<u8> {
        let mut p = vec![0u8; page_size as usize];
        p[0] = PAG_HEADER;
        p[2..4].copy_from_slice(&PAGE_CHECKSUM.to_le_bytes());
        p[4..8].copy_from_slice(&7u32.to_le_bytes()); // page generation
        put16(&mut p, OFF_PAGE_SIZE, page_size);
        put16(&mut p, OFF_ODS_VERSION, ods);
        put32(&mut p, OFF_PAGES, 3);
        put32(&mut p, OFF_NEXT_PAGE, 0);
        put32(&mut p, OFF_NEXT_TXN, 42);
        put16(&mut p, OFF_SEQUENCE, 0);
        put16(&mut p, OFF_FLAGS, 0x0100 | 0x0080);
        put32(&mut p, OFF_CREATION_DATE, CREATED_2024_03_17);
        put16(&mut p, OFF_IMPLEMENTATION, 1);
        put16(&mut p, OFF_ODS_MINOR, 2);
        put16(&mut p, OFF_ODS_MINOR_ORIGINAL, 1);
        put32(&mut p, OFF_PAGE_BUFFERS, 2048);
        p
    }

    fn put16(p: &mut [u8], at: usize, v: u16) {
        p[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put32(p: &mut [u8], at: usize, v: u32) {
        p[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn an_ods_11_header_page_reads_its_version_page_size_and_date() {
        let data = header_page(4096, 0x8000 | 11);
        assert!(
            looks_like_firebird(&data),
            "a real header page must be recognised"
        );
        let out = Firebird.extract(&data, "x.fdb").expect("extract");
        let Outcome::Text(text) = out else {
            panic!("expected a text report");
        };
        let s = String::from_utf8(text).unwrap();
        // The 0x8000 flag is masked off; reading the field raw would print
        // 32779 here.
        assert!(s.contains("firebird ods: 11.2"), "{s}");
        assert!(s.contains("page size: 4096"), "{s}");
        assert!(s.contains("next transaction: 42"), "{s}");
        assert!(s.contains("page buffers: 2048"), "{s}");
        assert!(s.contains("created: 2024-03-17 12:00:00"), "{s}");
        assert!(s.contains("shutdown"), "{s}");
        assert!(s.contains("SQL dialect 3"), "{s}");
    }

    #[test]
    fn the_minor_version_comes_from_its_own_field_not_from_the_major() {
        // ODS major 10 with minor 1: the classic InterBase-era pairing that
        // a reader folding both into one word would print as "10.10".
        let data = header_page(8192, 0x8000 | 10);
        put16(&mut data.clone(), OFF_ODS_MINOR, 1);
        let mut data = data;
        put16(&mut data, OFF_ODS_MINOR, 1);
        let out = Firebird.extract(&data, "x.gdb").expect("extract");
        let Outcome::Text(text) = out else {
            panic!("text")
        };
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("firebird ods: 10.1"),
            "minor is a separate field 44 bytes after the major"
        );
    }

    #[test]
    fn a_file_that_is_not_a_page_file_is_declined_rather_than_described() {
        // Right page type, wrong checksum word.
        let mut data = header_page(4096, 0x8000 | 11);
        put16(&mut data, 2, 9999);
        assert!(!looks_like_firebird(&data));
        assert!(Firebird.extract(&data, "x.fdb").is_err());

        // Right checksum, page size the engine never produces.
        let mut data = header_page(4096, 0x8000 | 11);
        put16(&mut data, OFF_PAGE_SIZE, 3000);
        assert!(
            !looks_like_firebird(&data),
            "3000 is not a Firebird page size"
        );

        // A bare SQLite header: the first byte is not a page type.
        let mut data = vec![0u8; 4096];
        data[..15].copy_from_slice(b"SQLite format 3");
        assert!(!looks_like_firebird(&data));

        // A truncated file that claims a page larger than it is.
        let mut data = header_page(16384, 0x8000 | 11);
        data.truncate(100);
        assert!(
            Firebird.extract(&data, "x.fdb").is_err(),
            "a file shorter than its own page is not a database"
        );
    }

    #[test]
    fn an_unset_clock_field_does_not_sink_the_whole_header() {
        // All-zero creation date: the file is still a Firebird page file, and
        // four bytes of a 96-byte header are not a reason to decline the
        // other ninety-two. This is the shape the E2E fixture uses, and the
        // unit suite missed it until the CLI test failed on it.
        let mut data = header_page(4096, 0x8000 | 11);
        put32(&mut data, OFF_CREATION_DATE, 0);
        let out = Firebird
            .extract(&data, "x.fdb")
            .expect("an unset date is not a failure");
        let Outcome::Text(text) = out else {
            panic!("text")
        };
        let s = String::from_utf8(text).unwrap();
        assert!(s.contains("created: 1858-11-17"), "day zero is a date: {s}");
        assert!(s.contains("page size: 4096"), "the rest survives: {s}");

        // The widest day count the 16-bit field can hold is a real date too,
        // and says so rather than refusing the file or panicking.
        put32(&mut data, OFF_CREATION_DATE, u32::MAX);
        let out = Firebird.extract(&data, "x.fdb").expect("still answers");
        let Outcome::Text(text) = out else {
            panic!("text")
        };
        let s = String::from_utf8(text).unwrap();
        assert!(
            s.contains("created: 20"),
            "every 16-bit day count is a date: {s}"
        );
    }

    #[test]
    fn the_report_says_it_is_not_reading_the_rows() {
        let data = header_page(4096, 0x8000 | 11);
        let out = Firebird.extract(&data, "x.fdb").expect("extract");
        let Outcome::Text(text) = out else {
            panic!("text")
        };
        let s = String::from_utf8(text).unwrap();
        assert!(
            s.contains("the rows are not walked"),
            "a metadata-only answer must say so: {s}"
        );
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![
                ("header", header_page(4096, 0x8000 | 11)),
                ("short", vec![1, 0x39, 0x30]),
                ("empty", vec![]),
                ("zeros", vec![0u8; 8192]),
            ],
            500,
            "firebird",
            |data| {
                let _ = Firebird.extract(data, "f.fdb");
                let _ = looks_like_firebird(data);
            },
        );
    }
}
