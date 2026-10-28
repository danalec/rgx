// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the inspect family, through the real binary.
//!
//! The unit tests in `rgx-adapters-inspect` call `Adapter::extract` directly.
//! That proves a parser reads a format; it cannot prove the *registry* sends
//! the file there, and the registry is where this batch of formats actually
//! failed: twenty-odd adapters were added to one crate whose order decides
//! who wins, and a claim that never fires is indistinguishable from a parser
//! that never ran.
//!
//! So every row here is checked twice. The search must come back (the adapter
//! surfaced the token), **and** `--json` must name the adapter that answered.
//! A row that falls through to `raw` fails the second check even though the
//! first one passes, because the bytes are still there.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

fn rgx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rgx"))
}

///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn scratch(name: &str) -> PathBuf {
    common::scratch(&format!("inspect-test-{name}"))
}

/// Every `--json` match line, as `(path, adapter)`.
///
/// The path matters as much as the adapter: an archive answers with
/// `Members`, so the unit that matches is the member, and its path carries a
/// `/` the container's does not. Checking only the adapter name would call a
/// correctly-recursed zip "raw" and a shadowed claim "fine".
fn hits(dir: &Path, pattern: &str) -> Vec<(String, String)> {
    let out = rgx()
        .args(["--json", pattern])
        .arg(dir)
        .output()
        .expect("rgx runs");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut found = Vec::new();
    for line in text.lines().filter(|l| l.contains("\"type\":\"match\"")) {
        let take = |key: &str| -> Option<String> {
            let at = line.find(key)?;
            let rest = &line[at + key.len()..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        };
        if let (Some(p), Some(a)) = (take("\"path\":{\"text\":\""), take("\"adapter\":\"")) {
            found.push((p, a));
        }
    }
    found
}

/// The adapters that reported a hit inside `file` (or inside one of its
/// members), plus whether any of those hits came from a member.
fn hits_in(dir: &Path, pattern: &str, file: &str) -> (Vec<String>, bool) {
    let mut adapters = Vec::new();
    let mut member = false;
    for (path, adapter) in hits(dir, pattern) {
        // The container itself, or anything inside it: a member's path is
        // `container!member`, so `ends_with` alone would drop every archive
        // row and a collision between two fixtures sharing a token would
        // pass by accident. The container is the part before the first `!`,
        // and the member's own name may carry a `/` of its own.
        let inside = path.ends_with(file)
            || path
                .split_once('!')
                .is_some_and(|(container, _)| container.ends_with(file));
        if !inside {
            continue;
        }
        if path.contains('!') {
            member = true;
        }
        if !adapters.contains(&adapter) {
            adapters.push(adapter);
        }
    }
    (adapters, member)
}

// --- fixture builders -------------------------------------------------------

fn le16(v: u16) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn le32(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn be32(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// One IFD with an explicit per-entry count. The count is what decides where
/// a value lives, so it cannot be left implicit in a fixture: a four-byte
/// ASCII value is stored in the entry's own slot and is never a file offset.
fn ifd(entries: &[(u16, u16, u32, u32)], next: u32) -> Vec<u8> {
    let mut v = le16(entries.len() as u16);
    for (tag, ty, count, val) in entries {
        v.extend_from_slice(&le16(*tag));
        v.extend_from_slice(&le16(*ty));
        v.extend_from_slice(&le32(*count));
        v.extend_from_slice(&le32(*val));
    }
    v.extend_from_slice(&le32(next));
    v
}

/// A one-page TIFF whose ImageDescription carries `text` out of line.
fn tiff(text: &[u8]) -> Vec<u8> {
    let mut out = b"II\x2a\x00".to_vec();
    out.extend_from_slice(&le32(8));
    let ifd0 = ifd(
        &[
            (256, 4, 1, 800),
            (257, 4, 1, 600),
            (270, 2, text.len() as u32, 0),
        ],
        0,
    );
    out.extend_from_slice(&ifd0);
    let at = out.len() as u32;
    out.extend_from_slice(text);
    // Patch the ImageDescription value slot now that the string has a home.
    let slot = 8 + 2 + 2 * 12 + 8;
    out[slot..slot + 4].copy_from_slice(&le32(at));
    out
}

/// The CRC-32 the ZIP central directory carries. Pinned to the standard
/// check value: a CRC that is wrong but *consistent* across the header and
/// the entry produces a zip that only this fixture can open.
const CRC32_CHECK: u32 = 0xCBF4_3926;
/// A stored (uncompressed) ZIP holding one member: the shape every package
/// format on the zip claim list actually is.
fn zip_with(member: &str, body: &[u8]) -> Vec<u8> {
    assert_eq!(
        crc32(b"123456789"),
        CRC32_CHECK,
        "the fixture CRC is wrong, and the zip reader would reject every entry"
    );
    let crc = crc32(body);
    let mut out = Vec::new();
    let local = 0u32;
    out.extend_from_slice(&le32(0x0403_4b50));
    out.extend_from_slice(&le16(20)); // version needed
    out.extend_from_slice(&le16(0)); // flags
    out.extend_from_slice(&le16(0)); // stored
    out.extend_from_slice(&le16(0)); // time
    out.extend_from_slice(&le16(0)); // date
    out.extend_from_slice(&le32(crc));
    out.extend_from_slice(&le32(body.len() as u32));
    out.extend_from_slice(&le32(body.len() as u32));
    out.extend_from_slice(&(member.len() as u16).to_le_bytes());
    // The local header's fixed part is 30 bytes and ends with the *extra
    // field* length. Skipping it puts the filename two bytes early and every
    // offset after it along with it.
    out.extend_from_slice(&le16(0));
    out.extend_from_slice(member.as_bytes());
    out.extend_from_slice(body);
    let dir_at = out.len() as u32;
    out.extend_from_slice(&le32(0x0201_4b50));
    out.extend_from_slice(&le16(20)); // version made by
    out.extend_from_slice(&le16(20)); // version needed
    out.extend_from_slice(&le16(0)); // flags
    out.extend_from_slice(&le16(0)); // stored
    out.extend_from_slice(&le16(0)); // time
    out.extend_from_slice(&le16(0)); // date
    out.extend_from_slice(&le32(crc));
    out.extend_from_slice(&le32(body.len() as u32));
    out.extend_from_slice(&le32(body.len() as u32));
    out.extend_from_slice(&(member.len() as u16).to_le_bytes());
    out.extend_from_slice(&le16(0)); // extra
    out.extend_from_slice(&le16(0)); // comment
    out.extend_from_slice(&le16(0)); // disk
    out.extend_from_slice(&le16(0)); // internal attrs
    out.extend_from_slice(&le32(0)); // external attrs
    out.extend_from_slice(&le32(local));
    out.extend_from_slice(member.as_bytes());
    let cd_at = out.len() as u32;
    let cd_len = out.len() as u32 - dir_at;
    out.extend_from_slice(&le32(0x0605_4b50));
    out.extend_from_slice(&le16(0)); // disk
    out.extend_from_slice(&le16(0)); // cd start disk
    out.extend_from_slice(&le16(1)); // entries on this disk
    out.extend_from_slice(&le16(1)); // total entries
    out.extend_from_slice(&le32(cd_len));
    out.extend_from_slice(&le32(dir_at));
    out.extend_from_slice(&le16(0)); // comment length
    let _ = cd_at;
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for b in data {
        crc = table[((crc ^ u32::from(*b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// The smallest compound file that is still a compound file: a header, one
/// FAT sector and a directory sector holding only the root entry.
fn compound() -> Vec<u8> {
    const SEC: usize = 512;
    const FREESECT: u32 = 0xFFFF_FFFF;
    const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
    const FATSECT: u32 = 0xFFFF_FFFD;

    // Four sectors: the header, the directory, a spare, and the FAT. Three
    // put the FAT one sector past the end of the buffer.
    let mut f = vec![0u8; SEC * 4];
    f[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    f[24..26].copy_from_slice(&le16(0x003E)); // minor version
    f[26..28].copy_from_slice(&le16(0x0003)); // major version 3
    f[28..30].copy_from_slice(&le16(0xFFFE)); // little endian
    f[30..32].copy_from_slice(&le16(9)); // 512-byte sectors
    f[32..34].copy_from_slice(&le16(6)); // 64-byte mini sectors
    f[44..48].copy_from_slice(&le32(1)); // one FAT sector
    f[48..52].copy_from_slice(&le32(1)); // first directory sector
    f[56..60].copy_from_slice(&le32(4096)); // mini stream cutoff
    f[60..64].copy_from_slice(&le32(ENDOFCHAIN)); // first mini FAT
    f[64..68].copy_from_slice(&le32(0)); // no mini FAT sectors
    f[68..72].copy_from_slice(&le32(ENDOFCHAIN)); // no DIFAT chain
    f[72..76].copy_from_slice(&le32(3)); // sector 3 holds the FAT

    // Sector 1: the directory. Entry 0 is the root, typed 5 and empty.
    let dir = SEC;
    f[dir..dir + 2].copy_from_slice(&(5u16).to_le_bytes());
    f[dir + 64..dir + 66].copy_from_slice(&le16(1)); // one child sector

    // Sector 3: the FAT. Sector 0 is the FAT itself, 1 the directory chain,
    // 2 unused, and the rest free.
    let fat = SEC * 3;
    for i in 0..(SEC / 4) {
        let v = match i {
            0 => FATSECT,
            1 => ENDOFCHAIN,
            _ => FREESECT,
        };
        f[fat + i * 4..fat + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    f
}

fn bmff(typ: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut v = be32((body.len() + 8) as u32);
    v.extend_from_slice(typ);
    v.extend_from_slice(body);
    v
}

/// An MP4 whose title lives in `moov/udta/meta/ilst/cnam/data`. Every level
/// of that path is a box; a missing wrapper shifts the level below it.
fn mp4(title: &str) -> Vec<u8> {
    let mut data = be32(1); // type-set: UTF-8
    data.extend_from_slice(&be32(0)); // locale
    data.extend_from_slice(title.as_bytes());
    let ilst = bmff(b"ilst", &bmff(b"\xa9nam", &bmff(b"data", &data)));
    let mut meta = vec![0u8; 4]; // FullBox version/flags
    meta.extend_from_slice(&ilst);
    let udta = bmff(b"udta", &bmff(b"meta", &meta));
    let mut ftyp = b"isom".to_vec();
    ftyp.extend_from_slice(&be32(0x200));
    ftyp.extend_from_slice(b"isomiso2mp41");
    let mut out = bmff(b"ftyp", &ftyp);
    out.extend_from_slice(&bmff(b"moov", &udta));
    out
}

/// GRIB2 edition 2, template 3.0, with a single uncompressed value.
/// Parameter 2.0 is Temperature in code table 4.2, which is the name a
/// search for "Temperature" has to be able to find.
fn be16(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn section(n: u8, body: &[u8]) -> Vec<u8> {
    // The declared length covers the length field AND the section-number
    // octet, so it is body + 5. Body + 4 understates every section by one
    // and lands the next header one byte into this one's body.
    let mut v = be32((body.len() + 5) as u32);
    v.push(n);
    v.extend_from_slice(body);
    v
}

/// GRIB2 edition 2, grid template 3.0, product template 4.0 with simple
/// packing. Parameter category 0 / number 6 is "Dew Point Temperature" in
/// code table 4.2, and that name is what a search has to be able to find: a
/// GRIB file's bytes carry the number, never the word.
fn grib2() -> Vec<u8> {
    let mut s1 = Vec::new();
    s1.extend_from_slice(&be16(7)); // octets 6-7 centre
    s1.extend_from_slice(&be16(0)); // octets 8-9 subcentre
    s1.push(2); // octet 10 master tables version
    s1.push(1); // octet 11 local tables version
    s1.push(1); // octet 12 significance of reference time
    s1.extend_from_slice(&be16(2026)); // octets 13-14 year
    s1.extend_from_slice(&[10, 18, 12, 30, 0]); // octets 15-19
    s1.push(0); // octet 20 production status
    s1.push(2); // octet 21 type of processed data

    let mut s3 = Vec::new();
    s3.push(0); // octet 6 source of grid definition
    s3.extend_from_slice(&be32(4)); // octets 7-10 data points
    s3.push(0); // octet 11 optional list length
    s3.push(0); // octet 12 interpretation
    s3.extend_from_slice(&be16(0)); // octets 13-14 grid template 3.0

    let mut s4 = Vec::new();
    s4.extend_from_slice(&be16(0)); // octets 6-7 coordinate values
    s4.extend_from_slice(&be16(0)); // octets 8-9 product template 4.0
    s4.push(0); // octet 10 parameter category
    s4.push(6); // octet 11 parameter number
    s4.push(2); // octet 12 type of generating process
    s4.push(0); // octet 13 background process
    s4.push(255); // octet 14 generating process id
    s4.extend_from_slice(&[0, 0, 0, 1]); // octets 15-18 cutoff and time unit
    s4.extend_from_slice(&be32(6)); // octets 19-22 forecast time
    s4.push(100); // octet 23 type of first fixed surface
    s4.push(0); // octet 24 scale factor
    s4.extend_from_slice(&be32(2)); // octets 25-28 scaled value
    s4.push(255); // octet 29 second surface
    s4.push(0); // octet 30 scale factor
    s4.extend_from_slice(&be32(0)); // octets 31-34

    let mut s5 = Vec::new();
    s5.extend_from_slice(&be32(4)); // octets 6-9 data points
    s5.extend_from_slice(&be16(0)); // octets 10-11 template 5.0
    s5.extend_from_slice(&0.0f32.to_be_bytes()); // octets 12-15 reference
    s5.extend_from_slice(&be16(0)); // octets 16-17 binary scale
    s5.extend_from_slice(&be16(0)); // octets 18-19 decimal scale
    s5.push(16); // octet 20 bits per value
    s5.push(0); // octet 21 type of original values

    let mut s7 = Vec::new();
    for v in [0u16, 1, 2, 3] {
        s7.extend_from_slice(&v.to_be_bytes());
    }

    let mut body = Vec::new();
    for s in [
        section(1, &s1),
        section(3, &s3),
        section(4, &s4),
        section(5, &s5),
        section(6, &[255]),
        section(7, &s7),
    ] {
        body.extend_from_slice(&s);
    }
    body.extend_from_slice(b"7777");

    let mut out = b"GRIB".to_vec();
    out.extend_from_slice(&[0, 0]); // reserved
    out.push(0); // discipline: meteorological products
    out.push(2); // edition
    out.extend_from_slice(&((16 + body.len()) as u64).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// A BUFR message whose declared length and terminator agree, so the adapter
/// reports the edition instead of calling the file truncated. Section 0 is
/// four indicator octets, a **three**-octet length and the edition number --
/// a four-octet length would push the edition one byte along and the adapter
/// would read the body's first byte as it.
fn bufr() -> Vec<u8> {
    let total = 8 + 12 + 4;
    let mut v = b"BUFR".to_vec();
    v.push((total >> 16) as u8);
    v.push((total >> 8) as u8);
    v.push(total as u8);
    v.push(4); // edition
    v.extend_from_slice(&[0u8; 12]);
    v.extend_from_slice(b"7777");
    v
}

/// SEG-Y: a 3200-byte EBCDIC textual header, a 400-byte binary header and a
/// 400-byte trace header.
fn segy(line: &str) -> Vec<u8> {
    /// CP037. The letter runs are broken by punctuation: uppercase A-I sit at
    /// 0x41-0x49, J-R at 0x51-0x59 and S-Z at 0x62-0x69, with lowercase at
    /// 0x81/0x91/0xA2. Treating the alphabet as one run maps everything from
    /// J on to a different letter -- "LINE" came back as " IIE".
    fn ebcdic(s: &str) -> Vec<u8> {
        s.bytes()
            .map(|b| match b {
                b'0'..=b'9' => b - b'0' + 0xF0,
                b' ' => 0x40,
                b'A'..=b'I' => b - b'A' + 0x41,
                b'J'..=b'R' => b - b'J' + 0x51,
                b'S'..=b'Z' => b - b'S' + 0x62,
                b'a'..=b'i' => b - b'a' + 0x81,
                b'j'..=b'r' => b - b'j' + 0x91,
                b's'..=b'z' => b - b's' + 0xA2,
                other => other,
            })
            .collect()
    }
    let mut card = vec![b' '; 80];
    let bytes = ebcdic(line);
    card[..bytes.len()].copy_from_slice(&bytes);
    let mut v = Vec::new();
    v.extend_from_slice(&card);
    v.extend_from_slice(&card);
    v.resize(3200, b' ');
    v.extend_from_slice(&[0u8; 400]);
    let mut trace = vec![0u8; 400];
    trace[0..4].copy_from_slice(&1i32.to_be_bytes());
    trace[4..8].copy_from_slice(&1i32.to_be_bytes());
    trace[12..16].copy_from_slice(&100i32.to_be_bytes());
    trace[16..20].copy_from_slice(&500i32.to_be_bytes());
    v.extend_from_slice(&trace);
    v
}

/// A BCF2 header: the five-byte magic (`BCF` + major 2 + minor 2), the
/// header-text length as a **little-endian** i32, and the VCF header text
/// whose `##fileformat` line is the one thing a BCF file states in words.
fn bcf() -> Vec<u8> {
    let text = "##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\n";
    let mut p = b"BCF\x02\x02".to_vec();
    p.extend_from_slice(&((text.len() as i32 + 1).to_le_bytes()));
    p.extend_from_slice(text.as_bytes());
    p.push(0); // the trailing NUL the length counts
               // A `.bcf` on disk is BGZF-compressed, so the fixture has to be too.
    bgzf(&p)
}

/// A CRAM 3 file: the definition (magic, major/minor, 20-byte id) followed by
/// an empty header container. Every ITF-8/LTF-8 zero is one `0x00` byte, so
/// the container is the 4-byte length, eight zero fields and a CRC -- and the
/// length counts all of it, including itself.
fn cram() -> Vec<u8> {
    let mut v = b"CRAM".to_vec();
    v.push(3);
    v.push(0);
    v.extend_from_slice(b"RGXFIXTUREID00000000000"); // 20-byte file id
    let body = [0u8; 8]; // ref, start, span, records, counter, bases, blocks, landmarks
    let mut container = be32((4 + body.len() + 4) as u32);
    container.extend_from_slice(&body);
    container.extend_from_slice(&crc32(&body).to_be_bytes());
    v.extend_from_slice(&container);
    v
}

/// Wrap `payload` in one BGZF block plus the empty terminator every BGZF
/// stream ends with.
///
/// The member is produced by the in-house `GzipWriter` and only its header is
/// rebuilt, because BGZF is gzip plus an extra field carrying the total block
/// size minus one as the `BC` subfield -- and that number is the only place a
/// BGZF block's length is written down. Writing a "stored" DEFLATE block by
/// hand instead is a second implementation of the compressor, and the
/// decoder's opinion about where the block ends is not something a test
/// should get to disagree with.
/// SAM text shared by the routing row and the plain-text half of the test
/// below. The header line and both records are what the assertions look for.
const SAM_TEXT: &str = "@HD\tVN:1.6\tSO:coordinate\n\
@SQ\tSN:chr7\tLN:159345973\n\
r1\t0\tchr7\t55271500\t255\t5S90M\t*\t0\t0\tTTTTACCTA\tRGXSAMREAD\n";

fn bgzf(payload: &[u8]) -> Vec<u8> {
    let gz = rgx_core::compress::GzipWriter::new().encode(payload);
    let body = &gz[10..];
    let total = 18 + body.len();
    let mut out = vec![0x1f, 0x8b, 0x08, 0x04]; // FEXTRA
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // mtime
    out.extend_from_slice(&[0x00, 0xff]); // xfl, os unknown
    out.extend_from_slice(&6u16.to_le_bytes()); // xlen
    out.extend_from_slice(b"BC");
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&((total - 1) as u16).to_le_bytes());
    out.extend_from_slice(body);
    assert!(total <= 1 << 16, "the payload does not fit one BGZF block");

    const EOF: [u8; 28] = [
        0x1f, 0x8b, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x06, 0x00, 0x42, 0x43, 0x02,
        0x00, 0x1b, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    out.extend_from_slice(&EOF);
    out
}

/// A BAM: one BGZF member holding `text` as the SAM header. A BAM on disk
/// is compressed like every other format in this family -- an uncompressed
/// fixture would make the adapter decline and the test would pass on the
/// raw bytes instead.
fn bam(text: &[u8]) -> Vec<u8> {
    let mut payload = b"BAM\x01".to_vec(); // the magic the adapter looks for
    payload.extend_from_slice(&le32(text.len() as u32));
    payload.extend_from_slice(text);
    payload.extend_from_slice(&le32(1)); // n_ref
    payload.extend_from_slice(&le32(5)); // l_name, counting the NUL
    payload.extend_from_slice(b"chr1\x00");
    payload.extend_from_slice(&le32(1_000_000)); // l_ref
    bgzf(&payload)
}

/// A binary property list: one dictionary whose single key and single value
/// are the same ASCII string. The trailer at the end carries the offset
/// table and its 32-byte size, so both are written here rather than guessed.
fn bplist(value: &str) -> Vec<u8> {
    let mut out = b"bplist00".to_vec();
    // object 0: the key, object 1: the value, object 2: the dictionary.
    let key_at = out.len();
    out.push(0x50 | value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    let val_at = out.len();
    out.push(0x50 | value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    let dict_at = out.len();
    out.push(0xD1); // dictionary, one key
    out.push(0); // key index
    out.push(1); // value index
    let table_at = out.len();
    for at in [key_at, val_at, dict_at] {
        out.push(at as u8);
    }

    // 5 unused, sortVersion, offsetSize, refSize, then three big-endian
    // counts: 8 + 24 = the 32 bytes the parser slices off the end.
    let mut trailer = [0u8; 32];
    trailer[6] = 1; // offsetSize
    trailer[7] = 1; // refSize
    trailer[8..16].copy_from_slice(&3u64.to_be_bytes()); // three objects
    trailer[16..24].copy_from_slice(&2u64.to_be_bytes()); // top: the dict
    trailer[24..32].copy_from_slice(&(table_at as u64).to_be_bytes());
    out.extend_from_slice(&trailer);
    out
}

fn dwg() -> Vec<u8> {
    let mut v = b"AC1032".to_vec();
    v.resize(64, 0);
    v
}

fn x_t() -> Vec<u8> {
    let mut v = b"**ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec();
    // `**END_OF_HEADER` is what closes the transmit header; without it the
    // adapter cannot tell where the ASCII header stops and the body starts,
    // and declines rather than guessing.
    v.extend_from_slice(
        b"PART1;\nFILE;\nMC=x86_64_win;\nOS=WINDOWS;\nFORMAT=BINARY;\n**END_OF_HEADER;\nEND;\n",
    );
    v
}

fn acis() -> Vec<u8> {
    let mut v = b"ACIS".to_vec();
    v.extend_from_slice(b" 1000\n");
    v.resize(64, 0);
    v
}

/// An ELF with a `.comment` section holding the toolchain string.
fn elf() -> Vec<u8> {
    let shstr = b"\0.shstrtab\0.comment\0".to_vec();
    // Section names are positions in the string table, so the offset is
    // derived from it: typed by hand it lands one byte out, and the
    // reader then reports an ELF with no toolchain instead of failing.
    let comment_name = shstr
        .windows(8)
        .position(|w| w == b".comment")
        .expect("the string table holds .comment") as u32;
    let comment = b"RGX FIXTURE TOOLCHAIN\0";
    let mut v = vec![0u8; 64];
    v[0..4].copy_from_slice(b"\x7fELF");
    v[4] = 2; // 64-bit
    v[5] = 1; // little endian
    v[6] = 1; // version
    let shoff = 64u64;
    let shentsize = 64usize;
    let shnum = 3usize;
    v[40..48].copy_from_slice(&shoff.to_le_bytes());
    v[58..60].copy_from_slice(&(shentsize as u16).to_le_bytes());
    v[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
    v[62..64].copy_from_slice(&1u16.to_le_bytes()); // shstrndx: the .shstrtab entry
    let sec = |name: u32, typ: u32, off: u64, size: u64, out: &mut Vec<u8>| {
        let mut h = vec![0u8; shentsize];
        h[0..4].copy_from_slice(&name.to_le_bytes());
        h[4..8].copy_from_slice(&typ.to_le_bytes());
        h[24..32].copy_from_slice(&off.to_le_bytes());
        h[32..40].copy_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&h);
    };
    let headers_end = 64 + shnum * shentsize;
    let shstr_off = headers_end as u64;
    let comment_off = shstr_off + shstr.len() as u64;
    sec(0, 0, 0, 0, &mut v);
    sec(1, 3, shstr_off, shstr.len() as u64, &mut v);
    sec(comment_name, 1, comment_off, comment.len() as u64, &mut v);
    v.extend_from_slice(&shstr);
    v.extend_from_slice(comment);
    v
}

// --- the table --------------------------------------------------------------

/// One row per newly claimed extension: the file name, its bytes, the token
/// the adapter has to surface, the adapter `--json` must name, and whether
/// the hit has to come from *inside* a container rather than from it.
///
/// Two rows name an adapter other than the newest claimant on purpose.
/// `page.tif` is single-page, and the single-page EXIF reader is registered
/// first and has the richer output; the multipage handoff is what the two
/// dedicated tests below cover. `a.mp4` is answered by the media crate's
/// `VideoTags`, which `rgx-adapters-inspect` is registered after.
/// A Firebird header page: one page, ODS 11.2, page size 4096.
///
/// Built at the documented offsets rather than as a literal, because the
/// offsets are the thing being asserted. The two fields the token depends on
/// are `hdr_ods_version` at 18 (the major ANDed with 0x8000) and
/// `hdr_ods_minor` at 62 (a separate word entirely).
fn fdb() -> Vec<u8> {
    let mut p = vec![0u8; 4096];
    p[0] = 1; // pag_header
    p[2..4].copy_from_slice(&12345u16.to_le_bytes()); // the constant "checksum"
    p[16..18].copy_from_slice(&4096u16.to_le_bytes()); // hdr_page_size
    p[18..20].copy_from_slice(&(0x8000u16 | 11).to_le_bytes()); // ODS 11
    p[20..24].copy_from_slice(&3u32.to_le_bytes()); // hdr_PAGES
    p[42..44].copy_from_slice(&0x0100u16.to_le_bytes()); // hdr_flags: SQLDialect3
    p[60..62].copy_from_slice(&1u16.to_le_bytes()); // hdr_implementation
    p[62..64].copy_from_slice(&2u16.to_le_bytes()); // hdr_ods_minor
    p
}

/// A 64-bit LMDB `MDB_meta` at the documented offsets, plus a page of
/// text standing in for what a leaf page would hold.
///
/// The offsets come from liblmdb's `mdb.c`: magic at 0, version at 4,
/// `mm_mapsize` at 16 (8 bytes, because `mm_address` before it is a
/// pointer), the page size at 24 through `mm_dbs[0].md_pad`, the main
/// database at 64 because `sizeof(MDB_db)` is 40, `mm_last_pg` at 104 and
/// `mm_txnid` at 112.
fn lmdb_env(payload: &[u8]) -> Vec<u8> {
    const PAGE: usize = 4096;
    let mut v = vec![0u8; PAGE];
    v[0..4].copy_from_slice(&0xBEEF_C0DEu32.to_le_bytes());
    v[4..8].copy_from_slice(&1u32.to_le_bytes());
    v[16..24].copy_from_slice(&(PAGE as u64).to_le_bytes()); // mm_mapsize
    v[24..28].copy_from_slice(&(PAGE as u32).to_le_bytes()); // mm_psize
    v[70..72].copy_from_slice(&2u16.to_le_bytes()); // main db depth
    v[96..104].copy_from_slice(&7u64.to_le_bytes()); // main db entries
    v[104..112].copy_from_slice(&4u64.to_le_bytes()); // mm_last_pg
    v[112..120].copy_from_slice(&99u64.to_le_bytes()); // mm_txnid
    v[120..120 + payload.len()].copy_from_slice(payload);
    v
}

/// A Visual FoxPro database container, which is a dBase table whose header
/// byte 28 carries bit 3 (`0x04`) — the "this file is a .dbc" flag.
///
/// The rows are the container's metadata: the tables, views and stored
/// procedures it binds together. The rows of those tables live in their own
/// `.dbf` files.
fn dbc_container() -> Vec<u8> {
    const NAMES: [&str; 2] = ["TYPE", "NAME"];
    const LENS: [usize; 2] = [10, 24];
    let rows: [(&str, &str); 2] = [("Table", "RGXDBCTABLE"), ("View", "RGXDBVIEW")];
    let record_len = 1 + LENS.iter().sum::<usize>();
    let header_size = 32 + 32 * NAMES.len() + 1 + 263;

    let mut v = vec![0u8; header_size];
    v[0] = 0x30; // the Visual FoxPro signature byte
    v[1..4].copy_from_slice(&[26, 10, 18]);
    v[4..8].copy_from_slice(&(rows.len() as u32).to_le_bytes());
    v[8..10].copy_from_slice(&(header_size as u16).to_le_bytes());
    v[10..12].copy_from_slice(&(record_len as u16).to_le_bytes());
    v[28] = 0x04; // bit 3: this file is a database container
    for (i, name) in NAMES.iter().enumerate() {
        let p = 32 + 32 * i;
        v[p..p + name.len()].copy_from_slice(name.as_bytes());
        v[p + 11] = b'C';
        v[p + 16] = LENS[i] as u8;
    }
    v[32 + 32 * NAMES.len()] = 0x0d; // header terminator

    for (kind, name) in rows {
        let mut rec = vec![b' '];
        for (i, value) in [kind, name].iter().enumerate() {
            let bytes = value.as_bytes();
            let mut f = vec![b' '; LENS[i]];
            let n = bytes.len().min(LENS[i]);
            f[..n].copy_from_slice(&bytes[..n]);
            rec.extend_from_slice(&f);
        }
        v.extend_from_slice(&rec);
    }
    v.push(0x1a); // EOF marker
    v
}

/// One RESP command: the array header, then each argument as a bulk string.
fn resp(args: &[&[u8]]) -> Vec<u8> {
    let mut v = format!("*{}\r\n", args.len()).into_bytes();
    for a in args {
        v.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        v.extend_from_slice(a);
        v.extend_from_slice(b"\r\n");
    }
    v
}

/// A Redis 7 AOF in its default shape: `aof-use-rdb-preamble` is on, so the
/// file opens with an RDB snapshot — a key that appears nowhere else, since a
/// rewrite folds everything written before it into the preamble — and the
/// command log starts after the CRC64 `rdbchecksum yes` appends.
fn aof_with_preamble(log: &[u8]) -> Vec<u8> {
    const KEY: &[u8] = b"RGXSNAPKEY1";
    const VAL: &[u8] = b"RGXSNAPVAL";
    let mut v = b"REDIS0011".to_vec();
    v.extend_from_slice(&[254, 0]); // OP_SELECTDB, db 0
    v.push(0); // OP_STRING
               // The length prefix is taken from the bytes, never typed by hand: a
               // disagreement here fails inside the string reader and reads as a defect
               // in the adapter rather than in the fixture.
    v.push(KEY.len() as u8); // length-encoded below 64 is one byte
    v.extend_from_slice(KEY);
    v.push(VAL.len() as u8);
    v.extend_from_slice(VAL);
    v.push(255); // OP_EOF
    v.extend_from_slice(&[0u8; 8]); // the checksum
    v.extend_from_slice(log);
    v
}

/// A LevelDB sorted table: one data block, an index naming it, and the
/// 48-byte footer whose last eight bytes carry the magic the reader routes
/// on. The block checksums are not verified by the reader, so this needs no
/// CRC -- what it proves is that `.ldb` reaches the adapter at all.
fn leveldb_table() -> Vec<u8> {
    fn varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            out.push(b | if v != 0 { 0x80 } else { 0 });
            if v == 0 {
                return;
            }
        }
    }
    // One restart per entry, so the entry bodies share no prefix and the
    // fixture carries no prefix-compression arithmetic.
    fn block(rows: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (k, v) in rows {
            varint(&mut body, 0); // no shared prefix
            varint(&mut body, k.len() as u64);
            varint(&mut body, v.len() as u64);
            body.extend_from_slice(k);
            body.extend_from_slice(v);
        }
        for i in 0..rows.len() {
            // Restart offsets are not consulted by this reader, but the
            // count at the end is: without it the block has no length.
            body.extend_from_slice(&0u32.to_le_bytes());
            let _ = i;
        }
        body.extend_from_slice(&(rows.len() as u32).to_le_bytes());
        body.push(0); // not compressed
                      // The five-byte trailer: the compression type and a masked
                      // CRC-32C of the type and the data, the way the store writes it.
        let split = body.len() - 1;
        let crc = crc32c(&[&body[..split], &body[split..]])
            .rotate_right(15)
            .wrapping_add(0xa282_ead8);
        body.extend_from_slice(&crc.to_le_bytes());
        body
    }

    /// CRC-32C (Castagnoli), the polynomial LevelDB and RocksDB use.
    fn crc32c(parts: &[&[u8]]) -> u32 {
        let mut crc = !0u32;
        for chunk in parts.iter().copied() {
            for &b in chunk {
                crc ^= u32::from(b);
                for _ in 0..8 {
                    let mask = 0u32.wrapping_sub(crc & 1);
                    crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
                }
            }
        }
        !crc
    }

    let rows: Vec<(&[u8], &[u8])> = vec![
        (b"user:1", b"RGX-LEVELDB-ALADDIN"),
        (b"user:2", b"senha-do-usuario"),
    ];
    let data = block(&rows);
    let mut file = data.clone();
    let mut handle = Vec::new();
    varint(&mut handle, 0);
    varint(&mut handle, data.len() as u64);
    let index_off = file.len();
    file.extend(block(&[(b"user:2", &handle)]));
    let index_size = file.len() - index_off;

    let mut footer = Vec::new();
    varint(&mut footer, index_off as u64);
    varint(&mut footer, index_size as u64);
    varint(&mut footer, 0); // metaindex
    varint(&mut footer, 0);
    while footer.len() < 40 {
        footer.push(0);
    }
    footer.extend_from_slice(&0xdb47_7524_8b80_fb57u64.to_le_bytes());
    file.extend_from_slice(&footer);
    file
}

fn claims() -> Vec<(&'static str, Vec<u8>, &'static str, &'static str, bool)> {
    vec![
        (
            "page.tif",
            tiff(b"RGX FIXTURE CAPTION"),
            "CAPTION",
            "tiff",
            false,
        ),
        ("a.djvu", djvu(), "single-page", "djvu", false),
        ("a.hwp", compound(), "compound", "ole2-compound", false),
        // `.rvt` is deliberately absent: the minimal compound file here is
        // good enough for `Compound` and not for the Revit reader, which
        // wants a directory with named streams. Asserting the routing with a
        // fixture the adapter declines would only pin the fall-through.
        // `Rvt` is covered by its own unit tests.
        (
            "a.bplist",
            bplist("RGXPLISTVALUE"),
            "RGXPLISTVALUE",
            "bplist",
            false,
        ),
        (
            "a.mp4",
            mp4("RGXMP4TITLE"),
            "RGXMP4TITLE",
            "videotags",
            false,
        ),
        ("a.grb2", grib2(), "Temperature", "grib", false),
        ("a.bufr", bufr(), "edition 4", "bufr", false),
        ("a.sgy", segy("C 1 LINE"), "C 1 LINE", "segy", false),
        ("a.bcf", bcf(), "VCFv4.2", "bcf", false),
        ("a.cram", cram(), "CRAM", "cram", false),
        (
            "a.bam",
            bam(b"@HD\tVN:1.6\tSO:fixture\n"),
            "fixture",
            "bam",
            false,
        ),
        ("a.dwg", dwg(), "AC1032", "dwg", false),
        ("a.x_t", x_t(), "PART1", "parasolid-xt", false),
        ("a.sab", acis(), "ACIS", "acis-sab", false),
        ("a.so", elf(), "TOOLCHAIN", "elf-provenance", false),
        // The four archives answer with `Members`, so the unit that matches is
        // the member and its path carries a `/`. Expecting the container's
        // adapter name here would be asking for a unit that does not exist.
        (
            "a.gem",
            zip_with("metadata", b"RGXGEMMARKER"),
            "RGXGEMMARKER",
            "raw",
            true,
        ),
        (
            "a.nupkg",
            zip_with("a.nuspec", b"RGXNUPKGMARKER"),
            "RGXNUPKGMARKER",
            "raw",
            true,
        ),
        (
            "a.crate",
            zip_with("vcs.json", b"RGXCRATEMARKER"),
            "RGXCRATEMARKER",
            "raw",
            true,
        ),
        (
            "a.e57",
            zip_with(
                "header.xml",
                b"<e57><scanName>RGXE57MARKER</scanName></e57>",
            ),
            "RGXE57MARKER",
            "raw",
            true,
        ),
        // Firebird: the report carries "11.2" only if the ODS major is masked
        // off its 0x8000 Firebird flag and the minor is read from its own
        // field 44 bytes later, which is the whole point of the reader.
        ("a.fdb", fdb(), "ods: 11.2", "firebird", false),
        // `.sxw` is the StarOffice 6/7 generation: OLE2, not the ZIP package
        // everything StarOffice wrote afterwards. Same reader as `.hwp`.
        ("a.sxw", compound(), "compound", "ole2-compound", false),
        // UOF is "XML contained in a compressed file container, similar to
        // OpenDocument and Office Open XML" — a ZIP, so the hit is in a member.
        (
            "a.uof",
            zip_with("contents.xml", b"<uof><body>RGXUOFMARKER</body></uof>"),
            "RGXUOFMARKER",
            "raw",
            true,
        ),
        // `.mdb` is claimed by two readers with disjoint magics: Jet is
        // 00 01 00 00 and LMDB is 0xBEEFC0DE. This row is the LMDB half; the
        // Access half is `access.mdb` in the dedicated test below.
        (
            "lmdb.mdb",
            lmdb_env(b"RGXLMDBKEY"),
            "RGXLMDBKEY",
            "lmdb",
            false,
        ),
        // A `.sam` that samtools wrote with --output-BGZF: `rg` over those
        // bytes finds nothing, so claiming the extension makes rgx a
        // superset rather than a subset. The plain-text half is the other
        // way round and is held down by the dedicated test below.
        (
            "aln.sam",
            bgzf(SAM_TEXT.as_bytes()),
            "RGXSAMREAD",
            "sam",
            false,
        ),
        // A Visual FoxPro database container IS a dBase table with a
        // different extension, so the dbf reader answers it and the rows are
        // the container's own metadata -- the tables it binds together.
        ("sales.dbc", dbc_container(), "RGXDBCTABLE", "dbf", false),
        // Redis AOF, in the shape Redis 7 writes by default: the RDB preamble
        // first, the command log after it. Both halves are claimed here
        // because a rewrite folds the pre-existing keys into the preamble --
        // a row that only searched the log would pass on a reader that threw
        // the snapshot away, and those keys are then unsearchable.
        (
            "appendonly.aof",
            aof_with_preamble(&resp(&[b"SET", b"rgx:aof:live", b"RGXAOFCOMMAND"])),
            "RGXAOFCOMMAND",
            "redis-aof",
            false,
        ),
        (
            "appendonly.aof",
            aof_with_preamble(&resp(&[b"SET", b"rgx:aof:live", b"RGXAOFCOMMAND"])),
            "RGXSNAPKEY1",
            "redis-aof",
            false,
        ),
        // The older single-file shape, with no snapshot in front of it.
        (
            "legacy.aof",
            resp(&[b"SET", b"rgx:aof:plain", b"RGXAOFPLAIN"]),
            "RGXAOFPLAIN",
            "redis-aof",
            false,
        ),
        // LevelDB and RocksDB. The reader routes on the footer magic rather
        // than the extension, so a `.ldb` that is not a table is left alone
        // instead of being read as one.
        (
            "store.ldb",
            leveldb_table(),
            "RGX-LEVELDB-ALADDIN",
            "leveldb",
            false,
        ),
    ]
}

fn djvu() -> Vec<u8> {
    let info = {
        let mut body = vec![0u8; 8];
        body[0..2].copy_from_slice(&1000u16.to_le_bytes());
        body[2..4].copy_from_slice(&1400u16.to_le_bytes());
        let mut c = b"INFO".to_vec();
        c.push(body.len() as u8);
        c.extend_from_slice(&[0, 0]);
        c.extend_from_slice(&body);
        c
    };
    let mut page = b"DJVU".to_vec();
    page.push(8);
    page.extend_from_slice(&[0, 0]);
    page.extend_from_slice(&[0u8; 8]);
    let mut f = b"AT&TFORM".to_vec();
    f.extend_from_slice(&1000u32.to_be_bytes());
    f.extend_from_slice(&page);
    f.extend_from_slice(&info);
    f
}

#[test]
fn every_new_extension_reaches_the_adapter_that_claims_it() {
    let dir = scratch("claims");
    for (name, bytes, _, _, _) in claims() {
        std::fs::write(dir.join(name), bytes).unwrap();
    }

    let mut wrong = Vec::new();
    for (name, _, token, want, from_member) in claims() {
        let (got, member) = hits_in(&dir, token, name);
        assert!(
            !got.is_empty(),
            "{name}: nothing matched {token:?} — the adapter never surfaced its text"
        );
        if !got.iter().all(|a| a == want) {
            wrong.push(format!(
                "{name}: wanted {want}, --json said {}",
                got.join("+")
            ));
        }
        if from_member && !member {
            wrong.push(format!(
                "{name}: the hit came from the container, not from a member inside it"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "claim routing is wrong:\n{}",
        wrong.join("\n")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_multipage_tiff_reports_a_page_the_single_page_reader_never_opens() {
    // The claim here is about the *handoff*: `rgx-adapters-media` reads IFD0
    // only and used to answer multipage TIFFs with page 1 and no warning, so
    // a caption written on page 2 was simply not in the output. The media
    // adapter now declines and this one walks the chain.
    let dir = scratch("tifpages");
    let mut out = b"II\x2a\x00".to_vec();
    out.extend_from_slice(&le32(8));
    let text = b"RGXSECONDPAGECAPTION";
    // IFD0 has geometry only; its link points at the IFD holding the caption.
    let first = ifd(&[(256, 4, 1, 800), (257, 4, 1, 600)], 0);
    let first_len = first.len();
    out.extend_from_slice(&first);
    let second_at = out.len() as u32;
    let second = ifd(
        &[
            (256, 4, 1, 400),
            (257, 4, 1, 300),
            (270, 2, text.len() as u32, 0),
        ],
        0,
    );
    // Patch IFD0's next pointer now that page 2's position is known.
    out[8 + 2 + 2 * 12..8 + 2 + 2 * 12 + 4].copy_from_slice(&second_at.to_le_bytes());
    out.extend_from_slice(&second);
    let str_at = out.len() as u32;
    out.extend_from_slice(text);
    // The value slot is only addressable once the IFD is in the buffer.
    let slot = (second_at as usize) + 2 + 2 * 12 + 8;
    out[slot..slot + 4].copy_from_slice(&str_at.to_le_bytes());
    assert_eq!(first_len, 2 + 2 * 12 + 4);

    std::fs::write(dir.join("scan.tif"), out).unwrap();
    let (named, _) = hits_in(&dir, "SECONDPAGECAPTION", "scan.tif");
    assert_eq!(named, vec!["tiff-pages".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_multipage_tiff_lists_both_pages() {
    let dir = scratch("tifpages2");
    let mut out = b"II\x2a\x00".to_vec();
    out.extend_from_slice(&le32(8));
    out.extend_from_slice(&ifd(&[(256, 4, 1, 800), (257, 4, 1, 600)], 0));
    let second_at = out.len() as u32;
    let second = ifd(&[(256, 4, 1, 400), (257, 4, 1, 300)], 0);
    out[8 + 2 + 2 * 12..8 + 2 + 2 * 12 + 4].copy_from_slice(&second_at.to_le_bytes());
    out.extend_from_slice(&second);
    std::fs::write(dir.join("scan.tif"), out).unwrap();

    let stdout = rgx()
        .args(["--no-heading", "pages:"])
        .arg(&dir)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&stdout.stdout).into_owned();
    assert!(text.contains("pages: 2"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of the `.mdb` collision, and the reason it is not a gap.
///
/// LMDB and Microsoft Access both claim the extension, and they are told
/// apart by four bytes rather than by registration order: Jet is
/// `00 01 00 00` at offset 0, LMDB is `0xBEEFC0DE`. Neither magic is a
/// prefix of the other, so whichever reader runs first refuses the file
/// belonging to the other and the second one answers.
///
/// Testing one file per format is what makes this claim falsifiable. An
/// adapter that accepted both, or neither, would pass the routing row above
/// and fail here.
#[test]
fn an_mdb_extension_is_answered_by_whichever_magic_the_file_carries() {
    let dir = scratch("mdbcollision");

    // Access: `00 01 00 00`, then the page size at 0x14 where the Jet
    // header keeps it, and a printable row value on a DATA page -- the Jet
    // reader skips the first page on purpose, so a row in the header would
    // prove nothing.
    let mut jet = vec![0u8; 8192];
    jet[0] = 0x00;
    jet[1] = 0x01;
    jet[4..8].copy_from_slice(&1u32.to_le_bytes()); // Jet 4.x
    jet[0x14..0x16].copy_from_slice(&2048u16.to_le_bytes());
    let row = b"RGXJETROWVALUE\x00\x00\x00";
    jet[3000..3000 + row.len()].copy_from_slice(row);
    std::fs::write(dir.join("access.mdb"), &jet).unwrap();

    // LMDB: `BEEFC0DE` and a page size in the DATA file, which is the claim
    // that made this readable at all.
    std::fs::write(dir.join("env.mdb"), lmdb_env(b"\x00RGXLMDBROWVALUE\x00")).unwrap();

    let adapter_for = |file: &str, token: &str| -> String {
        let out = rgx()
            .args(["-F", "--json", token])
            .arg(dir.join(file))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        for line in text.lines().filter(|l| l.contains("\"adapter\"")) {
            if let Some(rest) = line.split("\"adapter\":\"").nth(1) {
                return rest.split('"').next().unwrap_or_default().to_string();
            }
        }
        panic!("{file}: nothing matched {token:?}; --json said:\n{text}");
    };

    assert_eq!(adapter_for("access.mdb", "RGXJETROWVALUE"), "mdb");
    assert_eq!(adapter_for("env.mdb", "RGXLMDBROWVALUE"), "lmdb");

    // And the LMDB header itself is reported, not merely accepted. Each
    // pattern is searched separately: grep prints only the lines that
    // match, so one pattern cannot show what another line said.
    let report_has = |token: &str| -> String {
        let out = rgx()
            .args(["-F", token])
            .arg(dir.join("env.mdb"))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    assert!(report_has("page size:").contains("4096"), "mm_psize");
    let entries = report_has("entries");
    assert!(entries.contains("7 entries"), "main db record: {entries}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The `.sam` claim is only true for one of its two shapes, so both are
/// tested through the real binary.
///
/// A plain `.sam` is text `rg` already reads. An adapter that answered for
/// it would replace lines that ripgrep matches with something else, which
/// is the subset property the whole crate is built to avoid — so the
/// adapter declines it and the raw path searches it, and `--json` reports
/// `raw`. A `.sam` written by `samtools view --output-BGZF` is a container
/// whose records exist nowhere in its bytes; there the adapter inflates it
/// and reports `sam`. Testing one without the other would let either half
/// regress while the test still passed.
#[test]
fn a_plain_sam_stays_raw_and_a_bgzf_sam_is_inflated() {
    let dir = scratch("samtextvsbgzf");

    std::fs::write(dir.join("plain.sam"), SAM_TEXT).unwrap();
    std::fs::write(dir.join("aln.sam"), bgzf(SAM_TEXT.as_bytes())).unwrap();

    let adapter_for = |file: &str| -> String {
        let out = rgx()
            .args(["-F", "--json", "RGXSAMREAD"])
            .arg(dir.join(file))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            text.contains("RGXSAMREAD"),
            "{file}: the record must be findable at all:\n{text}"
        );
        for line in text.lines().filter(|l| l.contains("\"adapter\"")) {
            if let Some(rest) = line.split("\"adapter\":\"").nth(1) {
                return rest.split('"').next().unwrap_or_default().to_string();
            }
        }
        panic!("{file}: no adapter reported:\n{text}");
    };

    // The control: ripgrep reads the plain file, and so must rgx.
    let out = rgx()
        .args(["-F"])
        .arg("RGXSAMREAD")
        .arg(dir.join("plain.sam"))
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("RGXSAMREAD"),
        "the plain file's own line must still be reported"
    );
    assert_eq!(
        adapter_for("plain.sam"),
        "raw",
        "text is not the adapter's job"
    );
    assert_eq!(
        adapter_for("aln.sam"),
        "sam",
        "compressed records are invisible to rg and are the adapter's job"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
