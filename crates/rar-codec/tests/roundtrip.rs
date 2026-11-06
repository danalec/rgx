// SPDX-License-Identifier: Apache-2.0

//! Integration tests: writer→reader roundtrips, hand-built RAR4 fixture,
//! and malformed-input robustness (no panics, ever).

use rar_codec::{Archive, ArchiveBuilder, EntryKind, Error, Format, METHOD_STORE};

#[test]
fn roundtrip_single_file() {
    let mut w = ArchiveBuilder::new();
    w.add_stored("hello.txt", b"hi there").unwrap();
    let bytes = w.finish();

    let arc = Archive::open(&bytes).unwrap();
    assert_eq!(arc.format, Format::Rar5);
    assert_eq!(arc.entries().len(), 1);
    let e = &arc.entries()[0];
    assert_eq!(e.name, "hello.txt");
    assert_eq!(e.kind, EntryKind::File);
    assert_eq!(e.unpacked_size, 8);
    assert_eq!(e.method, 0); // RAR5: 0 = store
    assert!(!e.solid);
    assert!(!e.encrypted);
    assert_eq!(arc.extract(e).unwrap(), b"hi there");
}

#[test]
fn roundtrip_multiple_files_and_dirs() {
    let mut w = ArchiveBuilder::new();
    w.add_stored("a.txt", b"alpha").unwrap();
    w.add_directory("docs").unwrap();
    w.add_stored("docs/b.bin", &[0, 159, 255, 1, 2]).unwrap();
    w.add_stored("empty", b"").unwrap();
    let bytes = w.finish();

    let arc = Archive::open(&bytes).unwrap();
    assert_eq!(arc.entries().len(), 4);

    let a = &arc.entries()[0];
    assert_eq!(a.name, "a.txt");
    assert_eq!(arc.extract(a).unwrap(), b"alpha");

    assert_eq!(arc.entries()[1].kind, EntryKind::Directory);

    let b = &arc.entries()[2];
    assert_eq!(b.name, "docs/b.bin");
    assert_eq!(arc.extract(b).unwrap(), &[0, 159, 255, 1, 2]);

    let empty = &arc.entries()[3];
    assert_eq!(empty.unpacked_size, 0);
    assert_eq!(arc.extract(empty).unwrap(), b"");
}

#[test]
fn roundtrip_binary_payload_sizes() {
    let payload: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
    let mut w = ArchiveBuilder::new();
    w.add_stored("big/blob", &payload).unwrap();
    let bytes = w.finish();

    let arc = Archive::open(&bytes).unwrap();
    assert_eq!(arc.extract(&arc.entries()[0]).unwrap(), payload);
}

#[test]
fn header_crc_is_verified_strictly() {
    let mut w = ArchiveBuilder::new();
    w.add_stored("x", b"data").unwrap();
    let mut bytes = w.finish();
    // Flip one bit inside the first file header name.
    let pos = bytes.windows(1).position(|w| w == b"x").unwrap();
    bytes[pos] = b'y';
    let err = Archive::open(&bytes).unwrap_err();
    assert!(matches!(err, Error::BadCrc("rar5 header")), "{err}");
    // Lenient open still recovers the structure.
    let arc = Archive::open_lenient(&bytes).unwrap();
    assert_eq!(arc.entries().len(), 1);
}

#[test]
fn data_crc_is_verified_on_extract() {
    let mut w = ArchiveBuilder::new();
    w.add_stored("x", b"data").unwrap();
    let mut bytes = w.finish();
    // Corrupt the payload (near the end, inside "data").
    let pos = bytes.len() - 10;
    bytes[pos] ^= 0xFF;
    let arc = Archive::open_lenient(&bytes).unwrap();
    let err = arc.extract(&arc.entries()[0]).unwrap_err();
    assert!(matches!(err, Error::BadCrc("file data")), "{err}");
}

#[test]
fn rejects_non_rar() {
    assert!(matches!(
        Archive::open(b"PK\x03\x04 not rar"),
        Err(Error::Truncated) | Err(Error::BadMagic)
    ));
    assert_eq!(Archive::open(b"Rar!").unwrap_err(), Error::Truncated);
    assert_eq!(
        Archive::open(b"Rar!\x1a\x07\x02\x00").unwrap_err(),
        Error::BadMagic
    );
}

#[test]
fn rar4_parses_and_extracts_stored() {
    // Hand-built RAR4 fixture: marker + one stored file header + end block.
    let name = b"inner/memo.txt";
    let payload = b"rar4 stored payload";
    let hsize = 32 + name.len();
    let mut d = b"Rar!\x1a\x07\x00".to_vec();
    d.extend_from_slice(&[0; 2]); // HEAD_CRC (not verified by design)
    d.push(0x74); // file header
    d.extend_from_slice(&0x8000u16.to_le_bytes()); // LONG_BLOCK: data follows
    d.extend_from_slice(&(hsize as u16).to_le_bytes());
    d.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // pack size
    d.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // unpacked size
    d.push(3); // HOST_OS: unix
    d.extend_from_slice(&0xCBF43926u32.to_le_bytes()); // FILE_CRC (of "123456789"... replaced below)
    d.extend_from_slice(&[0; 4]); // FTIME
    d.push(0x1D); // UNP_VER 2.9
    d.push(METHOD_STORE);
    d.extend_from_slice(&(name.len() as u16).to_le_bytes());
    d.extend_from_slice(&[0; 4]); // ATTRS
    d.extend_from_slice(name);
    d.extend_from_slice(payload);
    d.extend_from_slice(&[0x45, 0x39, 0x7B, 0x00, 0x00, 0x07, 0x00]); // end block

    // Fix the file CRC to the real CRC32 of the payload.
    let crc = {
        let mut c = 0xFFFF_FFFFu32;
        for &b in payload {
            // IEEE crc32 via the crate's own function would be private; recompute inline
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
        }
        c ^ 0xFFFF_FFFF
    };
    let crc_pos = 7 + 2 + 1 + 2 + 2 + 4 + 4 + 1;
    d[crc_pos..crc_pos + 4].copy_from_slice(&crc.to_le_bytes());

    let arc = Archive::open(&d).unwrap();
    assert_eq!(arc.format, Format::Rar4);
    assert_eq!(arc.entries().len(), 1);
    let e = &arc.entries()[0];
    assert_eq!(e.name, "inner/memo.txt");
    assert_eq!(e.method, METHOD_STORE);
    assert_eq!(arc.extract(e).unwrap(), payload);
}

#[test]
fn never_panics_on_mutations() {
    let mut w = ArchiveBuilder::new();
    w.add_stored("dir/file.txt", b"some content here").unwrap();
    w.add_stored("other", &[7; 33]).unwrap();
    let good = w.finish();

    // Every single-byte truncation must error, not panic.
    for len in 0..good.len() {
        let _ = Archive::open(&good[..len]);
        let _ = Archive::open_lenient(&good[..len]);
    }

    // Every single-byte mutation (a few strides to keep the test fast) must
    // not panic either.
    for i in (0..good.len()).step_by(3) {
        for delta in [1u8, 0x80, 0xFF] {
            let mut m = good.clone();
            m[i] = m[i].wrapping_add(delta);
            if let Ok(arc) = Archive::open_lenient(&m) {
                for e in arc.entries() {
                    let _ = arc.extract(e);
                }
            }
        }
    }
}
