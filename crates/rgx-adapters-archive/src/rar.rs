// SPDX-License-Identifier: Apache-2.0

//! RAR adapter backed by the pure-Rust `rar-codec` crate (RAR4 + RAR5).
//!
//! Members are extracted in-process and recursed into as real archive
//! members. The codec decodes stored entries, the RAR5 LZ77/Huffman method
//! (including solid groups), and the RAR 2.9/3.x LZ77/Huffman method with its
//! standard E8/E8E9, delta, RGB, audio and multibyte-translate VM filters, all
//! with CRC-32 verification; the fixtures under `testdata/rar/` hold each of
//! those down against RARLAB `UnRAR` output. Payloads the codec cannot handle
//! (encrypted, PPMd filters, arbitrary RAR VM program filters, the RAR 7.x
//! compression algorithm, and multivolume sets, which need every volume at
//! once and so do not fit the one-slice-per-file adapter contract) are
//! skipped; when nothing is extractable the adapter falls back to a header
//! listing (names + sizes), which still answers "which archive in this tree
//! holds X?".

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use core::fmt::Write as _;
use rar_codec::{Archive, EntryKind, Error as RarError};
use rgx_core::{decline, Result};
use rgx_core::{Adapter, Outcome};

use crate::budget::Stopped;

/// RAR5 store method. RAR4's is `METHOD_STORE` (0x30) but RAR4 has no
/// size-unknown flag, so 0 is the only value this check has to get right.
const RAR5_STORE: u8 = 0;

/// `.rar` extraction (stored, RAR5 LZ, RAR 2.9/3.x LZ, solid groups) with
/// listing fallback.
pub struct Rar;
impl Adapter for Rar {
    fn name(&self) -> &'static str {
        "rar"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["rar"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // Strict open first (verifies RAR5 header CRCs, catching corruption);
        // fall back to lenient parsing so damaged archives still list.
        let archive = match Archive::open(data) {
            Ok(a) => a,
            Err(RarError::BadMagic) | Err(RarError::Truncated) => decline!("not a RAR file"),
            Err(_) => Archive::open_lenient(data)?,
        };

        let mut sink = crate::budget::MemberSink::new();
        sink.declare(archive.entries().len());
        // Entries the codec declined. Kept rather than dropped: an entry that is
        // silently absent and an entry that does not exist look identical to a
        // search, and only one of them is true.
        let mut refused: Vec<(String, String)> = Vec::new();
        for e in archive.entries() {
            if e.kind != EntryKind::File {
                continue;
            }
            if !sink.reserve(e.unpacked_size) {
                break;
            }
            if e.size_unknown && e.method != RAR5_STORE {
                // RAR5 file flag 0x0008: `unpacked_size` is zeroed and the
                // codec decodes to the end of the compression stream, so the
                // `reserve` above was charged 0 and nothing bounds the
                // output. Refused rather than decoded; a stored member is
                // still fine, since its length is the packed length.
                sink.stop(Stopped::Bytes);
                continue;
            }
            match archive.extract(e) {
                Ok(bytes) => {
                    if !sink.push(e.name.to_string(), bytes) {
                        break;
                    }
                }
                Err(err) => {
                    refused.push((e.name.to_string(), format!("{err}")));
                }
            }
        }
        let mut members = sink.finish();
        if !members.is_empty() {
            if !refused.is_empty() {
                // Only worth a member when there is real content beside it;
                // if nothing extracted, the listing below already carries the
                // names, and adding a note would change the Outcome to
                // `Members` and throw the listing away. First, like
                // TRUNCATION_MEMBER, because a note nobody scrolls to is not
                // a note.
                let (name, bytes) = crate::budget::unsupported_note(&refused);
                members.insert(0, (name, bytes));
            }
            return Ok(Outcome::Members(members));
        }

        // Nothing extractable (all members compressed/encrypted): list, and
        // say which of those names this build could not decode, so the listing
        // does not read as though the entries were empty.
        let refusal_of = |name: &str| -> Option<&str> {
            refused
                .iter()
                .find(|(n, _)| n.as_str() == name)
                .map(|(_, w)| w.as_str())
        };
        let mut out =
            String::from("rar archive contents (listing only, extraction requires unrar):\n");
        let mut files = 0;
        for e in archive
            .entries()
            .iter()
            .take(crate::budget::budget().members)
        {
            if e.kind == EntryKind::Directory {
                continue;
            }
            match refusal_of(e.name.as_ref()) {
                Some(why) => {
                    let _ = writeln!(
                        out,
                        "{} ({} bytes, not decoded: {})",
                        e.name, e.unpacked_size, why
                    );
                }
                None => {
                    let _ = writeln!(out, "{} ({} bytes)", e.name, e.unpacked_size);
                }
            }
            files += 1;
        }
        if files == 0 {
            decline!("no file entries in RAR headers");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{TRUNCATION_MEMBER, UNSUPPORTED_MEMBER};
    use alloc::vec::Vec;
    use rar_codec::ArchiveBuilder;

    fn vint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            out.push(if v == 0 { b } else { b | 0x80 });
            if v == 0 {
                return;
            }
        }
    }

    /// CRC-32 (IEEE, reflected) over `data`.
    fn crc32(data: &[u8]) -> u32 {
        let mut c = 0xFFFF_FFFFu32;
        for &b in data {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    }

    /// A RAR5 archive whose file headers are `(name, fflags, method,
    /// payload)`. `ArchiveBuilder` is store-only, so a header that lies
    /// about its size has to be written here.
    fn rar5(entries: &[(&str, u64, u8, &[u8])]) -> Vec<u8> {
        let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
        let push = |out: &mut Vec<u8>, body: &[u8]| {
            let mut sized = Vec::new();
            vint(&mut sized, body.len() as u64);
            sized.extend_from_slice(body);
            out.extend_from_slice(&crc32(&sized).to_le_bytes());
            out.extend_from_slice(&sized);
        };
        push(&mut out, &[1, 0, 0]); // main header

        for (name, fflags, method, payload) in entries {
            let mut body = vec![2]; // HTYPE = file
            vint(&mut body, 0x02); // HFLAGS: data size field present
            vint(&mut body, payload.len() as u64);
            vint(&mut body, *fflags);
            // 0x0008 makes the parser discard this field entirely, so the
            // fixture states a size the codec will never use.
            let unpacked = if fflags & 0x08 != 0 {
                1024
            } else {
                payload.len() as u64
            };
            vint(&mut body, unpacked);
            vint(&mut body, 0); // attributes
            if fflags & 0x04 != 0 {
                body.extend_from_slice(&crc32(payload).to_le_bytes());
            }
            vint(&mut body, u64::from(*method) << 7); // compression info
            vint(&mut body, 1); // host OS: Unix
            vint(&mut body, name.len() as u64);
            body.extend_from_slice(name.as_bytes());
            push(&mut out, &body);
            out.extend_from_slice(payload);
        }

        push(&mut out, &[5, 0]); // end of archive
        out
    }

    /// A RAR5 member with flag 0x0008 declares no size at all: the codec
    /// hands `unpack` a `None` target and decodes until the stream ends,
    /// with no ceiling in between. It has to be refused here — `reserve`
    /// was charged the 0 the flag forces `unpacked_size` to.
    #[test]
    fn a_size_unknown_compressed_member_is_refused_with_a_note() {
        // The refusal has to be searchable, so the archive's only member
        // becomes the notice rather than an empty result.
        let alone = rar5(&[("stream_ZIRCALOY.bin", 0x08, 1, &[0u8; 32])]);
        let Outcome::Members(m) = Rar.extract(&alone, "s.rar").unwrap() else {
            panic!("expected members")
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].0, TRUNCATION_MEMBER);
        assert!(String::from_utf8_lossy(&m[0].1).contains("1 entries declared"));

        // Beside a member that does extract, the rest still comes out.
        let both = rar5(&[
            ("ok_ZIRCALORY.txt", 0x04, 0, b"plain stored bytes"),
            ("stream_ZIRCALOY.bin", 0x08, 1, &[0u8; 32]),
        ]);
        let Outcome::Members(m) = Rar.extract(&both, "s.rar").unwrap() else {
            panic!("expected members")
        };
        assert_eq!(m[0].0, TRUNCATION_MEMBER, "a refusal has to be visible");
        let note = String::from_utf8_lossy(&m[0].1);
        assert!(note.contains("truncated"), "{note}");
        assert!(note.contains("2 entries declared"), "{note}");
        assert!(note.contains("1 extracted"), "{note}");
        assert_eq!(m[1].0, "ok_ZIRCALORY.txt");
        assert_eq!(m[1].1, b"plain stored bytes");
    }

    /// A stored member with the same flag is still fine: its length is the
    /// packed length, so there is no expansion to bound.
    #[test]
    fn a_size_unknown_stored_member_still_extracts() {
        let bytes = rar5(&[("flat_ZIRCALOY.bin", 0x08, 0, b"twelve bytes")]);
        let out = Rar.extract(&bytes, "t.rar").unwrap();
        let Outcome::Members(m) = out else {
            panic!("expected members")
        };
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].0, "flat_ZIRCALOY.bin");
        assert_eq!(m[0].1, b"twelve bytes");
    }

    #[test]
    fn rar5_stored_members_are_extracted() {
        let mut w = ArchiveBuilder::new();
        w.add_stored("inner/memo_ZIRCALOY.txt", b"rar5 stored content")
            .unwrap();
        w.add_stored("photo ZIRCALOY.png", &[0x89, 0x50, 0x4E, 0x47])
            .unwrap();
        let bytes = w.finish();

        let out = Rar.extract(&bytes, "a.rar").unwrap();
        let Outcome::Members(m) = out else {
            panic!("expected members")
        };
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].0, "inner/memo_ZIRCALOY.txt");
        assert_eq!(m[0].1, b"rar5 stored content");
        assert_eq!(m[1].0, "photo ZIRCALOY.png");
    }

    #[test]
    fn rar4_lists_file_names() {
        // marker (7 bytes) + one file header + end block
        let mut d = b"Rar!\x1a\x07\x00".to_vec();
        let name = b"inner/memo_ZIRCALOY.txt";
        let hsize = 32 + name.len();
        d.extend_from_slice(&[0; 2]); // HEAD_CRC (2 bytes in RAR4)
        d.push(0x74);
        d.extend_from_slice(&0x8000u16.to_le_bytes());
        d.extend_from_slice(&(hsize as u16).to_le_bytes());
        d.extend_from_slice(&128u32.to_le_bytes()); // pack size
        d.extend_from_slice(&256u32.to_le_bytes()); // unpacked size
        d.extend_from_slice(&[0; 9]); // host os, crc, ftime
        d.extend_from_slice(&0u16.to_le_bytes()); // version
        d.extend_from_slice(&(name.len() as u16).to_le_bytes());
        d.extend_from_slice(&[0; 4]); // attrs
        d.extend_from_slice(name);
        d.extend_from_slice(&[0x39, 0x38, 0xAD, 0x12]); // data
        d.extend_from_slice(&[0x45, 0x39, 0x7B, 0x00, 0x00, 0x07, 0x00]); // end
        let out = Rar.extract(&d, "a.rar").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        // The size is still reported, and the member is now also marked as
        // undecoded rather than merely absent. Both halves matter: the first
        // is what this test was written to hold down, the second is what
        // stopped a refusal from looking like an empty file.
        assert!(s.contains("inner/memo_ZIRCALOY.txt (256 bytes"), "{s}");
        assert!(s.contains("not decoded:"), "{s}");
    }

    #[test]
    fn rar5_with_bad_header_crc_still_extracts() {
        // Corrupt the main header CRC (bytes 8..12): strict open rejects,
        // lenient fallback recovers the members.
        let mut w = ArchiveBuilder::new();
        w.add_stored("photo ZIRCALOY.png", &[1, 2, 3]).unwrap();
        let mut d = w.finish();
        d[8..12].fill(0xAA);
        let out = Rar.extract(&d, "b.rar").unwrap();
        let Outcome::Members(m) = out else {
            panic!("expected members")
        };
        assert_eq!(m[0].0, "photo ZIRCALOY.png");
    }

    #[test]
    fn compressed_payload_falls_back_to_listing() {
        // A RAR4 member with a compressed method byte: extraction is
        // unsupported, so the adapter falls back to listing names + sizes.
        let mut d = b"Rar!\x1a\x07\x00".to_vec();
        let name = b"only_ZIRCALOY.bin";
        let hsize = 32 + name.len();
        d.extend_from_slice(&[0; 2]); // HEAD_CRC
        d.push(0x74);
        d.extend_from_slice(&0x8000u16.to_le_bytes());
        d.extend_from_slice(&(hsize as u16).to_le_bytes());
        d.extend_from_slice(&4u32.to_le_bytes()); // pack size
        d.extend_from_slice(&64u32.to_le_bytes()); // unpacked size
        d.extend_from_slice(&[0; 9]); // host os, crc, ftime
        d.extend_from_slice(&[0u8, 0x35]); // version, method (compressed)
        d.extend_from_slice(&(name.len() as u16).to_le_bytes());
        d.extend_from_slice(&[0; 4]); // attrs
        d.extend_from_slice(name);
        d.extend_from_slice(&[0x39, 0x38, 0xAD, 0x12]); // data
        d.extend_from_slice(&[0x45, 0x39, 0x7B, 0x00, 0x00, 0x07, 0x00]); // end
        let out = Rar.extract(&d, "c.rar").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("only_ZIRCALOY.bin (64 bytes"), "{s}");
        assert!(s.contains("not decoded:"), "{s}");
    }

    /// A member the codec declines is **named in the output**, not dropped.
    /// The contract: an archive with one readable member and one
    /// undecodable member comes back as a two-member archive with the
    /// refusal named first, so a search that found something in the
    /// readable one does not read like "this file has no match inside
    /// it".
    #[test]
    fn a_member_the_codec_refuses_is_named_rather_than_dropped() {
        // One RAR4 member that extracts, beside one whose method byte the
        // codec cannot handle. The compressed one fails; the stored one does
        // not, which is what makes the difference between the two outcomes
        // observable at all.
        let stored = rar5(&[("plain_ZIRCALOY.txt", 0x04, 0, b"readable bytes")]);
        let refused = rar5(&[
            ("ok_ZIRCALOY.txt", 0x04, 0, b"readable bytes"),
            ("bad_ZIRCALOY.bin", 0x04, 0x35, &[0u8; 16]),
        ]);

        // Baseline: the readable archive yields its one member, no note.
        let Outcome::Members(ok_only) = Rar.extract(&stored, "a.rar").unwrap() else {
            panic!("expected members")
        };
        assert_eq!(ok_only.len(), 1);
        assert!(
            !ok_only.iter().any(|(n, _)| n == UNSUPPORTED_MEMBER),
            "nothing was refused, so nothing should be announced"
        );

        // The refusal must appear as a member, first, naming the entry.
        let Outcome::Members(both) = Rar.extract(&refused, "b.rar").unwrap() else {
            panic!("expected members")
        };
        assert_eq!(both[0].0, UNSUPPORTED_MEMBER, "the note has to lead");
        let note = String::from_utf8_lossy(&both[0].1);
        assert!(
            note.contains("bad_ZIRCALOY.bin"),
            "note must name it: {note}"
        );
        assert!(note.contains("could not be decoded"), "{note}");
        assert!(note.contains("absent from the search, not empty"), "{note}");
        // And the readable member is still there, after the note.
        assert!(
            both.iter().any(|(n, _)| n == "ok_ZIRCALOY.txt"),
            "a refusal must not cost a readable member: {both:?}"
        );
    }

    /// When *everything* is refused there is no content for a note member to
    /// sit beside, so the note goes into the names-and-sizes listing instead.
    /// Returning `Members` with only a note would throw the listing away, and
    /// the listing is the more useful of the two.
    #[test]
    fn a_fully_refused_archive_annotates_its_listing() {
        let bytes = rar5(&[("bad_ZIRCALOY.bin", 0x04, 0x35, &[0u8; 16])]);
        let out = Rar.extract(&bytes, "c.rar").unwrap();
        let Outcome::Text(t) = out else {
            panic!("expected the listing fallback, not members")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("bad_ZIRCALOY.bin"), "{s}");
        assert!(
            s.contains("not decoded:"),
            "the reason must be visible: {s}"
        );
    }

    #[test]
    fn rejects_non_rar() {
        assert!(Rar.extract(b"PK\x03\x04 zip", "x.rar").is_err());
    }

    // ------------------------------------------------------- real archives
    //
    // Everything above builds its bytes by hand, which proves the container
    // parser agrees with itself. These are RARLAB-produced archives whose
    // members were extracted with UnRAR and kept as `.expected`, so they
    // hold the *decoder* down against the reference implementation. See
    // `testdata/rar/README.md` for each fixture's provenance.

    /// Every member the adapter yields, as (name, bytes), order preserved.
    fn members_of(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let Outcome::Members(m) = Rar.extract(bytes, "f.rar").unwrap() else {
            panic!("expected members, got a listing")
        };
        m
    }

    /// RAR 1.5, `METHOD=0x30`. The old copy gated the RAR4 data offset on
    /// `LHD` bit `0x8000` — a bit RAR4 does not define — so this member
    /// resolved to "entry has no data area" and the adapter listed names
    /// instead of content.
    #[test]
    fn rar4_stored_member_is_extracted_byte_for_byte() {
        let m = members_of(include_bytes!("../testdata/rar/rar4-store.rar"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].0, "tiny.bin");
        assert_eq!(
            m[0].1,
            include_bytes!("../testdata/rar/rar4-store.expected")
        );
    }

    /// RAR 2.9/3.x, `METHOD=0x33` — the path that used to answer
    /// `Unsupported("RAR4 compressed payload ... needs the rar3 decoder")`.
    #[test]
    fn rar4_lz29_compressed_member_is_extracted_byte_for_byte() {
        let m = members_of(include_bytes!("../testdata/rar/rar4-lz29.rar"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].0, "small.bin");
        assert_eq!(m[0].1, include_bytes!("../testdata/rar/rar4-lz29.expected"));
    }

    /// RAR 2.9/3.x with the E8/E8E9 VM filter over a 491 KB payload. The
    /// member is too big to keep a copy of, so the assertion is the length
    /// plus the CRC-32 RARLAB reports for it (0xa6f35521, cross-checked with
    /// `UnRAR lt` and with `UnRAR x` on the same archive).
    #[test]
    fn rar4_lz29_with_the_e8e9_filter_is_extracted() {
        let m = members_of(include_bytes!("../testdata/rar/rar4-lz29-e8e9.rar"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].0, "app.log");
        assert_eq!(m[0].1.len(), 491_258);
        assert_eq!(crc32(&m[0].1), 0xA6F3_5521);
    }

    /// RAR5 store, written by RARLAB rather than by this crate's own
    /// `ArchiveBuilder` — the writer and the reader agree on the container.
    #[test]
    fn rar5_store_from_rarlab_is_extracted_byte_for_byte() {
        let m = members_of(include_bytes!("../testdata/rar/rar5-store.rar"));
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].0, "note.txt");
        assert_eq!(m[0].1, include_bytes!("../testdata/rar/rar5-note.expected"));
        assert_eq!(m[1].0, "body.txt");
        assert_eq!(m[1].1, include_bytes!("../testdata/rar/rar5-body.expected"));
    }

    #[test]
    fn rar5_lz_members_are_extracted_byte_for_byte() {
        let m = members_of(include_bytes!("../testdata/rar/rar5-lz.rar"));
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].1, include_bytes!("../testdata/rar/rar5-note.expected"));
        assert_eq!(m[1].1, include_bytes!("../testdata/rar/rar5-body.expected"));
    }

    /// A solid group: the dictionary, the Huffman tables and the distance
    /// cache carry from member to member, so `second.txt` only decodes at
    /// all if the state survived. Its bytes are identical to the same text
    /// stored non-solid, which is what makes the shared dictionary's
    /// correctness checkable rather than merely non-erroring.
    #[test]
    fn rar5_solid_members_decode_against_the_shared_dictionary() {
        let solid = members_of(include_bytes!("../testdata/rar/rar5-solid.rar"));
        let plain = members_of(include_bytes!("../testdata/rar/rar5-lz.rar"));
        assert_eq!(solid.len(), 3, "three members: {solid:?}");
        // Same order as the non-solid archive for the two shared names, so
        // the comparison lines up by position.
        assert_eq!(solid[0].0, "body.txt");
        assert_eq!(
            solid[0].1,
            include_bytes!("../testdata/rar/rar5-body.expected")
        );
        assert_eq!(solid[1].0, "note.txt");
        assert_eq!(
            solid[1].1,
            include_bytes!("../testdata/rar/rar5-note.expected")
        );
        assert_eq!(solid[2].0, "second.txt");
        assert_eq!(
            solid[2].1,
            include_bytes!("../testdata/rar/rar5-solid-second.expected")
        );
        // The body is byte-identical compressed solid and compressed
        // non-solid: the only difference is who paid for the dictionary.
        let plain_body = plain.iter().find(|(n, _)| n == "body.txt").unwrap();
        assert_eq!(&solid[0].1, &plain_body.1);
    }

    mod fuzz {
        use super::*;

        fn stored_rar5() -> Vec<u8> {
            let mut w = ArchiveBuilder::new();
            w.add_stored("dir/file_ZIRCALOY.txt", b"some content here")
                .unwrap();
            w.finish()
        }

        #[test]
        fn rar_never_panics_on_mutation() {
            // The real archives are in the corpus on purpose: the rar3
            // unpacker, the PPMd sub-decoder and the solid-group cache are
            // all stateful, and a mutation fuzzer that only ever saw a
            // 60-byte RAR5 store would never reach their error paths.
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("rar5-stored", stored_rar5()),
                    (
                        "rar4-store",
                        include_bytes!("../testdata/rar/rar4-store.rar").to_vec(),
                    ),
                    (
                        "rar4-lz29",
                        include_bytes!("../testdata/rar/rar4-lz29.rar").to_vec(),
                    ),
                    (
                        "rar4-lz29-e8e9",
                        include_bytes!("../testdata/rar/rar4-lz29-e8e9.rar").to_vec(),
                    ),
                    (
                        "rar5-solid",
                        include_bytes!("../testdata/rar/rar5-solid.rar").to_vec(),
                    ),
                    ("marker4", b"Rar!\x1a\x07\x00".to_vec()),
                    ("marker5", b"Rar!\x1a\x07\x01\x00".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "rar",
                |data| {
                    let _ = Rar.extract(data, "fuzz.rar");
                },
            );
        }
    }
}
