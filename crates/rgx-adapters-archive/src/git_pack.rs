// SPDX-License-Identifier: Apache-2.0

//! Git packfile (.pack) adapter.
//!
//! Indexes and extracts Git objects (blobs, commits, tags) from Git packfiles.
//! Git pack format specification:
//! - 4-byte signature: 'PACK' (0x5041434B)
//! - 4-byte version: 2 (0x00000002)
//! - 4-byte number of objects (big-endian)
//! - Object entries:
//!   - Variable-length type and size header
//!   - Compressed zlib deflate stream
//! - 20-byte SHA-1 checksum at the end

use crate::budget::MemberSink;
use alloc::format;
use rgx_core::compress::zlib::ZlibDecoder;
use rgx_core::{bail, decline, Adapter, Outcome, Result};

pub struct GitPack;

impl Adapter for GitPack {
    fn name(&self) -> &'static str {
        "git-pack"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["pack"]
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 12 || &data[..4] != b"PACK" {
            decline!("not a Git packfile (bad magic)");
        }

        let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if version != 2 && version != 3 {
            bail!("unsupported Git pack version: {version}");
        }

        let num_objects = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let mut pos = 12usize;
        let mut sink = MemberSink::new();
        let zlib = ZlibDecoder::new();

        for i in 0..num_objects {
            if pos >= data.len().saturating_sub(20) {
                break;
            }

            let b = data[pos];
            pos += 1;
            let obj_type = (b >> 4) & 0x07;
            let mut _size = (b & 0x0F) as u64;
            let mut shift = 4;
            let mut more = (b & 0x80) != 0;

            while more && pos < data.len().saturating_sub(20) {
                let next = data[pos];
                pos += 1;
                // `shift` grew 7 per byte with no cap, so ten continuation
                // bytes pushed it to 67 and `<< shift` overflowed: a panic in
                // debug, a masked shift in release. A pack object size is a
                // u64 at most, so 63 bits is the widest a contribution can be;
                // past that the encoding is malformed and the extra bytes are
                // consumed but contribute nothing.
                if shift < 64 {
                    _size |= ((next & 0x7F) as u64) << shift;
                }
                shift += 7;
                more = (next & 0x80) != 0;
            }

            match obj_type {
                1..=4 => match zlib.decode_bounded_with_consumed(&data[pos..], 1 << 24) {
                    Ok((decompressed, consumed)) => {
                        pos += consumed;
                        if (obj_type == 1 || obj_type == 3 || obj_type == 4)
                            && !decompressed.bytes.is_empty()
                        {
                            let prefix = match obj_type {
                                1 => "commit",
                                3 => "blob",
                                4 => "tag",
                                _ => "obj",
                            };
                            let name = format!("{prefix}_{i:05}");
                            if !sink.reserve(decompressed.bytes.len() as u64)
                                || !sink.push(name, decompressed.bytes)
                            {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                },
                6 => {
                    if pos >= data.len() {
                        break;
                    }
                    let mut b = data[pos];
                    pos += 1;
                    while (b & 0x80) != 0 && pos < data.len() {
                        b = data[pos];
                        pos += 1;
                    }
                    match zlib.decode_bounded_with_consumed(&data[pos..], 1 << 24) {
                        Ok((_, consumed)) => {
                            pos += consumed;
                        }
                        Err(_) => break,
                    }
                }
                7 => {
                    if pos + 20 > data.len() {
                        break;
                    }
                    pos += 20;
                    match zlib.decode_bounded_with_consumed(&data[pos..], 1 << 24) {
                        Ok((_, consumed)) => {
                            pos += consumed;
                        }
                        Err(_) => break,
                    }
                }
                _ => break,
            }
        }

        Ok(Outcome::Members(sink.finish()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use rgx_core::compress::zlib::ZlibEncoder;

    #[test]
    fn extracts_blob_from_pack() {
        let content = b"hello git blob content\n";
        let compressed = ZlibEncoder::new().encode(content);

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes()); // version 2
        pack.extend_from_slice(&1u32.to_be_bytes()); // 1 object

        // OBJ_BLOB = 3
        let size = content.len();
        let hdr_byte = (3 << 4) | ((size as u8) & 0x0F);
        if size > 15 {
            pack.push(hdr_byte | 0x80);
            pack.push((size >> 4) as u8);
        } else {
            pack.push(hdr_byte);
        }
        pack.extend_from_slice(&compressed);
        // 20-byte dummy trailer
        pack.extend_from_slice(&[0u8; 20]);

        let outcome = GitPack.extract(&pack, "test.pack").unwrap();
        match outcome {
            Outcome::Members(m) => {
                assert_eq!(m.len(), 1);
                assert_eq!(m[0].0, "blob_00000");
                assert_eq!(m[0].1, content);
            }
            _ => panic!("expected Members outcome"),
        }
    }

    #[test]
    fn rejects_non_pack() {
        assert!(GitPack.extract(b"not a pack", "test.pack").is_err());
    }
}
