// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the RAR5 LZ77+Huffman decompressor.
//!
//! There is no reference encoder available in this repo, so these tests use
//! a small purpose-built *test encoder* that emits valid RAR5 compressed
//! streams (canonical Huffman tables transmitted in-band, block headers with
//! checksums, filters). Roundtripping real format data through the decoder
//! validates the port; final validation against WinRAR-produced archives
//! still needs the differential harness (see reference/README note).

// `expected.extend_from_slice(&expected[a..b])` does not compile: the
// receiver autoref is `&mut` and the argument indexes the same `Vec`, so the
// shared borrow outlives the two-phase reservation. The `.to_vec()` in those
// four lines is load-bearing, and clippy cannot see that.
#![allow(clippy::unnecessary_to_owned)]

use rar_codec::Archive;

// ---------------------------------------------------------------- bit writer

/// MSB-first bit writer, matching the RAR5 compressed stream bit order.
struct BitWriter {
    bytes: Vec<u8>,
    nbits: usize,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            bytes: Vec::new(),
            nbits: 0,
        }
    }

    fn put(&mut self, value: u32, n: u32) {
        for i in (0..n).rev() {
            let bit = ((value >> i) & 1) as u8;
            if self.nbits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if bit != 0 {
                let last = self.bytes.len() - 1;
                self.bytes[last] |= 1 << (7 - (self.nbits % 8));
            }
            self.nbits += 1;
        }
    }

    fn bit_len(&self) -> usize {
        self.nbits
    }
}

// --------------------------------------------------------- stream vocabulary
//
// Decode tables used by every test block:
//   ld  (306 symbols): all 9-bit codes, code(i) == i
//   dd  ( 64 symbols): all 9-bit codes, code(i) == i
//   ldd ( 16 symbols): all 9-bit codes (unused here)
//   rd  ( 44 symbols): all 9-bit codes, code(i) == i
//   bd  ( 20 symbols): symbol 9 -> code 0 (1 bit), symbol 17 -> code 1 (1 bit)

fn write_tables(w: &mut BitWriter) {
    // bd's own bit lengths, as nibbles (no escapes needed: values are 0/1).
    // Entry 9 = 1 (symbol 9 has length 1), entry 17 = 1 (symbol 17).
    let mut bd = [0u8; 20];
    bd[9] = 1;
    bd[17] = 1;
    for pair in 0..10 {
        w.put((bd[2 * pair] << 4 | bd[2 * pair + 1]) as u32, 8);
    }
    // The 430-entry table, coded with bd:
    //   literal 9      -> bd(0)              = 1 bit
    //   repeat-17(n)   -> bd(1) + 7 bits(n-11)
    let entries = |w: &mut BitWriter, total: usize| {
        w.put(0, 1); // first entry: 9
        let mut left = total - 1;
        while left > 0 {
            let n = left.min(138);
            w.put(1, 1); // code 17
            w.put((n - 11) as u32, 7);
            left -= n;
        }
    };
    entries(w, 306); // ld
    entries(w, 64); // dd
    entries(w, 16); // ldd
    entries(w, 44); // rd
}

// Command emitters (all ld codes are 9 bits, code(i) == i).
fn emit_literal(w: &mut BitWriter, b: u8) {
    w.put(b as u32, 9);
}

/// Match with any distance expressible in the slot encoding. The decoder
/// adds length adjustments for large distances; this encoder accounts for
/// them.
fn emit_match(w: &mut BitWriter, len: usize, dist: usize) {
    assert!(len >= 2);
    // distance slot
    let (slot, dbits, dextra) = if dist <= 4 {
        (dist - 1, 0, 0)
    } else {
        let mut found = None;
        for slot in 4..64usize {
            let dbits = slot / 2 - 1;
            let base = 1 + ((2 | (slot & 1)) << dbits);
            if dist < base + (1usize << dbits) {
                found = Some((slot, dbits, dist - base));
                break;
            }
        }
        found.expect("distance encodable with 64 slots")
    };
    // decoder length adjustment from distance magnitude
    let adjust = (dist > 0x100) as usize + (dist > 0x2000) as usize + (dist > 0x40000) as usize;
    let base_len = len - adjust;
    assert!(base_len >= 2, "length too short for its distance");
    // length code (decode_code_length inverse)
    let (lcode, lbits, lextra) = if base_len < 10 {
        (base_len - 2, 0, 0)
    } else {
        let mut found = None;
        for code in 8..=305usize {
            let lbits = code / 4 - 1;
            let base = 2 + ((4 | (code & 3)) << lbits);
            if base_len < base + (1 << lbits) {
                found = Some((code, lbits, base_len - base));
                break;
            }
        }
        found.expect("length encodable")
    };
    w.put((262 + lcode) as u32, 9); // length symbol
    if lbits > 0 {
        w.put(lextra as u32, lbits as u32);
    }
    w.put(slot as u32, 9); // distance slot symbol
    if dbits > 0 {
        if dbits >= 4 {
            // high bits above the low 4 (decoded via peek32), then the ldd
            // table supplies the low 4 bits.
            let high = dextra >> 4;
            w.put(high as u32, (dbits - 4) as u32);
            w.put((dextra & 0xF) as u32, 9); // ldd code (9-bit table)
        } else {
            w.put(dextra as u32, dbits as u32);
        }
    }
}

/// Repeat the previous match (code 257).
fn emit_repeat(w: &mut BitWriter) {
    w.put(257, 9);
}

/// Match reusing cached distance `idx` (0..=3, codes 258..=261) with a fresh
/// length from the repeating-distance table.
fn emit_cached(w: &mut BitWriter, idx: usize, len: usize) {
    assert!(idx <= 3 && (2..=9).contains(&len));
    w.put((258 + idx) as u32, 9);
    w.put((len - 2) as u32, 9); // rd code(len_slot)
}

/// Declare a delta filter over `block_length` bytes starting at the current
/// write position, with `channels` channels.
fn emit_delta_filter(w: &mut BitWriter, channels: usize, block_length: usize) {
    assert!((1..=32).contains(&channels) && block_length >= 4);
    w.put(256, 9); // filter literal
                   // block_start = 0 (current position): 1 byte of value 0
    w.put(0, 2); // 1 byte follows
    w.put(0, 8);
    // block_length as 1-4 bytes LE
    let bytes = [
        (block_length & 0xff) as u32,
        ((block_length >> 8) & 0xff) as u32,
        ((block_length >> 16) & 0xff) as u32,
        ((block_length >> 24) & 0xff) as u32,
    ];
    let nbytes: usize = if block_length <= 0xff {
        1
    } else if block_length <= 0xffff {
        2
    } else {
        4
    };
    w.put(nbytes as u32 - 1, 2);
    for &b in &bytes[..nbytes] {
        w.put(b, 8);
    }
    w.put(0, 3); // filter type 0 = delta
    w.put((channels - 1) as u32, 5);
}

// --------------------------------------------------------------- block frame

fn concat_tables_and_payload(payload: &BitWriter) -> (Vec<u8>, usize) {
    // Build one BitWriter: tables bits + payload bits (bit-exact).
    // Returns the bytes and the total number of meaningful bits.
    let mut w = BitWriter::new();
    write_tables(&mut w);
    for i in 0..payload.bit_len() {
        let b = payload.bytes[i / 8];
        let bit = ((b >> (7 - (i % 8))) & 1) as u32;
        w.put(bit, 1);
    }
    let n = w.bit_len();
    (w.bytes, n)
}

/// Wrap raw block payload bytes into a full block: header + data.
/// `payload_bits` = number of meaningful bits in the payload.
/// `tables`: transmit Huffman tables; `last`: set the last-block flag.
fn make_block_flags(
    mut payload: Vec<u8>,
    payload_bits: usize,
    tables: bool,
    last: bool,
) -> Vec<u8> {
    let bytes = payload.len();
    let valid_in_last = payload_bits - (bytes - 1) * 8; // 1..=8
    assert!((1..=8).contains(&valid_in_last));
    let bit_size_field = valid_in_last - 1;
    // 2-byte block size (byte_count = 1)
    let byte_count = 1u8;
    let mut flags = (byte_count << 3) | bit_size_field as u8;
    if tables {
        flags |= 0x80;
    }
    if last {
        flags |= 0x40;
    }
    let cksum = 0x5Au8 ^ flags ^ (bytes as u8) ^ ((bytes >> 8) as u8);
    let mut out = vec![flags, cksum, bytes as u8, (bytes >> 8) as u8];
    out.append(&mut payload);
    out
}

fn make_block(payload: Vec<u8>, payload_bits: usize) -> Vec<u8> {
    make_block_flags(payload, payload_bits, true, true)
}

// -------------------------------------------------------- archive frame test

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for &b in data {
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
}

fn vint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn push_header(out: &mut Vec<u8>, body: &[u8]) {
    let mut sized = Vec::new();
    vint(&mut sized, body.len() as u64);
    sized.extend_from_slice(body);
    out.extend_from_slice(&crc32_ieee(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
}

/// Build a complete RAR5 archive with one compressed member.
/// `cinfo_method` = 1..=5 (compression method), dictionary = 128 KB.
fn rar5_compressed_archive(name: &str, unpacked: &[u8], packed: &[u8], method: u64) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    push_header(&mut out, &[1, 0, 0]); // main header
    let mut body = Vec::new();
    body.push(2); // file header
    vint(&mut body, 0x02); // HFLAGS: data size follows
    vint(&mut body, packed.len() as u64); // data size
    vint(&mut body, 0x04); // file flags: data CRC32 present
    vint(&mut body, unpacked.len() as u64); // unpacked size
    vint(&mut body, 0); // attributes
    body.extend_from_slice(&crc32_ieee(unpacked).to_le_bytes());
    vint(&mut body, method << 7); // compression info: v0, method, 128KB dict
    vint(&mut body, 1); // host OS: unix
    vint(&mut body, name.len() as u64);
    body.extend_from_slice(name.as_bytes());
    push_header(&mut out, &body);
    out.extend_from_slice(packed);
    push_header(&mut out, &[5, 0]); // end header
    out
}

// --------------------------------------------------------------------- tests

#[test]
fn literals_only_roundtrip() {
    let payload_data: Vec<u8> = (0..200u8).map(|i| i.wrapping_mul(37)).collect();
    let mut p = BitWriter::new();
    for &b in &payload_data {
        emit_literal(&mut p, b);
    }
    let (payload, total_bits) = concat_tables_and_payload(&p);
    let packed = make_block(payload, total_bits);
    let archive = rar5_compressed_archive("lit.bin", &payload_data, &packed, 3);

    let arc = Archive::open(&archive).unwrap();
    let e = &arc.entries()[0];
    assert_eq!(e.method, 3);
    assert_eq!(arc.extract(e).unwrap(), payload_data);
}

#[test]
fn matches_and_dist_cache_roundtrip() {
    // Expected output, then the command sequence producing it.
    let mut expected: Vec<u8> = b"abcdefghij".to_vec();
    // match len 5 dist 10 -> copies "abcde"
    expected.extend_from_slice(&expected[0..5].to_vec());
    // repeat last (len 5, dist 10)
    expected.extend_from_slice(&expected[expected.len() - 10..expected.len() - 5].to_vec());
    // cached idx0 with new len 4, dist 10
    expected.extend_from_slice(&expected[expected.len() - 10..expected.len() - 6].to_vec());
    // a short near match: dist 3 len 3 ("fgh"-like tail)
    let n = expected.len();
    expected.extend_from_slice(&expected[n - 3..n].to_vec());
    expected.extend_from_slice(b"xyz");

    let mut p = BitWriter::new();
    for &b in b"abcdefghij" {
        emit_literal(&mut p, b);
    }
    emit_match(&mut p, 5, 10);
    emit_repeat(&mut p);
    emit_cached(&mut p, 0, 4);
    emit_match(&mut p, 3, 3);
    for &b in b"xyz" {
        emit_literal(&mut p, b);
    }

    let (payload, total_bits) = concat_tables_and_payload(&p);
    let packed = make_block(payload, total_bits);
    let archive = rar5_compressed_archive("match.bin", &expected, &packed, 5);

    let arc = Archive::open(&archive).unwrap();
    assert_eq!(arc.extract(&arc.entries()[0]).unwrap(), expected);
}

#[test]
fn delta_filter_roundtrip() {
    // Desired output: a smooth 2-channel signal.
    let mut desired = Vec::new();
    for i in 0..64u32 {
        desired.push((i * 7) as u8);
        desired.push((i * 3).wrapping_add(100) as u8);
    }
    // Compute the stored (pre-filter) bytes. The decoder reads the region
    // channel-planar: channel c consumes region[c*(len/ch) + m] and writes
    // output position c + m*channels, doing prev -= stored.
    let channels = 2usize;
    let mut stored = vec![0u8; desired.len()];
    for c in 0..channels {
        let mut prev: u8 = 0;
        for m in 0..desired.len() / channels {
            let dest = c + m * channels;
            stored[c * (desired.len() / channels) + m] = prev.wrapping_sub(desired[dest]);
            prev = desired[dest];
        }
    }

    let mut p = BitWriter::new();
    emit_delta_filter(&mut p, channels, stored.len());
    for &b in &stored {
        emit_literal(&mut p, b);
    }
    let (payload, total_bits) = concat_tables_and_payload(&p);
    let packed = make_block(payload, total_bits);
    let archive = rar5_compressed_archive("delta.raw", &desired, &packed, 2);

    let arc = Archive::open(&archive).unwrap();
    assert_eq!(arc.extract(&arc.entries()[0]).unwrap(), desired);
}

#[test]
fn e8e9_filter_applies() {
    // Region containing a fake x86 call: E8 + rel32.
    // stored bytes: E8, then addr. Decoder: addr has high bit clear ->
    //   if (addr - 0x1000000) has high bit set -> write addr - offset.
    let block_start = 0usize;
    let mut region = vec![0x90u8, 0x90, 0xE8, 0x00, 0x50, 0x00, 0x00, 0x90];
    let i_after_opcode = 3usize; // index of addr within region (after E8 at 2)
    let offset = ((i_after_opcode + block_start) as u32) % 0x1000000;
    let addr = u32::from_le_bytes([region[3], region[4], region[5], region[6]]);
    let mut expected = region.clone();
    if addr.wrapping_sub(0x1000000) & 0x8000_0000 != 0 {
        expected[3..7].copy_from_slice(&addr.wrapping_sub(offset).to_le_bytes());
    }
    let _ = &mut region;

    let mut p = BitWriter::new();
    // filter type 1 = E8
    w_put_filter_e8(&mut p, region.len());
    for &b in &region {
        emit_literal(&mut p, b);
    }
    let (payload, total_bits) = concat_tables_and_payload(&p);
    let packed = make_block(payload, total_bits);
    let archive = rar5_compressed_archive("code.exe", &expected, &packed, 4);

    let arc = Archive::open(&archive).unwrap();
    assert_eq!(arc.extract(&arc.entries()[0]).unwrap(), expected);
}

fn w_put_filter_e8(w: &mut BitWriter, block_length: usize) {
    w.put(256, 9);
    w.put(0, 2);
    w.put(0, 8); // block_start = 0
    let nbytes = if block_length <= 0xff { 1 } else { 2 };
    w.put(nbytes - 1, 2);
    for i in 0..nbytes {
        w.put(((block_length >> (8 * i)) & 0xff) as u32, 8);
    }
    w.put(1, 3); // filter type 1 = E8
}

#[test]
fn big_distance_uses_low_distance_table_and_length_adjust() {
    // 301 literals precede the match, so dist 301 → slot 16 (dbits 7 > 4):
    // high bits via peek32, low 4 bits via the ldd table; dist > 0x100 also
    // bumps the decoded length by 1.
    let mut expected: Vec<u8> = (0..=255u8).chain(0..=44u8).collect();
    let chunk = expected[0..20].to_vec();
    expected.extend_from_slice(&chunk); // match len 20 dist 301
    expected.extend_from_slice(b"end");

    let mut p = BitWriter::new();
    for b in (0..=255u8).chain(0..=44u8) {
        emit_literal(&mut p, b);
    }
    emit_match(&mut p, 20, 301);
    for &b in b"end" {
        emit_literal(&mut p, b);
    }

    let (payload, total_bits) = concat_tables_and_payload(&p);
    let packed = make_block(payload, total_bits);
    let archive = rar5_compressed_archive("big.bin", &expected, &packed, 5);

    let arc = Archive::open(&archive).unwrap();
    assert_eq!(arc.extract(&arc.entries()[0]).unwrap(), expected);
}

#[test]
fn multiple_blocks_reuse_tables() {
    let expected: Vec<u8> = {
        let mut v: Vec<u8> = (0..100u8).collect();
        v.extend_from_slice(&(0..50u8).collect::<Vec<u8>>());
        v
    };

    // block 1: literals 0..100, tables present, not last
    let mut p1 = BitWriter::new();
    for b in 0..100u8 {
        emit_literal(&mut p1, b);
    }
    let (payload1, bits1) = concat_tables_and_payload(&p1);
    let mut packed = make_block_flags(payload1, bits1, true, false);

    // block 2: match dist 100 len 50, no tables, last
    let mut p2 = BitWriter::new();
    emit_match(&mut p2, 50, 100);
    let b2bytes = p2.bytes.clone();
    let b2bits = p2.bit_len();
    packed.extend(make_block_flags(b2bytes, b2bits, false, true));

    let archive = rar5_compressed_archive("multi.bin", &expected, &packed, 3);
    let arc = Archive::open(&archive).unwrap();
    assert_eq!(arc.extract(&arc.entries()[0]).unwrap(), expected);
}

#[test]
fn corrupt_block_checksum_is_rejected() {
    let payload_data = b"hello hello hello".to_vec();
    let mut p = BitWriter::new();
    for &b in &payload_data {
        emit_literal(&mut p, b);
    }
    let (payload, total_bits) = concat_tables_and_payload(&p);
    let mut packed = make_block(payload, total_bits);
    packed[1] ^= 0xFF; // block header checksum
    let archive = rar5_compressed_archive("bad.bin", &payload_data, &packed, 3);
    let arc = Archive::open(&archive).unwrap();
    assert!(arc.extract(&arc.entries()[0]).is_err());
}

#[test]
fn compressed_never_panics_on_mutations() {
    let mut p = BitWriter::new();
    for &b in b"abcabcabc" {
        emit_literal(&mut p, b);
    }
    emit_match(&mut p, 4, 3);
    let (payload, total_bits) = concat_tables_and_payload(&p);
    let packed = make_block(payload, total_bits);
    let good = rar5_compressed_archive("fuzz.bin", b"abcabcabcabc", &packed, 3);

    for len in 0..good.len() {
        let _ = Archive::open(&good[..len]);
    }
    for i in (0..good.len()).step_by(2) {
        for delta in [1u8, 0x80] {
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
