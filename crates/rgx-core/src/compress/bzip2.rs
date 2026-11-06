// SPDX-License-Identifier: Apache-2.0

//! The bzip2 stream format: RLE, Burrows-Wheeler, move-to-front with
//! RUNA/RUNB runs, and canonical Huffman coding over 2-6 trees selected
//! in 50-symbol groups.
//!
//! Independent reimplementation of the published algorithm and bitstream
//! (the format `bzip2`/libbz2 produces), written from the format's
//! description rather than from any implementation's source. Bit packing
//! is MSB-first within bytes and continuous across block boundaries. The
//! BWT itself is [`super::bwt`]; the length-limited code lengths fall
//! back to [`super::huffman::package_merge_lengths`].
//!
//! A stream declares its *block* size (100 kB units) and nothing about
//! its total, so a bounded decode can only refuse late — a block that
//! does not fit is dropped whole rather than appended in part.

use super::bwt::Bwt;
use super::cap::Bounded;
use super::error::{CompressError, CompressResult};
use super::huffman::{build_canonical_codes, package_merge_lengths, MAX_BZIP2_CODE_LEN};
use alloc::vec;
use alloc::vec::Vec;

/// BZIP2 magic header.
const BZIP2_MAGIC: [u8; 3] = *b"BZh";

/// Maximum block size in 100KB units (1-9).
const MAX_BLOCK_SIZE: u8 = 9;

/// Maximum Huffman code length in bzip2.
const MAX_CODE_LEN: u8 = MAX_BZIP2_CODE_LEN as u8;

/// RUNA symbol (adds current `es` to the run length).
const RUNA: u16 = 0;

/// RUNB symbol (skips).
const RUNB: u16 = 1;

/// End-of-block symbol. All 256 byte values are always marked in use by the
/// encoder, so `nInUse = 256` and `EOB = nInUse + 1`.
const EOB: u16 = 257;

/// Total Huffman alphabet size: RUNA, RUNB, 256 byte values, EOB.
const ALPHA_SIZE: usize = 258;

/// Block magic: digits of pi.
const BLOCK_MAGIC: u64 = 0x3141_5926_5359;

/// End-of-stream magic: sqrt(pi).
const EOS_MAGIC: u64 = 0x1772_4538_5090;

/// How many payload symbols one selector group covers.
const GROUP_LEN: usize = 50;

/// CRC-32/BZIP2 (poly 0x04C11DB7, MSB-first, init/xorout 0xFFFFFFFF).
const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04C1_1DB7
            } else {
                crc << 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// CRC lookup table.
const CRC_TABLE: [u32; 256] = make_crc_table();

/// Compute the bzip2 CRC-32 of a block (original, uncompressed bytes).
fn bz2_crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc = CRC_TABLE[((crc >> 24) ^ b as u32) as usize & 0xFF] ^ (crc << 8);
    }
    !crc
}

/// MSB-first bit writer: the first bit written lands in bit 7 of the byte.
#[derive(Debug, Default)]
struct MsbWriter {
    out: Vec<u8>,
    /// Bits staged for the current byte, left-aligned in the low `used` bits.
    staged: u8,
    /// How many bits `staged` holds (0..8).
    used: u8,
}

impl MsbWriter {
    fn new() -> Self {
        Self::default()
    }

    fn write_bit(&mut self, bit: u8) {
        self.staged = (self.staged << 1) | (bit & 1);
        self.used += 1;
        if self.used == 8 {
            self.out.push(self.staged);
            self.staged = 0;
            self.used = 0;
        }
    }

    /// Write the low `n` bits of `value`, MSB first.
    fn write_bits(&mut self, value: u64, n: u8) {
        for i in (0..n).rev() {
            self.write_bit(((value >> i) & 1) as u8);
        }
    }

    /// Flush with zero padding and return the output.
    fn finish(mut self) -> Vec<u8> {
        if self.used > 0 {
            self.staged <<= 8 - self.used;
            self.out.push(self.staged);
        }
        self.out
    }
}

/// MSB-first bit reader: the bit at bit 7 of the current byte is next.
struct MsbReader<'a> {
    data: &'a [u8],
    /// Byte the next bit comes from.
    byte_pos: usize,
    /// How many bits of that byte are already spent (0..8).
    spent: u8,
}

impl<'a> MsbReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            spent: 0,
        }
    }

    fn read_bit(&mut self) -> CompressResult<u32> {
        let byte = *self
            .data
            .get(self.byte_pos)
            .ok_or(CompressError::UnexpectedEof)?;
        let bit = (byte >> (7 - self.spent)) & 1;
        self.spent += 1;
        if self.spent == 8 {
            self.byte_pos += 1;
            self.spent = 0;
        }
        Ok(bit as u32)
    }

    /// Read `n` bits (n <= 57), MSB first.
    fn read_bits(&mut self, n: u8) -> CompressResult<u64> {
        let mut value = 0u64;
        for _ in 0..n {
            value = (value << 1) | self.read_bit()? as u64;
        }
        Ok(value)
    }
}

/// Canonical Huffman decoding table for one bzip2 group tree.
///
/// Built from the code lengths the stream carries: for every length, the
/// smallest code of that length and the symbols that own codes of that
/// length in code order. Decoding accumulates bits MSB-first and stops at
/// the first length whose code range covers what has been read.
struct BzHuffman {
    /// `first[len]` is the smallest `len`-bit code, or 0 when no code of
    /// that length exists.
    first: [u32; (MAX_CODE_LEN + 1) as usize],
    /// `by_len[len]` lists the symbols whose codes are `len` bits, in
    /// ascending code order.
    by_len: [Vec<u16>; (MAX_CODE_LEN + 1) as usize],
}

impl BzHuffman {
    fn from_lengths(lengths: &[u8]) -> Self {
        // Canonical order: sort symbols by (length, symbol) and hand out
        // codes length by length, each starting where the previous left
        // off shifted up one.
        let mut order: Vec<(u8, u16)> = lengths
            .iter()
            .enumerate()
            .filter(|(_, &l)| l > 0)
            .map(|(s, &l)| (l, s as u16))
            .collect();
        order.sort_unstable();

        let mut first = [0u32; (MAX_CODE_LEN + 1) as usize];
        let mut by_len: [Vec<u16>; (MAX_CODE_LEN + 1) as usize] = Default::default();
        let mut code = 0u32;
        let mut prev_len = 0u8;
        for &(len, sym) in &order {
            if len != prev_len {
                if prev_len > 0 {
                    code <<= len - prev_len;
                }
                first[len as usize] = code;
                prev_len = len;
            }
            by_len[len as usize].push(sym);
            code += 1;
        }
        Self { first, by_len }
    }

    fn decode_symbol(&self, reader: &mut MsbReader) -> CompressResult<u16> {
        let mut code = 0u32;
        for len in 1..=(MAX_CODE_LEN as usize) {
            code = (code << 1) | reader.read_bit()?;
            let list = &self.by_len[len];
            if list.is_empty() {
                continue;
            }
            let offset = code.wrapping_sub(self.first[len]);
            if offset < list.len() as u32 {
                return Ok(list[offset as usize]);
            }
        }
        Err(CompressError::CorruptedData("invalid bzip2 huffman code"))
    }
}

/// Symbol stream for one block: advances through 50-symbol groups and
/// switches Huffman trees per the selector list.
struct SymStream<'r, 'd> {
    reader: &'r mut MsbReader<'d>,
    trees: &'r [BzHuffman],
    selectors: &'r [u8],
    group_rem: usize,
    sel_idx: usize,
}

impl<'r, 'd> SymStream<'r, 'd> {
    fn next(&mut self) -> CompressResult<u16> {
        if self.group_rem == 0 {
            self.sel_idx += 1;
            if self.sel_idx >= self.selectors.len() {
                return Err(CompressError::CorruptedData("selector list exhausted"));
            }
            self.group_rem = GROUP_LEN;
        }
        self.group_rem -= 1;
        let tree = &self.trees[self.selectors[self.sel_idx] as usize];
        tree.decode_symbol(self.reader)
    }
}

/// One run of identical bytes at the head of `data`, at least one byte
/// long.
fn take_run(data: &[u8]) -> (u8, usize) {
    let b = data[0];
    let mut n = 1;
    while n < data.len() && data[n] == b {
        n += 1;
    }
    (b, n)
}

/// RLE1 stage: a run of 4 identical bytes is followed by a count byte with
/// the number of additional repeats (0-255 per group).
fn rle1_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut rest = data;
    while !rest.is_empty() {
        let (b, run) = take_run(rest);
        rest = &rest[run..];
        if run < 4 {
            out.extend(core::iter::repeat_n(b, run));
            continue;
        }
        out.extend(core::iter::repeat_n(b, 4));
        let mut rem = run - 4;
        loop {
            // Format limit: count byte is 0..=251 (max group 4+251).
            let n = rem.min(251);
            out.push(n as u8);
            rem -= n;
            if rem == 0 {
                break;
            }
            // More repeats: start another group, which always ends with
            // a count byte so the decoder's 4-run rule stays satisfied.
            out.extend(core::iter::repeat_n(b, 4));
            rem -= 4;
        }
    }
    out
}

/// Invert the RLE1 stage: four of a byte in a row is the signal that the
/// next byte counts further repeats.
fn rle1_decode(data: &[u8]) -> CompressResult<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    let mut run = 0usize;
    let mut prev = 0u8;
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        i += 1;
        if run > 0 && b == prev {
            run += 1;
        } else {
            prev = b;
            run = 1;
        }
        out.push(b);
        if run == 4 {
            let n = *data.get(i).ok_or(CompressError::UnexpectedEof)? as usize;
            i += 1;
            out.extend(core::iter::repeat_n(b, n));
            run = 0;
        }
    }
    Ok(out)
}

/// Huffman code lengths without a length limit.
///
/// Combines nodes with a binary heap; each merge raises the depth of every
/// leaf in the merged subtree by one, so leaf lengths emerge without an
/// explicit tree walk.
fn huffman_lengths_unlimited(weights: &[u64]) -> Vec<u8> {
    let n = weights.len();
    let mut lens = vec![0u8; n];
    let active: Vec<usize> = (0..n).filter(|&i| weights[i] > 0).collect();
    match active.len() {
        0 => return lens,
        1 => {
            lens[active[0]] = 1;
            return lens;
        }
        _ => {}
    }

    let mut syms: Vec<Vec<u16>> = (0..n)
        .map(|i| {
            if weights[i] > 0 {
                vec![i as u16]
            } else {
                Vec::new()
            }
        })
        .collect();
    let mut heap: alloc::collections::BinaryHeap<(core::cmp::Reverse<u64>, u32)> =
        alloc::collections::BinaryHeap::new();
    for &i in &active {
        heap.push((core::cmp::Reverse(weights[i]), i as u32));
    }
    let mut next_id = n as u32;
    while heap.len() > 1 {
        let (core::cmp::Reverse(w1), i1) = heap.pop().unwrap_or((core::cmp::Reverse(0), 0));
        let (core::cmp::Reverse(w2), i2) = heap.pop().unwrap_or((core::cmp::Reverse(0), 0));
        let mut merged = core::mem::take(&mut syms[i1 as usize]);
        merged.extend_from_slice(&syms[i2 as usize]);
        for &s in &merged {
            lens[s as usize] = lens[s as usize].saturating_add(1);
        }
        syms.push(merged);
        heap.push((core::cmp::Reverse(w1 + w2), next_id));
        next_id += 1;
    }
    lens
}

/// Length-limited Huffman code lengths: build an optimal tree, and if any
/// length exceeds the limit, bump the weights of the deepest symbols and
/// rebuild. The result always comes from a real Huffman tree, so the Kraft
/// sum is exactly 1.
fn limited_huffman_lengths(freqs: &[u64], max_len: u8) -> Vec<u8> {
    let mut weights: Vec<u64> = freqs.to_vec();
    for _iteration in 0..64 {
        let lens = huffman_lengths_unlimited(&weights);
        let max_seen = lens.iter().copied().max().unwrap_or(0);
        if max_seen <= max_len {
            return lens;
        }
        for i in 0..weights.len() {
            if lens[i] == max_seen && weights[i] > 0 {
                weights[i] += 1;
            }
        }
    }
    // Fallback (practically unreachable): clamp via package-merge.
    package_merge_lengths(freqs, max_len)
}

/// MTF encode with RUNA/RUNB runs (bijective base-2), matching libbz2.
///
/// The full 256-symbol list is always used (`nInUse = 256`), so the literal
/// symbol for a byte at MTF index `j >= 1` is `j + 1`.
///
/// Run values use bijective base-2: `N = sum(d_i * 2^i)` with digits
/// `d_i in {1, 2}` (RUNA = 1, RUNB = 2). Digits are `d_i = 1 + bit_i(M)`
/// where `k = floor(log2(N+1))` and `M = N - (2^k - 1)`.
fn mtf_encode_runs(data: &[u8], mtfv: &mut Vec<u16>, freqs: &mut [u64; ALPHA_SIZE]) {
    let mut list: Vec<u8> = (0..=255u8).collect();
    let mut zpend = 0u64;
    for &b in data {
        let j = list.iter().position(|&c| c == b).unwrap_or(0);
        if j == 0 {
            zpend += 1;
            continue;
        }
        flush_zpend(zpend, mtfv, freqs);
        zpend = 0;
        let sym = j as u16 + 1;
        mtfv.push(sym);
        freqs[sym as usize] += 1;
        list.copy_within(0..j, 1);
        list[0] = b;
    }
    flush_zpend(zpend, mtfv, freqs);
}

/// Flush a pending front-byte run as RUNA/RUNB digits.
fn flush_zpend(zpend: u64, mtfv: &mut Vec<u16>, freqs: &mut [u64; ALPHA_SIZE]) {
    if zpend == 0 {
        return;
    }
    let k = 63 - (zpend + 1).leading_zeros();
    let base = (1u64 << k) - 1;
    let m = zpend - base;
    for i in 0..k {
        // bit set -> digit 2 (RUNB), bit clear -> digit 1 (RUNA)
        let sym = if (m >> i) & 1 == 1 { RUNB } else { RUNA };
        mtfv.push(sym);
        freqs[sym as usize] += 1;
    }
}

/// BZIP2 encoder producing libbz2-compatible streams.
#[derive(Debug)]
pub struct Bzip2Encoder {
    /// Block size in 100KB units (1-9).
    block_size: u8,
}

impl Bzip2Encoder {
    /// Create a new BZIP2 encoder with default block size (9).
    pub fn new() -> Self {
        Self::with_block_size(MAX_BLOCK_SIZE)
    }

    /// Create a BZIP2 encoder with a specific block size (1-9).
    pub fn with_block_size(block_size: u8) -> Self {
        Self {
            block_size: block_size.clamp(1, MAX_BLOCK_SIZE),
        }
    }

    /// Compress data using BZIP2.
    pub fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        let mut w = MsbWriter::new();
        w.write_bits(BZIP2_MAGIC[0] as u64, 8);
        w.write_bits(BZIP2_MAGIC[1] as u64, 8);
        w.write_bits(BZIP2_MAGIC[2] as u64, 8);
        w.write_bits((self.block_size + b'0') as u64, 8);

        let mut combined_crc = 0u32;
        let block_bytes = self.block_size as usize * 100_000;
        let mut bwt = Bwt::new();

        for chunk in data.chunks(block_bytes) {
            let block_crc = bz2_crc32(chunk);
            combined_crc = combined_crc.rotate_left(1) ^ block_crc;
            self.encode_block(chunk, block_crc, &mut bwt, &mut w);
        }

        w.write_bits(EOS_MAGIC, 48);
        w.write_bits(combined_crc as u64, 32);
        w.finish()
    }

    /// Encode a single block (chunk is a slice of the original input).
    fn encode_block(&mut self, chunk: &[u8], block_crc: u32, bwt: &mut Bwt, w: &mut MsbWriter) {
        // RLE1 -> BWT -> MTF with runs.
        let rle = rle1_encode(chunk);
        let (bwt_data, bwt_idx) = bwt.transform(&rle);
        let mut mtfv: Vec<u16> = Vec::new();
        let mut freqs = [1u64; ALPHA_SIZE]; // min freq 1: format forbids zero lengths
        mtf_encode_runs(&bwt_data, &mut mtfv, &mut freqs);
        freqs[EOB as usize] += 1;
        mtfv.push(EOB);

        let lengths = limited_huffman_lengths(&freqs, MAX_CODE_LEN);
        let codes = build_canonical_codes(&lengths, MAX_CODE_LEN as usize);

        // Block header.
        w.write_bits(BLOCK_MAGIC, 48);
        w.write_bits(block_crc as u64, 32);
        w.write_bits(0, 1); // not randomized
        w.write_bits(bwt_idx as u64, 24);

        // In-use byte map: 16 single bits (one per group), then 16 bits for
        // each set group.
        for _ in 0..16 {
            w.write_bits(1, 1);
        }
        for _ in 0..16 {
            w.write_bits(0xFFFF, 16);
        }

        // Huffman groups: 2 identical trees, all selectors point to tree 0.
        // Selector encoding is a unary bit run: j one-bits then a zero-bit;
        // tree 0 is MTF value 0, i.e. a single 0 bit.
        w.write_bits(2, 3);
        let n_selectors = mtfv.len().div_ceil(GROUP_LEN);
        w.write_bits(n_selectors as u64, 15);
        for _ in 0..n_selectors {
            w.write_bits(0, 1);
        }
        for _ in 0..2 {
            let mut curr = lengths[0];
            w.write_bits(curr as u64, 5);
            w.write_bits(0, 1); // terminator for symbol 0
            for &target in &lengths[1..ALPHA_SIZE] {
                while curr != target {
                    if target > curr {
                        w.write_bits(0b10, 2);
                        curr += 1;
                    } else {
                        w.write_bits(0b11, 2);
                        curr -= 1;
                    }
                }
                w.write_bits(0, 1); // terminator for symbol i
            }
        }

        // Payload.
        let mut group_rem = GROUP_LEN;
        for &sym in &mtfv {
            if group_rem == 0 {
                group_rem = GROUP_LEN;
            }
            group_rem -= 1;
            let code = codes[sym as usize];
            w.write_bits(code.code as u64, code.bits);
        }
    }
}

impl Default for Bzip2Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// BZIP2 decoder for libbz2-compatible streams.
#[derive(Debug, Default)]
pub struct Bzip2Decoder;

impl Bzip2Decoder {
    /// Create a new BZIP2 decoder.
    pub fn new() -> Self {
        Self
    }

    /// Decompress BZIP2 data.
    pub fn decode(&mut self, data: &[u8]) -> CompressResult<Vec<u8>> {
        self.decode_bounded(data, super::cap::UNLIMITED)
            .map(|b| b.bytes)
    }

    /// Decompress BZIP2 data without expanding it past `limit` bytes.
    ///
    /// A bzip2 stream declares its *block* size (100 kB units) and nothing
    /// about its total, so the ceiling is the running one. A block that
    /// does not fit is dropped whole rather than appended in part, so the
    /// overshoot is bounded by `ceil(limit / 900 kB)` blocks.
    pub fn decode_bounded(&mut self, data: &[u8], limit: u64) -> CompressResult<Bounded> {
        if data.len() < 4 || data[0..3] != BZIP2_MAGIC {
            return Err(CompressError::InvalidFormat("invalid BZIP2 magic"));
        }
        let block_size_char = data[3];
        if !(b'1'..=b'9').contains(&block_size_char) {
            return Err(CompressError::InvalidFormat("invalid block size"));
        }
        let block_cap = 10 + (block_size_char - b'0') as usize * 100_000;

        let mut reader = MsbReader::new(&data[4..]);
        let mut output = Vec::new();
        let mut cap = super::cap::OutputCap::new(limit);
        let mut combined_crc = 0u32;
        let mut bwt = Bwt::new();

        // A failed read is truncated padding after the last block: tolerate.
        while let Ok(magic) = reader.read_bits(48) {
            if magic == EOS_MAGIC {
                if let Ok(stored) = reader.read_bits(32) {
                    if stored as u32 != combined_crc {
                        return Err(CompressError::CorruptedData("stream CRC mismatch"));
                    }
                }
                break;
            }
            if magic != BLOCK_MAGIC {
                return Err(CompressError::InvalidFormat("invalid block magic"));
            }

            let (block_crc, orig_ptr, buf) = read_block_payload(&mut reader, block_cap)?;

            // Inverse BWT then inverse RLE1, verify block CRC.
            if orig_ptr >= buf.len() && !buf.is_empty() {
                return Err(CompressError::CorruptedData("bad BWT index"));
            }
            let rle_encoded = bwt.inverse(&buf, orig_ptr);
            let block = rle1_decode(&rle_encoded)?;
            if !cap.take(block.len() as u64) {
                return Ok(Bounded::stopped(output, None, limit));
            }
            if bz2_crc32(&block) != block_crc {
                return Err(CompressError::CorruptedData("block CRC mismatch"));
            }
            combined_crc = combined_crc.rotate_left(1) ^ block_crc;
            output.extend_from_slice(&block);
        }

        Ok(Bounded::complete(output, None, limit))
    }
}

/// Read everything one block carries between its magic and the inverse
/// transform: CRC, the BWT index, the in-use map (as the MTF seed), the
/// Huffman groups, and the run-expanded symbol payload.
fn read_block_payload(
    reader: &mut MsbReader,
    block_cap: usize,
) -> CompressResult<(u32, usize, Vec<u8>)> {
    let block_crc = reader.read_bits(32)? as u32;
    if reader.read_bits(1)? != 0 {
        return Err(CompressError::InvalidFormat(
            "randomized blocks are not supported",
        ));
    }
    let orig_ptr = reader.read_bits(24)? as usize;

    // In-use byte map: 16 single bits (one per group of 16 bytes),
    // then 16 bits for each set group.
    let mut inuse16 = 0u16;
    for g in 0..16 {
        if reader.read_bit()? != 0 {
            inuse16 |= 1 << g;
        }
    }
    let mut seq_to_unseq: Vec<u8> = Vec::new();
    for g in 0..16 {
        if inuse16 & (1 << g) != 0 {
            for j in 0..16 {
                if reader.read_bit()? != 0 {
                    seq_to_unseq.push((g * 16 + j) as u8);
                }
            }
        }
    }
    let n_in_use = seq_to_unseq.len();
    if n_in_use == 0 {
        return Err(CompressError::CorruptedData("empty in-use map"));
    }
    let alpha_size = n_in_use + 2;
    let eob = alpha_size - 1;

    // Huffman groups.
    let num_trees = reader.read_bits(3)? as usize;
    if !(2..=6).contains(&num_trees) {
        return Err(CompressError::InvalidFormat("invalid number of trees"));
    }
    let num_selectors = reader.read_bits(15)? as usize;
    if num_selectors == 0 || num_selectors > 2 + block_cap / GROUP_LEN {
        return Err(CompressError::InvalidFormat("invalid selector count"));
    }

    let mut selectors = vec![0u8; num_selectors];
    {
        let mut pos: Vec<u8> = (0..num_trees as u8).collect();
        for sel in selectors.iter_mut() {
            // Unary bit run: count 1-bits, terminated by a 0-bit.
            let mut j = 0usize;
            while reader.read_bit()? != 0 {
                j += 1;
                if j >= num_trees {
                    return Err(CompressError::CorruptedData("bad selector"));
                }
            }
            let tmp = pos[j];
            for k in (1..=j).rev() {
                pos[k] = pos[k - 1];
            }
            pos[0] = tmp;
            *sel = tmp;
        }
    }

    let mut trees = Vec::with_capacity(num_trees);
    for _ in 0..num_trees {
        let mut curr = reader.read_bits(5)? as i32;
        let mut lengths = vec![0u8; alpha_size];
        for len in lengths.iter_mut() {
            loop {
                if curr < 1 || curr > MAX_CODE_LEN as i32 {
                    return Err(CompressError::CorruptedData("bad code length"));
                }
                if reader.read_bit()? == 0 {
                    break;
                }
                // Second bit: 0 = increment, 1 = decrement.
                if reader.read_bit()? == 0 {
                    curr += 1;
                } else {
                    curr -= 1;
                }
            }
            *len = curr as u8;
        }
        trees.push(BzHuffman::from_lengths(&lengths));
    }

    // Payload: Huffman -> MTF with runs.
    let mut mtf = seq_to_unseq;
    let mut buf = Vec::with_capacity(block_cap.min(1 << 20));
    {
        let mut stream = SymStream {
            reader,
            trees: &trees,
            selectors: &selectors,
            group_rem: GROUP_LEN,
            sel_idx: 0,
        };
        loop {
            let sym = stream.next()?;
            if sym as usize == eob {
                break;
            }
            if sym <= RUNB {
                // Front-byte run: RUNA adds es, RUNB adds 2*es,
                // es doubles per symbol (bijective base-2).
                let mut es = 1u64;
                let mut n = 0u64;
                let mut s = sym;
                while s <= RUNB {
                    if s == RUNA {
                        n += es;
                    } else {
                        n += 2 * es;
                    }
                    es <<= 1;
                    if n >= 1 << 25 {
                        return Err(CompressError::CorruptedData("run too long"));
                    }
                    s = stream.next()?;
                }
                let b = mtf[0];
                buf.extend(core::iter::repeat_n(b, n as usize));
                if s as usize == eob {
                    break;
                }
                mtf_literal(s, &mut mtf, &mut buf)?;
            } else {
                mtf_literal(sym, &mut mtf, &mut buf)?;
            }
            if buf.len() > block_cap {
                return Err(CompressError::CorruptedData("block too large"));
            }
        }
    }

    Ok((block_crc, orig_ptr, buf))
}

/// Decode one MTF literal symbol (symbol >= 2 -> MTF index symbol - 1).
fn mtf_literal(sym: u16, mtf: &mut [u8], buf: &mut Vec<u8>) -> CompressResult<()> {
    let idx = sym as usize - 1;
    if idx == 0 || idx >= mtf.len() {
        return Err(CompressError::CorruptedData("bad MTF index"));
    }
    let b = mtf[idx];
    mtf.copy_within(0..idx, 1);
    mtf[0] = b;
    buf.push(b);
    Ok(())
}
#[cfg(all(test, feature = "bzip2"))]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    use std::println;

    #[test]
    fn test_bzip2_empty() {
        let mut encoder = Bzip2Encoder::new();
        let mut decoder = Bzip2Decoder::new();
        let compressed = encoder.encode(b"");
        assert_eq!(&compressed[0..4], b"BZh9");
        let decompressed = decoder.decode(&compressed).unwrap();
        assert_eq!(decompressed, b"");
    }

    #[test]
    fn test_bzip2_simple() {
        let mut encoder = Bzip2Encoder::new();
        let mut decoder = Bzip2Decoder::new();
        let data = b"Hello, World!";
        let compressed = encoder.encode(data);
        let decompressed = decoder.decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_bzip2_repeated() {
        let mut encoder = Bzip2Encoder::new();
        let mut decoder = Bzip2Decoder::new();
        let data = vec![b'a'; 10000];
        let compressed = encoder.encode(&data);
        let decompressed = decoder.decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_bzip2_block_size() {
        let mut encoder = Bzip2Encoder::with_block_size(1);
        let mut decoder = Bzip2Decoder::new();
        let data = b"Test data with block size 1";
        let compressed = encoder.encode(data);
        assert_eq!(&compressed[0..4], b"BZh1");
        let decompressed = decoder.decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_bzip2_multiblock() {
        // 250 KB forces three 100 KB blocks with block size 1.
        let mut encoder = Bzip2Encoder::with_block_size(1);
        let mut decoder = Bzip2Decoder::new();
        let mut data = Vec::new();
        let mut state = 0x12345678u32;
        for _ in 0..250_000 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            data.push((state >> 24) as u8);
        }
        let compressed = encoder.encode(&data);
        let decompressed = decoder.decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_bzip2_highly_repetitive() {
        // Worst case for naive rotation-based BWT.
        let mut encoder = Bzip2Encoder::new();
        let mut decoder = Bzip2Decoder::new();
        let mut data = Vec::new();
        for i in 0..50_000usize {
            data.extend_from_slice(b"abcabc");
            data.push((i % 7) as u8 + b'0');
        }
        let compressed = encoder.encode(&data);
        let decompressed = decoder.decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_bzip2_invalid_magic() {
        let mut decoder = Bzip2Decoder::new();
        let result = decoder.decode(b"invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_bzip2_crc_known_vector() {
        // CRC-32/BZIP2 of "123456789".
        assert_eq!(bz2_crc32(b"123456789"), 0xFC89_1918);
    }

    #[test]
    fn test_rle1_roundtrip() {
        let cases: Vec<Vec<u8>> = vec![
            b"abc".to_vec(),
            b"aaaa".to_vec(),
            b"aaaaa".to_vec(),
            vec![b'x'; 259],
            vec![b'x'; 263],
            vec![b'y'; 1000],
            b"aabbaaaabbbbbbbba".to_vec(),
        ];
        for data in cases {
            let encoded = rle1_encode(&data);
            assert_eq!(rle1_decode(&encoded).unwrap(), data);
        }
    }

    #[test]
    fn test_huffman_pipeline_synthetic() {
        // 258 symbols: a few hot, many cold — mirrors the "mixed" profile.
        let mut freqs = [1u64; ALPHA_SIZE];
        let mut rng = 0x12345678u64;
        for _ in 0..2000 {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            freqs[(rng >> 33) as usize % 40] += 1;
        }
        let lengths = limited_huffman_lengths(&freqs, MAX_CODE_LEN);
        let kraft: f64 = lengths
            .iter()
            .map(|&l| if l > 0 { 2f64.powi(-(l as i32)) } else { 0.0 })
            .sum();
        #[cfg(feature = "std")]
        println!("kraft={kraft:.6} max_len={}", lengths.iter().max().unwrap());
        assert!((kraft - 1.0).abs() < 1e-9, "kraft must be 1, got {kraft}");

        let codes = build_canonical_codes(&lengths, MAX_CODE_LEN as usize);
        // Encode a symbol stream and decode it back with the puff-style walk.
        let mut syms = Vec::new();
        for _ in 0..500 {
            rng = rng
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            syms.push((rng >> 33) as usize % 258);
        }
        let mut w = MsbWriter::new();
        for &s in &syms {
            let c = codes[s];
            assert!(c.bits > 0, "symbol {s} has no code");
            w.write_bits(c.code as u64, c.bits);
        }
        let bytes = w.finish();
        let tree = BzHuffman::from_lengths(&lengths);
        let mut r = MsbReader::new(&bytes);
        for &s in &syms {
            let got = tree.decode_symbol(&mut r).unwrap();
            assert_eq!(got as usize, s);
        }
    }

    #[test]
    fn test_huffman_limited_extreme_skew() {
        // One symbol dominates 1M:1 — forces the length-limit loop to bump
        // weights repeatedly. Result must still be a complete code with
        // max_len <= 20 (Kraft sum exactly 1), like BZ2_hbMakeCodeLengths.
        let mut freqs = [1u64; ALPHA_SIZE];
        freqs[7] = 1_000_000;
        freqs[200] = 500_000;
        let lengths = limited_huffman_lengths(&freqs, MAX_CODE_LEN);
        let max_seen = lengths.iter().copied().max().unwrap();
        assert!(max_seen <= MAX_CODE_LEN, "max_len {max_seen} exceeds limit");
        let kraft: f64 = lengths
            .iter()
            .map(|&l| if l > 0 { 2f64.powi(-(l as i32)) } else { 0.0 })
            .sum();
        assert!((kraft - 1.0).abs() < 1e-9, "kraft must be 1, got {kraft}");
        // Dominant symbols get the shortest codes.
        assert!(lengths[7] <= lengths[100]);
        assert!(lengths[200] <= lengths[100]);
    }

    #[test]
    fn test_bzip2_vector_match() {
        // bzip2 stream produced by CPython bz2 (matches + literals).
        let compressed = include_bytes!("../../testdata/bzip2_match.bin");
        let expected = include_bytes!("../../testdata/bzip2_match.expected");
        let mut decoder = Bzip2Decoder::new();
        let output = decoder.decode(compressed).expect("decode bzip2_match");
        assert_eq!(output, expected);
    }

    #[test]
    fn test_bzip2_vector_big() {
        let compressed = include_bytes!("../../testdata/bzip2_big.bin");
        let expected = include_bytes!("../../testdata/bzip2_big.expected");
        let mut decoder = Bzip2Decoder::new();
        let output = decoder.decode(compressed).expect("decode bzip2_big");
        assert_eq!(output, expected);
    }

    /// A bzip2 stream declares its block size and nothing about its total,
    /// so the ceiling is the running one, checked where each block joins the
    /// output. A block that does not fit is dropped whole.
    ///
    /// `bzip2_big` is CPython's and is a single 7.7 kB block, so under a cap
    /// of 1 kB the whole block is refused and nothing is emitted.
    #[test]
    fn decode_bounded_refuses_a_block_that_does_not_fit() {
        let compressed = include_bytes!("../../testdata/bzip2_big.bin");
        let expected = include_bytes!("../../testdata/bzip2_big.expected");
        let b = Bzip2Decoder::new()
            .decode_bounded(compressed, 1000)
            .expect("bounded");
        assert!(
            b.capped,
            "{} bytes decoded under a 1000 byte cap",
            expected.len()
        );
        assert_eq!(b.declared, None, "bzip2 declares no total");
        assert!(b.bytes.len() <= 1000, "emitted {} bytes", b.bytes.len());
        assert_eq!(b.bytes, &expected[..b.bytes.len()], "not the real prefix");

        let whole = Bzip2Decoder::new()
            .decode_bounded(compressed, expected.len() as u64)
            .expect("exact");
        assert!(!whole.capped);
        assert_eq!(whole.bytes, expected);
    }

    /// Multi-block, so the cap has a boundary to land on: the blocks that
    /// fit are kept and only the one that overruns is dropped.
    #[test]
    fn decode_bounded_keeps_the_blocks_that_fit() {
        let payload: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
        let compressed = Bzip2Encoder::with_block_size(1).encode(&payload);
        let b = Bzip2Decoder::new()
            .decode_bounded(&compressed, 120_000)
            .expect("bounded");
        assert!(b.capped);
        assert_eq!(b.bytes, &payload[..b.bytes.len()], "not the real prefix");
        assert!(
            b.bytes.len() <= 120_000 && !b.bytes.is_empty(),
            "{} bytes",
            b.bytes.len()
        );
    }
}

/// A stream is untrusted input: bad magic, a randomized block, a
/// selector run past the tree count, a run length that will not fit the
/// block — every one must answer with an error, never a panic.
#[cfg(all(test, feature = "bzip2"))]
mod fuzz {
    use super::*;

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: alloc::vec::Vec<(&str, alloc::vec::Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            ("magic", b"BZh9".to_vec()),
            ("eos", {
                let mut v = b"BZh9".to_vec();
                v.extend_from_slice(&EOS_MAGIC.to_be_bytes()[2..]);
                v.extend_from_slice(&[0u8; 4]);
                v
            }),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "bzip2", |data| {
            let mut decoder = Bzip2Decoder::new();
            let _ = decoder.decode(data);
            let mut decoder = Bzip2Decoder::new();
            let _ = decoder.decode_bounded(data, 4096);
            let _ = rle1_decode(data);
        });
    }
}
