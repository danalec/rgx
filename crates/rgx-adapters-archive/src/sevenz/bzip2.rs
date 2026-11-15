// SPDX-License-Identifier: Apache-2.0

//! BZIP2 compression codec, stream-compatible with libbz2 (bzip2 1.0.8).
//!
//! Independent reimplementation of the published bzip2 format: RLE1
//! run-length preprocessing, Burrows-Wheeler transform, move-to-front
//! coding with RUNA/RUNB bijective base-2 run digits, and canonical
//! Huffman coding over 2–6 trees with 50-symbol group selectors.
//!
//! Bit packing is MSB-first within bytes and continuous across block
//! boundaries, matching `bzip2` / libbz2 output byte-for-byte.

use alloc::vec::Vec;

use super::bwt::Bwt;
use super::error::{CompressError, CompressResult};
use super::huffman::{build_canonical_codes, package_merge_lengths, MAX_BZIP2_CODE_LEN};

// ── Format constants ───────────────────────────────────────────────────

/// Stream magic: `BZh`.
const BZIP2_MAGIC: [u8; 3] = *b"BZh";

/// Maximum block size in 100 KB units (1–9).
const MAX_BLOCK_SIZE: u8 = 9;

/// Maximum Huffman code length in bzip2.
const MAX_CODE_LEN: u8 = MAX_BZIP2_CODE_LEN as u8;

/// RUNA symbol (adds current `es` to the run length).
const RUNA: u16 = 0;

/// RUNB symbol (doubles `es` then adds).
const RUNB: u16 = 1;

/// End-of-block symbol.  The encoder marks all 256 byte values in use,
/// so `EOB = 257`.
const EOB: u16 = 257;

/// Total Huffman alphabet: RUNA, RUNB, 256 bytes, EOB.
const ALPHA_SIZE: usize = 258;

/// Block header magic: digits of pi (0x3141_5926_5359).
const BLOCK_MAGIC: u64 = 0x3141_5926_5359;

/// End-of-stream magic: sqrt(pi) (0x1772_4538_5090).
const EOS_MAGIC: u64 = 0x1772_4538_5090;

// ── CRC-32/BZIP2 ───────────────────────────────────────────────────────

/// Build the CRC lookup table at compile time.
///
/// Polynomial 0x04C11DB7, MSB-first, init/xorout 0xFFFFFFFF — the
/// CRC-32/BZIP2 variant (not the ISO-HDLC one used by zlib/gzip).
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

const CRC_TABLE: [u32; 256] = make_crc_table();

/// Compute CRC-32/BZIP2 over raw (uncompressed) bytes.
fn bz2_crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc = CRC_TABLE[((crc >> 24) ^ b as u32) as usize & 0xFF] ^ (crc << 8);
    }
    !crc
}

// ── MSB-first bit I/O ─────────────────────────────────────────────────

/// MSB-first bit writer: the first bit written lands in bit 7.
#[derive(Debug, Default)]
struct MsbWriter {
    out: Vec<u8>,
    cur: u8,
    nbits: u8,
}

impl MsbWriter {
    fn new() -> Self {
        Self::default()
    }

    fn write_bit(&mut self, bit: u8) {
        self.cur = (self.cur << 1) | (bit & 1);
        self.nbits += 1;
        if self.nbits == 8 {
            self.out.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
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
        if self.nbits > 0 {
            self.cur <<= 8 - self.nbits;
            self.out.push(self.cur);
        }
        self.out
    }
}

/// MSB-first bit reader.
struct MsbReader<'a> {
    data: &'a [u8],
    bit: usize,
}

impl<'a> MsbReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit: 0 }
    }

    fn read_bit(&mut self) -> CompressResult<u32> {
        if self.bit >= self.data.len() * 8 {
            return Err(CompressError::UnexpectedEof);
        }
        let byte = self.data[self.bit / 8];
        let b = (byte >> (7 - (self.bit % 8))) & 1;
        self.bit += 1;
        Ok(b as u32)
    }

    /// Read `n` bits (n ≤ 57), MSB first.
    fn read_bits(&mut self, n: u8) -> CompressResult<u64> {
        let mut value = 0u64;
        for _ in 0..n {
            value = (value << 1) | self.read_bit()? as u64;
        }
        Ok(value)
    }
}

// ── Canonical Huffman decoder (puff.c walk) ───────────────────────────

/// Decodes MSB-first using the classic puff.c walk: `counts` holds the
/// number of codes per length; `symbols` lists symbols sorted by
/// (length, symbol).
struct BzHuffman {
    counts: [u16; (MAX_CODE_LEN + 1) as usize],
    symbols: Vec<u16>,
}

impl BzHuffman {
    fn from_lengths(lengths: &[u8]) -> Self {
        let mut counts = [0u16; (MAX_CODE_LEN + 1) as usize];
        for &l in lengths {
            counts[l as usize] += 1;
        }
        let mut symbols = Vec::with_capacity(lengths.len());
        for len in 1..=(MAX_CODE_LEN as usize) {
            for (sym, &l) in lengths.iter().enumerate() {
                if l as usize == len {
                    symbols.push(sym as u16);
                }
            }
        }
        Self { counts, symbols }
    }

    fn decode_symbol(&self, reader: &mut MsbReader) -> CompressResult<u16> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: usize = 0;
        for len in 1..=(MAX_CODE_LEN as usize) {
            code |= reader.read_bit()? as i32;
            let count = self.counts[len] as i32;
            if code - first < count {
                return Ok(self.symbols[index + (code - first) as usize]);
            }
            index += count as usize;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(CompressError::CorruptedData("invalid bzip2 huffman code"))
    }
}

// ── Symbol stream (50-symbol groups) ──────────────────────────────────

/// Advances through 50-symbol groups and switches Huffman trees per the
/// selector list.
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
            self.group_rem = 50;
        }
        self.group_rem -= 1;
        let tree = &self.trees[self.selectors[self.sel_idx] as usize];
        tree.decode_symbol(self.reader)
    }
}

// ── RLE1 ───────────────────────────────────────────────────────────────

/// RLE1: a run of 4 identical bytes is followed by a count byte (0–251)
/// giving the number of additional repeats.
fn rle1_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        let mut run = 1usize;
        i += 1;
        while i < data.len() && data[i] == b {
            run += 1;
            i += 1;
        }
        if run < 4 {
            out.extend(core::iter::repeat_n(b, run));
        } else {
            out.extend(core::iter::repeat_n(b, 4));
            let mut rem = run - 4;
            loop {
                let n = rem.min(251);
                out.push(n as u8);
                rem -= n;
                if rem == 0 {
                    break;
                }
                out.extend(core::iter::repeat_n(b, 4));
                rem -= 4;
            }
        }
    }
    out
}

/// Invert the RLE1 stage.
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
            if i >= data.len() {
                return Err(CompressError::UnexpectedEof);
            }
            let n = data[i] as usize;
            i += 1;
            out.extend(core::iter::repeat_n(b, n));
            run = 0;
        }
    }
    Ok(out)
}

// ── Huffman length construction ────────────────────────────────────────

/// Build Huffman code lengths without a length limit.
///
/// Each merge raises the depth of every leaf in the merged subtree by one,
/// so leaf depths emerge without an explicit tree walk.
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
                alloc::vec![i as u16]
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

/// Length-limited Huffman code lengths, matching libbz2's iterative
/// deepening (`BZ2_hbMakeCodeLengths`): build an optimal tree, and if
/// any length exceeds the limit, bump the weights of the deepest symbols
/// and rebuild.  The result always comes from a real Huffman tree, so the
/// Kraft sum is exactly 1.
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

// ── MTF with RUNA/RUNB ────────────────────────────────────────────────

/// MTF encode with RUNA/RUNB runs (bijective base-2), matching libbz2.
///
/// The full 256-symbol list is always used, so a literal at MTF index
/// `j ≥ 1` is symbol `j + 1`.  Run values use bijective base-2:
/// `N = Σ(dᵢ · 2ⁱ)` with digits `dᵢ ∈ {1, 2}` (RUNA = 1, RUNB = 2).
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
        let sym = if (m >> i) & 1 == 1 { RUNB } else { RUNA };
        mtfv.push(sym);
        freqs[sym as usize] += 1;
    }
}

// ── Encoder ────────────────────────────────────────────────────────────

/// BZIP2 encoder producing libbz2-compatible streams.
#[derive(Debug)]
pub struct Bzip2Encoder {
    block_size: u8,
}

impl Bzip2Encoder {
    /// Create an encoder with default block size (9).
    pub fn new() -> Self {
        Self::with_block_size(MAX_BLOCK_SIZE)
    }

    /// Create an encoder with a specific block size (1–9).
    pub fn with_block_size(block_size: u8) -> Self {
        Self {
            block_size: block_size.clamp(1, MAX_BLOCK_SIZE),
        }
    }

    /// Compress `data` to a BZIP2 stream.
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

    /// Encode one block.  The chunk is a slice of the original input.
    fn encode_block(&mut self, chunk: &[u8], block_crc: u32, bwt: &mut Bwt, w: &mut MsbWriter) {
        let rle = rle1_encode(chunk);
        let (bwt_data, bwt_idx) = bwt.transform(&rle);
        let mut mtfv: Vec<u16> = Vec::new();
        let mut freqs = [1u64; ALPHA_SIZE]; // min freq 1: the format forbids zero lengths
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

        // In-use map: 16 group bits, then 16 bits per set group.
        for _ in 0..16 {
            w.write_bits(1, 1);
        }
        for _ in 0..16 {
            w.write_bits(0xFFFF, 16);
        }

        // Huffman groups: 2 identical trees, all selectors → tree 0.
        // Selector encoding is a unary bit run: j one-bits then a zero-bit.
        w.write_bits(2, 3);
        let n_selectors = mtfv.len().div_ceil(50);
        w.write_bits(n_selectors as u64, 15);
        for _ in 0..n_selectors {
            w.write_bits(0, 1);
        }
        for _ in 0..2 {
            let mut curr = lengths[0];
            w.write_bits(curr as u64, 5);
            w.write_bits(0, 1);
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
                w.write_bits(0, 1);
            }
        }

        // Payload.
        let mut group_rem = 50usize;
        for &sym in &mtfv {
            if group_rem == 0 {
                group_rem = 50;
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

// ── Decoder ────────────────────────────────────────────────────────────

/// BZIP2 decoder for libbz2-compatible streams.
#[derive(Debug, Default)]
pub struct Bzip2Decoder;

impl Bzip2Decoder {
    /// Create a new decoder.
    pub fn new() -> Self {
        Self
    }

    /// Decompress a BZIP2 stream.
    pub fn decode(&mut self, data: &[u8]) -> CompressResult<Vec<u8>> {
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
        let mut combined_crc = 0u32;
        let mut bwt = Bwt::new();

        // Tolerate trailing padding after the last block.
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

            let block_crc = reader.read_bits(32)? as u32;
            if reader.read_bits(1)? != 0 {
                return Err(CompressError::InvalidFormat(
                    "randomized blocks are not supported",
                ));
            }
            let orig_ptr = reader.read_bits(24)? as usize;

            // In-use map.
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
            if num_selectors == 0 || num_selectors > 2 + block_cap / 50 {
                return Err(CompressError::InvalidFormat("invalid selector count"));
            }

            let mut selectors = vec![0u8; num_selectors];
            {
                let mut pos: Vec<u8> = (0..num_trees as u8).collect();
                for sel in selectors.iter_mut() {
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

            // Payload: Huffman → MTF with runs.
            let mut mtf = seq_to_unseq;
            let mut buf = Vec::with_capacity(block_cap.min(1 << 20));
            {
                let mut stream = SymStream {
                    reader: &mut reader,
                    trees: &trees,
                    selectors: &selectors,
                    group_rem: 50,
                    sel_idx: 0,
                };
                loop {
                    let sym = stream.next()?;
                    if sym as usize == eob {
                        break;
                    }
                    if sym <= RUNB {
                        // Front-byte run: RUNA adds es, RUNB adds 2·es;
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

            // Inverse BWT, then inverse RLE1, then verify block CRC.
            if orig_ptr >= buf.len() && !buf.is_empty() {
                return Err(CompressError::CorruptedData("bad BWT index"));
            }
            let rle_encoded = bwt.inverse(&buf, orig_ptr);
            let block = rle1_decode(&rle_encoded)?;
            if bz2_crc32(&block) != block_crc {
                return Err(CompressError::CorruptedData("block CRC mismatch"));
            }
            combined_crc = combined_crc.rotate_left(1) ^ block_crc;
            output.extend_from_slice(&block);
        }

        Ok(output)
    }
}

/// Decode one MTF literal symbol (symbol ≥ 2 → MTF index symbol − 1).
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

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
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
        println!("kraft={kraft:.6} max_len={}", lengths.iter().max().unwrap());
        assert!((kraft - 1.0).abs() < 1e-9, "kraft must be 1, got {kraft}");

        let codes = build_canonical_codes(&lengths, MAX_CODE_LEN as usize);
        let mut syms = Vec::new();
        for i in 0..500 {
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
        assert!(lengths[7] <= lengths[100]);
        assert!(lengths[200] <= lengths[100]);
    }

    #[test]
    fn test_bzip2_vector_match() {
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
}
