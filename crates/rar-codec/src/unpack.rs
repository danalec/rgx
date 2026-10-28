// SPDX-License-Identifier: Apache-2.0

//! RAR 5.0 decompression: Huffman-coded commands over an LZ77 window.
//!
//! Independent reimplementation. RARLAB's published specification documents
//! the *container* only and publishes no formula for the *algorithms*, so
//! this module is written from the algorithm's shape — a canonical Huffman
//! table over a literal/command alphabet, a circular dictionary for
//! back-references, and a small distance cache — rather than from a
//! published formula. The constants below are the alphabet sizes this
//! format uses.
//!
//! # Alphabet
//!
//! The command table (`HUFF_NC` symbols) is:
//!
//! | range | meaning |
//! |---|---|
//! | 0..=255 | literal byte |
//! | 256 | a filter follows |
//! | 257 | repeat the last match |
//! | 258..=261 | copy from distance cache slot `n - 258` |
//! | 262.. | new match; length code is `n - 262` |
//!
//! A match is a length code plus a distance slot. The length code is a
//! base-plus-extra-bits ladder; the distance slot is the same, with a
//! second low-distance table when the slot needs more than 4 extra bits.
//! Distances above 0x100 / 0x2000 / 0x40000 each buy one extra byte of
//! length.
//!
//! # Filters
//!
//! A filter is a post-pass over a region of the output that has just been
//! produced: delta, x86 call fixup (`E8`), extended fixup (`E8`/`E9`), or
//! ARM branch fixup. Each is declared mid-stream and applied the moment its
//! range completes, so a later match can reference the filtered bytes.

use alloc::vec;
use alloc::vec::Vec;

use crate::bitreader::BitReader;
use crate::huffman::DecodeTable;
use crate::{Error, Result};

const HUFF_BC: usize = 20;
const HUFF_NC: usize = 306;
const HUFF_DC: usize = 64;
const HUFF_LDC: usize = 16;
const HUFF_RC: usize = 44;
const HUFF_TABLE_SIZE: usize = HUFF_NC + HUFF_DC + HUFF_RC + HUFF_LDC;

const FILTER_DELTA: u8 = 0;
const FILTER_E8: u8 = 1;
const FILTER_E8E9: u8 = 2;
const FILTER_ARM: u8 = 3;

/// A filter declared mid-stream, waiting for its range to complete.
#[derive(Debug, Clone, Copy)]
struct FilterInfo {
    ftype: u8,
    /// Absolute window offset where the region starts.
    block_start: usize,
    block_length: usize,
    /// Delta filter only: the interleave factor, 1..=32.
    channels: usize,
}

/// The four Huffman tables one block can carry.
struct Tables {
    /// Literals and commands, 306 symbols.
    ld: DecodeTable,
    /// Distance slots, 64 symbols.
    dd: DecodeTable,
    /// Low distance bits, 16 symbols.
    ldd: DecodeTable,
    /// Repeat-distance lengths, 44 symbols.
    rd: DecodeTable,
}

/// Decompress one RAR 5.0 packed area.
///
/// `unpacked_size` is the declared size, or `None` when the header said the
/// size is unknown and extraction runs until the stream ends. `dict_size`
/// bounds the back-reference window.
pub fn unpack(data: &[u8], unpacked_size: Option<u64>, dict_size: u64) -> Result<Vec<u8>> {
    let mut u = Unpacker::new(dict_size);
    u.begin_member(unpacked_size);
    u.run(data)?;
    u.finish()
}

/// Stateful decompressor. The window and the decoder state survive between
/// members so a solid group can reference data written by an earlier member.
pub struct Unpacker {
    /// Circular dictionary. `len` counts bytes ever written; index `n` lives
    /// at `window[n & window_mask]`.
    window: Vec<u8>,
    window_mask: usize,
    dict_limit: usize,
    /// Absolute count of bytes written into `window`.
    len: usize,
    /// Absolute offset where the current member started, so a member's
    /// output is `window[member_start..len]`.
    member_start: usize,
    /// Output of the current member, already filter-adjusted.
    out: Vec<u8>,
    /// Declared size of the current member, when known.
    unpacked_target: Option<u64>,
    tables: Option<Tables>,
    /// Most-recent-first distance cache.
    dist_cache: [usize; 4],
    last_len: usize,
    filters: Vec<FilterInfo>,
    last_filter_start: usize,
    last_filter_len: usize,
}

impl Unpacker {
    /// A decompressor with a `dict_size`-byte window.
    pub fn new(dict_size: u64) -> Unpacker {
        let dict_limit = (dict_size.max(64 * 1024)) as usize;
        // Round the window up to a power of two so the mask is a single AND.
        let mut cap = 1usize;
        while cap < dict_limit {
            cap <<= 1;
        }
        Unpacker {
            window: vec![0u8; cap],
            window_mask: cap - 1,
            dict_limit,
            len: 0,
            member_start: 0,
            out: Vec::new(),
            unpacked_target: None,
            tables: None,
            dist_cache: [0; 4],
            last_len: 0,
            filters: Vec::new(),
            last_filter_start: 0,
            last_filter_len: 0,
        }
    }

    /// Declare a new member. `unpacked_size` is checked at [`finish`].
    ///
    /// Only the member-scoped state resets. The dictionary, Huffman
    /// tables, distance cache and last match length belong to the solid
    /// group and carry over: a later member's blocks may say "no tables"
    /// and its matches may reference bytes of an earlier member.
    pub fn begin_member(&mut self, unpacked_size: Option<u64>) {
        self.member_start = self.len;
        self.out.clear();
        self.unpacked_target = unpacked_size;
    }

    /// Append raw bytes to the dictionary without decoding (a stored
    /// member inside a solid group): the bytes occupy the window for
    /// subsequent members. The caller returns the raw data itself as the
    /// member's output.
    pub fn write_stored(&mut self, data: &[u8]) {
        let mask = self.window_mask;
        for &b in data {
            self.window[self.len & mask] = b;
            self.len += 1;
        }
    }

    /// Feed one packed area. A member may arrive in one call; a solid group
    /// is several calls against the same window.
    pub fn run(&mut self, data: &[u8]) -> Result<()> {
        let mut offset = 0usize;
        let mut last_block = false;
        let mut blocks = 0usize;
        while !last_block {
            if data.len() - offset < 3 {
                return Err(Error::Truncated);
            }
            let flags = data[offset];
            let cksum = data[offset + 1];
            let byte_count = ((flags >> 3) & 7) as usize;
            if byte_count > 2 {
                return Err(Error::Malformed("block header size field too big"));
            }
            let size_bytes = byte_count + 1;
            if data.len() - offset < 2 + size_bytes {
                return Err(Error::Truncated);
            }
            let mut block_size: usize = 0;
            for i in 0..size_bytes {
                block_size |= (data[offset + 2 + i] as usize) << (8 * i);
            }
            // The header's check byte is the XOR of the constant, the flags
            // and each size byte — a cheap guard against a misaligned
            // stream being read as a block header.
            let calc = 0x5Au8
                ^ flags
                ^ (block_size as u8)
                ^ ((block_size >> 8) as u8)
                ^ ((block_size >> 16) as u8);
            if calc != cksum {
                return Err(Error::BadCrc("rar5 block header"));
            }
            offset += 2 + size_bytes;
            if data.len() - offset < block_size {
                return Err(Error::Truncated);
            }
            let block = &data[offset..offset + block_size];
            offset += block_size;

            // The bit reader peeks up to 5 bytes ahead; pad so peeks at the
            // tail see zeros rather than erroring. Decoding is terminated by
            // the block's valid-bit count, not by the padding.
            let mut block_ext = block.to_vec();
            block_ext.extend_from_slice(&[0u8; 5]);

            let bit_size = 1 + (flags & 7) as usize;
            let valid_bits = (block_size.saturating_sub(1)) * 8 + bit_size;

            let mut br = BitReader::new(&block_ext);
            if flags & 0x80 != 0 {
                self.parse_tables(&mut br)?;
            }
            if self.tables.is_none() {
                return Err(Error::Malformed("compressed data without huffman tables"));
            }

            self.decode_block(&mut br, valid_bits)?;

            last_block = flags & 0x40 != 0;
            blocks += 1;
            if blocks > data.len() {
                return Err(Error::Malformed("too many blocks"));
            }
        }
        self.apply_ready_filters()
    }

    /// Conclude the current member: verify its declared size and return the
    /// produced bytes. The window and decoder state stay available for the
    /// next solid member.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let produced = self.len - self.member_start;
        if let Some(t) = self.unpacked_target {
            if produced as u64 != t {
                return Err(Error::Malformed("unpacked size mismatch"));
            }
        }
        if !self.filters.is_empty() {
            // A filter whose range never completed inside this member.
            return Err(Error::Malformed(
                "filter range out of order or out of bounds",
            ));
        }
        Ok(core::mem::take(&mut self.out))
    }

    // ------------------------------------------------------------ tables

    /// Read this block's Huffman tables.
    ///
    /// Two layers: first the 20 code lengths of the *table-describing* code,
    /// packed as nibbles with a zero-run escape; then `HUFF_TABLE_SIZE`
    /// lengths of the real tables, RLE-coded through that code.
    fn parse_tables(&mut self, br: &mut BitReader) -> Result<()> {
        // Layer 1: nibbles with a zero-run RLE. 15 is the escape: the next
        // nibble is the run length of zeros, with the special case that a
        // second 15 means the literal length 15.
        let mut bit_length = [0u8; HUFF_BC];
        let mut i = 0usize;
        let mut mask = 0xF0u8;
        let mut shift = 4u8;
        let mut w = 0usize;
        while w < HUFF_BC {
            // Read one nibble from the raw block bytes, not through the bit
            // reader: this layer is nibble-aligned, not bit-aligned.
            let byte = *br.data_byte(i).ok_or(Error::Truncated)?;
            let value = (byte & mask) >> shift;
            if mask == 0x0F {
                i += 1;
            }
            mask ^= 0xFF;
            shift ^= 4;

            const ESCAPE: u8 = 15;
            if value == ESCAPE {
                let byte = *br.data_byte(i).ok_or(Error::Truncated)?;
                let value2 = (byte & mask) >> shift;
                if mask == 0x0F {
                    i += 1;
                }
                mask ^= 0xFF;
                shift ^= 4;
                if value2 == 0 {
                    bit_length[w] = ESCAPE;
                    w += 1;
                } else {
                    for _ in 0..(value2 + 2) {
                        if w >= HUFF_BC {
                            break;
                        }
                        bit_length[w] = 0;
                        w += 1;
                    }
                }
            } else {
                bit_length[w] = value;
                w += 1;
            }
        }
        // Re-sync the bit reader to the nibble boundary the RLE ended on:
        // `bit` is how many bits of `pos` are consumed, and the next nibble
        // begins at `shift ^ 4`'s complement within the current byte.
        br.seek_byte_bit(i, shift ^ 4);

        let bd = DecodeTable::build(&bit_length, HUFF_BC)?;

        // Layer 2: the real table lengths, RLE-coded through `bd`.
        // 0..=15 is a literal length. The rest are two families of two
        // lengths each: 16/17 repeat the *previous* entry, 18/19 fill
        // *zeroes*, and in each family the first is the short form
        // (3 + 3 bits, 3..=10) and the second the long (11 + 7 bits,
        // 11..=138).
        let mut table = [0u8; HUFF_TABLE_SIZE];
        let mut idx = 0usize;
        while idx < HUFF_TABLE_SIZE {
            let num = bd.decode(br)?;
            if num < 16 {
                table[idx] = num as u8;
                idx += 1;
            } else if num < 18 {
                // 16/17: repeat the previous entry n times.
                let n = if num == 16 {
                    br.take(3)? as usize + 3
                } else {
                    br.take(7)? as usize + 11
                };
                if idx == 0 {
                    return Err(Error::Malformed("repeat with no previous length"));
                }
                let prev = table[idx - 1];
                for _ in 0..n {
                    if idx >= HUFF_TABLE_SIZE {
                        break;
                    }
                    table[idx] = prev;
                    idx += 1;
                }
            } else if num < 20 {
                // 18/19: fill zeroes n times.
                let n = if num == 18 {
                    br.take(3)? as usize + 3
                } else {
                    br.take(7)? as usize + 11
                };
                for _ in 0..n {
                    if idx >= HUFF_TABLE_SIZE {
                        break;
                    }
                    table[idx] = 0;
                    idx += 1;
                }
            } else {
                return Err(Error::Malformed("unknown table code"));
            }
        }

        let ld = DecodeTable::build(&table[0..HUFF_NC], HUFF_NC)?;
        let dd = DecodeTable::build(&table[HUFF_NC..HUFF_NC + HUFF_DC], HUFF_DC)?;
        let ldd = DecodeTable::build(
            &table[HUFF_NC + HUFF_DC..HUFF_NC + HUFF_DC + HUFF_LDC],
            HUFF_LDC,
        )?;
        let rd = DecodeTable::build(
            &table[HUFF_NC + HUFF_DC + HUFF_LDC..HUFF_TABLE_SIZE],
            HUFF_RC,
        )?;
        self.tables = Some(Tables { ld, dd, ldd, rd });
        Ok(())
    }

    // ---------------------------------------------------------- commands

    /// Decode commands until the block's valid bits run out.
    fn decode_block(&mut self, br: &mut BitReader, valid_bits: usize) -> Result<()> {
        loop {
            if br.bit_pos() >= valid_bits {
                break;
            }
            let num = {
                let t = self.tables.as_ref().ok_or(Error::Malformed("no tables"))?;
                t.ld.decode(br)?
            };

            if num < 256 {
                self.push_byte(num as u8)?;
            } else if num >= 262 {
                // New match: length code plus distance slot.
                let len_code = decode_code_length(br, num - 262)?;
                let dist_slot = {
                    let t = self.tables.as_ref().ok_or(Error::Malformed("no tables"))?;
                    t.dd.decode(br)?
                } as usize;
                let (dbits, mut dist) = if dist_slot < 4 {
                    (0usize, 1usize + dist_slot)
                } else {
                    let dbits = dist_slot / 2 - 1;
                    (dbits, 1 + ((2 | (dist_slot & 1)) << dbits))
                };

                if dbits > 0 {
                    if dbits >= 4 {
                        if dbits > 4 {
                            let add32 = br.peek32()?;
                            br.skip((dbits - 4) as u32);
                            dist += ((add32 >> (36 - dbits)) << 4) as usize;
                        }
                        let low_dist = {
                            let t = self.tables.as_ref().ok_or(Error::Malformed("no tables"))?;
                            t.ldd.decode(br)?
                        } as usize;
                        dist = dist
                            .checked_add(low_dist)
                            .ok_or(Error::Malformed("distance overflow"))?;
                    } else {
                        dist += br.take(dbits as u32)? as usize;
                    }
                }

                // Longer distances buy extra length, because far matches
                // are typically of larger runs.
                let mut len = len_code;
                if dist > 0x100 {
                    len += 1;
                    if dist > 0x2000 {
                        len += 1;
                        if dist > 0x40000 {
                            len += 1;
                        }
                    }
                }

                self.dist_cache_push(dist);
                self.last_len = len;
                self.copy_string(len, dist)?;
            } else if num == 256 {
                self.parse_filter(br)?;
            } else if num == 257 {
                if self.last_len != 0 {
                    let d = self.dist_cache[0];
                    self.copy_string(self.last_len, d)?;
                }
            } else {
                // 258..=261: reuse a cached distance, moving it to front.
                let idx = (num - 258) as usize;
                let dist = self.dist_cache_touch(idx);
                let len_slot = {
                    let t = self.tables.as_ref().ok_or(Error::Malformed("no tables"))?;
                    t.rd.decode(br)?
                };
                let len = decode_code_length(br, len_slot)?;
                self.last_len = len;
                self.copy_string(len, dist)?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------- matches

    /// Append one literal to the window and the member output.
    #[inline]
    fn push_byte(&mut self, b: u8) -> Result<()> {
        self.window[self.len & self.window_mask] = b;
        self.len += 1;
        self.out.push(b);
        self.apply_ready_filters()
    }

    /// Copy `len` bytes from `dist` back in the window. A distance larger
    /// than what has been written is a malformed stream, not a wrap-around
    /// read of whatever the window happens to hold.
    fn copy_string(&mut self, len: usize, dist: usize) -> Result<()> {
        if dist == 0 {
            return Err(Error::Malformed("zero match distance"));
        }
        if dist > self.len {
            return Err(Error::Malformed("match distance beyond output"));
        }
        for _ in 0..len {
            let b = self.window[(self.len - dist) & self.window_mask];
            self.window[self.len & self.window_mask] = b;
            self.len += 1;
            self.out.push(b);
        }
        self.apply_ready_filters()
    }

    #[inline]
    fn dist_cache_push(&mut self, value: usize) {
        self.dist_cache[3] = self.dist_cache[2];
        self.dist_cache[2] = self.dist_cache[1];
        self.dist_cache[1] = self.dist_cache[0];
        self.dist_cache[0] = value;
    }

    /// Return cache slot `idx` and move it to the front (move-to-front, so
    /// a distance reused often stays at slot 0).
    #[inline]
    fn dist_cache_touch(&mut self, idx: usize) -> usize {
        let dist = self.dist_cache[idx];
        for i in (1..=idx).rev() {
            self.dist_cache[i] = self.dist_cache[i - 1];
        }
        self.dist_cache[0] = dist;
        dist
    }

    // ------------------------------------------------------------- filters

    /// Read one filter declaration.
    fn parse_filter(&mut self, br: &mut BitReader) -> Result<()> {
        let block_start = parse_filter_data(br)? as usize;
        let block_length = parse_filter_data(br)? as usize;
        let ftype = br.take(3)? as u8;

        // A filter range must not overlap the previous one and must fit in
        // half the dictionary, which is the format's own bound.
        let valid_start = self.last_filter_start == 0
            || self.len + block_start >= self.last_filter_start + self.last_filter_len;
        if !(4..=0x400000).contains(&block_length)
            || !valid_start
            || block_length > self.dict_limit / 2
        {
            return Err(Error::Malformed("invalid filter parameters"));
        }

        let mut channels = 0usize;
        if ftype == FILTER_DELTA {
            channels = br.take(5)? as usize + 1;
        }

        let start = self.len + block_start;
        self.filters.push(FilterInfo {
            ftype,
            block_start: start,
            block_length,
            channels,
        });
        self.last_filter_start = start;
        self.last_filter_len = block_length;
        Ok(())
    }

    /// Apply every filter whose region is now fully decoded. Filters are
    /// declared and complete in stream order; a region is only readable from
    /// the circular window while its last byte is the most recent output, so
    /// each filter is applied the moment its range completes, replacing the
    /// region bytes in the member output.
    fn apply_ready_filters(&mut self) -> Result<()> {
        while let Some(f) = self.filters.first() {
            let end = f.block_start + f.block_length;
            if end > self.len {
                break;
            }
            let f = self.filters.remove(0);
            let mut region = Vec::with_capacity(f.block_length);
            for p in f.block_start..end {
                region.push(self.at(p));
            }
            let filtered = run_filter(&f, &region)?;
            let start = f
                .block_start
                .checked_sub(self.member_start)
                .ok_or(Error::Malformed("filter before member start"))?;
            let out_end = start
                .checked_add(filtered.len())
                .ok_or(Error::Malformed("size overflow"))?;
            if out_end > self.out.len() {
                return Err(Error::Malformed("filter range out of bounds"));
            }
            self.out[start..out_end].copy_from_slice(&filtered);
        }
        Ok(())
    }

    /// Window byte at an absolute offset.
    #[inline]
    fn at(&self, abs: usize) -> u8 {
        self.window[abs & self.window_mask]
    }
}

// ------------------------------------------------------------ free helpers

/// Length code → match length, with the extra-bits ladder: codes 0..=7 are
/// lengths 2..=9; codes 8 and up add `(4 | (code & 3)) << (code / 4 - 1)`
/// plus that many extra bits.
fn decode_code_length(br: &mut BitReader, code: u16) -> Result<usize> {
    let mut length: usize = 2;
    if code < 8 {
        length += code as usize;
    } else {
        let lbits = (code as usize) / 4 - 1;
        length += (4 | (code as usize & 3)) << lbits;
        if lbits > 0 {
            length += br.take(lbits as u32)? as usize;
        }
    }
    Ok(length)
}

/// A filter's address/length fields are a length byte then that many bytes
/// little-endian, so a field can be 1..=4 bytes.
fn parse_filter_data(br: &mut BitReader) -> Result<u32> {
    let bytes = br.take(2)? + 1;
    let mut data = 0u32;
    for i in 0..bytes {
        data |= br.take(8)? << (i * 8);
    }
    Ok(data)
}

/// Run one filter over a decoded region.
fn run_filter(f: &FilterInfo, region: &[u8]) -> Result<Vec<u8>> {
    let len = region.len();
    match f.ftype {
        FILTER_DELTA => {
            // Byte-plane de-delta: `channels` interleaved streams, each a
            // running subtraction over its own lane.
            let channels = f.channels.max(1);
            let mut out = vec![0u8; len];
            let mut src_pos = 0usize;
            for i in 0..channels {
                let mut prev: u8 = 0;
                let mut dest = i;
                while dest < len {
                    prev = prev.wrapping_sub(region[src_pos]);
                    out[dest] = prev;
                    src_pos += 1;
                    dest += channels;
                }
            }
            Ok(out)
        }
        FILTER_E8 | FILTER_E8E9 => {
            // x86 call fixup: `E8` (and `E9` in the extended form) is a
            // relative call/jump whose target is stored relative to the
            // next instruction. Convert between the archive's relative
            // form and the file's absolute form.
            const FILE_SIZE: u32 = 0x1000000;
            let extended = f.ftype == FILTER_E8E9;
            let mut buf = region.to_vec();
            let mut i = 0usize;
            while (i as i64) < (len as i64) - 4 {
                let b = region[i];
                i += 1;
                if b == 0xE8 || (extended && b == 0xE9) {
                    let offset = ((i + f.block_start) as u32) % FILE_SIZE;
                    let addr = u32::from_le_bytes([
                        region[i],
                        region[i + 1],
                        region[i + 2],
                        region[i + 3],
                    ]);
                    if addr & 0x8000_0000 != 0 {
                        if (addr.wrapping_add(offset)) & 0x8000_0000 == 0 {
                            buf[i..i + 4]
                                .copy_from_slice(&addr.wrapping_add(FILE_SIZE).to_le_bytes());
                        }
                    } else if addr.wrapping_sub(FILE_SIZE) & 0x8000_0000 != 0 {
                        buf[i..i + 4].copy_from_slice(&addr.wrapping_sub(offset).to_le_bytes());
                    }
                    i += 4;
                }
            }
            Ok(buf)
        }
        FILTER_ARM => {
            // ARM BL/BLX fixup: the 24-bit immediate is a word offset from
            // the branch, so add the absolute word position.
            let mut buf = region.to_vec();
            let mut i = 0usize;
            while (i as i64) < (len as i64) - 3 {
                if region[i + 3] == 0xEB {
                    let offset = (i + f.block_start) as u32 / 4;
                    let addr = u32::from_le_bytes([
                        region[i],
                        region[i + 1],
                        region[i + 2],
                        region[i + 3],
                    ]);
                    let mut off = addr & 0x00FF_FFFF;
                    off = off.wrapping_sub(offset);
                    buf[i] = (off & 0xFF) as u8;
                    buf[i + 1] = ((off >> 8) & 0xFF) as u8;
                    buf[i + 2] = ((off >> 16) & 0xFF) as u8;
                }
                i += 4;
            }
            Ok(buf)
        }
        _ => Err(Error::Unsupported("unknown filter type")),
    }
}
