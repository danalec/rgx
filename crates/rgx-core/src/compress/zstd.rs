// SPDX-License-Identifier: Apache-2.0

//! Zstandard, decoding only — RFC 8878.
//!
//! Independent reimplementation of the published RFC, written from the
//! format description rather than translated from libzstd or any other
//! implementation's source.
//!
//! Frames (§3.1.1) including skippable and concatenated frames, all four
//! block types (§3.1.1.2), all four literals block types (§3.1.1.3.1),
//! Huffman decoding with both the direct and the FSE-compressed weight
//! table (§4.2.1), FSE decoding (§4.1) for all three sequence symbol types
//! in all four compression modes (§3.1.1.3.2.1), sequence execution with
//! the repeat-offset history (§3.1.1.5), and the XXH64 content checksum.
//!
//! Dictionary-compressed frames (RFC 8878 §5) are refused with
//! [`CompressError::UnsupportedFormat`]: the dictionary is the one thing
//! such a frame carries.
//!
//! Reference vectors live in `rgx-adapters-archive/testdata/zstd_*`
//! (reference `zstd` CLI v1.5.7 at levels 1/3/9/19/22 including `--long`,
//! and klauspost/compress, a Go implementation that is not a binding to
//! libzstd). The in-file tests below use only what RFC 8878 itself prints.

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::cap::{Bounded, OutputCap, UNLIMITED};
use crate::compress::error::{CompressError, CompressResult};

/// Frame magic, as read little-endian from `28 B5 2F FD`.
pub const MAGIC: u32 = 0xFD2F_B528;
/// Skippable frames are `0x184D2A50` through `0x184D2A5F`.
const SKIPPABLE_MASK: u32 = 0xFFFF_FFF0;
const SKIPPABLE_START: u32 = 0x184D_2A50;
/// 4 bytes of magic plus the one-byte frame header descriptor.
const FRAME_HEADER_MIN: usize = 5;
const BLOCK_HEADER_LEN: usize = 3;
/// `Block_Maximum_Size`: the most a block can regenerate.
const BLOCK_SIZE_MAX: usize = 128 * 1024;
/// The largest table an FSE distribution may declare (§4.1.1).
const FSE_LOG_MAX: u32 = 15;
/// Four Huffman streams need a jump table and one byte of stream each.
const MIN_LITERALS_FOR_4_STREAMS: usize = 6;

/// Sequence symbol ranges (§3.1.1.3.2.2).
const MAX_LL: usize = 35;
const MAX_ML: usize = 52;
const MAX_OFF: usize = 31;
/// Per-symbol accuracy ceilings (§3.1.1.3.2.1).
const LL_FSE_LOG: u32 = 9;
const ML_FSE_LOG: u32 = 9;
const OFF_FSE_LOG: u32 = 8;
/// The FSE table that carries the Huffman weights (§4.2.1.2).
const HUF_WEIGHT_FSE_LOG: u32 = 6;
const HUF_TABLELOG_MAX: u32 = 12;

const MODE_PREDEFINED: u8 = 0;
const MODE_RLE: u8 = 1;
const MODE_FSE: u8 = 2;
const MODE_REPEAT: u8 = 3;

fn err(msg: &'static str) -> CompressError {
    CompressError::CorruptedData(msg)
}

/// Index of the most significant set bit, zero-based. `0` has none; every
/// caller here passes a non-zero value.
fn highbit(v: u32) -> u32 {
    31 - v.leading_zeros()
}

// ---------------------------------------------------------------- bit readers

/// The backward bit reader of §3.1.1.3.2.1 and §4.2.2: a stream written
/// forward and read backward, whose last byte carries a 1 bit marking the
/// end, with zero padding above it.
///
/// Bits below the start of the buffer read as zero, exactly as the
/// reference decoder's over-read does; [`BackBits::at_end`] catches it.
struct BackBits<'a> {
    data: &'a [u8],
    /// Next byte to pull in, walking down towards the start.
    ptr: isize,
    /// Unread bits, left-aligned at the top of the word; below `valid` it
    /// is zero, which is what an over-read past the start returns.
    container: u64,
    valid: u32,
    /// How many of those bits have been handed out.
    used: u32,
    consumed: u64,
    total: u64,
}

impl<'a> BackBits<'a> {
    fn new(data: &'a [u8]) -> CompressResult<Self> {
        let Some(&last) = data.last() else {
            return Err(err("empty backward bitstream"));
        };
        if last == 0 {
            return Err(err("backward bitstream ends in a zero byte"));
        }
        let marker = 7 - last.leading_zeros();
        // A well-formed stream ends with every one of its bits consumed:
        // the zero padding and the marker below, then the payload.
        let total = data.len() as u64 * 8;
        let mut s = Self {
            data,
            ptr: data.len() as isize - 1,
            container: 0,
            valid: 0,
            used: 0,
            consumed: 0,
            total,
        };
        s.fill(8);
        s.skip(8 - marker);
        Ok(s)
    }

    /// Drop what has been handed out and pull in bytes until `need` bits
    /// are held, or the start of the buffer is reached.
    fn fill(&mut self, need: u32) {
        let drop = self.used.min(self.valid);
        self.container <<= drop;
        self.valid -= drop;
        self.used -= drop;
        if self.used >= 64 {
            self.container = 0;
            self.valid = 0;
            self.used = 0;
        }
        while self.valid < need && self.ptr >= 0 {
            self.container |= (self.data[self.ptr as usize] as u64) << (56 - self.valid);
            self.valid += 8;
            self.ptr -= 1;
        }
    }

    /// The next `n` bits, the first bit read as the most significant one.
    /// `n` must be at most 32.
    fn peek(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.fill(n);
        ((self.container << self.used) >> (64 - n)) as u32
    }

    fn skip(&mut self, n: u32) {
        self.consumed += n as u64;
        self.used = (self.used + n).min(64);
    }

    fn read(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.skip(n);
        v
    }

    /// The whole stream was consumed, which is the only way a well-formed
    /// backward bitstream ends.
    fn at_end(&self) -> bool {
        self.consumed == self.total
    }

    /// A read has run past the end of the stream. Reading on yields zeros,
    /// which is what the reference decoder's over-read does.
    fn past_end(&self) -> bool {
        self.consumed > self.total
    }
}

/// The forward, least-significant-bit-first reader [`read_ncount`] uses.
/// Reads past the end of the slice yield zero bits; the caller rejects a
/// header that claimed more bytes than it had.
struct FwdBits<'a> {
    data: &'a [u8],
    bit: u64,
}

impl<'a> FwdBits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit: 0 }
    }

    fn peek(&self, n: u32) -> u32 {
        let mut v = 0u32;
        for i in 0..n {
            let at = self.bit + i as u64;
            let b = at >> 3;
            let byte = if (b as usize) < self.data.len() {
                self.data[b as usize]
            } else {
                0
            };
            v |= u32::from((byte >> (at & 7)) & 1) << i;
        }
        v
    }

    fn read(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.bit += n as u64;
        v
    }

    fn skip(&mut self, n: u32) {
        self.bit += n as u64;
    }

    /// Bytes of the header consumed so far, rounding a partial byte up.
    fn bytes_used(&self) -> usize {
        self.bit.div_ceil(8) as usize
    }
}

// ------------------------------------------------------------------ entropy

/// A normalized FSE distribution as §4.1.1 writes it: `max_symbol + 1`
/// entries whose absolute values sum to `1 << log`.
struct Norm {
    counts: Vec<i16>,
    max_symbol: usize,
    log: u32,
    used: usize,
}

/// Read an FSE normalized distribution (§4.1.1).
fn read_ncount(src: &[u8], max_symbol_in: usize) -> CompressResult<Norm> {
    let mut counts = vec![0i16; max_symbol_in + 1];
    let mut br = FwdBits::new(src);

    let log = br.read(4) + 5;
    if log > FSE_LOG_MAX {
        return Err(err("FSE accuracy log above the absolute limit"));
    }
    let mut remaining: i32 = (1i32 << log) + 1;
    let mut threshold: i32 = 1i32 << log;
    let mut nb_bits: i32 = log as i32 + 1;
    let mut charnum = 0usize;
    let mut previous0 = false;

    while remaining > 1 && charnum <= max_symbol_in {
        if previous0 {
            // A run of absent symbols, two bits per repeat of three.
            let mut repeats = 0usize;
            while br.peek(2) == 3 {
                repeats += 1;
                br.skip(2);
                if 3 * repeats > max_symbol_in + 1 {
                    break;
                }
            }
            charnum += 3 * repeats;
            charnum += br.read(2) as usize;
            if charnum > max_symbol_in {
                break;
            }
        }
        let max = (2 * threshold - 1) - remaining;
        let count = if (br.peek(nb_bits as u32 - 1) as i32) < max {
            br.read(nb_bits as u32 - 1) as i32
        } else {
            let mut v = br.read(nb_bits as u32) as i32;
            if v >= threshold {
                v -= max;
            }
            v
        };
        // The stored value is one less than the probability, so that -1
        // means "less than one" and 0 means "exactly one".
        let count = count - 1;
        remaining -= count.abs();
        counts[charnum] = count as i16;
        charnum += 1;
        previous0 = count == 0;
        if remaining < threshold {
            if remaining <= 1 {
                break;
            }
            // The next width must still span `remaining`, so the threshold
            // is the highest power of two at or below it.
            nb_bits = highbit(remaining as u32) as i32 + 1;
            threshold = 1 << (nb_bits - 1);
        }
    }

    if remaining != 1 {
        return Err(err("FSE distribution does not sum to the table size"));
    }
    if charnum == 0 || charnum > max_symbol_in + 1 {
        return Err(err("FSE distribution names the wrong number of symbols"));
    }
    if br.bytes_used() > src.len() {
        return Err(err("FSE distribution header runs past its block"));
    }
    Ok(Norm {
        counts,
        max_symbol: charnum - 1,
        log,
        used: br.bytes_used(),
    })
}

/// A built FSE decoding table: what a state decodes to, and where it goes.
struct FseTable {
    log: u32,
    symbol: Vec<u8>,
    /// `log - highbit(nextState)`: the bits a state transition consumes.
    nb_bits: Vec<u8>,
    /// `(nextState << nbBits) - tableSize`: the next state's base.
    next_state: Vec<u32>,
}

impl FseTable {
    fn build(norm: &Norm) -> CompressResult<Self> {
        let log = norm.log;
        let size = 1usize << log;
        let max_symbol = norm.max_symbol;
        let mut symbol = vec![0u8; size];
        let mut nb_bits = vec![0u8; size];
        let mut next_state = vec![0u32; size];
        let mut symbol_next = vec![0u32; max_symbol + 1];

        // A "less than one" probability gets a single cell at the top of the
        // table, which the spread skips.
        let mut high = size - 1;
        for (s, &n) in norm.counts[..=max_symbol].iter().enumerate() {
            if n == -1 {
                let Some(cell) = high.checked_sub(1) else {
                    return Err(err("too many low-probability symbols for the table"));
                };
                symbol[high] = s as u8;
                high = cell;
                symbol_next[s] = 1;
            } else {
                symbol_next[s] = n as u32;
            }
        }

        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut pos = 0usize;
        for (s, &n) in norm.counts[..=max_symbol].iter().enumerate() {
            for _ in 0..n.max(0) {
                symbol[pos] = s as u8;
                pos = (pos + step) & mask;
                while pos > high {
                    pos = (pos + step) & mask;
                }
            }
        }
        if pos != 0 {
            // A distribution that does not tile the table is a bad header.
            return Err(err("FSE distribution does not fill its table"));
        }

        for (u, cell) in symbol.iter().enumerate() {
            let s = *cell as usize;
            let n = symbol_next[s];
            symbol_next[s] += 1;
            let nb = log - highbit(n);
            nb_bits[u] = nb as u8;
            next_state[u] = (n << nb) - size as u32;
        }
        Ok(Self {
            log,
            symbol,
            nb_bits,
            next_state,
        })
    }
}

// ------------------------------------------------------------- huffman (4.2)

/// A Huffman decoding table: one entry per `1 << log` prefix, replicated so
/// a single `log`-bit peek resolves the symbol with no tree walk.
struct HuffmanTable {
    log: u32,
    symbol: Vec<u8>,
    nb_bits: Vec<u8>,
}

/// Read a Huffman_Tree_Description (§4.2.1) and build the decoding table.
/// Returns the number of header bytes consumed.
fn read_huffman(src: &[u8]) -> CompressResult<(HuffmanTable, usize)> {
    let Some(&head) = src.first() else {
        return Err(err("empty Huffman tree description"));
    };
    let mut weights = [0u8; 256];
    let (o_size, used) = if head >= 128 {
        // Direct representation: `head - 127` weights, two per byte.
        let n = head as usize - 127;
        if n > 255 {
            return Err(err("Huffman weight list longer than the alphabet"));
        }
        let bytes = n.div_ceil(2);
        if 1 + bytes > src.len() {
            return Err(err("Huffman weight list runs past the block"));
        }
        for (i, w) in weights[..n].iter_mut().enumerate() {
            *w = if i % 2 == 0 {
                src[1 + i / 2] >> 4
            } else {
                src[1 + i / 2] & 15
            };
        }
        (n, 1 + bytes)
    } else {
        // FSE-compressed weights; the last weight is implied, so the stream
        // carries at most 255 of them.
        if 1 + head as usize > src.len() {
            return Err(err("Huffman weight header runs past the block"));
        }
        let decoded = huf_fse_decode_weights(&src[1..1 + head as usize])?;
        let n = decoded.len();
        if n > 255 {
            return Err(err("Huffman weight list longer than the alphabet"));
        }
        weights[..n].copy_from_slice(&decoded);
        (n, 1 + head as usize)
    };

    let mut rank = [0u32; (HUF_TABLELOG_MAX + 1) as usize];
    let mut total = 0u32;
    for &w in &weights[..o_size] {
        if w as u32 > HUF_TABLELOG_MAX {
            return Err(err("Huffman weight above the table limit"));
        }
        rank[w as usize] += 1;
        total += (1u32 << w) >> 1;
    }
    if total == 0 {
        return Err(err("Huffman weights are all zero"));
    }
    let log = highbit(total) + 1;
    if log > HUF_TABLELOG_MAX {
        return Err(err("Huffman table log above the limit"));
    }
    // The final weight is implied: the weights must complete a power of two.
    let rest = (1u32 << log) - total;
    if rest == 0 || (1u32 << highbit(rest)) != rest {
        return Err(err("Huffman weights do not complete a power of two"));
    }
    let last = highbit(rest) + 1;
    weights[o_size] = last as u8;
    rank[last as usize] += 1;
    // By construction there are at least two symbols of weight 1, an even
    // number of them.
    if rank[1] < 2 || rank[1] & 1 != 0 {
        return Err(err("Huffman weights cannot form a tree"));
    }

    // Symbols ordered by weight and then by value; weight 0 means "absent"
    // and never reaches the table.
    let nb_symbols = o_size + 1;
    let mut order = vec![0u8; nb_symbols];
    let mut rank_start = [0u32; (HUF_TABLELOG_MAX + 1) as usize];
    let mut next = 0u32;
    for (w, &c) in rank.iter().enumerate() {
        rank_start[w] = next;
        next += c;
    }
    for (sym, &w) in weights[..nb_symbols].iter().enumerate() {
        let w = w as usize;
        order[rank_start[w] as usize] = sym as u8;
        rank_start[w] += 1;
    }

    let size = 1usize << log;
    let mut symbol = vec![0u8; size];
    let mut nb_bits = vec![0u8; size];
    let mut sym = rank[0];
    let mut start = 0usize;
    for (w, &count) in rank.iter().enumerate().take(log as usize + 1).skip(1) {
        let length = (1usize << w) >> 1;
        let bits = (log + 1 - w as u32) as u8;
        for _ in 0..count {
            let s = order[sym as usize];
            symbol[start..start + length].fill(s);
            nb_bits[start..start + length].fill(bits);
            start += length;
            sym += 1;
        }
    }
    Ok((
        HuffmanTable {
            log,
            symbol,
            nb_bits,
        },
        used,
    ))
}

/// Decode the Huffman weights with a 6-bit-accuracy FSE table (§4.2.1.2).
fn huf_fse_decode_weights(src: &[u8]) -> CompressResult<Vec<u8>> {
    let norm = read_ncount(src, 255)?;
    if norm.log > HUF_WEIGHT_FSE_LOG {
        return Err(err("Huffman weight table accuracy log above 6"));
    }
    let table = FseTable::build(&norm)?;
    let body = &src[norm.used..];
    if body.is_empty() {
        return Err(err("empty Huffman weight bitstream"));
    }
    let mut br = BackBits::new(body)?;
    // A byte-symbol FSE stream runs two states, alternating, over one bit
    // stream: the bit stream is the two initial states and then every
    // symbol either state decodes. The stream running out is what ends the
    // list, so the loop below is the count.
    let mut a = br.read(table.log) as usize;
    let mut b = br.read(table.log) as usize;
    let mut out = Vec::new();
    loop {
        fse_push(&table, &mut a, &mut br, &mut out)?;
        if br.past_end() {
            fse_push(&table, &mut b, &mut br, &mut out)?;
            return Ok(out);
        }
        fse_push(&table, &mut b, &mut br, &mut out)?;
        if br.past_end() {
            fse_push(&table, &mut a, &mut br, &mut out)?;
            return Ok(out);
        }
    }
}

fn fse_push(
    table: &FseTable,
    state: &mut usize,
    br: &mut BackBits<'_>,
    out: &mut Vec<u8>,
) -> CompressResult<()> {
    if *state >= table.symbol.len() {
        return Err(err("FSE state out of range"));
    }
    if out.len() >= 255 {
        return Err(err("FSE stream longer than its alphabet"));
    }
    out.push(table.symbol[*state]);
    *state = table.next_state[*state] as usize + br.read(table.nb_bits[*state] as u32) as usize;
    Ok(())
}

/// Decode `out.len()` literals from one Huffman stream (§4.2.2).
fn huff_decode_stream(table: &HuffmanTable, src: &[u8], out: &mut [u8]) -> CompressResult<()> {
    if out.is_empty() {
        return Ok(());
    }
    let mut br = BackBits::new(src)?;
    for cell in out.iter_mut() {
        let idx = br.peek(table.log) as usize;
        *cell = table.symbol[idx];
        br.skip(table.nb_bits[idx] as u32);
    }
    if !br.at_end() {
        return Err(err("Huffman stream did not end where its length said"));
    }
    Ok(())
}

/// Decode the four interleaved streams of a large literals block, split by
/// the 6-byte jump table (§3.1.1.3.1.6).
fn huff_decode_four(table: &HuffmanTable, src: &[u8], out: &mut [u8]) -> CompressResult<()> {
    if src.len() < 6 {
        return Err(err("Huffman jump table runs past the literals block"));
    }
    if out.len() < MIN_LITERALS_FOR_4_STREAMS {
        return Err(err("four Huffman streams need at least six literals"));
    }
    let l1 = u16::from_le_bytes([src[0], src[1]]) as usize;
    let l2 = u16::from_le_bytes([src[2], src[3]]) as usize;
    let l3 = u16::from_le_bytes([src[4], src[5]]) as usize;
    if 6 + l1 + l2 + l3 > src.len() {
        return Err(err("Huffman jump table overruns the literals block"));
    }
    // Stream i decodes the i-th quarter of the literals; the last one
    // takes whatever is left, so the four add up to `out.len()`.
    let lens = [l1, l2, l3, src.len() - 6 - l1 - l2 - l3];
    let segment = out.len().div_ceil(4);
    let bounds = [0usize, segment, 2 * segment, 3 * segment];
    let mut at = 6usize;
    for i in 0..4 {
        let end = if i == 3 {
            out.len()
        } else {
            bounds[i + 1].min(out.len())
        };
        huff_decode_stream(table, &src[at..at + lens[i]], &mut out[bounds[i]..end])?;
        at += lens[i];
    }
    Ok(())
}

// ------------------------------------------------------------------ defaults

/// Predefined_Mode decoding table for literals length codes: (symbol, state
/// transition bits, next state). RFC 8878 Appendix A.1.
const LL_PREDEFINED: [(u8, u8, u32); 64] = [
    (0, 4, 0),
    (0, 4, 16),
    (1, 5, 32),
    (3, 5, 0),
    (4, 5, 0),
    (6, 5, 0),
    (7, 5, 0),
    (9, 5, 0),
    (10, 5, 0),
    (12, 5, 0),
    (14, 6, 0),
    (16, 5, 0),
    (18, 5, 0),
    (19, 5, 0),
    (21, 5, 0),
    (22, 5, 0),
    (24, 5, 0),
    (25, 5, 32),
    (26, 5, 0),
    (27, 6, 0),
    (29, 6, 0),
    (31, 6, 0),
    (0, 4, 32),
    (1, 4, 0),
    (2, 5, 0),
    (4, 5, 32),
    (5, 5, 0),
    (7, 5, 32),
    (8, 5, 0),
    (10, 5, 32),
    (11, 5, 0),
    (13, 6, 0),
    (16, 5, 32),
    (17, 5, 0),
    (19, 5, 32),
    (20, 5, 0),
    (22, 5, 32),
    (23, 5, 0),
    (25, 4, 0),
    (25, 4, 16),
    (26, 5, 32),
    (28, 6, 0),
    (30, 6, 0),
    (0, 4, 48),
    (1, 4, 16),
    (2, 5, 32),
    (3, 5, 32),
    (5, 5, 32),
    (6, 5, 32),
    (8, 5, 32),
    (9, 5, 32),
    (11, 5, 32),
    (12, 5, 32),
    (15, 6, 0),
    (17, 5, 32),
    (18, 5, 32),
    (20, 5, 32),
    (21, 5, 32),
    (23, 5, 32),
    (24, 5, 32),
    (35, 6, 0),
    (34, 6, 0),
    (33, 6, 0),
    (32, 6, 0),
];

/// Predefined_Mode decoding table for match length codes. RFC 8878
/// Appendix A.2.
const ML_PREDEFINED: [(u8, u8, u32); 64] = [
    (0, 6, 0),
    (1, 4, 0),
    (2, 5, 32),
    (3, 5, 0),
    (5, 5, 0),
    (6, 5, 0),
    (8, 5, 0),
    (10, 6, 0),
    (13, 6, 0),
    (16, 6, 0),
    (19, 6, 0),
    (22, 6, 0),
    (25, 6, 0),
    (28, 6, 0),
    (31, 6, 0),
    (33, 6, 0),
    (35, 6, 0),
    (37, 6, 0),
    (39, 6, 0),
    (41, 6, 0),
    (43, 6, 0),
    (45, 6, 0),
    (1, 4, 16),
    (2, 4, 0),
    (3, 5, 32),
    (4, 5, 0),
    (6, 5, 32),
    (7, 5, 0),
    (9, 6, 0),
    (12, 6, 0),
    (15, 6, 0),
    (18, 6, 0),
    (21, 6, 0),
    (24, 6, 0),
    (27, 6, 0),
    (30, 6, 0),
    (32, 6, 0),
    (34, 6, 0),
    (36, 6, 0),
    (38, 6, 0),
    (40, 6, 0),
    (42, 6, 0),
    (44, 6, 0),
    (1, 4, 32),
    (1, 4, 48),
    (2, 4, 16),
    (4, 5, 32),
    (5, 5, 32),
    (7, 5, 32),
    (8, 5, 32),
    (11, 6, 0),
    (14, 6, 0),
    (17, 6, 0),
    (20, 6, 0),
    (23, 6, 0),
    (26, 6, 0),
    (29, 6, 0),
    (52, 6, 0),
    (51, 6, 0),
    (50, 6, 0),
    (49, 6, 0),
    (48, 6, 0),
    (47, 6, 0),
    (46, 6, 0),
];

/// Predefined_Mode decoding table for offset codes. RFC 8878 Appendix
/// A.3.
const OF_PREDEFINED: [(u8, u8, u32); 32] = [
    (0, 5, 0),
    (6, 4, 0),
    (9, 5, 0),
    (15, 5, 0),
    (21, 5, 0),
    (3, 5, 0),
    (7, 4, 0),
    (12, 5, 0),
    (18, 5, 0),
    (23, 5, 0),
    (5, 5, 0),
    (8, 4, 0),
    (14, 5, 0),
    (20, 5, 0),
    (2, 5, 0),
    (7, 4, 16),
    (11, 5, 0),
    (17, 5, 0),
    (22, 5, 0),
    (4, 5, 0),
    (8, 4, 16),
    (13, 5, 0),
    (19, 5, 0),
    (1, 5, 0),
    (6, 4, 16),
    (10, 5, 0),
    (16, 5, 0),
    (28, 5, 0),
    (27, 5, 0),
    (26, 5, 0),
    (25, 5, 0),
    (24, 5, 0),
];

/// Literals length code baseline and extra bits (§3.1.1.3.2.2, Table 10).
const LL_BASE: [u32; MAX_LL + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
const LL_BITS: [u8; MAX_LL + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];

/// Match length code baseline and extra bits (Table 17).
const ML_BASE: [u32; MAX_ML + 1] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];
const ML_BITS: [u8; MAX_ML + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];
/// Offset code baseline and extra bits (§3.1.1.3.2.1): `(1 << code) - 3`
/// and `code` bits, with codes 0 and 1 special.
const OF_BASE: [u32; MAX_OFF + 1] = [
    0, 1, 1, 5, 13, 29, 61, 125, 253, 509, 1021, 2045, 4093, 8189, 16381, 32765, 65533, 131069,
    262141, 524285, 1048573, 2097149, 4194301, 8388605, 16777213, 33554429, 67108861, 134217725,
    268435453, 536870909, 1073741821, 2147483645,
];
const OF_BITS: [u8; MAX_OFF + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// A sequence symbol's decoding table, with the code baseline and extra-bit
/// count folded in so the sequence loop is a flat lookup.
#[derive(Clone, Default)]
struct SeqTable {
    log: u32,
    baseline: Vec<u32>,
    extra: Vec<u8>,
    nb_bits: Vec<u8>,
    next_state: Vec<u32>,
}

impl SeqTable {
    /// Build from a normalized distribution and the code table it indexes.
    fn from_norm(norm: &Norm, base: &[u32], bits: &[u8]) -> CompressResult<Self> {
        let t = FseTable::build(norm)?;
        let mut out = Self {
            log: t.log,
            baseline: Vec::with_capacity(t.symbol.len()),
            extra: Vec::with_capacity(t.symbol.len()),
            nb_bits: t.nb_bits,
            next_state: t.next_state,
        };
        for &sym in &t.symbol {
            let s = sym as usize;
            if s >= base.len() {
                return Err(err("FSE table names a symbol outside its code range"));
            }
            out.baseline.push(base[s]);
            out.extra.push(bits[s]);
        }
        Ok(out)
    }

    /// Predefined_Mode. The table is fixed data rather than something
    /// derived from the default distribution: the FSE spread that builds a
    /// table from a distribution does not reproduce these, and a decoder
    /// that derived them would read every Predefined_Mode block as noise.
    fn predefined(
        table: &[(u8, u8, u32)],
        log: u32,
        base: &[u32],
        bits: &[u8],
    ) -> CompressResult<Self> {
        let mut out = Self {
            log,
            baseline: Vec::with_capacity(table.len()),
            extra: Vec::with_capacity(table.len()),
            nb_bits: Vec::with_capacity(table.len()),
            next_state: Vec::with_capacity(table.len()),
        };
        for &(sym, nb, next) in table {
            let s = sym as usize;
            if s >= base.len() {
                return Err(err(
                    "predefined table names a symbol outside its code range",
                ));
            }
            out.baseline.push(base[s]);
            out.extra.push(bits[s]);
            out.nb_bits.push(nb);
            out.next_state.push(next);
        }
        Ok(out)
    }

    /// RLE_Mode: one symbol for every sequence, and no state bits.
    fn rle(symbol: u8, base: &[u32], bits: &[u8]) -> Self {
        let s = symbol as usize;
        Self {
            log: 0,
            baseline: vec![base[s]],
            extra: vec![bits[s]],
            nb_bits: vec![0],
            next_state: vec![0],
        }
    }
}

/// The three predefined tables, built once per decode rather than per block.
struct Predefined {
    ll: SeqTable,
    of: SeqTable,
    ml: SeqTable,
}

impl Predefined {
    fn new() -> CompressResult<Self> {
        Ok(Self {
            ll: SeqTable::predefined(&LL_PREDEFINED, 6, &LL_BASE, &LL_BITS)?,
            of: SeqTable::predefined(&OF_PREDEFINED, 5, &OF_BASE, &OF_BITS)?,
            ml: SeqTable::predefined(&ML_PREDEFINED, 6, &ML_BASE, &ML_BITS)?,
        })
    }
}

// ------------------------------------------------------------------ decoding

/// The entropy a frame carries from one compressed block to the next, plus
/// the repeat-offset history (§3.1.1.5). Reset at every frame.
struct FrameState {
    huf: Option<HuffmanTable>,
    ll: SeqTable,
    of: SeqTable,
    ml: SeqTable,
    have_fse: bool,
    /// Repeat_Offset_1..3, most recent first.
    rep: [u32; 3],
}

impl FrameState {
    fn new() -> Self {
        Self {
            huf: None,
            ll: SeqTable::default(),
            of: SeqTable::default(),
            ml: SeqTable::default(),
            have_fse: false,
            rep: [1, 4, 8],
        }
    }
}

/// A Zstandard frame decoder.
pub struct ZstdDecoder {
    _priv: (),
}

impl Default for ZstdDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ZstdDecoder {
    pub const fn new() -> Self {
        Self { _priv: () }
    }

    /// Decode every frame in `data` under an unlimited cap.
    pub fn decode(&self, data: &[u8]) -> CompressResult<Vec<u8>> {
        Self::new().decode_bounded(data, UNLIMITED).map(|b| b.bytes)
    }

    /// Decode every frame in `data`, stopping at `limit` bytes.
    ///
    /// A frame that declares more content than `limit` is refused from its
    /// header, before anything is expanded: a bomb should not cost what it
    /// was built to cost.
    pub fn decode_bounded(&self, data: &[u8], limit: u64) -> CompressResult<Bounded> {
        let pre = Predefined::new()?;
        let mut out = Vec::new();
        let mut cap = OutputCap::new(limit);
        let mut declared: Option<u64> = None;
        let mut at = 0usize;
        let mut frames = 0usize;

        while at < data.len() {
            at += decode_one_frame(data, at, &mut out, &mut cap, &mut declared, &pre)?;
            frames += 1;
            if cap.capped() {
                return Ok(Bounded::stopped(out, declared, limit));
            }
        }
        if frames == 0 {
            return Err(err("no zstd frame"));
        }
        Ok(Bounded::complete(out, declared, limit))
    }
}

/// Decode one frame, or skip one skippable frame, starting at `at`.
/// Returns how many input bytes it consumed.
fn decode_one_frame(
    data: &[u8],
    at: usize,
    out: &mut Vec<u8>,
    cap: &mut OutputCap,
    declared: &mut Option<u64>,
    pre: &Predefined,
) -> CompressResult<usize> {
    if data.len() - at < 4 {
        return Err(err("truncated zstd frame magic"));
    }
    let magic = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
    if magic & SKIPPABLE_MASK == SKIPPABLE_START {
        if data.len() - at < 8 {
            return Err(err("truncated skippable frame header"));
        }
        let n =
            u32::from_le_bytes([data[at + 4], data[at + 5], data[at + 6], data[at + 7]]) as usize;
        if data.len() - at - 8 < n {
            return Err(err("skippable frame runs past the input"));
        }
        return Ok(8 + n);
    }
    if magic != MAGIC {
        return Err(err("not a zstd frame"));
    }
    if data.len() - at < FRAME_HEADER_MIN {
        return Err(err("truncated zstd frame header"));
    }

    let fhd = data[at + 4];
    if fhd & 0x08 != 0 {
        return Err(err("reserved bit set in the frame header descriptor"));
    }
    let fcs_code = fhd >> 6;
    let single_segment = fhd & 0x20 != 0;
    let has_checksum = fhd & 0x04 != 0;
    let dict_id_size = [0usize, 1, 2, 4][(fhd & 3) as usize];

    let mut p = at + FRAME_HEADER_MIN;
    if !single_segment {
        // The window descriptor only bounds the window; a whole-buffer
        // decode never needs one, so the byte is counted and skipped.
        if data.get(p).is_none() {
            return Err(err("truncated window descriptor"));
        }
        p += 1;
    }
    if data.len() - p < dict_id_size {
        return Err(err("truncated dictionary id"));
    }
    let mut dict_id = 0u32;
    for i in 0..dict_id_size {
        dict_id |= (data[p + i] as u32) << (8 * i);
    }
    p += dict_id_size;
    if dict_id != 0 {
        return Err(CompressError::UnsupportedFormat(format!(
            "zstd frame needs dictionary {dict_id}"
        )));
    }

    // Frame_Content_Size: code 0 means one byte when the single-segment flag
    // is set, and no field at all when it is not.
    let fcs_size = match (fcs_code, single_segment) {
        (0, false) => 0,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    if data.len() - p < fcs_size {
        return Err(err("truncated frame content size"));
    }
    let mut content_size = 0u64;
    for i in 0..fcs_size {
        content_size |= (data[p + i] as u64) << (8 * i);
    }
    if fcs_code == 1 {
        content_size += 256;
    }
    p += fcs_size;
    if fcs_size != 0 && declared.is_none() {
        *declared = Some(content_size);
    }
    // Refuse from the header rather than after expanding the bomb.
    if fcs_size != 0 && content_size > cap.remaining() {
        cap.take(content_size);
        return Ok(data.len() - at);
    }

    let frame_start = out.len();
    let mut state = FrameState::new();
    let mut checksum = Xxh64::new();
    loop {
        if data.len() - p < BLOCK_HEADER_LEN {
            return Err(err("truncated block header"));
        }
        let bh = data[p] as u32 | (data[p + 1] as u32) << 8 | (data[p + 2] as u32) << 16;
        p += BLOCK_HEADER_LEN;
        let last = bh & 1 != 0;
        let block_type = (bh >> 1) & 3;
        let block_size = (bh >> 3) as usize;
        if data.len() - p < block_size && block_type != 1 {
            return Err(err("block runs past the input"));
        }

        let before = out.len();
        match block_type {
            0 => {
                if !cap.take(block_size as u64) {
                    return Ok(p - at);
                }
                out.extend_from_slice(&data[p..p + block_size]);
                p += block_size;
            }
            1 => {
                if data.len() - p < 1 {
                    return Err(err("truncated RLE block"));
                }
                if !cap.take(block_size as u64) {
                    return Ok(p - at);
                }
                let byte = data[p];
                p += 1;
                out.resize(out.len() + block_size, byte);
            }
            2 => {
                if block_size > BLOCK_SIZE_MAX {
                    return Err(err("compressed block larger than the block maximum"));
                }
                if !cap.fits(block_size as u64) {
                    cap.take(block_size as u64);
                    return Ok(p - at);
                }
                decode_compressed_block(&data[p..p + block_size], out, cap, &mut state, pre)?;
                p += block_size;
            }
            _ => return Err(err("reserved block type")),
        }
        if has_checksum {
            checksum.update(&out[before..]);
        }
        if last {
            break;
        }
    }

    if fcs_size != 0 && (out.len() - frame_start) as u64 != content_size {
        return Err(err(
            "frame produced a different size than its header declared",
        ));
    }
    if has_checksum {
        if data.len() - p < 4 {
            return Err(err("truncated content checksum"));
        }
        let want = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        let got = checksum.digest() as u32;
        if want != got {
            return Err(CompressError::CrcMismatch {
                expected: want,
                actual: got,
            });
        }
        p += 4;
    }
    Ok(p - at)
}

/// A compressed block: literals, then sequences (§3.1.1.3).
fn decode_compressed_block(
    src: &[u8],
    out: &mut Vec<u8>,
    cap: &mut OutputCap,
    state: &mut FrameState,
    pre: &Predefined,
) -> CompressResult<()> {
    if src.len() < 2 {
        return Err(err("compressed block too short to hold a literals header"));
    }
    let (literals, rest) = decode_literals(src, state)?;
    decode_sequences(rest, &literals, out, cap, state, pre)
}

/// Decode the literals section, returning `(literals, remainder)`.
fn decode_literals<'a>(
    src: &'a [u8],
    state: &mut FrameState,
) -> CompressResult<(Vec<u8>, &'a [u8])> {
    let first = src[0];
    let block_type = first & 3;
    let size_format = (first >> 2) & 3;

    let (header_len, regen, comp, four_streams) = match block_type {
        0 | 1 => {
            let (header_len, regen) = match size_format {
                // Size_Format 00 and 10 both use 1 bit and a 5-bit size.
                0 | 2 => (1usize, (first >> 3) as usize),
                1 => (2, le16(src, 0)? as usize >> 4),
                _ => (3, le24(src, 0)? as usize >> 4),
            };
            (
                header_len,
                regen,
                if block_type == 0 { regen } else { 1 },
                false,
            )
        }
        _ => {
            let lhc = le32(src, 0)?;
            match size_format {
                0 => (
                    3usize,
                    (lhc >> 4) as usize & 0x3FF,
                    (lhc >> 14) as usize & 0x3FF,
                    false,
                ),
                1 => (
                    3,
                    (lhc >> 4) as usize & 0x3FF,
                    (lhc >> 14) as usize & 0x3FF,
                    true,
                ),
                2 => (
                    4,
                    (lhc >> 4) as usize & 0x3FFF,
                    (lhc >> 18) as usize & 0x3FFF,
                    true,
                ),
                _ => {
                    let b4 = *src.get(4).ok_or_else(|| err("truncated literals header"))? as usize;
                    (
                        5,
                        (lhc >> 4) as usize & 0x3FFFF,
                        (lhc >> 22) as usize | (b4 << 10),
                        true,
                    )
                }
            }
        }
    };
    if regen > BLOCK_SIZE_MAX {
        return Err(err("literals larger than the block maximum"));
    }
    if four_streams && regen < MIN_LITERALS_FOR_4_STREAMS {
        return Err(err("four Huffman streams with too few literals"));
    }
    if src.len() < header_len + comp {
        return Err(err("literals section runs past the block"));
    }
    let body = &src[header_len..header_len + comp];

    let mut literals = vec![0u8; regen];
    match block_type {
        0 => literals.copy_from_slice(body),
        1 => literals.fill(body[0]),
        2 => {
            let (table, used) = read_huffman(body)?;
            if four_streams {
                huff_decode_four(&table, &body[used..], &mut literals)?;
            } else {
                huff_decode_stream(&table, &body[used..], &mut literals)?;
            }
            state.huf = Some(table);
        }
        _ => {
            // Treeless: the tree is the one the previous compressed literals
            // block in this frame installed.
            let table = state
                .huf
                .as_ref()
                .ok_or_else(|| err("treeless literals with no Huffman table"))?;
            if four_streams {
                huff_decode_four(table, body, &mut literals)?;
            } else {
                huff_decode_stream(table, body, &mut literals)?;
            }
        }
    }
    Ok((literals, &src[header_len + comp..]))
}

fn le16(src: &[u8], at: usize) -> CompressResult<u16> {
    let s = src
        .get(at..at + 2)
        .ok_or_else(|| err("truncated 16-bit field"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn le24(src: &[u8], at: usize) -> CompressResult<u32> {
    let s = src
        .get(at..at + 3)
        .ok_or_else(|| err("truncated 24-bit field"))?;
    Ok(s[0] as u32 | (s[1] as u32) << 8 | (s[2] as u32) << 16)
}

fn le32(src: &[u8], at: usize) -> CompressResult<u32> {
    let s = src
        .get(at..at + 4)
        .ok_or_else(|| err("truncated 32-bit field"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Build one of the three sequence FSE tables (§3.1.1.3.2.1).
// One call site per table kind (LL/OF/ML); each argument is a distinct
// per-kind constant or stream input, so a parameter struct would only rename them.
#[allow(clippy::too_many_arguments)]
fn build_seq_table(
    mode: u8,
    src: &[u8],
    max_symbol: usize,
    max_log: u32,
    predef: &SeqTable,
    base: &[u32],
    bits: &[u8],
    previous: &SeqTable,
    have_previous: bool,
) -> CompressResult<(SeqTable, usize)> {
    match mode {
        MODE_PREDEFINED => Ok((predef.clone(), 0)),
        MODE_RLE => {
            let Some(&sym) = src.first() else {
                return Err(err("truncated RLE sequence table"));
            };
            if sym as usize >= base.len() {
                return Err(err("RLE sequence symbol outside its code range"));
            }
            Ok((SeqTable::rle(sym, base, bits), 1))
        }
        MODE_FSE => {
            let norm = read_ncount(src, max_symbol)?;
            if norm.log > max_log {
                return Err(err("sequence FSE accuracy log above its limit"));
            }
            Ok((SeqTable::from_norm(&norm, base, bits)?, norm.used))
        }
        MODE_REPEAT => {
            if !have_previous {
                return Err(err("Repeat_Mode with no previous sequence table"));
            }
            Ok((previous.clone(), 0))
        }
        _ => Err(err("unknown sequence compression mode")),
    }
}

/// Resolve one sequence's offset and roll the repeat-offset history
/// (§3.1.1.5). `of_base`/`of_extra` are the offset code's baseline and
/// extra-bit count, `bits` the bits just read for them, and `ll0` whether
/// the sequence's literals length is zero — which shifts the repeat codes by
/// one, so that `Offset_Value` 1, 2 and 3 mean Repeat_Offset_2,
/// Repeat_Offset_3 and Repeat_Offset_1 - 1 respectively.
fn resolve_offset(
    rep: &mut [u32; 3],
    of_base: u32,
    of_extra: u8,
    ll0: bool,
    bits: u32,
) -> CompressResult<u32> {
    if of_extra > 1 {
        let v = of_base + bits;
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = v;
        return Ok(v);
    }
    if of_extra == 0 {
        // Offset code 0 is a repeat code with no extra bits at all.
        let sel = usize::from(ll0);
        let v = rep[sel];
        rep[1] = rep[1 - sel];
        rep[0] = v;
        return Ok(v);
    }
    let sel = of_base + u32::from(ll0) + bits;
    let v = if sel == 3 {
        rep[0].wrapping_sub(1)
    } else {
        rep[sel as usize]
    };
    if v == 0 {
        return Err(err("repeat offset resolved to zero"));
    }
    if sel != 1 {
        rep[2] = rep[1];
    }
    rep[1] = rep[0];
    rep[0] = v;
    Ok(v)
}

/// Number_of_Sequences and the bytes it occupies (§3.1.1.3.2.1): one byte
/// below 128, two up to 0x7EFF, and three from 0x7F00 on.
fn read_sequence_count(src: &[u8]) -> CompressResult<(usize, usize)> {
    let b0 = *src.first().ok_or_else(|| err("empty sequences section"))?;
    Ok(if b0 == 0 {
        (0, 1)
    } else if b0 < 128 {
        (b0 as usize, 1)
    } else if b0 == 255 {
        let v = le16(src, 1)? as usize + 0x7F00;
        (v, 3)
    } else {
        let b1 = *src.get(1).ok_or_else(|| err("truncated sequence count"))?;
        (((b0 as usize - 128) << 8) + b1 as usize, 2)
    })
}

/// Decode and execute the sequences section (§3.1.1.3.2, §3.1.1.4).
fn decode_sequences(
    src: &[u8],
    literals: &[u8],
    out: &mut Vec<u8>,
    cap: &mut OutputCap,
    state: &mut FrameState,
    pre: &Predefined,
) -> CompressResult<()> {
    let (nb_seq, p) = read_sequence_count(src)?;
    let mut p = p;
    if nb_seq == 0 {
        if p != src.len() {
            return Err(err("extraneous data after an empty sequences section"));
        }
        // The FSE tables are explicitly not updated in this case.
        if !cap.take(literals.len() as u64) {
            return Ok(());
        }
        out.extend_from_slice(literals);
        return Ok(());
    }

    let Some(&modes) = src.get(p) else {
        return Err(err("truncated symbol compression modes"));
    };
    p += 1;
    if modes & 3 != 0 {
        return Err(err("reserved bits set in the symbol compression modes"));
    }
    let have = state.have_fse;
    let (ll, n) = build_seq_table(
        modes >> 6,
        &src[p..],
        MAX_LL,
        LL_FSE_LOG,
        &pre.ll,
        &LL_BASE,
        &LL_BITS,
        &state.ll,
        have,
    )?;
    p += n;
    let (of, n) = build_seq_table(
        (modes >> 4) & 3,
        &src[p..],
        MAX_OFF,
        OFF_FSE_LOG,
        &pre.of,
        &OF_BASE,
        &OF_BITS,
        &state.of,
        have,
    )?;
    p += n;
    let (ml, n) = build_seq_table(
        (modes >> 2) & 3,
        &src[p..],
        MAX_ML,
        ML_FSE_LOG,
        &pre.ml,
        &ML_BASE,
        &ML_BITS,
        &state.ml,
        have,
    )?;
    p += n;
    if p > src.len() {
        return Err(err("sequence tables run past the block"));
    }
    state.ll = ll;
    state.of = of;
    state.ml = ml;
    state.have_fse = true;
    let (ll, of, ml) = (&state.ll, &state.of, &state.ml);

    let body = &src[p..];
    if body.is_empty() {
        return Err(err("empty sequence bitstream"));
    }
    let mut br = BackBits::new(body)?;
    let mut ll_state = br.read(ll.log) as usize;
    let mut of_state = br.read(of.log) as usize;
    let mut ml_state = br.read(ml.log) as usize;

    let mut lit_at = 0usize;
    for i in 0..nb_seq {
        if ll_state >= ll.baseline.len()
            || of_state >= of.baseline.len()
            || ml_state >= ml.baseline.len()
        {
            return Err(err("sequence state out of range"));
        }
        let (ll_base, ll_extra, ll_bits, ll_next) = (
            ll.baseline[ll_state],
            ll.extra[ll_state],
            ll.nb_bits[ll_state],
            ll.next_state[ll_state],
        );
        let (of_base, of_extra, of_bits, of_next) = (
            of.baseline[of_state],
            of.extra[of_state],
            of.nb_bits[of_state],
            of.next_state[of_state],
        );
        let (ml_base, ml_extra, ml_bits, ml_next) = (
            ml.baseline[ml_state],
            ml.extra[ml_state],
            ml.nb_bits[ml_state],
            ml.next_state[ml_state],
        );

        // The bit order is part of the format: offset bits, match length
        // bits, literals length bits, then the three state updates.
        let ll0 = ll_base == 0;
        let offset_bits = br.read(of_extra as u32);
        let offset = resolve_offset(&mut state.rep, of_base, of_extra, ll0, offset_bits)?;

        let match_len = ml_base + br.read(ml_extra as u32);
        let lit_len = ll_base + br.read(ll_extra as u32);
        if i + 1 < nb_seq {
            ll_state = ll_next as usize + br.read(ll_bits as u32) as usize;
            ml_state = ml_next as usize + br.read(ml_bits as u32) as usize;
            of_state = of_next as usize + br.read(of_bits as u32) as usize;
        }

        let end = lit_at
            .checked_add(lit_len as usize)
            .ok_or_else(|| err("literal length overflow"))?;
        if end > literals.len() {
            return Err(err("sequence wants more literals than the block holds"));
        }
        if !cap.take((lit_len + match_len) as u64) {
            return Ok(());
        }
        out.extend_from_slice(&literals[lit_at..end]);
        lit_at = end;
        // The match is measured from the position the literals left off at.
        let here = out.len();
        if offset == 0 || offset as usize > here {
            return Err(err("match offset points before the start of the frame"));
        }
        let from = here - offset as usize;
        let m = match_len as usize;
        if offset as usize >= m {
            out.extend_from_within(from..from + m);
        } else {
            // Overlapping match: take what the window holds, then keep
            // doubling it. Copying the pattern a byte at a time is what
            // makes a 128 KB match at offset 1 the slowest thing here.
            out.extend_from_within(from..from + offset as usize);
            let mut done = offset as usize;
            while done < m {
                let n = (m - done).min(done);
                let start = out.len() - done;
                out.extend_from_within(start..start + n);
                done += n;
            }
        }
    }

    if !br.at_end() {
        return Err(err("sequence bitstream did not end where its length said"));
    }
    if lit_at > literals.len() {
        return Err(err("sequences left literals unconsumed"));
    }
    // Whatever literals are left form the tail of the block.
    if !cap.take((literals.len() - lit_at) as u64) {
        return Ok(());
    }
    out.extend_from_slice(&literals[lit_at..]);
    Ok(())
}

// --------------------------------------------------------------------- XXH64

/// XXH64, seed 0, streamed. A frame's content checksum is its low 32 bits.
struct Xxh64 {
    total: u64,
    v: [u64; 4],
    tail: [u8; 32],
    tail_len: usize,
}

const P1: u64 = 11_400_714_785_074_694_791;
const P2: u64 = 14_029_467_366_897_019_727;
const P3: u64 = 1_609_587_929_392_839_161;
const P4: u64 = 9_650_029_242_287_828_579;
const P5: u64 = 2_870_177_450_012_600_261;

impl Xxh64 {
    fn new() -> Self {
        Self {
            total: 0,
            v: [P1.wrapping_add(P2), P2, 0, 0u64.wrapping_sub(P1)],
            tail: [0; 32],
            tail_len: 0,
        }
    }

    fn round(acc: u64, input: u64) -> u64 {
        acc.wrapping_add(input.wrapping_mul(P2))
            .rotate_left(31)
            .wrapping_mul(P1)
    }

    fn merge(acc: u64, val: u64) -> u64 {
        (acc ^ Self::round(0, val))
            .wrapping_mul(P1)
            .wrapping_add(P4)
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.tail_len > 0 {
            let want = 32 - self.tail_len;
            if data.len() < want {
                self.tail[self.tail_len..self.tail_len + data.len()].copy_from_slice(data);
                self.tail_len += data.len();
                return;
            }
            let (head, rest) = data.split_at(want);
            self.tail[self.tail_len..].copy_from_slice(head);
            let block = self.tail;
            self.consume32(&block);
            self.tail_len = 0;
            data = rest;
        }
        while data.len() >= 32 {
            let (head, rest) = data.split_at(32);
            self.consume32(head.try_into().unwrap());
            data = rest;
        }
        if !data.is_empty() {
            self.tail[..data.len()].copy_from_slice(data);
            self.tail_len = data.len();
        }
    }

    fn consume32(&mut self, b: &[u8; 32]) {
        for i in 0..4 {
            let lane = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
            self.v[i] = Self::round(self.v[i], lane);
        }
    }

    fn digest(&self) -> u64 {
        let mut h = if self.total >= 32 {
            let mut acc = self.v[0]
                .rotate_left(1)
                .wrapping_add(self.v[1].rotate_left(7))
                .wrapping_add(self.v[2].rotate_left(12))
                .wrapping_add(self.v[3].rotate_left(18));
            acc = Self::merge(acc, self.v[0]);
            acc = Self::merge(acc, self.v[1]);
            acc = Self::merge(acc, self.v[2]);
            acc = Self::merge(acc, self.v[3]);
            acc
        } else {
            P5
        };
        h = h.wrapping_add(self.total);

        let mut rest = &self.tail[..self.tail_len];
        while rest.len() >= 8 {
            let k = u64::from_le_bytes(rest[..8].try_into().unwrap());
            h ^= Self::round(0, k);
            h = h.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
            rest = &rest[8..];
        }
        if rest.len() >= 4 {
            let k = u32::from_le_bytes(rest[..4].try_into().unwrap()) as u64;
            h ^= k.wrapping_mul(P1);
            h = h.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
            rest = &rest[4..];
        }
        for &b in rest {
            h ^= (b as u64).wrapping_mul(P5);
            h = h.rotate_left(11).wrapping_mul(P1);
        }
        h ^= h >> 33;
        h = h.wrapping_mul(P2);
        h ^= h >> 29;
        h = h.wrapping_mul(P3);
        h ^= h >> 32;
        h
    }
}

/// The decompressed size the first frame in `data` declares, or `None` when
/// it declares none. Cheap enough to call before decoding a bomb.
pub fn frame_content_size(data: &[u8]) -> Option<u64> {
    if data.len() < FRAME_HEADER_MIN + 1 {
        return None;
    }
    if u32::from_le_bytes([data[0], data[1], data[2], data[3]]) != MAGIC {
        return None;
    }
    let fhd = data[4];
    let single_segment = fhd & 0x20 != 0;
    let fcs_code = fhd >> 6;
    let dict_id_size = [0usize, 1, 2, 4][(fhd & 3) as usize];
    let fcs_size = match (fcs_code, single_segment) {
        (0, false) => return None,
        (0, true) => 1,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    let mut p = FRAME_HEADER_MIN;
    if !single_segment {
        p += 1;
    }
    p += dict_id_size;
    if data.len() < p + fcs_size {
        return None;
    }
    let mut v = 0u64;
    for i in 0..fcs_size {
        v |= (data[p + i] as u64) << (8 * i);
    }
    if fcs_code == 1 {
        v += 256;
    }
    Some(v)
}

#[cfg(all(test, feature = "zstd"))]
mod tests {
    use super::*;
    use alloc::vec;

    /// Express an RFC `Offset_Value` as the offset code that produces it.
    fn offset_code(ov: u32) -> (u32, u8, u32) {
        match ov {
            1 => (OF_BASE[0], OF_BITS[0], 0),
            2 => (OF_BASE[1], OF_BITS[1], 0),
            3 => (OF_BASE[1], OF_BITS[1], 1),
            _ => {
                let off = ov - 3;
                let code = highbit(off) as usize;
                (OF_BASE[code], OF_BITS[code], off - OF_BASE[code])
            }
        }
    }

    /// The repeat-offset example table of RFC 8878 §3.1.1.5.
    ///
    /// The first seven rows are the table as printed. Rows eight and nine
    /// follow the normative text of the same section, which disagrees with
    /// two cells of the printed table (row eight's offset_value column, and
    /// row nine's third column, which is never rotated down). libzstd's
    /// decoder agrees with the text.
    #[test]
    fn the_repeat_offset_table_of_rfc_8878() {
        let mut rep = [1u32, 4, 8];
        let steps: [(u32, u32, [u32; 3], u32); 9] = [
            (1114, 11, [1111, 1, 4], 1111),
            (1, 22, [1111, 1, 4], 1111),
            (2225, 22, [2222, 1111, 1], 2222),
            (1114, 111, [1111, 2222, 1111], 1111),
            (3336, 33, [3333, 1111, 2222], 3333),
            (2, 22, [1111, 3333, 2222], 1111),
            (3, 33, [2222, 1111, 3333], 2222),
            (3, 0, [2221, 2222, 1111], 2221),
            (1, 0, [2222, 2221, 1111], 2222),
        ];
        for (i, &(ov, ll, want_rep, want_offset)) in steps.iter().enumerate() {
            let (of_base, of_extra, bits) = offset_code(ov);
            let got = resolve_offset(&mut rep, of_base, of_extra, ll == 0, bits)
                .unwrap_or_else(|e| panic!("step {i}: {e:?}"));
            assert_eq!(
                got, want_offset,
                "step {i}: offset for offset_value {ov}, ll {ll}"
            );
            assert_eq!(
                rep, want_rep,
                "step {i}: history after offset_value {ov}, ll {ll}"
            );
        }
    }

    /// XXH64 known answers from the reference implementation.
    #[test]
    fn xxh64_matches_the_reference() {
        let seq: Vec<u8> = (0..101u32).map(|i| (i * 167 + 13) as u8).collect();
        let cases: [(&[u8], u64); 7] = [
            (b"", 0xEF46_DB37_51D8_E999),
            (b"a", 0xD24E_C4F1_A98C_6E5B),
            (b"abc", 0x44BC_2CF5_AD77_0999),
            ("heiå".as_bytes(), 0xB9D3_D990_D200_1A1A),
            (b"abcdefghijklmnopqrstuvwxyz", 0xCFE1_F278_FA89_835C),
            (
                b"The quick brown fox jumps over the lazy dog",
                0x0B24_2D36_1FDA_71BC,
            ),
            (&seq, 0x3254_A36C_CC0F_3897),
        ];
        for (input, want) in cases {
            let mut h = Xxh64::new();
            h.update(input);
            assert_eq!(h.digest(), want, "XXH64 of {} bytes", input.len());
        }
    }

    /// The same answer whatever the update boundaries are. The 101-byte
    /// vector crosses three 32-byte blocks with a 5-byte tail.
    #[test]
    fn xxh64_is_independent_of_how_it_is_fed() {
        let seq: Vec<u8> = (0..101u32).map(|i| (i * 167 + 13) as u8).collect();
        let mut h = Xxh64::new();
        for chunk in seq.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(h.digest(), 0x3254_A36C_CC0F_3897);
    }

    /// The empty frame `zstd -3 </dev/null` produces, byte for byte.
    #[test]
    fn an_empty_frame_decodes_to_nothing() {
        let frame: &[u8] = &[
            0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x01, 0x00, 0x00, 0x99, 0xe9, 0xd8, 0x51,
        ];
        let b = ZstdDecoder::new()
            .decode_bounded(frame, UNLIMITED)
            .expect("empty frame");
        assert!(b.bytes.is_empty());
        assert_eq!(b.declared, Some(0));
        assert!(!b.capped);
        assert_eq!(frame_content_size(frame), Some(0));
    }

    /// A frame that is not a frame: the magic check has to reject.
    #[test]
    fn a_non_frame_is_rejected() {
        for junk in [
            b"not a zstd frame at all".as_slice(),
            b"",
            &[0x28, 0xb5, 0x2f],
        ] {
            assert!(ZstdDecoder::new().decode(junk).is_err(), "{junk:?}");
        }
    }

    /// A frame declaring a dictionary is refused, not decoded without one:
    /// the dictionary is the only thing that makes such a frame readable.
    #[test]
    fn a_dictionary_frame_is_refused_not_decoded() {
        let frame: &[u8] = &[
            0x28, 0xb5, 0x2f, 0xfd, 0xa3, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00,
        ];
        match ZstdDecoder::new().decode(frame) {
            Err(CompressError::UnsupportedFormat(m)) => assert!(m.contains("dictionary"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    /// A bomb is stopped by the header, before it expands. 8 MB of one byte
    /// in about twenty bytes of RLE blocks.
    #[test]
    fn a_declared_bomb_is_refused_before_it_expands() {
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xa0];
        frame.extend_from_slice(&(8u32 << 20).to_le_bytes());
        for last in [0u32, 1] {
            let size = (4u32 << 20) - (1 - last);
            let h = (size << 3) | (1 << 1) | last;
            frame.extend_from_slice(&h.to_le_bytes()[..3]);
            frame.push(b'Q');
        }
        let b = ZstdDecoder::new()
            .decode_bounded(&frame, 1 << 20)
            .expect("refused, not failed");
        assert!(b.capped, "must say the cap stopped it");
        assert!(b.bytes.is_empty(), "emitted {} bytes", b.bytes.len());
        assert_eq!(b.declared, Some(8 << 20));
    }

    /// The backward bit reader, against §3.1.1.3.2.1: the last byte is
    /// `0b0001_0100`, so the marker is bit 4 and the bits below it are
    /// the payload.
    #[test]
    fn the_backward_reader_starts_after_the_marker() {
        let mut br = BackBits::new(&[0b1011_0010u8, 0b0001_0100]).expect("marker present");
        // The marker is bit 4, so the payload is bits 3..0 of that byte.
        assert_eq!(br.read(4), 0b0100);
        assert_eq!(br.read(8), 0b1011_0010);
        assert!(br.at_end());
    }

    /// A backward bitstream whose last byte is zero has no marker; the
    /// reader must say so rather than read padding as data.
    #[test]
    fn a_backward_bitstream_without_a_marker_is_rejected() {
        assert!(BackBits::new(&[0x00, 0x00]).is_err());
        assert!(BackBits::new(&[]).is_err());
    }

    /// A skippable frame is skipped, not decoded, and the frame after it
    /// still decodes. §3.1.2.
    #[test]
    fn a_skippable_frame_is_skipped() {
        let empty: &[u8] = &[
            0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x01, 0x00, 0x00, 0x99, 0xe9, 0xd8, 0x51,
        ];
        let mut data = vec![
            0x50, 0x2a, 0x4d, 0x18, 0x04, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
        ];
        data.extend_from_slice(empty);
        assert!(ZstdDecoder::new()
            .decode(&data)
            .expect("skippable + frame")
            .is_empty());
    }

    /// Number_of_Sequences has three encodings (§3.1.1.3.2.1). The
    /// three-byte one starts at 0x7F00 and no encoder in the reference
    /// corpus reaches it, so it is pinned here rather than by a fixture.
    #[test]
    fn the_sequence_count_has_three_encodings() {
        for (bytes, want, used) in [
            (vec![0x00], 0usize, 1usize),
            (vec![0x01], 1, 1),
            (vec![0x7F], 127, 1),
            (vec![0x80, 0x00], 0, 2),
            (vec![0x80, 0x01], 1, 2),
            (vec![0xFE, 0xFF], 32511, 2),
            (vec![0xFF, 0x00, 0x00], 32512, 3),
            (vec![0xFF, 0xFF, 0xFF], 0xFFFF + 0x7F00, 3),
        ] {
            let (n, u) = read_sequence_count(&bytes).expect("count");
            assert_eq!((n, u), (want, used), "{bytes:02x?}");
        }
        assert!(read_sequence_count(&[]).is_err());
        assert!(read_sequence_count(&[0x80]).is_err());
        assert!(read_sequence_count(&[0xFF, 0x00]).is_err());
    }

    /// An RLE_Literals_Block (§3.1.1.3.1.3) inside a compressed block. The
    /// literals are one byte repeated, and with no sequences the block is
    /// exactly that. No reference encoder in reach emits this shape, so the
    /// frame is hand-built here.
    #[test]
    fn an_rle_literals_block_decodes() {
        // The 1-byte literals header carries a 5-bit size, so 31 is its cap.
        const N: usize = 31;
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xa0];
        frame.extend_from_slice(&(N as u32).to_le_bytes());
        // Bit 3 is the low bit of the size, not a size-format bit: with
        // Size_Format 00 only bit 2 carries format.
        let block: [u8; 3] = [((N as u8) << 3) | 1, b'Z', 0x00];
        let header = ((block.len() as u32) << 3) | (2 << 1) | 1;
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.extend_from_slice(&block);
        assert_eq!(
            ZstdDecoder::new().decode(&frame).expect("rle literals"),
            vec![b'Z'; N]
        );
    }

    /// The three predefined tables are data, and the only way to know they
    /// are right is to check them against the tables they replace.
    #[test]
    fn the_predefined_tables_are_usable() {
        let pre = Predefined::new().expect("predefined tables build");
        for (name, t) in [("ll", &pre.ll), ("of", &pre.of), ("ml", &pre.ml)] {
            assert!(!t.baseline.is_empty(), "{name}");
            // Every state's successor must itself be a valid state, or the
            // sequence loop walks off the table on a well-formed file.
            for (s, cell) in t.next_state.iter().enumerate() {
                let next = *cell as usize + (1u32 << t.nb_bits[s]) as usize - 1;
                assert!(next < t.baseline.len(), "{name} state {s} -> {next}");
            }
        }
    }
}
