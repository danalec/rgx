// SPDX-License-Identifier: Apache-2.0

//! RAR 2.9 / 3.x (RAR 4) compressed-stream decompressor: LZ77 over a
//! circular window, canonical Huffman command tables, and the standard
//! delta / E8 / E8E9 / RGB / audio VM filter programs.
//!
//! Independent reimplementation. The algorithm was rewritten from
//! understanding of the decompression pipeline and validated against this
//! crate's `rar4-*` fixtures as the behavioural oracle. RARLAB publishes no
//! compression specification — the RAR 4.11/4.20 technote documents only
//! the container (block layout, CRC-32 poly 0xEDB88320) — and LOC PRONOM
//! fmt/411 records the format's transparency as low. Real WinRAR-produced
//! bytes verify this module end to end as well: `rar4_normal`, `rar4_best`
//! and `rar4_store` (built by `Rar.exe` 6.24 with `-ma4`, extracted by
//! genuine `UnRAR.exe` 7.20) decode byte-identical, and the PPMd block path
//! through [`crate::ppmd7`] is verified by `ppmd_text` / `ppmd_mixed` in the
//! same corpus.
//!
//! # Shape
//!
//! The packed data area of one file member decodes to a circular LZSS
//! window; the decoder stops at the declared unpacked size or at the
//! end-of-file marker (command 256 with a clear "new tables" bit). Commands
//! are symbols of the main prefix code:
//!
//! | range | meaning |
//! |---|---|
//! | 0..=255 | literal byte |
//! | 256 | end of file / new tables follow |
//! | 257 | a VM filter definition follows |
//! | 258 | repeat the last match |
//! | 259..=262 | match from distance-cache slot `n - 259` |
//! | 263..=270 | 2-byte match at a short distance |
//! | 271..=298 | new match; length slot is `n - 271` |
//!
//! Lengths are a base-plus-extra-bits ladder (base 0..224); the length is
//! the base plus 2 for a cache hit, plus 3 for a new match. Distances are a
//! second ladder of 60 slots, with a low-distance prefix code for the low
//! bits of the wide slots. Distances above 0x2000 and 0x40000 each buy one
//! extra byte of match length.
//!
//! # Distance cache
//!
//! Four slots hold recent distances. A **cache hit** (259..=262) is a
//! move-to-front of the hit slot: rotate the first `k + 1` slots and
//! nothing else. A **new** distance (263+/271+) is an insert-at-front:
//! shift all four slots. Getting this wrong corrupts every later cache
//! hit, so the two updates are separate methods and both are pinned by
//! unit tests.
//!
//! # Solid groups
//!
//! One [`Unpacker3`] is shared by all members of a solid group: the window,
//! distance cache, Huffman tables and compiled filter programs persist
//! across [`Unpacker3::run_member`] calls, while the pending filter stack,
//! the bit reader and the per-member output reset. Filter blocks must lie
//! entirely inside the member that declares them.
//!
//! Not implemented (returns [`Error::Unsupported`]):
//! * PPMd filters applied inside a PPMd block,
//! * arbitrary RAR VM program filters (the five standard filters
//!   identified by their bytecode fingerprint are supported).
//!
//! PPMd var-H blocks are decoded by the companion [`crate::ppmd7`] module.

use alloc::vec;
use alloc::vec::Vec;

use crate::crc32::crc32;
use crate::{Error, Result};

// ------------------------------------------------------------- format data

const MAINCODE_SIZE: usize = 299;
const OFFSETCODE_SIZE: usize = 60;
const LOWOFFSETCODE_SIZE: usize = 17;
const LENGTHCODE_SIZE: usize = 28;
/// The whole length table: main + offset + low-offset + length codes.
const TABLE_SIZE: usize = MAINCODE_SIZE + OFFSETCODE_SIZE + LOWOFFSETCODE_SIZE + LENGTHCODE_SIZE;
/// Bit lengths are 0..=15; the precode that describes them is 20 symbols.
const MAX_CODE_BITS: u8 = 15;
const PRECODE_SIZE: usize = 20;

/// Largest window the format uses (the rar3 dictionary ceiling).
const DICTIONARY_MAX_SIZE: usize = 0x40000 * 16;
/// Filter programs run over a 240 KiB work area inside a 256 KiB VM image.
const PROGRAM_WORK_SIZE: u32 = 0x3C000;
const PROGRAM_MEM_SIZE: u32 = 0x40000;

/// Length slot `s`: match length is `LENGTH_BASES[s] + bias + extra`.
const LENGTH_BASES: [u32; LENGTHCODE_SIZE] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LENGTH_BITS: [u32; LENGTHCODE_SIZE] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];

/// Distance slot `s`: distance is `OFFSET_BASES[s] + 1 + extras`.
const OFFSET_BASES: [u32; OFFSETCODE_SIZE] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
    1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872,
    3670016, 3932160,
];
const OFFSET_BITS: [u32; OFFSETCODE_SIZE] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18,
];

/// Short distances (commands 263..=270): distance is `base + 1 + extra`.
const SHORT_BASES: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_BITS: [u32; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// Standard filter fingerprints: CRC-32 of the bytecode | length << 32.
const FP_DELTA: u64 = 0x1D0E06077D;
const FP_E8: u64 = 0x35AD576887;
const FP_E8E9: u64 = 0x393CD7E57E;
const FP_RGB: u64 = 0x951C2C5DC8;
const FP_AUDIO: u64 = 0xD8BC85E701;

/// Decompress one RAR4 file member (methods 0x31..=0x35).
///
/// * `data` — the packed data area
/// * `unp_size` — declared unpacked size
pub fn unpack(data: &[u8], unp_size: u64) -> Result<Vec<u8>> {
    if unp_size == 0 {
        return Ok(Vec::new());
    }
    // Smallest power of two that covers the output, capped at the 4 MB
    // dictionary: a match can never reach further back than the current
    // position, which is always inside such a window.
    let window_size = if unp_size >= DICTIONARY_MAX_SIZE as u64 {
        DICTIONARY_MAX_SIZE
    } else {
        1usize << (64 - (unp_size | 1).leading_zeros())
    };
    let mut d = Unpacker3::new(window_size);
    d.run_member(data, unp_size)
}

// ---------------------------------------------------------------- bit reader

/// MSB-first bit reader over the packed data.
///
/// Unconsumed bits sit in the low `avail` bits of `cache`; the next bit to
/// read is at position `avail - 1`. `take` fills at most 32 bits at a time,
/// so the cache never exceeds 39 valid bits and fits in a `u64`.
pub(crate) struct BitReader3<'a> {
    data: &'a [u8],
    next: usize,
    cache: u64,
    avail: u32,
}

impl<'a> BitReader3<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        BitReader3 {
            data,
            next: 0,
            cache: 0,
            avail: 0,
        }
    }

    fn fill_to(&mut self, n: u32) -> Result<()> {
        while self.avail < n {
            let b = self.data.get(self.next).ok_or(Error::Truncated)?;
            self.cache = (self.cache << 8) | u64::from(*b);
            self.next += 1;
            self.avail += 8;
        }
        Ok(())
    }

    /// Read and consume `n` bits (0..=32).
    pub(crate) fn take(&mut self, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        self.fill_to(n)?;
        self.avail -= n;
        Ok(((self.cache >> self.avail) & ((1u64 << n) - 1)) as u32)
    }

    /// Drop bits up to the next byte boundary of the original stream.
    fn align_byte(&mut self) {
        self.avail -= self.avail % 8;
    }
}

// ------------------------------------------------------------------ huffman

/// A canonical binary prefix code over `len` symbols given their bit
/// lengths.
///
/// Decoding uses the classic length-sorted table: walk down lengths one bit
/// at a time and compare the accumulated code against the running code-space
/// window of that length. Symbols of length 0 are absent from the code and
/// are never returned.
struct PrefixCode {
    /// Symbols ordered by (code length, symbol index).
    symbols: Vec<u16>,
    /// `counts[l]` = number of symbols of length `l`.
    counts: [u16; MAX_CODE_BITS as usize + 1],
}

impl PrefixCode {
    /// Build the canonical code implied by `lengths[..n]`.
    ///
    /// Over-subscribed length sets (two symbols claiming the same code) are
    /// refused here rather than at decode time; under-subscribed sets are
    /// accepted and fail only if the bitstream walks into the hole.
    fn new(lengths: &[u8], n: usize) -> Result<PrefixCode> {
        let mut counts = [0u16; MAX_CODE_BITS as usize + 1];
        for &l in lengths.iter().take(n) {
            if l > MAX_CODE_BITS {
                return Err(Error::Malformed("code longer than 15 bits"));
            }
            counts[l as usize] += 1;
        }
        // Kraft: the codes of length l need 2^l room in the code space.
        // left is the number of unassigned length-l codes as we walk down.
        let mut left: i32 = 1;
        for &count in &counts[1..] {
            left <<= 1;
            left -= i32::from(count);
            if left < 0 {
                return Err(Error::Malformed("prefix code: prefix found"));
            }
        }
        // Length-sorted symbol order assigns the canonical codes.
        let mut symbols = Vec::with_capacity(n);
        for l in 1..=MAX_CODE_BITS {
            for (s, &sl) in lengths.iter().take(n).enumerate() {
                if sl == l {
                    symbols.push(s as u16);
                }
            }
        }
        Ok(PrefixCode { symbols, counts })
    }

    /// Decode one symbol, MSB-first.
    fn decode(&self, br: &mut BitReader3) -> Result<u32> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: usize = 0;
        for l in 1..=MAX_CODE_BITS {
            code = (code << 1) | br.take(1)? as i32;
            let count = self.counts[l as usize] as i32;
            if code - first < count {
                return Ok(self.symbols[index + (code - first) as usize] as u32);
            }
            index += count as usize;
            first = (first + count) << 1;
        }
        Err(Error::Malformed("invalid prefix code in bitstream"))
    }
}

// ------------------------------------------------------- filter bit reader

/// MSB-first bit reader over a filter's bytecode block. Overreads return
/// zero bits and set [`ProgramBits::at_eof`], because a truncated filter
/// program is detected once at the end of the definition rather than at
/// every field.
struct ProgramBits<'a> {
    bytes: &'a [u8],
    offset: usize,
    bits: u64,
    available: u32,
    at_eof: bool,
}

impl<'a> ProgramBits<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        ProgramBits {
            bytes,
            offset: 0,
            bits: 0,
            available: 0,
            at_eof: false,
        }
    }

    fn fill(&mut self, n: u32) -> bool {
        while self.available < n && self.offset < self.bytes.len() {
            self.bits = (self.bits << 8) | u64::from(self.bytes[self.offset]);
            self.offset += 1;
            self.available += 8;
        }
        if n > self.available {
            self.at_eof = true;
            return false;
        }
        true
    }

    fn bits(&mut self, n: u32) -> u32 {
        if n > self.available && (self.at_eof || !self.fill(n)) {
            return 0;
        }
        self.available -= n;
        ((self.bits >> self.available) & ((1u64 << n) - 1)) as u32
    }

    /// Variable-length integer of the filter protocol: a 2-bit tag picks a
    /// 4-, 8-, 16- or 32-bit value, with the 8-bit form folding small
    /// values into a 12-bit range below 0xFFFFFF00.
    fn next_number(&mut self) -> u32 {
        match self.bits(2) {
            0 => self.bits(4),
            1 => {
                let val = self.bits(8);
                if val >= 16 {
                    val
                } else {
                    0xFFFFFF00 | (val << 4) | self.bits(4)
                }
            }
            2 => self.bits(16),
            _ => self.bits(32),
        }
    }
}

// ------------------------------------------------------------------ filters

/// One compiled filter program, identified by its bytecode fingerprint.
struct Program {
    fingerprint: u64,
    usagecount: u32,
    oldfilterlength: u32,
}

/// A filter instance waiting for its block to finish decoding.
/// `blockstartpos` is a global output position (member base + the declared
/// relative offset).
struct Filter {
    prog: usize,
    initialregisters: [u32; 8],
    blockstartpos: usize,
    blocklength: u32,
}

#[derive(Default)]
struct FilterState {
    progs: Vec<Program>,
    stack: Vec<Filter>,
    lastfilternum: u32,
}

// ------------------------------------------------------------------ decoder

/// The four prefix codes one table set carries.
struct Tables {
    main: PrefixCode,
    offset: PrefixCode,
    lowoffset: PrefixCode,
    length: PrefixCode,
}

/// Stateful RAR3/4 unpacker.
///
/// One instance is shared by all members of a solid group: window, distance
/// cache, Huffman tables and compiled filter programs persist across
/// [`Unpacker3::run_member`] calls, while the bit reader, the pending filter
/// stack and the output reset per member.
pub struct Unpacker3 {
    /// Circular LZSS window; power of two, indexed with `mask`.
    window: Vec<u8>,
    mask: usize,
    /// Decoded output of the whole group so far. Filter results replace
    /// their ranges in place, and later members may match into earlier
    /// ones through the shared window.
    out: Vec<u8>,
    /// Global output position of the first byte of the current member.
    member_base: usize,
    /// Declared unpacked size of the current member.
    cur_unp_size: u64,
    tables: Option<Tables>,
    /// Whether the current table set may be reused by the next solid
    /// member. Set by a table parse, cleared by the end-of-file marker's
    /// "next member has tables" bit and by a PPMd end-of-data.
    tables_read: bool,
    /// Bit lengths persist across `parse_codes` calls (mod-16 accumulation).
    lengthtable: [u8; TABLE_SIZE],
    /// Length of the most recent match (command 258 replays it).
    lastlength: u32,
    /// Four most recent distinct distances. An old-distance match
    /// (259..=262) moves its slot to the front; a new match inserts at the
    /// front.
    oldoffset: [u32; 4],
    /// Low 4/12 bits of wide distances, and their repeat counter.
    lastlowoffset: u32,
    lowoffsetrepeats: u32,
    filters: FilterState,
    /// PPMd model of the current PPMd block (torn down per file header).
    ppmd: Option<crate::ppmd7::Ppmd7>,
    is_ppmd_block: bool,
    /// Escape symbol for the current PPMd block (2 unless the block says
    /// otherwise); also the literal emitted by the "default" escape code.
    ppmd_escape: u32,
    ppmd_eod: bool,
}

impl Unpacker3 {
    /// Create an unpacker with a `window_size`-byte circular window.
    ///
    /// `window_size` must be a power of two.
    pub fn new(window_size: usize) -> Unpacker3 {
        debug_assert!(window_size.is_power_of_two());
        Unpacker3 {
            window: vec![0u8; window_size],
            mask: window_size - 1,
            out: Vec::new(),
            member_base: 0,
            cur_unp_size: 0,
            tables: None,
            tables_read: false,
            lengthtable: [0; TABLE_SIZE],
            lastlength: 0,
            // The reference initialises the four slots to all-ones, so a
            // stream that reuses a slot before recording any distance
            // copies from a wrapping window position rather than failing
            // on a zero distance.
            oldoffset: [u32::MAX; 4],
            lastlowoffset: 0,
            lowoffsetrepeats: 0,
            filters: FilterState::default(),
            ppmd: None,
            is_ppmd_block: false,
            ppmd_escape: 2,
            ppmd_eod: false,
        }
    }

    /// Decode one member's packed data, returning the member's bytes.
    ///
    /// `self.out` accumulates the whole group so far; the returned range is
    /// this member's contribution.
    pub fn run_member(&mut self, data: &[u8], unp_size: u64) -> Result<Vec<u8>> {
        self.member_base = self.out.len();
        self.cur_unp_size = unp_size;
        // Pending filters never span solid members, and the PPMd model is
        // torn down by every file header.
        self.filters.stack.clear();
        self.ppmd = None;
        self.is_ppmd_block = false;
        self.ppmd_eod = false;

        if unp_size == 0 {
            return Ok(Vec::new());
        }

        let mut br = BitReader3::new(data);
        // A first member (or one after a "fresh tables" marker) carries its
        // table set; later solid members continue with the current one.
        if !self.tables_read {
            self.parse_codes(&mut br)?;
        }
        self.decode_loop(&mut br)?;
        self.finish_member()
    }

    /// Store a member without compression (method 0x30): bytes go into the
    /// window so later solid members can reference them.
    pub fn write_stored(&mut self, data: &[u8]) -> Result<()> {
        self.member_base = self.out.len();
        self.cur_unp_size = data.len() as u64;
        let base = self.member_base;
        for (i, &b) in data.iter().enumerate() {
            self.window[(base + i) & self.mask] = b;
        }
        self.out.extend_from_slice(data);
        Ok(())
    }

    /// Current global output position (next byte written).
    fn wpos(&self) -> usize {
        self.out.len()
    }

    fn member_written(&self) -> u64 {
        (self.out.len() - self.member_base) as u64
    }

    // ---------------------------------------------------------- the loop

    fn decode_loop(&mut self, br: &mut BitReader3) -> Result<()> {
        loop {
            if self.member_written() >= self.cur_unp_size {
                break;
            }
            if self.is_ppmd_block {
                self.ppmd_step(br)?;
                if self.ppmd_eod {
                    // The model is gone: the next member must redefine it.
                    self.tables_read = false;
                    break;
                }
                self.apply_ready_filters()?;
                continue;
            }
            let symbol = match self.decode_symbol(br) {
                Ok(s) => s,
                // The packed area can simply run out of bits once the
                // declared size is reached.
                Err(Error::Truncated) if self.member_written() == self.cur_unp_size => break,
                Err(e) => return Err(e),
            };
            match symbol {
                0..=255 => self.emit_literal(symbol as u8)?,
                256 => {
                    // "1" = new tables follow in this member; otherwise a
                    // two-bit end-of-file: "0" keeps the tables for the
                    // next solid member, "1" announces fresh ones.
                    if br.take(1)? == 1 {
                        self.parse_codes(br)?;
                    } else {
                        self.tables_read = br.take(1)? == 0;
                        break;
                    }
                }
                257 => self.read_filter(br)?,
                258 => {
                    if self.lastlength != 0 {
                        let (o, l) = (self.oldoffset[0], self.lastlength);
                        self.emit_match(o, l)?;
                    }
                }
                259..=262 => {
                    let k = (symbol - 259) as usize;
                    let dist = self.oldoffset[k];
                    let lensym = self.decode_length_symbol(br)? as usize;
                    if lensym >= LENGTHCODE_SIZE {
                        return Err(Error::Malformed("bad length symbol"));
                    }
                    let len = LENGTH_BASES[lensym] + 2 + br.take(LENGTH_BITS[lensym])?;
                    self.remember_old_slot(k);
                    self.lastlength = len;
                    self.emit_match(dist, len)?;
                }
                263..=270 => {
                    let s = (symbol - 263) as usize;
                    let dist = SHORT_BASES[s] + 1 + br.take(SHORT_BITS[s])?;
                    self.remember_new_distance(dist);
                    self.lastlength = 2;
                    self.emit_match(dist, 2)?;
                }
                _ => {
                    // 271..=298: a new match.
                    let s = (symbol - 271) as usize;
                    if s >= LENGTHCODE_SIZE {
                        return Err(Error::Malformed("bad match symbol"));
                    }
                    let mut len = LENGTH_BASES[s] + 3 + br.take(LENGTH_BITS[s])?;
                    let dist = self.decode_distance(br)?;
                    // Wide distances buy length: 0x2000.. once,
                    // 0x40000.. twice in total.
                    if dist >= 0x2000 {
                        len += 1;
                    }
                    if dist >= 0x40000 {
                        len += 1;
                    }
                    self.remember_new_distance(dist);
                    self.lastlength = len;
                    self.emit_match(dist, len)?;
                }
            }
            self.apply_ready_filters()?;
        }
        Ok(())
    }

    /// One iteration of a PPMd block. Escape codes: 0 = a new table set
    /// follows, 2 = end of PPMd data, 3 = filters (unsupported), 4 = LZ
    /// match with a 3-byte offset and 1-byte length, 5 = RLE match at
    /// distance 1, anything else = the escape byte is a literal.
    fn ppmd_step(&mut self, br: &mut BitReader3) -> Result<()> {
        let sym = self.ppmd_decode(br)?;
        if sym < 0 {
            return Err(Error::Malformed("invalid PPMd symbol"));
        }
        if sym as u32 != self.ppmd_escape {
            self.emit_literal(sym as u8)?;
            return Ok(());
        }
        let code = self.ppmd_decode(br)?;
        if code < 0 {
            return Err(Error::Malformed("invalid PPMd escape"));
        }
        match code {
            0 => self.parse_codes(br)?,
            2 => self.ppmd_eod = true,
            3 => return Err(Error::Unsupported("PPMd filters")),
            4 => {
                let mut offset = 0u32;
                for i in (0..3).rev() {
                    let b = self.ppmd_decode(br)?;
                    if b < 0 {
                        return Err(Error::Malformed("invalid PPMd match offset"));
                    }
                    offset |= (b as u32) << (i * 8);
                }
                let length = self.ppmd_decode(br)?;
                if length < 0 {
                    return Err(Error::Malformed("invalid PPMd match length"));
                }
                self.emit_match(offset + 2, length as u32 + 32)?;
            }
            5 => {
                let length = self.ppmd_decode(br)?;
                if length < 0 {
                    return Err(Error::Malformed("invalid PPMd match length"));
                }
                self.emit_match(1, length as u32 + 4)?;
            }
            _ => {
                let esc = self.ppmd_escape as u8;
                self.emit_literal(esc)?;
            }
        }
        Ok(())
    }

    fn ppmd_decode(&mut self, br: &mut BitReader3) -> Result<i32> {
        self.ppmd
            .as_mut()
            .ok_or(Error::Malformed("PPMd block without model"))?
            .decode_symbol(br)
    }

    fn decode_symbol(&self, br: &mut BitReader3) -> Result<u32> {
        self.tables
            .as_ref()
            .ok_or(Error::Malformed("no tables"))?
            .main
            .decode(br)
    }

    fn decode_length_symbol(&self, br: &mut BitReader3) -> Result<u32> {
        self.tables
            .as_ref()
            .ok_or(Error::Malformed("no tables"))?
            .length
            .decode(br)
    }

    /// Distance of a new match: slot base plus extra bits, with the
    /// low-distance prefix code for the low part of wide slots.
    fn decode_distance(&mut self, br: &mut BitReader3) -> Result<u32> {
        let slotsym = self
            .tables
            .as_ref()
            .ok_or(Error::Malformed("no tables"))?
            .offset
            .decode(br)? as usize;
        if slotsym >= OFFSETCODE_SIZE {
            return Err(Error::Malformed("bad offset symbol"));
        }
        let mut dist = OFFSET_BASES[slotsym] + 1;
        let bits = OFFSET_BITS[slotsym];
        if bits == 0 {
            return Ok(dist);
        }
        if slotsym <= 9 {
            return Ok(dist + br.take(bits)?);
        }
        // Wide slot: the high part comes from the bit stream, the low part
        // from the low-distance code (or from a run of repeats).
        if bits > 4 {
            dist += br.take(bits - 4)? << 4;
        }
        if self.lowoffsetrepeats > 0 {
            self.lowoffsetrepeats -= 1;
            dist += self.lastlowoffset;
            return Ok(dist);
        }
        let low = self
            .tables
            .as_ref()
            .ok_or(Error::Malformed("no tables"))?
            .lowoffset
            .decode(br)?;
        if low == 16 {
            // "repeat the last low part 16 times": this one and 15 more.
            self.lowoffsetrepeats = 15;
            dist += self.lastlowoffset;
        } else {
            dist += low;
            self.lastlowoffset = low;
        }
        Ok(dist)
    }

    // ----------------------------------------------------- distance cache

    /// Command 259..=262: slot `k` of the distance cache is being re-used.
    /// That is a move-to-front of slot `k` — rotate the first `k + 1`
    /// slots and nothing more. (A new distance is a different update; see
    /// [`Unpacker3::remember_new_distance`].)
    fn remember_old_slot(&mut self, k: usize) {
        let dist = self.oldoffset[k];
        for i in (1..=k).rev() {
            self.oldoffset[i] = self.oldoffset[i - 1];
        }
        self.oldoffset[0] = dist;
    }

    /// A freshly decoded distance is recorded: insert at the front,
    /// shifting all four slots.
    fn remember_new_distance(&mut self, dist: u32) {
        self.oldoffset.rotate_right(1);
        self.oldoffset[0] = dist;
    }

    // ---------------------------------------------------------- emission

    fn emit_literal(&mut self, b: u8) -> Result<()> {
        // The loop stops at the declared size; a single command may still
        // step a little past it before the exact-size check in
        // `finish_member`. The bound keeps a corrupt stream from growing
        // without limit.
        if self.member_written() >= self.cur_unp_size + 260 {
            return Err(Error::Malformed("output exceeds declared size"));
        }
        let pos = self.wpos();
        self.window[pos & self.mask] = b;
        self.out.push(b);
        Ok(())
    }

    fn emit_match(&mut self, offset: u32, length: u32) -> Result<()> {
        if offset == 0 {
            return Err(Error::Malformed("zero match distance"));
        }
        // One bounds check per match, not per byte: the slack is the same
        // 260 `emit_literal` allows, because a match is a run of bytes the
        // member could have written as literals.
        if self.member_written() + u64::from(length) > self.cur_unp_size + 260 {
            return Err(Error::Malformed("output exceeds declared size"));
        }
        self.out.reserve(length as usize);
        let mask = self.mask;
        for _ in 0..length {
            // Wrapping reads mirror the reference: a corrupt distance
            // pulls stale window bytes instead of aborting (the CRC over
            // the output catches the damage).
            let wpos = self.wpos();
            let b = self.window[(wpos.wrapping_sub(offset as usize)) & mask];
            self.window[wpos & mask] = b;
            self.out.push(b);
        }
        Ok(())
    }

    fn finish_member(&mut self) -> Result<Vec<u8>> {
        self.apply_ready_filters()?;
        if let Some(f) = self.filters.stack.first() {
            let end = f
                .blockstartpos
                .checked_add(f.blocklength as usize)
                .ok_or(Error::Malformed("filter block overflow"))?;
            let member_end = self.member_base + self.cur_unp_size as usize;
            if f.blockstartpos < self.member_base || end > member_end {
                return Err(Error::Malformed("filter block spans solid members"));
            }
            return Err(Error::Malformed("filter block never completed"));
        }
        if self.member_written() != self.cur_unp_size {
            return Err(Error::Malformed("member size mismatch"));
        }
        // `tables_read` already carries the terminating marker's intent:
        // a size-terminated member leaves the table set reusable.
        Ok(self.out[self.member_base..].to_vec())
    }

    // ------------------------------------------------------------- tables

    /// Read a new table set: either a PPMd block header or the four
    /// Huffman length tables.
    fn parse_codes(&mut self, br: &mut BitReader3) -> Result<()> {
        br.align_byte();

        if br.take(1)? != 0 {
            return self.parse_ppmd_header(br);
        }
        self.is_ppmd_block = false;
        // Low-distance repeat state belongs to the table set.
        self.lastlowoffset = 0;
        self.lowoffsetrepeats = 0;

        // Bit 0: clear the accumulated lengths; bit 1: keep them and add
        // the new ones modulo 16.
        if br.take(1)? == 0 {
            self.lengthtable = [0; TABLE_SIZE];
        }

        let precode_lengths = self.read_precode_lengths(br)?;
        let precode = PrefixCode::new(&precode_lengths, PRECODE_SIZE)?;

        let mut idx = 0usize;
        while idx < TABLE_SIZE {
            let val = precode.decode(br)?;
            if val < 16 {
                // Lengths accumulate modulo 16 across table sets.
                self.lengthtable[idx] = (self.lengthtable[idx] + val as u8) & 0xF;
                idx += 1;
            } else if val < 18 {
                if idx == 0 {
                    return Err(Error::Malformed("repeat before any table entry"));
                }
                let n = if val == 16 {
                    br.take(3)? + 3
                } else {
                    br.take(7)? + 11
                };
                for _ in 0..n {
                    if idx >= TABLE_SIZE {
                        break;
                    }
                    self.lengthtable[idx] = self.lengthtable[idx - 1];
                    idx += 1;
                }
            } else {
                let n = if val == 18 {
                    br.take(3)? + 3
                } else {
                    br.take(7)? + 11
                };
                for _ in 0..n {
                    if idx >= TABLE_SIZE {
                        break;
                    }
                    self.lengthtable[idx] = 0;
                    idx += 1;
                }
            }
        }

        let t = &self.lengthtable;
        let main = PrefixCode::new(&t[0..MAINCODE_SIZE], MAINCODE_SIZE)?;
        let offset = PrefixCode::new(
            &t[MAINCODE_SIZE..MAINCODE_SIZE + OFFSETCODE_SIZE],
            OFFSETCODE_SIZE,
        )?;
        let lowoffset = PrefixCode::new(
            &t[MAINCODE_SIZE + OFFSETCODE_SIZE
                ..MAINCODE_SIZE + OFFSETCODE_SIZE + LOWOFFSETCODE_SIZE],
            LOWOFFSETCODE_SIZE,
        )?;
        let length = PrefixCode::new(
            &t[MAINCODE_SIZE + OFFSETCODE_SIZE + LOWOFFSETCODE_SIZE..],
            LENGTHCODE_SIZE,
        )?;
        self.tables = Some(Tables {
            main,
            offset,
            lowoffset,
            length,
        });
        // A parsed table set is reusable by the next solid member.
        self.tables_read = true;
        Ok(())
    }

    /// The 20 four-bit precode lengths, with `0xF` as a zero-run escape:
    /// `0xF` + non-zero `n` writes `n + 2` zeros, `0xF` + `0` is a literal
    /// 15.
    fn read_precode_lengths(&self, br: &mut BitReader3) -> Result<[u8; PRECODE_SIZE]> {
        let mut lengths = [0u8; PRECODE_SIZE];
        let mut i = 0usize;
        while i < PRECODE_SIZE {
            let v = br.take(4)? as u8;
            if v != 0xF {
                lengths[i] = v;
                i += 1;
                continue;
            }
            let zerocount = br.take(4)?;
            if zerocount == 0 {
                lengths[i] = 0xF;
                i += 1;
            } else {
                for _ in 0..zerocount + 2 {
                    if i >= PRECODE_SIZE {
                        break;
                    }
                    lengths[i] = 0;
                    i += 1;
                }
            }
        }
        Ok(lengths)
    }

    fn parse_ppmd_header(&mut self, br: &mut BitReader3) -> Result<()> {
        let flags = br.take(7)?;
        // Read order is fixed by the format: the dictionary size (0x20)
        // precedes the escape byte (0x40).
        let dict_size = if flags & 0x20 != 0 {
            let mb = br.take(8)? + 1;
            // One byte, so a crafted header can name 256 MiB of arena,
            // and a window allocation that fails aborts the process --
            // the failure cannot be caught. WinRAR 3's own switch tops
            // out at 128 MiB, so past that the block is refused by name
            // rather than paid for.
            if mb > 128 {
                return Err(Error::Malformed("PPMd memory beyond 128 MiB"));
            }
            mb << 20
        } else {
            0
        };
        self.ppmd_escape = if flags & 0x40 != 0 { br.take(8)? } else { 2 };
        if flags & 0x20 != 0 {
            let mut maxorder = (flags & 0x1F) + 1;
            if maxorder > 16 {
                maxorder = 16 + (maxorder - 16) * 3;
            }
            if maxorder == 1 {
                return Err(Error::Malformed("bad PPMd max order"));
            }
            let esc = self.ppmd_escape;
            let mut model = crate::ppmd7::Ppmd7::new(dict_size)?;
            model.init_range_rar(br)?;
            model.init_model(maxorder, esc);
            self.ppmd = Some(model);
        } else {
            let esc = self.ppmd_escape;
            match self.ppmd.as_mut() {
                Some(m) => {
                    m.set_init_esc(esc);
                    m.init_range_rar(br)?;
                }
                None => {
                    return Err(Error::Malformed(
                        "PPMd block without a preceding model reset",
                    ))
                }
            }
        }
        self.is_ppmd_block = true;
        Ok(())
    }

    // ------------------------------------------------------------ filters

    /// Read one filter definition (command 257): a flags byte, a length,
    /// and that many bytes of filter protocol.
    fn read_filter(&mut self, br: &mut BitReader3) -> Result<()> {
        let flags = br.take(8)? as u8;
        let lenfield = flags & 0x07;
        let length = match lenfield {
            6 => br.take(8)? + 7,
            7 => (br.take(8)? << 8) | br.take(8)?,
            _ => u32::from(lenfield) + 1,
        };
        let mut code = Vec::with_capacity(length as usize);
        for _ in 0..length {
            code.push(br.take(8)? as u8);
        }
        self.parse_filter(&code, flags)
    }

    fn parse_filter(&mut self, bytes: &[u8], flags: u8) -> Result<()> {
        let mut pbr = ProgramBits::new(bytes);
        let numprogs = self.filters.progs.len() as u32;

        // Bit 7: an explicit filter number is present. Number 0 resets
        // every compiled program; otherwise the number is 1-based.
        let num = if flags & 0x80 != 0 {
            let mut num = pbr.next_number();
            if num == 0 {
                self.filters.stack.clear();
                self.filters.progs.clear();
            } else {
                num -= 1;
            }
            if num > numprogs {
                return Err(Error::Malformed("invalid filter number"));
            }
            self.filters.lastfilternum = num;
            num
        } else {
            self.filters.lastfilternum
        };

        // An existing program at `num`, or None when a new one follows.
        let (prog_idx, usagecount) = match self.filters.progs.get_mut(num as usize) {
            Some(p) => {
                p.usagecount += 1;
                (Some(num as usize), p.usagecount)
            }
            None => (None, 0),
        };

        let mut blockstartpos = pbr.next_number() as usize;
        blockstartpos = blockstartpos.wrapping_add(self.wpos());
        if flags & 0x40 != 0 {
            blockstartpos = blockstartpos.wrapping_add(258);
        }
        let blocklength = if flags & 0x20 != 0 {
            pbr.next_number()
        } else {
            prog_idx
                .map(|i| self.filters.progs[i].oldfilterlength)
                .unwrap_or(0)
        };
        if blocklength as usize > self.window.len() {
            return Err(Error::Malformed("filter block too large"));
        }

        // VM registers: R3 points at the work area, R4 carries the block
        // length, R5 the use count of the program, R7 the VM memory size.
        // Register 6 is a guard, not an argument.
        let mut registers = [0u32; 8];
        registers[3] = PROGRAM_WORK_SIZE;
        registers[4] = blocklength;
        registers[5] = usagecount;
        registers[7] = PROGRAM_MEM_SIZE;

        if flags & 0x10 != 0 {
            let mask = pbr.bits(7);
            for (i, r) in registers.iter_mut().enumerate().take(7) {
                if mask & (1 << i) != 0 {
                    *r = pbr.next_number();
                }
            }
        }

        let prog_idx = match prog_idx {
            Some(i) => i,
            None => {
                // A new program: its bytecode follows, identified by the
                // fingerprint of the bytecode (CRC-32 and length).
                let len = pbr.next_number();
                if len == 0 || len > 0x10000 {
                    return Err(Error::Malformed("invalid filter program"));
                }
                let mut bytecode = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    bytecode.push(pbr.bits(8) as u8);
                }
                let prog = compile_program(&bytecode)?;
                self.filters.progs.push(prog);
                self.filters.progs.len() - 1
            }
        };
        self.filters.progs[prog_idx].oldfilterlength = blocklength;

        if flags & 0x08 != 0 {
            let globaldatalen = pbr.next_number();
            if globaldatalen > 0x1FC0 {
                return Err(Error::Malformed("filter global data too large"));
            }
            for _ in 0..globaldatalen {
                pbr.bits(8);
            }
        }

        if pbr.at_eof {
            return Err(Error::Malformed("truncated filter data"));
        }

        self.filters.stack.push(Filter {
            prog: prog_idx,
            initialregisters: registers,
            blockstartpos,
            blocklength,
        });
        Ok(())
    }

    /// Apply every filter whose block has been fully decoded, in stream
    /// order. Filter blocks may not overlap.
    fn apply_ready_filters(&mut self) -> Result<()> {
        while let Some(f) = self.filters.stack.first() {
            let end = match f.blockstartpos.checked_add(f.blocklength as usize) {
                Some(e) => e,
                None => return Err(Error::Malformed("filter block overflow")),
            };
            if end > self.wpos() {
                break;
            }
            if f.blockstartpos < self.member_base {
                return Err(Error::Malformed("filter block spans solid members"));
            }
            let f = self.filters.stack.remove(0);
            let start_local = f.blockstartpos - self.member_base;
            let end_local = start_local + f.blocklength as usize;
            let gstart = self.member_base + start_local;
            let gend = self.member_base + end_local;
            let region = &self.out[gstart..gend];
            // The E8 filters use the member-relative position written so
            // far, matching the reference's per-member write counter.
            let filtered = execute_filter(&f, &self.filters.progs[f.prog], region, start_local)?;
            self.out[gstart..gend].copy_from_slice(&filtered);
            if let Some(next) = self.filters.stack.first() {
                if next.blockstartpos < gend {
                    return Err(Error::Malformed("overlapping filter blocks"));
                }
            }
        }
        Ok(())
    }
}

/// Accept a filter program: verify its XOR checksum, record its
/// fingerprint, and skip any leading static data.
fn compile_program(bytecode: &[u8]) -> Result<Program> {
    let first = match bytecode.first() {
        Some(&b) => b,
        None => return Err(Error::Malformed("corrupt filter program")),
    };
    let mut xor = 0u8;
    for &b in bytecode.iter().skip(1) {
        xor ^= b;
    }
    if xor != first {
        return Err(Error::Malformed("corrupt filter program"));
    }
    let fingerprint = u64::from(crc32(bytecode)) | ((bytecode.len() as u64) << 32);
    let mut pbr = ProgramBits::new(bytecode);
    pbr.offset = 1;
    if pbr.bits(1) != 0 {
        let staticdatalen = pbr.next_number();
        if staticdatalen >= 0x40000 {
            return Err(Error::Malformed("filter static data too large"));
        }
        for _ in 0..staticdatalen + 1 {
            pbr.bits(8);
        }
    }
    Ok(Program {
        fingerprint,
        usagecount: 0,
        oldfilterlength: 0,
    })
}

fn execute_filter(f: &Filter, prog: &Program, region: &[u8], pos: usize) -> Result<Vec<u8>> {
    match prog.fingerprint {
        FP_DELTA => filter_delta(region, f.initialregisters[0] as usize),
        FP_E8 => filter_e8(region, pos, false),
        FP_E8E9 => filter_e8(region, pos, true),
        FP_RGB => filter_rgb(region, f.initialregisters[0], f.initialregisters[1]),
        FP_AUDIO => filter_audio(region, f.initialregisters[0] as usize),
        _ => Err(Error::Unsupported("RAR VM program filter")),
    }
}

// ----------------------------------------------------- standard filters

/// Delta filter: `numchannels` interleaved channels, each an integrated
/// byte stream. Input is stored planar (channel-major) and read out
/// interleaved. Register R0 carries the channel count.
fn filter_delta(region: &[u8], numchannels: usize) -> Result<Vec<u8>> {
    let length = region.len();
    if length > PROGRAM_WORK_SIZE as usize / 2 || numchannels == 0 || numchannels > 128 {
        return Err(Error::Malformed("invalid delta filter parameters"));
    }
    let mut out = vec![0u8; length];
    let mut src = 0usize;
    for ch in 0..numchannels {
        let mut last: u8 = 0;
        let mut dst = ch;
        while dst < length {
            last = last.wrapping_sub(region[src]);
            out[dst] = last;
            src += 1;
            dst += numchannels;
        }
    }
    Ok(out)
}

/// x86 call fixup: turn relative `E8`/`E9` call targets into absolute
/// file positions and back. `pos` is the member-relative offset of the
/// region; the file size model is the reference's 16 MB window.
fn filter_e8(region: &[u8], pos: usize, e9also: bool) -> Result<Vec<u8>> {
    let length = region.len();
    if length > PROGRAM_WORK_SIZE as usize || length <= 4 {
        return Err(Error::Malformed("invalid e8 filter parameters"));
    }
    const FILE_SIZE: u32 = 0x1000000;
    let mut buf = region.to_vec();
    let mut i = 0usize;
    while i + 5 <= length {
        if buf[i] == 0xE8 || (e9also && buf[i] == 0xE9) {
            let currpos = (pos as u32).wrapping_add(i as u32).wrapping_add(1);
            let addr = i32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]);
            if addr < 0 && currpos >= (addr as u32).wrapping_neg() {
                buf[i + 1..i + 5]
                    .copy_from_slice(&addr.wrapping_add(FILE_SIZE as i32).to_le_bytes());
            } else if addr >= 0 && (addr as u32) < FILE_SIZE {
                buf[i + 1..i + 5]
                    .copy_from_slice(&(addr as u32).wrapping_sub(currpos).to_le_bytes());
            }
            i += 4;
        }
        i += 1;
    }
    Ok(buf)
}

/// RGB predictor: 3-channel planar-in / interleaved-out delta with a
/// Paeth-style neighbour predictor. Register R0 is the stride, R1 the
/// byte offset of the pixel grid.
fn filter_rgb(region: &[u8], stride: u32, byteoffset: u32) -> Result<Vec<u8>> {
    let blocklength = region.len();
    // A stride under 3 passes `> blocklength` and sends the predictor's
    // `prev + 3` read past the block's end: a real RGB row is at least
    // one pixel wide, which is three bytes, so less than that is a
    // crafted register, not a filter.
    if blocklength > PROGRAM_WORK_SIZE as usize / 2
        || stride as usize > blocklength
        || stride < 3
        || blocklength < 3
        || byteoffset > 2
    {
        return Err(Error::Malformed("invalid rgb filter parameters"));
    }
    let stride = stride as usize;
    let mut dst = vec![0u8; blocklength];
    let mut src = 0usize;
    for i in 0..3usize {
        let mut byte: u8 = 0;
        let mut j = i;
        while j < blocklength {
            if j >= stride {
                let prev = j - stride;
                let up_left = dst[prev] as i32;
                let up = dst[prev + 3] as i32;
                let d1 = (up - up_left).abs();
                let d2 = (byte as i32 - up_left).abs();
                let d3 = (up - up_left + byte as i32 - up_left).abs();
                if d1 > d2 || d1 > d3 {
                    byte = if d2 <= d3 { dst[prev + 3] } else { dst[prev] };
                }
            }
            byte = byte.wrapping_sub(region[src]);
            src += 1;
            dst[j] = byte;
            j += 3;
        }
    }
    let byteoffset = byteoffset as usize;
    let mut i = byteoffset;
    while i + 2 < blocklength {
        dst[i] = dst[i].wrapping_add(dst[i + 1]);
        dst[i + 2] = dst[i + 2].wrapping_add(dst[i + 1]);
        i += 3;
    }
    Ok(dst)
}

/// Audio predictor: per-channel adaptive delta with five weights. The
/// prediction sum is computed as an unsigned 32-bit shift, as the
/// reference's C does — an arithmetic shift would differ for negative
/// sums. Register R0 carries the channel count.
fn filter_audio(region: &[u8], numchannels: usize) -> Result<Vec<u8>> {
    let length = region.len();
    if length > PROGRAM_WORK_SIZE as usize / 2 || numchannels == 0 || numchannels > 128 {
        return Err(Error::Malformed("invalid audio filter parameters"));
    }
    let mut out = vec![0u8; length];
    let mut src = 0usize;
    for ch in 0..numchannels {
        let mut weight = [0i32; 5];
        let mut delta = [0i16; 4];
        let mut lastdelta: i16 = 0;
        let mut error = [0i32; 11];
        let mut count: u32 = 0;
        let mut lastbyte: u8 = 0;
        let mut j = ch;
        while j < length {
            let d = i32::from(region[src] as i8);
            src += 1;
            delta[2] = delta[1];
            delta[1] = lastdelta.wrapping_sub(delta[0]);
            delta[0] = lastdelta;
            let pred = (8 * i32::from(lastbyte)
                + weight[0] * i32::from(delta[0])
                + weight[1] * i32::from(delta[1])
                + weight[2] * i32::from(delta[2])) as u32;
            let predbyte = ((pred >> 3) & 0xFF) as i32;
            let byte = (predbyte - d) & 0xFF;
            let prederror = d * 8;
            error[0] += prederror.abs();
            error[1] += (prederror - i32::from(delta[0])).abs();
            error[2] += (prederror + i32::from(delta[0])).abs();
            error[3] += (prederror - i32::from(delta[1])).abs();
            error[4] += (prederror + i32::from(delta[1])).abs();
            error[5] += (prederror - i32::from(delta[2])).abs();
            error[6] += (prederror + i32::from(delta[2])).abs();
            // prevDelta = (signed char)(byte - lastbyte): low byte, sign-extended.
            lastdelta = ((byte - i32::from(lastbyte)) as i8) as i16;
            lastbyte = byte as u8;
            out[j] = lastbyte;
            if count & 0x1F == 0 {
                let mut idx = 0usize;
                for k in 1..7 {
                    if error[k] < error[idx] {
                        idx = k;
                    }
                }
                error = [0; 11];
                match idx {
                    1 if weight[0] >= -16 => weight[0] -= 1,
                    2 if weight[0] < 16 => weight[0] += 1,
                    3 if weight[1] >= -16 => weight[1] -= 1,
                    4 if weight[1] < 16 => weight[1] += 1,
                    5 if weight[2] >= -16 => weight[2] -= 1,
                    6 if weight[2] < 16 => weight[2] += 1,
                    _ => {}
                }
            }
            count = count.wrapping_add(1);
            j += numchannels;
        }
    }
    Ok(out)
}

// -------------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;

    // ------------------------------------------------------- test encoder

    /// MSB-first bit writer. Test streams are built with the same bit
    /// order the decoder reads.
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
                if self.nbits.is_multiple_of(8) {
                    self.bytes.push(0);
                }
                if (value >> i) & 1 != 0 {
                    let last = self.bytes.len() - 1;
                    self.bytes[last] |= 1 << (7 - (self.nbits % 8));
                }
                self.nbits += 1;
            }
        }

        /// Pad to a byte boundary (the table block starts byte-aligned).
        fn align(&mut self) {
            while !self.nbits.is_multiple_of(8) {
                self.put(0, 1);
            }
        }

        fn into_bytes(self) -> Vec<u8> {
            self.bytes
        }
    }

    /// Write one table set. The precode uses four length-2 codes (symbols
    /// 5, 6, 9, 17 -> 00, 01, 10, 11) so every table length is either a
    /// literal or a repeat-17 run. The four tables are uniform-length, so
    /// canonical code `s` of length L is the `L`-bit value `s`.
    fn write_tables(w: &mut BitWriter) {
        w.put(0, 1); // not PPMd
        w.put(0, 1); // clear accumulated lengths
                     // Precode lengths as 20 nibbles: 5,6,9,17 have length 2.
        let mut pre = [0u8; PRECODE_SIZE];
        pre[5] = 2;
        pre[6] = 2;
        pre[9] = 2;
        pre[17] = 2;
        for pair in 0..10 {
            w.put(
                u32::from(pre[2 * pair]) << 4 | u32::from(pre[2 * pair + 1]),
                8,
            );
        }
        // Length table: 299 nines, 60 sixes, 17 fives, 28 fives.
        // Precode codes: 5 -> 0b00, 6 -> 0b01, 9 -> 0b10, repeat17 -> 0b11.
        let repeat = |w: &mut BitWriter, n: usize| {
            // n in 11..=138 for one repeat-17 run; larger n is split.
            let mut left = n;
            while left > 0 {
                let take = left.min(138);
                w.put(0b11, 2);
                w.put((take - 11) as u32, 7);
                left -= take;
            }
        };
        w.put(0b10, 2); // value 9
        repeat(w, 298);
        w.put(0b01, 2); // value 6
        repeat(w, 59);
        w.put(0b00, 2); // value 5
        repeat(w, 16);
        repeat(w, 28); // still 5
    }

    fn stream_prefix() -> BitWriter {
        let mut w = BitWriter::new();
        w.align();
        write_tables(&mut w);
        w
    }

    fn lit(w: &mut BitWriter, b: u8) {
        w.put(u32::from(b), 9);
    }

    /// New match: length slot 0 (length 3) plus a distance in the small
    /// slots (no low-distance code).
    fn new_match(w: &mut BitWriter, dist: u32, len: u32) {
        // len = LENGTH_BASES[s] + 3 + extra. Only slot 0 is needed here
        // (base 0 -> length 3, no extra bits).
        assert_eq!(len, 3, "test encoder emits length 3 new matches only");
        w.put(271, 9); // length slot 0
        let (slot, extra) = dist_slot(dist);
        w.put(slot, 6);
        let bits = OFFSET_BITS[slot as usize];
        if bits > 0 {
            w.put(extra, bits);
        }
    }

    /// Old-distance match from cache slot `k`, length 2 (length slot 0 of
    /// the length code: base 0 + 2).
    fn old_match(w: &mut BitWriter, k: u32) {
        w.put(259 + k, 9);
        w.put(0, 5); // length slot 0 -> length 2, no extra bits
    }

    /// Split a distance into (slot, extra) for the small slots.
    fn dist_slot(dist: u32) -> (u32, u32) {
        for s in 0..10u32 {
            let base = OFFSET_BASES[s as usize] + 1;
            let bits = OFFSET_BITS[s as usize];
            let span = 1u32 << bits;
            if dist >= base && dist < base + span {
                return (s, dist - base);
            }
        }
        panic!("distance {dist} needs the low-distance code; keep tests in the small slots");
    }

    // ------------------------------------------- distance-cache semantics

    /// Old-distance match (259..=262): move-to-front of slot k — rotate
    /// the first k+1 slots and nothing else. A new match inserts at the
    /// front, shifting all four.
    #[test]
    fn old_distance_match_moves_only_its_slot_to_the_front() {
        let mut d = Unpacker3::new(4);
        assert_eq!(d.oldoffset, [u32::MAX; 4]);
        // Four new distances fill the cache: insert-at-front each time.
        d.remember_new_distance(10);
        assert_eq!(d.oldoffset, [10, u32::MAX, u32::MAX, u32::MAX]);
        d.remember_new_distance(20);
        d.remember_new_distance(30);
        d.remember_new_distance(40);
        assert_eq!(d.oldoffset, [40, 30, 20, 10]);
        // Slot 0 is already at the front: a no-op.
        d.remember_old_slot(0);
        assert_eq!(d.oldoffset, [40, 30, 20, 10]);
        // Slot 2 moves to the front; slots 3 keeps its value. This is the
        // whole update — no insert-at-front, no second rotation.
        d.remember_old_slot(2);
        assert_eq!(d.oldoffset, [20, 40, 30, 10]);
        // Slot 1 rotates the first two.
        d.remember_old_slot(1);
        assert_eq!(d.oldoffset, [40, 20, 30, 10]);
        // A new distance still shifts all four.
        d.remember_new_distance(50);
        assert_eq!(d.oldoffset, [50, 40, 20, 30]);
    }

    /// End-to-end cache eviction and cache-hit sequence. The decoded
    /// bytes pin both the insert-at-front and the move-to-front paths:
    /// each cache hit copies from the distance its slot holds after the
    /// earlier updates, so a double-rotate would change the output.
    #[test]
    fn distance_cache_eviction_sequence_decodes_to_pinned_bytes() {
        let mut w = stream_prefix();
        // Ten literals 0..=9.
        for b in 0..10u8 {
            lit(&mut w, b);
        }
        // Four new matches recording distances 10, 9, 8, 7 (cache fills
        // and evicts the initial all-ones slots).
        new_match(&mut w, 10, 3); // copies 0,1,2
        new_match(&mut w, 9, 3); // copies 4,5,6
        new_match(&mut w, 8, 3); // copies 8,9,0
        new_match(&mut w, 7, 3); // copies 2,4,5
                                 // Cache is now [7, 8, 9, 10].
        old_match(&mut w, 2); // slot 2 = 9 -> copies 4,5; cache [9, 7, 8, 10]
        old_match(&mut w, 0); // slot 0 = 9 -> copies 6,8; cache unchanged
        old_match(&mut w, 3); // slot 3 = 10 -> copies 8,9; cache [10, 9, 7, 8]
        old_match(&mut w, 1); // slot 1 = 9 -> copies 2,4; cache [9, 10, 7, 8]
        let out = unpack(&w.into_bytes(), 30).unwrap();
        assert_eq!(
            out,
            vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // literals
                0, 1, 2, // dist 10
                4, 5, 6, // dist 9
                8, 9, 0, // dist 8
                2, 4, 5, // dist 7
                4, 5, // cache slot 2 -> 9
                6, 8, // cache slot 0 -> 9 (moved to front)
                8, 9, // cache slot 3 -> 10
                2, 4, // cache slot 1 -> 9
            ]
        );
    }

    // ------------------------------------------------------------- tables

    /// A table block cut off inside its precode must fail, not panic and
    /// not invent lengths.
    #[test]
    fn truncated_huffman_table_is_rejected() {
        // One non-PPMd table start, then nothing.
        let mut w = BitWriter::new();
        w.align();
        w.put(0, 1); // not PPMd
        w.put(0, 1); // clear lengths
        let bytes = w.into_bytes();
        assert!(matches!(
            unpack(&bytes, 8),
            Err(Error::Truncated) | Err(Error::Malformed(_))
        ));

        // A table start with a partial precode nibble run.
        let mut w = BitWriter::new();
        w.align();
        w.put(0, 1);
        w.put(0, 1);
        w.put(0, 4); // first precode nibble, then stream ends
        let bytes = w.into_bytes();
        assert!(matches!(
            unpack(&bytes, 8),
            Err(Error::Truncated) | Err(Error::Malformed(_))
        ));

        // A complete precode but a length table cut off after one symbol.
        let mut w = BitWriter::new();
        w.align();
        w.put(0, 1);
        w.put(0, 1);
        let mut pre = [0u8; PRECODE_SIZE];
        pre[9] = 2;
        pre[17] = 2;
        for pair in 0..10 {
            w.put(
                u32::from(pre[2 * pair]) << 4 | u32::from(pre[2 * pair + 1]),
                8,
            );
        }
        w.put(0b10, 2); // one value 9, then EOF before the repeats
        let bytes = w.into_bytes();
        assert!(matches!(
            unpack(&bytes, 8),
            Err(Error::Truncated) | Err(Error::Malformed(_))
        ));
    }

    // ------------------------------------------------------------- filters

    /// Build a 29-byte filter program whose XOR checksum is valid and
    /// whose CRC-32/length fingerprint is the standard delta filter.
    /// Standard filters are identified by fingerprint and run natively, so
    /// the bytecode body is never interpreted — only its identity is.
    ///
    /// CRC-32 is affine over GF(2) of the message bits, and the checksum
    /// byte is the XOR of the rest: flipping a body bit also flips the
    /// same bit of the checksum. Solve for the body bits whose combined
    /// delta lands on the target CRC.
    fn make_delta_program() -> Vec<u8> {
        const LEN: usize = 29;
        // FP_DELTA = CRC-32 | length << 32 = 0x0E06077D | 29 << 32.
        let target = 0x0E06_077Du32;
        let mut base = vec![0u8; LEN];
        base[0] = base[1..].iter().fold(0u8, |a, &b| a ^ b);
        let c0 = crc32(&base);
        // Per-bit CRC delta, checksum byte re-derived after the flip.
        let mut deltas: Vec<(usize, u32)> = Vec::new();
        for i in 1..LEN {
            for j in 0..8u8 {
                let mut p = base.clone();
                p[i] ^= 1 << j;
                p[0] = p[1..].iter().fold(0u8, |a, &b| a ^ b);
                deltas.push((i * 8 + j as usize, crc32(&p) ^ c0));
            }
        }
        // GF(2) basis keyed by leading bit: each entry holds the reduced
        // delta and the original bit indices XORed into it.
        let mut basis: Vec<Option<(u32, Vec<usize>)>> = (0..32).map(|_| None).collect();
        for (idx, d) in deltas {
            let mut v = d;
            let mut src = vec![idx];
            while v != 0 {
                let lead = (31 - v.leading_zeros()) as usize;
                if let Some((bv, bs)) = &basis[lead] {
                    let (bv, bs) = (*bv, bs.clone());
                    v ^= bv;
                    src.extend(bs);
                } else {
                    basis[lead] = Some((v, src));
                    break;
                }
            }
        }
        // Reduce the goal through the basis; the source sets give the flips.
        let mut goal = c0 ^ target;
        let mut flip = vec![false; LEN * 8];
        while goal != 0 {
            let lead = (31 - goal.leading_zeros()) as usize;
            let (bv, bs) = basis[lead].as_ref().expect("target CRC not in the span");
            goal ^= *bv;
            for &s in bs {
                flip[s] = !flip[s];
            }
        }
        for (s, on) in flip.iter().enumerate() {
            if *on {
                base[s / 8] ^= 1 << (s % 8);
            }
        }
        base[0] = base[1..].iter().fold(0u8, |a, &b| a ^ b);
        assert_eq!(crc32(&base), target, "solved program has the delta CRC");
        assert_eq!(base[1..].iter().fold(0u8, |a, &b| a ^ b), base[0]);
        base
    }

    /// Encode a filter definition (command 257) that declares a new
    /// program, a block at the current position, and writes `r0` into VM
    /// register 0 via the register mask.
    fn emit_delta_filter(w: &mut BitWriter, r0: u32, blocklength: u32) {
        let program = make_delta_program();
        // Filter protocol bits: number 1 (new program), block offset 0,
        // block length, register mask setting R0, program length+bytes.
        let mut p = BitWriter::new();
        p.put(0b00, 2); // number tag = 4-bit form
        p.put(1, 4); // filter number 1 -> index 0
        p.put(0b00, 2); // block start tag
        p.put(0, 4); // block starts at the current position
        p.put(0b00, 2); // block length tag
        p.put(blocklength, 4); // block length (fits in 4 bits)
        p.put(0b000_0001, 7); // register mask: R0 only
        p.put(0b00, 2);
        p.put(r0, 4); // R0 value (4-bit form)
        p.put(0b01, 2); // program length tag: 8-bit form
        p.put(program.len() as u32, 8); // 29 >= 16, returned verbatim
        for &b in &program {
            p.put(u32::from(b), 8);
        }
        p.align();
        let code = p.into_bytes();
        let len = code.len();
        // len = (flags & 7) + 1 for 1..=6; lenfield 6 -> byte + 7 for 7..=262.
        let (lenfield, extralen) = if len <= 6 {
            ((len - 1) as u32, None)
        } else if len <= 262 {
            (6u32, Some((len - 7) as u32))
        } else {
            panic!("filter code too long for this encoder");
        };
        let flags = 0x80 | 0x20 | 0x10 | lenfield; // new num, length, registers
        w.put(257, 9);
        w.put(flags, 8);
        if let Some(x) = extralen {
            w.put(x, 8);
        }
        for &b in &code {
            w.put(u32::from(b), 8);
        }
    }

    /// A VM filter whose register mask writes R0: the delta filter's
    /// channel count is taken from that register, so the same block with
    /// R0=1 and R0=2 decodes differently. This pins the register-write
    /// path and the register-to-filter argument handoff.
    #[test]
    fn vm_filter_register_write_changes_the_decoded_block() {
        // Planar 2-channel delta input; the decoder output interleaves.
        let region = [10u8, 20, 30, 40, 50, 60];

        // R0 = 2 channels: channel 0 reads 10,20,30 and channel 1 reads
        // 40,50,60; each integrates as (0 - src) per step.
        let mut w = stream_prefix();
        emit_delta_filter(&mut w, 2, region.len() as u32);
        for &b in &region {
            lit(&mut w, b);
        }
        let out2 = unpack(&w.into_bytes(), region.len() as u64).unwrap();
        assert_eq!(out2, vec![246, 216, 226, 166, 196, 106]);

        // R0 = 1 channel: all six bytes integrate in one run.
        let mut w = stream_prefix();
        emit_delta_filter(&mut w, 1, region.len() as u32);
        for &b in &region {
            lit(&mut w, b);
        }
        let out1 = unpack(&w.into_bytes(), region.len() as u64).unwrap();
        assert_ne!(out1, out2, "the register write must reach the filter");
        assert_eq!(out1, vec![246, 226, 196, 156, 106, 46]);
    }

    // -------------------------------------------------------------- window

    /// A 4 MiB window wraps: matches near the wrap point must read the
    /// overwritten slots, not the bytes that were there 4 MiB ago.
    #[test]
    fn window_wraps_at_the_dictionary_ceiling() {
        const WIN: usize = 1 << 22; // 4 MiB
        let mut d = Unpacker3::new(WIN);
        // Fill the window with 0xAA, then 100 distinctive tail bytes. The
        // tail overwrites the first 100 slots of the window.
        let mut fill = vec![0xAAu8; WIN];
        fill.extend(0..100u8);
        d.write_stored(&fill).unwrap();

        // One literal, then a match of length 3 at distance 30. Position
        // is WIN+101 after the literal; the source is WIN+71, whose window
        // slot (71) holds 71 from the tail, not 0xAA.
        let mut w = stream_prefix();
        lit(&mut w, b'X');
        let dist = 30;
        // length 3 via new match slot 0.
        w.put(271, 9);
        let (slot, extra) = dist_slot(dist);
        w.put(slot, 6);
        w.put(extra, OFFSET_BITS[slot as usize]);
        let out = d.run_member(&w.into_bytes(), 4).unwrap();
        assert_eq!(out, vec![b'X', 71, 72, 73]);
    }

    // ---------------------------------------------------------- fuzz floor

    /// Deterministic mutation floor (the `rgx-core::fuzzkit` pattern, kept
    /// local because this crate has zero dependencies). `Err` is fine;
    /// a panic fails the test with the repro bytes.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn byte(&mut self) -> u8 {
            self.next() as u8
        }
    }

    fn never_panics<F: FnMut(&[u8])>(
        corpus: &[(&str, &[u8])],
        rounds: usize,
        name: &str,
        mut f: F,
    ) {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for (seed_name, data) in corpus {
            for round in 0..rounds {
                let mut v = data.to_vec();
                match rng.next() % 6 {
                    0 => {
                        if !v.is_empty() {
                            let i = (rng.next() as usize) % v.len();
                            v[i] = v[i].wrapping_add(1 + rng.byte() % 255);
                        }
                    }
                    1 => {
                        if !v.is_empty() {
                            let i = (rng.next() as usize) % v.len();
                            v[i] ^= 1 << (rng.byte() % 8);
                        }
                    }
                    2 => {
                        let cut = (rng.next() as usize) % (v.len() + 1);
                        v.truncate(cut);
                    }
                    3 => {
                        let junk: Vec<u8> = (0..1 + (rng.next() as usize) % 16)
                            .map(|_| rng.byte())
                            .collect();
                        let at = (rng.next() as usize) % (v.len() + 1);
                        v.splice(at..at, junk);
                    }
                    4 => {
                        if !v.is_empty() {
                            let i = (rng.next() as usize) % v.len();
                            let j = (rng.next() as usize) % v.len();
                            v.swap(i, j);
                        }
                    }
                    _ => {
                        let n = v.len();
                        v = (0..n).map(|_| rng.byte()).collect();
                    }
                }
                let repro = v.clone();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    f(&repro);
                }));
                if result.is_err() {
                    let mut hex = String::new();
                    for b in repro.iter().take(64) {
                        hex.push_str(&format!("{b:02x}"));
                    }
                    panic!(
                        "{name}: panicked on round {round} (seed '{seed_name}')\nrepro hex: {hex}"
                    );
                }
            }
        }
    }

    /// The decoder must never panic on arbitrary or half-valid bytes.
    #[test]
    fn never_panics_on_arbitrary_bytes() {
        // Seeds: an empty stream, a valid table prefix, and a full valid
        // stream — mutations then explore half-valid shapes.
        let mut good = stream_prefix();
        for b in 0..8u8 {
            lit(&mut good, b);
        }
        let good = good.into_bytes();
        let prefix = {
            let mut w = BitWriter::new();
            w.align();
            w.put(0, 1);
            w.put(0, 1);
            w.into_bytes()
        };
        let corpus: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("table-prefix", prefix),
            ("valid-literals", good),
        ];
        let corpus_refs: Vec<(&str, &[u8])> =
            corpus.iter().map(|(n, v)| (*n, v.as_slice())).collect();
        never_panics(&corpus_refs, 500, "unpack3", |data| {
            let _ = unpack(data, 64);
            let _ = unpack(data, 1 << 20);
            let mut d = Unpacker3::new(256);
            let _ = d.run_member(data, 64);
            let _ = d.write_stored(data);
        });
    }

    /// Stored members put raw bytes in the window for later solid members.
    #[test]
    fn write_stored_feeds_the_window_for_later_members() {
        let mut d = Unpacker3::new(64);
        d.write_stored(b"hello world!").unwrap();
        // A compressed member matching "world" back at distance 7.
        let mut w = stream_prefix();
        lit(&mut w, b'X');
        // length 3 is the minimum new match; "orl" sits at distance 7
        // from after the X... position 13 (12 stored + 1 literal), so
        // distance 7 reads position 6 = 'w'. Emit three literals instead
        // to keep the test about the window, not the match ladder.
        for b in b"w0r" {
            lit(&mut w, *b);
        }
        let out = d.run_member(&w.into_bytes(), 4).unwrap();
        assert_eq!(out, b"Xw0r");
    }

    /// Symbol 258 replays the last match's distance and length at the new
    /// position — the bytes differ each time because the copy source moves
    /// with the write head.
    #[test]
    fn last_match_repeat_uses_the_same_distance_and_length() {
        let mut w = stream_prefix();
        for b in 0..10u8 {
            lit(&mut w, b);
        }
        new_match(&mut w, 10, 3); // copies 0,1,2 from 10 back
        w.put(258, 9); // at distance 10 again: copies 3,4,5
        w.put(258, 9); // and 6,7,8
        let out = unpack(&w.into_bytes(), 19).unwrap();
        assert_eq!(
            out,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8]
        );
    }
}
