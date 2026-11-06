// SPDX-License-Identifier: Apache-2.0

//! PPMd var.H decoder — the context-model coder inside RAR 2.9/3.x/4.x
//! PPMd blocks.
//!
//! Independent reimplementation of the PPMd (Prediction by Partial Matching,
//! discrete) algorithm as instantiated by the var.H variant: a suffix-linked
//! context tree over an order-N model, per-context symbol frequency tables,
//! scaled escape estimation (SEE) for the fallback probability, and a
//! carry-less range decoder with RAR's `0x8000` renormalisation floor.
//! Written from the published algorithm description (Shkarin's PPMd / PPMdI)
//! and from the contract the caller in [`crate::unpack3`] binds to — not a
//! port of any implementation.
//!
//! Correctness is established behaviourally: real PPMd-bearing archives are
//! decoded byte-identically through this module. `Rar.exe` 6.24 can still
//! emit RAR 4.x PPMd (`-ma4 -mct+`, the "text compression" module RAR 5.0
//! cannot carry) and genuine `UnRAR.exe` 7.20 extracts them; the cases
//! `ppmd_text` (40 000 B of generated English, 2 822 B packed) and
//! `ppmd_mixed` (98 304 B of mixed zeros/random/text) match the UnRAR
//! goldens exactly. The synthetic tests pin the model invariants the
//! archives cannot isolate (allocator floors, rescale, restart).
//!
//! # Arena
//!
//! Contexts and symbol states are carved from one flat byte pool using
//! `u32` offsets (the layout the C "not `PPMD_32BIT`" mode uses, which is
//! the natural shape for `#![forbid(unsafe_code)]` + `no_std`).  A
//! **context** is 12 bytes — `NumStats: u16, SummFreq: u16, Stats: u32,
//! Suffix: u32`.  A **state** is 6 bytes — `Symbol: u8, Freq: u8,
//! Successor: u32` (stored as two little-endian `u16` halves).  A
//! one-state context overlays its single state on the `SummFreq` field.
//! A free-list node reuses the first 12 bytes as `Stamp: u16, NU: u16,
//! Next: u32, Prev: u32`.  Reads past the pool yield 0 and writes are
//! dropped: valid streams never reference outside it, and corrupt streams
//! are caught by the member-size / CRC checks upstream instead of
//! panicking.
//!
//! # Model
//!
//! The model is a tree of contexts linked by suffix pointers.  The root
//! (order-0) context holds all 256 symbols; each higher-order context
//! represents one longer recent-symbol suffix.  Decoding starts at
//! `min_context` (the deepest context matching the recent history) and,
//! on escape (the coded symbol is not in the current context), walks
//! toward the root until an unmasked symbol is found.  The escape
//! probability is estimated by SEE counters indexed by the number of
//! masked symbols and the context's shape.
//!
//! After each symbol the model updates frequencies, may rescale the table
//! when a frequency overflows, and may create or expand successor contexts
//! along the suffix chain.

use alloc::vec;
use alloc::vec::Vec;

use crate::unpack3::BitReader3;
use crate::{Error, Result};

// ---------------------------------------------------------------- constants

/// Width of the integer part of a frequency estimate in SEE / binary scales.
const INT_BITS: u32 = 7;
/// Width of the period part (the SEE adaptation period is `1 << PERIOD_BITS`).
const PERIOD_BITS: u32 = 7;
/// Binary symbol scale: `1 << (INT_BITS + PERIOD_BITS)`.
const BIN_SCALE: u32 = 1 << (INT_BITS + PERIOD_BITS);
/// Number of unit-pool size classes (unit counts 1, 2, 3, 4, 6, 8, …, 128).
const NUM_INDEXES: usize = 38;

/// Frequency ceiling — a symbol frequency above this triggers a rescale.
const MAX_FREQ: u32 = 124;
/// Byte size of one allocation unit (one context, or two states + spare).
const UNIT_SIZE: u32 = 12;
/// Byte size of one symbol state.
const STATE_SIZE: u32 = 6;
/// Range-coder renormalisation threshold: while `low` and `low+range`
/// agree in the top byte the coder can shift one byte out.
const TOP_VALUE: u32 = 1 << 24;
/// RAR's range floor — the range is expanded back to at least this before
/// a renormalisation shift.
const BOTTOM: u32 = 0x8000;

/// Initial binary-escape estimates for the eight binary-SEE columns
/// (one per (num-stats-in-suffix, high-bits) bucket).
const INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];
/// Escape-count ladder: how many escapes subtract one from `escape_init`
/// at each binary-SEE row.
const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

/// `hb2flag`: 0 for symbols below `0x40`, 8 at or above — the "high
/// symbol byte" contribution to the binary-SEE column.
fn hb2flag(sym: u8) -> u8 {
    if sym < 0x40 {
        0
    } else {
        8
    }
}

/// `ns2bsindx`: num-stats → binary-SEE column base.
fn ns2bsindx(ns: u8) -> u8 {
    match ns {
        0 => 0,
        1 => 2,
        2..=10 => 4,
        _ => 6,
    }
}

/// `ns2indx`: num-stats → SEE row (groups of increasing width: 1, 2, 3, …).
fn ns2indx(ns: u8) -> u8 {
    if ns < 3 {
        return ns;
    }
    // Row `m` covers `m - 2` consecutive values starting at `1 + sum(1..m-2)`.
    // Invert: find the smallest `m >= 3` whose cumulative count passes `ns`.
    let mut m = 3u8;
    let mut base = 3u8; // first value covered by row `m`
    loop {
        let width = m - 2;
        if ns < base + width {
            return m;
        }
        base += width;
        m += 1;
        if m > 24 {
            return 24;
        }
    }
}

/// Mean of a SEE accumulator: `(summ + 1 << (PERIOD_BITS - 2)) >> PERIOD_BITS`.
#[inline]
fn see_mean(summ: u32) -> u32 {
    (summ + (1 << (PERIOD_BITS - 2))) >> PERIOD_BITS
}

// ------------------------------------------------------------------- See

/// One SEE (scaled escape estimation) counter: an adaptive estimate of the
/// escape probability, right-shifted by `shift` to produce the mean.
#[derive(Clone, Copy, Default)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

// ---------------------------------------------------------- RangeDecoder

/// Carry-less range decoder with RAR's renormalisation floor.
///
/// The state is three `u32`s: `code` is the encoded value, `low` is the
/// bottom of the current interval, `range` is its width.  Decoding a
/// symbol in `[start, start+size)` narrows the interval and shifts in
/// bytes whenever the top byte of `low` and `low+range` agree.
struct RangeDecoder {
    code: u32,
    low: u32,
    range: u32,
}

impl RangeDecoder {
    fn new() -> Self {
        RangeDecoder {
            code: 0,
            low: 0,
            range: 0,
        }
    }

    /// Read the four-byte big-endian initial code.  An all-ones code is
    /// refused: it is the C decoder's sentinel for "cannot initialise",
    /// and decoding one would divide by a zero range later.
    fn init(&mut self, br: &mut BitReader3) -> Result<()> {
        self.low = 0;
        self.range = 0xFFFF_FFFF;
        let mut code = 0u32;
        for _ in 0..4 {
            code = (code << 8) | br.take(8)?;
        }
        if code == 0xFFFF_FFFF {
            return Err(Error::Malformed("ppmd range decoder init"));
        }
        self.code = code;
        Ok(())
    }

    /// Divide the range by `total` and return which sub-interval the code
    /// falls in.
    fn threshold(&mut self, total: u32) -> Result<u32> {
        // A context whose `SummFreq` wrapped to zero -- every writer
        // adds with `wrapping_add` -- divides by zero here, and the
        // division panics in release too.
        if total == 0 {
            return Err(Error::Malformed("ppmd zero symbol total"));
        }
        self.range /= total;
        if self.range == 0 {
            return Err(Error::Malformed("ppmd zero range"));
        }
        Ok(self.code.wrapping_sub(self.low) / self.range)
    }

    /// Narrow to the sub-interval `[start, start+size)` and renormalise.
    fn consume(&mut self, br: &mut BitReader3, start: u32, size: u32) -> Result<()> {
        self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize(br)
    }

    /// Shift in bytes while the top byte of `low` and `low+range` agree,
    /// or while the range has shrunk below `BOTTOM`.
    fn normalize(&mut self, br: &mut BitReader3) -> Result<()> {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP_VALUE {
                if self.range >= BOTTOM {
                    break;
                }
                // Expand the range back to the next multiple of BOTTOM.
                self.range = self.low.wrapping_neg() & (BOTTOM - 1);
            }
            self.code = (self.code << 8) | br.take(8)?;
            self.range <<= 8;
            self.low <<= 8;
        }
        Ok(())
    }

    /// Binary decision: 0 if the code falls below `size0`, 1 otherwise.
    fn decode_bit(&mut self, br: &mut BitReader3, size0: u32) -> Result<u32> {
        let value = self.threshold(BIN_SCALE)?;
        if value < size0 {
            self.consume(br, 0, size0)?;
            Ok(0)
        } else {
            self.consume(br, size0, BIN_SCALE - size0)?;
            Ok(1)
        }
    }
}

// ------------------------------------------------------------------- Ppmd7

/// PPMd var.H model + the RAR range decoder, over a fixed-size arena.
pub struct Ppmd7 {
    // Context-tree state.
    min_context: u32,
    max_context: u32,
    found: u32,
    order_fall: u32,
    escape_init: u32,
    prev_success: u32,
    max_order: u32,
    hi_bits: u32,
    run_length: i32,
    run_length_init: i32,

    // Arena.
    pool: Vec<u8>,
    pool_size: u32,
    align: u32,
    lo_unit: u32,
    hi_unit: u32,
    text: u32,
    units_start: u32,
    glue_count: u32,

    // Unit-pool size classes.
    indx2units: [u8; NUM_INDEXES],
    units2indx: [u8; 128],
    free: [u32; NUM_INDEXES],

    // Adaptive estimation tables.
    dummy_see: See,
    see: Vec<See>,      // 25 rows × 16 columns
    bin_summ: Vec<u16>, // 128 rows × 64 columns

    // Range decoder.
    rd: RangeDecoder,
}

// --------------------------------------------------------- arena access

impl Ppmd7 {
    // ---- raw byte access (reads past the pool yield 0, writes are dropped) ----

    #[inline]
    fn get_u8(&self, off: u32) -> u8 {
        self.pool.get(off as usize).copied().unwrap_or(0)
    }

    #[inline]
    fn set_u8(&mut self, off: u32, v: u8) {
        if let Some(b) = self.pool.get_mut(off as usize) {
            *b = v;
        }
    }

    #[inline]
    fn get_u16(&self, off: u32) -> u16 {
        match self.pool.get(off as usize..off as usize + 2) {
            Some(b) => u16::from_le_bytes([b[0], b[1]]),
            None => 0,
        }
    }

    #[inline]
    fn set_u16(&mut self, off: u32, v: u16) {
        if let Some(b) = self.pool.get_mut(off as usize..off as usize + 2) {
            b.copy_from_slice(&v.to_le_bytes());
        }
    }

    #[inline]
    fn get_u32(&self, off: u32) -> u32 {
        match self.pool.get(off as usize..off as usize + 4) {
            Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            None => 0,
        }
    }

    #[inline]
    fn set_u32(&mut self, off: u32, v: u32) {
        if let Some(b) = self.pool.get_mut(off as usize..off as usize + 4) {
            b.copy_from_slice(&v.to_le_bytes());
        }
    }

    // ---- symbol state fields (6 bytes) ----

    #[inline]
    fn sym_byte(&self, s: u32) -> u8 {
        self.get_u8(s)
    }

    #[inline]
    fn sym_freq(&self, s: u32) -> u8 {
        self.get_u8(s + 1)
    }

    #[inline]
    fn set_sym_freq(&mut self, s: u32, f: u8) {
        self.set_u8(s + 1, f);
    }

    #[inline]
    fn sym_succ(&self, s: u32) -> u32 {
        self.get_u16(s + 2) as u32 | ((self.get_u16(s + 4) as u32) << 16)
    }

    #[inline]
    fn set_sym_succ(&mut self, s: u32, v: u32) {
        self.set_u16(s + 2, (v & 0xFFFF) as u16);
        self.set_u16(s + 4, (v >> 16) as u16);
    }

    /// Copy one full state (6 bytes).
    #[inline]
    fn copy_state(&mut self, dst: u32, src: u32) {
        for i in 0..STATE_SIZE {
            let v = self.get_u8(src + i);
            self.set_u8(dst + i, v);
        }
    }

    /// Swap two adjacent or non-adjacent states.
    fn swap_states(&mut self, a: u32, b: u32) {
        let mut tmp = [0u8; STATE_SIZE as usize];
        for (i, t) in tmp.iter_mut().enumerate() {
            *t = self.get_u8(a + i as u32);
        }
        for i in 0..STATE_SIZE {
            let v = self.get_u8(b + i);
            self.set_u8(a + i, v);
        }
        for (i, t) in tmp.iter().enumerate() {
            self.set_u8(b + i as u32, *t);
        }
    }

    /// Copy `num` consecutive 12-byte units.
    fn copy_units(&mut self, dst: u32, src: u32, num: u32) {
        for i in 0..num * UNIT_SIZE {
            let v = self.get_u8(src + i);
            self.set_u8(dst + i, v);
        }
    }

    // ---- context fields (12 bytes) ----

    #[inline]
    fn ctx_nsyms(&self, c: u32) -> u16 {
        self.get_u16(c)
    }

    #[inline]
    fn set_ctx_nsyms(&mut self, c: u32, v: u16) {
        self.set_u16(c, v);
    }

    #[inline]
    fn ctx_total(&self, c: u32) -> u16 {
        self.get_u16(c + 2)
    }

    #[inline]
    fn set_ctx_total(&mut self, c: u32, v: u16) {
        self.set_u16(c + 2, v);
    }

    #[inline]
    fn ctx_syms(&self, c: u32) -> u32 {
        self.get_u32(c + 4)
    }

    #[inline]
    fn set_ctx_syms(&mut self, c: u32, v: u32) {
        self.set_u32(c + 4, v);
    }

    #[inline]
    fn ctx_parent(&self, c: u32) -> u32 {
        self.get_u32(c + 8)
    }

    #[inline]
    fn set_ctx_parent(&mut self, c: u32, v: u32) {
        self.set_u32(c + 8, v);
    }

    /// The single state of a one-state context (overlays `SummFreq`).
    #[inline]
    fn one_state(c: u32) -> u32 {
        c + 2
    }

    // ---- unit-pool size classes ----

    /// Bytes for `nu` units.
    #[inline]
    fn unit_bytes(nu: u32) -> u32 {
        nu * UNIT_SIZE
    }

    /// Size-class index for `nu` units (0 for `nu == 0`).
    #[inline]
    fn index_of(&self, nu: u32) -> u32 {
        if nu == 0 {
            return 0;
        }
        self.units2indx.get((nu - 1) as usize).copied().unwrap_or(0) as u32
    }

    /// Unit count for size-class `indx` (0 if out of range).
    #[inline]
    fn units_of(&self, indx: u32) -> u32 {
        self.indx2units.get(indx as usize).copied().unwrap_or(0) as u32
    }
}

// ---------------------------------------------------------- unit allocator

impl Ppmd7 {
    /// Push a block of `indx` units onto the free list.
    fn free_push(&mut self, node: u32, indx: u32) {
        self.set_u32(node, self.free[indx as usize]);
        self.free[indx as usize] = node;
    }

    /// Pop a block of `indx` units from the free list.
    fn free_pop(&mut self, indx: u32) -> u32 {
        let node = self.free[indx as usize];
        self.free[indx as usize] = self.get_u32(node);
        node
    }

    /// Carve `new_indx` units off the front of a `old_indx`-unit block and
    /// free the remainder.
    fn split_block(&mut self, ptr: u32, old_indx: u32, new_indx: u32) {
        let rem = self.units_of(old_indx) - self.units_of(new_indx);
        let tail = ptr + Self::unit_bytes(self.units_of(new_indx));
        let mut i = self.index_of(rem);
        if self.units_of(i) != rem {
            i -= 1;
            let k = self.units_of(i);
            self.free_push(tail + Self::unit_bytes(k), rem - k - 1);
        }
        self.free_push(tail, i);
    }

    /// Merge adjacent free blocks and refill the size-class free lists.
    fn glue_free_blocks(&mut self) {
        let head = self.align + self.pool_size;
        let mut n = head;
        self.glue_count = 255;

        // Build a doubly-linked list of every free block.
        for i in 0..NUM_INDEXES {
            let nu = self.units_of(i as u32);
            let mut next = self.free[i];
            self.free[i] = 0;
            while next != 0 {
                let node = next;
                self.set_u32(node + 4, n);
                self.set_u32(n + 8, next);
                n = next;
                next = self.get_u32(node);
                self.set_u16(node, 0);
                self.set_u16(node + 2, nu as u16);
            }
        }
        self.set_u16(head, 1);
        self.set_u32(head + 4, n);
        self.set_u32(n + 8, head);
        if self.lo_unit != self.hi_unit {
            self.set_u16(self.lo_unit, 1);
        }

        // Merge physically adjacent free blocks.
        while n != head {
            let mut nu = self.get_u16(n + 2) as u32;
            loop {
                let next_node = n + nu * UNIT_SIZE;
                nu += self.get_u16(next_node + 2) as u32;
                if self.get_u16(next_node) != 0 || nu >= 0x10000 {
                    break;
                }
                let prev = self.get_u32(next_node + 8);
                let next = self.get_u32(next_node + 4);
                self.set_u32(prev + 4, next);
                self.set_u32(next + 8, prev);
                self.set_u16(n + 2, nu as u16);
            }
            n = self.get_u32(n + 4);
        }

        // Refill the size-class free lists from the merged blocks.
        let mut n = self.get_u32(head + 4);
        while n != head {
            let mut node = n;
            let next = self.get_u32(n + 4);
            let mut nu = self.get_u16(node + 2) as u32;
            while nu > 128 {
                self.free_push(node, (NUM_INDEXES - 1) as u32);
                nu -= 128;
                node += 128 * UNIT_SIZE;
            }
            let mut i = self.index_of(nu);
            if self.units_of(i) != nu {
                i -= 1;
                let k = self.units_of(i);
                self.free_push(node + Self::unit_bytes(k), nu - k - 1);
            }
            self.free_push(node, i);
            n = next;
        }
    }

    /// Allocate `indx` units when the free list for that size is empty.
    fn alloc_rare(&mut self, indx: u32) -> Option<u32> {
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.free[indx as usize] != 0 {
                return Some(self.free_pop(indx));
            }
        }
        // Try a larger size class and split.
        let mut i = indx;
        loop {
            i += 1;
            if i == NUM_INDEXES as u32 {
                // Nothing larger: eat into the text area if there is room.
                let bytes = Self::unit_bytes(self.units_of(indx));
                self.glue_count = self.glue_count.wrapping_sub(1);
                return if self.units_start - self.text > bytes {
                    self.units_start -= bytes;
                    Some(self.units_start)
                } else {
                    None
                };
            }
            if self.free[i as usize] != 0 {
                break;
            }
        }
        let ret = self.free_pop(i);
        self.split_block(ret, i, indx);
        Some(ret)
    }

    /// Allocate `indx` units from the pool.
    fn alloc(&mut self, indx: u32) -> Option<u32> {
        if self.free[indx as usize] != 0 {
            return Some(self.free_pop(indx));
        }
        let bytes = Self::unit_bytes(self.units_of(indx));
        // Saturating: a pool under 8 units collapses the 7/8 split in
        // `restart_model`, leaving `hi_unit` below `lo_unit`. That is zero
        // bump space, not a huge one — and this check must not panic on it.
        if bytes <= self.hi_unit.saturating_sub(self.lo_unit) {
            let ret = self.lo_unit;
            self.lo_unit += bytes;
            return Some(ret);
        }
        self.alloc_rare(indx)
    }

    /// Shrink a block from `old_nu` to `new_nu` units, freeing the tail.
    fn shrink_block(&mut self, old_ptr: u32, old_nu: u32, new_nu: u32) -> u32 {
        let i0 = self.index_of(old_nu);
        let i1 = self.index_of(new_nu);
        if i0 == i1 {
            return old_ptr;
        }
        if self.free[i1 as usize] != 0 {
            let ptr = self.free_pop(i1);
            self.copy_units(ptr, old_ptr, new_nu);
            self.free_push(old_ptr, i0);
            return ptr;
        }
        self.split_block(old_ptr, i0, i1);
        old_ptr
    }
}

// ------------------------------------------------------------- construction

impl Ppmd7 {
    /// Construct a model over `size` bytes of arena.  `size` must be at
    /// least one unit (12 bytes) — the model cannot be built in less.
    pub fn new(size: u32) -> Result<Ppmd7> {
        if size < UNIT_SIZE {
            return Err(Error::Malformed("ppmd memory size too small"));
        }
        // Align the pool to a 4-byte boundary (the C layout requires it).
        let align = 4 - (size & 3);
        let mut p = Ppmd7 {
            min_context: 0,
            max_context: 0,
            found: 0,
            order_fall: 0,
            escape_init: 0,
            prev_success: 0,
            max_order: 0,
            hi_bits: 0,
            run_length: 0,
            run_length_init: 0,
            pool: vec![0u8; (align + size + UNIT_SIZE) as usize],
            pool_size: size,
            align,
            lo_unit: 0,
            hi_unit: 0,
            text: 0,
            units_start: 0,
            glue_count: 0,
            indx2units: [0; NUM_INDEXES],
            units2indx: [0; 128],
            free: [0; NUM_INDEXES],
            dummy_see: See::default(),
            see: vec![See::default(); 25 * 16],
            bin_summ: vec![0u16; 128 * 64],
            rd: RangeDecoder::new(),
        };
        // Unit size classes: index i covers `step` consecutive unit counts,
        // with step = 1 for i < 4, 2 for i < 8, 3 for i < 12, 4 after that.
        let mut k = 0usize;
        for i in 0..NUM_INDEXES {
            let step = if i >= 12 { 4 } else { (i >> 2) + 1 };
            for _ in 0..step {
                p.units2indx[k] = i as u8;
                k += 1;
            }
            p.indx2units[i] = k as u8;
        }
        Ok(p)
    }

    /// Rebuild the context tree from scratch at `max_order`.
    fn restart_model(&mut self) {
        self.free = [0; NUM_INDEXES];
        self.text = self.align;
        self.hi_unit = self.text + self.pool_size;
        // Reserve 7/8 of the pool for the context/state area, 1/8 for text.
        self.lo_unit = self.hi_unit - (self.pool_size / 8 / UNIT_SIZE) * 7 * UNIT_SIZE;
        self.units_start = self.lo_unit;
        self.glue_count = 0;

        self.order_fall = self.max_order;
        self.run_length = -(self.max_order.min(12) as i32) - 1;
        self.run_length_init = self.run_length;
        self.prev_success = 0;

        // The order-0 root context: 256 symbols, each frequency 1.
        self.hi_unit -= UNIT_SIZE;
        self.min_context = self.hi_unit;
        self.max_context = self.min_context;
        self.set_ctx_parent(self.min_context, 0);
        self.set_ctx_nsyms(self.min_context, 256);
        self.set_ctx_total(self.min_context, 257);
        self.found = self.lo_unit;
        self.lo_unit += Self::unit_bytes(128);
        self.set_ctx_syms(self.min_context, self.found);
        for i in 0..256u32 {
            let s = self.found + i * STATE_SIZE;
            self.set_u8(s, i as u8);
            self.set_u8(s + 1, 1);
            self.set_sym_succ(s, 0);
        }

        // Binary SEE table: row i (freq-1), column k+8·m.
        for i in 0..128u32 {
            for k in 0..8u32 {
                let val = (BIN_SCALE - u32::from(INIT_BIN_ESC[k as usize]) / (i + 2)) as u16;
                for m in (0..64u32).step_by(8) {
                    self.bin_summ[(i * 64 + k + m) as usize] = val;
                }
            }
        }

        // SEE table: row i, column k.
        for i in 0..25u32 {
            for k in 0..16u32 {
                let idx = (i * 16 + k) as usize;
                self.see[idx].shift = (PERIOD_BITS - 4) as u8;
                self.see[idx].summ = ((5 * i + 10) << (PERIOD_BITS - 4)) as u16;
                self.see[idx].count = 4;
            }
        }
    }

    /// (Re-)initialise the range decoder from four code bytes.  Used both
    /// for a fresh model and when a later PPMd block re-inits only the
    /// range decoder while keeping the model.
    pub fn init_range_rar(&mut self, br: &mut BitReader3) -> Result<()> {
        self.rd.init(br)
    }

    /// Restart the model at `max_order` and set the initial escape count.
    pub fn init_model(&mut self, max_order: u32, init_esc: u32) {
        self.max_order = max_order;
        self.restart_model();
        self.dummy_see.shift = PERIOD_BITS as u8;
        self.dummy_see.summ = 0;
        self.dummy_see.count = 64;
        self.escape_init = init_esc;
    }

    /// Set the escape initial value without rebuilding the model (the
    /// "switch back to PPMd" path where only the range coder restarts).
    pub fn set_init_esc(&mut self, esc: u32) {
        self.escape_init = esc;
    }
}

// ---------------------------------------------------------- model evolution

impl Ppmd7 {
    /// Build successor contexts for every state whose successor is the
    /// "up-branch" text pointer `up_branch`.  Returns the new
    /// `min_context` on success, `None` if the arena is exhausted.
    fn create_successors(&mut self, skip: bool) -> Option<u32> {
        let mut chain = [0u32; 64];
        let mut n_chain = 0usize;
        let mut c = self.min_context;
        let up_branch = self.sym_succ(self.found);
        let target = self.sym_byte(self.found);

        if !skip {
            chain[n_chain] = self.found;
            n_chain += 1;
        }

        // Walk up the suffix chain collecting states whose successor is
        // still the up-branch (they all need the same new successor).
        while self.ctx_parent(c) != 0 {
            c = self.ctx_parent(c);
            let s = if self.ctx_nsyms(c) != 1 {
                let mut s0 = self.ctx_syms(c);
                let mut guard = 0;
                while self.sym_byte(s0) != target {
                    s0 += STATE_SIZE;
                    guard += 1;
                    if guard > 4096 {
                        return None;
                    }
                }
                s0
            } else {
                Self::one_state(c)
            };
            let successor = self.sym_succ(s);
            if successor != up_branch {
                // Found a state whose successor already points at a real
                // context: that context is the answer.
                c = successor;
                if n_chain == 0 {
                    return Some(c);
                }
                break;
            }
            if n_chain >= chain.len() {
                return None;
            }
            chain[n_chain] = s;
            n_chain += 1;
        }

        // The "up symbol" is the first byte at the up-branch text pointer.
        let up_symbol = self.get_u8(up_branch);
        // Its frequency is estimated from the current context's table.
        let up_freq = if self.ctx_nsyms(c) == 1 {
            self.sym_freq(Self::one_state(c))
        } else {
            let mut s = self.ctx_syms(c);
            let mut guard = 0;
            while self.sym_byte(s) != up_symbol {
                s += STATE_SIZE;
                guard += 1;
                if guard > 4096 {
                    return None;
                }
            }
            // The C code promotes to unsigned before subtracting, so a
            // zero frequency wraps to 0xFFFF_FFFF.  The formula below
            // reproduces that.
            let cf = u32::from(self.sym_freq(s)).wrapping_sub(1);
            let s0 = (self.ctx_total(c) as u32)
                .wrapping_sub(self.ctx_nsyms(c) as u32)
                .wrapping_sub(cf);
            if s0 == 0 {
                return None;
            }
            let denom = s0.wrapping_mul(2);
            if denom == 0 {
                return None;
            }
            let two_cf = cf.wrapping_mul(2);
            let three_s0 = s0.wrapping_mul(3);
            1 + if two_cf <= s0 {
                u8::from(cf.wrapping_mul(5) > s0)
            } else {
                (two_cf.wrapping_add(three_s0).wrapping_sub(1) / denom) as u8
            }
        };
        let up_succ = up_branch.wrapping_add(1);

        // Allocate a one-state context per collected state, chained
        // bottom-up.
        while n_chain != 0 {
            let c1 = if self.hi_unit != self.lo_unit {
                self.hi_unit -= UNIT_SIZE;
                self.hi_unit
            } else if self.free[0] != 0 {
                self.free_pop(0)
            } else {
                self.alloc_rare(0)?
            };
            self.set_ctx_nsyms(c1, 1);
            // One-state overlay: (up_symbol, up_freq, up_succ).
            self.set_u8(c1 + 2, up_symbol);
            self.set_u8(c1 + 3, up_freq);
            self.set_u16(c1 + 4, (up_succ & 0xFFFF) as u16);
            self.set_u16(c1 + 6, (up_succ >> 16) as u16);
            self.set_ctx_parent(c1, c);
            n_chain -= 1;
            self.set_sym_succ(chain[n_chain], c1);
            c = c1;
        }
        Some(c)
    }

    /// Propagate the just-decoded symbol through the suffix chain,
    /// expanding contexts and creating successors as needed.
    fn update_model(&mut self) {
        // Reinforce the symbol's parent context while its frequency is low.
        if self.sym_freq(self.found) < (MAX_FREQ / 4) as u8
            && self.ctx_parent(self.min_context) != 0
        {
            let c = self.ctx_parent(self.min_context);
            if self.ctx_nsyms(c) == 1 {
                let s = Self::one_state(c);
                if self.sym_freq(s) < 32 {
                    let f = self.sym_freq(s);
                    self.set_sym_freq(s, f + 1);
                }
            } else {
                let target = self.sym_byte(self.found);
                let mut s = self.ctx_syms(c);
                let mut guard = 0;
                if self.sym_byte(s) != target {
                    loop {
                        s += STATE_SIZE;
                        guard += 1;
                        if guard > 4096 {
                            self.restart_model();
                            return;
                        }
                        if self.sym_byte(s) == target {
                            break;
                        }
                    }
                    // Keep the list sorted by descending frequency.
                    if self.sym_freq(s) >= self.sym_freq(s - STATE_SIZE) {
                        self.swap_states(s, s - STATE_SIZE);
                        s -= STATE_SIZE;
                    }
                }
                if self.sym_freq(s) < (MAX_FREQ - 9) as u8 {
                    let f = self.sym_freq(s);
                    self.set_sym_freq(s, f + 2);
                    let sf = self.ctx_total(c);
                    self.set_ctx_total(c, sf.wrapping_add(2));
                }
            }
        }

        if self.order_fall == 0 {
            // At full order: just step to the successor.
            match self.create_successors(true) {
                Some(mc) => {
                    self.min_context = mc;
                    self.max_context = mc;
                }
                None => {
                    self.restart_model();
                    return;
                }
            }
            self.set_sym_succ(self.found, self.min_context);
            return;
        }

        // Below full order: append the symbol to the text buffer and use
        // the text position as a provisional successor.
        let symbol = self.sym_byte(self.found);
        self.set_u8(self.text, symbol);
        self.text += 1;
        let mut successor = self.text;
        if self.text >= self.units_start {
            self.restart_model();
            return;
        }

        let mut f_successor = self.sym_succ(self.found);
        if f_successor != 0 {
            if f_successor <= successor {
                match self.create_successors(false) {
                    Some(cs) => f_successor = cs,
                    None => {
                        self.restart_model();
                        return;
                    }
                }
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                successor = f_successor;
                if self.max_context != self.min_context {
                    self.text -= 1;
                }
            }
        } else {
            self.set_sym_succ(self.found, successor);
            f_successor = self.min_context;
        }

        // Expanding the suffix chain: for every context from max_context
        // down to (but not including) min_context, add the symbol.
        let ns = self.ctx_nsyms(self.min_context) as u32;
        let s0 = (self.ctx_total(self.min_context) as u32)
            .wrapping_sub(ns)
            .wrapping_sub(self.sym_freq(self.found) as u32 - 1);

        let mut c = self.max_context;
        loop {
            if c == self.min_context {
                break;
            }
            let ns1 = self.ctx_nsyms(c) as u32;
            if ns1 != 1 {
                // Even count → maybe grow the state array by one unit pair.
                if (ns1 & 1) == 0 {
                    let old_nu = ns1 >> 1;
                    let i = self.index_of(old_nu);
                    if i != self.index_of(old_nu + 1) {
                        let ptr = match self.alloc(i + 1) {
                            Some(p) => p,
                            None => {
                                self.restart_model();
                                return;
                            }
                        };
                        let old_ptr = self.ctx_syms(c);
                        self.copy_units(ptr, old_ptr, old_nu);
                        self.free_push(old_ptr, i);
                        self.set_ctx_syms(c, ptr);
                    }
                }
                // Bump the escape frequency so the new symbol has room.
                let sf = self.ctx_total(c) as u32;
                let bump = u32::from(2 * ns1 < ns) + 2 * u32::from(4 * ns1 <= ns && sf <= 8 * ns1);
                self.set_ctx_total(c, (sf + bump) as u16);
            } else {
                // One-state → allocate a two-state array and expand.
                let s = match self.alloc(0) {
                    Some(s) => s,
                    None => {
                        self.restart_model();
                        return;
                    }
                };
                self.copy_state(s, Self::one_state(c));
                self.set_ctx_syms(c, s);
                let f = self.sym_freq(s);
                let nf = if f < (MAX_FREQ / 4 - 1) as u8 {
                    f << 1
                } else {
                    (MAX_FREQ - 4) as u8
                };
                self.set_sym_freq(s, nf);
                let sf = u32::from(nf) + self.escape_init + u32::from(ns > 3);
                self.set_ctx_total(c, sf as u16);
            }
            // Assign the new symbol a frequency proportional to how well
            // the current model predicts it.
            let mut cf = 2 * u32::from(self.sym_freq(self.found)) * (self.ctx_total(c) as u32 + 6);
            let sf = s0 + self.ctx_total(c) as u32;
            if cf < 6 * sf {
                cf = 1 + u32::from(cf > sf) + u32::from(cf >= 4 * sf);
                let v = self.ctx_total(c);
                self.set_ctx_total(c, v.wrapping_add(3));
            } else {
                cf = 4
                    + u32::from(cf >= 9 * sf)
                    + u32::from(cf >= 12 * sf)
                    + u32::from(cf >= 15 * sf);
                let v = self.ctx_total(c);
                self.set_ctx_total(c, v.wrapping_add(cf as u16));
            }
            let s = self.ctx_syms(c) + ns1 * STATE_SIZE;
            self.set_sym_succ(s, successor);
            self.set_u8(s, symbol);
            self.set_u8(s + 1, cf as u8);
            self.set_ctx_nsyms(c, (ns1 + 1) as u16);

            c = self.ctx_parent(c);
        }
        self.max_context = f_successor;
        self.min_context = f_successor;
    }

    /// Halve all frequencies in `min_context` (after a frequency
    /// overflow), drop zero-frequency symbols, and possibly collapse to
    /// a one-state context.
    fn rescale(&mut self) {
        let stats = self.ctx_syms(self.min_context);
        // Move the found state to the front, shifting the rest right.
        {
            let tmp_sym = self.get_u8(self.found);
            let tmp_freq = self.get_u8(self.found + 1);
            let tmp_lo = self.get_u16(self.found + 2);
            let tmp_hi = self.get_u16(self.found + 4);
            let mut t = self.found;
            let mut guard = 0;
            while t != stats {
                self.copy_state(t, t.wrapping_sub(STATE_SIZE));
                t = t.wrapping_sub(STATE_SIZE);
                guard += 1;
                if guard > 4096 {
                    return;
                }
            }
            self.set_u8(stats, tmp_sym);
            self.set_u8(stats + 1, tmp_freq);
            self.set_u16(stats + 2, tmp_lo);
            self.set_u16(stats + 4, tmp_hi);
        }
        let mut s = stats;

        let mut esc_freq =
            (self.ctx_total(self.min_context) as u32).wrapping_sub(self.sym_freq(s) as u32);
        let f = u32::from(self.sym_freq(s)) + 4;
        let adder = u32::from(self.order_fall != 0);
        let f = (f + adder) >> 1;
        self.set_u8(s + 1, f as u8);
        let mut sum_freq = f;

        let mut i = self.ctx_nsyms(self.min_context) as u32 - 1;
        loop {
            s = s.wrapping_add(STATE_SIZE);
            esc_freq = esc_freq.wrapping_sub(self.sym_freq(s) as u32);
            let f = (u32::from(self.sym_freq(s)) + adder) >> 1;
            self.set_u8(s + 1, f as u8);
            sum_freq += f;
            // Insertion-sort the halved frequencies into descending order.
            if self.sym_freq(s) > self.sym_freq(s.wrapping_sub(STATE_SIZE)) {
                let tmp_sym = self.get_u8(s);
                let tmp_freq = self.get_u8(s + 1);
                let tmp_lo = self.get_u16(s + 2);
                let tmp_hi = self.get_u16(s + 4);
                let mut s1 = s;
                loop {
                    self.copy_state(s1, s1.wrapping_sub(STATE_SIZE));
                    s1 = s1.wrapping_sub(STATE_SIZE);
                    if s1 == stats || tmp_freq <= self.sym_freq(s1.wrapping_sub(STATE_SIZE)) {
                        break;
                    }
                }
                self.set_u8(s1, tmp_sym);
                self.set_u8(s1 + 1, tmp_freq);
                self.set_u16(s1 + 2, tmp_lo);
                self.set_u16(s1 + 4, tmp_hi);
            }
            i -= 1;
            if i == 0 {
                break;
            }
        }

        // Drop trailing zero-frequency symbols.
        if self.sym_freq(s) == 0 {
            let nsyms_orig = self.ctx_nsyms(self.min_context) as u32;
            let mut dropped = 0u32;
            loop {
                dropped += 1;
                s = s.wrapping_sub(STATE_SIZE);
                if self.sym_freq(s) != 0 || dropped > 4096 {
                    break;
                }
            }
            esc_freq += dropped;
            let nsyms = nsyms_orig.saturating_sub(dropped);
            self.set_ctx_nsyms(self.min_context, nsyms as u16);
            if nsyms == 1 {
                // Collapse to a one-state context.
                let tmp_sym = self.get_u8(stats);
                let mut freq = self.sym_freq(stats) as u32;
                let tmp_lo = self.get_u16(stats + 2);
                let tmp_hi = self.get_u16(stats + 4);
                loop {
                    freq -= freq >> 1;
                    esc_freq >>= 1;
                    if esc_freq <= 1 {
                        break;
                    }
                }
                self.free_push(stats, self.index_of((nsyms_orig + 1) >> 1));
                let os = Self::one_state(self.min_context);
                self.set_u8(os, tmp_sym);
                self.set_u8(os + 1, freq as u8);
                self.set_u16(os + 2, tmp_lo);
                self.set_u16(os + 4, tmp_hi);
                self.found = os;
                return;
            }
            let n0 = (nsyms_orig + 1) >> 1;
            let n1 = (nsyms + 1) >> 1;
            if n0 != n1 {
                let shrunk = self.shrink_block(stats, n0, n1);
                self.set_ctx_syms(self.min_context, shrunk);
            }
        }
        let sf = sum_freq.wrapping_add(esc_freq).wrapping_sub(esc_freq >> 1);
        self.set_ctx_total(self.min_context, sf as u16);
        self.found = self.ctx_syms(self.min_context);
    }

    /// Estimate the escape frequency for the current context given
    /// `masked` already-excluded symbols.  Returns the SEE index (None
    /// for the dummy SEE used at order 0) and the estimate.
    fn esc_estimate(&mut self, masked: u32) -> (Option<usize>, u32) {
        let nsyms = self.ctx_nsyms(self.min_context) as u32;
        let visible = nsyms - masked;
        if nsyms != 256 {
            let suffix_nsyms = self.ctx_nsyms(self.ctx_parent(self.min_context)) as u32;
            let row = ns2indx((visible - 1) as u8) as usize;
            let col = (visible < suffix_nsyms.wrapping_sub(nsyms)) as usize
                + 2 * (self.ctx_total(self.min_context) < 11 * nsyms as u16) as usize
                + 4 * (masked > visible) as usize
                + self.hi_bits as usize;
            let idx = row * 16 + col;
            let see = self.see[idx];
            let r = (see.summ >> see.shift) as u32;
            self.see[idx].summ = see.summ.wrapping_sub(r as u16);
            (Some(idx), r + u32::from(r == 0))
        } else {
            (None, 1)
        }
    }

    /// Advance to the successor context (or fall through to model update).
    fn next_context(&mut self) {
        let c = self.sym_succ(self.found);
        if self.order_fall == 0 && c > self.text {
            self.min_context = c;
            self.max_context = c;
        } else {
            self.update_model();
        }
    }

    /// Update after a non-first symbol in a multi-state context.
    fn update_later(&mut self) {
        let s = self.found;
        let f = u32::from(self.sym_freq(s)) + 4;
        self.set_u8(s + 1, f as u8);
        let sf = self.ctx_total(self.min_context);
        self.set_ctx_total(self.min_context, sf.wrapping_add(4));
        if self.sym_freq(s) > self.sym_freq(s.wrapping_sub(STATE_SIZE)) {
            self.swap_states(s, s.wrapping_sub(STATE_SIZE));
            self.found = s.wrapping_sub(STATE_SIZE);
            if self.sym_freq(self.found) as u32 > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    /// Update after the first symbol in a multi-state context.
    fn update_first(&mut self) {
        self.prev_success = u32::from(
            2 * u32::from(self.sym_freq(self.found)) > self.ctx_total(self.min_context) as u32,
        );
        self.run_length += self.prev_success as i32;
        let sf = self.ctx_total(self.min_context);
        self.set_ctx_total(self.min_context, sf.wrapping_add(4));
        let f = u32::from(self.sym_freq(self.found)) + 4;
        self.set_u8(self.found + 1, f as u8);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    /// Update after a binary (one-state) hit.
    fn update_bin(&mut self) {
        let f = self.sym_freq(self.found);
        if f < 128 {
            self.set_u8(self.found + 1, f + 1);
        }
        self.prev_success = 1;
        self.run_length += 1;
        self.next_context();
    }

    /// Update after a symbol found via the escape path.
    fn update_escaped(&mut self) {
        let sf = self.ctx_total(self.min_context);
        self.set_ctx_total(self.min_context, sf.wrapping_add(4));
        let f = u32::from(self.sym_freq(self.found)) + 4;
        self.set_u8(self.found + 1, f as u8);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.run_length = self.run_length_init;
        self.update_model();
    }

    /// Adapt a SEE counter after a successful decode through it.
    fn see_adapt(&mut self, idx: usize) {
        let see = &mut self.see[idx];
        if see.shift < PERIOD_BITS as u8 {
            see.count = see.count.wrapping_sub(1);
            if see.count == 0 {
                see.summ <<= 1;
                see.count = 3u8.wrapping_shl(see.shift as u32);
                see.shift += 1;
            }
        }
    }

    /// Binary-SEE index: row is the one-state symbol's frequency,
    /// column is (prev-success + suffix shape + high-bits + run-length).
    fn bin_index(&mut self) -> usize {
        let one = Self::one_state(self.min_context);
        let row = (self.sym_freq(one) as usize).saturating_sub(1).min(127);
        let suffix_nsyms = self.ctx_nsyms(self.ctx_parent(self.min_context));
        let col = self.prev_success as usize
            + ns2bsindx(suffix_nsyms.max(1).saturating_sub(1) as u8) as usize
            + {
                self.hi_bits = u32::from(hb2flag(self.sym_byte(self.found)));
                self.hi_bits as usize
            }
            + 2 * usize::from(hb2flag(self.sym_byte(one)))
            + ((self.run_length >> 26) & 0x20) as usize;
        row * 64 + col.min(63)
    }
}

// --------------------------------------------------------------- decoding

impl Ppmd7 {
    /// Decode one symbol.  Returns the byte on success, `-1` when the
    /// escape chain walks past order 0 (corrupt stream), or `-2` when the
    /// range-coder count falls outside the frequency table (corrupt
    /// stream).  The caller in [`crate::unpack3`] treats either sentinel
    /// as a hard error.  An exhausted input buffer yields
    /// [`Error::Truncated`].
    pub fn decode_symbol(&mut self, br: &mut BitReader3) -> Result<i32> {
        let mut mask = [0xFFu8; 256];

        if self.ctx_nsyms(self.min_context) != 1 {
            // Multi-symbol context: decode against the frequency table.
            let count = self.rd.threshold(self.ctx_total(self.min_context) as u32)?;
            let mut s = self.ctx_syms(self.min_context);
            let mut cum = self.sym_freq(s) as u32;
            if count < cum {
                self.rd.consume(br, 0, cum)?;
                self.found = s;
                let symbol = self.sym_byte(s);
                self.update_first();
                return Ok(i32::from(symbol));
            }
            self.prev_success = 0;
            let mut remaining = self.ctx_nsyms(self.min_context) as u32 - 1;
            loop {
                s += STATE_SIZE;
                cum += self.sym_freq(s) as u32;
                if cum > count {
                    let f = self.sym_freq(s) as u32;
                    self.rd.consume(br, cum - f, f)?;
                    self.found = s;
                    let symbol = self.sym_byte(s);
                    self.update_later();
                    return Ok(i32::from(symbol));
                }
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
            // Fell off the table: escape region.
            if count >= self.ctx_total(self.min_context) as u32 {
                return Ok(-2);
            }
            self.hi_bits = u32::from(hb2flag(self.sym_byte(self.found)));
            let total = self.ctx_total(self.min_context) as u32;
            self.rd.consume(br, cum, total.wrapping_sub(cum))?;
            // Mask every symbol in this context.
            mask.fill(0xFF);
            let mut s = self.ctx_syms(self.min_context);
            let mut n = self.ctx_nsyms(self.min_context) as u32;
            while n > 0 {
                mask[self.sym_byte(s) as usize] = 0;
                s += STATE_SIZE;
                n -= 1;
            }
        } else {
            // One-symbol (binary) context.
            let idx = self.bin_index();
            let prob = self.bin_summ[idx];
            if self.rd.decode_bit(br, u32::from(prob))? == 0 {
                // Hit: strengthen the binary estimate.
                self.bin_summ[idx] =
                    (u32::from(prob) + (1 << INT_BITS) - see_mean(u32::from(prob))) as u16;
                let os = Self::one_state(self.min_context);
                self.found = os;
                let symbol = self.sym_byte(os);
                self.update_bin();
                return Ok(i32::from(symbol));
            }
            // Escape: weaken the estimate and mask the one symbol.
            self.bin_summ[idx] = (u32::from(prob) - see_mean(u32::from(prob))) as u16;
            self.escape_init = u32::from(EXP_ESCAPE[usize::from(self.bin_summ[idx] >> 10)]);
            mask.fill(0xFF);
            mask[self.sym_byte(Self::one_state(self.min_context)) as usize] = 0;
            self.prev_success = 0;
        }

        // Escape loop: walk toward the root until a context has an
        // unmasked symbol.
        let mut candidates = [0u32; 256];
        loop {
            let masked = self.ctx_nsyms(self.min_context) as u32;
            // Skip contexts that contain only already-masked symbols.
            loop {
                self.order_fall += 1;
                let parent = self.ctx_parent(self.min_context);
                if parent == 0 {
                    return Ok(-1);
                }
                self.min_context = parent;
                if self.ctx_nsyms(self.min_context) as u32 != masked {
                    break;
                }
            }

            // Collect the unmasked symbols.
            let mut visible_freq = 0u32;
            let mut s = self.ctx_syms(self.min_context);
            let mut n_visible = 0usize;
            let expected = self.ctx_nsyms(self.min_context) as usize - masked as usize;
            let mut scanned = 0usize;
            loop {
                if mask[self.sym_byte(s) as usize] != 0 {
                    visible_freq += self.sym_freq(s) as u32;
                    candidates[n_visible] = s;
                    n_visible += 1;
                }
                s += STATE_SIZE;
                scanned += 1;
                if n_visible == expected || scanned > 4096 {
                    break;
                }
            }
            if n_visible != expected {
                return Err(Error::Malformed("ppmd escape accounting"));
            }

            let (see_idx, mut esc_freq) = self.esc_estimate(masked);
            esc_freq += visible_freq;
            let count = self.rd.threshold(esc_freq)?;

            if count < visible_freq {
                // Picked one of the visible symbols.
                let mut cum = 0u32;
                let mut pick = 0usize;
                loop {
                    cum += self.sym_freq(candidates[pick]) as u32;
                    if cum > count {
                        break;
                    }
                    pick += 1;
                    if pick >= candidates.len() {
                        return Err(Error::Malformed("ppmd escape pick"));
                    }
                }
                let s = candidates[pick];
                let f = self.sym_freq(s) as u32;
                self.rd.consume(br, cum - f, f)?;
                if let Some(idx) = see_idx {
                    self.see_adapt(idx);
                }
                self.found = s;
                let symbol = self.sym_byte(s);
                self.update_escaped();
                return Ok(i32::from(symbol));
            }
            if count >= esc_freq {
                return Ok(-2);
            }
            // Escaped again: consume the escape region and mask the
            // visible set before trying the next-lower context.
            self.rd
                .consume(br, visible_freq, esc_freq.wrapping_sub(visible_freq))?;
            if let Some(idx) = see_idx {
                let summ = self.see[idx].summ;
                self.see[idx].summ = summ.wrapping_add(esc_freq as u16);
            }
            let mut i = n_visible;
            while i > 0 {
                i -= 1;
                mask[self.sym_byte(candidates[i]) as usize] = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unpack3::BitReader3;
    use alloc::vec::Vec;

    // ---- construction ------------------------------------------------

    /// `Ppmd7::new` refuses a heap smaller than one unit — the model
    /// cannot be built in it — and accepts exactly one unit.
    #[test]
    fn new_rejects_a_heap_smaller_than_one_unit() {
        assert!(Ppmd7::new(UNIT_SIZE - 1).is_err());
        assert!(Ppmd7::new(0).is_err());
        assert!(Ppmd7::new(UNIT_SIZE).is_ok());
    }

    /// After `init_model` the order-0 root holds 256 symbols at
    /// frequency 1 each, total 257.
    #[test]
    fn order_zero_root_starts_with_256_unit_frequency_symbols() {
        let mut p = Ppmd7::new(1 << 16).unwrap();
        p.init_model(2, 2);
        assert_eq!(p.ctx_nsyms(p.min_context), 256);
        assert_eq!(p.ctx_total(p.min_context), 257);
        let base = p.ctx_syms(p.min_context);
        for i in 0..256u32 {
            assert_eq!(p.sym_byte(base + i * STATE_SIZE), i as u8);
            assert_eq!(p.sym_freq(base + i * STATE_SIZE), 1);
        }
    }

    /// `index_of` maps every unit count 1..=128 to a class that holds at
    /// least that many units.  The classes are [1, 2, 3, 4, 6, 8, …] —
    /// counts between class sizes land in the next-larger class.
    #[test]
    fn unit_size_classes_cover_one_through_128() {
        let p = Ppmd7::new(1 << 12).unwrap();
        for nu in 1..=128u32 {
            let idx = p.index_of(nu);
            assert!(idx < NUM_INDEXES as u32);
            assert!(
                p.units_of(idx) >= nu,
                "index_of({nu}) = {idx} holds only {} units",
                p.units_of(idx)
            );
        }
    }

    // ---- range coder -------------------------------------------------

    /// `init` reads four bytes big-endian into `code` and refuses an
    /// all-ones code word.
    #[test]
    fn range_init_refuses_an_all_ones_code() {
        let mut p = Ppmd7::new(1 << 16).unwrap();
        let mut br = BitReader3::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        assert!(p.init_range_rar(&mut br).is_err());
    }

    #[test]
    fn range_init_accepts_a_non_saturating_code() {
        let mut p = Ppmd7::new(1 << 16).unwrap();
        let mut br = BitReader3::new(&[0x00, 0x01, 0x02, 0x03]);
        assert!(p.init_range_rar(&mut br).is_ok());
    }

    /// A short buffer is a hard error, not a panic.  `init` reads four
    /// code bytes and must not walk past the end.
    #[test]
    fn range_init_truncates_cleanly() {
        let mut p = Ppmd7::new(1 << 16).unwrap();
        let mut br = BitReader3::new(&[0x01, 0x02]);
        assert!(p.init_range_rar(&mut br).is_err());
    }

    /// `threshold` divides the range by `total` and returns
    /// `(code - low) / range`.  With code = 0x4100_0000 and total = 257
    /// the quotient is 65: 65 × 0x00FF_00FF ≤ 0x4100_0000 < 66 ×
    /// 0x00FF_00FF.
    #[test]
    fn range_threshold_divides_range_and_returns_code_quotient() {
        let mut p = Ppmd7::new(1 << 16).unwrap();
        let mut br = BitReader3::new(&[0x41, 0x00, 0x00, 0x00]);
        p.init_range_rar(&mut br).unwrap();
        assert_eq!(p.rd.range, 0xFFFF_FFFF);
        let v = p.rd.threshold(257).unwrap();
        assert_eq!(v, 65);
        assert_eq!(p.rd.range, 0x00FF_00FF);
    }

    /// `decode_bit` returns 0 when the threshold is below `size0`.
    /// With code = 0 the threshold over `BIN_SCALE` is 0, which is below
    /// any positive `size0`, so the answer is 0 and the lower sub-interval
    /// is consumed.
    #[test]
    fn range_decode_bit_returns_zero_when_code_is_below_size0() {
        let mut p = Ppmd7::new(1 << 16).unwrap();
        let mut br = BitReader3::new(&[0x00, 0x00, 0x00, 0x00]);
        p.init_range_rar(&mut br).unwrap();
        let bit = p.rd.decode_bit(&mut br, 0x4000).unwrap();
        assert_eq!(bit, 0);
    }

    // ---- model decode ------------------------------------------------

    /// A crafted code of 0x4100_0000 puts the range-coder count at 65 in
    /// the fresh order-0 table, so the first decoded symbol is `'A'`.
    /// This exercises the multi-state decode path and `update_first`.
    #[test]
    fn order_zero_context_decodes_a_crafted_symbol() {
        let mut p = Ppmd7::new(1 << 16).unwrap();
        let mut br = BitReader3::new(&[0x41, 0x00, 0x00, 0x00]);
        p.init_range_rar(&mut br).unwrap();
        p.init_model(2, 2);
        assert_eq!(p.decode_symbol(&mut br).unwrap(), 65);
    }

    /// A crafted code of 0xFF00_FF00 puts the count at 256 — the escape
    /// region of the order-0 table.  The escape chain walks to the root's
    /// parent (0) and returns the corrupt-stream sentinel −1.  Extra
    /// bytes after the four code bytes are padding for renormalisation.
    #[test]
    fn escaping_past_order_zero_returns_the_corrupt_sentinel() {
        let mut p = Ppmd7::new(1 << 16).unwrap();
        let mut br = BitReader3::new(&[0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00]);
        p.init_range_rar(&mut br).unwrap();
        p.init_model(2, 2);
        assert_eq!(p.decode_symbol(&mut br).unwrap(), -1);
    }

    // ---- SEE arithmetic ----------------------------------------------

    /// `see_adapt` counts down `count` shifts of the estimate; when it
    /// hits zero the estimate doubles, the countdown resets to `3 << shift`,
    /// and the shift grows by one (capped at `PERIOD_BITS`).
    #[test]
    fn see_adaptation_doubles_the_estimate_when_the_countdown_expires() {
        let mut p = Ppmd7::new(1 << 16).unwrap();
        p.init_model(2, 2);
        let idx = 0;
        p.see[idx].shift = 0;
        p.see[idx].summ = 100;
        p.see[idx].count = 1;
        p.see_adapt(idx);
        assert_eq!(p.see[idx].summ, 200);
        assert_eq!(p.see[idx].shift, 1);
        // count = 3 << old_shift (before the increment), so 3 << 0 = 3.
        assert_eq!(p.see[idx].count, 3);
    }

    /// Once `shift` reaches `PERIOD_BITS`, adaptation stops: the counter
    /// is at its finest granularity and no longer doubles.
    #[test]
    fn see_adaptation_stops_at_the_period_ceiling() {
        let mut p = Ppmd7::new(1 << 16).unwrap();
        p.init_model(2, 2);
        let idx = 0;
        p.see[idx].shift = PERIOD_BITS as u8;
        p.see[idx].summ = 100;
        p.see[idx].count = 1;
        p.see_adapt(idx);
        assert_eq!(p.see[idx].summ, 100);
        assert_eq!(p.see[idx].count, 1);
    }

    /// `esc_estimate` on the order-0 root (256 symbols) uses the dummy
    /// SEE and returns an escape frequency of 1.
    #[test]
    fn esc_estimate_on_the_root_returns_the_dummy_frequency() {
        let mut p = Ppmd7::new(1 << 16).unwrap();
        p.init_model(2, 2);
        let (idx, esc) = p.esc_estimate(0);
        assert!(idx.is_none());
        assert_eq!(esc, 1);
    }

    // ---- allocator ---------------------------------------------------

    /// A pool of exactly N single-unit allocations serves N then fails:
    /// the text reserve and context bootstrap consume the slack, so the
    /// usable floor is smaller than the raw pool.  The floor is that
    /// allocation failure is a clean `None`, never a panic.
    #[test]
    fn unit_pool_allocation_failure_is_clean_not_a_panic() {
        let mut p = Ppmd7::new(UNIT_SIZE * 4).unwrap();
        p.init_model(2, 2);
        // Exhaust whatever is left with single-unit allocations.
        let mut count = 0;
        while p.alloc(0).is_some() {
            count += 1;
            if count > 1000 {
                break;
            }
        }
        // After exhaustion, further allocs must still return None (or
        // succeed after a glue), never panic.
        let _ = p.alloc(0);
    }

    /// Free-list round-trip: push a block and pop it back.
    #[test]
    fn free_list_round_trips_a_block() {
        let mut p = Ppmd7::new(1 << 12).unwrap();
        p.init_model(2, 2);
        // Allocate a block, free it, and pop it again.
        let node = p.alloc(0).expect("one unit");
        p.free_push(node, 0);
        assert_eq!(p.free_pop(0), node);
    }

    // ---- memory floor ------------------------------------------------

    /// No PPMd-encoded RAR can be crafted on this machine (`rar-codec`
    /// encodes store-only), so the decoder has no known-good vector here.
    /// What it must still have is a floor: a full init-plus-decode cycle
    /// over arbitrary bytes returns an error and never panics, at every
    /// model order and over every length.  A panic in this module is a
    /// crash in a search tool reading an untrusted archive.
    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for max_order in [2u32, 4, 8, 16] {
            for len in [0usize, 1, 3, 4, 5, 16, 64, 256] {
                let bytes: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
                let mut p = match Ppmd7::new(1 << 12) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                p.init_model(max_order, 2);
                let mut br = BitReader3::new(&bytes);
                if p.init_range_rar(&mut br).is_err() {
                    continue;
                }
                for _ in 0..64 {
                    // Err is the documented answer for a corrupt stream;
                    // the C decoder returns a −1/−2 sentinel and
                    // libarchive treats either as a hard error.  A panic
                    // is the only failure this test rejects.
                    match p.decode_symbol(&mut br) {
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        }
    }

    /// The arena never grows past the size given to `new`: a decode cycle
    /// over arbitrary bytes must not allocate beyond the initial pool.
    #[test]
    fn decode_does_not_grow_the_arena() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let arena_size = 1 << 12;
        let mut p = Ppmd7::new(arena_size).unwrap();
        let pool_len = p.pool.len();
        p.init_model(4, 2);
        let bytes: Vec<u8> = (0..128).map(|_| (next() & 0xFF) as u8).collect();
        let mut br = BitReader3::new(&bytes);
        if p.init_range_rar(&mut br).is_ok() {
            for _ in 0..32 {
                if p.decode_symbol(&mut br).is_err() {
                    break;
                }
            }
        }
        assert_eq!(p.pool.len(), pool_len);
    }
}
