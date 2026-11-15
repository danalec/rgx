// SPDX-License-Identifier: Apache-2.0

//! Structural JSON scanner: stage 1 of a two-stage parser.
//!
//! It answers one question about a byte slice and nothing else — **which bytes
//! are structural, and which are string delimiters** — as one bit per byte for
//! each. A stage-2 parser walks those two bitsets and never looks at the
//! document again. Nothing in this module interprets JSON syntax, parses a
//! value, or allocates anything except the two bitsets.
//!
//! | bit | set when |
//! |-----|----------|
//! | `structural` | the byte is `{ } [ ] : ,` or whitespace **and** is not inside a string, **or** it is a quote that opens or closes a string |
//! | `quote` | the byte is a quote that opens or closes a string |
//!
//! ## The predicate
//!
//! For byte `b` at offset `i`, with `in_string` the state *before* `b`:
//!
//! ```text
//! escaped(i)    = (the run of backslashes ending at i-1 has odd length)
//! boundary(i)   = b is '"' and not escaped(i)
//! structural(i) = boundary(i) or (b is ws or punctuation and not in_string)
//! quote(i)      = boundary(i)
//! ```
//!
//! and the state advances by `in_string ^= boundary(i)` plus the backslash-run
//! bookkeeping. [`scan_scalar`] is that, one byte at a time, in the clearest
//! form there is. [`scan_swar`] and [`scan_avx2`] are faster spellings of the
//! same predicate over 64-byte blocks, and `tests` holds all three — plus an
//! oracle transcribed from RFC 8259 without looking at any of them — against
//! each other on a corpus chosen to break each of the ways this can go wrong.
//!
//! The escaped quote is the reason the module exists. The quote that delimits a
//! string and the quote a `\` makes literal are the same byte, and only the run
//! of backslashes in front of them tells them apart. Note also that an
//! unescaped quote outside a string still *opens* one, so the state is a
//! toggle and not a flag: a lone `"` at offset 0 sets both bits.
//!
//! ## Why a union of rectangles and not one shuffle pair
//!
//! The `pshufb` classification trick — one 16-byte table per nibble, ANDed —
//! selects exactly `{b : b & 0x0F ∈ L, b >> 4 ∈ H}`, which is one rectangle of
//! the high-nibble × low-nibble grid. One AND per plane instead of a chain, but
//! **for this byte set no single rectangle is the structural set**: `,` (0x2C)
//! and `:` (0x3A) are both structural, so one rectangle holding both must light
//! low nibbles `C` and `A` and select rows 2 and 3 — and row 2 then drags in
//! `0x2A` (`#`), which is content. The two bits cannot be a 4-class code
//! either: that is the same obstruction from the other side, since row 2's
//! other members `"` and `0x2A` would have to come out as their own codes out
//! of an AND.
//!
//! A *union* of rectangles has no such problem, so this uses six: the five
//! structural groups and the quote on its own. Each is a byte set this module
//! can name, generate from a nibble mask, and test exhaustively, which a single
//! fused pair is not. Still one pass, still six `pshufb` pairs.
//!
//! ## Bytes >= 0x80
//!
//! No rectangle lights a row above `7`, so UTF-8 lead and continuation bytes
//! are OTHER by construction. That is not a runtime check — it is a property of
//! the tables, and `tests::hi_nibble_rows_above_7_are_inert` is what pins it.
//! It is also the answer to the `pshufb` high-bit rule: the instruction zeroes
//! any lane whose index has bit 7 set, which is what keeps a hand-rolled
//! nibble table in bounds when a byte's high nibble is `8`.
//!
//! ## The class codes are compared, never masked
//!
//! [`CLASS_BACKSLASH`] is `0b11`. Every use of a code in this module is an
//! equality test, and a single `class & CLASS_STRUCTURAL` would classify every
//! backslash in the document as structural *and* as a quote, which turns a lone
//! `\` into a string delimiter.
//! `tests::class_codes_are_compared_not_masked` is what keeps that true.
//!
//! ## Dispatch
//!
//! [`scan`] checks AVX2 and PCLMULQDQ at runtime and calls the vector path;
//! everything else lands in [`scan_scalar`]. The check is [`crate::detect`]'s
//! -- the crate's own CPUID and XGETBV read, shared by every caller and by
//! both configurations of the crate, so a `std` build and a `no_std` build
//! reach the same kernel on the same machine -- and
//! `tests::cpuid_detection_matches_the_std_macro` holds it to the standard
//! library's answer. All `unsafe` is confined to the `#[target_feature]`
//! functions in the private [`avx2`] module, each of which documents the
//! check that guards it.

use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
mod avx2;

#[cfg(target_arch = "x86_64")]
pub use avx2::scan_avx2;

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// A byte that carries no meaning for the grammar.
pub const CLASS_OTHER: u8 = 0;
/// `{ } [ ] : ,` or one of the four JSON whitespace bytes.
pub const CLASS_STRUCTURAL: u8 = 1;
/// `"`.
pub const CLASS_QUOTE: u8 = 2;
/// `\`, as `0b11`.
///
/// Two bits have no room for a fifth class, and the backslash is the one that
/// does not fit: it is neither plane, and it is needed per byte to resolve the
/// escape parity. [`Classified16::code`] carries all four together so a caller
/// reads one number instead of three masks. **Nothing may read it as bit
/// flags** — see the module header.
pub const CLASS_BACKSLASH: u8 = 3;

/// The 256-entry lookup the scalar paths classify through.
///
/// Every use of a code is equality. See [`CLASS_BACKSLASH`] for why a mask is
/// not an option here.
pub const CLASS_TABLE: [u8; 256] = build_class_table();

/// The classification code for one byte.
#[must_use]
pub const fn class_of(b: u8) -> u8 {
    match b {
        b' ' | b'\t' | b'\n' | b'\r' => CLASS_STRUCTURAL,
        b'{' | b'}' | b'[' | b']' | b':' | b',' => CLASS_STRUCTURAL,
        b'"' => CLASS_QUOTE,
        b'\\' => CLASS_BACKSLASH,
        _ => CLASS_OTHER,
    }
}

/// Whether `b` is one of RFC 8259's four whitespace bytes.
#[must_use]
pub const fn is_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

const fn build_class_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        table[i] = class_of(i as u8);
        i += 1;
    }
    table
}

/// One 16-byte window, classified three ways at once.
///
/// The packed code exists because two bits cannot carry five classes; the
/// whitespace and backslash planes come beside it because those are the two
/// the code cannot distinguish.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Classified16 {
    /// Two bits per byte, byte `i` at bits `2i..2i+2`: [`CLASS_OTHER`],
    /// [`CLASS_STRUCTURAL`], [`CLASS_QUOTE`] or [`CLASS_BACKSLASH`].
    pub code: u32,
    /// Bit `i` set when byte `i` is whitespace.
    pub whitespace: u16,
    /// Bit `i` set when byte `i` is a backslash.
    pub backslash: u16,
}

/// Classify 16 bytes, two bits per byte.
///
/// The portable reference for the vector path; `tests` compares the two window
/// by window over all 256 byte values at all 16 offsets.
#[must_use]
pub fn classify16(bytes: &[u8; 16]) -> Classified16 {
    let mut out = Classified16::default();
    for (i, &b) in bytes.iter().enumerate() {
        // Matched, never masked: a backslash packs as 0b11, whose low two
        // bits would read as "structural and quote" to any bitwise test.
        let packed = match CLASS_TABLE[b as usize] {
            CLASS_BACKSLASH => u32::from(CLASS_BACKSLASH),
            CLASS_QUOTE => u32::from(CLASS_QUOTE),
            CLASS_STRUCTURAL => u32::from(CLASS_STRUCTURAL),
            _ => 0,
        };
        out.code |= packed << (2 * i);
        if is_whitespace(b) {
            out.whitespace |= 1 << i;
        }
        if b == b'\\' {
            out.backslash |= 1 << i;
        }
    }
    out
}

// --- the pshufb rectangles -------------------------------------------------

// The rectangles are the vector path's tables: the AVX2 module reads them,
// and the tests read them to pin what each one selects. A target with no
// vector path has no use for them, and code nobody calls is an error under
// the gate's `-D warnings` -- which is how a tree that only ever ran on
// x86_64 stopped at the first warning of an arm64 build.

/// Build the (low-table, high-table) pair for one rectangle of the
/// high-nibble × low-nibble grid, from a bitmask of nibbles for each.
#[cfg(any(target_arch = "x86_64", test))]
const fn rect(lo_set: u16, hi_set: u16) -> ([u8; 16], [u8; 16]) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    let mut i = 0usize;
    while i < 16 {
        lo[i] = if (lo_set >> i) & 1 == 1 { 0xFF } else { 0x00 };
        hi[i] = if (hi_set >> i) & 1 == 1 { 0xFF } else { 0x00 };
        i += 1;
    }
    (lo, hi)
}

/// `0x20`, the space.
#[cfg(any(target_arch = "x86_64", test))]
pub(crate) const RECT_SPACE: ([u8; 16], [u8; 16]) = rect(1 << 0x0, 1 << 0x2);
/// `0x09 0x0A 0x0D` — tab, line feed, carriage return.
#[cfg(any(target_arch = "x86_64", test))]
pub(crate) const RECT_CTRL_WS: ([u8; 16], [u8; 16]) =
    rect((1 << 0x9) | (1 << 0xA) | (1 << 0xD), 1 << 0x0);
/// `0x2C`, the comma.
#[cfg(any(target_arch = "x86_64", test))]
pub(crate) const RECT_COMMA: ([u8; 16], [u8; 16]) = rect(1 << 0xC, 1 << 0x2);
/// `0x3A`, the colon.
#[cfg(any(target_arch = "x86_64", test))]
pub(crate) const RECT_COLON: ([u8; 16], [u8; 16]) = rect(1 << 0xA, 1 << 0x3);
/// `0x5B 0x5D 0x7B 0x7D` — `[ ] { }`.
///
/// The bracket set is why the union exists: `0x5B` and `0x7B` differ in their
/// *high* nibble, so one rectangle holding both spans two rows, and row 5 then
/// admits `0x5C` (the backslash) unless row 5 is only lit on low nibbles `B`
/// and `D`. The low-table half is what pins that down.
#[cfg(any(target_arch = "x86_64", test))]
pub(crate) const RECT_BRACKET: ([u8; 16], [u8; 16]) =
    rect((1 << 0xB) | (1 << 0xD), (1 << 0x5) | (1 << 0x7));
/// `0x22`, the quote.
#[cfg(any(target_arch = "x86_64", test))]
pub(crate) const RECT_QUOTE: ([u8; 16], [u8; 16]) = rect(1 << 0x2, 1 << 0x2);

/// Every rectangle with the byte values it is required to select.
///
/// `tests::each_rectangle_selects_exactly_the_bytes_it_documents` and
/// `tests::the_planes_reconstruct_the_class_table` read this table, so a
/// rectangle edited without its row here fails on the class plane rather than
/// silently drifting.
#[cfg(test)]
#[allow(clippy::type_complexity)]
pub(crate) const RECTANGLES: [(&str, ([u8; 16], [u8; 16]), &[u8]); 6] = [
    ("space", RECT_SPACE, &[0x20]),
    ("ctrl-ws", RECT_CTRL_WS, &[0x09, 0x0A, 0x0D]),
    ("comma", RECT_COMMA, &[0x2C]),
    ("colon", RECT_COLON, &[0x3A]),
    ("bracket", RECT_BRACKET, &[0x5B, 0x5D, 0x7B, 0x7D]),
    ("quote", RECT_QUOTE, &[0x22]),
];

/// The 256 bytes one (low-table, high-table) pair selects, computed the way
/// `pshufb` computes it: `low[b & 0x0F] & high[b >> 4]`.
///
/// The high-nibble index is `b >> 4`, at most 15 for every `u8`. That bound is
/// why the tables have no row above `7`, and why bytes `>= 0x80` are safe here
/// at all.
#[must_use]
pub const fn rect_bytes((lo, hi): ([u8; 16], [u8; 16])) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut b = 0usize;
    while b < 256 {
        let byte = b as u8;
        out[b] = lo[(byte & 0x0F) as usize] & hi[(byte >> 4) as usize];
        b += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// A dense bit set over a known byte range: bit `i` of word `i / 64` describes
/// byte `i`.
///
/// **The word layout is the input's, not a re-packing.** A 64-byte block of
/// input is one word of output, so the block loops never shift between the two
/// and `set_word` writes straight into place. Bits past [`BitSet::len`] are
/// zero, which `tests::lengths_around_the_block_size` pins.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BitSet {
    words: Vec<u64>,
    len: usize,
    any: bool,
}

impl BitSet {
    /// An all-zero set over `len` bytes.
    #[must_use]
    pub fn with_len(len: usize) -> Self {
        Self {
            words: alloc::vec![0u64; len.div_ceil(64)],
            len,
            any: false,
        }
    }

    /// The number of bytes this set describes.
    ///
    /// This is the *range*, not the population: a set over 100 bytes with
    /// nothing in it has `len() == 100` and `is_empty() == true`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no byte is in the set.
    ///
    /// "Empty" means no bits set, as for any other collection — *not*
    /// "describes no bytes", which is [`BitSet::len`] being zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.any
    }

    /// Whether byte `i` is in the set. `false` past the end, and `false` for
    /// `usize::MAX` without overflowing on the division.
    #[must_use]
    pub fn contains(&self, i: usize) -> bool {
        if i >= self.len {
            return false;
        }
        self.words[i / 64] & (1u64 << (i % 64)) != 0
    }

    /// How many bytes are in the set.
    #[must_use]
    pub fn count_ones(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// The backing words, low word first.
    #[must_use]
    pub fn words(&self) -> &[u64] {
        &self.words
    }

    /// The byte positions in the set, ascending.
    pub fn iter_set(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(wi, &w)| {
            (0..64).filter_map(move |b| {
                if w & (1u64 << b) != 0 {
                    Some(wi * 64 + b)
                } else {
                    None
                }
            })
        })
    }

    fn set(&mut self, i: usize) {
        self.words[i / 64] |= 1u64 << (i % 64);
        self.any = true;
    }

    /// Store a whole 64-byte word. Word `k` covers exactly bytes
    /// `64k..64k + 64`, so the block loops need no shifting.
    fn set_word(&mut self, word: usize, w: u64) {
        self.words[word] = w;
        self.any |= w != 0;
    }
}

/// The stage-1 output: where the structural bytes are, where the string
/// delimiters are, and whether the input ended inside a string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuralIndex {
    /// Structural bytes, delimiters included.
    pub structural: BitSet,
    /// The quotes that open and close strings, and only those — an escaped
    /// quote is neither a delimiter nor structural.
    pub quote: BitSet,
    /// The length of the scanned input.
    pub len: usize,
    /// Whether a string was still open at the end of the input. Stage 2 reads
    /// this as a truncated document rather than reaching a terminal.
    pub end_in_string: bool,
}

impl StructuralIndex {
    /// The structural byte positions, ascending.
    pub fn structural_positions(&self) -> impl Iterator<Item = usize> + '_ {
        self.structural.iter_set()
    }

    /// The string-delimiter positions, ascending.
    pub fn quote_positions(&self) -> impl Iterator<Item = usize> + '_ {
        self.quote.iter_set()
    }
}

// ---------------------------------------------------------------------------
// The block algebra
// ---------------------------------------------------------------------------

/// The state that crosses a 64-byte block boundary.
///
/// "Process 64 bytes independently" is false and these three bits are the
/// reason: a quote's meaning depends on a backslash run that can start in one
/// block and end in another, and the string flag can be set by a quote in the
/// last byte of a block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Carry {
    /// The input was inside a string when this block starts.
    pub in_string: bool,
    /// The last byte of the previous block was a backslash, so a run is open.
    pub run: bool,
    /// That open run's length so far is odd.
    pub parity: bool,
}

/// The whole 64-byte predicate, in masks.
///
/// `structural_raw` is the structural plane (`ws | punctuation`), `quote` the
/// quote plane, `backslash` the backslash plane — one bit per byte, bit `i`
/// being byte `i`. The return is one word of structural output and one of
/// delimiters.
///
/// `prefix` supplies the inclusive prefix-XOR. The vector path passes a
/// carry-less multiply and [`scan_swar`] passes [`prefix_xor`]. It is a
/// parameter rather than a `cfg` so both spellings are monomorphised into the
/// identical algebra and the tests can run the same code around either.
///
/// ## Escape parity
///
/// `odd` ends up with bit `i` set exactly when byte `i` is a backslash and the
/// run ending at `i` has odd length. A quote at `i+1` is then escaped exactly
/// when `odd` is set at `i` — no lookahead, and no need to know where the run
/// ends, which is the property that makes a block-at-a-time scanner possible at
/// all.
///
/// The recurrence is `odd[i] = start[i] | (b[i] & b[i-1] & odd[i-2])`: a run's
/// odd/even alternates with distance from its start, so a position two back is
/// what decides this one. A stride-2 chain is not a global prefix-XOR and
/// cannot be done with one of those, so it is unrolled by doubling instead —
/// each step extends the runs reachable through a gate twice as long, and five
/// steps cover every even distance from 0 to 62, which is every one a 64-byte
/// block has.
#[inline]
pub(crate) fn block_with<F>(
    structural_raw: u64,
    quote: u64,
    backslash: u64,
    carry: &mut Carry,
    prefix: F,
) -> (u64, u64)
where
    F: Fn(u64) -> u64,
{
    // --- escape parity -----------------------------------------------------
    // A run crossing the boundary reaches this block through *two* virtual
    // inputs, not one: `odd[-1]`, lane 1's predecessor, and `odd[-2]`, lane 0's.
    // They are `run && parity` and `run && !parity`.
    //
    // Injecting lane 0 alone is the bug a shorter version had, and it is not a
    // rare one: a run of length 1 has odd parity, so `!parity` is 0 and a byte
    // at lane 0 then has no virtual predecessor to be reached through at all.
    // Every block whose second byte ended an odd run crossing the boundary
    // lost one backslash, and only the boundary sweeps found it.
    let open = 0u64.wrapping_sub(u64::from(carry.run));
    // Bit 0 of `start` is `backslash[0] && !carry.run`, so a run carried in
    // from the previous block does not look like a fresh start.
    let start = backslash & !((backslash << 1) | u64::from(carry.run));
    let mut odd = start
        | (backslash & open & u64::from(!carry.parity))
        | (backslash & (backslash << 1) & (u64::from(carry.parity) << 1) & open);

    // `gate` marks the positions the recurrence can *reach* through: bit `i`
    // survives while `i` and `i-1` are both backslashes, then while the four
    // before that are too, and so on.
    let mut gate = backslash & (backslash << 1);
    odd |= gate & (odd << 2);
    gate &= gate << 2;
    odd |= gate & (odd << 4);
    gate &= gate << 4;
    odd |= gate & (odd << 8);
    gate &= gate << 8;
    odd |= gate & (odd << 16);
    gate &= gate << 16;
    odd |= gate & (odd << 32);

    // Lane 0 has no byte in front of it in this block: a quote there is
    // escaped by whatever run is still open from the previous one. That is why
    // the carry holds a parity and not just a flag, and it is the same
    // `run && parity` that seeded `odd` above.
    let escaped = ((odd << 1) | u64::from(carry.run && carry.parity)) & quote;
    let toggle = quote & !escaped;

    // --- string state ------------------------------------------------------
    // The inclusive prefix-XOR of the toggles is the in-string state after each
    // byte, counted from outside. Seeding with the carry's negation is what
    // makes a block entered inside a string read as inside: bit 0 of the
    // result is the state *before* the block, and XORing an all-ones word
    // flips every lane.
    let in_string = prefix(toggle) ^ 0u64.wrapping_sub(u64::from(carry.in_string));

    // The delimiters are the toggles themselves. (`in_string[i] ^
    // in_string[i-1]` recovers `toggle[i]` from the prefix-XOR — the two are
    // provably equal — and is spelled out in `tests` rather than relied on
    // here, where it would only cost a shift and a XOR.)
    //
    // The quote plane is deliberately absent from `structural_raw`: an escaped
    // quote outside a string would otherwise come out structural, which the
    // byte-at-a-time reference does not do.
    let structural = (structural_raw & !in_string) | toggle;

    carry.in_string = in_string >> 63 == 1;
    carry.run = backslash >> 63 == 1;
    carry.parity = odd >> 63 == 1;

    (structural, toggle)
}

/// Inclusive prefix-XOR: bit `i` of the result is the XOR of bits `0..=i`.
///
/// The carry-less multiply in [`avx2`] computes the same function in one
/// instruction. This is the portable spelling, and
/// `tests::clmul_prefix_xor_agrees_with_the_shift_chain` holds the two to each
/// other word for word — a carry-less multiply with the wrong operand, or
/// reading the wrong half of its result, is otherwise a silent
/// one-bit-per-block corruption.
#[must_use]
pub fn prefix_xor(x: u64) -> u64 {
    let mut x = x;
    x ^= x << 1;
    x ^= x << 2;
    x ^= x << 4;
    x ^= x << 8;
    x ^= x << 16;
    x ^= x << 32;
    x
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Collects output words and carries the boundary state between blocks.
///
/// One builder serves all three paths: the scalar paths call [`Builder::step`]
/// per byte and the block paths call [`Builder::push_word`]. Nothing here is
/// cleared between calls, so a `Builder` is single-use — which is also what
/// `tests::the_scan_agrees_with_itself_across_repetition` would catch.
pub(crate) struct Builder {
    structural: BitSet,
    quote: BitSet,
    carry: Carry,
    next_word: usize,
}

impl Builder {
    pub(crate) fn new(len: usize) -> Self {
        Self {
            structural: BitSet::with_len(len),
            quote: BitSet::with_len(len),
            carry: Carry::default(),
            next_word: 0,
        }
    }

    /// Store one 64-byte block of output. Word `k` is exactly the byte range
    /// `64k..64k + 64`, so no shifting is involved.
    pub(crate) fn push_word(&mut self, structural: u64, quote: u64) {
        self.structural.set_word(self.next_word, structural);
        self.quote.set_word(self.next_word, quote);
        self.next_word += 1;
    }

    /// The predicate for one byte, in the clearest form there is.
    ///
    /// This is [`scan_scalar`]'s body and the tail of every other path, for
    /// the bytes past the last whole block.
    pub(crate) fn step(&mut self, at: usize, b: u8) {
        let escaped = self.carry.run && self.carry.parity;
        let class = CLASS_TABLE[b as usize];
        let boundary = class == CLASS_QUOTE && !escaped;
        let structural = boundary || (class == CLASS_STRUCTURAL && !self.carry.in_string);

        if class == CLASS_BACKSLASH {
            self.carry.run = true;
            self.carry.parity = !self.carry.parity;
        } else {
            self.carry.run = false;
            self.carry.parity = false;
        }
        if boundary {
            self.carry.in_string = !self.carry.in_string;
        }

        if structural {
            self.structural.set(at);
        }
        if boundary {
            self.quote.set(at);
        }
    }

    pub(crate) fn finish(self) -> StructuralIndex {
        let len = self.structural.len;
        StructuralIndex {
            structural: self.structural,
            quote: self.quote,
            len,
            end_in_string: self.carry.in_string,
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Whether this CPU can run the AVX2 path.
///
/// The answer comes from [`crate::detect`], the hand-written CPUID/XGETBV
/// read: `is_x86_feature_detected!` lives in `std`, and this crate is
/// `no_std` + `alloc`, and a build that dispatched on one answer and a build
/// that dispatched on the other would not be comparable. The probe is tested
/// against the standard library's answer rather than trusted.
#[must_use]
pub fn has_avx2() -> bool {
    crate::detect::avx2()
}

/// Whether this CPU can run the block path: AVX2 *and* PCLMULQDQ, the latter
/// because the string state is carried across blocks by a carry-less multiply.
#[must_use]
pub fn has_avx2_pclmulqdq() -> bool {
    crate::detect::avx2() && crate::detect::pclmulqdq()
}

/// Scan `bytes` with the best implementation this CPU admits to.
///
/// The vector path is the AVX2 one; everything else falls back to
/// [`scan_scalar`], the same predicate one byte at a time.
#[must_use]
pub fn scan(bytes: &[u8]) -> StructuralIndex {
    #[cfg(target_arch = "x86_64")]
    if has_avx2_pclmulqdq() {
        // SAFETY: `has_avx2_pclmulqdq` just reported both features, which is
        // the precondition of `scan_avx2`; see its documentation.
        return unsafe { avx2::scan_avx2(bytes) };
    }
    scan_scalar(bytes)
}

/// The reference: the predicate, one byte at a time.
///
/// The fallback for CPUs without AVX2, and the oracle the other two paths are
/// held to.
#[must_use]
pub fn scan_scalar(bytes: &[u8]) -> StructuralIndex {
    let mut builder = Builder::new(bytes.len());
    for (at, &b) in bytes.iter().enumerate() {
        builder.step(at, b);
    }
    builder.finish()
}

/// The block algebra in portable scalar code: the same 64-byte pipeline as the
/// vector path, with [`prefix_xor`] where that path has a carry-less multiply.
///
/// **It is not a fast path, deliberately.** Its classification still runs one
/// byte at a time, so all it saves is the per-byte state machine. That is the
/// point: it is how the two prefix-XOR implementations are compared, and how
/// the mask algebra is read on a machine with no AVX2.
#[must_use]
pub fn scan_swar(bytes: &[u8]) -> StructuralIndex {
    let mut builder = Builder::new(bytes.len());
    let mut at = 0usize;
    while at + 64 <= bytes.len() {
        let mut structural_raw = 0u64;
        let mut quote = 0u64;
        let mut backslash = 0u64;
        for (lane, &b) in bytes[at..at + 64].iter().enumerate() {
            // Equality, never a mask: `CLASS_BACKSLASH` is 0b11 and would
            // land in two planes at once. See the module header.
            match CLASS_TABLE[b as usize] {
                CLASS_STRUCTURAL => structural_raw |= 1u64 << lane,
                CLASS_QUOTE => quote |= 1u64 << lane,
                CLASS_BACKSLASH => backslash |= 1u64 << lane,
                _ => {}
            }
        }
        let (structural, quote_mask) = block_with(
            structural_raw,
            quote,
            backslash,
            &mut builder.carry,
            prefix_xor,
        );
        builder.push_word(structural, quote_mask);
        at += 64;
    }
    while at < bytes.len() {
        builder.step(at, bytes[at]);
        at += 1;
    }
    builder.finish()
}

/// Classify 16 bytes with `pshufb`, falling back to [`classify16`] on a CPU
/// without AVX2.
///
/// The vector counterpart of [`classify16`], present so the rectangle tables
/// can be held against the 256-entry table on a real CPU.
#[cfg(target_arch = "x86_64")]
#[must_use]
pub fn classify16_avx2(bytes: &[u8; 16]) -> Classified16 {
    if has_avx2() {
        // SAFETY: `has_avx2` just reported AVX2, which is the precondition of
        // `classify16_avx2_inner`; `bytes` is a `&[u8; 16]`, so the 16-byte
        // load is in bounds by the type.
        return unsafe { avx2::classify16_avx2_inner(bytes) };
    }
    classify16(bytes)
}
