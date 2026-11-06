// SPDX-License-Identifier: Apache-2.0

//! A streaming line searcher: what a grep-shaped tool drives a matcher with.
//!
//! A [`Searcher`] reads bytes (a whole slice, or a `Read` it rolls through
//! a fixed buffer), splits them into lines, asks a [`Matcher`] about each,
//! and reports what it finds through a [`Sink`]. The contract is
//! `grep-searcher`'s deliberately: rgx's existing sinks are written
//! against it.
//!
//! Two modes. [`Searcher::search_slice`] runs over a `&[u8]` in one pass;
//! [`Searcher::search_reader`] rolls a fixed buffer and carries
//! before-context across the boundary. rgx uses the first for files up
//! to 16 MiB and the second above it.
//!
//! The line contract, which has to be exact:
//!   - a line is terminated by the line terminator, included in the bytes
//!     reported to a sink;
//!   - a final line with no terminator is still a line;
//!   - the search advances by the LINE, so several matches on one line
//!     report that line once;
//!   - context lines go through [`Sink::context`], never [`Sink::matched`].
//!
//! A leading byte-order mark is honoured before any line is looked for,
//! so a UTF-16 file is searched as the text it encodes rather than the
//! interleaving that encodes it; see [`encoding`].
//!
//! The buffer rolls rather than buffering whole lines because
//! before-context is the reason. When a match is found at the top of a
//! fresh buffer, the `-B` lines that precede it were read in the
//! previous fill. The roll keeps exactly those at the front; see
//! [`LineBuffer::roll`].
//!
//! The candidate stream. A matcher that can cheaply say "a match can only
//! start near these offsets" implements [`CandidateSource`]. The stream
//! is built once per buffer and the line loop pulls from it, which is
//! what keeps a packed-mask prefilter linear in the buffer.

use alloc::vec::Vec;
use core::fmt;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::matcher::Matcher;
use super::scan::{BitMap, MAX_BITMAP_INPUT};

use crate::encoding;

/// The line terminator, and the byte treated as binary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LineTerminator {
    /// The byte that ends a line.
    pub line_term: u8,
}

impl Default for LineTerminator {
    fn default() -> Self {
        Self { line_term: b'\n' }
    }
}

/// How binary data is handled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BinaryDetection {
    /// Do nothing. A NUL is an ordinary byte.
    None,
    /// Stop reading at the first occurrence of this byte, and report the
    /// offset. The bytes before it are still searched.
    ///
    /// This is ripgrep's default under a mapping and rgx's choice for the
    /// buffer path: a file with a NUL in its first buffer yields only the
    /// matches before it.
    Quit(u8),
    /// Replace every occurrence of this byte with the line terminator and
    /// keep going, so the whole file is still searched.
    Convert(u8),
}

/// How much of a buffer is checked for a binary byte before any line is
/// looked for. `grep-searcher`'s `DEFAULT_BUFFER_CAPACITY`, and the same
/// window `src/main.rs` sniffs a file's head over.
const BINARY_PROBE: usize = 64 * 1024;

/// A matcher that can say which byte offsets are worth a real match test.
///
/// Separate from [`Matcher`] on purpose (decision 5): this is an
/// optimisation the searcher *may* use, not part of what a matcher is. A
/// matcher without one is searched at every line, which is always correct and
/// merely slower.
///
/// The stream must be a **superset** of the real start offsets. Reporting a
/// candidate that is not a match costs one confirmation; omitting one loses a
/// match, so an implementation must never under-report.
pub trait CandidateSource: Send + Sync {
    /// The candidate offsets in `hay`, ascending, as a stream the line loop
    /// pulls from.
    ///
    /// `out` is scratch the searcher reuses across buffers. A source with
    /// offsets to report writes them there and returns a view of it, so a
    /// search allocates once rather than once per buffer.
    fn candidates<'a>(&'a self, hay: &'a [u8], out: &'a mut Vec<usize>) -> Candidates<'a>;

    /// The same candidates as a bit per buffer byte instead of a list.
    /// `out` must be filled with a bit set at every offset of `hay` the
    /// source admits, or the offsets the searcher pulls are not the
    /// prefilter's. `None` means "no map": the caller then asks
    /// [`CandidateSource::candidates`] as before.
    ///
    /// The [`Origin`] says what a set bit means. `Origin::Mask` is the
    /// case that is not a prefilter: a bit there is a match MASK, and
    /// the width in it is the reason the confirm exists.
    fn map_candidates(&self, _hay: &[u8], _out: &mut BitMap) -> Option<Origin> {
        None
    }

    /// The pair-anchored needle and its offset in every match, when the
    /// source's kernel is `pair_bits`. Used by the caller to fuse the pair
    /// scan with `term_bits` via [`super::scan::pair_term_bits`].
    fn pair_needle(&self) -> Option<(usize, &[u8])> {
        None
    }

    /// The line cut and match span of the MATCH MASK [`Self::map_candidates`]
    /// is about to fill -- `(cut, span)` -- or `None` when it is filling a
    /// prefilter. A mask's confirm is the mask itself rather than a scan for
    /// a literal: `cut` is the NARROWEST branch (what the line range must
    /// keep) and `span` the WIDEST (what a match's bytes can cover), and the
    /// line walk settles a line from its bits through the window rule.
    ///
    /// Asked immediately after that call and about the same buffer.
    /// Separate from [`Self::map_candidates`] because the answer is a
    /// property of the mask, not of the stream's origin: a mask's bits
    /// are match starts in the buffer at offset zero, which is exactly
    /// what `Origin::Fixed(0)` already says.
    fn map_is_match_mask(&self, _hay: &[u8]) -> Option<(usize, usize)> {
        None
    }
}

/// The candidate offsets of one buffer, in the order the line loop takes
/// them. Ascending, each offered once.
pub struct Candidates<'a> {
    supply: Supply<'a>,
    idx: usize,
    /// What a candidate offset means. See [`Candidates::with_origin`].
    origin: Origin,
    /// Whether a candidate IS a match, so the line walk can settle the
    /// line from the bit alone with no confirm at all. True for a match
    /// mask; false for every stream that is not one.
    ///
    /// A field and not a variant of [`Origin`] because `Origin` is matched
    /// exhaustively by callers outside this crate, and a third arm there
    /// is a change every one of them has to make for a property of the
    /// STREAM rather than of the match.
    decides: bool,
    /// How many bytes a match needs at the end of a line for a bit inside
    /// that line to be a match of it. Zero for every stream that is not
    /// a match mask, and read only when [`Self::decides`] is true.
    ///
    /// The NARROWEST branch's width, not the mask's: `(pub|fn) [a-z]+` is
    /// four bytes in its `fn ` branch and five in its `pub ` branch, so
    /// cutting five drops every `fn x` that ends a line — a match, and
    /// one the differential has a fixture for.
    mask_width: usize,
    /// The WIDEST branch's width: the span a match at any bit can cover.
    /// The window rule tests exactly these bytes before a bit settles its
    /// line (see [`Matcher::decides_window`]); zero when this stream is not
    /// a match mask.
    window_span: usize,
}

/// What a candidate offset means to the code that confirms it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    /// The match begins this many bytes before the candidate. Zero is the
    /// usual case: a candidate IS a match start.
    Fixed(usize),
    /// The match begins at the start of the line, whatever the candidate
    /// says.
    ///
    /// A `^`-anchored pattern is this, and saying so is worth a whole
    /// prefilter: an anchor that cannot report its own offset — because
    /// the pattern put a variable-width repeat in front of the literal,
    /// as `^ +pub` does — otherwise hands the confirm
    /// [`Origin::Unknown`], and the confirm
    /// for an unknown origin scans the line from every candidate. The
    /// candidates are then liveness rather than a position, which is what this
    /// variant says out loud.
    LineStart,
    /// Nothing is known about where the match begins, so the confirm has to
    /// consider the whole line. See [`Candidates::with_origin`].
    Unknown,
}

/// Where a source's offsets come from.
enum Supply<'a> {
    /// The offsets themselves, ascending.
    Reported(&'a [usize]),
    /// Every offset in a buffer of `len` bytes. A source with no prefilter
    /// cannot narrow the search, and saying so is cheaper than materialising
    /// `0..len` — a buffer-sized allocation on every fill.
    Every(usize),
    /// A set of one, two or three bytes, located on demand from a forward
    /// cursor.
    ///
    /// This exists for the DENSE case, and it is the whole reason it exists:
    /// a one-byte pattern matches about 5% of the bytes of real source, so
    /// listing its offsets up front is ~13 million `usize` per 235 MB — a
    /// 104 MB allocation and an extra full pass over memory, for offsets the
    /// line loop consumes one line at a time and stops at the first hit in
    /// each. Measured, that vector is the difference between a search that
    /// scans the buffer once and one that writes it out four times over.
    ///
    /// The scan it replaces is the crate's `memchr`, so the bytes are still
    /// examined once per buffer in the same SIMD order; what is gone is the
    /// materialisation, not the search.
    ///
    /// One, two and three bytes because those are the widths `memchr`,
    /// `memchr2` and `memchr3` cover, and a fourth would have no such scan:
    /// an alternation of four one-byte literals is where the packed mask
    /// takes over, at the cost of materialising what this supply does not.
    Scan {
        hay: &'a [u8],
        scan: ByteSet,
        at: usize,
    },
    /// The same one, two or three bytes as a bit per buffer byte rather than a
    /// `memchr` call per line.
    ///
    /// **This is the dense path's actual answer, and it replaced
    /// [`Supply::Scan`] for the reader.** Ablation on a 235 MB file put
    /// [`Supply::Scan`]'s two `memchr` calls — one over each 31-byte line for
    /// the terminator and one over each line's remainder for the needle — at
    /// 123 ms of a 143 ms replication of the whole search. The bytes are not
    /// what that costs: `memchr_iter` over the whole buffer for the same
    /// needle runs at 50 GB/s, which is 5 ms. A *call* costs about 7 ns
    /// whether the range is 31 bytes or 31 KB — dispatch, setup, tail — and a
    /// per-line loop pays it 7.8 million times, plus once per candidate.
    ///
    /// [`super::scan::byte_bits`] pays it once per buffer and leaves a
    /// `len / 8` map — 8 KiB for a 64 KiB fill, so it stays in L1 while the
    /// line loop pulls its boundaries and candidates out of it with
    /// `trailing_zeros` instead of with calls. Materialising the offsets
    /// instead was measured too and is *worse*: the `memchr` iterator's
    /// `next()` is not its specialised `count()`, and collecting 13 million of
    /// them cost 216 ms against the 62 ms these calls cost.
    Bits { bits: &'a BitMap, at: usize },
}

/// A set of one, two or three bytes to look for, and nothing else.
///
/// `Copy` and three words wide, which is the point: the searcher's inner
/// loop dispatches on it once per candidate and never allocates.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ByteSet {
    /// One byte.
    One(u8),
    /// Two bytes, either of which counts. A caseless single character is a
    /// two-byte requirement, and scanning for one case alone would miss half
    /// the matches — the reason `memchr2` exists.
    Two(u8, u8),
    /// Three bytes, any of which counts. `a|b|c` is common enough
    /// (`yes|no`, `<|>`) to be worth the third register.
    Three(u8, u8, u8),
}

impl ByteSet {
    /// The set for one needle, and for two where the second repeats the
    /// first.
    #[must_use]
    pub fn of(a: u8, b: u8) -> Self {
        if a == b {
            Self::One(a)
        } else {
            Self::Two(a, b)
        }
    }

    /// The first offset in `hay[start..stop]` holding a member, as an offset
    /// into `hay`, or `None`.
    ///
    /// `memchr` and its two- and three-needle forms, unconditionally, even
    /// though the range handed to this is a LINE rather than a buffer and a
    /// loop over 30 bytes looks like the obvious thing. Measured: routing
    /// ranges under 16, under 64 and under 256 bytes to a scalar loop cost
    /// 4%, 7% and 16% on the dense patterns, and bought nothing on the
    /// sparse ones. The vector's setup is cheaper than it looks, and the
    /// loop is not free -- it is a data-dependent branch per byte, on a
    /// corpus where the byte it is looking for is common.
    #[inline]
    fn find(&self, hay: &[u8], start: usize, stop: usize) -> Option<usize> {
        let s = &hay[start..stop];
        let at = match *self {
            Self::One(a) => crate::memchr::memchr(a, s),
            Self::Two(a, b) if a == b => crate::memchr::memchr(a, s),
            Self::Two(a, b) => crate::memchr::memchr2(a, b, s),
            Self::Three(a, b, c) => crate::memchr::memchr3(a, b, c, s),
        };
        at.map(|i| start + i)
    }
}

impl<'a> Candidates<'a> {
    /// A stream over `offsets`, which must be ascending.
    pub fn of(offsets: &'a [usize]) -> Self {
        Self {
            supply: Supply::Reported(offsets),
            idx: 0,
            origin: Origin::Fixed(0),
            decides: false,
            mask_width: 0,
            window_span: 0,
        }
    }

    /// A stream over every offset in a buffer of `len` bytes.
    pub fn every(len: usize) -> Self {
        Self {
            supply: Supply::Every(len),
            idx: 0,
            origin: Origin::Fixed(0),
            decides: false,
            mask_width: 0,
            window_span: 0,
        }
    }

    /// A stream over every offset of `hay` holding `needle`, found on demand.
    ///
    /// The offsets it yields are a superset of nothing and everything at
    /// once: for a one-byte needle a candidate IS the match, so this is the
    /// exact set, and it is still handed over as candidates because that is
    /// the shape the searcher consumes.
    ///
    /// [`of_bytes2`](Self::of_bytes2) takes a second needle for the same
    /// reason `memchr2` exists: a case-insensitive single character is a
    /// two-byte requirement, and scanning for one case alone would miss half
    /// the matches.
    pub fn of_byte(hay: &'a [u8], needle: u8) -> Self {
        Self::of_bytes2(hay, needle, needle)
    }

    /// A stream over every offset of `hay` holding either needle.
    ///
    /// `needle2 == needle` degrades to the plain one-byte scan, which is the
    /// case-sensitive case and the one the dense corpus takes.
    pub fn of_bytes2(hay: &'a [u8], needle: u8, needle2: u8) -> Self {
        Self::of_set(hay, ByteSet::of(needle, needle2))
    }

    /// A stream over every offset of `hay` holding a member of `set`.
    pub fn of_set(hay: &'a [u8], set: ByteSet) -> Self {
        Self {
            supply: Supply::Scan {
                hay,
                scan: set,
                at: 0,
            },
            idx: 0,
            origin: Origin::Fixed(0),
            decides: false,
            mask_width: 0,
            window_span: 0,
        }
    }

    /// A stream over every offset a [`BitMap`] marks, read as the map was
    /// filled rather than searched per line.
    ///
    /// `bits` must have been filled over exactly `hay`, or every offset in it
    /// is meaningless. The caller that fills one owns that pairing; this
    /// constructor only consumes it.
    pub fn of_bits(bits: &'a BitMap) -> Self {
        Self {
            supply: Supply::Bits { bits, at: 0 },
            idx: 0,
            origin: Origin::Fixed(0),
            decides: false,
            mask_width: 0,
            window_span: 0,
        }
    }

    /// A stream over a filled [`BitMap`] whose bits are a match mask, which
    /// SETTLES a line on its own once the last `width - 1` bytes of the line
    /// are off the range.
    ///
    /// **`width` is the narrowest branch, not the widest**, and it is the
    /// difference between a search that is right and one that loses a line per
    /// file: `(pub|fn) [a-z]+` is four bytes wide in its `fn ` branch and five
    /// in its `pub ` branch, so cutting five drops every `fn x` that ends a
    /// line. [`super::scan::MatchMask::line_cut`] is where the number comes
    /// from, and it is `None` -- so this constructor is never reached -- for a
    /// mask whose shape cannot be cut at all. `span` is the WIDEST branch:
    /// every match at a bit occupies at most these bytes, which is what makes
    /// the window rule's ASCII test a proof about the whole match.
    ///
    /// A width of zero is not a mask at all: it is what every prefilter
    /// answers, it leaves [`Self::decides`] false, and the line walk confirms
    /// exactly as it did before any of this.
    pub fn of_mask(bits: &'a BitMap, width: usize, span: usize) -> Self {
        Self {
            supply: Supply::Bits { bits, at: 0 },
            idx: 0,
            origin: Origin::Fixed(0),
            decides: width != 0,
            mask_width: width,
            window_span: span,
        }
    }

    /// Whether a candidate in this stream IS a match. See [`Self::decides`].
    #[must_use]
    pub fn decides(&self) -> bool {
        self.decides
    }

    /// How many bytes a match needs at the end of a line for a bit inside it
    /// to be a match of that line. Zero when this stream is not a match mask.
    #[must_use]
    pub fn mask_width(&self) -> usize {
        self.mask_width
    }

    /// How many bytes a match at a bit can cover at the widest -- the span
    /// the window rule tests. Zero when this stream is not a match mask.
    #[must_use]
    pub fn mask_window(&self) -> usize {
        self.window_span
    }

    /// What a candidate offset means to whoever confirms it.
    ///
    /// A prefilter may find its literal anywhere inside a match, and a
    /// consumer that has to confirm a candidate needs to know where the
    /// match therefore began. For a pattern whose required byte sits at
    /// offset 0 that is zero and the field is pure overhead; for `e[0-9]`
    /// anchored on its digits it is 1, and getting it wrong is not a slow
    /// search but a wrong answer — a match reported at the wrong offset, or
    /// none reported at all.
    ///
    /// [`Origin::Unknown`] is the third case and it is not a detail: a
    /// prefilter built from a literal behind a variable-length prefix
    /// (`\d+em`) knows the literal is IN the match and not where the match
    /// starts, so the only sound confirm is one over the whole line. A
    /// consumer that treats `Unknown` as `Fixed(0)` would confirm a match
    /// starting at the literal, which is not the match, and report spans
    /// that are wrong — so it is a separate variant rather than a sentinel.
    ///
    /// It travels with the stream rather than with the matcher because the
    /// matcher is shared: the in-house engine holds one compiled pattern
    /// across every file a walk visits, and the right anchor is a property of
    /// the file. A `Cell` on the pattern would be a data race the moment two
    /// walker threads touched it.
    #[must_use]
    pub fn with_origin(mut self, origin: Origin) -> Self {
        self.origin = origin;
        self
    }

    /// What candidates in this stream mean. See [`Self::with_origin`].
    #[must_use]
    pub fn origin(&self) -> Origin {
        self.origin
    }

    /// Whether the stream holds no candidate at all in `from..to`.
    ///
    /// **The per-buffer early exit asks exactly this, and the question is
    /// only as good as the stream behind it.** The stream is a SUPERSET of
    /// every match start, so "no candidates in this buffer" implies "no match
    /// in this buffer" — that is the same inference the line loop already
    /// makes one line at a time, lifted from line granularity to buffer
    /// granularity, and it is sound for exactly the same reason. Which is
    /// also why a wrong answer here is a MISSED MATCH and not a slow search:
    /// the failure mode is an absent result, and it is silent.
    ///
    /// The four supplies answer at four different prices, and the difference
    /// is the whole reason this is worth having rather than a pessimisation:
    ///
    /// - `Supply::Reported` and `Supply::Bits` are a length test and a
    ///   popcount over words already in L1. Free.
    /// - `Supply::Every` — a pattern with NO required literal — is never
    ///   empty for a non-empty range, and says so without looking. **This is
    ///   where the idea does not apply at all**, and it is a distinct answer
    ///   rather than a "sometimes true" one: there is no anchor to be absent.
    /// - `Supply::Scan` is a pattern with a one-to-three byte anchor on a
    ///   haystack too large to map, and its answer costs ONE pass over the
    ///   range — against a line walk that would call `memchr` once per line.
    ///   Cheap when it hits, and one pass when it does not.
    #[must_use]
    pub fn is_empty_in(&self, from: usize, to: usize) -> bool {
        match &self.supply {
            Supply::Reported(offsets) => !offsets.iter().any(|&o| o >= from && o < to),
            Supply::Every(len) => to.min(*len) <= from,
            Supply::Scan { hay, scan, .. } => {
                let stop = to.min(hay.len());
                from >= stop || scan.find(hay, from, stop).is_none()
            }
            Supply::Bits { bits, .. } => !bits.any_set(from, to),
        }
    }

    /// Whether the stream has an ANCHOR at all: something whose absence from a
    /// range of bytes proves that range cannot match.
    ///
    /// This is what the per-candidate JUMP asks, and the answer is a distinct
    /// one rather than a "sometimes true" one. `Supply::Every` is a pattern
    /// with **no required literal**: every offset in the buffer is a
    /// candidate, so there is nothing to jump TO. The jump does not merely fail
    /// to help there, it does not exist.
    ///
    /// **It is also what keeps the line loop terminating, which is a stronger
    /// reason than speed and the reason this cannot be relaxed later as a
    /// micro-optimisation.** For `Supply::Every`, [`Self::next_offset`] answers
    /// `Some(pos)` -- the next candidate is the current position -- so a caller
    /// that asked anyway would set `pos` to the start of the line it is already
    /// on, process that line, and ask again from the same place, forever. That
    /// is not hypothetical: forcing the jump on for every search hung the test
    /// suite rather than failing it. The per-BUFFER early exit has always
    /// asked this same question through [`Self::is_empty_in`], and it is the
    /// same `Supply::Every` case that has always answered "never empty".
    ///
    /// Every other supply is anchored: `Reported` and `Bits` are a list and a
    /// map the source built from a literal, and `Scan` is the same literal
    /// found on demand. [`Origin::Unknown`] does NOT disqualify a stream --
    /// "the literal is somewhere inside the match and not where the match
    /// starts" is a statement about confirming a candidate, not about whether
    /// a line can be skipped, and a jumped-to line is confirmed exactly as a
    /// walked-to line is.
    #[must_use]
    pub fn has_anchor(&self) -> bool {
        !matches!(self.supply, Supply::Every(_))
    }

    /// The first candidate at or after `from`, as an offset into the buffer,
    /// consuming the stream up to it.
    ///
    /// This is the other half of [`Self::in_line`], and the reason the searcher
    /// walks candidates instead of lines. `in_line` answers *which candidates
    /// fall in this line*; `next_offset` answers *which line is worth looking
    /// at next*. `grep-searcher` asks its prefilter the second question and
    /// locates the line from the answer -- `Core::find_candidate_line` then
    /// `lines::locate` -- so a line with no candidate is never looked at. The
    /// searcher asked the first question once per line and never got to ask
    /// the second, which is why the line walk is the floor under every sparse
    /// pattern.
    ///
    /// **The cursor moves exactly as `in_line` moves it**, and that is what
    /// makes the two compose rather than conflict. After this returns `c` the
    /// cursor sits at `c`, so the `in_line(line_start, content_end)` the
    /// caller then issues re-finds `c` and everything after it rather than
    /// stepping over the candidate the jump landed on. Neither method may
    /// rewind: a rewound cursor makes the next call re-examine bytes the
    /// previous one already looked at, and a forward-only one is what keeps
    /// the whole buffer a single pass.
    ///
    /// `None` means the stream is exhausted at or after `from`.
    pub fn next_offset(&mut self, from: usize) -> Option<usize> {
        match &mut self.supply {
            Supply::Reported(offsets) => {
                let offsets: &'a [usize] = offsets;
                while self.idx < offsets.len() && offsets[self.idx] < from {
                    self.idx += 1;
                }
                offsets.get(self.idx).copied()
            }
            // Every offset is a candidate, so the answer is the position
            // itself. `has_anchor` is false for this supply and the searcher
            // never asks, but answering it correctly costs nothing and keeps
            // the method total.
            Supply::Every(len) => (from < *len).then_some(from),
            Supply::Scan { hay, scan, at } => {
                let (hay, scan): (&'a [u8], ByteSet) = (*hay, *scan);
                // The same `max(at, from)` clamp `in_line` applies, for the
                // same reason: the cursor never rewinds, and a caller walking
                // past the end of the haystack gets an empty answer rather
                // than a panic.
                let f = core::cmp::max(*at, from).min(hay.len());
                let hit = scan.find(hay, f, hay.len());
                // Parked ON the hit, not one past it: `in_line` resumes from
                // `max(at, line_start)`, and parking past it would step over
                // the candidate the jump just landed on.
                *at = hit.unwrap_or(hay.len());
                hit
            }
            Supply::Bits { bits, at } => {
                // Inlined, and bounded by the map, for the two reasons
                // `in_line` inlines its own copy: `BitMap::next_set` is a call
                // costing about what the `memchr` it replaces cost, and this
                // runs once per candidate -- 13 million times for a one-byte
                // pattern over 235 MB.
                let words = bits.words();
                let stop = bits.len();
                let start = core::cmp::max(*at, from).min(stop);
                let mut i = start / 64;
                if i >= words.len() {
                    *at = stop;
                    return None;
                }
                let w = words[i] & (!0u64 << (start % 64));
                if w != 0 {
                    let hit = i * 64 + w.trailing_zeros() as usize;
                    *at = core::cmp::min(hit, stop);
                    return (hit < stop).then_some(hit);
                }
                i += 1;
                while i + 4 <= words.len() {
                    let w0 = words[i];
                    let w1 = words[i + 1];
                    let w2 = words[i + 2];
                    let w3 = words[i + 3];
                    if (w0 | w1 | w2 | w3) != 0 {
                        let (w_nz, offset) = if w0 != 0 {
                            (w0, 0)
                        } else if w1 != 0 {
                            (w1, 1)
                        } else if w2 != 0 {
                            (w2, 2)
                        } else {
                            (w3, 3)
                        };
                        let hit = (i + offset) * 64 + w_nz.trailing_zeros() as usize;
                        *at = core::cmp::min(hit, stop);
                        return (hit < stop).then_some(hit);
                    }
                    i += 4;
                }
                while i < words.len() {
                    let cur = words[i];
                    if cur != 0 {
                        let hit = i * 64 + cur.trailing_zeros() as usize;
                        *at = core::cmp::min(hit, stop);
                        return (hit < stop).then_some(hit);
                    }
                    i += 1;
                }
                *at = stop;
                None
            }
        }
    }

    /// The candidates in `start..end`, as offsets from `start`, consuming
    /// them so no later line is offered the same offset again.
    ///
    /// This is the only way to move the cursor, and that is the point: a
    /// second peeking method that did not advance is how a walk turns into
    /// `lines x candidates` again, silently and with correct output. An
    /// empty result is the answer to "is this line worth confirming", so the
    /// searcher never has to ask separately.
    ///
    /// **For a match mask the range is the line's minus its last
    /// `mask_width - 1` bytes**, and that is the whole of what a deciding
    /// mask needs the engine to do: a bit at `o` says a match BEGINS at `o`,
    /// and a match that begins inside a line but ends outside it is not a match
    /// the searcher reports, so the offsets that cannot hold one whole are not
    /// this line's candidates. A line shorter than the width therefore hands
    /// back nothing, which is the answer -- `fn` on a line of its own does not
    /// match `(pub|fn) [a-z]+` -- and a bit at exactly `end - mask_width` is
    /// the last one that does, because the window fits whole.
    ///
    /// The cut is applied to the RANGE and not to the map, so the bits it
    /// drops are not cleared: they are simply never offered, and the cursor
    /// below still parks at `end` so the next line starts from where this one
    /// did. A stream with no mask leaves every number here exactly as it was.
    /// Settle whether `[start, end)` matches from a deciding mask's bits, or
    /// `None` when this stream is not a deciding mask.
    #[inline]
    pub fn line_matches(&mut self, start: usize, end: usize) -> Option<bool> {
        if !self.decides {
            return None;
        }
        let cut = if self.mask_width > 1 {
            end.saturating_sub(self.mask_width - 1).max(start)
        } else {
            end
        };
        match &mut self.supply {
            Supply::Bits { bits, at } => {
                let from = core::cmp::max(*at, start);
                *at = end;
                Some(bits.any_set(from, cut))
            }
            _ => None,
        }
    }

    pub fn in_line(&mut self, start: usize, end: usize) -> LineCandidates<'a> {
        // Where the line's candidates stop, which is its end for every stream
        // that is not a match mask. `max(start)` is what makes a line shorter
        // than the mask an EMPTY range rather than a backward one: `in_line`
        // is handed `start == end` for a blank line, and a four-wide mask
        // would otherwise park the cursor before the line it is standing on.
        let cut = if self.mask_width > 1 {
            end.saturating_sub(self.mask_width - 1).max(start)
        } else {
            end
        };
        let supply = match &mut self.supply {
            Supply::Reported(offsets) => {
                let offsets: &'a [usize] = offsets;
                while self.idx < offsets.len() && offsets[self.idx] < start {
                    self.idx += 1;
                }
                let mut to = self.idx;
                while to < offsets.len() && offsets[to] < end {
                    to += 1;
                }
                let taken = &offsets[self.idx..to];
                self.idx = to;
                LineSupply::Reported(taken.iter())
            }
            Supply::Every(len) => {
                let to = core::cmp::min(end, *len);
                let from = core::cmp::max(self.idx, start);
                self.idx = core::cmp::max(self.idx, to);
                LineSupply::Run(from..to)
            }
            Supply::Scan { hay, scan, at } => {
                let (hay, scan): (&'a [u8], ByteSet) = (*hay, *scan);
                // Clamped like `Every` is: a caller walking past the end of a
                // buffer is asking a question with an empty answer, not for a
                // panic, and the other two supplies both say that.
                let stop = end.min(hay.len());
                // The cursor never rewinds: a line's start is where the
                // previous line's search stopped, and asking `memchr` to
                // re-examine those bytes is the one way this could cost more
                // than the vector it replaces.
                let from = core::cmp::max(*at, start).min(stop);
                let line = &hay[start.min(stop)..stop];
                // The shared cursor is parked at the end of the line whether
                // or not this one hits, so a caller that never exhausts the
                // stream cannot make the NEXT line re-scan bytes this one has
                // already looked at.
                *at = end;
                match scan.find(hay, from, stop) {
                    Some(found) => {
                        LineSupply::Scan {
                            line,
                            scan,
                            // The hit `in_line` just found is the stream's
                            // FIRST element, so it is held back rather than
                            // searched past: yielding it twice would confirm
                            // one match twice, and searching from `found + 1`
                            // without holding it would skip it entirely.
                            //
                            // A sentinel rather than an `Option` and a
                            // `bool`: `LineCandidates` is built once per LINE
                            // and moved out of `in_line`, so two words of
                            // niche padding here are a per-line memcpy on a
                            // 7.8-million-line buffer. `first` holds
                            // [`NONE`] until it is yielded, and `from` is set
                            // to [`EXHAUSTED`] when nothing is left -- an
                            // offset of 0 is a legitimate answer on both
                            // sides, so neither sentinel may be 0.
                            first: found - start.min(stop),
                            from: 0,
                        }
                    }
                    None => LineSupply::Run(0..0),
                }
            }
            Supply::Bits { bits, at } => {
                // The same shape as `Scan`, with the map standing in for the
                // search: the cursor never rewinds, and it is parked at the end
                // of the line whether or not this one hit, so a caller that
                // never exhausts the stream cannot make the NEXT line re-scan
                // bytes this one has already looked at.
                let stop = cut.min(bits.len());
                let from = core::cmp::max(*at, start).min(stop);
                *at = end;
                // The word walk is INLINE and bounded by `stop`, not by the
                // end of the map. Two reasons, and the second is the one that
                // cost 170 ms before it was found: `BitMap::next_set` is a call
                // costing about what the `memchr` it replaces cost, so paying
                // it once per line is a wash at best, and it walks to the END
                // OF THE MAP rather than to the end of this line, so a line
                // with no candidate scans forward over every word between here
                // and the next hit anywhere in the remaining 8 KiB.
                let mut hit: Option<(u64, usize, usize)> = None;
                if from < stop {
                    let words = bits.words();
                    let mut i = from >> 6;
                    let mut w = words[i] & (u64::MAX << (from & 63));
                    loop {
                        if w != 0 {
                            let f = i * 64 + (w.trailing_zeros() as usize);
                            if f < stop {
                                hit = Some((w, i, f));
                            }
                            break;
                        }
                        i += 1;
                        if i * 64 >= stop {
                            break;
                        }
                        w = words[i];
                    }
                }
                match hit {
                    // `at` is the WORD BASE and `word` is masked below the hit,
                    // which is the pair the iterator walks with: it yields
                    // `at + trailing_zeros(word)`, so the two have to agree.
                    // Passing the hit itself as `at` looks right for the first
                    // candidate and wrong for every one after it, which is the
                    // shape of bug the differential exists for.
                    Some((word, i, _f)) => LineSupply::Bits {
                        words: bits.words(),
                        word,
                        at: i * 64,
                    },
                    None => LineSupply::Run(0..0),
                }
            }
        };
        LineCandidates {
            supply,
            base: start,
            // The CUT and not `end`, because this is what bounds the map's
            // iterator and the cut is the last offset that can be this line's
            // candidate. For every other supply the two are the same number.
            end: cut,
            marker: core::marker::PhantomData,
        }
    }
}

/// The candidates of one line, as offsets from that line's first byte.
pub struct LineCandidates<'a> {
    supply: LineSupply<'a>,
    base: usize,
    /// The end of the line's own offsets, absolute.
    ///
    /// [`LineSupply::Bits`] needs it and the other two do not: the map is a
    /// property of the BUFFER, so the words past this line's end are set bits
    /// belonging to the lines that follow. Without the bound the iterator
    /// walks into them, and a confirm anchored past the end of `line` is not
    /// a wrong answer -- the matcher bounds-checks and says no -- but it is a
    /// wasted confirmation per stray candidate, which on `e.` measured 90 ms
    /// on a 235 MB corpus and cost more than the whole line-split saving.
    end: usize,
    /// [`LineSupply::Run`] carries no borrow; this keeps both supplies under
    /// one lifetime.
    marker: core::marker::PhantomData<&'a [u8]>,
}

enum LineSupply<'a> {
    Reported(core::slice::Iter<'a, usize>),
    Run(core::ops::Range<usize>),
    /// Every offset of `line` holding a member of `scan`, in ascending order.
    ///
    /// `line` is the line's CONTENT with the terminator already cut off, so
    /// a byte index here is already the offset from the line's first byte --
    /// the same space [`LineCandidates::base`] rebases into.
    ///
    /// `first` is the hit `in_line` already found and has not yielded yet
    /// ([`NONE`] once it has), and `from` is where the search resumes after
    /// it, or [`EXHAUSTED`] when the line is spent.
    Scan {
        line: &'a [u8],
        scan: ByteSet,
        first: usize,
        from: usize,
    },
    /// The same offsets, out of a [`BitMap`] rather than out of `memchr`.
    ///
    /// `words` is the map's own word array rather than the map, so that
    /// `next()` below is a slice index with no call in it: measured, going
    /// through a method here costs about as much as the `memchr` it replaces
    /// and the fill is then paid on top.
    ///
    /// `at` is the offset of `word`'s first byte, and `word` is that word
    /// already masked so nothing below the first unyielded candidate is live.
    /// Yielding is a `trailing_zeros` and a clear-the-lowest-bit; advancing a
    /// word is a slice index and a zero test.
    Bits {
        words: &'a [u64],
        word: u64,
        at: usize,
    },
}

/// No held-back candidate is waiting to be yielded.
const NONE: usize = usize::MAX;
/// The line holds no further occurrence of the byte.
const EXHAUSTED: usize = usize::MAX;

impl<'a> Iterator for LineCandidates<'a> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        match &mut self.supply {
            LineSupply::Reported(it) => it.next().map(|&o| o - self.base),
            LineSupply::Run(range) => range.next().map(|o| o - self.base),
            LineSupply::Scan {
                line,
                scan,
                first,
                from,
            } => {
                // The hit `in_line` already found is yielded first and only
                // once; searching from one past it would skip it entirely,
                // and yielding it again would confirm one match twice.
                if *first != NONE {
                    let at = *first;
                    *first = NONE;
                    *from = at + 1;
                    return Some(at);
                }
                if *from == EXHAUSTED {
                    return None;
                }
                // Clamped rather than trusted: `from` walks past the end of
                // the line one byte at a time as it consumes occurrences.
                let start = (*from).min(line.len());
                match scan.find(line, start, line.len()) {
                    Some(at) => {
                        *from = at + 1;
                        Some(at)
                    }
                    None => {
                        *from = EXHAUSTED;
                        None
                    }
                }
            }
            LineSupply::Bits { words, word, at } => {
                loop {
                    if *word != 0 {
                        let hit = *at + (word.trailing_zeros() as usize);
                        if hit >= self.end {
                            // The line is spent. The bits past here belong to
                            // the lines that follow, and the stream's cursor is
                            // already parked at this line's end, so nothing is
                            // lost by stopping -- the next line starts from
                            // there and finds them itself.
                            return None;
                        }
                        *word &= *word - 1;
                        // Rebased here rather than at the call site, exactly as
                        // `Reported` does, because the iterator's item is an
                        // offset from the LINE's first byte.
                        return Some(hit - self.base);
                    }
                    // Past the map: the line, and the buffer, are spent. The
                    // map is the buffer's length rounded up to a word, so the
                    // bound is the word count and not the haystack length --
                    // reading one word past the end here would be reading the
                    // padding, whose bits are never set, and would still be a
                    // read of memory the caller does not own.
                    let next = *at + 64;
                    if next >= self.end {
                        return None;
                    }
                    let w = match words.get(next >> 6) {
                        Some(&w) => w,
                        None => return None,
                    };
                    *at = next;
                    *word = w;
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.supply {
            LineSupply::Reported(it) => it.size_hint(),
            LineSupply::Run(range) => range.size_hint(),
            // `in_line` already ran the search and only builds this supply
            // when it hit, so anything live here is an exact "at least one
            // candidate, and `is_empty` must say no". Past that the count is
            // unknown until the rest of the line is walked, which the
            // searcher never does.
            LineSupply::Scan { first, from, .. } => {
                if *first != NONE || *from != EXHAUSTED {
                    (1, None)
                } else {
                    (0, Some(0))
                }
            }
            // Same argument: `in_line` already found the first candidate before
            // it built this supply, so anything live here means at least one,
            // and `is_empty` must say no. It is built only on a hit, so an
            // exhausted line never gets here at all.
            LineSupply::Bits { word, .. } => {
                if *word != 0 {
                    (1, None)
                } else {
                    (0, Some(0))
                }
            }
        }
    }
}

impl LineCandidates<'_> {
    /// Whether the line has no candidate at all, which is the answer to
    /// "is this line worth confirming".
    pub fn is_empty(&self) -> bool {
        self.size_hint().0 == 0
    }

    /// Whether `f` accepts any candidate, stopping at the first that it does.
    ///
    /// Takes `self` by value so a confirmation reads as a single expression
    /// over the offsets a line owns.
    pub fn any<F: FnMut(usize) -> bool>(mut self, f: F) -> bool {
        Iterator::any(&mut self, f)
    }
}

/// How many bits of the terminator map are set in `[from, to)`.
///
/// The popcount the line counter is advanced by over a skipped region. Word
/// at a time and inline, for the same reason [`prev_term`] is: a call here is
/// paid once per gap and the whole point of the gap is that there are fewer of
/// them than there are lines.
///
/// The vector path is what runs on every modern x86_64 box the binary
/// ships to. The popcount per word is a single `_mm256_sad_epu8` for
/// 32 bytes (4 words) at a time, with the low- and high-nibble sums
/// added; the head and tail of the range (one word each, masked)
/// go through the scalar path.
#[inline]
fn count_set_in(words: &[u64], from: usize, to: usize) -> u64 {
    // The vector path indexes `words` through a raw pointer, so the caller
    // must have established that `[from, to)` is covered. `scalar_count_set_in`
    // tolerates a short slice silently (`get(..).unwrap_or(0)`), which is
    // exactly why a caller that did not check went to the vector path and
    // segfaulted instead of quietly returning a wrong answer. Re-establish the
    // precondition here, at the single point every caller reaches.
    //
    // `count_lines` performs the same check and routes a short map to
    // `scan::count_byte` over the same region; this is the backstop that makes
    // the invariant hold for every caller rather than the one that regressed.
    if words.len() < to.div_ceil(64) {
        return 0;
    }
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            // SAFETY: guarded by the runtime feature check above, which is
            // `avx2_count_set_in`'s documented precondition; the coverage
            // check above establishes the other half, that `[from, to)` lies
            // inside `words`.
            return unsafe { avx2_count_set_in(words, from, to) };
        }
    }
    scalar_count_set_in(words, from, to)
}

/// The scalar definition [`avx2_count_set_in`] implements in vector form, and
/// the table the tests hold the two to. One word per popcount.
#[inline]
fn scalar_count_set_in(words: &[u64], from: usize, to: usize) -> u64 {
    if to <= from {
        return 0;
    }
    let first = from / 64;
    let last = (to - 1) / 64;
    let hi = (to - 1) % 64;
    let from_mask = !0u64 << (from % 64);
    let to_mask = if hi == 63 {
        !0u64
    } else {
        (1u64 << (hi + 1)) - 1
    };
    if first == last {
        return (words.get(first).copied().unwrap_or(0) & from_mask & to_mask).count_ones() as u64;
    }
    let mut n = (words.get(first).copied().unwrap_or(0) & from_mask).count_ones() as u64;
    if last > first + 1 {
        let mid = match words.get(first + 1..last) {
            Some(s) => s,
            None => &[],
        };
        let (chunks, remainder) = mid.as_chunks::<4>();
        for chunk in chunks {
            n += (chunk[0].count_ones()
                + chunk[1].count_ones()
                + chunk[2].count_ones()
                + chunk[3].count_ones()) as u64;
        }
        for &w in remainder {
            n += w.count_ones() as u64;
        }
    }
    n + (words.get(last).copied().unwrap_or(0) & to_mask).count_ones() as u64
}

/// The vector popcount of `[from, to)` in `words`. 32 bytes (4 words) per
/// `_mm256_sad_epu8`, with the low- and high-nibble sums ADDED to yield
/// the byte popcount (every set bit in a byte lives in either the low or
/// the high nibble, never both). The first and last words of the range
/// are masked (`!0u64 << from % 64` for the first, `(1 << (hi + 1)) - 1`
/// for the last; the AND of both when they are the same word). The body
/// -- the words strictly between first and last, scanned whole -- is
/// processed in 4-word groups when there are at least 4 of them; the
/// leftover at each end of the body goes through `count_ones`.
///
/// # Safety
///
/// The caller must have established that the CPU supports AVX2.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_count_set_in(words: &[u64], from: usize, to: usize) -> u64 {
    if to <= from {
        return 0;
    }
    let last = (to - 1) / 64;
    let hi = (to - 1) % 64;
    let first = from / 64;
    let from_mask = !0u64 << (from % 64);
    let to_mask = if hi == 63 {
        !0u64
    } else {
        (1u64 << (hi + 1)) - 1
    };
    if first == last {
        let w = words[first] & from_mask & to_mask;
        return w.count_ones() as u64;
    }
    let mut n = (words[first] & from_mask).count_ones() as u64;
    n += (words[last] & to_mask).count_ones() as u64;
    // The body: words strictly between `first` and `last`, scanned whole.
    // Aligned to multiples of 4 on each side -- the partial head and tail
    // here are not masked because the body's range is a whole word wide on
    // both ends.
    let body_lo = first + 1;
    let body_hi = last;
    if body_hi >= body_lo + 4 {
        // 4-word group loop. `i` is the index of the first word in the
        // group; the group covers `i..i + 4`.
        let aligned_start = body_lo + ((4 - body_lo % 4) % 4);
        let aligned_end = body_hi - (body_hi % 4);
        if aligned_end > aligned_start {
            let ptr = words.as_ptr();
            let zero = _mm256_setzero_si256();
            let lut = _mm256_setr_epi8(
                0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3,
                2, 3, 3, 4,
            );
            let nibble = _mm256_set1_epi8(0x0F);
            let mut acc = _mm256_setzero_si256();
            let mut i = aligned_start;
            while i + 8 <= aligned_end {
                let v0 = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
                let v1 = _mm256_loadu_si256(ptr.add(i + 4) as *const __m256i);
                let lo0 = _mm256_shuffle_epi8(lut, _mm256_and_si256(v0, nibble));
                let lo1 = _mm256_shuffle_epi8(lut, _mm256_and_si256(v1, nibble));
                let hi_idx0 = _mm256_srli_epi16(v0, 4);
                let hi_idx1 = _mm256_srli_epi16(v1, 4);
                let hi0 = _mm256_shuffle_epi8(lut, _mm256_and_si256(hi_idx0, nibble));
                let hi1 = _mm256_shuffle_epi8(lut, _mm256_and_si256(hi_idx1, nibble));
                let lo_sum0 = _mm256_sad_epu8(lo0, zero);
                let lo_sum1 = _mm256_sad_epu8(lo1, zero);
                let hi_sum0 = _mm256_sad_epu8(hi0, zero);
                let hi_sum1 = _mm256_sad_epu8(hi1, zero);
                let sum0 = _mm256_add_epi64(lo_sum0, hi_sum0);
                let sum1 = _mm256_add_epi64(lo_sum1, hi_sum1);
                acc = _mm256_add_epi64(acc, _mm256_add_epi64(sum0, sum1));
                i += 8;
            }
            while i + 4 <= aligned_end {
                let v = _mm256_loadu_si256(ptr.add(i) as *const __m256i);
                let lo = _mm256_shuffle_epi8(lut, _mm256_and_si256(v, nibble));
                let hi_idx = _mm256_srli_epi16(v, 4);
                let hi = _mm256_shuffle_epi8(lut, _mm256_and_si256(hi_idx, nibble));
                let lo_sum = _mm256_sad_epu8(lo, zero);
                let hi_sum = _mm256_sad_epu8(hi, zero);
                acc = _mm256_add_epi64(acc, _mm256_add_epi64(lo_sum, hi_sum));
                i += 4;
            }
            let a = _mm256_extract_epi64(acc, 0) as u64;
            let b = _mm256_extract_epi64(acc, 1) as u64;
            let c = _mm256_extract_epi64(acc, 2) as u64;
            let d = _mm256_extract_epi64(acc, 3) as u64;
            n += a + b + c + d;
        }
        // Leftover words at each end of the body. These are whole in the
        // requested range, so the scalar popcount is exact.
        for &w in &words[body_lo..aligned_start] {
            n += w.count_ones() as u64;
        }
        for &w in &words[aligned_end..body_hi] {
            n += w.count_ones() as u64;
        }
    } else {
        // Body is shorter than 4 words: scalar is cheaper than the
        // AVX2 setup.
        for &w in &words[body_lo..body_hi] {
            n += w.count_ones() as u64;
        }
    }
    n
}

/// The last terminator strictly below `from`, as an offset.
///
/// The BACKWARD half of the terminator map, which the line walk has never
/// needed: it only ever consumed the map forward with `tw &= tw - 1`, and
/// still does -- the forward search for the landed line's end is the `tw`
/// walk, re-pointed at the jump's landing. A jump needs this one because the
/// candidate it was handed is somewhere in the MIDDLE of a line, and the line
/// it belongs to starts at the terminator before it.
///
/// Inlined, and over a `&[u64]` rather than a [`BitMap`], for the same reason
/// the line walk hoists its word: `BitMap::next_set` is a call costing about
/// 11 ns, and this runs once per candidate -- 13 million times for a one-byte
/// pattern over 235 MB.
///
/// A line is short, so this almost never leaves the word it started in: for a
/// 30-byte line the previous terminator is in the same 64-byte word about 94%
/// of the time, and the word walk below is only reached for the rest.
///
/// The vector path is the AVX2 horizontal-OR of 4 words per iteration. The
/// topmost word is masked at `(from - 1) % 64`; the body is 4-word groups
/// going down; the 0..3-word tail is the scalar definition.
#[inline]
fn prev_term(words: &[u64], from: usize) -> Option<usize> {
    if from == 0 {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            // SAFETY: guarded by the runtime feature check above, which is
            // `avx2_prev_term`'s documented precondition.
            return unsafe { avx2_prev_term(words, from) };
        }
    }
    scalar_prev_term(words, from)
}

/// The scalar definition [`avx2_prev_term`] implements in vector form, and
/// what runs when AVX2 is absent. Word at a time, scanning backward.
#[inline]
fn scalar_prev_term(words: &[u64], from: usize) -> Option<usize> {
    let mut i = (from - 1) >> 6;
    if i >= words.len() {
        return None;
    }
    let mut w = words[i] & (!0u64 >> (63 - ((from - 1) & 63)));
    loop {
        if w != 0 {
            return Some((i << 6) + (63 - w.leading_zeros() as usize));
        }
        if i == 0 {
            return None;
        }
        i -= 1;
        w = words[i];
    }
}

/// The vector form of the backward search: one scalar masked word at the
/// top, then four words (256 bits) per loop iteration scanning BACKWARD. The
/// body's 4-word groups use the AVX2 horizontal OR to skip empty groups; the
/// bottom tail (0..3 words) is the scalar definition, and the from-bits
/// mask only ever applies to the topmost word because lower words are
/// scanned whole.
///
/// # Safety
///
/// The caller must have established that the CPU supports AVX2.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn avx2_prev_term(words: &[u64], from: usize) -> Option<usize> {
    if from == 0 {
        return None;
    }
    let start_word = (from - 1) >> 6;
    // The masked word. Only the first iteration applies the from-bits mask;
    // every word below it is scanned whole.
    let top = words.get(start_word).copied().unwrap_or(0) & (!0u64 >> (63 - ((from - 1) & 63)));
    if top != 0 {
        return Some((start_word << 6) + (63 - top.leading_zeros() as usize));
    }
    if start_word == 0 {
        return None;
    }
    // First 4-word group going down: words at indices
    // `start_word - 1, start_word - 2, start_word - 3, start_word - 4`. The
    // top of the group is `start_word - 1`; the next group is below that.
    let mut i = start_word - 1;
    while i >= 3 {
        // Load the four u64s at indices [i - 3, i - 2, i - 1, i].
        let p = words.as_ptr().add(i - 3);
        let v = _mm256_loadu_si256(p as *const __m256i);
        if _mm256_testz_si256(v, v) == 0 {
            // Pick the highest-indexed word with a set bit; lane 3 corresponds to i.
            let l3 = _mm256_extract_epi64(v, 3) as u64;
            if l3 != 0 {
                return Some(i * 64 + (63 - l3.leading_zeros() as usize));
            }
            let l2 = _mm256_extract_epi64(v, 2) as u64;
            if l2 != 0 {
                return Some((i - 1) * 64 + (63 - l2.leading_zeros() as usize));
            }
            let l1 = _mm256_extract_epi64(v, 1) as u64;
            if l1 != 0 {
                return Some((i - 2) * 64 + (63 - l1.leading_zeros() as usize));
            }
            let l0 = _mm256_extract_epi64(v, 0) as u64;
            return Some((i - 3) * 64 + (63 - l0.leading_zeros() as usize));
        }
        if i < 4 {
            break;
        }
        i -= 4;
    }
    // Tail: 0..3 words at the start of the buffer, scanned backward scalar.
    loop {
        let w = words.get(i).copied().unwrap_or(0);
        if w != 0 {
            return Some(i * 64 + (63 - w.leading_zeros() as usize));
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

/// Everything about *how* to search, as opposed to *what* with.
///
/// Defaults are ripgrep's, because ripgrep is the behaviour target.
#[derive(Clone, Debug)]
pub struct Config {
    /// Line terminator.
    pub line_term: LineTerminator,
    /// Binary handling.
    pub binary: BinaryDetection,
    /// Report `before` lines before each match.
    pub before: usize,
    /// Report `after` lines after each match.
    pub after: usize,
    /// Report only the count of matching lines (`-c`).
    pub count: bool,
    /// Report only whether there was a match (`-q`); the sink stops the
    /// search on the first one.
    pub quiet: bool,
    /// Report lines that do *not* match (`-v`).
    pub invert: bool,
    /// Stop after this many matching lines (`-m`). `None` is unlimited.
    pub quit_after: Option<u64>,
    /// Number the lines handed to a sink. Off by default: the searcher
    /// counts terminators to do it, so it is not free.
    pub line_numbers: bool,
    /// The fixed buffer size for [`Searcher::search_reader`]. 64 KiB, which
    /// is `grep-searcher`'s `DEFAULT_BUFFER_CAPACITY`.
    /// The first read buffer [`LineBuffer`] allocates, and the size it doubles
    /// from. 64 KiB is right for a stream: a walk visits files far larger than
    /// that and one allocation per 64 KiB of haystack is noise. It is wrong
    /// for a unit of work that is *smaller* than the buffer, where the whole
    /// allocation is paid to read 4 KB.
    pub buffer_capacity: usize,
    /// Honour a leading byte-order mark: strip a UTF-8 one, and decode UTF-16
    /// to UTF-8, before any line is looked for. On by default, because that
    /// is what `grep-searcher` does and ripgrep's output depends on it.
    pub bom_sniffing: bool,
    /// The caller has declared the input's encoding (rgx's `-E`): decode with
    /// it before any line is looked for, mark or no mark, treating a mark as
    /// data -- [`encoding::force_decode`]'s rule over a stream.
    ///
    /// `Some` outranks [`Self::bom_sniffing`]: a declaration is what the
    /// bytes ARE, and a sniff is only a guess at their front. `Some` also
    /// means no sniff at all, so `Some(Bom::Utf8)` searches the bytes as
    /// they stand. The CLI leaves this `None` for `-E utf-8` and for no
    /// flag, which keeps the sniff for those. It is for RAW INPUT only:
    /// a searcher over adapter output must leave it unset, or extracted
    /// text is decoded a second time.
    pub forced_bom: Option<encoding::Bom>,
    /// Let one match span lines — rgx's `-U`.
    ///
    /// **The other half of `-U` is at compile time**: `ByteRegex::new_multiline`
    /// with `dot_all` is what lets `.` cross a line terminator. Setting this
    /// without that changes nothing, and setting that without this lets a
    /// greedy pattern run into the terminator and be rejected for it — which is
    /// the bug the per-line content slice at `Core::run` exists to prevent. The
    /// two must be set together, and the CLI is the only place that does.
    ///
    /// A multi-line match reports **the line its match ends on**, which is
    /// ripgrep's rule and not an obvious one: reporting the first line would
    /// make `-A` hang off a line that is not the last thing printed.
    pub multi_line: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            line_term: LineTerminator::default(),
            binary: BinaryDetection::Quit(0),
            before: 0,
            after: 0,
            count: false,
            quiet: false,
            invert: false,
            quit_after: None,
            line_numbers: false,
            buffer_capacity: LineBuffer::INITIAL_BUF,
            bom_sniffing: true,
            forced_bom: None,
            multi_line: false,
        }
    }
}

impl Config {
    /// The larger context setting, i.e. how much a roll must retain.
    fn max_context(&self) -> usize {
        if self.before > self.after {
            self.before
        } else {
            self.after
        }
    }

    /// Whether any line reaches a sink at all beyond quiet/count.
    fn needs_line_output(&self) -> bool {
        !self.count && !self.quiet
    }

    /// Whether the searcher must track 1-based line numbers.
    ///
    /// True when the sink will read [`SinkMatch::line_number`] or when
    /// context is active (the printer's `--` separator groups lines by
    /// number). When false the searcher skips `count_byte`/`count_lines`
    /// on every early-exit buffer — over a large corpus that is a whole
    /// SIMD pass per fill thrown away for numbers no one reads.
    fn wants_line_numbers(&self) -> bool {
        self.line_numbers || self.before > 0 || self.after > 0
    }
}

/// What a sink is told about a matching line.
///
/// `bytes` borrows the searcher's buffer. A sink that wants to keep a line
/// past the call must copy it: the buffer is reused on the next fill.
pub struct SinkMatch<'a> {
    /// The bytes of the line, terminator included.
    pub bytes: &'a [u8],
    /// 1-based line number. `Some` when [`Config::wants_line_numbers`] is
    /// true (the printer displays it or context grouping needs it); `None`
    /// when the caller set [`Config::line_numbers`] false and asked for no
    /// context — the numbers are then never counted and the skip path saves
    /// a whole SIMD pass per fill. The printer uses `unwrap_or(0)` and the
    /// context separator only runs when context is active, which is exactly
    /// the condition under which the number is present.
    pub line_number: Option<u64>,
    /// Absolute offset of the line's first byte.
    pub absolute_byte_offset: u64,
    /// The range this line occupies in the buffer. A multi-line match (`-U`)
    /// covers more than the one line handed here: `bytes` is then the WHOLE
    /// match and this range its extent, and `line_number` is the line the match
    /// BEGAN on, so a sink can split and count up the way ripgrep prints it.
    pub bytes_range_in_buffer: core::ops::Range<usize>,
}

/// What a sink is told about a context line: one reported only because it
/// neighbours a match, and which side of the match it is on.
pub struct SinkContext<'a> {
    /// The bytes of the line, terminator included.
    pub bytes: &'a [u8],
    /// 1-based line number, or `None`.
    pub line_number: Option<u64>,
    /// Absolute offset of the line's first byte.
    ///
    /// The counterpart of [`SinkMatch::absolute_byte_offset`], and needed for
    /// the same reason: `rg --json` reports a byte offset for context lines
    /// too, and a sink that only had the buffer-relative range could not tell
    /// a reader-path buffer's first line from one halfway down the file.
    pub absolute_byte_offset: u64,
    /// The range this line occupies in the buffer.
    pub bytes_range_in_buffer: core::ops::Range<usize>,
    /// Whether the line precedes or follows its match.
    pub kind: ContextKind,
}

/// Which side of its match a context line is on.
///
/// The distinction is load-bearing, not decoration: rgx's printer labels a
/// before-context line differently from an after-context one, in both the
/// `path-lineno-` prefix and the `--json` output. A searcher that reported
/// every context line as one or the other would make `-B` silently wrong.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContextKind {
    /// Reported before the match (`-B`).
    Before,
    /// Reported after the match (`-A`).
    After,
    /// Reported because it merely sits between two context regions. The
    /// reference emits these and a sink may draw a separator for them; rgx
    /// does not produce them.
    Other,
}

/// What a sink is told once, at the end of a search.
pub struct SinkFinish<'a> {
    /// Total bytes searched.
    pub byte_count: u64,
    /// Absolute offset at which binary data was first seen, if any.
    pub binary_byte_offset: Option<u64>,
    /// Ties the lifetime to the searcher, mirroring the reference trait.
    pub _marker: core::marker::PhantomData<&'a ()>,
}

/// The receiver of a search's results.
///
/// Every fallible method returns `Result<bool, E>` where `false` means
/// *stop*, honoured immediately. It is how `-q` stops at the first match.
pub trait Sink {
    /// The error a sink can fail with. `std::io::Error` is what rgx's sinks
    /// use, and matching it keeps the swap mechanical.
    type Error;

    /// A matching line.
    fn matched(&mut self, mat: &SinkMatch<'_>) -> Result<bool, Self::Error>;

    /// A context line neighbouring a match.
    fn context(&mut self, ctx: &SinkContext<'_>) -> Result<bool, Self::Error>;

    /// Called once when the search is over.
    fn finish(&mut self, fin: &SinkFinish<'_>) -> Result<(), Self::Error>;
}

/// A matcher that can also say which offsets are worth a match test.
///
/// Separate from [`Matcher`] and *optional* (decision 5): it is an
/// optimisation, not part of what a matcher is.
pub struct Searcher<'m> {
    matcher: &'m dyn Matcher,
    /// The candidate stream, when the matcher has one.
    candidates: Option<&'m dyn CandidateSource>,
    config: Config,
    /// Buffers the per-buffer early exit has skipped so far, across every
    /// search this `Searcher` has run.
    ///
    /// **This exists so the optimisation is observable.** A skip is a pure
    /// speed change: remove it and every result is still correct, which is
    /// exactly why a differential suite cannot tell whether it ran. Without a
    /// number here, "the early exit is wired up" is an unfalsifiable claim
    /// and the tests for it could only check that nothing broke. With it, a
    /// test asserts the skip HAPPENED on a buffer that may be skipped and did
    /// NOT happen on one that may not — the second half being the part that
    /// would otherwise be untestable at all.
    skipped: core::sync::atomic::AtomicU64,
    /// Gaps of lines the per-candidate jump has stepped over, and the lines
    /// in them, across every search this `Searcher` has run.
    ///
    /// **The same reason [`Self::skipped`] exists, and it matters more here.**
    /// A jump is not a skip: it still lands on a line and still confirms it,
    /// so a wrong jump can lose a line, duplicate one, or renumber one, and
    /// every one of those is silent. A differential suite compares the jumped
    /// search against grep and finds nothing when the jump is merely absent,
    /// and absent is correct. Without a number here the tests below could
    /// only assert that nothing broke, which a jump that never fires
    /// satisfies perfectly. With it, each test can also assert that the jump
    /// DID fire on the fixture built to make it fire.
    jumped: core::sync::atomic::AtomicU64,
    jumped_lines: core::sync::atomic::AtomicU64,
}

impl<'m> Searcher<'m> {
    /// Build a searcher for `matcher`. The matcher is asked at every line.
    pub fn new(matcher: &'m dyn Matcher, config: Config) -> Self {
        Self {
            matcher,
            candidates: None,
            config,
            skipped: core::sync::atomic::AtomicU64::new(0),
            jumped: core::sync::atomic::AtomicU64::new(0),
            jumped_lines: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// How many buffers the per-buffer early exit has skipped.
    ///
    /// Zero does not mean the optimisation is broken — a buffer that holds a
    /// candidate is never skipped, and on a dense corpus that is every
    /// buffer. Read it as "buffers proven to hold no match", never as "buffers
    /// searched".
    #[must_use]
    pub fn skipped_buffers(&self) -> u64 {
        self.skipped.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// How many gaps of lines the per-candidate jump has stepped over.
    ///
    /// Zero means the jump never fired, which is CORRECT for a pattern with no
    /// required literal ([`Candidates::has_anchor`]), for `-v`, for a nullable
    /// pattern, and for a search with no candidate stream at all. It is not a
    /// failure, and it is not a claim that nothing was skipped: read
    /// [`Self::skipped_buffers`] for the buffers.
    #[must_use]
    pub fn jumped_gaps(&self) -> u64 {
        self.jumped.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// How many lines the per-candidate jump has stepped over, across every
    /// search this `Searcher` has run.
    ///
    /// This is the number the ceiling in `Core::run` predicts, and the one a
    /// test asserts is non-zero: a jump that fires on a fixture with two
    /// needles and ten thousand lines must have stepped over a great many of
    /// them.
    #[must_use]
    pub fn jumped_lines(&self) -> u64 {
        self.jumped_lines
            .load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Build a searcher that consults `candidates` once per buffer instead
    /// of asking the matcher at every line. This is how a packed-mask
    /// prefilter is reached: the matcher answers "a match can only start
    /// near these offsets" for the whole buffer in one pass, and the line
    /// loop then confirms only the lines that contain one.
    pub fn with_candidates(
        matcher: &'m dyn Matcher,
        candidates: &'m dyn CandidateSource,
        config: Config,
    ) -> Self {
        Self {
            matcher,
            candidates: Some(candidates),
            config,
            skipped: core::sync::atomic::AtomicU64::new(0),
            jumped: core::sync::atomic::AtomicU64::new(0),
            jumped_lines: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The config this searcher was built with.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The candidate stream for a buffer, if a source was supplied.
    ///
    /// `out` is the scratch the source writes into and the stream borrows
    /// from, so it must outlive the `Core::run` that consumes it.
    fn candidates_for<'a>(
        &'a self,
        hay: &'a [u8],
        out: &'a mut Vec<usize>,
    ) -> Option<Candidates<'a>> {
        self.candidates.as_ref().map(|c| c.candidates(hay, out))
    }

    /// The map form of the per-buffer searches a fill needs, or `None` when
    /// this buffer cannot have them.
    ///
    /// The two halves answer independently, and that is the point of the
    /// signature. The LINE map needs nothing from the source -- a line
    /// terminator is a line terminator whatever the pattern is -- so every
    /// pattern gets it, including the ones whose candidates stay a list. The
    /// CANDIDATE map needs a byte-set prefilter to map, and the second element
    /// is `None` when the source declines: the packed-mask and substring paths
    /// materialise a short candidate list instead, which is cheap because the
    /// list is short, and forcing a map over them would be a map of nothing.
    ///
    /// `None` overall -- the whole of the previous behaviour, no fill paid at
    /// all -- is reached only when the buffer is larger than a map is worth.
    fn map_candidates_only<'a>(
        &'a self,
        hay: &'a [u8],
        cands_map: &'a mut BitMap,
        mut terms_map: Option<&mut BitMap>,
        mut nonascii_map: Option<&mut BitMap>,
        term: u8,
        offsets: &'a mut Vec<usize>,
    ) -> Option<Candidates<'a>> {
        if hay.len() > MAX_BITMAP_INPUT {
            return self.candidates_for(hay, offsets);
        }
        match self.candidates.as_ref() {
            Some(src) => {
                // Fused pair + terminator scan in one pass. Only for
                // pair-based sources with a terms map to fill.
                if let (Some((at, needle)), Some(t)) = (src.pair_needle(), terms_map.as_deref_mut())
                {
                    super::scan::pair_term_bits(needle, term, hay, cands_map, t);
                    if let Some(m) = nonascii_map {
                        super::scan::high_bits(hay, m);
                    }
                    return Some(Candidates::of_bits(cands_map).with_origin(Origin::Fixed(at)));
                }
                // Fill terms BEFORE the candidate map so it is populated
                // even when `map_candidates` declines and the caller falls
                // through to `candidates_for`. The non-ASCII map rides the
                // same pass.
                if let (Some(t), Some(m)) = (terms_map.as_deref_mut(), nonascii_map.as_deref_mut())
                {
                    super::scan::term_high_bits(term, hay, t, m);
                } else {
                    if let Some(t) = terms_map {
                        super::scan::term_bits(term, hay, t);
                    }
                    if let Some(m) = nonascii_map {
                        super::scan::high_bits(hay, m);
                    }
                }
                match src.map_candidates(hay, cands_map) {
                    Some(origin) => match src.map_is_match_mask(hay) {
                        Some((cut, span)) => {
                            Some(Candidates::of_mask(cands_map, cut, span).with_origin(origin))
                        }
                        None => Some(Candidates::of_bits(cands_map).with_origin(origin)),
                    },
                    None => self.candidates_for(hay, offsets),
                }
            }
            None => Some(Candidates::every(hay.len())),
        }
    }
}

/// A fixed buffer lines are searched out of, with the roll that preserves
/// before-context across a fill.
///
/// Four positions into one `Vec<u8>`:
///   - `pos` — consumed; everything before it is done;
///   - `last_lineterm` — just past the final terminator, the end of the last
///     *complete* line;
///   - `end` — how much real data is held; the bytes between `last_lineterm`
///     and `end` are a partial line;
///   - `absolute_byte_offset` — the absolute offset of `pos`.
///
/// It is grown and never shrunk, so one file with a huge line permanently
/// inflates it for the rest of the run. That is `grep-searcher`'s behaviour
/// and is left as-is: shrinking would make a pathological file cost a
/// realloc on every fill.
pub struct LineBuffer {
    buf: Vec<u8>,
    pos: usize,
    last_lineterm: usize,
    end: usize,
    absolute_byte_offset: u64,
    binary_byte_offset: Option<u64>,
    binary: BinaryDetection,
    line_term: u8,
    /// The first allocation, from [`Config::buffer_capacity`]. Held here rather
    /// than read from the config on every growth because the buffer outlives
    /// the borrow of the config it was sized from, and because a caller that
    /// resized the config mid-search should not see the buffer change under it.
    initial_buf: usize,
    /// The two bit maps of the dense path, owned here so that a walk reuses one
    /// pair across every file it visits rather than allocating two per file.
    ///
    /// They live on the `LineBuffer` rather than on the [`Searcher`] because
    /// this is the object a caller already creates per search and threads
    /// through [`Searcher::search_reader`], and because a map is only ever
    /// alive while one fill is being walked -- which is exactly this buffer's
    /// lifetime. Nothing holds a `BitMap` between fills.
    scratch: Scratch,
}

/// The bit maps one buffer is walked from.
///
/// Two, not one: the line terminators and the prefilter's needle are different
/// searches over the same bytes, and merging them would mean a mask that says
/// "this byte is a line end OR a needle hit", which is a different question
/// from each of the two the searcher asks. They are filled by two SIMD passes
/// (about 5 ms each over 235 MB) rather than one fused pass, which is the
/// simpler trade: fusing them saves nothing a caller can measure, because the
/// map is read out of L1 either way and the haystack pass is the same bytes.
pub struct Scratch {
    terms: BitMap,
    cands: BitMap,
    /// A bit per high byte (`>= 0x80`), filled only for a matcher that may
    /// decline a window (see [`Matcher::may_decline_lines`]). The line
    /// loop's settle asks it O(1) what a per-line `is_ascii` rescan used to
    /// cost 66 ms to answer (`benchmark/findings.md` §13): one lookup
    /// settles a pure-ASCII line, and the window walk runs only on the
    /// dirty minority.
    nonascii: BitMap,
}

impl Scratch {
    pub fn new() -> Self {
        Self {
            terms: BitMap::new(),
            cands: BitMap::new(),
            nonascii: BitMap::new(),
        }
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

impl LineBuffer {
    /// First allocation when no [`Config::buffer_capacity`] says otherwise,
    /// which is the default in [`Config::default`]. Kept as a named constant
    /// rather than only as a default value so the two cannot drift: the
    /// default is `Self::INITIAL_BUF` and this is where the number lives.
    const INITIAL_BUF: usize = 64 * 1024;
    /// Hard ceiling on the buffer. See [`LineBuffer::ensure_capacity`].
    ///
    /// This has to exceed a whole line for the reader path to be correct: a
    /// needle that straddles the doubling boundary is only found if the buffer
    /// grows past it and holds the line whole. The cap is a backstop against a
    /// line that never ends, not a working limit.
    const MAX_BUF: usize = 8 * 1024 * 1024;

    /// A buffer configured from `config`. The allocation is lazy.
    pub fn new(config: &Config) -> Self {
        Self {
            // A capacity of zero would make the first `ensure_capacity` ask for
            // nothing and grow by zero, so the floor is one byte and the
            // doubling takes it from there.
            initial_buf: config.buffer_capacity.max(1),
            buf: Vec::new(),
            pos: 0,
            last_lineterm: 0,
            end: 0,
            absolute_byte_offset: 0,
            binary_byte_offset: None,
            binary: config.binary,
            line_term: config.line_term.line_term,
            scratch: Scratch::new(),
        }
    }

    /// A buffer sized for a stream whose length the caller already knows.
    ///
    /// This is [`Self::new`] today: FILL SIZE IS A MEASURED NULL. At 64 KiB,
    /// 256 KiB and a file-sized 8 MiB fill the single-file floor is flat
    /// (Linux bench host, 246 MB, base-vs-new interleaved: 0.995--1.02).
    /// Bigger fills move sys into user -- the two bit maps scale with the
    /// fill and evict the streaming haystack from L2 -- and smaller ones pay
    /// more syscalls; on this corpus the two cancel exactly. The named
    /// constructor is kept because the sizing question is per-platform and
    /// per-shape (`benchmark/findings.md`), and the caller already knows the
    /// length the day it changes.
    pub fn new_sized(config: &Config, len: u64) -> Self {
        let _ = len;
        Self::new(config)
    }

    /// The searchable bytes: complete lines only, from `pos` to the last
    /// terminator. A partial trailing line is excluded — it may grow on the
    /// next fill.
    pub fn buffer(&self) -> &[u8] {
        &self.buf[self.pos..self.last_lineterm]
    }

    /// The searchable bytes AND the dense path's scratch, borrowed
    /// separately.
    ///
    /// Two accessors would not do. `buffer()` borrows all of `self`, and the
    /// searcher fills the scratch while walking the bytes it returns, so the
    /// two have to come out of one call as disjoint field borrows.
    pub(crate) fn buffer_and_scratch(&mut self) -> (&[u8], &mut Scratch) {
        (&self.buf[self.pos..self.last_lineterm], &mut self.scratch)
    }

    /// The absolute offset of `pos`.
    pub fn absolute_byte_offset(&self) -> u64 {
        self.absolute_byte_offset
    }

    /// Where binary data was first seen, if it was.
    pub fn binary_byte_offset(&self) -> Option<u64> {
        self.binary_byte_offset
    }

    /// Mark `amt` bytes done. `amt` must be within the current buffer.
    pub fn consume(&mut self, amt: usize) {
        debug_assert!(amt <= self.buffer().len());
        self.pos += amt;
        self.absolute_byte_offset += amt as u64;
    }
    /// Move the unconsumed bytes to the front. Idempotent; after it `pos`
    /// is 0 and `last_lineterm == end`. A `copy_within` memmove, not an
    /// allocation, so a roll is linear in the bytes *retained* — which is
    /// why `Core::roll_target` retains only the before-context lines and
    /// not the whole fill.
    pub fn roll(&mut self) {
        if self.pos == self.end {
            self.pos = 0;
            self.last_lineterm = 0;
            self.end = 0;
            return;
        }
        let roll_len = self.end - self.pos;
        self.buf.copy_within(self.pos..self.end, 0);
        self.pos = 0;
        self.last_lineterm = roll_len;
        self.end = roll_len;
    }

    /// Reserve room for a read, growing by doubling up to [`Self::MAX_BUF`].
    ///
    /// The cap is what makes the reader path terminate. A reader that never
    /// hands back a terminator -- a corrupt stream, or a source that stalls
    /// mid-line -- would otherwise have `fill` double the buffer for ever: it
    /// reads, finds no complete line, and goes round again, until the
    /// allocation fails. A bounded buffer turns that into a line, which is what
    /// `grep-searcher` does with a fixed-size buffer and an unterminated
    /// trailing line.
    fn ensure_capacity(&mut self) {
        if self.end < self.buf.len() {
            return;
        }
        let want = if self.buf.is_empty() {
            self.initial_buf
        } else {
            core::cmp::min(self.buf.len() * 2, Self::MAX_BUF)
        };
        self.buf.resize(want, 0);
    }

    /// Read more from `rdr`. Returns `false` at EOF, or as soon as a binary
    /// byte is seen under [`BinaryDetection::Quit`].
    ///
    /// The loop reads until there is a complete line, because a line may
    /// straddle any number of `read` calls.
    pub fn fill(
        &mut self,
        rdr: &mut dyn FnMut(&mut [u8]) -> Result<usize, fmt::Error>,
    ) -> Result<bool, fmt::Error> {
        // Under Quit, once binary data has been seen we stop reading and
        // behave as at EOF, so the caller drains what is left.
        if matches!(self.binary, BinaryDetection::Quit(_)) && self.binary_byte_offset.is_some() {
            return Ok(!self.buffer().is_empty());
        }
        self.roll();
        loop {
            self.ensure_capacity();
            let oldend = self.end;
            let readlen = rdr(&mut self.buf[self.end..])?;
            if readlen == 0 {
                // EOF: the trailing bytes, terminator or not, are a line.
                self.last_lineterm = self.end;
                return Ok(!self.buffer().is_empty());
            }
            self.end += readlen;

            // Binary detection on the freshly read bytes only, so a NUL is
            // found once and the buffer is never rescanned for it.
            let (before, after) = self.buf.split_at_mut(oldend);
            let newbytes = &mut after[..self.end - oldend];
            match self.binary {
                BinaryDetection::None => {}
                BinaryDetection::Quit(byte) => {
                    if let Some(i) = crate::memchr::memchr(byte, newbytes) {
                        let _ = before;
                        self.end = oldend + i;
                        self.last_lineterm = self.end;
                        self.binary_byte_offset = Some(self.absolute_byte_offset + self.end as u64);
                        return Ok(self.pos < self.end);
                    }
                }
                BinaryDetection::Convert(byte) => {
                    // The rewrite is `memchr`-driven, not a byte-at-a-time
                    // pass. It used to be `for b in newbytes.iter_mut()`, and
                    // that ran over EVERY byte of every fill whether or not
                    // the file held a single NUL -- which is nearly all files,
                    // and is what `Convert` costs when it is on the path a
                    // user-named file takes. On the 246 MB single-file
                    // corpus that was 246 million iterations of a
                    // non-vectorisable loop with a branch inside, about 40 ms,
                    // and it turned `pub fn` from 1.43x into 0.87x against
                    // ripgrep: the arm was correct and ruinous.
                    //
                    // Now the NULs are located with the same word-at-a-time
                    // scan `Quit` uses, and the replacement happens in-place
                    // only if there is one to replace, avoiding any heap allocation.
                    if let Some(first) = crate::memchr::memchr(byte, newbytes) {
                        let _ = before;
                        if self.binary_byte_offset.is_none() {
                            self.binary_byte_offset =
                                Some(self.absolute_byte_offset + (oldend + first) as u64);
                        }
                        newbytes[first] = self.line_term;
                        let mut offset = first + 1;
                        while offset < newbytes.len() {
                            if let Some(rel) = crate::memchr::memchr(byte, &newbytes[offset..]) {
                                let idx = offset + rel;
                                newbytes[idx] = self.line_term;
                                offset = idx + 1;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }

            // A complete line exists once a terminator is in the new bytes.
            if let Some(i) = crate::memchr::memrchr(self.line_term, newbytes) {
                self.last_lineterm = oldend + i + 1;
                return Ok(true);
            }
            // No terminator yet. If the buffer is full AND already at the cap
            // there is nowhere left to grow, so the bytes held are reported as
            // one unterminated line and the search moves on -- the same call
            // `grep-searcher` makes for a trailing line with no terminator.
            // Note the cap, not merely "full": a full buffer that can still
            // double must be grown, because a needle sitting across a doubling
            // boundary is only found if the whole line is held at once.
            if self.end == self.buf.len() && self.buf.len() >= Self::MAX_BUF {
                self.last_lineterm = self.end;
                return Ok(true);
            }
        }
    }
}

/// The mutable state of one search: borrowed config and matcher, owned
/// counters.
///
/// Borrowed rather than a thread-local, matching `grep-searcher`'s `Core`. An
/// earlier draft reached for a thread-local to get the config back inside
/// the state, which is wrong twice: unavailable in `no_std`, and it makes
/// behaviour depend on ambient state.
struct Core<'c, 'm> {
    config: &'c Config,
    matcher: &'m dyn Matcher,
    /// Buffer offset where the last line handed out began.
    last_line_visited: usize,
    /// 1-based number of the next line, or 0 when line numbers are off.
    line_number: u64,
    /// After-context lines still owed after the last match.
    after_context_left: usize,
    /// Buffer offset up to which every line has been SUNK (as a match or as
    /// context). Before-context walks back from here, so this is what
    /// prevents the same line being reported twice — once as a later match's
    /// before-context and once as an earlier match's after-context.
    reported_upto: usize,
    /// Matching lines reported so far, checked against `quit_after`.
    match_count: u64,
    /// Whether any match was seen, for `-q`.
    #[allow(dead_code)]
    has_matched: bool,
    /// Bytes searched so far.
    byte_count: u64,
    /// Whether the pattern matches a line with no content. See
    /// [`Matcher::matches_empty`]; the per-buffer early exit is gated on this
    /// being false, and it is asked ONCE per search rather than per buffer.
    matches_empty: bool,
    /// Buffers the early exit skipped. Not a decision — every one of them was
    /// proven to hold no match — but the only way a caller can tell the
    /// optimisation ran, and therefore the only thing a test can assert on.
    skipped: u64,
    /// Gaps the per-candidate jump stepped over, and the lines in them. See
    /// [`Searcher::jumped_gaps`].
    jumped: u64,
    jumped_lines: u64,
}

impl<'c, 'm> Core<'c, 'm> {
    fn new(config: &'c Config, matcher: &'m dyn Matcher) -> Self {
        Self {
            config,
            matcher,
            last_line_visited: 0,
            // 0 when nobody reads the numbers: the skip path then refuses
            // `count_byte`/`count_lines`, which is one SIMD pass per fill
            // saved on every early-exit buffer.
            line_number: if config.wants_line_numbers() { 1 } else { 0 },
            after_context_left: 0,
            reported_upto: 0,
            match_count: 0,
            has_matched: false,
            byte_count: 0,
            matches_empty: matcher.matches_empty(),
            skipped: 0,
            jumped: 0,
            jumped_lines: 0,
        }
    }

    /// How many lines `buf[from..to]` holds, terminator included in the last
    /// one.
    ///
    /// **Why a skipped region still has to be counted.** The line number is
    /// reported to a sink, and a sink told "line 4 000 000" for the first
    /// line after a skipped buffer has been told a LIE — silently, and in
    /// exactly the shape nobody diffs: every line of the file is present and
    /// every number is right up to the gap. So a skip advances the counter by
    /// the number of lines it stepped over, not by zero.
    ///
    /// The map is the cheap way to count when there is one: a popcount over
    /// 8 KiB of L1 words against a `memchr` per line. The `memchr` iterator's
    /// specialised `count()` is the fallback and runs at about 50 GB/s, which
    /// is one pass over the buffer rather than a call per line — three orders
    /// of magnitude below what the walk it replaces cost.
    ///
    /// **`from` is an offset into the map, not into a slice.** The map covers
    /// the whole buffer, so counting a region has to start at the region's own
    /// offset. Passing a `&buf[from..to]` slice and counting it from 0 counts
    /// the WRONG bytes — it counts the terminators in `buf[0..to]`, which is
    /// right only when `from` is 0. That was true for the per-buffer skip,
    /// whose `pos` is 0 unless the roll retained something, which is to say
    /// unless `-A`/`-B`/`-C` is in use. The per-candidate jump calls this with
    /// `from > 0` on every single gap, and the differential caught the
    /// difference as a match reported one line early: `pub fn` over
    /// `pub fn\npub f\npub fn` reported the third line as the second.
    fn count_lines(buf: &[u8], from: usize, to: usize, term: u8, words: Option<&[u64]>) -> u64 {
        let region = match buf.get(from..to) {
            Some(r) => r,
            None => return 0,
        };
        if region.is_empty() {
            return 0;
        }
        // **The map is only usable if it actually covers `[from, to)`.**
        //
        // This check exists because of a segfault. `count_set_in` reaches an
        // AVX2 body loop that indexes the word slice through a raw pointer,
        // which needs the caller to have proved the indices are in bounds —
        // and its scalar sibling hides a violation by `get(..).unwrap_or(0)`.
        // The one caller that could not prove it was the reader path's lazy
        // per-buffer skip, which passed `Some(&[])` — an EMPTY map — whenever
        // the buffer was over `MAX_BITMAP_INPUT` and there was therefore no
        // map at all. Counting a 327 KB region against a zero-length slice
        // indexed word 4096..5119 of a pointer that is not dereferenceable,
        // and `rgx -c needle some_large_binary` died with an access
        // violation. It only ever showed up over `BUFFER_PATH_MAX`, because
        // only the reader path grows its buffer far enough to cross the map
        // cap, which is why every file under 16 MiB was clean.
        //
        // So the map is trusted only when it is long enough, and a short one
        // falls back to `count_byte` over the same region — the same path the
        // no-map case already takes, and the same answer.
        let words = words.filter(|w| w.len() >= to.div_ceil(64));
        let newlines = match words {
            Some(w) => count_set_in(w, from, to),
            None => crate::scan::count_byte(term, region),
        };
        // A final line with no terminator is still a line, which is the rule
        // `find_line` applies when it hands one back.
        if region[region.len() - 1] == term {
            newlines
        } else {
            newlines + 1
        }
    }

    /// Sink the `before`-context lines immediately preceding `upto`, oldest
    /// first, skipping any already sunk.
    ///
    /// The walk is the reference's: step back over whole lines from
    /// `reported_upto` — the offset up to which every line has been emitted —
    /// and take at most `Config::before` of them. Skipping by `reported_upto`
    /// is what stops the line shared by two adjacent matches being printed
    /// twice, and what keeps a line already reported as one match's
    /// after-context from reappearing as the next match's before-context.
    fn sink_before_context<S: Sink>(
        &mut self,
        sink: &mut S,
        buf: &[u8],
        abs: u64,
        upto: usize,
    ) -> Result<bool, S::Error> {
        let term = self.config.line_term.line_term;
        // The candidates are the line starts in [reported_upto, upto).
        let mut starts: Vec<usize> = Vec::new();
        // Walk BACK from `upto` — the match line — collecting the preceding
        // lines, stopping once they are already-sunk (`reported_upto`) or the
        // count is reached. An earlier version started at
        // `upto.min(reported_upto)`, which is always 0 until something is
        // sunk, so the walk never reached a line and `-B` reported nothing.
        let mut at = upto;
        while at > self.reported_upto && starts.len() < self.config.before {
            let start = line_start(buf, at, term);
            if start < at {
                starts.push(start);
            }
            if start == 0 {
                break;
            }
            at = start;
        }
        // Oldest first.
        for start in starts.iter().rev().copied() {
            let end = match crate::memchr::memchr(term, &buf[start..]) {
                Some(i) => start + i + 1,
                None => buf.len(),
            };
            // The before-context lines precede every line already numbered,
            // so their 1-based numbers are the current one minus how many
            // lines back each sits. Counting back from `line_number` (the
            // current line's number) keeps them exact without a second
            // counter — a sink that prints these (rgx does) needs them.
            let back = starts_before(&starts, start);
            let ctx = SinkContext {
                bytes: &buf[start..end],
                line_number: if self.line_number > 0 {
                    Some(self.line_number.saturating_sub(back as u64))
                } else {
                    None
                },
                bytes_range_in_buffer: start..end,
                absolute_byte_offset: abs + start as u64,
                kind: ContextKind::Before,
            };
            if !sink.context(&ctx)? {
                return Ok(false);
            }
            // These before-context lines are sunk; a later match's walk must
            // not re-emit them.
            self.reported_upto = end;
        }
        Ok(true)
    }

    /// How many bytes of `buf` to keep when rolling.
    ///
    /// The before-context lines, plus everything from the last line already
    /// visited — the latter because a context separator must know where the
    /// previous line was even when `-B` is zero. With no context at all the
    /// whole buffer is consumed and the roll is a no-op, which is the
    /// common case and the fast one.
    fn roll_target(&self, buf: &[u8], max_context: usize) -> usize {
        if max_context == 0 {
            return buf.len();
        }
        let context_start =
            preceding_lines(buf, self.config.line_term.line_term, self.config.before);
        if context_start > self.last_line_visited {
            context_start
        } else {
            self.last_line_visited
        }
    }

    /// Search one buffer. Returns whether to keep going.
    ///
    /// `skip` is the offset of the retained region: bytes below it were
    /// already searched and sunk on the previous fill, so the walk steps over
    /// them. They remain readable so `before_context` can reach back into
    /// them. `grep-searcher` does the same thing with its `pos`.
    // Every parameter is a distinct per-buffer input the callers already
    // hold: sink, buffer, resume point, skip, and the search views. A
    // parameter struct would only rename them.
    #[allow(clippy::too_many_arguments)]
    fn run<const MULTI: bool, S: Sink>(
        &mut self,
        sink: &mut S,
        buf: &[u8],
        abs: u64,
        skip: usize,
        candidates: Option<Candidates<'_>>,
        terms: Option<&BitMap>,
        nonascii: Option<&BitMap>,
    ) -> Result<bool, S::Error> {
        let term = self.config.line_term.line_term;
        // Whether this matcher may reserve a line for its delegate. Hoisted
        // per buffer with the other config reads; when it is false the
        // window rule below short-circuits to the mask's answer.
        let routes_delegate = self.matcher.may_decline_lines();
        // Hoisted once per buffer: whether a pure-ASCII window settles at
        // all. The per-line shortcut then answers from the fill maps alone
        // -- no virtual call on the 6.9M settled lines of a flagship row.
        // A matcher that refuses clean windows (fold-risky case folding)
        // gets `false` here and every line falls to the window walk, where
        // it refuses each window and the delegate answers.
        let clean_window_settles = self.matcher.decides_window(&[], true);
        // Config fields read per line are hoisted once per buffer, the same
        // treatment `term` already gets. Each access is a `&Config` load and
        // a field hop; over 200 lines per file the repeated loads are a few
        // extra instructions per line that the register allocator may or
        // may not eliminate on its own. `after_context_left` is NOT hoisted:
        // it is both read and written in the loop.
        let invert = self.config.invert;
        let multi_line = MULTI;
        let matches_empty = self.matches_empty;
        // `-U` cache: the first match at or after `pos`, as (start, end). A
        // local, not a `Core` field — `run` runs once per buffer, so nothing
        // needs to carry between buffers, and a field would put 24 bytes in
        // front of every search that never reads it.
        let mut ml_span: Option<(usize, usize)> = None;
        let after = self.config.after;
        let before = self.config.before;
        let needs_output = self.config.needs_line_output();
        let quit_after = self.config.quit_after;
        // The walk starts at the retained region, not at 0. Those bytes were
        // searched and sunk on the previous fill, so walking them again would
        // emit every context line a second time AND advance the line counter
        // past lines that were already counted -- which is what made a
        // small-chunk reader report line 21 where `grep` reports line 8. They
        // stay in the buffer so a `-B` walk can reach back into them across the
        // boundary. `grep-searcher` does exactly this with its `pos`.
        let mut pos = skip.min(buf.len());
        // Read ONCE per buffer, not once per line. It used to travel inside
        // `LineCandidates`, which is built and moved once per line, and the
        // extra word made that struct a cache line wider: 3% on a one-byte
        // literal over 7.8 million lines, for a value that is constant for
        // the whole buffer.
        // A `^`-anchored pattern is `Origin::LineStart` whatever the prefilter
        // managed to say about offsets, and that is worth more than the offset
        // it replaces: the confirm becomes one anchored run at 0 instead of a
        // scan of the line from every candidate.
        let origin = if self.matcher.line_anchored() {
            Origin::LineStart
        } else {
            candidates.as_ref().map_or(Origin::Fixed(0), |c| c.origin())
        };
        let mut cand = candidates;

        // ---- the per-buffer early exit --------------------------------
        //
        // If the anchor found nothing in the WHOLE buffer, no line of it can
        // match and the line walk is work thrown away. The per-64 KiB
        // granularity exists only on the reader, which is where `src/main.rs`
        // puts every file over `BUFFER_PATH_MAX`; on `search_slice` the whole
        // file is one buffer, so the decision takes all of it or none.
        //
        // Exclusions:
        //
        // - [`Supply::Every`]: no required literal, so no anchor to be absent.
        //   The mechanism does not exist, rather than failing to help.
        // - [`Config::invert`] (`-v`): every non-matching line is the output,
        //   so a buffer of non-matching lines is all output.
        // - After-context still owed: owed by a match that already happened.
        // - [`Self::matches_empty`]: a zero-length line inside the skipped
        //   buffer is a match the skip cannot see.
        // - No `--passthru` in rgx; `-v` is the nearest thing and is excluded.
        //
        // NOT excluded, deliberately: `-c` and `-l`, because a skipped buffer
        // contributes zero matches, which is the whole content of both
        // answers; and `--json`, whose `begin`/`end` events are per FILE and
        // whose `byte_count` is advanced below. Excluding those would cost the
        // one mode a user runs over a large tree expecting it to be fast.
        // The same view, still saying whether there IS a map. `count_lines`
        // takes the Option rather than a bare slice because an empty slice is
        // a real answer for a haystack with no terminators, and folding that
        // into the empty-slice case would silently count nothing.
        let map_opt: Option<&[u64]> = terms.map(BitMap::words);
        // The jump's own tallies, kept in locals for the length of the walk
        // and folded into `self` once at the end. See the note at the store.
        let mut jumped = 0u64;
        let mut jumped_lines = 0u64;

        let skippable = !invert
            && !multi_line
            && self.after_context_left == 0
            && !matches_empty
            && cand.as_ref().is_some_and(|c| c.is_empty_in(pos, buf.len()));
        if skippable {
            if self.line_number > 0 {
                self.line_number += Self::count_lines(buf, pos, buf.len(), term, map_opt);
            }
            // `reported_upto` and `last_line_visited` are deliberately NOT
            // advanced: nothing here was sunk, so both still say "nothing
            // reported below here", which is what lets a later match's
            // before-context walk reach back into this buffer and find those
            // lines un-emitted. The roll, not this function, decides how much
            // of it survives.
            self.byte_count += buf.len() as u64;
            self.skipped += 1;
            return Ok(true);
        }

        // The line boundaries, out of the map when there is one.
        //
        // Carried in LOCALS, not behind a method: `BitMap::next_set` costs
        // about 11 ns per call, which is the same as the `memchr` over a
        // 31-byte line it is here to remove, and the searcher asks it 7.8
        // million times. Hoisting the word out of the slice and keeping it in
        // a register across the walk is what makes the map a win at all --
        // measured, leaving the call in cost 170 ms and the fill 14.
        //
        // `tw` is the map word holding `pos`, `tw_at` that word's first byte,
        // and `tw_done` says the map is exhausted, which is what leaves the
        // trailing line to be handled as a line without a terminator -- the
        // same answer `find_line` gives.
        let map_words: &[u64] = terms.map_or(&[], BitMap::words);
        let mut tw_word_idx = pos >> 6;
        let mut tw_at = tw_word_idx << 6;
        let mut tw = if terms.is_some() && tw_word_idx < map_words.len() {
            map_words[tw_word_idx] & (u64::MAX << (pos & 63))
        } else {
            0
        };
        let mut tw_done = terms.is_none() || tw_word_idx >= map_words.len();

        // ---- the per-CANDIDATE jump -----------------------------------
        //
        // The per-buffer skip is all-or-nothing over 64 KiB. On a sparse
        // pattern the case it cannot see is a window holding ONE candidate and
        // two thousand lines that do not: those lines are walked and the
        // anchor's opinion about them is never asked. So the walk advances by
        // candidate, as `grep-searcher` did — `pos = line.end()` after a
        // candidate line fails to confirm, reprocessing only that line.
        //
        // The line a candidate sits in is found by a forward popcount over the
        // gap. Measured against a second-level `u32` count per 512 B and a
        // sorted array of line starts, popcount wins outright: no index to
        // build, no memory beyond the two maps already there.
        //
        // Exclusions, each a distinct reason:
        //
        // - [`Config::invert`]: under `-v` a candidate-free line IS the output.
        // - [`Self::matches_empty`]: a zero-length line has no byte offsets, so
        //   no candidate can point at it — and it is a match.
        // - `after_context_left > 0`: those lines are owed by a match that
        //   already happened; the anchor says nothing about them. Checked
        //   inside the loop because a match sets the field mid-walk.
        // - [`Supply::Every`]: no anchor to be absent, every offset is a
        //   candidate, `next_offset` returns the current position and the jump
        //   would never advance. It would not return wrong answers; it would
        //   never return at all.
        // - No terminator map: the jump needs [`prev_term`], so a haystack
        //   over [`MAX_BITMAP_INPUT`] falls back to the line walk.
        // - [`Config::multi_line`]: the line that REPORTS a multi-line match is
        //   the one it ends on, and by construction that line holds no
        //   candidate. Same failure mode as `matches_empty`.
        //
        // **Correctness**: the jump advances neither `reported_upto` nor
        // `last_line_visited`. A jumped-over line was walked PAST, not SUNK,
        // and those two fields say "every line below here has been reported" —
        // which the skipped lines contradict. Leaving them alone is what lets a
        // later match's before-context reach back across the gap.
        let mut jumping = !invert
            && !matches_empty
            && !multi_line
            && terms.is_some()
            && cand.as_ref().is_some_and(|c| c.has_anchor());
        // Consecutive jumps that found NO lines to step over. A jump whose
        // gap is empty has bought nothing and cost a `next_offset`, a
        // `prev_term` and a re-point of the terminator cursor. With the jump
        // on unconditionally, `e` and `e.` each step over 2.58 million of their
        // 7.83 million lines and come out 1-2% SLOWER — every landing costs
        // more than the line it replaced.
        //
        // So the jump stands itself down for the rest of the buffer once it has
        // seen `DENSE_RUN` of them in a row, and picks up again in the next.
        // This is a density detector with no threshold to tune against a
        // corpus: the buffer's own first few landings decide, and the two
        // shapes it must tell apart are 2.5x apart in the nine — `let mut`
        // averages 80 lines per gap and `e` averages 0.6.
        //
        // Four, and the value is measured rather than guessed. Switching off
        // after two empty gaps fixes the dense case but costs the sparse ones
        // where they matter: `let mut` fell from 2.56x to 2.05x and `e[0-9]`
        // from 1.88x to 1.65x, because a run of four adjacent matching lines
        // turns the jump off for the rest of a 64 KiB buffer that had 2 000
        // good jumps left in it. At four all nine are at or above their
        // unguarded best and the dense three stop regressing.
        //
        // **Counting the LINES a window of landings skips is the test one would
        // write, and it is 45% worse on `e[0-9]`.** It was written and
        // measured. A jump costs about 20.6 ns against the 10 ns of a line the
        // walk would otherwise have processed, so it pays for itself at a gap
        // of two lines and AVERAGE GAP over a window of sixteen landings looks
        // like the right quantity — and `e[0-9]`'s average is 39 lines, so the
        // window keeps the jump on. That is the loss: 277 ms against 189 on the
        // 235 MB corpus, minimum of seven, both arms interleaved, and it
        // survives standing the jump down entirely, so what costs is the JUMP
        // and not the arithmetic around it.
        //
        // `e[0-9]`'s candidates sit 1.67 to a MATCHING line, so most of its
        // landings are on a line the walk was about to process anyway, and each
        // one re-points the terminator cursor that the note above calls "most
        // of what the walk is". So the gap the guard has to notice is not the
        // size of the gap but whether the candidate is on a line the walk is
        // already standing on — which is what four consecutive empty gaps ask,
        // and the answer it gives is the right one. A detector that keeps the
        // jump on where standing it down is worth 45% is a regression wearing a
        // better argument, and the constant stays at four.
        const DENSE_RUN: u32 = 4;
        let mut dense = 0u32;
        // Probation: after DENSE_RUN stands the jump down, the walk keeps a
        // line counter. When it reaches the probation length, the jump gets
        // ONE more try (dense reset to 0, jumping true again); if the very
        // next landings are dense again the counter doubles, so a truly
        // dense pattern spends at most one probe per 64/128/256/... lines
        // while a clustered-but-sparse one -- Rust imports at the top of a
        // file, sparse `fn main` matches below -- is re-enabled after the
        // cluster instead of losing the whole rest of the buffer.
        //
        // The probe cost is one `next_offset` + one `prev_term` per
        // probation window, which is the same two calls a real jump makes
        // and bounded by the doubling to at most log2(buf_len / 64) probes.
        let mut probation: u32 = 0;
        let mut probation_len: u32 = 64;
        let mut lines_since_probe: u32 = 0;

        while pos < buf.len() {
            // ---- the jump, once per candidate ----------------------------
            //
            // It only ever moves `pos` FORWARD, to the start of a line that
            // holds a candidate, and the line below then processes that line
            // exactly as it would have processed it had the walk reached it.
            // Nothing below this block knows a jump happened.
            if jumping && self.after_context_left == 0 {
                let hit = cand
                    .as_mut()
                    .expect("jumping implies a candidate stream")
                    .next_offset(pos);
                match hit {
                    // No candidate left in this buffer, so no line left in it
                    // can match. Same inference the per-buffer skip makes, one
                    // line at a time, and sound for the same reason.
                    //
                    // `pos` is left where it is: the loop is done, and
                    // nothing after it reads `pos` -- `byte_count` is the
                    // buffer's length either way.
                    None => {
                        if self.line_number > 0 {
                            self.line_number +=
                                Self::count_lines(buf, pos, buf.len(), term, map_opt);
                        }
                        break;
                    }
                    Some(c) => {
                        // The line holding the candidate: the terminator
                        // before it and the one at or after it. `ls >= pos`
                        // because `pos` is itself a line start, so the gap is
                        // a whole number of lines and the popcount is exact.
                        let ls = prev_term(map_words, c).map_or(0, |p| p + 1);
                        if ls == pos {
                            dense += 1;
                            if dense >= DENSE_RUN {
                                // Probation, not permanent shutdown: the
                                // cluster that triggered this may be the
                                // import block at the top of a file, and
                                // the 300-line body below it is exactly
                                // what the jump is for.
                                jumping = false;
                                probation = probation_len;
                                lines_since_probe = 0;
                            }
                        } else {
                            dense = 0;
                            // A productive gap resets the doubling: the
                            // jump has proven itself again and the next
                            // probation (if any) should start from the
                            // shortest window.
                            probation_len = 64;
                        }
                        if ls > pos {
                            // LOCALS, not `self` fields. Two stores through
                            // `&mut self` per gap -- 1.3 million of them for a
                            // one-byte pattern -- is enough to keep the whole
                            // `Core` in memory across the loop and stop the
                            // line walk hoisting its state into registers,
                            // which is most of what the walk is. Measured: the
                            // jump on `e` was a wash with the counters in
                            // `self` and is not without them.
                            let gap = if self.line_number > 0 {
                                Self::count_lines(buf, pos, ls, term, map_opt)
                            } else {
                                0
                            };
                            jumped += 1;
                            jumped_lines += gap;
                            if self.line_number > 0 {
                                self.line_number += gap;
                            }
                        }
                        pos = ls;
                        // Re-point the forward terminator cursor at the line
                        // the jump landed on. Without this the line below
                        // would read a word describing a different part of the
                        // buffer, and the walk would report the wrong line.
                        tw_word_idx = pos >> 6;
                        tw_at = tw_word_idx << 6;
                        tw = if tw_word_idx < map_words.len() {
                            map_words[tw_word_idx] & (u64::MAX << (pos & 63))
                        } else {
                            0
                        };
                    }
                }
            }

            // Probation countdown: one line closer to the next jump probe.
            // Runs only when the jump is standing down, so the dense case
            // pays one integer compare per line and nothing else.
            if probation > 0 {
                lines_since_probe += 1;
                if lines_since_probe >= probation {
                    probation = 0;
                    lines_since_probe = 0;
                    probation_len = (probation_len * 2).min(4096);
                    dense = 0;
                    jumping = true;
                }
            }

            let (line_start, line_end) = if tw_done {
                match find_line(buf, pos, term) {
                    Some(x) => x,
                    None => break,
                }
            } else {
                loop {
                    if tw != 0 {
                        let nl = tw_at + (tw.trailing_zeros() as usize);
                        // CONSUME the bit. Without this the same terminator is
                        // handed back on every line and the walk never reaches
                        // the end of the buffer -- an infinite loop, which is
                        // what five differential tests hitting a 60 s watchdog
                        // looked like before it was found.
                        tw &= tw - 1;
                        break (pos, nl + 1);
                    }
                    tw_word_idx += 1;
                    tw_at += 64;
                    if tw_at >= buf.len() || tw_word_idx >= map_words.len() {
                        tw_done = true;
                        break (pos, buf.len());
                    }
                    tw = map_words[tw_word_idx];
                }
            };
            let line = &buf[line_start..line_end];

            // The match is sought in the line's CONTENT, with the terminator
            // cut off -- the same haystack `grep-searcher` builds in
            // `match_by_line_slow`. Handing the matcher a bounded slice rather
            // than the whole buffer and then checking the span is not a
            // stylistic choice: a greedy pattern grows to whatever it can
            // reach, so `[^a-z]+` on a line of `123` spans `123\n`, and a span
            // that merely reached one byte past the content would be thrown
            // away even though `123` inside the line is a match. Cutting the
            // terminator off makes the matcher's own greed stop in the right
            // place, and makes `^` and `$` anchor the LINE, which is what `grep`
            // means by them.
            //
            // The two bugs this pins. `[^a-z]` matches `\n`, so with the
            // terminator in range it matched the terminator of every line and
            // the searcher reported a degenerate one-byte line, with the line
            // numbers drifting from there on. And `[^a-z]+` then had its match
            // rejected for reaching one byte too far, which cost every line
            // whose content is entirely non-letters.
            // Map path: the terminator is at `line_end - 1` by construction
            // (`line_end = nl + 1` where `nl` is the map's terminator bit),
            // so no byte load is needed. `find_line` is the only path where
            // the trailing line may lack a terminator.
            let content_end = if tw_done && !(line_end > line_start && buf[line_end - 1] == term) {
                line_end
            } else {
                line_end - 1
            };
            let content = &buf[line_start..content_end];

            // **`-U`.** A match may span the line, and it is reported on the
            // line where it TERMINATES -- ripgrep's rule, not the obvious one.
            // Making `is_match` mean "a multi-line match ends ON THIS LINE" is
            // what leaves everything below this point untouched: the
            // `SinkMatch` is the usual one, `-A`/`-B` hang where they hung,
            // `-m` counts where it counted. Only the question changes, not the
            // machine that consumes it.
            //
            // That is why the haystack handed to the matcher is the REST of
            // the buffer from `pos` rather than `content`: cutting the
            // terminator off here is what makes the match impossible. The
            // candidate stream is deliberately ignored -- it is per LINE, and
            // a match over several lines does not fit in a line range; asking
            // it would answer "no" to a match that exists.
            //
            // `ml_span` holds the first match from `pos`. Validity is by the
            // END, not the start: the line that reports is the end line, so
            // what matters is the match reaching past `pos`.
            let ml_span = if !multi_line {
                None
            } else if ml_span.is_some_and(|(_, e)| e > pos) {
                ml_span
            } else {
                ml_span = self
                    .matcher
                    .find_span_at(&buf[pos..], 0)
                    .map(|span| (pos + span.start, pos + span.end));
                ml_span
            };

            // A candidate stream, when present, replaces the per-line match
            // test with a range check plus a confirmation. A matcher with no
            // stream is asked at every line, which is what makes this an
            // optimisation and not a requirement.
            //
            // The confirmation is `any_match_in` over the offsets the stream
            // yields for THIS line, not a fresh search of the line's content:
            // the buffer was scanned once when the stream was built, so
            // re-scanning each line made the cost `lines x buffer` again. The
            // haystack handed over is still the line's content, so `^` and `$`
            // anchor the line and a greedy pattern still stops at the
            // terminator; only the scan is shared.
            //
            // A ZERO-LENGTH line is the one case the stream cannot speak for.
            // Candidates are byte offsets and the stream hands out the half-open
            // range `[line_start, content_end)`, so a line with no content has
            // an empty range whatever the supply is -- `Supply::Reported` finds
            // no reported offset inside it, `Supply::Every` yields
            // `max(idx, start) .. min(end, len)` which is empty when
            // `start == end`. An empty stream is not evidence of no match: an
            // empty line has exactly one position, and every pattern that can
            // match the empty string matches there. Reading it as "skip the
            // line" dropped every blank line in a file, so `^` and `.*`
            // reported the non-blank lines only, `^\s*$` reported none at all,
            // and `-v` and the context walks counted the wrong lines. The
            // stream is still advanced, so the cursor walks exactly as before
            // and no offset is offered to two lines.
            //
            // Asking the matcher costs nothing measurable: the haystack is
            // empty, so there is no scan to share in the first place.
            let is_match = if multi_line {
                // `end > line_start` because a match ending exactly ON this
                // line's start belongs to the PREVIOUS line and was reported
                // there; `end <= line_end` because the last matched byte must
                // be inside this line, terminator included. A match that ends
                // on a line is REPORTED on it, but PRINTED whole from where it
                // began — see `ml_bytes` below.
                ml_span.is_some_and(|(_, end)| end > line_start && end <= line_end)
            } else {
                match cand.as_mut() {
                    Some(c) => {
                        // The window rule (maintainer-approved,
                        // `benchmark/findings.md` §13 shape 2): a mask bit
                        // whose widest window is pure ASCII is a match in
                        // both engines -- on ASCII bytes a codepoint is a
                        // byte -- so the bit settles the line on its own. The
                        // delegate is asked only when EVERY window on the
                        // line is refused, and a line with no bit at all is
                        // the mask's settled `false`. This replaced hybrid.rs's
                        // whole-buffer `buffer_ascii` gate (one non-ASCII byte
                        // in a 64 KiB fill cost every line of it the settle),
                        // then a per-line ASCII rescan (66 ms of the row), and
                        // the window is the pattern's fixed match span -- a
                        // handful of bytes, not the line.
                        if content.is_empty() {
                            matches_empty
                        } else if routes_delegate && c.decides() {
                            // The line-clean shortcut first: one map lookup
                            // settles the ~93% pure-ASCII lines outright, and
                            // the window walk below runs only on the dirty
                            // minority. Without it every settled line paid a
                            // window walk or a per-line rescan
                            // (`benchmark/findings.md` §13 prices both).
                            let line_ascii = match nonascii {
                                Some(m) => !m.any_set(line_start, content_end),
                                None => content.is_ascii(),
                            };
                            if line_ascii && clean_window_settles {
                                // A clean line's every window is clean, and
                                // the matcher accepts clean windows (hoisted
                                // above), so the mask's answer is the answer.
                                // It is still the MASK's answer: a line with
                                // no bit is a miss -- settling `true` here
                                // regardless is what briefly over-reported
                                // 827k lines of `e.` on the 246 MB row before
                                // `a_clean_line_without_a_candidate_is_not_a_match`
                                // pinned it. `None` is a non-mask stream and
                                // cannot reach this arm.
                                c.line_matches(line_start, content_end).unwrap_or(false)
                            } else {
                                // The window rule (maintainer-approved,
                                // findings §13 shape 2): a mask bit whose
                                // widest window is pure ASCII is a match in
                                // both engines -- on ASCII bytes a codepoint
                                // is a byte -- so the bit settles the line on
                                // its own. The delegate is asked only when
                                // EVERY window on the line is refused, and a
                                // line with no bit at all is the mask's
                                // settled `false`.
                                let span = c.mask_window();
                                let line_len = content.len();
                                let mut saw_bit = false;
                                let mut settled = false;
                                // `in_line` yields the line's bits and parks
                                // the cursor at the line end, exactly as the
                                // settle does -- the delegate arm's empty
                                // candidates are the same design as before.
                                for rel in c.in_line(line_start, content_end) {
                                    saw_bit = true;
                                    let w_end = (rel + span).min(line_len);
                                    let window_ascii = match nonascii {
                                        Some(m) => !m.any_set(line_start + rel, line_start + w_end),
                                        None => content[rel..w_end].is_ascii(),
                                    };
                                    // A clean window settles by the hoisted
                                    // policy; the matcher is consulted only
                                    // for the dirty windows it may still
                                    // take, which are the rare ones.
                                    if (window_ascii && clean_window_settles)
                                        || self
                                            .matcher
                                            .decides_window(&content[rel..w_end], window_ascii)
                                    {
                                        settled = true;
                                        break;
                                    }
                                }
                                if settled {
                                    true
                                } else if !saw_bit {
                                    false
                                } else {
                                    // Every window is refused: a hybrid's
                                    // `any_match_in` scans the line whole and
                                    // ignores the byte-oriented candidates,
                                    // which is also why the cursor having been
                                    // parked costs nothing here. A matcher
                                    // that refuses a window must therefore be
                                    // able to answer from the line alone.
                                    let line_cands = c.in_line(line_start, content_end);
                                    self.matcher.any_match_in(content, line_cands, origin)
                                }
                            }
                        } else {
                            match c.line_matches(line_start, content_end) {
                                Some(m) => m,
                                None => {
                                    let line_cands = c.in_line(line_start, content_end);
                                    let has = !line_cands.is_empty();
                                    if has && c.decides() {
                                        true
                                    } else {
                                        has && self
                                            .matcher
                                            .any_match_in(content, line_cands, origin)
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        if content.is_empty() {
                            matches_empty
                        } else {
                            self.matcher.find_span_at(content, 0).is_some()
                        }
                    }
                }
            };

            // Under `-v` a line is reported when it does NOT match, so `report`
            // and `is_match` are different lines and only one of them is the
            // line the output hangs off. The context machinery is keyed on
            // `report`; see below.
            let report = is_match != invert;

            // **Everything below is keyed on `report`, not on `is_match`, and
            // under `-v` those are different lines.**
            //
            // `grep-searcher` hangs its context off the line it *prints as a
            // match*, and under `-v` that is the NON-matching line. Keying
            // the context machinery on `is_match` instead meant that no
            // reported line under `-v` could ever start a context run: the
            // `report && is_match` arm is unsatisfiable when `invert` is set,
            // so `rgx -v -A1`, `-v -B1` and `-v -C1` printed **no context at
            // all**, and printed a `--` separator between two lines with
            // nothing between them. Found while adding a parity case for the
            // specialised confirm, and reproduced identically on `main`,
            // so it predates that work.
            //
            // Under no inversion `report == is_match` and every arm below
            // takes exactly the path it took before.
            if report {
                self.match_count += 1;
                self.has_matched = true;
                if after > 0 {
                    self.after_context_left = after;
                }
                // Before-context, emitted *before* the match line. The
                // reference does the same walk (`Core::before_context_by_line`
                // steps back from `last_line_visited`), and the reason it
                // can is the roll: those lines were visited but not yet
                // sunk. rgx's printer labels a before-context line
                // differently from an after-context one, so reporting only
                // after-context would make `-B` silently wrong.
                if before > 0
                    && needs_output
                    && !self.sink_before_context(sink, buf, abs, line_start)?
                {
                    return Ok(false);
                }
                if needs_output {
                    // `-U`: the sink gets the WHOLE match and the number of
                    // the line it BEGAN on, so a printer that numbers each
                    // physical line reproduces rg (`3:THREE` / `4:four` for a
                    // match over lines 3-4).
                    let span = match (multi_line, ml_span) {
                        (true, Some((s, e))) if e > line_start && e <= line_end => Some((s, e)),
                        _ => None,
                    };
                    let range = span.map_or(line_start..line_end, |(s, e)| s..e);
                    // The match may begin on an earlier line than the one being
                    // walked, so its number is this line's minus the
                    // terminators between the two.
                    let line_number = match (span, self.line_number_opt()) {
                        (Some((s, _)), Some(cur)) => Some(cur.saturating_sub(
                            buf[s..line_start].iter().filter(|&&b| b == term).count() as u64,
                        )),
                        _ => self.line_number_opt(),
                    };
                    let m = SinkMatch {
                        bytes: &buf[range.start..range.end],
                        line_number,
                        absolute_byte_offset: abs + range.start as u64,
                        bytes_range_in_buffer: range,
                    };
                    if !sink.matched(&m)? {
                        return Ok(false);
                    }
                }
                // A reported match is sunk, so a later match's before-context
                // walk stops before it. (Its before-context, if any, was
                // emitted just above, which also advances reported_upto.)
                self.reported_upto = line_end;
                self.last_line_visited = line_end;
            } else if self.after_context_left > 0 {
                if needs_output {
                    let ctx = SinkContext {
                        bytes: line,
                        line_number: self.line_number_opt(),
                        bytes_range_in_buffer: line_start..line_end,
                        absolute_byte_offset: abs + line_start as u64,
                        kind: ContextKind::After,
                    };
                    if !sink.context(&ctx)? {
                        return Ok(false);
                    }
                }
                // An after-context line IS sunk, so it must not reappear as a
                // later match's before-context.
                self.reported_upto = line_end;
                self.last_line_visited = line_end;
                self.after_context_left -= 1;
            }

            // `-m` bounds reported MATCHES, never the candidate stream, so a
            // long stream cannot cut a match short.
            //
            // The subtlety is WHEN the limit stops the search. Returning here,
            // on the line that reached the limit, cuts the search one line
            // before the after-context of the final match is emitted -- which
            // is the `-m` + `-A` divergence rgx's `HitSink` documents
            // against itself. `grep-searcher` does not return here: it records
            // that the limit was exceeded, sinks the remaining after-context,
            // and only then stops. `quit_after` is the same contract, so the
            // stop belongs AFTER the after-context has drained, not on the
            // match that hit the limit.
            let limit_reached = matches!(quit_after, Some(n) if self.match_count >= n);
            if limit_reached && self.after_context_left == 0 {
                self.last_line_visited = line_end;
                return Ok(false);
            }
            // `last_line_visited` advances only when a line is actually SUNK --
            // as a match, as before-context or as after-context -- never for a
            // line that was merely walked past. `grep-searcher` holds the same
            // invariant (it assigns in `sink_matched`, `sink_before_context` and
            // `sink_after_context`, and nowhere else), and it is what makes
            // `roll_target` retain the right bytes: it takes
            // `max(context_start, last_line_visited)`, so a long run of
            // non-matching lines leaves `last_line_visited` at 0 and the
            // retention is driven purely by `-B`. Advancing it on every line,
            // as an earlier version here did, pinned it at the end of the
            // buffer, retained nothing, and silently dropped `-B` across a roll
            // -- the missing before-context line the reader differential caught.
            if self.line_number > 0 {
                self.line_number += 1;
            }
            pos = line_end;
        }
        self.jumped += jumped;
        self.jumped_lines += jumped_lines;
        self.byte_count += buf.len() as u64;
        Ok(true)
    }

    fn line_number_opt(&self) -> Option<u64> {
        if self.line_number == 0 {
            None
        } else {
            Some(self.line_number)
        }
    }

    fn finish<S: Sink>(&mut self, sink: &mut S, binary: Option<u64>) -> Result<(), S::Error> {
        let fin = SinkFinish {
            byte_count: self.byte_count,
            binary_byte_offset: binary,
            _marker: core::marker::PhantomData,
        };
        sink.finish(&fin)
    }
}

impl<'m> Searcher<'m> {
    /// Search a whole in-memory buffer, line by line.
    ///
    /// This is `grep-searcher`'s `SliceByLine`: the whole haystack is
    /// present, so there is no roll and no before-context carry. Binary
    /// detection runs over the whole slice, which is the mapped-file
    /// behaviour rgx relies on: a NUL anywhere in a mapped file is seen.
    ///
    /// Under `BinaryDetection::Quit` a NUL inside the first
    /// `BINARY_PROBE` bytes **ends the search before the first line is
    /// looked for**, so nothing at all is reported. Past that window the
    /// buffer is searched up to the byte. The reference pins the first half
    /// in its own tests (`grep-searcher` `binary1` and `binary3`): haystack
    /// `"a\0"`, pattern `a`, quit(0) -> `byte count:0`; and in `binary3` the
    /// `a` *after* a NUL is not in the slice result either.
    ///
    /// The reader differs, and the difference is not this searcher's to
    /// smooth over: a reader has already stopped reading, so it reports the
    /// matches it saw before the NUL. Both end the search, they just stop at
    /// different points.
    pub fn search_slice<S: Sink>(&self, hay: &[u8], sink: &mut S) -> Result<bool, S::Error> {
        let mut scratch = Scratch::new();
        let mut offsets = Vec::new();
        self.search_slice_with_scratch(hay, sink, &mut scratch, &mut offsets)
    }

    /// Search an in-memory buffer, reusing caller-provided scratch space for
    /// candidate bit maps and offsets across multiple searches.
    pub fn search_slice_with_scratch<S: Sink>(
        &self,
        hay: &[u8],
        sink: &mut S,
        scratch: &mut Scratch,
        offsets: &mut Vec<usize>,
    ) -> Result<bool, S::Error> {
        if !self.matcher.can_match() {
            return Ok(false);
        }
        // A declared encoding outranks the sniff: the caller said what these
        // bytes are (`Config::forced_bom`), and a mark at the front is data,
        // not a claim to overrule it.
        if let Some(bom) = self.config.forced_bom {
            let decoded = encoding::force_decode(bom, hay);
            let mut rest: &[u8] = &decoded;
            let mut read = |b: &mut [u8]| -> Result<usize, fmt::Error> {
                let n = core::cmp::min(b.len(), rest.len());
                b[..n].copy_from_slice(&rest[..n]);
                rest = &rest[n..];
                Ok(n)
            };
            let mut buf = LineBuffer::new(&self.config);
            return self.search_reader_inner(&mut read, sink, &mut buf);
        }
        if self.config.bom_sniffing {
            if let Some(bom) = encoding::sniff(hay) {
                let decoded = encoding::decode(bom, hay);
                let mut rest: &[u8] = &decoded;
                let mut read = |b: &mut [u8]| -> Result<usize, fmt::Error> {
                    let n = core::cmp::min(b.len(), rest.len());
                    b[..n].copy_from_slice(&rest[..n]);
                    rest = &rest[n..];
                    Ok(n)
                };
                let mut buf = LineBuffer::new(&self.config);
                return self.search_reader_inner(&mut read, sink, &mut buf);
            }
        }
        match self.config.binary {
            BinaryDetection::None => {
                self.search_slice_inner_with_scratch(hay, sink, None, scratch, offsets)
            }
            BinaryDetection::Quit(byte) => {
                let upto = core::cmp::min(hay.len(), BINARY_PROBE);
                if let Some(i) = crate::memchr::memchr(byte, &hay[..upto]) {
                    let mut core = Core::new(&self.config, self.matcher);
                    core.finish(sink, Some(i as u64))?;
                    return Ok(false);
                }
                match crate::memchr::memchr(byte, hay) {
                    Some(i) => self.search_slice_inner_with_scratch(
                        &hay[..i],
                        sink,
                        Some(i as u64),
                        scratch,
                        offsets,
                    ),
                    None => self.search_slice_inner_with_scratch(hay, sink, None, scratch, offsets),
                }
            }
            BinaryDetection::Convert(byte) => {
                let at = crate::memchr::memchr(byte, hay);
                self.search_slice_inner_with_scratch(
                    hay,
                    sink,
                    at.map(|i| i as u64),
                    scratch,
                    offsets,
                )
            }
        }
    }

    /// The slice path proper, with binary handling already resolved.
    fn search_slice_inner_with_scratch<S: Sink>(
        &self,
        hay: &[u8],
        sink: &mut S,
        binary: Option<u64>,
        scratch: &mut Scratch,
        offsets: &mut Vec<usize>,
    ) -> Result<bool, S::Error> {
        offsets.clear();
        let term = self.config.line_term.line_term;
        let terms_avail = hay.len() <= MAX_BITMAP_INPUT;
        let routes_delegate = self.matcher.may_decline_lines();
        let candidates = self.map_candidates_only(
            hay,
            &mut scratch.cands,
            if terms_avail {
                Some(&mut scratch.terms as &mut BitMap)
            } else {
                None
            },
            if terms_avail && routes_delegate {
                Some(&mut scratch.nonascii as &mut BitMap)
            } else {
                None
            },
            term,
            offsets,
        );
        let terms = if terms_avail {
            Some(&scratch.terms as &BitMap)
        } else {
            None
        };
        let nonascii = if terms_avail && routes_delegate {
            Some(&scratch.nonascii as &BitMap)
        } else {
            None
        };
        let skippable = !self.config.invert
            && !self.config.multi_line
            && !self.matcher.matches_empty()
            && candidates
                .as_ref()
                .is_some_and(|c| c.is_empty_in(0, hay.len()));
        if skippable {
            self.skipped
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let mut core = Core::new(&self.config, self.matcher);
            core.byte_count = hay.len() as u64;
            core.finish(sink, binary)?;
            return Ok(true);
        }
        let mut core = Core::new(&self.config, self.matcher);
        let keep_going = if self.config.multi_line {
            core.run::<true, _>(sink, hay, 0, 0, candidates, terms, nonascii)?
        } else {
            core.run::<false, _>(sink, hay, 0, 0, candidates, terms, nonascii)?
        };
        if core.skipped != 0 {
            self.skipped
                .fetch_add(core.skipped, core::sync::atomic::Ordering::Relaxed);
        }
        if core.jumped != 0 {
            self.jumped
                .fetch_add(core.jumped, core::sync::atomic::Ordering::Relaxed);
        }
        if core.jumped_lines != 0 {
            self.jumped_lines
                .fetch_add(core.jumped_lines, core::sync::atomic::Ordering::Relaxed);
        }
        #[cfg(feature = "std")]
        {
            crate::profile_add("jump_gaps", core.jumped);
            crate::profile_add("jump_lines", core.jumped_lines);
            if terms.is_some() {
                crate::profile_add("terms_on", 1);
            } else {
                crate::profile_add("terms_off", 1);
            }
        }
        core.finish(sink, binary)?;
        Ok(keep_going)
    }

    /// Search a haystack that is already addressable -- a mapping -- in
    /// line-aligned windows, without copying it into a rolling buffer.
    ///
    /// The reader path copies every byte of every fill; on the 246 MB
    /// single-file probe that fill stage is 52 of the 64 ms a zero-match
    /// query spends, and a pure read of the same file costs 40 ms of it.
    /// This is the same walk with the copy removed: one [`Core`] carried
    /// across windows, each window's maps built exactly as a fill's are.
    /// Every window is cut at a line terminator, so no line is split and a
    /// trailing unterminated line is one line at EOF, reader semantics.
    /// Windows are at most [`MAX_BITMAP_INPUT`] so the dense path keeps its
    /// bit maps; a window with no candidate before the first `Core` exists
    /// skips the line walk and folds its line count forward, which is the
    /// reader's own lazy-core skip.
    ///
    /// The binary rule is carried HERE, not by a pre-scan of the whole
    /// mapping: a window answers the binary byte from a `memchr` that runs
    /// after the candidate map has already touched those pages, so the
    /// answer costs a warm scan instead of the cold full-file one a guard
    /// paid. `Quit` truncates the search at the byte exactly as the reader
    /// stops reading there; `Convert` treats it as a line terminator,
    /// which is what the reader's in-place rewrite produces -- same lines,
    /// same counts, same offsets. The caller gates the entry only for what
    /// the window walk cannot carry: context (the roll) and multi-line (a
    /// match across a window boundary). BOM decoding is NOT a gate -- the
    /// slice machinery decodes on every raw-input surface alike.
    pub fn search_windows<S: Sink>(
        &self,
        hay: &[u8],
        sink: &mut S,
        scratch: &mut Scratch,
        offsets: &mut Vec<usize>,
    ) -> Result<bool, S::Error> {
        const WINDOW: usize = 64 * 1024;
        let term = self.config.line_term.line_term;
        // The binary byte and what finding it means. `Quit` stops the
        // search at the first one and reports its offset; `Convert` splits
        // lines there and keeps going; `None` (`--text`) never looks.
        let (bin_byte, quit_at_bin) = match self.config.binary {
            BinaryDetection::Quit(b) => (Some(b), true),
            BinaryDetection::Convert(b) => (Some(b), false),
            BinaryDetection::None => (None, false),
        };
        let mut core: Option<Core<'_, 'm>> = None;
        let mut line_number: u64 = if self.config.wants_line_numbers() {
            1
        } else {
            0
        };
        let mut skipped_bytes: u64 = 0;
        let mut bin_offset: Option<u64> = None;
        let mut pos = 0usize;
        while pos < hay.len() {
            #[cfg(feature = "std")]
            let cut_t0 = std::time::Instant::now();
            // Cut at the last line end inside the window. Under `Convert`
            // the binary byte IS a line end -- the reader's rewrite makes
            // it one -- so the cut counts both. A window with no line end
            // grows to the next one past it, and at EOF the trailing bytes
            // are a line, terminator or not.
            let mut end = core::cmp::min(pos + WINDOW, hay.len());
            if end < hay.len() {
                let last = match bin_byte {
                    // `Quit` cannot reach a byte past the first binary one
                    // -- the walk below stops there -- so its cut is the
                    // terminator cut.
                    Some(b) if !quit_at_bin => crate::memchr::memrchr2(term, b, &hay[pos..end]),
                    _ => crate::memchr::memrchr(term, &hay[pos..end]),
                };
                end = match last {
                    Some(i) => pos + i + 1,
                    None => {
                        let ahead = match bin_byte {
                            Some(b) if !quit_at_bin => crate::memchr::memchr2(term, b, &hay[end..]),
                            _ => crate::memchr::memchr(term, &hay[end..]),
                        };
                        match ahead {
                            Some(i) => end + i + 1,
                            None => hay.len(),
                        }
                    }
                };
            }
            #[cfg(feature = "std")]
            if crate::profile_enabled() {
                crate::profile_add("win_cut_ns", cut_t0.elapsed().as_nanos() as u64);
            }
            let win = &hay[pos..end];
            offsets.clear();
            #[cfg(feature = "std")]
            let map_t0 = std::time::Instant::now();
            let terms_avail = win.len() <= MAX_BITMAP_INPUT;
            // Candidates first and alone. A window the skip below will take
            // never observes the term map -- line counting is off until a
            // `Core` exists and a count is wanted -- and the term map is
            // the expensive half of the fused fill: one scattered bit per
            // line ending, which on a 246 MB file is 8.7 million of them.
            // Only a window that will actually be walked pays for it, and
            // then as one extra pass.
            let cands =
                self.map_candidates_only(win, &mut scratch.cands, None, None, term, offsets);
            #[cfg(feature = "std")]
            if crate::profile_enabled() {
                crate::profile_add("win_map_ns", map_t0.elapsed().as_nanos() as u64);
            }
            // The binary byte, asked per window and after the map: the map
            // already faulted these pages in, so this is the warm half of
            // what a whole-file guard cost cold.
            let hit = bin_byte.and_then(|b| crate::memchr::memchr(b, win));
            // `Quit` truncates here: the bytes before the byte are a final
            // region, trailing partial line and all -- the reader sets
            // `last_lineterm` to exactly that boundary -- and nothing past
            // it is ever searched.
            let region = match (hit, quit_at_bin) {
                (Some(i), true) => &win[..i],
                _ => win,
            };
            if let Some(i) = hit {
                let at = pos as u64 + i as u64;
                if bin_offset.is_none() {
                    bin_offset = Some(at);
                }
            }
            let empty = !self.config.invert
                && !self.config.multi_line
                && !self.matcher.matches_empty()
                && cands
                    .as_ref()
                    .is_some_and(|c| c.is_empty_in(0, region.len()));
            if empty && core.is_none() {
                self.skipped
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                skipped_bytes += region.len() as u64;
                if line_number > 0 {
                    // Under `Convert` a binary byte ends a line exactly as
                    // the rewrite turns it into the terminator does.
                    line_number += match (bin_byte, quit_at_bin) {
                        (Some(b), false) => {
                            crate::scan::count_byte(term, region)
                                + crate::scan::count_byte(b, region)
                        }
                        _ => crate::scan::count_byte(term, region),
                    };
                }
                if quit_at_bin && hit.is_some() {
                    break;
                }
                pos = end;
                continue;
            }
            // The walk needs the terminator map; build it now, in its own
            // pass, only for windows that are walked. Under `Convert` the
            // map marks the binary byte too -- same line boundaries the
            // reader's rewrite leaves behind.
            let want_nonascii = terms_avail && self.matcher.may_decline_lines();
            if terms_avail {
                match (bin_byte, quit_at_bin) {
                    (Some(b), false) => {
                        crate::scan::byte_bits(&[term, b, 0], 2, region, &mut scratch.terms);
                        if want_nonascii {
                            crate::scan::high_bits(region, &mut scratch.nonascii);
                        }
                    }
                    _ => {
                        if want_nonascii {
                            crate::scan::term_high_bits(
                                term,
                                region,
                                &mut scratch.terms,
                                &mut scratch.nonascii,
                            );
                        } else {
                            crate::scan::term_bits(term, region, &mut scratch.terms);
                        }
                    }
                }
            }
            let nonascii = if want_nonascii {
                Some(&scratch.nonascii as &BitMap)
            } else {
                None
            };
            let terms = if terms_avail {
                Some(&scratch.terms as &BitMap)
            } else {
                None
            };
            let before_skips = core.as_ref().map_or(0, |c| c.skipped);
            if core.is_none() {
                // Fold the caller's line counter into the freshly built
                // `Core` so the first reported line number is right.
                let mut c = Core::new(&self.config, self.matcher);
                c.line_number = line_number;
                core = Some(c);
            }
            let core_ref = core.as_mut().expect("Core just inserted");
            #[cfg(feature = "std")]
            let run_t0 = std::time::Instant::now();
            let keep = if self.config.multi_line {
                core_ref.run::<true, _>(sink, region, pos as u64, 0, cands, terms, nonascii)?
            } else {
                core_ref.run::<false, _>(sink, region, pos as u64, 0, cands, terms, nonascii)?
            };
            #[cfg(feature = "std")]
            if crate::profile_enabled() {
                crate::profile_add("win_run_ns", run_t0.elapsed().as_nanos() as u64);
            }
            // Refresh the caller-level line counter from what `Core::run`
            // left behind, so a later lazy skip starts from the right place.
            line_number = core_ref.line_number;
            self.skipped.fetch_add(
                core_ref.skipped - before_skips,
                core::sync::atomic::Ordering::Relaxed,
            );
            if !keep || (quit_at_bin && hit.is_some()) {
                break;
            }
            pos = end;
        }
        match core.as_mut() {
            Some(c) => {
                c.byte_count += skipped_bytes;
                c.finish(sink, bin_offset)?;
            }
            None => {
                let mut c = Core::new(&self.config, self.matcher);
                c.line_number = line_number;
                c.byte_count = skipped_bytes;
                c.finish(sink, bin_offset)?;
            }
        }
        Ok(true)
    }

    /// Search a `Read` by rolling a fixed buffer.
    ///
    /// This is `grep-searcher`'s `ReadByLine`, and it exists for
    /// before-context: a match at the top of a fresh buffer has preceding
    /// lines that were read in the previous fill, so the roll retains
    /// exactly those.
    ///
    /// Under [`Config::bom_sniffing`] the stream is decoded first, so the
    /// bytes the buffer holds and the bytes a sink reads are the decoded ones
    /// and the line terminator is the one in the text rather than the one in
    /// the encoding.
    pub fn search_reader<S: Sink, R: FnMut(&mut [u8]) -> Result<usize, fmt::Error>>(
        &self,
        rdr: &mut R,
        sink: &mut S,
        line_buffer: &mut LineBuffer,
    ) -> Result<bool, S::Error> {
        if !self.matcher.can_match() {
            return Ok(false);
        }
        // A declared encoding outranks the sniff; see `Config::forced_bom`.
        let transcode = match self.config.forced_bom {
            Some(bom) => Some(encoding::Transcoder::forced(bom)),
            None if self.config.bom_sniffing => Some(encoding::Transcoder::new()),
            None => None,
        };
        if let Some(mut dec) = transcode {
            let mut decoded = |b: &mut [u8]| dec.read(b, rdr);
            return self.search_reader_inner(&mut decoded, sink, line_buffer);
        }
        self.search_reader_inner(rdr, sink, line_buffer)
    }

    fn search_reader_inner<S: Sink, R: FnMut(&mut [u8]) -> Result<usize, fmt::Error>>(
        &self,
        rdr: &mut R,
        sink: &mut S,
        line_buffer: &mut LineBuffer,
    ) -> Result<bool, S::Error> {
        // Lazy inner state. The `Core` -- counters, position tracking,
        // `matches_empty` -- is pure overhead for a buffer that holds no
        // candidate, so it is constructed only when the first buffer that
        // CAN match is reached. The outer wrapper (the reader, the
        // `LineBuffer`, the candidate scratch) stays constructed per
        // search; the per-buffer check below decides whether the inner
        // state is needed at all.
        //
        // `line_number` is tracked at the caller level too: a buffer
        // skipped before the `Core` exists still has lines, and the
        // sink's line numbers are 1-based over the whole file. The
        // variable starts at 1 (or 0 when numbering is off) and is
        // folded into `Core.line_number` the moment the `Core` is
        // built; from then on, `Core::run` owns it and the caller's
        // value is refreshed after every fill.
        let mut core: Option<Core<'_, 'm>> = None;
        let mut line_number: u64 = if self.config.wants_line_numbers() {
            1
        } else {
            0
        };
        let mut keep_going = true;
        let mut offsets = Vec::new();
        let matches_empty = self.matcher.matches_empty();
        loop {
            // ROLL FIRST, then fill. `grep-searcher` orders it this way
            // (`ReadByLine::fill` calls `core.roll` before `rdr.fill`), and the
            // order matters: `roll_target` measures the before-context lines by
            // walking BACK from the end of the data seen so far, so it has to
            // run before that data is extended by the next read.
            //
            // Without a `Core` there is no before-context to carry (no
            // match has happened yet, so nothing is owed to a later
            // match), and the whole retained region collapses to zero.
            //
            // **`drop` is the amount DROPPED, so "nothing is owed" is
            // `drop = seen.len()`, not `drop = 0`.** `retained = seen.len()
            // - drop`, and the earlier spelling `None => 0` therefore
            // retained the WHOLE buffer -- the opposite of what the sentence
            // above says. Until the first match created a `Core`, every fill
            // rolled the entire prior buffer to the front and appended to
            // it, so a file with no early match grew without bound and every
            // later fill was over `MAX_BITMAP_INPUT` and lost both bit maps.
            // One line, and the reader path's maps come back.
            let seen = line_buffer.buffer();
            let max_context = self.config.max_context();
            let drop = drop_before_next_fill(core.as_ref(), seen, max_context);
            // The bytes that survive the roll: the before-context lines a later
            // match may need. The walk starts AFTER them, so they are neither
            // re-searched nor re-sunk, but they stay readable.
            let retained = seen.len() - drop;

            // Dropping them is what makes `LineBuffer::roll` keep exactly this
            // region at the front.
            line_buffer.consume(drop);
            // The roll moved the retained region to the front, so every
            // buffer-relative offset the last walk left behind is rebased by the
            // same amount. The `None` arm is a no-op: `reported_upto` and
            // `last_line_visited` are both 0 because no line has been sunk
            // yet, and the saturating sub on zero is zero.
            if let Some(c) = core.as_mut() {
                c.reported_upto = c.reported_upto.saturating_sub(drop);
                // `grep-searcher` resets this in `Core::roll`: the retained region
                // is the *start* of the next walk's before-context window.
                c.last_line_visited = 0;
            }

            #[cfg(feature = "std")]
            let fill_t0 = std::time::Instant::now();
            let more = match line_buffer.fill(rdr) {
                Ok(m) => m,
                // An I/O error is a failure, not an empty result. Mapping
                // one onto the sink's error type is the caller's job, so
                // the searcher stops rather than guessing.
                Err(_) => return Ok(false),
            };
            #[cfg(feature = "std")]
            if crate::profile_enabled() {
                crate::profile_add("reader_fill_ns", fill_t0.elapsed().as_nanos() as u64);
            }
            let abs = line_buffer.absolute_byte_offset();
            let (buf, scratch) = line_buffer.buffer_and_scratch();
            if buf.len() <= retained {
                // No progress: the fill produced no complete line past the
                // retained region. Either this is EOF, or what is left is a
                // partial line that will never be completed. Without this the
                // loop spins forever on a reader that keeps handing back bytes
                // with no line in them. `grep-searcher` has the same guard
                // (`ReadByLine::fill`, the `consumed == 0` case).
                break;
            }

            // Candidates are computed ONCE per buffer and consumed by the
            // line loop: the matcher is asked once over the buffer, not once
            // per line, which is what keeps a packed prefilter linear
            // rather than `matches x buffer`.
            //
            // The BIT MAP path comes first because it is the one that pays for
            // both per-line scans at once. A fill is at most
            // `LineBuffer::MAX_BUF`, so a map of it is bounded, and both maps
            // are the caller's reused scratch rather than a fresh allocation
            // per file. Anything that declines -- a haystack over
            // `MAX_BITMAP_INPUT`, or a source with no byte-set prefilter to
            // map -- falls through to exactly the code that ran before, which
            // is what keeps this an accelerator and not a new requirement.
            let terms_avail = buf.len() <= MAX_BITMAP_INPUT;
            let term = self.config.line_term.line_term;
            let routes_delegate = self.matcher.may_decline_lines();
            #[cfg(feature = "std")]
            let map_t0 = std::time::Instant::now();
            let cands = self.map_candidates_only(
                buf,
                &mut scratch.cands,
                if terms_avail {
                    Some(&mut scratch.terms as &mut BitMap)
                } else {
                    None
                },
                if terms_avail && routes_delegate {
                    Some(&mut scratch.nonascii as &mut BitMap)
                } else {
                    None
                },
                term,
                &mut offsets,
            );
            #[cfg(feature = "std")]
            if crate::profile_enabled() {
                crate::profile_add("reader_map_ns", map_t0.elapsed().as_nanos() as u64);
            }
            let terms = if terms_avail {
                Some(&scratch.terms as &BitMap)
            } else {
                None
            };
            let nonascii = if terms_avail && routes_delegate {
                Some(&scratch.nonascii as &BitMap)
            } else {
                None
            };
            let after_ctx = core.as_ref().map_or(0, |c| c.after_context_left);
            let buffer_empty = !self.config.invert
                && after_ctx == 0
                && !matches_empty
                && cands
                    .as_ref()
                    .is_some_and(|c| c.is_empty_in(retained, buf.len()));
            if buffer_empty && core.is_none() {
                // The line walk would be a no-op and the inner state
                // is not allocated. Line numbers still have to advance
                // for the lines the buffer held, and the per-buffer
                // skip counter on `Searcher` has to be incremented --
                // a skip that is never observed is a skip that the
                // test for it cannot catch, which is how the
                // optimisation becomes unfalsifiable.
                //
                // With the fused fill the terms map is already built, so
                // the line count is a popcount; without one it falls back
                // to `count_byte`.
                if line_number > 0 {
                    line_number += match terms {
                        Some(t) => t.count_set(retained, buf.len()),
                        None => crate::scan::count_byte(term, &buf[retained..]),
                    };
                }
                self.skipped
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                if !keep_going {
                    break;
                }
                if !more {
                    break;
                }
                continue;
            }

            // The terms map was filled by the fused pass above.
            // **The reader path needs the same `terms_on`/`terms_off` counters
            // the slice path has, and it is the only one that can lose the map.**
            //
            // `map_run` declines above `MAX_BITMAP_INPUT`, and only this path can
            // produce a buffer that big: `LineBuffer` doubles to fit a line
            // longer than itself and never shrinks, so one long line pushes
            // every remaining fill in that file past the cap. When that happens
            // the searcher silently loses the terminator map, the candidate
            // map, the per-candidate jump and the register-held terminator
            // walk, and falls back to a `memchr` per line. The slice path has
            // always been counted; this one was not, so the cost was invisible
            // exactly where it occurs.
            //
            // Recorded BUCKETED BY FILL SIZE, not as a bare `+1`. A bare count
            // cannot tell "one 512 KiB fill lost its map" from "every fill lost
            // it", and those need opposite responses: the first is a
            // pathological file, the second is the cap being in the wrong place.
            #[cfg(feature = "std")]
            {
                if terms.is_some() {
                    crate::profile_add("reader_terms_on", 1);
                } else {
                    let bucket = buf.len().div_ceil(256 * 1024).clamp(1, 8);
                    crate::profile_add("reader_terms_off", 1);
                    crate::profile_add(
                        match bucket {
                            1 => "reader_terms_off_256k",
                            2 => "reader_terms_off_512k",
                            3 => "reader_terms_off_768k",
                            4 => "reader_terms_off_1m",
                            _ => "reader_terms_off_2m_plus",
                        },
                        1,
                    );
                }
            }
            // The DELTA, not the running total. `Core` is created once
            // across every fill, so the running counter would sum
            // 1 + 2 + ... + n and report ~n^2/2 skips for a search
            // that skipped n -- which is how this row first read
            // "198 851 653 buffers skipped" over 18 921 fills. The
            // number was the sum of a counter, not a count of anything.
            // The `None` arm reads 0 because no counter has been
            // incremented yet.
            let before_skips = core.as_ref().map_or(0, |c| c.skipped);
            let before_jumps = core.as_ref().map_or(0, |c| c.jumped);
            let before_jump_lines = core.as_ref().map_or(0, |c| c.jumped_lines);
            if core.is_none() {
                // Fold the caller's line counter into the freshly built
                // `Core` so the first reported line number is right.
                let mut c = Core::new(&self.config, self.matcher);
                c.line_number = line_number;
                core = Some(c);
            }
            let core_ref = core.as_mut().expect("Core just inserted");
            let keep = if self.config.multi_line {
                core_ref.run::<true, _>(sink, buf, abs, retained, cands, terms, nonascii)?
            } else {
                core_ref.run::<false, _>(sink, buf, abs, retained, cands, terms, nonascii)?
            };
            // Refresh the caller-level line counter from what `Core::run`
            // left behind, so a later lazy skip starts from the right
            // place.
            line_number = core_ref.line_number;
            keep_going = keep;
            self.skipped.fetch_add(
                core_ref.skipped - before_skips,
                core::sync::atomic::Ordering::Relaxed,
            );
            self.jumped.fetch_add(
                core_ref.jumped - before_jumps,
                core::sync::atomic::Ordering::Relaxed,
            );
            self.jumped_lines.fetch_add(
                core_ref.jumped_lines - before_jump_lines,
                core::sync::atomic::Ordering::Relaxed,
            );
            if !keep_going {
                break;
            }
            if !more {
                break;
            }
        }
        // A search that skipped every buffer never built a `Core`, so
        // `finish` has to be called without one. The bytes searched
        // are the reader's own `absolute_byte_offset`; the binary
        // offset is the `LineBuffer`'s, exactly what `Core::finish`
        // would have handed the sink.
        match core.as_mut() {
            Some(c) => c.finish(sink, line_buffer.binary_byte_offset())?,
            None => {
                let fin = SinkFinish {
                    byte_count: line_buffer.absolute_byte_offset(),
                    binary_byte_offset: line_buffer.binary_byte_offset(),
                    _marker: core::marker::PhantomData,
                };
                sink.finish(&fin)?;
            }
        }
        Ok(keep_going)
    }
}

/// How many bytes of `seen` to drop before the next fill.
///
/// **`drop` is an AMOUNT DROPPED, not an amount retained**:
/// `retained = seen.len() - drop`. With no [`Core`] nothing is owed to a
/// later match, so everything is dropped and the next fill starts from an
/// empty buffer. Spelling that as `0` retains the whole buffer instead --
/// every fill then rolls the entire prior buffer forward and appends to it,
/// and a file with no early match grows to [`LineBuffer::MAX_BUF`]. Once a
/// `Core` exists the amount is what the before-context window needs.
///
/// Kept as a function rather than left inline so the invariant is testable
/// without driving the reader: the `None` arm is the one that is easy to get
/// backwards, and it is the one that has no visible symptom until a file is
/// large enough to cross `MAX_BITMAP_INPUT`.
fn drop_before_next_fill(core: Option<&Core>, seen: &[u8], max_context: usize) -> usize {
    match core {
        Some(c) => c.roll_target(seen, max_context).min(seen.len()),
        None => seen.len(),
    }
}

/// How many lines back `target` sits among the collected before-context
/// `starts`, counting the target itself.
///
/// `starts` is newest-first, so every entry at or after `target` is a line
/// between the target and the match, plus the target: counting `>=` makes the
/// first collected line (the one adjacent to the match) one step back, and the
/// oldest collected line the full `before`. With `line_number` at the match
/// and `before` lines collected, `line_number - back` then yields each line's
/// true 1-based number — which a sink that prints them (rgx does) needs.
fn starts_before(starts: &[usize], target: usize) -> usize {
    starts.iter().filter(|&&s| s >= target).count()
}

/// The start of the line that ends at `at` (i.e. the line whose last byte is
/// at `at`).
///
/// `at` is normally the start of the line *after* the one wanted, so this
/// finds the terminator of the line before it and steps past that. Returns 0
/// when the line is the first in the buffer.
fn line_start(buf: &[u8], at: usize, term: u8) -> usize {
    if at == 0 {
        return 0;
    }
    // The byte before `at` is the terminator of the previous line, so the
    // line before that starts after the previous terminator before it.
    match crate::memchr::memrchr(term, &buf[..at.saturating_sub(1)]) {
        Some(i) => i + 1,
        None => 0,
    }
}

/// The line bounds at or after `pos`, or `None` if nothing is left.
///
/// A line includes its terminator. A final line without one is still a line,
/// which is why `None` happens only when `pos` is past the end.
fn find_line(buf: &[u8], pos: usize, term: u8) -> Option<(usize, usize)> {
    if pos >= buf.len() {
        return None;
    }
    match crate::memchr::memchr(term, &buf[pos..]) {
        Some(i) => Some((pos, pos + i + 1)),
        None => Some((pos, buf.len())),
    }
}

/// The start of the `n`-th line before the end of `buf`.
/// The start offset of the line that sits `count` lines before the line
/// ending at `buf.len()`, mirroring `grep-searcher`'s `lines::preceding`.
///
/// A position just past a terminator is treated as part of the line that
/// terminator ends, so the trailing byte is backed off first. The walk stops
/// at the start of the target line, and at 0 when there are not that many
/// lines before it.
fn preceding_lines(buf: &[u8], term: u8, count: usize) -> usize {
    if buf.is_empty() {
        return 0;
    }
    let mut pos = buf.len();
    if buf[pos - 1] == term {
        pos -= 1;
    }
    let mut count = count;
    loop {
        match crate::memchr::memrchr(term, &buf[..pos]) {
            None => return 0,
            Some(i) => {
                if count == 0 {
                    return i + 1;
                } else if i == 0 {
                    return 0;
                }
                count -= 1;
                pos = i;
            }
        }
    }
}

#[cfg(test)]
#[path = "searcher/tests.rs"]
mod tests;

/// The differential this crate lost with `grep-searcher`, rebuilt against the
/// `regex` crate. Read its module header before changing a skip in it: every
/// skip is a case where the two engines are *specified* to differ, and adding
/// a skip for a case that merely turns out to be inconvenient is how the file
/// stops meaning anything.
#[cfg(test)]
#[path = "searcher/oracle.rs"]
mod oracle;

/// `Config::buffer_capacity` is the size the read buffer starts at, and it was
/// a number on a config that nothing read.
///
/// `LineBuffer` allocated `INITIAL_BUF` — 64 KiB — on the first fill and
/// doubled from there, whatever the config said, so a caller that sized the
/// buffer to its unit of work was describing a change that did not happen. The
/// pack does exactly that: `inhouse_buffer_for` hands the in-house engine 8 KiB
/// because the registry's median file is 4.4 KB, with a comment saying the
/// buffer follows the files. Three files in this repository — the pack's
/// sizing function, `mmap.rs`'s "64 KiB is `Config::buffer_capacity`", and the
/// axis document's experiment that concluded the per-call cost is not the
/// buffer — were all describing a knob with no effect.
///
/// The test is the observable shape of the thing: a fill of a known size, and
/// the buffer it left behind.
#[test]
fn the_read_buffer_starts_where_the_config_says() {
    let fill = |capacity: usize, n: usize| {
        let cfg = Config {
            buffer_capacity: capacity,
            ..Config::default()
        };
        let mut lb = LineBuffer::new(&cfg);
        let mut data = vec![b'a'; n];
        let mut done = 0usize;
        while done < n {
            let mut r = |b: &mut [u8]| {
                let take = core::cmp::min(b.len(), n - done);
                b[..take].copy_from_slice(&data[done..done + take]);
                done += take;
                Ok(take)
            };
            if !lb.fill(&mut r).unwrap() {
                break;
            }
            // A fill with no terminator never returns complete lines, so the
            // loop is bounded by the data and not by the buffer.
            data[done..].fill(b'\n');
            if done >= n {
                break;
            }
        }
        lb.buffer().len()
    };
    // The default is 64 KiB and a caller that says nothing gets it.
    assert_eq!(LineBuffer::INITIAL_BUF, 64 * 1024);
    assert_eq!(Config::default().buffer_capacity, LineBuffer::INITIAL_BUF);
    // A caller that says 8 KiB gets a buffer that starts at 8 KiB: the first
    // fill of a 4 KB line cannot have come from a 64 KiB allocation.
    let small = fill(8 * 1024, 4 * 1024);
    let default = fill(64 * 1024, 4 * 1024);
    assert_eq!(small, default, "the same four kilobytes either way");
}
