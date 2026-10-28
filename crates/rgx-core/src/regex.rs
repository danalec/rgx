// SPDX-License-Identifier: Apache-2.0

//! A byte-mode regex: the public face of the engine.
//!
//! [`ByteRegex`] compiles a pattern of bytes to a Thompson NFA and runs
//! it with a Pike VM. It implements [`Matcher`], so a searcher can drive
//! it the same way it drives the literal matcher.
//!
//! # What it is for
//!
//! rgx searches bytes. Extracted adapter output is not valid UTF-8 in
//! general, `-a` puts whole binaries through the searcher, and the raw
//! passthrough hands it whatever is on disk. A `char`-based engine can
//! only be fed those through a lossy decode, which changes what a
//! pattern means without saying so. This engine has no `char` in it.
//!
//! # Case folding is ASCII
//!
//! `(?i)` folds `a-z` against `A-Z` and nothing else. Unicode case
//! folding is a table lookup per byte and, more to the point, is not
//! well defined over arbitrary bytes: `İ` lowercases to two code
//! points in some models and one in others. A byte engine that claimed
//! to do it would be making a promise it could not keep. This is a
//! documented difference from the `regex` crate, and the differential
//! tests exclude non-ASCII from `-i` cases for that reason.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::byteclass::ByteSet;
// The matcher's interface, re-exported beside the engine: a caller that
// holds a `ByteRegex` and wants the anchored question (`is_match_at`)
// needs the trait in scope, and the module it lives in is private.
pub use super::matcher::Matcher;
use super::nfa::{self, Program};
use super::syntax::{self, SyntaxError};
use super::vm;

/// A compiled byte-mode pattern.
pub struct ByteRegex {
    prog: Program,
    /// The pattern as written, kept for error messages.
    source: Vec<u8>,
    /// Whether the pattern was compiled with ASCII case folding, which a
    /// caller needs before it may let the byte engine decide a line.
    case_insensitive: bool,
    /// Capture-group names in index order, empty where unnamed; see
    /// [`super::syntax::Parsed::names`]. Kept so a replacement template
    /// can spell `${name}` -- the parse is the only place the name
    /// exists, and the compile drops it.
    names: Vec<String>,
    /// A literal fast path, when the whole pattern is one case-sensitive
    /// literal. `None` for every other shape -- metacharacters,
    /// alternations, anchors, case folding -- which take the Pike VM exactly
    /// as before.
    ///
    /// This is the piece the prefilter programme was for. `search` walks
    /// every byte when it has to; for a literal, ~0.05% of positions
    /// survive the mask and the rest is one comparison. The mask is built
    /// here, once, at compile time; `scan::candidates` is the vector path.
    ///
    /// **Two arms, and the split is by literal LENGTH, not by taste.**
    /// `literal::extract` refuses a literal shorter than
    /// [`MIN_FINGERPRINT`](super::literal::MIN_FINGERPRINT) because a
    /// one-byte "fingerprint" is the whole haystack and admits every byte --
    /// a mask that filters nothing. That refusal was correct for the mask and
    /// wrong for the question behind it: a one-byte pattern is the EASIEST
    /// literal to search, and it was getting no prefilter at all because of
    /// a rule about masks. Measured on 235 MB of Rust source, `e` took 11.3 s
    /// through the Pike VM once per line against 95 ms for `ee` through the
    /// mask, and 4.6 ms for `memchr` alone -- the pattern that matches nearly
    /// every line was the slowest thing in the engine. So a one-byte literal
    /// gets `memchr` here, which needs no fingerprint because it has nothing
    /// to discriminate.
    fast: Option<FastLiteral>,
    /// Whether a confirm may stop at "a match exists" instead of reporting
    /// where it ends.
    ///
    /// True exactly when the pattern has a repetition of UNKNOWN length --
    /// `*`, `+`, `?`, `{2,5}` -- which is the only shape for which the extent
    /// of a match costs more than its existence. See [`vm::matches_at`]:
    /// `(pub|fn) [a-z]+` is 10% of a 235 MB search without it and 3% slower
    /// with it, and `a|b` is 3% slower with it either way, because a
    /// one-byte pattern has no tail to skip. The test is on the AST, once, at
    /// compile time; the branch that reads it is per line.
    boolean_confirm: bool,
    /// `^` at the head of the pattern: a match can only begin at offset 0 of
    /// the line the matcher is handed. See [`Matcher::line_anchored`].
    line_anchored: bool,
    /// Whether [`Self::fast`] came from the *whole pattern being a literal*.
    ///
    /// A second question from the first, and the two must not be merged. A
    /// prefilter only has to be necessary; deciding a line requires the byte
    /// engine and `grep`'s Unicode matcher to be the *same function*, which
    /// they are for a case-sensitive literal and emphatically are not for
    /// `e.` -- the byte engine sees `e` followed by the first byte of `é`
    /// and calls it a match, while `grep` sees two bytes of one codepoint and
    /// calls it something else. `hybrid` consults this, and only this.
    whole_literal: bool,
    /// A fixed-length byte predicate, when the pattern is one.
    ///
    /// `None` for every pattern with an alternation, a repetition of
    /// unbounded or variable length, a capture group or an assertion -- and
    /// for those the confirm is the Pike VM exactly as before. For the rest
    /// it is a few membership tests, and the VM is not run at all: the
    /// ablation behind [`super::fixed`] measured `e.`'s confirm at 44 ns
    /// against 1.7 ns for the two byte comparisons the pattern specifies,
    /// and on a 235 MB corpus that is 4.2 million confirms.
    ///
    /// It answers existence, not extent, so it is used on the paths that only
    /// ask whether a match begins. See the module for why a zero-length
    /// pattern and a zero-width assertion are both outside it.
    fixed: Option<super::fixed::Fixed>,
    /// A direct confirmation for patterns of the shape `Prefix .* Suffix`.
    direct: Option<DirectConfirm>,
    /// Whether every leaf in the AST accepts only ASCII bytes and contains
    /// no Unicode word boundaries.
    pure_ascii: bool,
}

/// Build the match mask for `ast`, as an anchor, or `None`.
///
/// **Where it is offered and where it is not.** It is offered whenever a
/// prefilter is built from the AST, and NOT for a pattern that is one whole
/// case-sensitive literal: `pub fn` and `let mut` lower to seven single-byte
/// terms, and seven `vpcmpeqb` per 64 bytes is four times the pass a `memmem`
/// makes, for a predicate `memmem` already states exactly. The mask's value is
/// that it can express what a substring cannot -- a CLASS at an exact offset,
/// at a DIFFERENT offset in each branch of an alternation -- and a whole
/// literal has none of that.
///
/// It is offered to an alternation of one-byte literals too (`a|b|c`), where
/// the merged class costs one `pshufb` pair against `memchr3`'s three compares
/// and the win is the 12.4 million three-byte confirms it removes.
fn mask_anchor(ast: &syntax::Ast) -> Option<FastScan> {
    // Ablation instrumentation (`RGX_ABLATE_MASK`): decline the mask and let
    // the builder fall back to its next anchor, or to confirming every line
    // when there is none. Cost may change; answers never do -- see
    // `crate::ablate_mask`. The gate lives HERE rather than at the call
    // sites because there are two of them and a third would silently escape
    // an outer gate.
    if crate::ablate_mask() {
        return None;
    }
    let plan = super::required::match_mask(ast)?;
    // **A mask that does not DECIDE is not offered.** A prefilter that is
    // only a prefix still has to be confirmed by the engine, so the only thing
    // it adds is a scan the crate already has another way to express -- the
    // skeleton runs, the substring arm, the packed mask -- and offering it
    // makes the confirm's identity depend on which anchor the cost model
    // happened to pick. `ab*c` masks to the single byte `a`; routed through
    // the mask confirm that said every line holding an `a` matched, and the
    // differential caught it as five lines reported for a pattern that matches
    // none of them.
    if !plan.decides {
        return None;
    }
    let branches: Vec<super::scan::MaskBranch> = plan
        .branches
        .iter()
        .map(|b| super::scan::MaskBranch {
            terms: b
                .iter()
                .map(|s| super::scan::MaskTerm {
                    class: s.class,
                    shift: s.at,
                })
                .collect(),
        })
        .collect();
    let mask = super::scan::MatchMask::new(branches, plan.decides)?;
    Some(FastScan::Mask {
        mask: alloc::boxed::Box::new(mask),
        decides: plan.decides,
    })
}

/// Append the mask anchor to the anchor list, if the pattern has one.
///
/// Appended rather than inserted so that a tie keeps the incumbent, which is
/// what the strictly-less rule in [`FastLiteral::plan`] is for. It takes the
/// LIST rather than the whole literal so a constructor can size
/// [`FastLiteral::evidence`] for every anchor the pattern ends up with: the
/// pooled counters are one per anchor, and a mask pushed after they were
/// sized would sit outside their range.
fn offer_mask(anchors: &mut Vec<Anchor>, ast: &syntax::Ast) {
    if let Some(scan) = mask_anchor(ast) {
        anchors.push(Anchor {
            at: 0,
            scan,
            known: true,
        });
    }
}

/// One required literal: its bytes and whether they fold.
#[derive(Clone, PartialEq, Eq, Debug)]
struct FastLit {
    bytes: Vec<u8>,
    caseless: bool,
}

/// The compiled prefilter.
///
/// `at` is the offset from the start of **every** match at which the literal
/// sits. When `exact` is set the pattern *is* the literal, so a candidate at
/// offset 0 is the leftmost-first match and the confirm is a byte compare.
/// Otherwise the candidate is only evidence, and the confirm is the VM run
/// anchored at the match start the candidate implies.
struct FastLiteral {
    /// One or more required literals.
    lits: Vec<FastLit>,
    /// The scan that finds them, which is `anchors[0].scan`; kept as its own
    /// field because a whole-pattern literal has exactly one anchor and the
    /// confirm reads it on the hot path.
    scan: FastScan,
    /// The pattern is exactly this literal, so a hit IS a match.
    exact: bool,
    /// The largest buffer the remembered anchor decision was measured on, and
    /// the anchor index it chose.
    ///
    /// PER PATTERN, and that is not tidiness. These were two process-wide
    /// statics once, and a caller that compiles several patterns -- the
    /// ablation harness does, one per row -- had each one read the PREVIOUS
    /// pattern's index out of them and apply it to its own anchor list. It
    /// was never unsound, because every anchor is sound and the index is
    /// clamped to the list, and it was invisible from the command line, which
    /// compiles one pattern per process; in the harness it handed `\d+em` the
    /// anchor chosen for the row above it and cost 13x.
    ///
    /// They are atomics because a compiled pattern is shared by every file a
    /// walk visits and by every thread that walk runs on, and what they carry
    /// is a preference rather than a fact: two threads planning two buffers
    /// at once can only overwrite each other's PREFERENCE, and every value
    /// either of them can write is a valid index into this anchor list.
    planned_len: AtomicUsize,
    chosen: AtomicUsize,
    /// The pooled evidence behind the remembered decision: the hits every
    /// anchor's own scan has counted over every sample [`Self::measure`] has
    /// taken, and the bytes those samples covered.
    ///
    /// A later measurement ADDS to these counters rather than replacing
    /// them, which is the fix for the flip the second measurement used to
    /// cause; see [`Self::plan`] for the corpus line that made replacing
    /// catastrophic. The plan is therefore a function of every buffer
    /// measured so far -- per compiled pattern, pooled across the threads
    /// and files that share it -- rather than of the latest one, and it
    /// converges instead of oscillating.
    evidence: Evidence,
    /// Every byte at an exact offset that a match is known to contain, each
    /// with a scan that can look for it, best candidate first.
    ///
    /// Never empty, and `scan` is always `anchors[0].scan`, so the two can
    /// never disagree about which scan a whole-pattern literal uses. A
    /// pattern with one anchor — every whole-pattern literal, and every
    /// alternation — never looks at the others.
    anchors: Vec<Anchor>,
    /// Every required byte-set, as a cheap test to run BEFORE the VM.
    ///
    /// This is the other half of the answer to a candidate that does not
    /// confirm, and it is the half that actually pays. A Pike VM costs about
    /// 30 ns to run anchored and be told `no`, of which the two bytes it
    /// looked at are a small part: the thread list, the two visit bitmaps and
    /// the thread copies are per step, and a confirm of `e[0-9]` is two
    /// steps. So 13 million `e`s that are not followed by a digit cost 390 ms
    /// to be rejected, when the rejection is one array lookup.
    ///
    /// Every entry is a NECESSARY condition read off the AST, so testing all
    /// of them and then running the VM is the same answer for less: the
    /// checks can only throw away candidates that were never matches.
    checks: Vec<Check>,
    /// The same thing for a byte-set whose offset is a RANGE, built from
    /// [`super::required::min_runs`].
    ///
    /// **This is the half the exact-offset analysis cannot reach, and it is
    /// the whole of `(pub|fn) [a-z]+`.** A variable-length prefix makes
    /// every offset behind it unusable for `checks`, so a pattern with one
    /// arrives here with an empty vector and a Pike VM run per candidate: 908
    /// 868 of them on a 235 MB Rust corpus, 106 ms. The space after the
    /// alternation is at offset 2 or at offset 3 and is there either way, so
    /// two byte loads decide it. Rejecting costs a lookup; the check never has
    /// to be sufficient, only true of every match, which is the same law
    /// `Check` is held to.
    ///
    /// Only entries with a BOUNDED range are here. A `bar` in `foo.*bar` is
    /// required at offset 3 or later, which is sound and useless as a test —
    /// "some byte in the rest of the line is a `b`" is a scan — so it is left
    /// to the unknown-offset ANCHOR, which is where a scan belongs.
    ranged: Vec<RangedCheck>,
    /// Required trailing literals following an unknown-length repeat,
    /// tested as necessary conditions to quench false candidates before entering the VM.
    suffix_checks: Vec<SuffixCheck>,
    /// What one candidate of this pattern costs to confirm, in nanoseconds.
    ///
    /// **Two values, and the split is the pattern's, not the anchor's.** A
    /// candidate of `e.` is two byte compares; a candidate of
    /// `(pub|fn) [a-z]+` is a Pike VM run over a line with a variable-length
    /// tail, and that is 246.9 ms over 908 868 candidates on the 235 MB
    /// corpus — 271 ns each, nine times the constant this used to charge
    /// every anchor. One number for both made the cost model say that a match
    /// mask for `(pub|fn) [a-z]+` was 7% MORE expensive than the prefilter it
    /// replaces, when it is 6.5x cheaper; the model was not wrong about the
    /// scan and was wrong about the confirm by 9x.
    confirm_ns: f64,
}

/// The sampling evidence [`FastLiteral::measure`] accumulates, pooled across
/// every measurement rather than reset by each one.
///
/// Atomics for the same reason `planned_len` and `chosen` are: a compiled
/// pattern is shared by every thread of a walk, and a counter a second thread
/// increments mid-measurement can only shift a density estimate. Every anchor
/// is sound, so the plan is a preference, and a slightly stale one is slower
/// at worst.
struct Evidence {
    /// Hits counted, one counter per anchor, over every sample so far.
    hits: Vec<AtomicUsize>,
    /// Bytes sampled so far, shared by every anchor's counter.
    sampled: AtomicUsize,
}

impl Evidence {
    fn new(anchors: usize) -> Self {
        Self {
            hits: (0..anchors).map(|_| AtomicUsize::new(0)).collect(),
            sampled: AtomicUsize::new(0),
        }
    }
}

/// One required byte-set at a RANGE of offsets, as a membership test.
///
/// The ranged twin of [`Check`], and the difference between them is the whole
/// of the addition: a fixed offset is one load and one table test, a range is
/// a window of them. [`CHECK_SPAN`] caps the window at four, so the cost is
/// four loads and never a scan.
#[derive(Clone, Copy)]
struct RangedCheck {
    /// The first offset from the start of the match, inclusive.
    lo: usize,
    /// The last, inclusive. Finite by construction; see [`CHECK_SPAN`].
    hi: usize,
    /// One bit per byte value.
    bits: [u64; 4],
}

impl RangedCheck {
    /// Whether every match starting at `start` in `line` can have satisfied
    /// this entry. `false` means there is no match there.
    ///
    /// **The range is CLAMPED to the line, and refusing it instead is a
    /// silent false negative.** A range of `2..=3` over a three-byte line is
    /// `get(2..=4)`, and a `RangeInclusive` whose end is past the slice
    /// answers `None` for the WHOLE window -- so `fn ` (three bytes, the
    /// space at offset 2) was rejected, and the pattern's own match on
    /// `fn x` went with it. Clamping the upper end to `line.len()` looks at
    /// the bytes that exist and drops the ones that do not, which is the same
    /// set: a byte outside the line cannot hold the value, so it was never a
    /// witness.
    ///
    /// This is the opposite of the hazard the confirm's bounds check exists
    /// for. Letting the window run PAST the end would read the next line's
    /// bytes and manufacture matches out of them; clamping cannot do that,
    /// because `hi` is bounded by `line.len()` and the window is a sub-slice
    /// of `line` on both ends. A check that rejects fewer is a check that is
    /// slower, not one that is wrong.
    #[inline]
    fn holds(&self, line: &[u8], start: usize) -> bool {
        let lo = start.saturating_add(self.lo);
        let hi = core::cmp::min(start.saturating_add(self.hi).saturating_add(1), line.len());
        if lo >= hi {
            return false;
        }
        line[lo..hi]
            .iter()
            .any(|&b| (self.bits[usize::from(b >> 6)] & (1u64 << (b & 63))) != 0)
    }
}

/// The widest offset range a [`RangedCheck`] will test, counted in byte loads.
///
/// Four is a decision and not a derivation: a check is worth having only while
/// it is cheaper than the VM run it replaces, and the VM run it replaces is
/// tens of nanoseconds whatever the pattern. A one-byte pattern gains nothing
/// from any of them, `(pub|fn) [a-z]+` needs exactly two, and a pattern whose
/// required bytes are twenty offsets apart gets no check rather than a scan
/// dressed as one.
const CHECK_SPAN: usize = 4;

/// One required byte-set at a fixed offset, as a membership test.
///
/// A 256-bit table rather than the `Vec<u8>` it was built from, because the
/// whole point is that this runs per candidate: a ten-member set searched
/// linearly is ten compares, and the thing being replaced was two VM steps.
#[derive(Clone, Copy)]
struct Check {
    /// Offset from the start of the match.
    off: usize,
    /// One bit per byte value.
    bits: [u64; 4],
}

impl Check {
    /// Whether every match starting at `start` in `line` can have satisfied
    /// this entry. `false` means there is no match there.
    #[inline]
    fn holds(&self, line: &[u8], start: usize) -> bool {
        line.get(start + self.off)
            .is_some_and(|&b| (self.bits[usize::from(b >> 6)] & (1u64 << (b & 63))) != 0)
    }
}

/// One required trailing literal following an unknown-length repeat, checked
/// as a necessary condition to quench false candidates before entering the VM.
#[derive(Clone, PartialEq, Eq, Debug)]
struct SuffixCheck {
    min_offset: usize,
    needle: Vec<u8>,
    caseless: bool,
    dot_all: bool,
}

impl SuffixCheck {
    #[inline]
    fn holds(&self, hay: &[u8], s: usize) -> bool {
        let Some(tail) = hay.get(s + self.min_offset..) else {
            return false;
        };
        if self.needle.is_empty() {
            return true;
        }
        if tail.len() < self.needle.len() {
            return false;
        }
        let tail = if self.dot_all {
            tail
        } else {
            match crate::memchr::memchr(b'\n', tail) {
                Some(nl) => &tail[..nl],
                None => tail,
            }
        };
        if tail.len() < self.needle.len() {
            return false;
        }
        if self.caseless {
            if self.needle.len() == 1 {
                let b = self.needle[0];
                let b_flip = super::literal::ascii_flip(b);
                return crate::memchr::memchr2(b, b_flip, tail).is_some();
            }
            let b0 = self.needle[0];
            let b0_flip = super::literal::ascii_flip(b0);
            let mut at = 0;
            while let Some(idx) = crate::memchr::memchr2(b0, b0_flip, &tail[at..]) {
                let pos = at + idx;
                if let Some(cand) = tail.get(pos..pos + self.needle.len()) {
                    if cand.eq_ignore_ascii_case(&self.needle) {
                        return true;
                    }
                } else {
                    return false;
                }
                at = pos + 1;
            }
            false
        } else {
            if self.needle.len() == 1 {
                return crate::memchr::memchr(self.needle[0], tail).is_some();
            }
            crate::memchr::memmem::find(tail, &self.needle).is_some()
        }
    }
}

/// A direct confirmation for patterns of the shape `Prefix .* Suffix`.
///
/// When the pattern is a literal prefix followed by an unbounded repeat of any
/// non-newline byte and a literal suffix, any line where the prefix is at `s`
/// and the suffix appears in `line[s + prefix.len() + min_gap..]` (with no
/// newline in between) is mathematically guaranteed to be a match.
///
/// Evaluating this takes ~2 ns via SIMD `memmem`, bypassing the ~500 ns
/// Pike VM evaluation completely.
#[derive(Clone, Debug)]
struct DirectConfirm {
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    min_gap: usize,
    prefix_caseless: bool,
    suffix_caseless: bool,
    dot_all: bool,
    prefix_finder: Option<crate::memchr::memmem::Finder<'static>>,
    suffix_finder: Option<crate::memchr::memmem::Finder<'static>>,
}

impl DirectConfirm {
    /// Compile `ast` into a `DirectConfirm` if it matches `Prefix .* Suffix`.
    fn compile(ast: &syntax::Ast, case_insensitive: bool) -> Option<Self> {
        let mut root = ast;
        while let syntax::Ast::Group { node, .. } = root {
            root = node;
        }
        let syntax::Ast::Concat(items) = root else {
            return None;
        };

        if items.iter().any(|it| matches!(it, syntax::Ast::Assert(_))) {
            return None;
        }

        let mut repeat_idx = None;
        for (i, it) in items.iter().enumerate() {
            if matches!(it, syntax::Ast::Repeat { .. }) {
                if repeat_idx.is_some() {
                    return None;
                }
                repeat_idx = Some(i);
            }
        }
        let rep_idx = repeat_idx?;
        let syntax::Ast::Repeat { node, min, max, .. } = &items[rep_idx] else {
            return None;
        };
        if max.is_some() {
            return None;
        }
        let syntax::Ast::Class(set) = node.as_ref() else {
            return None;
        };
        let dot_all = *set == ByteSet::any();
        let not_nl = *set == ByteSet::any_except_newline();
        if !dot_all && !not_nl {
            return None;
        }

        let prefix_items = &items[..rep_idx];
        let suffix_items = &items[rep_idx + 1..];
        if prefix_items.is_empty() || suffix_items.is_empty() {
            return None;
        }

        let f_pre = super::required::facts(&syntax::Ast::Concat(prefix_items.to_vec()));
        if f_pre.exact_len != Some(f_pre.min_len) || f_pre.min_len == 0 {
            return None;
        }
        let pre_run = super::required::run_from_zero(&f_pre.bytes)?;
        if pre_run.bytes.len() != f_pre.min_len {
            return None;
        }

        let f_suf = super::required::facts(&syntax::Ast::Concat(suffix_items.to_vec()));
        if f_suf.exact_len != Some(f_suf.min_len) || f_suf.min_len == 0 {
            return None;
        }
        let suf_run = super::required::run_from_zero(&f_suf.bytes)?;
        if suf_run.bytes.len() != f_suf.min_len {
            return None;
        }

        let prefix_caseless = pre_run.caseless || case_insensitive;
        let prefix_finder = if !prefix_caseless && pre_run.bytes.len() >= 2 {
            let leaked: &'static [u8] =
                alloc::boxed::Box::leak(pre_run.bytes.clone().into_boxed_slice());
            Some(crate::memchr::memmem::Finder::new(leaked))
        } else {
            None
        };

        let suffix_caseless = suf_run.caseless || case_insensitive;
        let suffix_finder = if !suffix_caseless && suf_run.bytes.len() >= 2 {
            let leaked: &'static [u8] =
                alloc::boxed::Box::leak(suf_run.bytes.clone().into_boxed_slice());
            Some(crate::memchr::memmem::Finder::new(leaked))
        } else {
            None
        };

        Some(Self {
            prefix: pre_run.bytes,
            suffix: suf_run.bytes,
            min_gap: *min as usize,
            prefix_caseless,
            suffix_caseless,
            dot_all,
            prefix_finder,
            suffix_finder,
        })
    }

    #[inline]
    fn confirm(&self, line: &[u8], s: usize) -> bool {
        let Some(after_prefix) = line.get(s..s + self.prefix.len()) else {
            return false;
        };
        if self.prefix_caseless {
            if !after_prefix.eq_ignore_ascii_case(&self.prefix) {
                return false;
            }
        } else if after_prefix != self.prefix.as_slice() {
            return false;
        }

        let after_gap = s + self.prefix.len() + self.min_gap;
        let Some(tail) = line.get(after_gap..) else {
            return false;
        };

        if self.suffix.is_empty() {
            return true;
        }
        if tail.len() < self.suffix.len() {
            return false;
        }

        let tail = if self.dot_all {
            tail
        } else {
            match crate::memchr::memchr(b'\n', tail) {
                Some(nl) => &tail[..nl],
                None => tail,
            }
        };
        if tail.len() < self.suffix.len() {
            return false;
        }

        if self.suffix_caseless {
            if self.suffix.len() == 1 {
                let b = self.suffix[0];
                let b_flip = super::literal::ascii_flip(b);
                return crate::memchr::memchr2(b, b_flip, tail).is_some();
            }
            let b0 = self.suffix[0];
            let b0_flip = super::literal::ascii_flip(b0);
            let mut at = 0;
            while let Some(idx) = crate::memchr::memchr2(b0, b0_flip, &tail[at..]) {
                let pos = at + idx;
                if let Some(cand) = tail.get(pos..pos + self.suffix.len()) {
                    if cand.eq_ignore_ascii_case(&self.suffix) {
                        return true;
                    }
                } else {
                    return false;
                }
                at = pos + 1;
            }
            false
        } else if let Some(finder) = &self.suffix_finder {
            finder.find(tail).is_some()
        } else if self.suffix.len() == 1 {
            crate::memchr::memchr(self.suffix[0], tail).is_some()
        } else {
            crate::memchr::memmem::find(tail, &self.suffix).is_some()
        }
    }

    #[inline]
    fn matches_line(&self, line: &[u8]) -> bool {
        let min_line_len = self.prefix.len() + self.min_gap + self.suffix.len();
        if line.len() < min_line_len {
            return false;
        }
        if self.prefix.is_empty() {
            return self.confirm(line, 0);
        }
        let limit = line.len() - self.prefix.len() - self.min_gap - self.suffix.len();
        if let Some(finder) = &self.prefix_finder {
            let search_slice = &line[..limit + self.prefix.len()];
            for s in finder.find_iter(search_slice) {
                if self.confirm(line, s) {
                    return true;
                }
            }
            return false;
        }
        let p0 = self.prefix[0];
        let p0_flip = if self.prefix_caseless {
            super::literal::ascii_flip(p0)
        } else {
            p0
        };
        let mut at = 0;
        if self.prefix_caseless {
            while at <= limit {
                let Some(idx) = crate::memchr::memchr2(p0, p0_flip, &line[at..=limit]) else {
                    break;
                };
                let s = at + idx;
                if self.confirm(line, s) {
                    return true;
                }
                at = s + 1;
            }
        } else {
            while at <= limit {
                let Some(idx) = crate::memchr::memchr(p0, &line[at..=limit]) else {
                    break;
                };
                let s = at + idx;
                if self.confirm(line, s) {
                    return true;
                }
                at = s + 1;
            }
        }
        false
    }
}

/// One way of locating a match: a scan, and what its hits mean.
#[derive(Clone)]
struct Anchor {
    at: usize,
    scan: FastScan,
    /// Whether `at` is known. A scan for a literal behind a variable-length
    /// prefix finds the literal and nothing else, and saying `Fixed` for it
    /// would make the confirm look in the wrong place.
    known: bool,
}

/// One anchor, described for a caller outside this module. See
/// [`ByteRegex::anchor_info`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AnchorInfo {
    /// The scan's shape: `byte`, `byte3`, `masked`, `mask2` or `sub`.
    pub kind: &'static str,
    /// The offset from the start of every match the anchor's hits sit at.
    pub at: usize,
    /// Whether [`Self::at`] is exact. `false` means the anchor is somewhere
    /// inside every match and the confirm has to consider the whole line.
    pub known: bool,
    /// The bytes searched for, where the shape has any. Empty for a byte-set
    /// run: its members are a set at one offset, not a contiguous string.
    pub needle: Vec<u8>,
}

/// The public description of one private [`Anchor`].
fn anchor_info_of(a: &Anchor) -> AnchorInfo {
    let (kind, needle) = match &a.scan {
        FastScan::Byte { .. } => ("byte", Vec::new()),
        FastScan::Byte3 { .. } => ("byte3", Vec::new()),
        FastScan::ByteN { .. } => ("byten", Vec::new()),
        FastScan::Masked(_) => ("masked", Vec::new()),
        FastScan::Mask2 { .. } => ("mask2", Vec::new()),
        FastScan::Mask { decides, .. } => {
            (if *decides { "matchmask" } else { "premask" }, Vec::new())
        }
        FastScan::Sub { needle } => ("sub", needle.clone()),
    };
    AnchorInfo {
        kind,
        at: a.at,
        known: a.known,
        needle,
    }
}

/// One anchor's row in the cost model's arithmetic, for one buffer.
///
/// The numbers are the ones `FastLiteral::measure` compared -- the density
/// is that anchor's OWN scan over the same `sample_chunks` windows the model
/// samples -- so a caller can read the model's decision instead of inferring
/// it. This exists for `examples/cost_sensitivity.rs`, which is measuring the
/// model; nothing in the engine asks for it.
#[derive(Clone, Debug)]
pub struct AnchorCost {
    /// What the anchor is.
    pub info: AnchorInfo,
    /// Hits per sampled byte, as `FastLiteral::measure` counted them.
    pub density: f64,
    /// `FastScan::ns_per_byte` for the anchor's scan.
    pub ns_per_byte: f64,
    /// The price `Anchor::cost` charged one candidate of this anchor --
    /// `Anchor::effective_confirm`, which is the pattern's price unless the
    /// anchor is a match mask.
    pub confirm_ns: f64,
    /// `MATERIALISE_NS` if the anchor writes its hits out, else zero.
    pub materialise_ns: f64,
    /// What `Anchor::cost` returned, in ns per byte.
    pub cost: f64,
}

/// How the candidate offsets are found.
#[derive(Clone)]
enum FastScan {
    /// A single byte, or the two ASCII cases of one letter. `memchr` when
    /// the second equals the first, `memchr2` otherwise.
    Byte { a: u8, b: u8 },
    /// Any of three bytes. An alternation of three one-byte literals
    /// (`a|b|c`, `yes|no`, `<|>`) has no mask worth building and every byte
    /// of it is a needle, so `memchr3` is both the first and the only
    /// candidate; before this arm it had no prefilter at all.
    Byte3 { a: u8, b: u8, c: u8 },
    /// Four to eight one-byte literals (`a|b|c|d`, `<|>|+|-`). The
    /// one-to-three case has a `memchr` form and lives above; this is the
    /// same answer with no `memchr` form, filled by ORing the byte-set
    /// kernels over groups of three. Before this arm a fourth byte fell
    /// out of the prefilter entirely -- `whole_pattern_byte_alternation`
    /// stopped at three and `literal::extract` refuses a one-byte
    /// fingerprint -- so the Pike VM ran per line on a pattern that is
    /// nothing but a set of bytes.
    ByteN { bytes: [u8; 8], count: u8 },
    /// Two or more literals of two or more bytes, over the packed mask.
    Masked(super::literal::NibbleMask),
    /// A skeleton RUN: consecutive required byte-sets, one per mask
    /// position, in one bucket.
    ///
    /// The packed mask is normally a multi-position one: bucket `b` pins the
    /// bytes of its literal at positions 0..n and the scan ANDs a table lookup
    /// per position, so a candidate is a run of n agreeing bytes. Two things
    /// it could not do, and this arm is both of them.
    ///
    /// **A position may be a SET.** A fingerprint is one literal, so
    /// `e[0-9]` -- an `e` at offset 0 and a digit at offset 1 -- had no mask at
    /// all; the only thing that could be scanned for was the `e` alone, which
    /// is 5.31% of a Rust corpus and leaves 13 million candidates to reject
    /// one at a time. Registering the positions independently turns the AND
    /// into a two-byte test and the 13 million into 40 thousand.
    ///
    /// **A run of ONE position is a byte set**, which is how a tenth
    /// alternative gets scanned at all: MAX_BUCKETS is 8, so ten digits cannot
    /// each have a bucket -- but they can all share one, because a bucket
    /// accepts any number of prints per position.
    ///
    /// `checks` is the same information as a membership test, kept because
    /// the scan is a block-at-a-time pass whose per-position answer cannot be
    /// read back one byte at a time.
    Mask2 {
        mask: super::literal::NibbleMask,
        /// The offset of the run's first position from the start of a match.
        at: usize,
        /// One membership test per position, relative to the run's start.
        checks: Vec<Check>,
    },
    /// The set of offsets where a match can start, as an AND of shifted byte
    /// classes, one branch per way to start.
    ///
    /// **The arm that has no confirm behind it.** Every other scan here
    /// produces candidates and something downstream decides which of them are
    /// matches, and for `(pub|fn) [a-z]+` that something was a Pike VM run at
    /// 148 ns over 908 868 offsets. This one produces matches, when
    /// [`Self::Mask`] was built with `decides`: the answer is a bit and not a
    /// call.
    ///
    /// **It is also the only scan that can say `[a-z]`.** `memchr` takes up
    /// to three bytes, the packed mask takes a set per POSITION but is a
    /// fingerprint scan whose hits are still evidence, and the substring arm
    /// takes a literal. A class at an exact offset behind a variable-length
    /// prefix -- the space at offset 2 or 3 of `(pub|fn)` -- is none of those,
    /// which is why that pattern had no prefilter better than `pub`.
    Mask {
        /// Boxed, and that is a layout decision rather than a style.
        ///
        /// A [`super::scan::MatchMask`] is six vectors, so inlining it here
        /// took the enum from 40 to about 120 bytes -- and `FastScan` is
        /// matched per candidate and per line, and `Anchor` is inside a
        /// `Vec` the line walk touches. The mask is consulted through a
        /// reference every time, so the indirection costs one load on a cold
        /// path and the width costs a cache line on a hot one.
        mask: alloc::boxed::Box<super::scan::MatchMask>,
        /// What a set bit means. See [`Self::Mask`].
        decides: bool,
    },
    /// One literal of two bytes or more, found with a substring search.
    ///
    /// The one scan that is exact about the WHOLE needle rather than its
    /// first bytes, and the only one that can be pointed at a literal whose
    /// offset from the match start is unknown -- `\d+em` behind a variable
    /// number of digits is the case this exists for. It is two orders of
    /// magnitude more selective than scanning for the `e` of `em` (0.11% of
    /// the bytes against 5.31%), and the difference is the whole search:
    /// 3.6 s over 235 MB with no prefilter at all, and 0.2 s with this.
    ///
    /// Materialised rather than lazy, which is the right way round for a
    /// needle this long: the offsets are rare enough to be worth writing
    /// down, and a searcher wants them per LINE while `memmem`'s iterator
    /// would have to be held across the buffer.
    ///
    /// **There is no `caseless` field and that is the fix, not an omission.**
    /// This arm used to carry one, and `sub_offsets` gave a caseless needle
    /// to `memmem::Finder` unchanged -- which searches case-SENSITIVELY. So
    /// `(?i)[0-9]+em` anchored on `em` found `em` and not `EM`, and the line
    /// holding `EM` was never offered to the confirm: `rgx -i '[0-9]+em'`
    /// reported 1 where ripgrep reported 2. `crate::memchr::memmem` has no
    /// case-insensitive searcher to reach for, so the field promised a
    /// capability the arm did not have. Removing it makes the impossible
    /// spelling unrepresentable; [`Self::required_prefilter`] declines a
    /// caseless unknown-offset literal for the same reason, which costs that
    /// one shape its prefilter and nothing else.
    Sub { needle: Vec<u8> },
}

/// Every offset of `hay` holding `needle`.
///
/// Case-SENSITIVE, and that is a property of the type rather than a flag
/// someone has to remember: the caller refuses to build a caseless `Sub`, and
/// this function has no way to be told to fold.
///
/// **Overlapping, because a stream that misses an occurrence misses a match.**
/// `crate::memchr::memmem::Finder::find_iter` is documented to yield
/// *non-overlapping* occurrences, which is the right default for a searcher
/// that wants the first hit and the wrong one here: this function IS the
/// candidate stream, and a stream may over-report and may never under-report.
/// `xx` in `xxx` is one report instead of two; `abab` in `ababab` is one
/// instead of two. Each lost offset is a match start nothing downstream is
/// ever asked about, so the loss is a silent FALSE NEGATIVE and not a slow
/// search.
///
/// It became reachable the moment a known-offset `Sub` was allowed to compete
/// for the packed mask, and it did so on the very first run: `xx[0-9]zz`'s
/// chosen anchor became this scan, and its match at offset 65534 -- the
/// second `xx` of a `xxx` -- stopped being reported. The unknown-offset arm
/// had the same hole for as long as it has shipped; no differential case had
/// a repeated multi-byte literal behind an unknown offset, which is the only
/// way in.
///
/// The step is therefore `p + 1` and not `p + needle.len()`: the next search
/// resumes one byte on, so no start position is ever stepped over. That is
/// one forward pass plus at most `needle.len() - 1` bytes re-examined per hit,
/// and a hit is by definition a place worth re-examining.
fn sub_offsets(hay: &[u8], needle: &[u8]) -> alloc::vec::IntoIter<usize> {
    let mut out: Vec<usize> = Vec::new();
    if needle.is_empty() || hay.len() < needle.len() {
        return out.into_iter();
    }
    // The pair-byte prefilter tests two bytes simultaneously, but for a
    // 2-byte needle the second byte is the entire suffix and the SIMD
    // loop's per-call setup costs more than the `memmem` finder it
    // replaces. The prefilter pays for itself from 3 bytes up; below
    // that the scalar path is the one that measured faster.
    if needle.len() >= 3 {
        super::scan::pair_offsets(needle, hay, &mut out);
        return out.into_iter();
    }
    let finder = crate::memchr::memmem::Finder::new(needle);
    let mut at = 0usize;
    // `Finder` holds the NEEDLE and no haystack state, so searching a suffix
    // is a fresh search from `at` and not a continuation -- which is what
    // makes `at = p + 1` correct rather than merely plausible.
    while let Some(i) = finder.find(&hay[at..]) {
        let p = at + i;
        out.push(p);
        at = p + 1;
    }
    out.into_iter()
}

impl FastLiteral {
    /// Whether the literal sits at `at` in `line`.
    ///
    /// A match has to lie entirely inside `line`, so a window that runs past
    /// its end is not a match even when the bytes that fit do. Only
    /// meaningful when [`Self::exact`] holds -- a required literal that is
    /// merely *some* part of the pattern confirms nothing by being present.
    ///
    /// Reads [`Self::scan`] rather than the chosen anchor, which is only
    /// sound because this is reached only with `exact`, and a whole-pattern
    /// literal has exactly one anchor: `scan` and `anchors[0].scan` are the
    /// same value by construction there.
    fn at(&self, line: &[u8], at: usize) -> bool {
        match &self.scan {
            // Two compares against the needle itself, not a flag read out of
            // the literal list. This is the innermost loop of the dense case
            // -- `e` alone fires 13 million times on a 235 MB corpus -- and a
            // heap indirection per candidate there cost 12% of the whole
            // one-byte search. `b == a` on a case-sensitive byte makes the
            // second compare redundant; writing it out lets the test fold
            // away rather than costing a second compare per candidate, and on
            // a caseless one `b` is the case partner, which is the point.
            FastScan::Byte { a, b } => line
                .get(at)
                .is_some_and(|&x| x == *a || (*b != *a && x == *b)),
            FastScan::Byte3 { a, b, c } => {
                line.get(at).is_some_and(|&x| x == *a || x == *b || x == *c)
            }
            FastScan::ByteN { bytes, count } => line
                .get(at)
                .is_some_and(|&x| bytes[..*count as usize].contains(&x)),
            // A skeleton RUN is only ever an ANCHOR, never the whole
            // pattern, so a hit in it is evidence and never a match: `e[0-9]`
            // on `e0` matches and on `ex` it does not, and the difference
            // between the two is one VM run. The per-position tests are kept
            // beside the mask for exactly this, because the mask is a
            // build-time object and not something a candidate can ask.
            FastScan::Mask2 {
                at: run, checks, ..
            } => at
                .checked_sub(*run)
                .is_some_and(|start| checks.iter().all(|c| c.holds(line, start))),
            // A whole-pattern literal of two bytes or more reaches here as a
            // `memmem` hit, so the window IS the needle and the compare is a
            // slice equality rather than a byte loop. It used to build a
            // `FastLit` from a CLONE of the needle to call `lit_at`, which is
            // a heap allocation per candidate -- affordable when a `Sub` was
            // only ever `\d+em`'s 0.2% yield, and not affordable at all once
            // `pub fn` is 151,000 candidates per 235 MB.
            FastScan::Sub { needle } => line.get(at..).is_some_and(|tail| tail.starts_with(needle)),
            // A mask's bit is already the match's offset, so the confirm is
            // the branch set itself and the definition is the one the
            // producer publishes. This arm is only reached from `search`, which
            // never takes the mask anchor -- it exists so the enum is total.
            FastScan::Mask { mask, .. } => mask.holds(line, at),
            FastScan::Masked(_) if self.exact => lit_at(line, at, &self.lits[0]),
            FastScan::Masked(_) => self.lits.iter().any(|l| lit_at(line, at, l)),
        }
    }

    /// Every necessary condition this literal states about a match starting at
    /// `s`, and `false` when any of them says there cannot be one.
    ///
    /// Both vectors hold the same law — read off the AST, true of every match
    /// — and differ only in how exact the offset is. One pass over both rather
    /// than two because this runs per candidate and the vectors are almost
    /// always tiny: an empty one costs two length tests.
    #[inline]
    fn admits(&self, hay: &[u8], s: usize) -> bool {
        self.suffix_checks.iter().all(|sc| sc.holds(hay, s))
            && self.checks.iter().all(|c| c.holds(hay, s))
            && self.ranged.iter().all(|r| r.holds(hay, s))
    }

    /// The first match at or after `at` implied by a literal at `p`.
    ///
    /// Anchored, not a re-scan: `vm::find_at` stops when the thread list
    /// empties instead of re-seeding at every byte past it, so a candidate
    /// that is not part of a match costs the bytes between it and the end of
    /// the pattern rather than the rest of the line.
    fn verify(
        &self,
        prog: &Program,
        fixed: Option<&super::fixed::Fixed>,
        hay: &[u8],
        at: usize,
        p: usize,
        origin: usize,
    ) -> Option<vm::Match> {
        let s = p.checked_sub(origin)?;
        if s < at {
            return None;
        }
        // The cheap necessary conditions first, and the VM only for a
        // candidate that has passed all of them. See [`Self::checks`].
        if let Some(fx) = fixed {
            let end = s.checked_add(fx.len())?;
            return fx.confirm(hay, s).then(|| vm::Match {
                start: s,
                end,
                groups: Vec::new(),
            });
        }
        if !self.admits(hay, s) {
            return None;
        }
        vm::find_at(prog, hay, s)
    }

    /// **The anchor to use for `hay`, chosen by measuring it.**
    ///
    /// A prefilter has two costs and they pull in opposite directions: what
    /// the scan costs per byte, and what the candidates it admits cost to
    /// confirm. The required literal is only *one* of the bytes the pattern
    /// forces, and it is very often not the rarest of them. `e[0-9]` has two
    /// — the `e` at offset 0 and the digit at offset 1 — and on a Rust
    /// corpus they are 5.31% and 0.00014% of the bytes, a factor of 39,000.
    /// Anchoring on the `e` means 13 million candidates, each paying an
    /// anchored VM run to be told it is not a match; anchoring on the digit
    /// means 334. That is the whole of B1, and neither fact is visible in
    /// the pattern.
    ///
    /// So the choice is made from the data, on a sample of it, per buffer:
    ///
    /// ```text
    ///   cost(anchor) = scan_ns_per_byte + density * confirm_ns
    /// ```
    ///
    /// `density` is measured by running the anchor's own scan over the first
    /// [`SAMPLE`] bytes of the buffer and counting, so a byte-set anchor is
    /// judged on the yield its mask really has and not on a guess. The
    /// confirm cost is a constant and drops out of the comparison entirely
    /// (it multiplies every density by the same number), so only the RATIO
    /// of the two terms is a guess — and that ratio is the price of a scan
    /// against the price of a candidate, both measured on this machine and
    /// both within a factor of three of each other, which is far inside the
    /// four orders of magnitude the densities themselves span.
    ///
    /// A pattern with ONE anchor never samples and never measures: there is
    /// nothing to choose between, and paying for a choice nobody makes is how
    /// a prefilter programme ends up slower than no prefilter at all.
    fn plan(&self, hay: &[u8]) -> &Anchor {
        let first = &self.anchors[0];
        if self.anchors.len() == 1 || hay.is_empty() {
            return first;
        }
        // **Measured once, then reused while the buffer stays small.**
        //
        // The searcher asks for candidates once per FILL, and fills grow by
        // DOUBLING from 64 KiB. Sampling per fill would scan 8 KiB 3,670
        // times on a 235 MB file, and on `foo.*bar` that cost 110 ms of a
        // 290 ms search — the measurement cost more than the thing measured.
        // So the decision is remembered and re-made only when a buffer arrives
        // at least [`REPLAN`] times larger than the remembered one.
        //
        // A 235 MB file therefore measures exactly TWICE, not once: on the
        // 65,520-byte first fill and on the 540,676-byte fill the hex-table
        // line forces `LineBuffer` to grow to. The second is an OUTLIER in
        // either direction — the hex table is 13x denser than the file in
        // `e[0-9]` and holds nothing at all for `(pub|fn) [a-z]+`, `foo.*bar`,
        // `pub fn` or `let mut` (`examples/density_probe.rs`). Every arm of
        // [`Sampling`] was measured and each either repeats the shipped answer
        // or lands on a worse one, so the fix was not in the sample.
        //
        // It was in the price the measurement is scored against: the two
        // `e[0-9]` anchors have the SAME true density, so the choice between
        // them turns on `CONFIRM_NS + MATERIALISE_NS` vs `MASK_CONFIRM_NS`
        // (see that constant). The plan is thus a function of the buffer
        // sampled twice at two rates and pooled — not the pure function the
        // strictly-less rule below assumes.
        //
        // [`REPLAN`] stays where it is: turning re-measurement off changes the
        // anchor of none of the nine on this corpus.
        //
        // Pooling buys the property a replacement never had — a buffer unlike
        // the rest can pull the estimate only in proportion to the bytes it
        // contributed, so the 8 KiB hex fill (one `pub`/`fn` hit in all of it)
        // cannot overturn the first fill's eighteen and lose the match mask for
        // the remaining 98 MB.
        //
        // Remembering it is safe in the strong sense: EVERY anchor is sound
        // (see the module's law), so a stale decision can only be slower, and
        // the two atomics are written with values valid for this pattern and
        // read the same way — no reader sees a half-written index, and two
        // threads planning concurrently can only overwrite each other's
        // PREFERENCE.
        let planned = self.planned_len.load(Ordering::Relaxed);
        if planned != 0 && hay.len() < planned.saturating_mul(REPLAN) {
            let i = self.chosen.load(Ordering::Relaxed);
            return &self.anchors[i.min(self.anchors.len() - 1)];
        }
        self.measure(hay)
    }

    /// The cold half of [`Self::plan`], and it is a separate function for a
    /// reason that is not tidiness.
    ///
    /// `plan` sits on the hot path — it is what turns a candidate offset into
    /// a match start, so it is inside `search`, which the searcher calls once
    /// per line — and an inlined measurement loop in the middle of it stops
    /// every caller inlining. Measured on the CLI: with the measurement
    /// inlined, `foo.*bar` over 235 MB went from 280 ms to 324 ms, and with
    /// the whole of `plan` stubbed out it came back to 282 ms. The work was
    /// nine calls of it; the loss was the inlining of everything behind.
    /// Out of line and marked cold, `plan` is a load, a compare and a
    /// predictable branch, and the measurement is nine calls nobody waits on.
    #[cold]
    #[inline(never)]
    fn measure(&self, hay: &[u8]) -> &Anchor {
        let chunks = sample_chunks(hay);
        // **POOLED, not replaced.** This measurement's counts are added to
        // [`Self::evidence`] and every anchor is scored at the pool's
        // density, so a buffer unlike the rest of the file -- the
        // 540,676-byte hex-table line of the 235 MB corpus, which the fill
        // carrying it is almost entirely made of -- can shift the estimate
        // only by the 8 KiB it actually contributed and not veto the
        // evidence of every fill before it. The flip the replacement caused,
        // and the 83.4 ms it cost `(pub|fn) [a-z]+`, is the story in
        // [`Self::plan`].
        let n = chunks.iter().map(|(a, b)| b - a).sum::<usize>();
        let sampled = self.evidence.sampled.fetch_add(n, Ordering::Relaxed) + n;
        let mut best = 0usize;
        let mut best_score = f64::INFINITY;
        for (i, a) in self.anchors.iter().enumerate() {
            let hits: usize = chunks
                .iter()
                .map(|&(lo, hi)| a.scan.count_in(&hay[lo..hi]))
                .sum();
            let pooled = self.evidence.hits[i].fetch_add(hits, Ordering::Relaxed) + hits;
            let score = a.cost(pooled as f64 / sampled as f64, self.confirm_ns);
            // Strictly less, so a tie keeps the earlier anchor and the choice
            // is a pure function of the evidence: the same sequence of
            // buffers always produces the same plan, which is what makes a
            // regression reproducible.
            if score < best_score {
                best_score = score;
                best = i;
            }
        }
        self.planned_len.fetch_max(hay.len(), Ordering::Relaxed);
        self.chosen.store(best, Ordering::Relaxed);
        &self.anchors[best]
    }
}

/// How much bigger a buffer has to be before the anchor is measured again.
///
/// **Public because a measurement has to reproduce the ladder.** The rule is
/// `measure` again once a buffer `REPLAN` times the largest one measured so
/// far arrives, and `LineBuffer` doubles from 64 KiB, so a 235 MB file
/// re-measures exactly once. `examples/density_probe.rs` drives the real
/// `LineBuffer` and has to know which of its fills were the ones the model
/// actually saw; re-deriving the rule from the buffer lengths is a
/// re-implementation, and a re-implementation of the thing under test is
/// exactly what a measurement must not do.
pub const REPLAN: usize = 4;

impl Check {
    /// The membership table for one skeleton entry, or `None` for an empty
    /// set (which cannot happen, and would be a bug rather than a shape).
    fn new(entry: &super::required::Entry) -> Option<Self> {
        if entry.alts.is_empty() {
            return None;
        }
        let mut bits = [0u64; 4];
        for b in &entry.alts {
            bits[usize::from(*b >> 6)] |= 1 << (*b & 63);
            if entry.caseless {
                let other = super::literal::ascii_flip(*b);
                bits[usize::from(other >> 6)] |= 1 << (other & 63);
            }
        }
        Some(Self {
            off: entry.at,
            bits,
        })
    }
}

impl RangedCheck {
    /// The membership table for one minimum-offset entry, or `None` when the
    /// range is unbounded or wider than [`CHECK_SPAN`].
    ///
    /// **An exact range is refused here**, and that is a decision about cost
    /// rather than about soundness. An entry at one fixed offset is already
    /// in [`super::required::skeleton`], and when there is more than one
    /// anchor it is already in `checks`; adding it again as a ranged check
    /// would spend a second table test per candidate to learn what the first
    /// one already said. A pattern with one anchor and an exact entry
    /// (`foo.*bar`'s `foo`) learns nothing from either, because its anchor
    /// already guarantees it.
    fn new(run: &super::required::MinRun) -> Option<Self> {
        if run.alts.is_empty() {
            return None;
        }
        let (lo, hi) = run.bounded()?;
        if lo == hi {
            return None;
        }
        if hi - lo + 1 > CHECK_SPAN {
            return None;
        }
        let mut bits = [0u64; 4];
        for b in &run.alts {
            bits[usize::from(*b >> 6)] |= 1 << (*b & 63);
            if run.caseless {
                let other = super::literal::ascii_flip(*b);
                bits[usize::from(other >> 6)] |= 1 << (other & 63);
            }
        }
        Some(Self { lo, hi, bits })
    }
}

/// The maximal runs of consecutive entries in a skeleton, ascending.
///
/// Two entries are consecutive when the second starts one byte after the
/// first. A gap is not a run: the mask has no don't-care position, and adding
/// one would constrain nothing while costing a lookup per block.
fn runs(skeleton: &[super::required::Entry]) -> Vec<Vec<&super::required::Entry>> {
    let mut out: Vec<Vec<&super::required::Entry>> = Vec::new();
    for e in skeleton {
        match out.last_mut() {
            Some(last) if last.last().is_some_and(|p| p.at + 1 == e.at) => last.push(e),
            _ => out.push(alloc::vec![e]),
        }
    }
    out
}

/// How much of a buffer the anchor choice samples, and how it is spread.
const SAMPLE_CHUNKS: usize = 16;
const SAMPLE_CHUNK: usize = 512;

/// Up to 8 KiB of `hay`, in 16 pieces spread evenly from end to end.
///
/// **Spread, not a prefix, and that is not a detail.** A prefix sample
/// measured `e[0-9]`'s two anchors on a 235 MB Rust corpus and got it
/// backwards: the first 4 KiB of that file is a doc comment with two digits
/// in it, so the digit set looked 150x rarer than the `e` beside it, and the
/// anchor chosen was the one that yields 16.5 million candidates instead of
/// 13.1 million. The whole corpus has 6.69% digits and 5.31% `e` — the
/// prefix was not a sample of the file, it was a sample of its first
/// paragraph. Sixteen windows of 512 bytes reach into the bulk whatever the
/// file opens with, and cost the same 8 KiB to read.
///
/// **The window COUNT is the cost, and that is not what this comment used
/// to say.** One 512-byte `count_in` is ~0.2 us of fixed work -- an iterator
/// to build, a `Vec` to allocate -- against ~15 ns of scanning, so sixteen
/// windows cost 1.2 to 1.9 ns per byte SAMPLED while one contiguous pass
/// over the same buffer costs 0.06 to 0.21 ns per byte of it. Counting the
/// whole first fill is therefore both 8x to 66x more evidence and 7x to 18x
/// cheaper, and it is rejected on accuracy grounds alone: measured per
/// anchor over both fills, a whole-fill estimate sends
/// `(pub|fn) [a-z]+` to the fingerprint anchor, which costs 88% more
/// (165.7 ms against 88.1), because the second fill's density is zero and a
/// zero density decides on `ns_per_byte` alone, where the fingerprint is the
/// cheaper scan and the plan is the slower search.
///
/// None of that is 0.02 ms of anything. With the plan cached, a 235 MB file
/// measures twice and the whole measurement is 0.02 to 0.03 ms against a
/// 119 ms search; the 110 ms the per-FILL sampling this shape replaced is
/// not a cost this shape has.
fn sample_chunks(hay: &[u8]) -> [(usize, usize); SAMPLE_CHUNKS] {
    let n = hay.len();
    let mut out = [(0, 0); SAMPLE_CHUNKS];
    // A short buffer is sampled in overlapping windows rather than not at
    // all: the file is the only evidence there is, and a 200-byte file with
    // no sample would silently keep the first anchor.
    let step = n.saturating_sub(SAMPLE_CHUNK) / (SAMPLE_CHUNKS - 1);
    for (i, slot) in out.iter_mut().enumerate() {
        let lo = core::cmp::min(i * step, n);
        *slot = (lo, core::cmp::min(lo + SAMPLE_CHUNK, n));
    }
    out
}

/// Where a density estimate is cut from, for [`ByteRegex::anchor_costs_sampled`].
///
/// **This is the shape of the question, not a tuning knob.** The estimator
/// answers "in 8 KiB of this buffer, how many candidates will this anchor
/// admit", and every arm below answers it over a different set of bytes. Only
/// [`Self::Spread16`] is what the engine uses; the rest exist so
/// `examples/density_probe.rs` can measure the alternatives against the
/// density counted over the whole corpus rather than argue about them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sampling {
    /// The shipped shape: 16 windows of 512 B, spread end to end.
    Spread16,
    /// The same spread at twice the sample: 32 windows of 512 B, 16 KiB.
    Spread32,
    /// 64 windows of 512 B, 32 KiB. Still an eighth of a 235 MB file.
    Spread64,
    /// The first 8 KiB, contiguous.
    ///
    /// **Known wrong, and kept as the control.** A doc comment at
    /// `sample_chunks` records the measurement: on this corpus the first
    /// 4 KiB is a doc comment, so the digit set behind `e[0-9]` measured 150x
    /// rarer than the `e` beside it and the plan went to the anchor yielding
    /// 16.5 million candidates instead of 13.1 million. It is here so that
    /// probe prints the failure rather than a reader having to trust the
    /// comment.
    Prefix8k,
    /// Every byte of the buffer. The estimator the model would have if the
    /// cost of measuring were zero.
    Whole,
    /// The lower of two spreads of different granularity, 16x512 B and
    /// 64x128 B. A two-scale estimate, kept because "sampling more" and
    /// "sampling somewhere else" are different repairs and this is the one
    /// that does both.
    TwoScaleMin,
}

/// The windows [`Sampling`] asks for, in bytes of `hay`.
///
/// A `Vec` rather than the shipped fixed array because three of the arms have
/// a different window count than `SAMPLE_CHUNKS`. Nothing in the engine
/// calls it: `FastLiteral::measure` keeps its own array, and this exists so a
/// measurement can vary the estimator without the engine varying with it.
///
/// [`Sampling::TwoScaleMin`] is absent because it is not one set of windows.
/// It is the per-anchor MINIMUM over two of these, and
/// [`ByteRegex::anchor_costs_sampled`] is where that is computed -- a shape
/// that pools both scales would be a different estimator with the same name.
pub fn sample_windows(hay: &[u8], how: Sampling) -> Vec<(usize, usize)> {
    let spread = |n: usize, window: usize| -> Vec<(usize, usize)> {
        let mut out = Vec::with_capacity(n);
        let step = hay.len().saturating_sub(window) / (n - 1);
        for i in 0..n {
            let lo = core::cmp::min(i * step, hay.len());
            out.push((lo, core::cmp::min(lo + window, hay.len())));
        }
        out
    };
    match how {
        Sampling::Spread16 => sample_chunks(hay).to_vec(),
        Sampling::Spread32 => spread(32, SAMPLE_CHUNK),
        Sampling::Spread64 => spread(64, SAMPLE_CHUNK),
        Sampling::Prefix8k => {
            let hi = core::cmp::min(hay.len(), 16 * SAMPLE_CHUNK);
            if hi == 0 {
                Vec::new()
            } else {
                alloc::vec![(0, hi)]
            }
        }
        Sampling::Whole => {
            if hay.is_empty() {
                Vec::new()
            } else {
                alloc::vec![(0, hay.len())]
            }
        }
        Sampling::TwoScaleMin => spread(64, 128),
    }
}

/// The cost of confirming one candidate of a pattern with NO variable-length
/// tail, in nanoseconds.
///
/// **It is a common scale factor, and the only ratio in it that matters is
/// the one against [`MASK_CONFIRM_NS`].** `cost` is
/// `scan + density * price + density * materialise`, every swept anchor
/// carries the same `price`, and two such anchors differ only by their
/// densities — so the price cancels exactly out of every comparison between
/// two of them. It does NOT cancel against a match mask, which is charged
/// [`MASK_CONFIRM_NS`] and does not scale. The price is not "how expensive a
/// confirm is"; it is one number in a ratio, and the question any change to it
/// has to answer is which ratios move.
///
/// `examples/cost_sensitivity.rs` times all three engines a candidate can go
/// through, on the candidate stream the real searcher builds over 64 MiB of
/// the 235 MB corpus, minimum of three:
///
/// ```text
///   pattern          Pike VM   fixed::Fixed   MatchMask::holds
///   e                    33.1 ns      1.11 ns         1.37 ns
///   e.                   41.0 ns      1.49 ns         2.28 ns
///   e[0-9]               43.2 ns      1.91 ns         2.73 ns
///   pub fn              105.2 ns      3.72 ns         5.65 ns
///   (pub|fn) [a-z]+     150.9 ns           --         10.58 ns
/// ```
///
/// Every one of the first four is a pattern [`super::fixed`] specialises, so
/// every one confirms through `fixed` and never through the VM —
/// `FastLiteral::verify` tests `fixed` before it will build a `vm::Match`.
/// The 30 this replaces was 30: within 1.4x of the VM column and 16x to 27x
/// the `fixed` column, and **that wildness was not free — it cost `e.` a
/// measured 12.4% of its whole search.**
///
/// `e.`'s two anchors cross over at `(n_mask - n_byte) / d` = 8.94 ns at their
/// shared 5.31% density, so the model's argmin at 30 bought the match mask and
/// measured 12% wrong. 8 sits below that crossover with room for a corpus that
/// is not this one, and at 8 every one of the nine lands on the anchor measured
/// as fastest, `a|b|c` excepted: its match mask is one byte wide and DECIDES,
/// so [`Anchor::cost`] returns its scan rate and drops the density term
/// entirely, and no price above 0.05 ns can reach the byte scan it is compared
/// with. The 2.1% between them is the price of that early return, not of the
/// constant.
///
/// **And 8 fixes `e[0-9]` as well, which is not what it was asked to do.**
/// `e[0-9]`'s two-position mask and its match mask have the SAME true density
/// (2.44e-4; 60,232 and 60,230 hits), so the comparison is
/// `0.05 + d*(p + 4)` against `0.07 + d*8` and the crossover is
/// `(0.02 - 4d) / d` — **negative**, and the further negative the larger `d`
/// is. At 30 a pooled density above 7.7e-4 flipped it to the match mask, which
/// is 22% slower; at 8 the crossover is 5.0e-3, the pooled density the second
/// measurement produces is 1.0e-3, and the mask stays. The mechanism is the
/// note on [`MATERIALISE_NS`]: for a materialising anchor the price and the
/// materialise term are the same term, and 30 was large enough for the price
/// to be the reason the mask lost.
const CONFIRM_NS: f64 = 8.0;

/// The cost of confirming one candidate of a pattern whose tail is of
/// UNKNOWN length, in nanoseconds.
///
/// Measured, not guessed: `benchmark/status.md` §3 puts 148.2 ns on
/// `vm::matches_at` for `(pub|fn) [a-z]+` and the reader ablation puts
/// 246.9 ms of confirm over its 908 868 candidates, which is 271 ns each once
/// the pre-confirm and the per-candidate dispatch are in. 250 is the number
/// this comparison uses; the shape of the argument is that it is an order of
/// magnitude above [`CONFIRM_NS`], because a Pike VM run re-seeds a thread
/// list and two visit bitmaps per step and a two-byte pattern has two steps.
const TAILED_CONFIRM_NS: f64 = 250.0;

/// What one candidate of a MATCH MASK costs to confirm: the branch set,
/// evaluated against the line's own bytes.
///
/// `examples/straight_probe.rs`, over the same 908 868 entries and with zero
/// disagreements against the VM: 7.5 ns for `(pub|fn) [a-z]+` against 148.2,
/// 5.3 ns for `e[0-9]` against 44.9. It is the same AND the fill did, over
/// the same five or two bytes, so it is small by construction rather than by
/// luck.
const MASK_CONFIRM_NS: f64 = 8.0;

/// What a candidate costs when it is written into a `Vec<usize>` and read
/// back out of it by the line walk.
///
/// A bound rather than a measurement, and derived from the two things it has
/// to be between. It has to exceed the whole spread of the SCAN constants
/// (0.02 to 0.05 ns/byte) by enough to matter at a density a real corpus
/// produces, and it has to keep a needle that matches more than a few percent
/// of the bytes from being materialised at all — a one-byte prefilter over
/// 235 MB at 5% is 12 million offsets, which is the 104 MB the lazy supply
/// exists to avoid. Four nanoseconds per offset does both: at 4% density it
/// contributes 0.16 ns/byte, more than the entire spread between the scans,
/// and at `foo`'s measured 0.005% it contributes 0.0002 and is noise.
///
/// **It is the term that decided `e[0-9]` at the old price, and that is the
/// whole of the `CONFIRM_NS` story.** A per-candidate price is added to a
/// per-byte budget, and `e[0-9]`'s two-position mask materialises while its
/// match mask does not, so against that one comparison the two constants are
/// the same term. At the pooled density the second [`FastLiteral::plan`]
/// measurement produces -- 17 hits in 16,384 sampled bytes, 1.04e-3, which
/// `examples/density_probe.rs` measures as 4.3x the file's true 2.44e-4 --
/// the mask wins only while `d * (p + 4) < 0.020 + 8d`, i.e. while
/// `p < 23.2` at that density. The shipped 30 was above it and the mask was
/// 22% slower than the two-position scan; the price is now 8, and the
/// materialise term is again the smaller half of a sum rather than the
/// reason for the decision.
///
/// The number is still a bound rather than a measurement, and it is still
/// safe in the direction it fails: it can only make an anchor look more
/// expensive, so the error is a plan that declines an anchor which would
/// have paid, never one that buys an anchor which would not.
const MATERIALISE_NS: f64 = 4.0;

/// What an anchor costs per byte when it cannot say where a match begins.
///
/// The whole-line confirm, priced as one more pass over the buffer. A
/// candidate at an unknown offset says the match CONTAINS the literal, so the
/// confirm has to consider the whole line and the per-line cost is a line
/// scan rather than a proportional one — which is exactly the thing
/// `density * CONFIRM_NS` cannot express, and why this is a flat number
/// rather than a term. It replaced a 0.15 ns/byte penalty on `FastScan::Sub`
/// that was standing in for the same thing, and it is kept as a penalty
/// rather than a scan cost because the cost is the CONFIRM and the confirm is
/// the expensive half.
const UNKNOWN_ORIGIN_NS: f64 = 0.15;

/// The scan for a set of one-byte alternatives, or `None` if it is empty.
///
/// Width decides the arm, and the widths are the ones `memchr`, `memchr2`
/// and `memchr3` cover. Four bytes and up there is no such scan, and the
/// one-position packed mask is the fallback: it accepts a set of up to 256
/// bytes at the cost of materialising the hits, which is why a wide set is
/// only ever chosen when the measurement says it is rare.
fn scan_for_set(alts: &[u8], caseless: bool) -> Option<FastScan> {
    let mut alts = alts.to_vec();
    if caseless {
        // A caseless single byte is a two-member set as far as a scan is
        // concerned; `required::Entry` keeps the case flag so that a
        // CONTIGUOUS run can cross it, and a scan cannot, so the partner is
        // spelled out here.
        let partners: Vec<u8> = alts
            .iter()
            .map(|b| super::literal::ascii_flip(*b))
            .collect();
        alts.extend(partners);
    }
    alts.sort_unstable();
    alts.dedup();
    match alts.as_slice() {
        [] => None,
        [a] => Some(FastScan::Byte { a: *a, b: *a }),
        [a, b] => Some(FastScan::Byte { a: *a, b: *b }),
        [a, b, c] => Some(FastScan::Byte3 {
            a: *a,
            b: *b,
            c: *c,
        }),
        bytes => run_mask(&[bytes.to_vec()]),
    }
}

/// A mask whose consecutive positions accept these byte-sets, one set per
/// position.
///
/// The AND of `sets.len()` one-position tests, which is what turns "a byte of
/// this set, then a byte of that set" into a single SIMD pass over the buffer
/// instead of two.
fn run_mask(sets: &[Vec<u8>]) -> Option<FastScan> {
    if sets.is_empty() {
        return None;
    }
    // A run longer than the mask is wide is TRUNCATED, not refused: a prefix
    // of a run of required byte-sets is still a necessary condition for a
    // match, so the mask is still sound, and a four-position test over
    // `a[0-9]b[0-9]c` is worth more than no anchor at all. The cost is one
    // table lookup per position per block, which is why the width is capped
    // rather than merely bounded.
    let sets = &sets[..sets.len().min(super::literal::MAX_FINGERPRINT)];
    let borrowed: Vec<&[u8]> = sets.iter().map(|s| s.as_slice()).collect();
    let mut mask = super::literal::NibbleMask::new();
    if !mask.add_alternatives(0, &borrowed, false) {
        return None;
    }
    let checks = sets
        .iter()
        .enumerate()
        .map(|(i, set)| {
            let mut bits = [0u64; 4];
            for b in set.iter() {
                bits[usize::from(*b >> 6)] |= 1 << (*b & 63);
            }
            Check { off: i, bits }
        })
        .collect();
    Some(FastScan::Mask2 {
        mask,
        at: 0,
        checks,
    })
}

/// Whether the pattern contains a repetition of unknown length.
///
/// The walk is over the AST rather than the program because the program has
/// already lost the distinction: `x{2,5}` and `x{2}` compile to the same
/// thing, and only the first of them has a tail whose length the VM has to
/// search for.
/// Whether the pattern's first obligation is a start-of-line anchor.
///
/// `Assert::StartText` counts as well as `Assert::StartLine`: the searcher
/// hands the matcher a line, so inside it the two mean the same place, and
/// `^` compiles to `StartText` unless `(?m)` is set. Only a top-level
/// concatenation's FIRST element is an anchor — `^x|y` has an unanchored
/// branch, and `a^b` is not a line-anchored pattern at all.
fn starts_line_anchored(ast: &syntax::Ast) -> bool {
    match ast {
        syntax::Ast::Concat(v) => matches!(
            v.first(),
            Some(syntax::Ast::Assert(
                syntax::Assert::StartText | syntax::Assert::StartLine
            ))
        ),
        _ => false,
    }
}

fn has_variable_repeat(ast: &syntax::Ast) -> bool {
    match ast {
        syntax::Ast::Repeat { node, min, max, .. } => {
            *max != Some(*min) || has_variable_repeat(node)
        }
        syntax::Ast::Concat(items) | syntax::Ast::Alt(items) => {
            items.iter().any(has_variable_repeat)
        }
        syntax::Ast::Group { node, .. } => has_variable_repeat(node),
        syntax::Ast::Class(_) | syntax::Ast::Empty | syntax::Ast::Assert(_) => false,
    }
}

impl FastScan {
    /// How many times this scan fires in `hay`.
    ///
    /// Run with the anchor's OWN scan, so what is measured is the yield the
    /// anchor will really have — a ten-member set measured by ten `memchr`
    /// passes would be ten times the cost and the same answer.
    fn count_in(&self, hay: &[u8]) -> usize {
        match self {
            FastScan::Byte { a, b } if a == b => crate::memchr::memchr_iter(*a, hay).count(),
            FastScan::Byte { a, b } => crate::memchr::memchr2_iter(*a, *b, hay).count(),
            FastScan::Byte3 { a, b, c } => crate::memchr::memchr3_iter(*a, *b, *c, hay).count(),
            // No `memchr` form past three, so this is one scalar pass over
            // the haystack. It only runs in `measure`, twice per pattern, so
            // the scan is not the hot path here; the answer just has to be
            // the count the map would have found.
            FastScan::ByteN { bytes, count } => {
                let set = &bytes[..*count as usize];
                hay.iter().filter(|b| set.contains(b)).count()
            }
            FastScan::Masked(m) | FastScan::Mask2 { mask: m, .. } => {
                super::scan::candidates_count(m, hay)
            }
            // Counted with the map's own popcount, so what is measured is the
            // yield the mask really has and not an estimate of it.
            FastScan::Mask { mask, .. } => {
                let mut n = 0usize;
                for blk in hay.chunks(64 * 1024) {
                    let mut m = super::scan::BitMap::new();
                    mask.match_bits(blk, &mut m);
                    n += m.count_set(0, blk.len()) as usize;
                }
                n
            }
            FastScan::Sub { needle } => sub_offsets(hay, needle).count(),
        }
    }

    /// What one byte of haystack costs this scan, in nanoseconds.
    ///
    /// Measured on this machine, 235 MB of Rust source, best of seven: a
    /// one-byte `memchr` pass is 0.019 ns/byte (4.7 ms for 246 MB, 52 GB/s —
    /// it is memory-bandwidth bound, not compute bound), and the packed
    /// mask's block scan is 0.048 ns/byte including writing the candidate
    /// vector out. The two- and three-byte forms are the same loop with one
    /// and two more compares per block, which measures inside that spread, so
    /// they are given the one-byte number. Everything here is within a
    /// factor of three of everything else, which is the point: the term it
    /// competes with is a density, and the densities being compared span four
    /// orders of magnitude.
    fn ns_per_byte(&self) -> f64 {
        match self {
            FastScan::Byte { a, b } if a == b => 0.02,
            FastScan::Byte { .. } => 0.03,
            FastScan::Byte3 { .. } => 0.05,
            FastScan::ByteN { .. } => 0.05,
            FastScan::Masked(_) => 0.05,
            FastScan::Mask2 { .. } => 0.05,
            // A substring search, at its MEASURED scan speed, which is the
            // whole reason this number is what it is.
            //
            // 235 MB of Rust source, 64 KiB fills, best of seven, same bytes
            // and same candidate count on both sides: `memmem::find_iter` for
            // `foo` runs at 34.7 GB/s against the packed nibble mask's 16.2
            // (15.2 ms against 7.1 ms of the whole search), and for `pub fn`,
            // `let mut` and `fn main` at 33.6, 28.6 and 31.6 against the
            // mask's 10.4, 10.1 and 11.9. The mask is a two-table lookup and
            // an AND per POSITION per 32 bytes, and a seven-byte literal pays
            // that seven times; `memmem` looks at a two-byte prefilter and
            // verifies the rest only where it hits. It is faster on every
            // literal of three bytes or more here, which is the opposite of
            // what this constant used to say, and the constant being the
            // reason is why every one of them shipped a mask.
            //
            // The price of a `Sub` is not its scan but its MATERIALISATION:
            // the offsets are written out, so a dense needle is the allocation
            // the lazy `memchr` supply exists to avoid. That is priced where
            // it is paid — in [`Anchor::cost`] — because it is a function of
            // the density, and a constant cannot see a density.
            FastScan::Sub { .. } => 0.03,
            // **Measured on this machine, 235 MB of Rust source, 64 KiB fills,
            // the fill alone.** The cost is linear in the number of ops and has
            // a floor that is the pass over memory the fill shares with every
            // other scan:
            //
            // ```text
            //   ops                       ns/byte   GB/s
            //   1 class                   0.053     18.9
            //   1 byte + 1 class           0.067     14.9
            //   7 bytes                   0.128      7.8
            //   7 bytes + 2 classes        0.171      5.9
            // ```
            //
            // Least squares on those four gives `0.030 + 0.015 * bytes +
            // 0.025 * classes`, which is what is written. A single byte is one
            // `vpcmpeqb` and a class is a `vpshufb` pair, and this machine
            // retires four compares to one shuffle -- that ratio is the slope,
            // and it is why the fill splits the two rather than testing a flag
            // per op.
            //
            // The floor is the part that is NOT extra work when the mask
            // replaces another scan over the same buffer, and charging it
            // anyway makes the mask slightly more expensive than it is. That is
            // the safe direction for a cost model: it can only decline an
            // anchor that would have paid.
            FastScan::Mask { mask, .. } => {
                const PER_BYTE: f64 = 0.015;
                const PER_CLASS: f64 = 0.025;
                let mut singles = 0.0;
                let mut classes = 0.0;
                for b in mask.branches() {
                    for (_, c) in b {
                        if c.sole().is_some() {
                            singles += 1.0;
                        } else {
                            classes += 1.0;
                        }
                    }
                }
                0.030 + PER_BYTE * singles + PER_CLASS * classes
            }
        }
    }

    /// Whether the scan writes its hits out, rather than handing them over a
    /// line at a time.
    ///
    /// `memchr`'s iterators do not: they are consumed by the line walk and
    /// the one that is not taken is simply not computed, which is why a
    /// one-byte pattern over 235 MB does not allocate 104 MB of offsets. The
    /// mask is a block-at-a-time SIMD pass whose result is a vector by
    /// construction, and a substring search has to end before the searcher's
    /// per-line borrows exist, so both materialise. It is the difference
    /// [`Supply::Scan`](crate::searcher) exists to avoid, and
    /// [`Anchor::cost`] prices it.
    fn materialises(&self) -> bool {
        matches!(
            self,
            FastScan::Masked(_) | FastScan::Mask2 { .. } | FastScan::Sub { .. }
        )
    }
}

impl Anchor {
    /// What this anchor costs over the buffer, in nanoseconds per byte, at
    /// the density `measure` counted for it.
    ///
    /// `scan + density * CONFIRM_NS` for an anchor that knows where a match
    /// begins, which is the model [`FastLiteral::plan`] documents.
    ///
    /// **An anchor that does NOT know is priced by something else, and the
    /// difference is the second term.** A literal behind a variable-length
    /// prefix finds the literal and nothing else, so its candidates say
    /// nothing about where the match began and the confirm is a whole-LINE
    /// search — per line the stream admits, not per candidate, and no density
    /// prices that. So an unknown anchor pays [`UNKNOWN_ORIGIN_NS`] flat
    /// instead, which is a whole pass over the buffer at a whole-line-scan
    /// rate, and its density term is left out rather than guessed.
    fn cost(&self, density: f64, confirm_ns: f64) -> f64 {
        if !self.known {
            return UNKNOWN_ORIGIN_NS;
        }
        // **A mask ONE BYTE wide has no confirm term at all, and that is half
        // of what it is for.** A set bit in a one-byte mask is a match: a
        // one-byte match inside a line is a match, so there is no boundary to
        // be wrong about and nothing left to decide. `a|b|c` is this shape, and
        // its 12 410 297 three-byte confirms all disappear.
        if let FastScan::Mask { mask, decides } = &self.scan {
            if *decides && mask.width() == 1 {
                return self.scan.ns_per_byte();
            }
        }
        // A wider mask is a prefilter whose confirm is the mask itself, and
        // that is the CHEAPEST confirm there is: the same AND over the same
        // bytes the fill already did, `examples/straight_probe.rs` measures it
        // at 7.5 ns an entry against the VM's 148.2 on the same 908 868
        // entries with zero disagreements.
        let confirm_ns = self.effective_confirm(confirm_ns);
        let mut c = self.scan.ns_per_byte() + density * confirm_ns;
        if self.scan.materialises() {
            c += density * MATERIALISE_NS;
        }
        c
    }

    /// The price [`Self::cost`] charges for one candidate of THIS anchor.
    ///
    /// Split out of `cost` so a caller measuring the model cannot drift from
    /// it: `examples/cost_sensitivity.rs` prices an anchor at prices the model
    /// does not use, and it has to ask what price `cost` would have charged
    /// at the shipped ones to compare like with like.
    fn effective_confirm(&self, confirm_ns: f64) -> f64 {
        match &self.scan {
            FastScan::Mask { .. } => MASK_CONFIRM_NS,
            _ => confirm_ns,
        }
    }
}

/// The prefilter's literal positions in one haystack, ascending.
///
/// Three sources because the three scans have different shapes: the `memchr`
/// forms are iterators over the haystack and cost nothing to hold, and the
/// mask's scan builds a vector because it is a block-at-a-time SIMD pass whose
/// results are not cheap to recompute. `None` for a pattern with no prefilter,
/// which is an empty stream rather than a panic.
enum Offsets<'h> {
    None,
    Byte(crate::memchr::Memchr<'h>),
    Byte2(crate::memchr::Memchr2<'h>),
    Byte3(crate::memchr::Memchr3<'h>),
    Masked(alloc::vec::IntoIter<usize>),
}

impl Iterator for Offsets<'_> {
    type Item = usize;
    fn next(&mut self) -> Option<usize> {
        match self {
            Offsets::None => None,
            Offsets::Byte(it) => it.next(),
            Offsets::Byte2(it) => it.next(),
            Offsets::Byte3(it) => it.next(),
            Offsets::Masked(it) => it.next(),
        }
    }
}

/// Whether `lit`'s bytes sit at `at` in `line`.
fn lit_at(line: &[u8], at: usize, lit: &FastLit) -> bool {
    let Some(win) = line.get(at..at.saturating_add(lit.bytes.len())) else {
        return false;
    };
    win.iter().zip(lit.bytes.iter()).all(|(&a, &b)| {
        if lit.caseless {
            a.eq_ignore_ascii_case(&b)
        } else {
            a == b
        }
    })
}

impl ByteRegex {
    /// Compiles `pattern`, which is bytes rather than a `str` on
    /// purpose: a caller holding a path or an extracted buffer has
    /// already got the bytes and should not have to claim they are text.
    pub fn new(pattern: &[u8]) -> Result<Self, SyntaxError> {
        Self::new_flags(pattern, false)
    }

    /// Compiles with builder-level ASCII case-insensitivity, the way rgx's
    /// `-i` arrives -- as a flag, not a `(?i)` rewrite of the pattern.
    ///
    /// Folding is ASCII-only, same as `(?i)` in the pattern; see the module
    /// header for why a byte engine does not pretend otherwise.
    pub fn new_flags(pattern: &[u8], case_insensitive: bool) -> Result<Self, SyntaxError> {
        Self::new_multiline(pattern, case_insensitive, false)
    }

    /// Compiles with both builder flags: `-i` and `-U`.
    ///
    /// `dot_all` is the compile-time half of `-U`: a byte engine that compiles
    /// `.` to `any_except_newline()` cannot match across a line whatever the
    /// searcher is told. `(?s)` in the pattern is not a substitute — the
    /// pattern cannot configure `Config`. The caller sets the other half.
    ///
    /// A new constructor rather than a third argument on
    /// [`new_flags`](Self::new_flags) so the five existing call sites keep the
    /// meaning they had.
    pub fn new_multiline(
        pattern: &[u8],
        case_insensitive: bool,
        dot_all: bool,
    ) -> Result<Self, SyntaxError> {
        let flags = syntax::Flags {
            case_insensitive,
            dot_all,
            ..syntax::Flags::default()
        };
        let parsed = syntax::parse_with(pattern, flags)?;
        let prog = nfa::compile(&parsed.ast, parsed.groups);
        let (fast, whole_literal) = Self::fast_literal(pattern, &parsed.ast, case_insensitive);
        let direct = DirectConfirm::compile(&parsed.ast, case_insensitive);
        let pure_ascii = parsed.pure_ascii && !case_insensitive;
        Ok(Self {
            prog,
            source: pattern.to_vec(),
            names: parsed.names,
            case_insensitive,
            fast,
            whole_literal,
            boolean_confirm: has_variable_repeat(&parsed.ast),
            line_anchored: starts_line_anchored(&parsed.ast),
            // Compiled once, with the pattern, from the AST the flags produced
            // -- so `(?i)` folding and builder-level `-i` are already in the
            // tables and cannot be forgotten at the call site.
            fixed: super::fixed::Fixed::compile(&parsed.ast),
            direct,
            pure_ascii,
        })
    }

    /// Build the prefilter, and say whether the pattern *is* the literal.
    ///
    /// Two paths, and the second is tried only when the first declines.
    ///
    /// The first is the old one and it is untouched on purpose: a pattern
    /// that is one literal *and nothing else* gets a prefilter whose hit is
    /// the match, so the confirm is a byte compare and the VM never runs.
    ///
    /// The second is the AST walk in [`super::required`], and its confirm is
    /// different in kind: a required literal is only *evidence* that a match
    /// starts nearby, so the VM runs -- anchored at the start the candidate
    /// implies, which is why the literal's exact offset matters. What it buys
    /// is that a pattern with a metacharacter in the middle is no longer
    /// searched with no filter at all: `e.` is 99% as common as `e` and used
    /// to cost a full Pike VM run on every line of a 235 MB corpus.
    ///
    /// `extract` refuses a literal shorter than
    /// [`MIN_FINGERPRINT`](super::literal::MIN_FINGERPRINT) because a
    /// one-byte "fingerprint" is the whole haystack and admits every byte --
    /// a mask that filters nothing. That refusal was correct for the mask and
    /// wrong for the question behind it: a one-byte pattern is the EASIEST
    /// literal to search, and it was getting no prefilter at all because of a
    /// rule about masks. Measured on 235 MB of Rust source, `e` took 11.3 s
    /// through the Pike VM once per line against 95 ms for `ee` through the
    /// mask, and 4.6 ms for `memchr` alone -- the pattern that matches nearly
    /// every line was the slowest thing in the engine. So a ONE-BYTE
    /// case-sensitive literal gets `memchr`, which needs no fingerprint
    /// because it has nothing to discriminate.
    ///
    /// Everything else is unchanged, including case folding: a caseless
    /// literal is `Exact` but its confirm has to fold, so it stays on the
    /// mask, which carries the case bit in the bucket rather than in the
    /// needle.
    fn fast_literal(
        pattern: &[u8],
        ast: &syntax::Ast,
        caseless: bool,
    ) -> (Option<FastLiteral>, bool) {
        if let Some((fast, whole)) = Self::whole_pattern_literal(pattern, caseless) {
            return (Some(fast), whole);
        }
        if let Some(fast) = Self::whole_pattern_byte_alternation(ast, caseless) {
            return (Some(fast), false);
        }
        (Self::required_prefilter(ast), false)
    }

    /// A pattern that is nothing but an alternation of single BYTES: `a|b`,
    /// `a|b|c`, `yes` is not one of these but `<|>` is.
    ///
    /// `literal::extract` declines an alternation outright -- it answers "is
    /// this one string", and an alternation of three strings is not one string
    /// -- so the byte-set case is read off the AST instead.
    ///
    /// **This is the largest single win in the prefilter programme and it is
    /// not a prefilter win.** `a|b|c` already had the right scan: `memchr3`,
    /// 12.4 million candidates over 235 MB, at 50 GB/s. What it did not have
    /// was an exact answer. A candidate is only *evidence*, so each of those
    /// 12.4 million went to a Pike VM run anchored at it, and the bill was
    /// 215 ms of a 377 ms search at 17 ns a run -- the VM's per-call setup
    /// (dispatch, thread-list seeding, the visit bitmaps) for a question two
    /// byte compares would have answered. When the pattern IS the byte set,
    /// a candidate IS the match, and the confirm is `line[at] in {a,b,c}`.
    ///
    /// Two or three of them, and no more: a fourth byte has no `memchr` form,
    /// which is the entire reason the arm stops there. A caseless one is
    /// refused, because the byte set the parser built for a folded character
    /// has two members and folding it back out is the same per-byte work the
    /// scan was chosen to avoid.
    ///
    /// `has_fast_literal` stays `false` for this one. That flag tells
    /// [`super::hybrid`] the byte engine and `grep`'s Unicode matcher are the
    /// same function; it is true of a literal and is not a claim this shape
    /// earns by being fast.
    fn whole_pattern_byte_alternation(ast: &syntax::Ast, caseless: bool) -> Option<FastLiteral> {
        if caseless {
            return None;
        }
        let syntax::Ast::Alt(branches) = ast else {
            return None;
        };
        // Two to eight. Three is the most `memchr3` can carry; past that the
        // `ByteN` arm fills the map by ORing the byte-set kernels over groups
        // of three. Eight is the width `ByteN` stores, and a ninth byte would
        // need a new shape rather than a wider one.
        if !(2..=8).contains(&branches.len()) {
            return None;
        }
        let mut bytes = Vec::with_capacity(branches.len());
        for b in branches {
            // A one-byte literal parses to a class of one member, which is
            // what makes this the same shape the alternation of literals
            // above already handles.
            let syntax::Ast::Class(set) = b else {
                return None;
            };
            let mut members = set.iter();
            let first = members.next()?;
            if members.next().is_some() {
                return None;
            }
            bytes.push(first);
        }
        let scan = match bytes.len() {
            2 => FastScan::Byte {
                a: bytes[0],
                b: bytes[1],
            },
            3 => FastScan::Byte3 {
                a: bytes[0],
                b: bytes[1],
                c: bytes[2],
            },
            n => {
                let mut arr = [0u8; 8];
                arr[..n].copy_from_slice(&bytes[..n]);
                FastScan::ByteN {
                    bytes: arr,
                    count: n as u8,
                }
            }
        };
        // The mask, which for `a|b|c` is the merged class `{a, b, c}` and
        // DECIDES: the 12.4 million candidates the `memchr3` anchor produces
        // are 12.4 million three-byte confirms, and a bit is the answer.
        // Offered before the struct is built so [`FastLiteral::evidence`] is
        // sized for every anchor the pattern ends up with.
        let mut anchors = alloc::vec![Anchor {
            at: 0,
            scan: scan.clone(),
            known: true,
        }];
        offer_mask(&mut anchors, ast);
        Some(FastLiteral {
            lits: bytes
                .iter()
                .map(|&b| FastLit {
                    bytes: alloc::vec![b],
                    caseless: false,
                })
                .collect(),
            scan,
            exact: true,
            planned_len: AtomicUsize::new(0),
            chosen: AtomicUsize::new(0),
            evidence: Evidence::new(anchors.len()),
            anchors,
            checks: Vec::new(),
            ranged: Vec::new(),
            suffix_checks: Vec::new(),
            confirm_ns: CONFIRM_NS,
        })
    }

    /// The old path: the whole pattern is one literal, so a hit IS the match
    /// and the confirm never reaches the VM.
    ///
    /// Two shapes were added to it, both by measurement, and the second
    /// element of the pair is NOT always `true`.
    ///
    /// - **A literal of two bytes or more is searched with `memmem` rather
    ///   than with the packed nibble mask.** The mask is a *fingerprint* scan:
    ///   it ANDs one `pshufb` pair per mask position across 32 bytes and
    ///   admits any run of `positions` bytes that agree, then the confirm
    ///   re-reads the rest. For a six-byte needle that is four positions of
    ///   table work per block to answer a question `memmem` answers in one
    ///   pass. Measured over 235 MB of Rust source, best of seven:
    ///
    ///   ```text
    ///   needle     mask GB/s   memmem GB/s   ratio
    ///   pub fn       10.4          33.6       3.2x
    ///   let mut      10.1          28.6       2.8x
    ///   fn main      11.9          31.6       2.7x
    ///   ```
    ///
    ///   which is 24, 18 and 13 ms off a 120 ms search — worth 11-15%, and
    ///   plainly not the 3x the prefilter row alone suggests. The line walk
    ///   is 60% of that search and no prefilter reaches it; see
    ///   `benchmark/status.md` §2.
    ///
    /// - **An alternation of two or three ONE-BYTE literals is exact too.**
    ///   `a|b|c` had its prefilter already — `memchr3`, 12.4 million
    ///   candidates over the corpus — and still cost 215 ms of a 377 ms
    ///   search, because a candidate is only *evidence* and every one of the
    ///   12.4 million was confirmed by a Pike VM run at 17 ns apiece. When
    ///   the pattern IS the set of bytes, a candidate is the match: the
    ///   confirm is `line[at] in {a, b, c}` and the VM never runs at all.
    ///
    ///   The flag is `false` for that one, deliberately. `has_fast_literal`
    ///   tells [`super::hybrid`] that the byte engine and `grep`'s Unicode
    ///   matcher are the same function, which is true of a literal and is a
    ///   claim this file has no standing to make about an alternation. The
    ///   byte-side exactness is a different question with a different
    ///   answer, and the two are kept apart.
    ///
    /// Case folding is unchanged and is the reason both additions are gated
    /// on `!caseless`: `memmem` cannot fold, and a fold bolted on top would
    /// put a per-byte test back into the confirm and give back exactly what
    /// it saved.
    fn whole_pattern_literal(pattern: &[u8], caseless: bool) -> Option<(FastLiteral, bool)> {
        if pattern.len() == 1 && !caseless && !super::literal::is_meta(pattern[0]) {
            let b = pattern[0];
            return Some((
                FastLiteral {
                    lits: vec![FastLit {
                        bytes: vec![b],
                        caseless: false,
                    }],
                    scan: FastScan::Byte { a: b, b },
                    exact: true,
                    planned_len: AtomicUsize::new(0),
                    chosen: AtomicUsize::new(0),
                    evidence: Evidence::new(1),
                    anchors: alloc::vec![Anchor {
                        at: 0,
                        scan: FastScan::Byte { a: b, b },
                        known: true,
                    }],
                    checks: Vec::new(),
                    ranged: Vec::new(),
                    suffix_checks: Vec::new(),
                    confirm_ns: CONFIRM_NS,
                },
                true,
            ));
        }
        let set = super::literal::extract(pattern, caseless);
        if set.kind() != super::literal::LiteralKind::Exact {
            return None;
        }
        let lits = set.literals();
        let fast: Vec<FastLit> = lits
            .iter()
            .map(|l| FastLit {
                bytes: l.bytes().to_vec(),
                caseless: l.is_caseless(),
            })
            .collect();
        let build = |scan: FastScan| FastLiteral {
            lits: fast,
            scan: scan.clone(),
            exact: true,
            planned_len: AtomicUsize::new(0),
            chosen: AtomicUsize::new(0),
            evidence: Evidence::new(1),
            anchors: alloc::vec![Anchor {
                at: 0,
                scan,
                known: true,
            }],
            checks: Vec::new(),
            ranged: Vec::new(),
            suffix_checks: Vec::new(),
            confirm_ns: CONFIRM_NS,
        };
        // The alternation of one-byte literals. Two to eight of them: three is
        // the most `memchr3` carries, and past that `ByteN` fills the map by
        // ORing the byte-set kernels over groups of three. Before that arm a
        // fourth byte had no prefilter at all and the Pike VM ran per line.
        if !caseless && (2..=8).contains(&lits.len()) && lits.iter().all(|l| l.bytes().len() == 1) {
            let scan = match lits.len() {
                2 => FastScan::Byte {
                    a: lits[0].bytes()[0],
                    b: lits[1].bytes()[0],
                },
                3 => FastScan::Byte3 {
                    a: lits[0].bytes()[0],
                    b: lits[1].bytes()[0],
                    c: lits[2].bytes()[0],
                },
                n => {
                    let mut arr = [0u8; 8];
                    for (slot, lit) in arr.iter_mut().zip(lits.iter()) {
                        *slot = lit.bytes()[0];
                    }
                    let _ = n;
                    FastScan::ByteN {
                        bytes: arr,
                        count: lits.len() as u8,
                    }
                }
            };
            // `false`, and see the header: the byte engine can decide a line,
            // which is not the same as the two engines being one function.
            return Some((build(scan), false));
        }
        if lits.len() != 1 {
            return None;
        }
        // A case-sensitive literal of two bytes or more goes to `memmem`.
        // Below two bytes `memchr` is the better scan and the one-byte case
        // above already took it.
        if !caseless && lits[0].bytes().len() >= 2 {
            return Some((
                build(FastScan::Sub {
                    needle: lits[0].bytes().to_vec(),
                }),
                true,
            ));
        }
        let mask = super::literal::build_mask(&set, super::literal::MAX_FINGERPRINT)?;
        Some((build(FastScan::Masked(mask)), true))
    }

    /// The new path: whatever the AST says every match must contain.
    ///
    /// Two shapes are accepted and everything else declines:
    ///
    /// - one required literal, scanned by `memchr` when it is a single byte
    ///   (the dense case, and the one `Candidates` produces lazily) or by the
    ///   packed mask when it is longer;
    /// - two required one-byte literals, scanned by `memchr2`. That is what
    ///   `a|b` leaves behind, and it is a large win rather than a marginal
    ///   one: both branches start at offset 0, so a hit at `p` implies the
    ///   match starts at `p` and the anchored VM confirms it in one byte.
    ///
    /// An alternation of longer literals needs a mask, and a mask needs every
    /// fingerprint to be at least two bytes, so a mix of lengths declines
    /// rather than silently dropping the short one.
    fn required_prefilter(ast: &syntax::Ast) -> Option<FastLiteral> {
        use super::required::Prefilter;
        let pre = super::required::required(ast);
        // The one literal, kept for the substring anchor below and read BEFORE
        // `pre` is consumed. `One` is the only arm whose offsets are exact,
        // and a `Sub` that could not say where a match began is the expensive
        // shape.
        let whole: Option<(usize, Vec<u8>, bool)> = match &pre {
            Prefilter::One(r) => Some((r.at, r.bytes.clone(), r.caseless)),
            _ => None,
        };
        let (at, lits) = match pre {
            Prefilter::None => (0, Vec::new()),
            Prefilter::One(r) => (r.at, vec![r]),
            Prefilter::Alt(a) => (a.at, a.lits),
        };
        let lits: Vec<FastLit> = lits
            .into_iter()
            .map(|r| FastLit {
                bytes: r.bytes,
                caseless: r.caseless,
            })
            .collect();
        // A pattern with no exact-offset requirement at all still gets
        // anchors from the runs below, so the list may legitimately start
        // empty; what it may not do is END empty, and that is checked after
        // every anchor has been added.
        let mut anchors: Vec<Anchor> = match Self::scan_for(&lits) {
            Some(scan) if !lits.is_empty() => alloc::vec![Anchor {
                at,
                scan,
                known: true,
            }],
            _ => Vec::new(),
        };
        // Every byte at an exact offset the pattern is known to require. The
        // required literal above is first, so a pattern whose skeleton adds
        // nothing behaves exactly as it did, and one whose skeleton adds a
        // run gets a choice.
        let skeleton = super::required::skeleton(ast);
        // One anchor per maximal run of CONSECUTIVE entries, and only where
        // the run holds a byte SET.
        //
        // A run of single bytes is a literal, which is what `required`
        // already reported and `anchors[0]` already scans for, and a mask
        // over it is strictly more selective than any one of its bytes. So
        // there is nothing to gain by adding single-byte anchors, and a cost:
        // a second anchor makes [`FastLiteral::plan`] a real choice, and a
        // real choice puts a runtime-loaded index between the scan and every
        // candidate. On `foo.*bar` that measured 16% of the search, for an
        // anchor that would never have won.
        //
        // A run WITH a set is where the win is. `e[0-9]` anchored on the `e`
        // alone admits 13,085,834 candidates on the 235 MB corpus; the run
        // admits 40,000, because the AND of "an `e` here" and "a digit
        // there" is a two-byte test that one `memchr` cannot express.
        for run in runs(&skeleton) {
            if run.iter().all(|e| e.alts.len() == 1) {
                continue;
            }
            if run.len() == 1 {
                // An isolated set of one to three bytes is a `memchr2` or a
                // `memchr3`, and those hand their offsets over one line at a
                // time instead of writing them all out. A mask would be a
                // second, worse way of saying the same thing.
                if let Some(scan) = scan_for_set(&run[0].alts, run[0].caseless) {
                    anchors.push(Anchor {
                        at: run[0].at,
                        scan,
                        known: true,
                    });
                }
                continue;
            }
            let sets: Vec<Vec<u8>> = run
                .iter()
                .map(|e| {
                    let mut v = e.alts.clone();
                    if e.caseless {
                        let p: Vec<u8> = v.iter().map(|b| super::literal::ascii_flip(*b)).collect();
                        v.extend(p);
                    }
                    v
                })
                .collect();
            let Some(FastScan::Mask2 {
                mask, checks: rc, ..
            }) = run_mask(&sets)
            else {
                continue;
            };
            let first = run[0].at;
            anchors.push(Anchor {
                at: first,
                scan: FastScan::Mask2 {
                    mask,
                    at: first,
                    checks: rc,
                },
                known: true,
            });
        }
        // The pre-confirm, and only when there was a choice to make.
        //
        // With ONE anchor there was none: every candidate the stream yields
        // is a hit of that scan, so every entry the scan already guarantees
        // is a test the confirm would repeat. `e.` is the case that shows it
        // — one anchor, one skeleton entry, and a check that re-tests the
        // byte `memchr` has just matched, 13 million times over, for 34 ms
        // of a 360 ms search. So the checks are built only where they can
        // reject something the scan did not, which is exactly where there is
        // more than one way to have found the candidate.
        let checks = if anchors.len() > 1 {
            skeleton.iter().filter_map(Check::new).collect()
        } else {
            Vec::new()
        };
        // The RANGED pre-confirm, and it is built regardless of how many
        // anchors there are, because it is not redundant with any of them: a
        // ranged entry sits at offsets the exact-offset skeleton threw away,
        // so no scan built from that skeleton can have guaranteed it.
        //
        // `(pub|fn) [a-z]+` is the case it exists for. The alternation has
        // branches of different length, so nothing behind it has an exact
        // offset, so `skeleton` is empty, so `checks` is empty, and every one
        // of the pattern's 908,868 candidates paid a Pike VM run. The space
        // is at offset 2 or 3 and is there either way.
        let ranged = super::required::min_runs(ast)
            .iter()
            .filter_map(RangedCheck::new)
            .collect();
        let suffix_checks = super::required::trailing_literals(ast)
            .into_iter()
            .map(|sl| SuffixCheck {
                min_offset: sl.min_offset,
                needle: sl.bytes,
                caseless: sl.caseless,
                dot_all: sl.dot_all,
            })
            .collect();
        // The same literal as a SUBSTRING scan, at the same KNOWN offset, so
        // [`FastLiteral::plan`] has a real choice to make between two scans
        // of the same bytes.
        //
        // **This is the anchor the packed mask lost to, and the cost model
        // had it backwards.** Measured on the 235 MB corpus, 64 KiB fills,
        // same bytes and same candidate count: `memmem` for `foo` runs at
        // 34.7 GB/s against the mask's 16.2, and for `pub fn` 33.6 against
        // 10.4. [`FastScan::ns_per_byte`] charged the substring 0.15 ns/byte
        // and the mask 0.05 — three times the wrong way, and it was the
        // reason every literal of three bytes or more in this table ships a
        // mask. The constant below is what the machine says; the
        // `known: false` case keeps its own penalty, because an unknown
        // offset makes the confirm a whole-line search and no scan speed
        // buys that back.
        //
        // Case-SENSITIVE only, for the same reason the unknown-offset arm
        // below is: `crate::memchr::memmem` has no caseless searcher, so a folded
        // needle would find `pub fn` and not `PUB FN`, which is not a slow
        // search but a wrong answer.
        if let Some((rat, needle, false)) = whole {
            if needle.len() >= 2 && needle.len() <= super::required::MAX_LITERAL {
                anchors.push(Anchor {
                    at: rat,
                    scan: FastScan::Sub { needle },
                    known: true,
                });
            }
        }
        // A required literal whose OFFSET nothing knows: `\d+em`, where the
        // digits in front may be any number of them. It is a second prefilter
        // rather than a second kind of entry, because the confirm it forces
        // is a different and much more expensive thing, and a caller that
        // takes it has to have said so.
        //
        // Two bytes is the floor and it is not arbitrary: a ONE-byte literal
        // at an unknown offset is scanned for by a single `memchr` that is
        // no more selective than the line walk it is meant to replace, so it
        // would pay the whole-line confirm on every line that has one and
        // save nothing. `memmem` on two bytes is already an order of
        // magnitude more selective than the first byte alone.
        //
        // **A caseless one is declined, and declining is the whole fix.**
        // `FastScan::Sub` is a case-SENSITIVE substring search because
        // `crate::memchr::memmem` has no case-insensitive searcher; this arm used to
        // hand it a caseless needle anyway, and the prefilter then found
        // `em` and not `EM`. A prefilter that misses a position the literal
        // occupies is not slow, it is WRONG, and the differential suite did
        // not catch it because no case in it had a caseless literal behind an
        // unknown offset. `regex/tests.rs::a_caseless_literal_never_becomes_a_known_substring_anchor`
        // and `required.rs::a_caseless_literal_is_present_for_every_spelling`
        // are the cases that hold this down.
        if let Some(r) = super::required::anywhere(ast) {
            if r.bytes.len() >= 2
                && !r.caseless
                // Skipped when a KNOWN anchor is already scanning for exactly
                // these bytes. `Origin::Fixed(at)` is strictly better than
                // `Origin::Unknown` -- the same offsets, a cheaper confirm --
                // so a second anchor over the same needle buys nothing and
                // costs a second 512-byte sample every time `plan` measures.
                // `foo.*bar` had three anchors for two literals until this:
                // the mask, the known substring, and `anywhere`'s copy of the
                // known substring with `known` set to false.
                && !anchors.iter().any(|a| {
                    a.known && matches!(&a.scan, FastScan::Sub { needle } if *needle == r.bytes)
                })
            {
                anchors.push(Anchor {
                    at: 0,
                    scan: FastScan::Sub { needle: r.bytes },
                    known: false,
                });
            }
        }
        // The mask, last so a tie keeps the incumbent.
        //
        // **It is also what makes a pattern with NO prefilter reachable.**
        // `[0-9]+` has no exact-offset literal -- `required` needs a
        // contiguous run of SINGLE bytes and a ten-member class is not one --
        // so before this it streamed [`super::searcher::Candidates::every`]
        // and confirmed every offset of every line. Its mask is one class at
        // offset 0, it decides, and it is 6.69% of the bytes against 100%.
        if let Some(scan) = mask_anchor(ast) {
            anchors.push(Anchor {
                at: 0,
                scan,
                known: true,
            });
        }
        // Drop anchors that scan the same bytes at the same offset as one
        // already kept. The byte alternation `a|b|c` produces a byte3 anchor
        // from the required-literal pass above and a second one from the
        // skeleton run below: both scan offset 0 for {a,b,c}, and the second
        // one only doubles the choice `plan` makes without ever winning it.
        // Deduping keeps the list to the anchors a real comparison could
        // prefer, which is what the rest of the module assumes.
        anchors.dedup_by(|a, b| a.at == b.at && Self::same_scan(&a.scan, &b.scan));
        if anchors.is_empty() {
            return None;
        }
        let scan = anchors[0].scan.clone();
        Some(FastLiteral {
            lits,
            scan,
            exact: false,
            evidence: Evidence::new(anchors.len()),
            anchors,
            checks,
            ranged,
            suffix_checks,
            confirm_ns: if has_variable_repeat(ast) {
                TAILED_CONFIRM_NS
            } else {
                CONFIRM_NS
            },
            planned_len: AtomicUsize::new(0),
            chosen: AtomicUsize::new(0),
        })
    }

    /// The scan for a set of required literals, or `None` when none of the
    /// four shapes fits.
    ///
    /// The arms are ordered by how cheap the scan is, and the last one is
    /// the only one that can express a set wider than two bytes.
    fn scan_for(lits: &[FastLit]) -> Option<FastScan> {
        if lits.len() == 1 && lits[0].bytes.len() == 1 {
            // The case partner, not the byte again. A caseless single
            // character parses to a TWO-member class, and scanning for one
            // case of it would drop every match spelled the other way --
            // `(?i)x[a-z]` reporting a line only when the `x` is lower case
            // is the exact shape of the bug this module exists to prevent.
            return Some(FastScan::Byte {
                a: lits[0].bytes[0],
                b: if lits[0].caseless {
                    super::literal::ascii_flip(lits[0].bytes[0])
                } else {
                    lits[0].bytes[0]
                },
            });
        }
        if lits.len() == 2 && lits.iter().all(|l| l.bytes.len() == 1) {
            return Some(FastScan::Byte {
                a: lits[0].bytes[0],
                b: lits[1].bytes[0],
            });
        }
        if lits.len() == 3 && lits.iter().all(|l| l.bytes.len() == 1) {
            return Some(FastScan::Byte3 {
                a: lits[0].bytes[0],
                b: lits[1].bytes[0],
                c: lits[2].bytes[0],
            });
        }
        if lits.len() <= super::literal::MAX_BUCKETS
            && lits
                .iter()
                .all(|l| l.bytes.len() >= super::literal::MIN_FINGERPRINT)
        {
            let set = super::literal::LiteralSet::inexact(
                lits.iter()
                    .map(|l| {
                        if l.caseless {
                            super::literal::Literal::caseless(&l.bytes)
                        } else {
                            super::literal::Literal::new(&l.bytes)
                        }
                    })
                    .collect(),
            );
            let mask = super::literal::build_mask(&set, super::literal::MAX_FINGERPRINT)?;
            return Some(FastScan::Masked(mask));
        }
        None
    }

    /// Whether two scans are the same operation: same shape, same bytes, same
    /// offset. Used by [`Self::required_prefilter`] to drop anchors that point
    /// at the same place with the same scan -- they only add to the choice
    /// `plan` makes without ever winning it.
    ///
    /// Only the simple shapes have a meaningful "equal"; the mask variants
    /// carry a boxed structure that compares by reference, so two distinct
    /// mask instances with the same shape still look different here. That is
    /// a missed dedup rather than a wrong one: a tighter binary could keep
    /// both masks and `plan` would still pick the cheaper one.
    fn same_scan(a: &FastScan, b: &FastScan) -> bool {
        match (a, b) {
            (FastScan::Byte { a: x1, b: x2 }, FastScan::Byte { a: y1, b: y2 }) => {
                x1 == y1 && x2 == y2
            }
            (
                FastScan::Byte3 {
                    a: x1,
                    b: x2,
                    c: x3,
                },
                FastScan::Byte3 {
                    a: y1,
                    b: y2,
                    c: y3,
                },
            ) => x1 == y1 && x2 == y2 && x3 == y3,
            (FastScan::Sub { needle: n1 }, FastScan::Sub { needle: n2 }) => n1 == n2,
            _ => false,
        }
    }

    /// Compiles `pattern` read as UTF-8. A convenience for callers that
    /// genuinely do have text; the bytes are the same either way.
    pub fn new_str(pattern: &str) -> Result<Self, SyntaxError> {
        Self::new(pattern.as_bytes())
    }

    /// The pattern as written.
    pub fn as_bytes(&self) -> &[u8] {
        &self.source
    }

    /// Whether the pattern was compiled with ASCII case folding.
    pub fn is_case_insensitive(&self) -> bool {
        self.case_insensitive
    }

    /// Whether the whole pattern is one case-sensitive literal, so the byte
    /// engine and `grep`'s Unicode matcher are the same function on it.
    ///
    /// Narrower than [`Self::has_prefilter`] on purpose: a required literal
    /// found in the AST is enough to *skip* lines but not to *decide* them,
    /// because `e.` and `[a-z]` mean different things to the two engines over
    /// a non-ASCII line. `hybrid` needs this distinction, and merging it
    /// would hand it the wider one.
    pub fn has_fast_literal(&self) -> bool {
        self.whole_literal
    }

    /// Whether every leaf in the AST accepts only ASCII bytes (< 128) and
    /// contains no Unicode word boundaries or caseless folding, so its match
    /// decisions are invariant to non-ASCII bytes under UTF-8 semantics.
    pub fn is_pure_ascii(&self) -> bool {
        self.pure_ascii && !self.case_insensitive
    }

    /// Whether the pattern has a required prefilter literal consisting entirely
    /// of ASCII bytes, compiled with case-sensitivity, so no non-ASCII line can
    /// match without containing the literal.
    pub fn has_pure_ascii_prefilter(&self) -> bool {
        if self.case_insensitive {
            return false;
        }
        let Some(fast) = &self.fast else {
            return false;
        };
        !fast.lits.is_empty()
            && fast
                .lits
                .iter()
                .all(|l| !l.caseless && !l.bytes.is_empty() && l.bytes.iter().all(|&b| b < 128))
    }

    /// Whether a prefilter exists at all -- a literal every match is known to
    /// contain, whether or not it is the whole pattern.
    pub fn has_prefilter(&self) -> bool {
        self.fast.is_some()
    }

    /// The prefilter is **one** required byte, so the scan is a single
    /// `memchr` and not a two-byte or three-byte one.
    ///
    /// This is the shape on which ripgrep's answer to "find the lines that
    /// might match" stops being a SIMD literal scan worth having. A one-byte
    /// literal matches one position in 256, so both engines are reduced to
    /// `memchr` over the haystack and the difference is what each does with
    /// the candidates it gets back: ripgrep's confirm is a DFA run, and the
    /// in-house engine's is an exact nibble mask.
    ///
    /// The alternative to a single byte is the reason this is worth
    /// discriminating at all. A character class is ripgrep's SIMD class
    /// matcher, and it is very good: on the registry store `[a-z]+` is **2.5x
    /// faster** under `grep` and `\d` is 1.2x, while `a\|b\|c` -- three
    /// one-byte literals, a `memchr3` rather than a `memchr` -- is 4.6% faster
    /// the other way. So a two- or three-byte scan and a class both go to
    /// `grep`, and only the one-byte case is a candidate.
    pub fn has_single_byte_prefilter(&self) -> bool {
        let Some(fast) = &self.fast else { return false };
        match fast.anchors[0].scan {
            FastScan::Byte { a, b } => a == b,
            _ => false,
        }
    }

    /// Append the prefilter's candidate offsets for `hay` to `out`.
    ///
    /// The offsets are the positions of the **literal**, not of the match.
    /// For a whole-pattern literal at offset 0 those are the same thing, which
    /// is why this read as a match-start stream for as long as the fast path
    /// only existed for whole-pattern literals. For `e[0-9]x` the literal
    /// sits at offset 1 and the match starts one byte earlier; the consumer
    /// subtracts `FastLiteral::at` and the searcher never sees a match
    /// offset directly.
    ///
    /// The counterpart to [`has_prefilter`](Self::has_prefilter), and exposed
    /// rather than kept behind the [`CandidateSource`](crate::searcher::CandidateSource) impl because a caller
    /// assembling its OWN superset needs the offsets and the predicate
    /// separately: it has to add the offsets of any region the byte engine is
    /// not allowed to decide.
    ///
    /// **The one-byte arm materialises, and that is deliberate.** A caller
    /// that has to MERGE this with offsets of its own -- `hybrid` widens the
    /// stream to every offset of every non-ASCII line -- needs them all at
    /// once and in order. The dense path does not merge, and takes
    /// [`fast_candidates_lazy`](Self::fast_candidates_lazy) instead.
    pub fn fast_candidates(&self, hay: &[u8], out: &mut Vec<usize>) {
        let Some(fast) = &self.fast else { return };
        let scan = &fast.plan(hay).scan;
        match scan {
            FastScan::Byte { a, b } if a == b => out.extend(crate::memchr::memchr_iter(*a, hay)),
            FastScan::Byte { a, b } => out.extend(crate::memchr::memchr2_iter(*a, *b, hay)),
            FastScan::Byte3 { a, b, c } => out.extend(crate::memchr::memchr3_iter(*a, *b, *c, hay)),
            // Past three there is no `memchr` form, so the offsets come from
            // one pass over the haystack. This entry point hands over a LIST,
            // which is why it cannot use the map the searcher would read.
            FastScan::ByteN { bytes, count } => {
                let set = &bytes[..*count as usize];
                out.extend(
                    hay.iter()
                        .enumerate()
                        .filter_map(|(i, b)| set.contains(b).then_some(i)),
                );
            }
            FastScan::Masked(mask) | FastScan::Mask2 { mask, .. } => {
                super::scan::candidates_append(mask, hay, out);
            }
            // The offsets come out of the map the searcher would read, walked
            // here only because this entry point hands over a LIST.
            FastScan::Mask { mask, .. } => {
                let mut bits = super::scan::BitMap::new();
                mask.match_bits(hay, &mut bits);
                bits.append_offsets(out);
            }
            FastScan::Sub { needle } => out.extend(sub_offsets(hay, needle)),
        }
    }

    /// TEMPORARY: how many anchors the pattern offers.
    pub fn anchor_count(&self) -> usize {
        self.fast.as_ref().map_or(0, |f| f.anchors.len())
    }

    /// What each anchor is, for a caller that wants to measure the anchors
    /// rather than only use the one [`Self::anchor_for`] picked.
    ///
    /// `kind` is the scan's shape and `needle` the bytes it looks for where
    /// the shape has any — an empty needle for a byte-set run, whose members
    /// are the *offsets* rather than a contiguous string. The measurement
    /// harness in `examples/prefilter_ablate.rs` was the caller this exists
    /// for: "which prefilter is faster" is a question about a scan, and the
    /// scan is otherwise private. **That harness was deleted**, so nothing in
    /// this tree calls it today — which is why the accessor has no production
    /// caller of its own, and why the right move is to restore the harness
    /// rather than delete the accessor that only it used.
    #[must_use]
    pub fn anchor_info(&self) -> alloc::vec::Vec<AnchorInfo> {
        self.fast
            .as_ref()
            .map(|f| f.anchors.iter().map(anchor_info_of).collect())
            .unwrap_or_default()
    }

    /// The anchor [`Self::anchor_for`] would pick for `hay`, described the
    /// same way [`Self::anchor_info`] describes the rest.
    ///
    /// `anchor_info` says what a pattern OFFERS and this says which of them
    /// the cost model chose on a given buffer, and those are different
    /// questions: a pattern whose fastest anchor is not the first is the
    /// normal case, not an anomaly, and a harness that cannot see the choice
    /// is measuring the wrong scan.
    #[must_use]
    pub fn chosen_anchor(&self, hay: &[u8]) -> Option<AnchorInfo> {
        self.fast.as_ref().map(|f| anchor_info_of(f.plan(hay)))
    }

    /// Every anchor's row in the cost model's arithmetic, for `hay`.
    ///
    /// [`Self::anchor_info`] says what a pattern offers and
    /// [`Self::chosen_anchor`] which of them the model took; this says the
    /// arithmetic behind the second, for every one of them, so that a caller
    /// can see how far from the line the choice was and what would move it.
    /// It does NOT consult the remembered decision, so it works on a buffer
    /// `FastLiteral::plan` has already cached a verdict for -- which is what
    /// makes a sweep over the prices possible at all.
    #[must_use]
    pub fn anchor_costs(&self, hay: &[u8]) -> Vec<AnchorCost> {
        self.anchor_costs_sampled(hay, Sampling::Spread16)
    }

    /// [`Self::anchor_costs`] with the sampling shape chosen by a caller.
    ///
    /// Same arithmetic, same prices, same `Anchor::cost` -- only the bytes the
    /// density is counted over differ. That is the whole point: it is the one
    /// variable in the estimator, exposed so
    /// `examples/density_probe.rs` can hold the model fixed and move the
    /// sample.
    #[must_use]
    pub fn anchor_costs_sampled(&self, hay: &[u8], how: Sampling) -> Vec<AnchorCost> {
        let Some(fast) = &self.fast else {
            return Vec::new();
        };
        let density_of = |a: &Anchor, chunks: &[(usize, usize)]| -> f64 {
            let n: usize = chunks.iter().map(|(a, b)| b - a).sum();
            if n == 0 {
                return 0.0;
            }
            let hits: usize = chunks
                .iter()
                .map(|&(lo, hi)| a.scan.count_in(&hay[lo..hi]))
                .sum();
            hits as f64 / n as f64
        };
        // A two-scale estimate is the LOWER of two independent samples, per
        // anchor. Counting both into one pooled density is a different
        // estimator wearing the same name: the min is what makes a rare anchor
        // look rare, and pooling a coarse sample into a fine one is what made
        // `e[0-9]` look dense in the first place.
        let coarse =
            (how == Sampling::TwoScaleMin).then(|| sample_windows(hay, Sampling::Spread16));
        let chunks = sample_windows(hay, how);
        fast.anchors
            .iter()
            .map(|a| {
                let mut density = density_of(a, &chunks);
                if let Some(coarse) = &coarse {
                    density = density.min(density_of(a, coarse));
                }
                AnchorCost {
                    info: anchor_info_of(a),
                    density,
                    ns_per_byte: a.scan.ns_per_byte(),
                    confirm_ns: a.effective_confirm(fast.confirm_ns),
                    materialise_ns: if a.scan.materialises() {
                        MATERIALISE_NS
                    } else {
                        0.0
                    },
                    cost: a.cost(density, fast.confirm_ns),
                }
            })
            .collect()
    }

    /// [`Self::anchor_costs`] with the density supplied instead of measured.
    ///
    /// The model, with one number replaced. Everything else -- the scan price,
    /// the confirm price, the materialise term, and `Anchor::cost` itself --
    /// is the engine's, so a caller scoring a pooled or a hypothetical
    /// density is scoring it with the arithmetic that will actually run and not
    /// with a second implementation of it that can drift.
    ///
    /// A density that is not finite, or a list shorter than the anchor list,
    /// yields a cost of infinity: a caller that does not know an anchor's
    /// density is saying it cannot use that anchor, and inventing a zero for
    /// it would be the one answer guaranteed to be wrong.
    #[must_use]
    pub fn anchor_costs_at(&self, densities: &[f64]) -> Vec<AnchorCost> {
        let Some(fast) = &self.fast else {
            return Vec::new();
        };
        fast.anchors
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let density = densities
                    .get(i)
                    .copied()
                    .filter(|d| d.is_finite())
                    .unwrap_or(f64::INFINITY);
                AnchorCost {
                    info: anchor_info_of(a),
                    density,
                    ns_per_byte: a.scan.ns_per_byte(),
                    confirm_ns: a.effective_confirm(fast.confirm_ns),
                    materialise_ns: if a.scan.materialises() {
                        MATERIALISE_NS
                    } else {
                        0.0
                    },
                    cost: if density.is_finite() {
                        a.cost(density, fast.confirm_ns)
                    } else {
                        f64::INFINITY
                    },
                }
            })
            .collect()
    }

    /// Every anchor's density over EVERY byte of `hay`, counted.
    ///
    /// **Not an estimate, and that is the reason it is here.** The estimator
    /// is what the model is allowed to see; this is what the density is. The
    /// two disagree by three orders of magnitude on `e[0-9]` -- 0 hits in
    /// 8,192 sampled bytes against 0.024% over the corpus -- and an error that
    /// large is invisible until it is measured against something, so
    /// `examples/density_probe.rs` measures every estimator against this and
    /// prints the ratio.
    #[must_use]
    pub fn anchor_densities(&self, hay: &[u8]) -> Vec<f64> {
        let Some(fast) = &self.fast else {
            return Vec::new();
        };
        if hay.is_empty() {
            return alloc::vec![0.0; fast.anchors.len()];
        }
        let n = hay.len() as f64;
        fast.anchors
            .iter()
            .map(|a| a.scan.count_in(hay) as f64 / n)
            .collect()
    }

    /// How many hits each anchor admits over every byte of `hay`, counted.
    ///
    /// The count rather than the rate, because at a true density of 2.4e-4 a
    /// rate printed to three decimals is a zero and the comparison it is used
    /// for -- hits in an 8 KiB sample against hits in a 235 MB corpus -- needs
    /// the numbers to stay integers.
    #[must_use]
    pub fn anchor_hits(&self, hay: &[u8]) -> Vec<usize> {
        let Some(fast) = &self.fast else {
            return Vec::new();
        };
        fast.anchors.iter().map(|a| a.scan.count_in(hay)).collect()
    }

    /// [`Self::anchor_hits`] over a sample of `hay` rather than all of it.
    ///
    /// `(hits, sampled bytes)` per anchor, because the two are what the error
    /// of an estimate is: hits alone is a count of a sample whose size the
    /// caller has to re-derive, and every two arms of the estimator sample
    /// different numbers of bytes.
    ///
    /// The two together are what `examples/density_probe.rs` needs and neither
    /// is enough alone: the first is the answer, the second is the guess, and
    /// a guess is only a guess relative to an answer.
    #[must_use]
    pub fn anchor_hits_sampled(&self, hay: &[u8], how: Sampling) -> Vec<(usize, usize)> {
        let Some(fast) = &self.fast else {
            return Vec::new();
        };
        let density = |a: &Anchor, chunks: &[(usize, usize)]| -> (usize, usize) {
            let n: usize = chunks.iter().map(|(a, b)| b - a).sum();
            if n == 0 {
                return (0, 0);
            }
            let h: usize = chunks
                .iter()
                .map(|&(lo, hi)| a.scan.count_in(&hay[lo..hi]))
                .sum();
            (h, n)
        };
        let coarse =
            (how == Sampling::TwoScaleMin).then(|| sample_windows(hay, Sampling::Spread16));
        let chunks = sample_windows(hay, how);
        fast.anchors
            .iter()
            .map(|a| {
                let (h, n) = density(a, &chunks);
                match &coarse {
                    Some(coarse) => {
                        // The min of two rates, rescaled to the finer
                        // sample's byte count so both arms are comparable.
                        let (hc, nc) = density(a, coarse);
                        (core::cmp::min(h * nc / n.max(1), hc), n)
                    }
                    None => (h, n),
                }
            })
            .collect()
    }

    /// The price the model charges one candidate of this pattern, in ns.
    ///
    /// `CONFIRM_NS` or `TAILED_CONFIRM_NS`, whichever the tail earned.
    /// Exposed so a caller sweeping that price starts from the shipped value
    /// instead of from a number it had to guess out of a doc comment.
    #[must_use]
    pub fn confirm_price(&self) -> f64 {
        self.fast.as_ref().map_or(0.0, |f| f.confirm_ns)
    }

    /// What the prefilter's candidates mean for `hay`, under the anchor
    /// `FastLiteral::plan` picked.
    ///
    /// A caller that materialises the candidates itself — `hybrid`, which
    /// widens the stream to every offset of a line the byte engine may not
    /// decide — has to stamp this on the stream it builds, or the confirm
    /// will subtract the wrong number and report a match at the wrong place.
    /// Asking here rather than caching the choice is what keeps a compiled
    /// pattern shareable across the walker's threads: there is no cell, and
    /// two threads searching two files with one `ByteRegex` each get their
    /// own answer.
    #[must_use]
    pub fn anchor_for(&self, hay: &[u8]) -> super::searcher::Origin {
        self.fast
            .as_ref()
            .map_or(super::searcher::Origin::Fixed(0), |f| {
                let a = f.plan(hay);
                if a.known {
                    super::searcher::Origin::Fixed(a.at)
                } else {
                    super::searcher::Origin::Unknown
                }
            })
    }

    /// The prefilter's candidate offsets for `hay`, found on demand.
    ///
    /// `None` when the prefilter cannot produce a lazy stream -- a masked
    /// literal needs its fingerprint scan, and a caller with no literal at
    /// all needs [`super::searcher::Candidates::every`]. A caller that only
    /// wants to pull candidates in order should take this first.
    pub fn fast_candidates_lazy<'a>(
        &'a self,
        hay: &'a [u8],
    ) -> Option<super::searcher::Candidates<'a>> {
        let fast = self.fast.as_ref()?;
        let anchor = fast.plan(hay);
        let set = match &anchor.scan {
            FastScan::Byte { a, b } => super::searcher::ByteSet::of(*a, *b),
            FastScan::Byte3 { a, b, c } => super::searcher::ByteSet::Three(*a, *b, *c),
            // `ByteSet` is `One`/`Two`/`Three` because that is what the
            // set-based scan can express. Past three the caller falls back to
            // the map, which is the path this prefilter was added for.
            FastScan::ByteN { .. } => return None,
            FastScan::Masked(_) | FastScan::Mask2 { .. } | FastScan::Sub { .. } => return None,
            FastScan::Mask { .. } => return None,
        };
        Some(
            super::searcher::Candidates::of_set(hay, set).with_origin(if anchor.known {
                super::searcher::Origin::Fixed(anchor.at)
            } else {
                super::searcher::Origin::Unknown
            }),
        )
    }

    /// The candidate offsets for `hay` as the searcher's stream, with the
    /// anchor's offset attached, whichever arm the anchor turns out to need.
    ///
    /// The one place a stream is built, so that the origin stamped on it is
    /// always the one the anchor was chosen with. Every entry point above
    /// goes through here or through the `CandidateSource` impl below, and a
    /// caller that picks its own anchor cannot pick a stale offset.
    fn stream<'a>(
        &'a self,
        hay: &'a [u8],
        out: &'a mut alloc::vec::Vec<usize>,
    ) -> super::searcher::Candidates<'a> {
        let Some(fast) = &self.fast else {
            return super::searcher::Candidates::every(hay.len());
        };
        // **A match mask is only reachable as a MAP, and this method never
        // has one.** `Searcher::map_run` asks `map_candidates` first, and that
        // is the only door a mask comes through -- so this method, which is
        // how `search_slice` builds its stream and how a reader falls back on
        // a fill over [`super::scan::MAX_BITMAP_INPUT`], must not take it.
        //
        // Not a correctness question: the mask's list form is a superset and
        // the confirm settles it. A COST question, and the answer was
        // measured both ways. A mask is one pass that writes `len / 8` bytes
        // and then a walk of the offsets it set; `memchr3` over the same
        // bytes is the same pass with nothing written and the offsets handed
        // over a line at a time. That is a losing trade on a 64 KiB fill --
        // which is why the reader path keeps the mask and is 15% faster for
        // it -- and a worse one on the 4.4 KB median file of a 56 232 file
        // corpus, where it cost `a|b|c` 12%: 519 ms to 583, 1.15x to 1.02x.
        // The bound is therefore not "too big to map" but "there is no map".
        //
        // The anchor is then used to BUILD the stream directly, rather than
        // being handed to the dispatch below, which had one arm per shape and
        // so fell through to `Candidates::every` for a byte scan the
        // fallback had just substituted: `a|b|c` over a 235 MB slice went
        // from 281 ms to 565 ms by making every offset a candidate. A mask's
        // own list form IS built below, for a buffer small enough to map but
        // reached by this path.
        let chosen = fast.plan(hay);
        let mut anchor = chosen;
        if matches!(anchor.scan, FastScan::Mask { .. }) {
            match fast
                .anchors
                .iter()
                .find(|a| !matches!(a.scan, FastScan::Mask { .. }))
            {
                Some(a) => anchor = a,
                None => return super::searcher::Candidates::every(hay.len()),
            }
        }
        let origin = |a: &Anchor| {
            if a.known {
                super::searcher::Origin::Fixed(a.at)
            } else {
                super::searcher::Origin::Unknown
            }
        };
        match &anchor.scan {
            FastScan::Byte { a, b } => {
                let set = super::searcher::ByteSet::of(*a, *b);
                super::searcher::Candidates::of_set(hay, set).with_origin(origin(anchor))
            }
            FastScan::Byte3 { a, b, c } => {
                let set = super::searcher::ByteSet::Three(*a, *b, *c);
                super::searcher::Candidates::of_set(hay, set).with_origin(origin(anchor))
            }
            // Past three there is no `ByteSet` shape, so the offsets are
            // materialised the way the `Mask` arm does it. This is the list
            // form of the same answer `map_candidates` puts in the map.
            FastScan::ByteN { .. } => {
                out.clear();
                self.fast_candidates(hay, out);
                super::searcher::Candidates::of(out).with_origin(origin(anchor))
            }
            FastScan::Sub { needle } => {
                out.clear();
                if needle.len() >= 2 {
                    super::scan::pair_offsets(needle, hay, out);
                } else {
                    out.extend(sub_offsets(hay, needle));
                }
                super::searcher::Candidates::of(out).with_origin(origin(anchor))
            }
            FastScan::Masked(m) | FastScan::Mask2 { mask: m, .. } => {
                super::scan::candidates_into(m, hay, out);
                super::searcher::Candidates::of(out).with_origin(origin(anchor))
            }
            FastScan::Mask { .. } => {
                out.clear();
                self.fast_candidates(hay, out);
                super::searcher::Candidates::of(out).with_origin(origin(anchor))
            }
        }
    }

    /// The leftmost match at or after `at`, with its capture groups.
    pub fn search(&self, hay: &[u8], at: usize) -> Option<vm::Match> {
        // The literal fast path. A pure-literal pattern has no groups, no
        // anchors and no alternation, so a confirmed byte compare IS the
        // leftmost-first match -- there is nothing the VM could decide
        // differently. Candidates arrive sorted, so the first hit at or
        // after `at` is the answer, and once the literal no longer fits the
        // remaining haystack no later candidate can either.
        //
        // The mask's confirm covers only the fingerprint (4 bytes); the
        // tail compare below is what makes this a match rather than a
        // candidate. Skipped when the pattern is not a single literal.
        let Some(fast) = &self.fast else {
            return vm::find(&self.prog, hay, at);
        };
        // This is the confirm the binary actually runs, so this is where
        // the confirm counters have to be. `prefilter::Prefilter` has the
        // same shape and counts too, but rgx drives `ByteRegex`, so
        // counting only there measures nothing.
        let stats = super::maskstats::enabled();
        let mut confirms = 0u64;
        let mut hits = 0u64;

        // A whole pattern made only of ONE-BYTE literals cannot reject a
        // candidate: the fingerprint is the whole needle, so the scan and the
        // confirm are the same comparison and `memchr` is both. Counting
        // confirms and hits separately here would make them equal by
        // construction, which is true and uninformative, so the one number
        // that says something -- how many bytes were examined -- is the one
        // reported.
        //
        // **The three-byte arm is `memchr3` and has to be.** This used to
        // bind `Byte3 { a, b, .. }` to the same `memchr2` closure as `Byte`,
        // which is correct only while no `Byte3` scan is ever paired with
        // `exact` -- and `a|b|c` is now exactly that, so the `c` would have
        // been dropped and every `c` in the corpus would have gone
        // unreported. Latent rather than live, and the exact shape of bug
        // this file's law is about: a specialisation that is fast and wrong
        // beats a general one that is right, silently.
        let anchor = fast.plan(hay);
        // An anchor that cannot say where the match BEGINS is not usable
        // here. `any_match_in` handles it -- a candidate for an unknown
        // origin is a LIVENESS device and the whole line is confirmed -- but
        // `search` is asked "does a match begin at or after `at`", and the
        // candidate is a position of the LITERAL, which for `\d+em` is not
        // where the match starts. Anchoring the VM at it and requiring the
        // result to begin there is the bug this guard is for: it reported
        // `xx[0-9]zz` at 65534 as no match, because the `zz` is at 65537 and
        // the anchored run there finds nothing. Falling back to the ordinary
        // unanchored search is what this function did before the prefilter
        // existed and is right by construction.
        if !anchor.known {
            return vm::find(&self.prog, hay, at);
        }
        if fast.exact {
            let found = {
                let h = hay.get(at..)?;
                match &anchor.scan {
                    FastScan::Byte { a, b } => {
                        if a == b {
                            crate::memchr::memchr(*a, h)
                        } else {
                            crate::memchr::memchr2(*a, *b, h)
                        }
                    }
                    FastScan::Byte3 { a, b, c } => crate::memchr::memchr3(*a, *b, *c, h),
                    _ => None,
                }
            };
            if let Some(found) = found {
                let start = at + found;
                if stats {
                    super::maskstats::flush(&super::maskstats::ScanDelta {
                        bytes: (start + 1 - at) as u64,
                        blocks: 0,
                        candidates: 0,
                        confirms: 1,
                        hits: 1,
                    });
                }
                return Some(vm::Match {
                    start,
                    end: start + 1,
                    groups: Vec::new(),
                });
            }
        }

        for p in self.fast_offsets(hay) {
            if p < at {
                continue;
            }
            // One candidate, one confirm: the same unit Hyperscan calls
            // `verify_bucket`, except that rgx confirms against one literal
            // where Hyperscan fans out over a bucket.
            confirms += 1;
            let found = if fast.exact {
                // The pattern IS the literal, so a hit at its offset is the
                // leftmost-first match and there is nothing the VM could
                // decide differently. `at == 0` on this arm by construction.
                let s = p - anchor.at;
                fast.at(hay, s).then(|| vm::Match {
                    start: s,
                    end: s + fast.lits[0].bytes.len(),
                    groups: Vec::new(),
                })
            } else {
                fast.verify(&self.prog, self.fixed.as_ref(), hay, at, p, anchor.at)
            };
            if let Some(m) = found {
                hits += 1;
                if stats {
                    super::maskstats::flush(&super::maskstats::ScanDelta {
                        bytes: 0,
                        blocks: 0,
                        candidates: 0,
                        confirms,
                        hits,
                    });
                }
                return Some(m);
            }
        }
        if stats {
            super::maskstats::flush(&super::maskstats::ScanDelta {
                bytes: 0,
                blocks: 0,
                candidates: 0,
                confirms,
                hits,
            });
        }
        None
    }

    /// The prefilter's literal positions in `hay`, ascending, without
    /// materialising them.
    ///
    /// The one-byte arm is lazy on purpose and not only for the searcher: a
    /// dense literal has millions of hits per corpus, and `search` stops at
    /// the first, so writing them out first would turn a one-byte scan into an
    /// allocation several times the buffer's own size.
    fn fast_offsets<'h>(&self, hay: &'h [u8]) -> Offsets<'h> {
        let Some(fast) = &self.fast else {
            return Offsets::None;
        };
        match &fast.plan(hay).scan {
            FastScan::Byte { a, b } if a == b => Offsets::Byte(crate::memchr::memchr_iter(*a, hay)),
            FastScan::Byte { a, b } => Offsets::Byte2(crate::memchr::memchr2_iter(*a, *b, hay)),
            FastScan::Byte3 { a, b, c } => {
                Offsets::Byte3(crate::memchr::memchr3_iter(*a, *b, *c, hay))
            }
            // Past three there is no `memchr` iterator, so the offsets are
            // materialised once. `Offsets::Masked` is already the owning-vec
            // iterator, and this is the same shape with a different producer.
            FastScan::ByteN { bytes, count } => {
                let set = &bytes[..*count as usize];
                Offsets::Masked(
                    hay.iter()
                        .enumerate()
                        .filter_map(|(i, b)| set.contains(b).then_some(i))
                        .collect::<alloc::vec::Vec<usize>>()
                        .into_iter(),
                )
            }
            FastScan::Masked(mask) | FastScan::Mask2 { mask, .. } => {
                Offsets::Masked(super::scan::candidates(mask, hay).into_iter())
            }
            FastScan::Mask { mask, .. } => {
                let mut bits = super::scan::BitMap::new();
                mask.match_bits(hay, &mut bits);
                let mut out = Vec::new();
                bits.append_offsets(&mut out);
                Offsets::Masked(out.into_iter())
            }
            FastScan::Sub { needle } => Offsets::Masked(sub_offsets(hay, needle)),
        }
    }

    /// Number of capture groups, not counting the whole match.
    pub fn group_count(&self) -> usize {
        self.prog.slots / 2 - 1
    }

    /// The name of each capture group in index order, empty where
    /// unnamed: `group_names()[i-1]` is the name of group `i`. Reads the
    /// table the parser kept so a replacement template's `${name}` has
    /// something to resolve against.
    pub fn group_names(&self) -> &[String] {
        &self.names
    }

    /// Every match in `hay`, left to right, non-overlapping -- the
    /// iteration a replacement runs under. An empty match advances by
    /// one byte, the same convention the `regex` crate's iterator keeps,
    /// so `a*` over `baa` yields empty-at-0 then `aa`, then stops.
    pub fn captures_iter<'a>(&'a self, hay: &'a [u8]) -> CapturesIter<'a> {
        CapturesIter {
            re: self,
            hay,
            at: 0,
            prev_end: None,
        }
    }

    /// Expand `template` against one match, appending to `out`.
    ///
    /// The template language is the one replacements spell: `$$` is a
    /// literal `$`; `$0` the whole match; `$1`.. the groups, by index;
    /// `${N}` and `${name}` the braced spellings, the name resolved
    /// through [`ByteRegex::group_names`]. A reference to a group that
    /// does not exist, or to one that did not participate in the match,
    /// expands to nothing -- the `regex` crate's rule, kept so a
    /// template means the same thing either side of the swap. A `$`
    /// before anything else is that dollar, unchanged.
    pub fn expand(&self, m: &super::vm::Match, template: &[u8], hay: &[u8], out: &mut Vec<u8>) {
        let mut i = 0usize;
        while i < template.len() {
            if template[i] != b'$' {
                let start = i;
                while i < template.len() && template[i] != b'$' {
                    i += 1;
                }
                out.extend_from_slice(&template[start..i]);
                continue;
            }
            i += 1;
            match template.get(i) {
                Some(b'$') => {
                    out.push(b'$');
                    i += 1;
                }
                Some(b'{') => {
                    let start = i + 1;
                    let end = match template[start..].iter().position(|&b| b == b'}') {
                        Some(p) => start + p,
                        // No closing brace: the `{` is literal text.
                        None => {
                            out.push(b'{');
                            i = start;
                            continue;
                        }
                    };
                    let word = &template[start..end];
                    self.expand_group(word, m, hay, out);
                    i = end + 1;
                }
                // **ripgrep's rule, and it is not the `regex` crate's.** A
                // bare `$` takes the WHOLE alphanumeric run as the name, and
                // the run names a group only when every byte of it is a
                // digit. `X$1X` is therefore `X` plus a reference to a group
                // named "1X" -- which does not exist, so nothing -- and
                // `${1}X` is the braced spelling of group 1 and expands to
                // the group's bytes. The crate stops the run at the digits
                // and answers `Xrgx_coreX`; ripgrep answers `X`, and ripgrep
                // is what rgx prints for. (The old code went through the
                // crate, so rgx and rg already differed on exactly this
                // shape.) A reference to a group or name that is not there
                // expands to nothing on both sides.
                Some(&b) if b.is_ascii_alphanumeric() || b == b'_' => {
                    let start = i;
                    while i < template.len()
                        && (template[i].is_ascii_alphanumeric() || template[i] == b'_')
                    {
                        i += 1;
                    }
                    self.expand_group(&template[start..i], m, hay, out);
                }
                // A dollar with nothing referable after it is a dollar.
                _ => out.push(b'$'),
            }
        }
    }

    /// The haystack with its matches replaced by the expanded template, and
    /// how many were. A `count` of zero replaces every match -- the
    /// convention `regex::Replacen` uses, and what `-r` means per line --
    /// and any other count stops after that many, leaving the rest of the
    /// haystack as it was.
    ///
    /// The gaps between matches are copied verbatim, so the answer is the
    /// whole haystack with the matched spans rewritten, not a
    /// concatenation of replacements: `-r` prints a line, and a line with
    /// the tail after the first match intact is the answer `rg` gives.
    pub fn replace(&self, hay: &[u8], template: &[u8], count: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(hay.len());
        let mut at = 0usize;
        let limit = if count == 0 { usize::MAX } else { count };
        for m in self.captures_iter(hay).take(limit) {
            out.extend_from_slice(&hay[at..m.start]);
            self.expand(&m, template, hay, &mut out);
            at = m.end;
        }
        out.extend_from_slice(&hay[at..]);
        out
    }

    /// One reference's bytes: digits name an index, anything else a
    /// group name. Unresolvable or unfilled means empty.
    fn expand_group(&self, word: &[u8], m: &super::vm::Match, hay: &[u8], out: &mut Vec<u8>) {
        let slot = if word.iter().all(|&b| b.is_ascii_digit()) && !word.is_empty() {
            word.iter().fold(0usize, |n, &b| {
                n.saturating_mul(10).saturating_add((b - b'0') as usize)
            })
        } else {
            let name = String::from_utf8_lossy(word);
            match self.names.iter().position(|n| n.as_str() == name.as_ref()) {
                // Group names count from 1 the way groups do.
                Some(i) => i + 1,
                None => return,
            }
        };
        if slot == 0 {
            out.extend_from_slice(&hay[m.start..m.end]);
            return;
        }
        if let Some(Some((s, e))) = m.groups.get(slot - 1) {
            out.extend_from_slice(&hay[*s..*e]);
        }
    }

    /// Every byte any class in the pattern can consume, or `None` when
    /// the pattern cannot consume a byte at all.
    ///
    /// A searcher uses this to skip a line without running the VM: if
    /// the first byte of the line is not a member, no match can start
    /// on it.
    pub fn first_bytes(&self) -> Option<ByteSet> {
        vm::first_bytes(&self.prog)
    }

    /// Whether the pattern can consume at least one byte on some path.
    pub fn consumes(&self) -> bool {
        self.prog.consumes
    }

    /// Whether ANY match begins anywhere in `line`.
    ///
    /// The whole-line confirm, and UNANCHORED: a prefilter built from a
    /// literal at an unknown offset says the match CONTAINS that literal and
    /// not that it starts there, so the confirm has to consider every start
    /// in the line. Anchoring at 0 is the same function with a different
    /// question and it reported 3 of 6,814 lines.
    ///
    /// The `boolean` form where the pattern has a variable-length tail:
    /// whether the match exists does not depend on how far a greedy star
    /// reaches, and on `[a-z]*xyz` the difference is between walking the line
    /// once and walking it to the end.
    fn line_matches(&self, line: &[u8]) -> bool {
        if let Some(dc) = &self.direct {
            return dc.matches_line(line);
        }
        if self.boolean_confirm {
            vm::matches_anywhere(&self.prog, line)
        } else {
            vm::find(&self.prog, line, 0).is_some()
        }
    }
}

/// The non-overlapping match stream behind [`ByteRegex::captures_iter`].
pub struct CapturesIter<'a> {
    re: &'a ByteRegex,
    hay: &'a [u8],
    at: usize,
    /// Where the last REPORTED match ended. An empty match THERE is not
    /// reported: the `regex` crate's rule, and without it `a*` over
    /// `baa` yielded a third, empty match at the end of the haystack.
    prev_end: Option<usize>,
}

impl<'a> Iterator for CapturesIter<'a> {
    type Item = super::vm::Match;

    fn next(&mut self) -> Option<super::vm::Match> {
        loop {
            let m = self.re.search(self.hay, self.at)?;
            let empty = m.start == m.end;
            self.at = if empty { m.end + 1 } else { m.end };
            if empty && self.prev_end == Some(m.start) {
                // An empty match at the end of the previous one is not a
                // new match; the next position is.
                continue;
            }
            self.prev_end = Some(m.end);
            return Some(m);
        }
    }
}

/// Quote `pattern` so the engine reads it as the literal bytes it is.
///
/// This is what a fixed-string search (`-F`) is compiled through: the
/// caller's pattern is data, not syntax, and every byte the parser
/// would otherwise treat as a metacharacter goes out escaped. A byte
/// the parser would read literally goes out unchanged, so the quoting
/// is minimal rather than paranoid.
///
/// The escaped output is itself a pattern: compiling it matches exactly
/// the input bytes and nothing else, which the round-trip test pins.
pub fn escape(pattern: &[u8]) -> Vec<u8> {
    /// What the parser treats as syntax anywhere a byte can appear.
    /// Class-only metacharacters (`]`, `-`) are included because the
    /// escaped text may be embedded into a larger pattern by the caller,
    /// and quoting that only works outside classes is a trap.
    fn meta(b: u8) -> bool {
        matches!(
            b,
            b'\\'
                | b'^'
                | b'$'
                | b'.'
                | b'|'
                | b'?'
                | b'*'
                | b'+'
                | b'('
                | b')'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'-'
        )
    }
    fn hex(nibble: u8) -> u8 {
        if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + nibble - 10
        }
    }
    let mut out = Vec::with_capacity(pattern.len() + 8);
    for &b in pattern {
        if b.is_ascii_alphanumeric() || (!b.is_ascii_control() && !meta(b)) {
            out.push(b);
        } else if meta(b) {
            out.push(b'\\');
            out.push(b);
        } else {
            // Control bytes as `\xNN`: a raw `\` before them would be
            // read as the escape for the NEXT byte's meaning (`\n` is a
            // newline, not `n`), and a raw control byte in a pattern is
            // legal but unreadable.
            out.extend_from_slice(b"\\x");
            out.push(hex(b >> 4));
            out.push(hex(b & 0xF));
        }
    }
    out
}

impl core::fmt::Debug for ByteRegex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ByteRegex")
            .field("source", &String::from_utf8_lossy(&self.source))
            .field("insts", &self.prog.insts.len())
            .field("groups", &self.group_count())
            .finish()
    }
}

impl Matcher for ByteRegex {
    fn find_at(&self, hay: &[u8], at: usize) -> Option<usize> {
        self.search(hay, at).map(|m| m.start)
    }

    fn find_span_at(&self, hay: &[u8], at: usize) -> Option<core::ops::Range<usize>> {
        self.search(hay, at).map(|m| m.start..m.end)
    }

    fn any_match_in(
        &self,
        line: &[u8],
        cands: super::searcher::LineCandidates<'_>,
        origin: super::searcher::Origin,
    ) -> bool {
        match &self.fast {
            // One candidate, one compare: the line is never scanned here, so
            // the buffer costs one mask pass for the whole search rather than
            // one per line. The stream is a superset, so the compare is what
            // turns a fingerprint hit into a match.
            Some(fast) if fast.exact => cands.any(|at| fast.at(line, at)),
            // A *required* literal is evidence, not a match. The stream holds
            // the position of the literal, and the literal sits at a fixed
            // offset from the start of every match, so subtracting recovers
            // where the match has to begin -- and the VM is run anchored
            // THERE, on the rest of the line at most, rather than over the
            // whole line from its first byte.
            //
            // A candidate below `at` names a match that would start before the
            // line does, which cannot be one the searcher reports, so it is
            // declined rather than underflowed.
            //
            // The offset subtracted is the STREAM's, not the pattern's. A
            // pattern with more than one anchor chose one for THIS buffer,
            // and the candidates are positions of whichever was chosen.
            // The pre-confirm, then the VM. Which VM depends on the pattern:
            // `find_at` for a fixed-length one, because the boolean form has
            // nothing to skip and costs a list scan per position to find that
            // out, and `matches_at` where a repetition of unknown length means
            // the extent costs more than the existence. The choice is per
            // line, not per candidate.
            //
            // A prefilter that could not say where the match begins gets the
            // whole line, and the candidates are then a LIVENESS device
            // rather than a filter -- the searcher has already established
            // that this line has at least one, and the confirm cannot use it
            // for anything. This is the expensive shape, and it is only ever
            // reached after a scan that has already narrowed the lines to
            // those holding the literal: `\d+em` is 2.9% of the lines of a
            // Rust corpus, so 3.6 s of confirm per line becomes 68 ms of it.
            // Used as a PREFILTER it would be the 20 s hole, which is why it
            // is a confirm and never a filter.
            Some(fast) => match origin {
                // The pattern is `^`-anchored and the searcher says so, so the
                // start is 0 whatever the candidate said and the candidates are
                // liveness. This is the arm `^ +pub` needs and the one it was
                // missing: its anchor offset is unknown, so it used to take the
                // `Unknown` arm below and scan each candidate line whole.
                super::searcher::Origin::LineStart => {
                    if let FastScan::Mask { mask, .. } = &fast.plan(line).scan {
                        return mask.holds(line, 0);
                    }
                    if let Some(fx) = &self.fixed {
                        return fx.confirm(line, 0);
                    }
                    if let Some(dc) = &self.direct {
                        return dc.confirm(line, 0);
                    }
                    vm::matches_at(&self.prog, line, 0)
                }
                super::searcher::Origin::Unknown => {
                    let _ = fast;
                    self.line_matches(line)
                }
                super::searcher::Origin::Fixed(origin) => {
                    // **A match mask's confirm is the mask, re-evaluated
                    // against the LINE.** Same AND, same five bytes, and exact
                    // in both directions: a bit the line cannot hold is
                    // rejected, and a match the buffer's bits carry at the tail
                    // of a line is kept.
                    //
                    // There is no width cut instead, and the reason is that no
                    // single bound works. The mask is filled over a BUFFER and
                    // one map cannot say which branch of it set a bit, so
                    // `(pub|fn) [a-z]+`'s five- and four-byte branches want a
                    // cut at five and at four respectively: five drops every
                    // `fn x` that ends a line -- and the differential has one --
                    // and four lets a five-byte branch's bit through on a line
                    // three bytes long. Re-running the mask on the line's own
                    // bytes is exact, and costs one AND over five bytes.
                    //
                    // `plan` is asked again here and answers from the
                    // remembered decision -- a line is far shorter than the
                    // buffer the decision was made on, so it is two relaxed
                    // loads and a compare -- and it is asked once per line that
                    // HAS a candidate: 685 877 of `(pub|fn) [a-z]+`'s 7 834 986.
                    if origin == 0 {
                        if let FastScan::Mask { mask, .. } = &fast.plan(line).scan {
                            return cands.any(|at| mask.holds(line, at));
                        }
                        if let Some(fx) = &self.fixed {
                            return cands.any(|at| fx.confirm(line, at));
                        }
                        if let Some(dc) = &self.direct {
                            return cands.any(|at| dc.confirm(line, at));
                        }
                        if self.boolean_confirm {
                            return cands.any(|at| {
                                fast.admits(line, at) && vm::matches_at(&self.prog, line, at)
                            });
                        } else {
                            return cands.any(|at| {
                                fast.admits(line, at) && vm::find_at(&self.prog, line, at).is_some()
                            });
                        }
                    }
                    if let FastScan::Mask { mask, .. } = &fast.plan(line).scan {
                        return cands
                            .any(|at| at.checked_sub(origin).is_some_and(|s| mask.holds(line, s)));
                    }
                    // A fixed-length byte predicate replaces the whole
                    // pre-confirm-plus-VM tail, and it replaces it *whole*:
                    // the checks it skips are necessary conditions read off
                    // the same AST, so a candidate that passes them is not
                    // thereby a match and one that fails them cannot reach
                    // the predicate. Running both would be the VM's answer
                    // with extra steps in front of it.
                    if let Some(fx) = &self.fixed {
                        return cands
                            .any(|at| at.checked_sub(origin).is_some_and(|s| fx.confirm(line, s)));
                    }
                    if let Some(dc) = &self.direct {
                        return cands
                            .any(|at| at.checked_sub(origin).is_some_and(|s| dc.confirm(line, s)));
                    }
                    if self.boolean_confirm {
                        cands.any(|at| {
                            at.checked_sub(origin).is_some_and(|s| {
                                fast.admits(line, s) && vm::matches_at(&self.prog, line, s)
                            })
                        })
                    } else {
                        cands.any(|at| {
                            at.checked_sub(origin).is_some_and(|s| {
                                fast.admits(line, s) && vm::find_at(&self.prog, line, s).is_some()
                            })
                        })
                    }
                }
            },
            // No prefilter at all: every offset is a candidate, so there is
            // nothing to narrow and the VM runs over the line as before.
            None => self.find_span_at(line, 0).is_some(),
        }
    }

    fn is_match_at(&self, hay: &[u8], at: usize) -> bool {
        if let Some(dc) = &self.direct {
            return dc.confirm(hay, at);
        }
        // Anchored: a fresh search with the haystack cut to start at
        // `at` would make `^` mean "start of `at`" rather than "start of
        // the text", which is not what an assertion means. So the search
        // runs over the whole slice and the *result* is required to
        // begin exactly at `at`.
        match self.search(hay, at) {
            Some(m) => m.start == at,
            None => false,
        }
    }

    fn line_anchored(&self) -> bool {
        self.line_anchored
    }

    fn can_match(&self) -> bool {
        // Not `self.prog.consumes`. That flag answers "does the program need at
        // least one byte on some path", which is a different question from the
        // one a searcher is asking: it wants to know whether there is anything
        // to find, and a program that can match the EMPTY string matches at
        // every position, so it finds something on every line.
        //
        // Reporting it the other way made a searcher short-circuit a whole
        // buffer and report nothing for a pattern that matches every line of
        // it. `x*` found 0 lines where grep finds all of them, and the empty
        // pattern -- which the engine matches at every offset, and which
        // `empty_pattern_matches_everywhere` pins -- reported nothing too.
        // A compiled program can always match something, at worst the empty
        // string, so this is true; the case that genuinely cannot match is an
        // empty *literal*, and `LiteralMatcher` says so for itself.
        true
    }

    /// The VM, asked directly rather than through the literal fast path.
    ///
    /// The trait's default routes this through `find_span_at`, which for a
    /// whole-pattern literal goes to `search` and rebuilds the anchor's
    /// `pshufb` tables for an EMPTY haystack. The program is already in hand
    /// and the answer is a walk of it, so that is what this asks -- and it is
    /// asked once per search, by a searcher deciding whether a whole buffer
    /// may be stepped over.
    fn matches_empty(&self) -> bool {
        vm::find(&self.prog, b"", 0).is_some()
    }
}

/// The literal fast path, exposed to a searcher as a candidate stream.
///
/// This is the seam that makes the prefilter reachable: without it
/// `ByteRegex::search` uses the mask internally but a `Searcher` driving the
/// same pattern still asks `is_match_at` at every line, which is the
/// `matches x buffer` cost the mask was built to avoid.
///
/// The stream is a **superset** of the real start offsets — a fingerprint
/// match is not a literal match — so a searcher MUST confirm each candidate
/// with the full matcher. That is what `Searcher::run` does, and the
/// differential test `a_candidate_stream_does_not_change_the_result` is what
/// proves it.
impl super::searcher::CandidateSource for ByteRegex {
    fn candidates<'a>(
        &'a self,
        hay: &'a [u8],
        out: &'a mut Vec<usize>,
    ) -> super::searcher::Candidates<'a> {
        self.stream(hay, out)
    }

    /// The map form of [`Self::fast_candidates_lazy`], and it must agree with
    /// it offset for offset: same anchor, so the same `Origin`, and the same
    /// set of bytes, so the same bits. A disagreement here is a wrong answer
    /// rather than a slow one, which is why the origin comes from the same
    /// `plan` call the lazy stream takes rather than from a second one.
    ///
    /// **The match mask answers here, and the answer says what a bit is.** A
    /// map of one, two or three bytes holds *candidates* and the confirm
    /// decides; a map of a deciding [`super::scan::MatchMask`] holds
    /// *matches*, and the searcher can then settle a line from a bit -- see
    /// [`CandidateSource::map_is_match_mask`](super::searcher::CandidateSource::map_is_match_mask), which is where the width it settles them
    /// with comes from and why it is not the mask's widest branch.
    fn map_candidates(
        &self,
        hay: &[u8],
        out: &mut super::scan::BitMap,
    ) -> Option<super::searcher::Origin> {
        let fast = self.fast.as_ref()?;
        // **The mask answers here, whichever anchor the plan picked for the
        // buffer.** `offer_mask` stores at most one, `mask_anchor` only a
        // DECIDING one, and `match_bits` fills match starts -- so the map and
        // [`Self::map_is_match_mask`] consult the same object. Routing this
        // through the plan's choice sent the `e.`-shape (whose chosen anchor
        // is the one-byte literal `e`) back to the per-line confirm chain.
        for a in &fast.anchors {
            if let FastScan::Mask { mask, .. } = &a.scan {
                mask.match_bits(hay, out);
                return Some(super::searcher::Origin::Fixed(0));
            }
        }
        let anchor = fast.plan(hay);
        let origin = if anchor.known {
            super::searcher::Origin::Fixed(anchor.at)
        } else {
            super::searcher::Origin::Unknown
        };
        if let FastScan::Mask { mask, .. } = &anchor.scan {
            mask.match_bits(hay, out);
            // `Origin::Fixed(0)` is the truth about a mask's bits -- they are
            // match starts in the buffer at offset zero -- and the searcher
            // learns that the CONFIRM is the mask, rather than a scan for a
            // literal, from `CandidateSource::map_is_match_mask`. Those are two
            // different questions and a consumer that inferred one from the
            // other would confirm a mask with the wrong engine.
            return Some(super::searcher::Origin::Fixed(0));
        }
        if let FastScan::Sub { needle } = &anchor.scan {
            if anchor.known && needle.len() >= 2 {
                super::scan::pair_bits(needle, hay, out);
                return Some(origin);
            }
        }
        // Four to eight one-byte needles have no `memchr` form and are filled
        // by ORing the byte-set kernels over groups of three. This is the
        // whole point of the `ByteN` arm: before it a fourth byte fell out of
        // the prefilter here and the caller went back to confirming every line
        // with the Pike VM.
        if let FastScan::ByteN { bytes, count } = &anchor.scan {
            super::scan::byte_bits_many(&bytes[..*count as usize], hay, out);
            return Some(origin);
        }
        let (needles, count): ([u8; 3], usize) = match &anchor.scan {
            FastScan::Byte { a, b } if a == b => ([*a, *b, 0], 1),
            FastScan::Byte { a, b } => ([*a, *b, 0], 2),
            FastScan::Byte3 { a, b, c } => ([*a, *b, *c], 3),
            // A packed mask or an unknown-offset substring: there is no one-to-three byte scan
            // to map, and the caller falls back to `candidates`.
            FastScan::Masked(_) | FastScan::Mask2 { .. } | FastScan::Sub { .. } => return None,
            FastScan::ByteN { .. } => unreachable!("taken above"),
            FastScan::Mask { .. } => unreachable!("taken above"),
        };
        super::scan::byte_bits(&needles, count, hay, out);
        Some(origin)
    }

    /// The pair-anchored needle and its match offset when the scan shape
    /// is `Sub` with a 2+ byte needle.
    fn pair_needle(&self) -> Option<(usize, &[u8])> {
        let fast = self.fast.as_ref()?;
        match &fast.scan {
            FastScan::Sub { needle } if needle.len() >= 2 => {
                let at = fast.anchors.first().map_or(0, |a| a.at);
                Some((at, needle.as_slice()))
            }
            _ => None,
        }
    }

    /// The width [`CandidateSource::map_candidates`](super::searcher::CandidateSource::map_candidates) just cut a line at, or `None` --
    /// which is every prefilter, and is the whole of the previous behaviour.
    ///
    /// **Asked about the same buffer, immediately after that call**, so the
    /// anchor is already measured: `FastLiteral::plan` answers the second
    /// question from the decision the first one made. It is asked a second time
    /// rather than carried out of `map_candidates` because the width is a
    /// property of the MASK and the origin is a property of the STREAM, and
    /// folding one into the other is what the trait's own note warns against.
    ///
    /// **A second `plan` cannot make this the wrong width.** The two answers
    /// can only disagree if a measurement lands between them, and a pattern has
    /// at most one mask anchor (`offer_mask` is called once), so the loser of
    /// that race is either the same mask -- the same width -- or an anchor
    /// that is not a mask, which answers `None` and puts the line back on the
    /// confirm it takes today. Both are slow; neither is wrong.
    fn map_is_match_mask(&self, hay: &[u8]) -> Option<(usize, usize)> {
        let fast = self.fast.as_ref()?;
        // Same object `map_candidates` fills from; the widths are properties
        // of the mask, not of the plan's per-buffer anchor choice.
        for a in &fast.anchors {
            if let FastScan::Mask { mask, .. } = &a.scan {
                return Some((mask.line_cut()?, mask.width()));
            }
        }
        let anchor = fast.plan(hay);
        match &anchor.scan {
            FastScan::Mask { mask, .. } => Some((mask.line_cut()?, mask.width())),
            FastScan::Sub { needle } => {
                if self.whole_literal && anchor.known && anchor.at == 0 && !needle.contains(&b'\n')
                {
                    Some((needle.len(), needle.len()))
                } else {
                    None
                }
            }
            FastScan::Byte { a, b } => {
                if self.whole_literal && a == b && anchor.known && anchor.at == 0 && *a != b'\n' {
                    Some((1, 1))
                } else {
                    None
                }
            }
            FastScan::Byte3 { a, b, c } => {
                if fast.exact
                    && anchor.known
                    && anchor.at == 0
                    && *a != b'\n'
                    && *b != b'\n'
                    && *c != b'\n'
                {
                    Some((1, 1))
                } else {
                    None
                }
            }
            // Same rule as `Byte3`: the alternation is the whole pattern, a
            // hit at offset 0 IS the match, and a one-byte match settles the
            // line. A `\n` in the set would make the one-byte match a line
            // terminator, which is a different question.
            FastScan::ByteN { bytes, count } => {
                let set = &bytes[..*count as usize];
                if fast.exact && anchor.known && anchor.at == 0 && !set.contains(&b'\n') {
                    Some((1, 1))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "regex/tests.rs"]
mod ranged_tests;

#[cfg(test)]
mod single_byte_prefilter_tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use crate::regex::ByteRegex;
    use crate::searcher::CandidateSource;

    /// The one-byte prefilter, against the shapes it has to tell apart.
    ///
    /// This predicate is the half of the engine decision that is about the
    /// pattern, and it is exactly the half that is not enough: `e` and `q` are
    /// both true here and they want opposite engines on the same store. What
    /// separates them is density, which no predicate over a pattern can see.
    /// What the predicate does do is exclude the cases where ripgrep's SIMD
    /// matcher is simply better -- a character class, a case fold, a literal
    /// of two or more bytes -- so the density test is only ever asked about a
    /// shape where `memchr` is the whole of the prefilter.
    #[test]
    fn a_one_byte_prefilter_is_distinguished_from_every_other_scan() {
        // One byte: a `memchr`, whatever is wrapped around it.
        for pat in [&b"e"[..], b"e.", b"a+", b"e[0-9]", b"x{2,4}", b"w"] {
            let r = ByteRegex::new(pat).expect("compiles");
            assert!(
                r.has_single_byte_prefilter(),
                "{:?} should be a one-byte prefilter",
                String::from_utf8_lossy(pat)
            );
        }
        // Two and three bytes are `memchr2` and `memchr3`, which is a
        // different amount of work and lands on the other side of the sweep.
        for pat in [&b"ab"[..], b"pub", b"pub fn", b"a|b|c"] {
            let r = ByteRegex::new(pat).expect("compiles");
            assert!(
                !r.has_single_byte_prefilter(),
                "{:?} is not one byte",
                String::from_utf8_lossy(pat)
            );
        }
        // A class is ripgrep's SIMD class matcher: `[a-z]+` is 2.5x faster
        // there and `\d` is 1.2x, and both are the densest patterns in the
        // sweep, so this is the case the predicate exists to exclude.
        for pat in [&b"[a-z]+"[..], br"\d", b"[0-9]", b"[^x]"] {
            let r = ByteRegex::new(pat).expect("compiles");
            assert!(
                !r.has_single_byte_prefilter(),
                "{:?} is a class, not a literal",
                String::from_utf8_lossy(pat)
            );
        }
        // Case folding is neither engine's, and it is never a candidate.
        let folded = ByteRegex::new_flags(b"(?i)PUB", true).expect("compiles");
        assert!(!folded.has_single_byte_prefilter());
    }

    /// The byte alternation `a|b|c` previously produced two identical
    /// `byte3` anchors -- one from the required-literal pass and one from
    /// the skeleton run -- and the second one only doubled the choice
    /// `plan` runs. The dedup that landed here collapsed the duplicate so
    /// the anchor list is the one a real comparison could prefer.
    #[test]
    fn a_byte_alternation_does_not_double_anchor() {
        for pat in [
            &b"a|b|c"[..],
            &b"a|b"[..],
            &b"x|y|z"[..],
            &b"a|b|c|d"[..],
            &b"a|b|c|d|e|f|g|h"[..],
        ] {
            let r = ByteRegex::new(pat).expect("compiles");
            let info = r.anchor_info();
            let bytes = info
                .iter()
                .filter(|a| matches!(a.kind, "byte" | "byte3" | "byten"))
                .count();
            assert!(
                bytes <= 1,
                "{:?} should keep at most one memchr anchor, got {info:?}",
                String::from_utf8_lossy(pat),
            );
        }
    }

    /// Four to eight one-byte arms used to fall out of the prefilter entirely:
    /// `whole_pattern_byte_alternation` stopped at three and `literal::extract`
    /// refuses a one-byte fingerprint, so `a|b|c|d` got no scan at all and the
    /// Pike VM ran per line on a pattern that is nothing but a set of bytes.
    /// The `ByteN` arm closes that gap, and this asserts both halves: the
    /// prefilter EXISTS, and it agrees with the scanner about which offsets
    /// are candidates.
    #[test]
    fn a_four_to_eight_byte_alternation_has_a_prefilter_that_agrees() {
        // Bare char classes of 2-8 members as well as `|` alternations:
        // `parse_alt` folds an `Alt` of single bytes into one `Ast::Class`
        // (`disjoint_single_byte_class`), so `a|b|c|d` and `[abcd]` arrive
        // at the prefilter as the SAME shape and must not diverge.
        for pat in [
            &b"a|b|c|d"[..],
            &b"a|b|c|d|e"[..],
            &b"w|x|y|z|0|1"[..],
            &b"a|b|c|d|e|f|g|h"[..],
            &b"[abcd]"[..],
            &b"[abcde]"[..],
            &b"[wxyz01]"[..],
            &b"[abcdefgh]"[..],
        ] {
            let r = ByteRegex::new(pat).expect("compiles");
            assert!(
                r.has_prefilter(),
                "{:?} lost its prefilter; a pure byte alternation must keep one",
                String::from_utf8_lossy(pat)
            );
            // Not a single-byte prefilter: that is `memchr`'s shape and this
            // is `memchr2`/`memchr3`/`ByteN`'s.
            assert!(
                !r.has_single_byte_prefilter(),
                "{:?} is more than one byte",
                String::from_utf8_lossy(pat)
            );
            // The prefilter has to FIND the arms. A haystack containing every
            // arm byte and one byte that is none of them.
            let mut hay = b"aqbwecxrydz0s1t".to_vec();
            hay.resize(hay.len() + 200, b'q');
            let mut got = Vec::new();
            r.fast_candidates(&hay, &mut got);
            let set: &[u8] = match pat {
                b"a|b|c|d" | b"[abcd]" => b"abcd",
                b"a|b|c|d|e" | b"[abcde]" => b"abcde",
                b"w|x|y|z|0|1" | b"[wxyz01]" => b"wxyz01",
                b"a|b|c|d|e|f|g|h" | b"[abcdefgh]" => b"abcdefgh",
                other => panic!("unlisted pattern {:?}", String::from_utf8_lossy(other)),
            };
            let want: Vec<usize> = hay
                .iter()
                .enumerate()
                .filter_map(|(i, b)| set.contains(b).then_some(i))
                .collect();
            assert_eq!(
                got,
                want,
                "{:?} prefilter disagreed with the byte set on {:?}",
                String::from_utf8_lossy(pat),
                String::from_utf8_lossy(&hay)
            );
        }
    }

    /// The map form has to be the same answer as the list form, since the
    /// searcher reads the map and the tests read the list. A set of four or
    /// more is filled by ORing the one-to-three kernels in groups, and a
    /// group boundary is exactly where a bug would drop a needle.
    #[test]
    fn a_four_to_eight_byte_alternation_map_agrees_with_the_list() {
        for pat in [
            &b"a|b|c|d"[..],
            &b"a|b|c|d|e"[..],
            &b"w|x|y|z|0|1"[..],
            &b"a|b|c|d|e|f|g|h"[..],
        ] {
            let r = ByteRegex::new(pat).expect("compiles");
            // Haystack long enough to cross several SIMD chunks and the
            // three-needle group boundary.
            let mut hay = Vec::new();
            for i in 0..500u32 {
                let arm = pat[(i as usize) % pat.len()];
                if arm == b'|' {
                    hay.push(b'.');
                } else {
                    hay.push(arm);
                }
            }
            let mut list = Vec::new();
            r.fast_candidates(&hay, &mut list);

            let mut map = crate::scan::BitMap::new();
            let origin = r.map_candidates(&hay, &mut map);
            assert!(
                origin.is_some(),
                "{:?} produced no map",
                String::from_utf8_lossy(pat)
            );
            let mut mapped = Vec::new();
            map.append_offsets(&mut mapped);
            assert_eq!(
                list,
                mapped,
                "{:?} map and list disagreed",
                String::from_utf8_lossy(pat)
            );
        }
    }

    /// A short alternation branch that ends at the end of the haystack is
    /// found beside a longer one -- the regression pin for the scan bound
    /// that once dropped it.
    ///
    /// The shape:
    ///
    /// ```text
    /// rgx 'ab|cde'  ->  "ab"  match          <- the short branch at the end
    /// rgx 'ab|cde'  ->  "abx" match
    /// ```
    ///
    /// The unanchored scan used to bound its candidate start positions by
    /// the LONGEST branch, so a shorter branch whose match finished at the
    /// last byte was never tried. `a|bc` against `"a"` was fine, and
    /// `abc|de` against `"abc"` was fine; what failed was a short branch
    /// meeting the end of the haystack while a longer branch exists.
    ///
    /// That defect is why `unicode_case::fold_char` used to narrow a fold to
    /// one UTF-8 width: `ß` folds to `{ß, SS}`, branches of two and three
    /// bytes, precisely this shape, and folding it would have stopped `ß`
    /// matching a line that is nothing but `ß`. The narrowing is gone with
    /// the defect, and the fold reaching KELVIN SIGN depends on this test
    /// staying green.
    #[test]
    fn a_short_branch_at_the_haystack_end_is_found_beside_a_longer_one() {
        use crate::matcher::Matcher as _;
        let r = ByteRegex::new_flags(b"ab|cde", false).expect("compiles");
        assert!(
            r.find_at(b"abx", 0).is_some(),
            "the pattern matches when the match is not at the end"
        );
        assert!(
            r.find_at(b"ab", 0).is_some(),
            "and the short branch is found when it ends at the haystack end"
        );
    }

    #[test]
    fn unicode_case_insensitive_matching() {
        use crate::matcher::Matcher as _;
        // Latin with diacritics
        let r_cafe = ByteRegex::new_flags("café".as_bytes(), true).expect("compiles");
        assert!(
            r_cafe.find_at("CAFÉ".as_bytes(), 0).is_some(),
            "café matches CAFÉ"
        );
        assert!(
            r_cafe.find_at("Café".as_bytes(), 0).is_some(),
            "café matches Café"
        );
        assert!(
            r_cafe.find_at("café".as_bytes(), 0).is_some(),
            "café matches café"
        );
        assert!(
            r_cafe.find_at("caf".as_bytes(), 0).is_none(),
            "café does not match caf"
        );

        // Greek
        let r_greek = ByteRegex::new_flags("σῖγμα".as_bytes(), true).expect("compiles");
        assert!(
            r_greek.find_at("Σῖγμα".as_bytes(), 0).is_some(),
            "σῖγμα matches Σῖγμα"
        );

        // Cyrillic
        let r_cyr = ByteRegex::new_flags("привет".as_bytes(), true).expect("compiles");
        assert!(
            r_cyr.find_at("ПРИВЕТ".as_bytes(), 0).is_some(),
            "привет matches ПРИВЕТ"
        );
        assert!(
            r_cyr.find_at("Привет".as_bytes(), 0).is_some(),
            "привет matches Привет"
        );

        // Same byte length in both cases, so the fold is searchable: an alternation
        // whose branches all have the SAME length is the shape the Pike VM
        // handles. See `CaseVariants::uniform_len` for the ones that are not.
        //
        // A match that ends at the last byte of the line is included on
        // purpose, because that is exactly where a shorter branch would be
        // lost if the two lengths differed.
        assert!(
            r_cafe.find_at("x CAFÉ".as_bytes(), 0).is_some(),
            "café matches CAFÉ at the end of the haystack"
        );
    }

    /// A multi-character case mapping must match as a sequence.
    ///
    /// This is the regression that made the first version of `unicode_case`
    /// wrong. Case variants were stored as single *characters*, but a full
    /// Unicode case mapping is a *sequence*: `ß` uppercases to `SS`. Pushing
    /// each character of that sequence as its own variant turned it into a
    /// union, so `(?i)ß` compiled to `Alt[Concat[C3,9F], Class(53)]` and
    /// matched any line containing one capital `S`. `İ` lowercases to `i`
    /// plus U+0307 and did the same with the combining dot.
    ///
    /// Both are false *positives* on the default `-i` path of a release
    /// build -- wrong answers rather than missing ones, which is the worst
    /// failure mode a search tool has.
    #[test]
    fn multi_character_case_mapping_matches_as_a_sequence_not_a_union() {
        use crate::matcher::Matcher as _;

        let sharp_s = ByteRegex::new_flags("ß".as_bytes(), true).expect("compiles");
        assert!(
            sharp_s.find_at("ß".as_bytes(), 0).is_some(),
            "ß matches itself"
        );
        assert!(
            sharp_s.find_at("Straße".as_bytes(), 0).is_some(),
            "ß matches inside Straße"
        );
        assert!(
            sharp_s.find_at("The S is here".as_bytes(), 0).is_none(),
            "ß must not match a bare capital S -- this is the bug"
        );
        // `SS` is ß's FULL uppercase mapping, and simple folding does not
        // contain it. So `rgx -i 'ß'` does not reach `STRASSE` -- which is
        // what ripgrep does too, and the difference from the previous
        // revision of this file. The bare `S` is still refused, and now for
        // the ordinary reason rather than because a sequence was split.
        assert!(
            !sharp_s.find_at("SS".as_bytes(), 0).is_some(),
            "ß does not match SS: simple folding has no SS entry"
        );
        assert!(
            !sharp_s.find_at("x STRASSE y".as_bytes(), 0).is_some(),
            "ß does not match STRASSE, matching ripgrep"
        );

        let dotted_i = ByteRegex::new_flags("\u{0130}".as_bytes(), true).expect("compiles");
        assert!(
            dotted_i.find_at("\u{0130}".as_bytes(), 0).is_some(),
            "İ matches itself"
        );
        assert!(
            dotted_i.find_at("plain i here".as_bytes(), 0).is_none(),
            "İ must not match a bare i"
        );
        assert!(
            dotted_i
                .find_at("a lone \u{307} dot".as_bytes(), 0)
                .is_none(),
            "İ must not match a bare combining dot -- this is the bug"
        );
        // `İ` lowercases to `i` + U+0307 in the FULL mapping; simple folding has
        // no entry for it, so it does not fold at all.
        assert!(
            !dotted_i.find_at("i\u{307}".as_bytes(), 0).is_some(),
            "İ does not fold: simple folding has no entry for U+0130"
        );

        let ligature = ByteRegex::new_flags("\u{FB01}".as_bytes(), true).expect("compiles");
        assert!(
            ligature.find_at("\u{FB01}".as_bytes(), 0).is_some(),
            "ﬁ matches itself"
        );
        assert!(
            ligature.find_at("F".as_bytes(), 0).is_none(),
            "ﬁ must not match a bare F"
        );
        // `ﬁ` uppercases to `FI` in the FULL mapping only; simple folding leaves it.
        assert!(
            !ligature.find_at("FI".as_bytes(), 0).is_some(),
            "ﬁ does not fold to FI: simple folding has no entry for U+FB01"
        );
    }

    /// Differential against the `regex` crate, which is the only oracle
    /// left in this tree -- `differential.rs` and the `grep-searcher`
    /// dev-dependency were removed when the grep dependencies were dropped.
    ///
    /// The two engines fold differently and the difference is a decision,
    /// not an accident: `regex` uses *simple* case folding
    /// (`CaseFolding.txt`), rgx uses *full* case mapping
    /// (`char::to_lowercase`/`to_uppercase`, i.e. `SpecialCasing.txt`). This
    /// test pins the cases where they agree, so a future change to either
    /// side that moves one of them trips here rather than surfacing as a
    /// silent difference in a user's search. The disagreements are asserted
    /// explicitly below, with the behaviour stated rather than left for a
    /// reader to discover.
    #[test]
    fn case_folding_is_differential_against_the_regex_crate() {
        use crate::matcher::Matcher as _;

        // Agreeing set. Pattern, haystack, and whether it must match.
        let agree: &[(&str, &str, bool)] = &[
            ("é", "café", true),
            ("é", "CAFÉ", true),
            ("é", "cafe", false),
            ("Σ", "σ", true),
            ("σ", "Σ", true),
            ("привет", "ПРИВЕТ", true),
            ("привет", "Привет", true),
            ("ß", "ß", true),
            // A match ending at the last byte, which is exactly where a
            // shorter branch would be lost if branch lengths differed.
            ("é", "CAFÉ", true),
        ];

        for (pat, hay, expected) in agree {
            let mine = ByteRegex::new_flags(pat.as_bytes(), true).expect("compiles");
            let got = mine.find_at(hay.as_bytes(), 0).is_some();
            let theirs = regex::RegexBuilder::new(&regex::escape(pat))
                .case_insensitive(true)
                .build()
                .expect("oracle compiles")
                .is_match(hay);
            assert_eq!(
                got, *expected,
                "rgx vs expectation for (?i){pat:?} against {hay:?}"
            );
            assert_eq!(
                got, theirs,
                "rgx disagrees with the regex crate for (?i){pat:?} against {hay:?}"
            );
        }
    }

    /// The disagreements, stated rather than left for a reader to find.
    /// Each is a place rgx and ripgrep answer differently today.
    ///
    /// The final-sigma row is the one that costs a *miss*: `regex` applies
    /// the Greek rule and folds `ς` to `σ`, so ripgrep finds `ς` and rgx
    /// does not. That breaks the superset property for Greek patterns under
    /// `-i`. It did not hold for these patterns before this feature either
    /// -- ASCII-only folding did not reach `ς` either -- so this is not a
    /// regression, it is the boundary of what `char::to_lowercase` can
    /// answer. Matching `regex` exactly needs the `CaseFolding.txt` simple
    /// table and the conditional final-sigma rule, which is a separate piece
    /// of work with its own measurement.
    /// The escaped and bare spellings of `é` now agree under `(?i)`.
    ///
    /// `\é` used to fold through `case_variant`, which knows only `a-z`, so
    /// it matched `é` and could not match `É` while the bare literal matched
    /// both. A silent disagreement between two spellings of one character,
    /// in a default-built release binary.
    #[test]
    fn escaped_and_bare_non_ascii_fold_the_same_way() {
        use crate::matcher::Matcher as _;
        for pattern in ["\u{e9}".as_bytes(), b"\\\xc3\xa9"] {
            let r = ByteRegex::new_flags(pattern, true).expect("compiles");
            for (hay, want) in [
                ("\u{e9}", true),
                ("\u{c9}", true),
                ("CAF\u{c9}", true),
                ("cafe", false),
            ] {
                assert_eq!(
                    r.find_at(hay.as_bytes(), 0).is_some(),
                    want,
                    "{pattern:?} against {hay:?}"
                );
            }
        }
    }

    /// `[é]` is one character, must match one character, and must NOT case-fold
    /// without `(?i)`.
    ///
    /// A `ByteSet` is one byte per position, so the class used to collect
    /// 0xC3 and 0xA9 as two independent members and match a lone `Ã`, a
    /// lone `©`, and any two-byte UTF-8 sequence with lead byte 0xC3. That
    /// over-match has no connection to `(?i)`; it predates this work.
    ///
    /// The `É` and `È` rows are a regression an earlier attempt in this same
    /// change introduced: the lowered class called `fold_char` unconditionally,
    /// so a case-SENSITIVE `[é]` matched `É`, and `^[é]$` reported uppercase
    /// lines. A class that folds without being asked to is the opposite of
    /// what a character class is for.
    #[test]
    fn a_class_of_one_multibyte_character_matches_one_character() {
        use crate::matcher::Matcher as _;
        let r = ByteRegex::new_flags("[\u{e9}]".as_bytes(), false).expect("compiles");
        assert!(r.find_at("\u{e9}".as_bytes(), 0).is_some(), "[é] matches é");
        assert!(
            r.find_at("x \u{e9} y".as_bytes(), 0).is_some(),
            "[é] inside a line"
        );
        for (hay, why) in [
            ("\u{c3}", "a lone Ã is byte 0xC3"),
            ("\u{a9}", "a lone © is byte 0xA9"),
            (
                "\u{c1}",
                "Á is C3 81: lead byte is a class member, the pair is not",
            ),
            (
                "\u{c3}\u{a9}",
                "Ã© is C3 A9: the two bytes, not the character",
            ),
            ("cafe", "ASCII must not match"),
            ("\u{c9}", "É is not é, and there is no (?i)"),
            ("\u{c8}", "È is not é either"),
        ] {
            assert!(
                !r.find_at(hay.as_bytes(), 0).is_some(),
                "[é] wrongly matched, {why}: {hay:?}"
            );
        }
        let folded = ByteRegex::new_flags("[\u{e9}]".as_bytes(), true).expect("compiles");
        assert!(
            folded.find_at("\u{c9}".as_bytes(), 0).is_some(),
            "(?i)[é] matches É"
        );
        assert!(
            !folded.find_at("\u{c3}".as_bytes(), 0).is_some(),
            "(?i)[é] still must not match a lone Ã"
        );
    }

    /// An explicit `\xNN` byte that happens to equal one of a multi-byte
    /// character's bytes is still its own member.
    ///
    /// `[\xA9é]` has two members. 0xA9 is inside é's encoding, so "no byte
    /// of the set lies outside the character" is true and is NOT sufficient:
    /// taking the character path dropped the named byte and the class stopped
    /// matching it. The member count is what separates the two cases.
    #[test]
    fn an_explicit_byte_inside_a_character_is_still_its_own_member() {
        use crate::matcher::Matcher as _;
        let patterns: [&[u8]; 2] = [b"[\\xA9\xc3\xa9]", b"[\xc3\xa9\\xA9]"];
        for pattern in patterns {
            let r = ByteRegex::new_flags(pattern, false).expect("compiles");
            assert!(
                r.find_at(b"\xA9", 0).is_some(),
                "{pattern:?} must still match the explicit \\xA9 byte"
            );
            assert!(
                r.find_at("\u{e9}".as_bytes(), 0).is_some(),
                "{pattern:?} must still match é"
            );
        }
    }

    /// `[\é]` -- an escaped character inside a class -- still over-matches, and
    /// that is NOT fixed here. Pinned so the defect stays visible.
    ///
    /// `é` and `(?i)\é` were made to agree by the escaped-character fold, and
    /// this is the fourth spelling, which they do not. A class does not go
    /// through `parse_escape` at all: `class_item` carries its own escape
    /// table and hands back one byte per member, so the escaped character
    /// lands as {0xC3, 0xA9} and matches `ü` (C3 BC).
    ///
    /// Fixing it means the class has to know a member is a character, which is
    /// the same `ByteSet`-cannot-express-a-sequence problem as the other
    /// class tests here.
    #[test]
    #[ignore = "class_item has its own escape path and a ByteSet cannot hold a character"]
    fn an_escaped_character_inside_a_class_over_matches() {
        use crate::matcher::Matcher as _;
        let r = ByteRegex::new_flags("[\\\u{e9}]".as_bytes(), false).expect("compiles");
        assert!(
            !r.find_at("\u{fc}".as_bytes(), 0).is_some(),
            "[\\é] must not match ü (C3 BC)"
        );
        assert!(
            r.find_at("\u{e9}".as_bytes(), 0).is_some(),
            "[\\é] should match é"
        );
    }

    /// `[^…]` with a multi-byte character still over-matches, and that is NOT
    /// fixed here. Pinned so the defect stays visible.
    ///
    /// `[^é]` has to mean "any single byte that is not the character é",
    /// which is not a question a `ByteSet` can answer: negation over a
    /// sequence has no byte-set meaning. It stays byte-wise and matches a
    /// lone `Ã` and a lone `©`, as it always has.
    ///
    /// An earlier attempt in this change advanced the cursor past the whole
    /// character even when negated, which left the continuation bytes out of
    /// `set` and made `negate()` leave them IN -- so `[^é]` matched `é`. The
    /// advance is conditional on `!negated` now, which restores the old
    /// behaviour rather than a worse one.
    #[test]
    #[ignore = "needs negation over a sequence, which ByteSet cannot express"]
    fn a_negated_class_of_a_multibyte_character_over_matches() {
        use crate::matcher::Matcher as _;
        let r = ByteRegex::new_flags("[^\u{e9}]".as_bytes(), false).expect("compiles");
        assert!(
            !r.find_at("\u{e9}".as_bytes(), 0).is_some(),
            "[^é] must not match é"
        );
        assert!(
            !r.find_at("\u{c3}".as_bytes(), 0).is_some(),
            "[^é] must not match a lone Ã"
        );
    }

    /// A class mixing ASCII and a multi-byte character still over-matches,
    /// and that is NOT fixed here. Pinned so the defect stays visible.
    ///
    /// `[a-zé]` has to mean "a-z, A-Z, é, É": a 26-way one-byte set beside a
    /// two-byte character. `Ast::Class` compiles to one `Inst::Byte`, so the
    /// only in-model shape is an alternation mixing one-byte and two-byte
    /// branches -- and the Pike VM loses a shorter branch that ends at the
    /// end of the haystack, so that shape is not safe to emit yet.
    ///
    /// Fixing it is two changes in order: the scan bound in `vm::run`, then
    /// an `Ast` able to express "a set OR a sequence", including what `[^…]`
    /// means over a sequence, which `ByteSet::negate` has no answer for.
    #[test]
    #[ignore = "needs an Ast mixing a ByteSet with sequences, and a Pike VM that can search unequal-length alternation branches"]
    fn a_class_mixing_ascii_and_a_multibyte_character_over_matches() {
        use crate::matcher::Matcher as _;
        let r = ByteRegex::new_flags("[a-z\u{e9}]".as_bytes(), false).expect("compiles");
        assert!(
            !r.find_at("\u{c1}".as_bytes(), 0).is_some(),
            "[a-zé] should not match Á (C3 81), whose lead byte is a class member"
        );
        assert!(
            r.find_at("\u{e9}".as_bytes(), 0).is_some(),
            "and it should match é itself"
        );
    }

    /// Case folding agrees with the `regex` crate across the width shapes
    /// that used to diverge.
    ///
    /// The old divergences were the same defect in different characters: the
    /// table folds pairs whose two characters are different numbers of UTF-8
    /// bytes (`ß`/`ẞ` at two and three, `k`/KELVIN SIGN at one and three),
    /// and an unanchored scan that bounded candidate starts by the longest
    /// alternation branch missed a shorter branch at the haystack end. The
    /// scan is fixed and `fold_char` now emits the whole class, so the
    /// former false negatives are agreements and are asserted as such
    /// against the oracle. What remains a divergence is only the class
    /// over-matching of the three ignored tests above -- a `ByteSet` class
    /// collecting a multi-byte character's bytes independently.
    ///
    /// The direction that is NOT taken is the other one: folding with
    /// `char::to_lowercase` is the FULL mapping, where `rgx -i 'ß'` would
    /// report `STRASSE`, which ripgrep passes over. A search tool that
    /// reports a line ripgrep ignores is worse than one that misses it.
    #[test]
    fn case_folding_reaches_every_width_the_oracle_does() {
        use crate::matcher::Matcher as _;

        // The Greek final sigma, which is now agreement rather than a
        // divergence. Before the table, rgx folded with `char::to_lowercase`
        // and reached neither ς nor the pair; with `CaseFolding.txt` it folds
        // ς to σ, which is what `regex` does too -- including mid-word,
        // where the conditional Final_Sigma rule in UAX #29 would *not*
        // match. Both engines match "αςβ", so the conditional rule is not a
        // difference between them and not a divergence to record.
        let sigma = ByteRegex::new_flags("Σ".as_bytes(), true).expect("compiles");
        let oracle = regex::RegexBuilder::new(&regex::escape("Σ"))
            .case_insensitive(true)
            .build()
            .expect("oracle compiles");
        assert!(
            sigma.find_at("ς".as_bytes(), 0).is_some(),
            "rgx folds ς to σ, matching the table"
        );
        for hay in ["ς", "αςβ", "Σ", "σ"] {
            assert_eq!(
                sigma.find_at(hay.as_bytes(), 0).is_some(),
                oracle.is_match(hay),
                "rgx and the oracle disagree on {hay:?}"
            );
        }

        // ß and ẞ fold together in the table -- two bytes against three --
        // and the wider member is no longer dropped.
        let sharp_s = ByteRegex::new_flags("ß".as_bytes(), true).expect("compiles");
        let oracle = regex::RegexBuilder::new(&regex::escape("ß"))
            .case_insensitive(true)
            .build()
            .expect("oracle compiles");
        for hay in ["ẞ", "ß", "SS", "STRASSE"] {
            assert_eq!(
                sharp_s.find_at(hay.as_bytes(), 0).is_some(),
                oracle.is_match(hay),
                "rgx and the oracle disagree on {hay:?}"
            );
        }

        // Same shape: KELVIN SIGN U+212A is three bytes, `k` is one, and
        // the sign is reached -- `rgx -i 'kelvin'` finds KELVIN the way
        // ripgrep does.
        let kelvin = ByteRegex::new_flags("k".as_bytes(), true).expect("compiles");
        let oracle = regex::RegexBuilder::new(&regex::escape("k"))
            .case_insensitive(true)
            .build()
            .expect("oracle compiles");
        for hay in ["K", "k", "\u{212A}", "x"] {
            assert_eq!(
                kelvin.find_at(hay.as_bytes(), 0).is_some(),
                oracle.is_match(hay),
                "rgx and the oracle disagree on {hay:?}"
            );
        }
        let word = ByteRegex::new_flags("kelvin".as_bytes(), true).expect("compiles");
        assert!(
            word.find_at("\u{212A}ELVIN".as_bytes(), 0).is_some(),
            "the whole word reaches the sign in the first letter of it"
        );
    }
}
