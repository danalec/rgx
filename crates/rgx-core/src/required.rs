// SPDX-License-Identifier: Apache-2.0

//! Which bytes a pattern **requires**, read off its AST.
//!
//! A prefilter may produce false positives and may never produce a
//! false negative, so the analysis below reports only bytes **every**
//! match contains at an offset that is the **same in every match**.
//! `e.` requires an `e` at offset 0; `foo.*bar` requires `foo` at
//! offset 0; `[ab]lpha` requires `lpha` at offset 1. None of them is
//! a literal, and all of them had no prefilter before this — which is
//! why `e.` paid a full Pike VM run per line.
//!
//! With an exact offset, the candidate stream can hand the engine the
//! offset of the literal and the engine can recover the match start by
//! subtracting, then confirm with an anchored run of the VM. Without
//! one — `a*b`, where `b` is at offset 0 or at offset 3 — a candidate
//! at `p` tells the engine nothing about where the match began.
//!
//! `a|b` yields nothing: the branches share no byte. `a?bc` yields
//! nothing: the `a` is optional, and the `bc` that follows it is at
//! offset 0 or at offset 1.

use alloc::vec::Vec;

use super::syntax::Ast;

/// The longest literal handed back. Long enough for `pub fn` and its
/// ilk, short enough that the confirm's tail compare stays a handful
/// of bytes. The mask's *fingerprint* is capped separately and much
/// lower ([`super::literal::MAX_FINGERPRINT`]); this is the needle, not
/// the fingerprint.
pub const MAX_LITERAL: usize = 24;

/// One required literal, and where in a match it has to sit.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Required {
    /// The bytes, as the pattern spells them.
    pub bytes: Vec<u8>,
    /// Whether matching them ignores ASCII case.
    pub caseless: bool,
    /// The offset from the start of **every** match at which `bytes` appear.
    ///
    /// Not a lower bound. An offset a match *may* sit at cannot be used to
    /// recover a match's start from a literal's position, and recovering the
    /// start is what turns a cheap `memchr` into an anchored confirm; see the
    /// module header.
    pub at: usize,
}

/// A set of literals, every one of which is required at [`Prefilter::Alt`]'s
/// own offset.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AltLiterals {
    /// The exact offset, shared by every literal.
    pub at: usize,
    /// The alternatives. At least two.
    pub lits: Vec<Required>,
}

/// What the analysis found.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Prefilter {
    /// Nothing every match is known to contain. The engine runs as before.
    None,
    /// One required literal at an exact offset.
    One(Required),
    /// Several required literals, all at the same exact offset — the shape
    /// an alternation leaves behind when its branches share no single byte.
    Alt(AltLiterals),
}

impl Prefilter {
    /// Whether anything was found.
    #[must_use]
    pub fn is_none(&self) -> bool {
        matches!(self, Prefilter::None)
    }
}

// ---------------------------------------------------------------------------
// The match mask
// ---------------------------------------------------------------------------

/// One required byte-set at an offset, as the mask producer wants it.
///
/// The difference from [`Entry`] is the class, not the offset. An
/// `Entry` is capped at [`MAX_ALTS`] members because a *scan* for a wide
/// set is a membership test per candidate; a `pshufb` pair answers
/// "is this byte one of these 256" in three instructions whatever
/// the width, so the cap has no reason to exist here.
///
/// Nor is there a `caseless` flag: a `(?i)` class parses to a set
/// holding both ASCII cases, so the class IS the fold and a consumer
/// cannot get it wrong by forgetting to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MaskStep {
    /// The offset from the start of a match, in bytes.
    pub at: usize,
    /// The bytes the byte at `at` has to be one of.
    pub class: super::scan::ByteClass,
}

/// One way a match can start: these bytes, at these offsets, all of them.
pub type MaskBranch = Vec<MaskStep>;

/// The set of offsets where a match can start, as an AND of byte
/// classes per branch.
///
/// `decides` is the difference between a prefilter and a mask. A
/// prefilter's offsets are *candidates*: every match starts at one
/// of them and a confirm decides which. A mask that DECIDES has
/// offsets that are matches — the branch set is the answer, and a
/// consumer can settle a line from a bit without calling the engine.
/// Both are built the same way; only the claim differs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MaskPlan {
    /// The ways a match can start, at least one.
    pub branches: Vec<MaskBranch>,
    /// Whether a branch's steps are the WHOLE of what a match must hold, so a
    /// bit is a match rather than a candidate.
    pub decides: bool,
}

/// The most bytes one mask branch may name. A cap, not a derivation:
/// past this a pattern is better served by the substring scan, and
/// [`super::regex::ByteRegex`] prices the two against each other.
pub const MAX_MASK_STEPS: usize = 8;

/// The set of offsets where a match of `ast` can start, or `None` when the
/// pattern is not a straight path.
///
/// The shape it accepts is much wider than [`skeleton`]:
/// - a class of any width, with none of [`MAX_ALTS`]'s business (a `pshufb`
///   pair is width-256);
/// - an alternation, one branch per alternative, at offsets that DIFFER
///   between branches: `pub` is three bytes and `fn` is two, so the space
///   behind them is at offset 3 in one branch and at offset 2 in the other;
/// - a mandatory repetition of a fixed-length body, at the END of the
///   pattern: `(pub|fn) [a-z]+` is the whole of it.
///
/// What it refuses, each for its own reason:
/// - an assertion. `^` is the start of a LINE to the searcher and the start
///   of a BUFFER to the mask, and a mask that read it the wrong way
///   would report a match on a line that has none;
/// - a repetition that is not the tail, which is a barrier: everything
///   behind it slides, so the mask keeps what came before and stops
///   being exact;
/// - a pattern that can match the empty string, because then it matches
///   at every offset and there is no set of offsets left to hold.
#[must_use]
pub fn match_mask(ast: &Ast) -> Option<MaskPlan> {
    let (branches, decides) = lower(ast)?;
    // An empty branch is a match of zero length, which means the
    // pattern matches at every offset: the mask would be all-ones.
    if branches.is_empty() || branches.iter().any(Vec::is_empty) {
        return None;
    }
    Some(MaskPlan { branches, decides })
}

/// The pattern lowered to branch sets, and whether the lowering is exact.
///
/// `None` is a refusal, never a partial answer -- so nothing half-lowered is
/// ever used.
fn lower(ast: &Ast) -> Option<(Vec<MaskBranch>, bool)> {
    match ast {
        Ast::Empty => Some((vec![Vec::new()], true)),
        Ast::Assert(_) => None,
        Ast::Class(set) => {
            let mut class = super::scan::ByteClass::empty();
            for b in set.iter() {
                class.insert(b);
            }
            if class.is_empty() {
                return None;
            }
            Some((vec![alloc::vec![MaskStep { at: 0, class }]], true))
        }
        // A CAPTURING group is invisible here, and refusing it would refuse
        // `(pub|fn) [a-z]+` -- the pattern the mask exists for -- because a
        // group is capturing unless it is spelled `(?:...)`. A capture changes
        // where group 1 is, not whether a match exists or where it begins,
        // and the mask answers exactly the second question: it is read by the
        // searcher to settle a LINE. `super::fixed` refuses captures for the
        // opposite reason -- it builds a `Match` with a group list, and there
        // the difference is the whole answer.
        // A group is a boundary for EXACTNESS, and passing its content's
        // `d` straight through is how `(\w+)=(\w+)` came to claim the
        // `=` sits at offset 1. The repeat arm returns `true` when its
        // steps fit a mask -- the steps ARE required of every match, one
        // iteration or fifty -- and the concat above reads that same `d`
        // as "the next sibling's offset is known". A `+` has no fixed
        // length, so a group wrapping one must not say otherwise: the
        // match `bb=22` has no mask bit at its true start (4) because the
        // mask wants `=` at 1, and the search answered (5, 9) where the
        // leftmost-first answer is (4, 9).
        //
        // The bare-repeat case in `lower_concat` already declines this
        // ("Anywhere else it is a barrier") and the tail case is
        // genuinely exact; a group is the middle case wearing the
        // tail's clothes.
        Ast::Group { node, .. } => {
            let (v, d) = lower(node)?;
            let variable = matches!(&**node, Ast::Repeat { min, max, .. }
                if max.is_none_or(|m| m != *min));
            Some((v, d && !variable))
        }
        Ast::Alt(branches) => {
            let mut out: Vec<MaskBranch> = Vec::new();
            let mut decides = true;
            for b in branches {
                let (v, d) = lower(b)?;
                out.extend(v);
                decides &= d;
            }
            Some((out, decides))
        }
        Ast::Concat(items) => lower_concat(items),
        Ast::Repeat { node, min, .. } => {
            // A repetition that is the WHOLE pattern. One iteration is
            // required, and with nothing behind it one is sufficient,
            // but `min` is not always one: `a{2,5}` needs two.
            if *min == 0 {
                return Some((vec![Vec::new()], true));
            }
            let (v, d) = lower(node)?;
            if !d || v.iter().any(Vec::is_empty) {
                return Some((v, false));
            }
            let out = repeat(&v, *min as usize);
            let sized = out.iter().all(|b| b.len() <= MAX_MASK_STEPS);
            Some((out, sized))
        }
    }
}

/// A concatenation, left to right, stopping at the first thing that slides.
fn lower_concat(items: &[Ast]) -> Option<(Vec<MaskBranch>, bool)> {
    let n = items.len();
    let mut cur: Vec<MaskBranch> = alloc::vec![Vec::new()];
    for (i, item) in items.iter().enumerate() {
        if let Ast::Repeat { node, min, .. } = item {
            let (body, body_exact) = match lower(node) {
                Some(v) => v,
                // A body that will not lower requires nothing of its own.
                None => return Some((cur, false)),
            };
            if *min >= 1 && body_exact && !body.iter().any(Vec::is_empty) {
                // `min` iterations, laid end to end. At the TAIL that is
                // exact: the match needs them. Anywhere else it is a
                // barrier.
                let tail = i + 1 == n;
                cur = if tail {
                    cross(&cur, &repeat(&body, *min as usize))
                } else {
                    cross(&cur, &body)
                };
                if tail && cur.iter().all(|b| b.len() <= MAX_MASK_STEPS) {
                    continue;
                }
                return Some((cur, false));
            }
            return Some((cur, false));
        }
        let (v, d) = lower(item)?;
        // A non-exact item is still crossed — every step in it is at an
        // exact offset of its own branch, so it is still required of
        // every match — and only the claim changes.
        cur = cross(&cur, &v);
        if !d {
            return Some((cur, false));
        }
        if cur.len() > super::scan::MAX_MASK_BRANCHES
            || cur.iter().any(|b| b.len() > MAX_MASK_STEPS)
        {
            return Some((cur, false));
        }
    }
    Some((cur, true))
}

/// Every alternative of `add` appended to every branch of `cur`, each at
/// the offset that branch's own width puts it.
///
/// The width is PER BRANCH, and that is the whole point. `pub` is
/// three bytes and `fn` is two, so the space behind the alternation
/// is at offset 3 in one branch and at offset 2 in the other. An
/// analysis that reported one offset for both would have to scan
/// for the space instead of ANDing it.
fn cross(cur: &[MaskBranch], add: &[MaskBranch]) -> Vec<MaskBranch> {
    let mut out = Vec::with_capacity(cur.len() * add.len());
    for a in cur {
        let w = width_of(a);
        for b in add {
            let mut v = Vec::with_capacity(a.len() + b.len());
            v.extend_from_slice(a);
            for s in b {
                v.push(MaskStep {
                    at: w + s.at,
                    class: s.class,
                });
            }
            out.push(v);
        }
    }
    out
}

/// The body repeated `times`, end to end.
fn repeat(body: &[MaskBranch], times: usize) -> Vec<MaskBranch> {
    let mut out = Vec::with_capacity(body.len());
    for b in body {
        let w = width_of(b);
        let mut v = Vec::with_capacity(b.len() * times);
        for k in 0..times {
            for s in b {
                v.push(MaskStep {
                    at: s.at + k * w,
                    class: s.class,
                });
            }
        }
        out.push(v);
    }
    out
}

/// How many bytes a branch reaches over: one past its last required byte.
fn width_of(b: &[MaskStep]) -> usize {
    b.iter().map(|s| s.at + 1).max().unwrap_or(0)
}

/// The longest literal that EVERY match contains, at an offset nothing
/// knows. The other half of the analysis: an exact offset is not
/// always available, but the offset is not the only useful fact.
///
/// A literal at an unknown offset is still a good thing to SCAN for.
/// What it is not is a thing to CONFIRM with: a candidate at `p` does
/// not say where the match began, so the confirm has to consider the
/// whole line. That is the expensive part, and it is why this is a
/// separate query rather than another kind of [`Entry`].
///
/// Soundness is the same law as everywhere else, with one thing
/// dropped: the offset. Every literal reported here occurs in every
/// match, so scanning for it can only over-report.
#[must_use]
pub fn anywhere(ast: &Ast) -> Option<Required> {
    let mut best: Option<Required> = None;
    let take = |r: Required, best: &mut Option<Required>| {
        if best.as_ref().is_none_or(|b| b.bytes.len() < r.bytes.len()) {
            *best = Some(r);
        }
    };
    // The exact skeleton first: an exact offset is a special case of
    // an unknown one, and this is the cheap way to answer the question
    // for a pattern that turns out to be fixed-length.
    if let Some(r) = best_run(&facts(ast).bytes) {
        take(r, &mut best);
    }
    match ast {
        Ast::Concat(items) => {
            // Each SEGMENT of the text whose internal layout is known.
            // Two entries in one segment are adjacent in every match, so
            // they form a literal; entries in different segments are not,
            // because something of unknown length sits between them.
            for seg in segments(items) {
                if let Some(r) = best_run(&seg) {
                    take(r, &mut best);
                }
            }
            for item in items {
                if let Some(r) = anywhere(item) {
                    take(r, &mut best);
                }
            }
        }
        Ast::Alt(branches) => {
            // Only what EVERY branch contains.
            let mut common: Option<Vec<Required>> = None;
            for b in branches {
                let r = anywhere(b);
                common = Some(match (common, r) {
                    (None, r) => r.into_iter().collect(),
                    (Some(mut acc), Some(r)) => {
                        acc.retain(|x| x.bytes == r.bytes && x.caseless == r.caseless);
                        acc
                    }
                    (Some(_), None) => Vec::new(),
                });
            }
            for r in common.unwrap_or_default() {
                take(r, &mut best);
            }
        }
        Ast::Group { node, .. } => {
            if let Some(r) = anywhere(node) {
                take(r, &mut best);
            }
        }
        Ast::Repeat { node, min, .. } => {
            if *min >= 1 {
                if let Some(r) = anywhere(node) {
                    take(r, &mut best);
                }
            }
        }
        Ast::Class(set) => {
            if let Some(e) = class_entry(set) {
                if e.caseless {
                    take(
                        Required {
                            bytes: e.alts,
                            caseless: true,
                            at: 0,
                        },
                        &mut best,
                    );
                } else if let Some(b) = e.single() {
                    take(
                        Required {
                            bytes: alloc::vec![b],
                            caseless: false,
                            at: 0,
                        },
                        &mut best,
                    );
                }
            }
        }
        Ast::Empty | Ast::Assert(_) => {}
    }
    best
}

/// The maximal stretches of a concatenation whose internal byte layout
/// every match agrees on, each as entries at offsets relative to ITS OWN
/// start.
///
/// A segment ends where a sibling of unknown length begins, and the
/// next one starts at offset 0 again — not because the text restarts
/// there, but because nothing can say where it starts. Two entries
/// inside one segment are adjacent in every match; entries in
/// different segments are not.
fn segments(items: &[Ast]) -> Vec<Vec<Entry>> {
    let mut out: Vec<Vec<Entry>> = Vec::new();
    // `abs` is where an entry sits in the match, only good while every
    // item before it had a known length. `rel` is where it sits within
    // the CURRENT segment, and it stays good across a variable item.
    let mut abs = 0usize;
    let mut rel = 0usize;
    let mut exact = true;
    for item in items {
        let f = facts(item);
        if out.is_empty() {
            out.push(Vec::new());
        }
        let base = if exact { abs } else { rel };
        out.last_mut()
            .expect("non-empty")
            .extend(f.bytes.iter().map(|e| Entry {
                at: e.at + base,
                alts: e.alts.clone(),
                caseless: e.caseless,
            }));
        // A MANDATORY repetition of a fixed-length body does not break
        // the segment. `y+` consumes an unknown number of bytes, so
        // nothing after it is at a known offset — and yet the last `y`
        // is always immediately followed by the `z`, because a
        // repetition ends where the next sibling begins. So the
        // body's entries are placed as the LAST iteration rather than
        // the first, and the sibling after it lands next to them.
        // `min >= 1` is the condition, and it is not optional: an
        // optional body may not run at all.
        let body = match item {
            Ast::Repeat { node, min, .. } if *min >= 1 => facts(node).exact_len,
            _ => f.exact_len,
        };
        if let Some(len) = body {
            if exact {
                abs += len;
            } else {
                rel += len;
            }
        } else {
            // A variable item breaks the segment: nothing after it is
            // adjacent to anything before it.
            exact = false;
            rel = 0;
            out.push(Vec::new());
        }
    }
    out.retain(|s| !s.is_empty());
    out
}

/// The widest set of alternative bytes one skeleton entry may hold.
///
/// An entry is "at this exact offset, **one** of these bytes" — the
/// shape a narrow character class leaves behind. The cap is about
/// usefulness, not expressibility (a scan can test all 256): a
/// 26-member set is not a needle, and a caller that picked one as its
/// anchor would have paid a scan to find candidates it could not
/// afford to confirm.
pub const MAX_ALTS: usize = 16;

/// One required byte-set at an exact offset: every match has one of
/// these bytes there, and nowhere else.
///
/// This is the unit a *rarity* decision can be made over, and that is
/// the reason it exists. [`Prefilter::One`] reports the LONGEST
/// contiguous run, which is the right needle and the wrong anchor:
/// for `e[0-9]` the run is the single `e`, at 5.3% of the bytes of a
/// Rust corpus, while the `[0-9]` next to it is required at offset 1
/// and holds 0.0001% of them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    /// The offset from the start of **every** match at which one of
    /// [`Self::alts`] sits. Exact, for the reasons the module header gives.
    pub at: usize,
    /// The alternative bytes, at least one and at most [`MAX_ALTS`], distinct.
    pub alts: Vec<u8>,
    /// Whether matching them ignores ASCII case.
    ///
    /// Only ever true for a two-member ASCII case pair, and then `alts` holds
    /// both cases rather than one of them, so a scan that folds the haystack
    /// and a scan that looks for both spell it differently.
    pub caseless: bool,
}

impl Entry {
    /// The single byte this entry requires, or `None` when it is a set.
    ///
    /// A set is scan evidence but it is not a *run*, and the two are not
    /// interchangeable: a contiguous literal can be searched with a substring
    /// search and a set cannot.
    #[must_use]
    pub fn single(&self) -> Option<u8> {
        if self.alts.len() == 1 {
            self.alts.first().copied()
        } else {
            None
        }
    }
}

/// Every entry the AST walk found, in ascending offset order.
///
/// Unlike [`required`] this does not pick a winner. A caller that has a
/// buffer in hand — which is exactly when the choice of anchor is worth
/// making — gets the whole skeleton and can rank the entries by how often
/// their bytes actually occur in *that* buffer. Every entry is sound on its
/// own: the same law, the same exactness, the same refusal to report a byte
/// it is not sure of. The difference is only that the caller is handed the
/// choice instead of having it made by a rule about run length.
#[must_use]
pub fn skeleton(ast: &Ast) -> Vec<Entry> {
    facts(ast).bytes
}

/// One required byte-set, and the RANGE of offsets at which every match holds
/// it.
///
/// **The gap this fills.** `Facts::bytes` is exact-offset or nothing, and
/// that is right for an ANCHOR: an offset a match *may* sit at does not let a
/// candidate's position say where the match began. It is wrong for a
/// REJECTOR. A candidate at `s` that has no space in `s+2..=s+3` cannot begin
/// a match of `(pub|fn) [a-z]+`, whether or not the space's offset is the same
/// in every match — and every match of that pattern has one there, because
/// `pub` is three bytes and `fn` is two and the space follows both. Rejecting
/// on that is a table lookup, and what it replaces is a Pike VM run.
///
/// So this is the same law with the offset weakened, and nothing else
/// weakened with it: `alts` is still true of **every** match, and the only
/// thing given up is *where*. As a check that is sound by construction,
/// because a check only ever rejects — it never has to be sufficient, and one
/// that rejects nothing costs a lookup per candidate.
/// `max_at == usize::MAX` means the offset is genuinely unbounded
/// (`bar` in `foo.*bar`), which is sound and useless as a check:
/// "some byte in the rest of the line is a `b`" is a scan.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MinRun {
    /// The byte values, at least one. A contiguous literal is a run of these
    /// with consecutive `min_at`s.
    pub alts: Vec<u8>,
    /// Whether matching them ignores ASCII case.
    pub caseless: bool,
    /// The least offset from the start of any match at which one sits.
    pub min_at: usize,
    /// The greatest such offset, or [`UNBOUNDED`].
    pub max_at: usize,
}

/// The `max_at` of an offset nothing bounds.
pub const UNBOUNDED: usize = usize::MAX;

impl MinRun {
    /// Whether the range is narrow enough to test with a few byte loads.
    ///
    /// A wide range is not refused because it is unsound (it is not),
    /// but because testing it means scanning the line, and a scan in
    /// the confirm is what [`MinRun`] exists to avoid. The window a
    /// check pays for is `max_at - min_at + 1` loads, so the question
    /// is whether that is a number or a line.
    #[must_use]
    pub fn bounded(&self) -> Option<(usize, usize)> {
        if self.max_at == UNBOUNDED {
            return None;
        }
        Some((self.min_at, self.max_at))
    }

    /// The single byte at one exact offset, when this entry is that.
    #[must_use]
    pub fn single(&self) -> Option<u8> {
        if self.min_at == self.max_at && self.alts.len() == 1 {
            self.alts.first().copied()
        } else {
            None
        }
    }
}

/// Every required byte-set and the range of offsets it can sit at,
/// over the whole pattern.
///
/// The third of the three questions this module answers:
///
/// | query | what it says | what a caller does with it |
/// |---|---|---|
/// | [`required`] | one literal at an EXACT offset | anchors a confirm |
/// | [`skeleton`] | every literal at an exact offset | chooses an anchor, or a set of checks |
/// | [`min_runs`] | every literal at a RANGE of offsets | rejects a candidate, or scans for it |
///
/// The third exists because the first two both go quiet at the same
/// place. `(pub|fn) [a-z]+` has a variable-length prefix, so
/// [`skeleton`] is empty, and the space is at offset 2 or 3 and
/// either way it is there; a ranged entry says so and costs two
/// loads.
#[must_use]
pub fn min_runs(ast: &Ast) -> Vec<MinRun> {
    let mut out: Vec<MinRun> = Vec::new();
    collect_min_runs(ast, 0, Some(0), &mut out);
    out.sort_by_key(|r| (r.min_at, r.max_at));
    out.dedup_by(|a, b| {
        a.min_at == b.min_at && a.max_at == b.max_at && a.alts == b.alts && a.caseless == b.caseless
    });
    out
}

/// `node` BEGINS inside a match; collect everything `node` forces,
/// rebased by that range.
///
/// The recursion carries a RANGE rather than an offset, which is the
/// whole difference from [`facts`]. There, a variable-length sibling
/// makes every offset after it unknown and the analysis drops the
/// tail; here the tail is kept and its offsets are reported as
/// "somewhere in this window", which is still a fact about every
/// match.
///
/// `hi` is `None` for unbounded and is propagated rather than
/// clamped: a saturated `usize::MAX - 1` would be a range of two to
/// the sixty-fourth power of two, which [`MinRun::bounded`] would
/// have to treat as bounded. An unbounded offset has to be
/// recognisably unbounded, because an anchor wants to scan for it
/// and a check wants nothing to do with it.
fn collect_min_runs(node: &Ast, at_min: usize, at_max: Option<usize>, out: &mut Vec<MinRun>) {
    let hi = at_max.unwrap_or(UNBOUNDED);
    match node {
        Ast::Concat(items) => {
            let mut lo = at_min;
            let mut top = at_max;
            for item in items {
                collect_min_runs(item, lo, top, out);
                let f = facts(item);
                lo = lo.saturating_add(f.min_len);
                top = match (top, f.max_len) {
                    (Some(a), Some(b)) => a.checked_add(b),
                    _ => None,
                };
            }
        }
        Ast::Group { node, .. } => collect_min_runs(node, at_min, at_max, out),
        Ast::Repeat { node, min, .. } => {
            // A body that may not run requires nothing. A mandatory body's
            // FIRST iteration starts here, which is the tightest range, so
            // that is what is reported: the later iterations hold the same
            // bytes at higher offsets and reporting those would only widen
            // the range for no gain.
            if *min >= 1 {
                collect_min_runs(node, at_min, at_max, out);
            }
        }
        Ast::Alt(branches) => {
            // An entry every branch agrees on, at the same relative
            // offset and the same values. Keyed by all three, for the
            // reason `facts`'s intersection is: `a|b` shares nothing,
            // and merging `{a}` with `{b}` would report a byte no branch
            // ever required.
            let mut common: Option<Vec<Entry>> = None;
            for b in branches {
                let f = facts(b);
                common = Some(match common {
                    None => f.bytes,
                    Some(acc) => acc.into_iter().filter(|e| f.bytes.contains(e)).collect(),
                });
            }
            for e in common.unwrap_or_default() {
                out.push(MinRun {
                    alts: e.alts,
                    caseless: e.caseless,
                    min_at: at_min.saturating_add(e.at),
                    max_at: hi.saturating_add(e.at),
                });
            }
        }
        Ast::Class(set) => {
            if let Some(e) = class_entry(set) {
                out.push(MinRun {
                    alts: e.alts,
                    caseless: e.caseless,
                    min_at: at_min,
                    max_at: hi,
                });
            }
        }
        Ast::Empty | Ast::Assert(_) => {}
    }
}

/// What the walk knows about one subtree.
pub(crate) struct Facts {
    /// The fewest bytes any match of this subtree can consume.
    pub(crate) min_len: usize,
    /// The most, or `None` when some path through it consumes an unbounded
    /// number. This is the half of the length [`min_runs`] needs and
    /// [`Facts::bytes`] does not: an exact-offset skeleton is thrown away
    /// behind a variable sibling, whereas a RANGE only has to be wide, and
    /// "one of these bytes sits somewhere in offsets 2 through 3" is a fact
    /// about every match however the two branches got there.
    pub(crate) max_len: Option<usize>,
    /// `Some(l)` when every match consumes exactly `l` bytes. `None` when the
    /// length varies, which is what makes an offset behind it unusable.
    pub(crate) exact_len: Option<usize>,
    /// Bytes at **exact** offsets, ascending, one entry per offset.
    ///
    /// This is the whole soundness story. An entry at offset `o` says every
    /// match of this subtree has one of its alternative bytes at exactly `o` —
    /// not at `o` or later. The alternatives are ruled out as follows:
    ///
    /// - a class wider than [`MAX_ALTS`] contributes nothing, because an
    ///   offset is not what is unknown but the *value* is, and a set too wide
    ///   to be worth scanning cannot be handed to a scan at all;
    /// - under a concatenation, a sibling contributes only while every
    ///   preceding sibling has an exact length, because otherwise the sibling
    ///   is free to slide;
    /// - under `x{0,}` nothing contributes, since the body may not run;
    /// - under `x{1,}` the body's own entries carry over unchanged, because
    ///   the first iteration starts at offset 0;
    /// - under an alternation only the entries **every** branch agrees on
    ///   survive, keyed by both offset and value, which is what makes `a|b`
    ///   yield nothing and `foo|fop` yield `fo`.
    pub(crate) bytes: Vec<Entry>,
    /// The alternation fallback: literals every match contains at the same
    /// exact offset, used only when [`Facts::bytes`] is empty.
    pub(crate) alt: Option<AltLiterals>,
}

impl Facts {
    fn empty() -> Self {
        Self {
            min_len: 0,
            max_len: Some(0),
            exact_len: Some(0),
            bytes: Vec::new(),
            alt: None,
        }
    }
}

/// The analysis. `ast` must have come from [`super::syntax::parse`], because
/// the answer depends on the flags that were in force while it was parsed: a
/// `(?i)` pattern's `e` is a two-member class and only a case-aware consumer
/// can scan for it.
#[must_use]
pub fn required(ast: &Ast) -> Prefilter {
    let f = facts(ast);
    if let Some(r) = best_run(&f.bytes) {
        return Prefilter::One(r);
    }
    match f.alt {
        Some(alt) if alt.lits.len() >= 2 => Prefilter::Alt(alt),
        _ => Prefilter::None,
    }
}

/// The longest contiguous run in an exact-offset byte skeleton, as one
/// literal at the run's start offset.
///
/// Contiguity is what makes the run a literal rather than a set of
/// independent facts, and it is checked against the offsets rather than
/// against the positions in the vector: a skeleton can have a gap, and a run
/// taken across a gap would be a needle no match contains.
///
/// A caseless byte next to a case-sensitive one does not extend the run. The
/// consumer compares a literal with a single fold flag, and a run that needed
/// per-position folding would either fold a byte it must not or miss one it
/// must. Stopping is sound; pretending is not.
fn best_run(bytes: &[Entry]) -> Option<Required> {
    let mut best: Option<Required> = None;
    let mut i = 0;
    while i < bytes.len() {
        let Some(b0) = bytes[i].single() else {
            i += 1;
            continue;
        };
        let start = bytes[i].at;
        let fold = bytes[i].caseless;
        let mut j = i + 1;
        // A set cannot extend a run: a needle is a sequence of REQUIRED
        // bytes, and `[ab]c` is a sequence of one required byte and one
        // unknown one. The run stops there rather than picking a member.
        while j < bytes.len()
            && bytes[j].at == bytes[j - 1].at + 1
            && bytes[j].caseless == fold
            && bytes[j].single().is_some()
        {
            j += 1;
        }
        let len = core::cmp::min(j - i, MAX_LITERAL);
        if best.as_ref().is_none_or(|b| b.bytes.len() < len) {
            best = Some(Required {
                bytes: bytes[i..i + len]
                    .iter()
                    .map(|e| e.single().unwrap_or(b0))
                    .collect(),
                caseless: fold,
                at: start,
            });
        }
        i = j;
    }
    best
}

/// The run starting at offset 0, or `None` when the skeleton has nothing at
/// offset 0. This is the per-branch quantity an alternation intersects.
pub(crate) fn run_from_zero(bytes: &[Entry]) -> Option<Required> {
    let first = bytes.first()?;
    let b0 = first.single()?;
    if first.at != 0 {
        return None;
    }
    let fold = first.caseless;
    let mut n = 1;
    while n < bytes.len()
        && bytes[n].at == n
        && bytes[n].caseless == fold
        && bytes[n].single().is_some()
        && n < MAX_LITERAL
    {
        n += 1;
    }
    Some(Required {
        bytes: bytes[..n]
            .iter()
            .map(|e| e.single().unwrap_or(b0))
            .collect(),
        caseless: fold,
        at: 0,
    })
}

/// A required literal occurring after an unbounded or variable-length gap,
/// and the minimum offset from the start of the match where it may appear.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SuffixLiteral {
    /// The needle bytes.
    pub bytes: Vec<u8>,
    /// Whether ASCII case is ignored.
    pub caseless: bool,
    /// Minimum offset from the start of the match.
    pub min_offset: usize,
    /// Whether any variable repeat in front of this suffix allows matching across newlines.
    pub dot_all: bool,
}

fn is_repeat_dot_all(ast: &Ast) -> bool {
    let mut node = ast;
    while let Ast::Group { node: inner, .. } = node {
        node = inner;
    }
    if let Ast::Repeat { node: inner, .. } = node {
        let mut inner_node = inner.as_ref();
        while let Ast::Group { node: g, .. } = inner_node {
            inner_node = g;
        }
        if let Ast::Class(set) = inner_node {
            return *set == super::byteclass::ByteSet::any();
        }
    }
    true
}

/// Literals that are required to appear after an unknown-length or variable
/// repeat in the AST, together with their minimum offsets from match start.
///
/// **What this is for.** [`required`] and [`skeleton`] only report literals
/// at exact offsets, and drop anything following a variable repeat like `.*`.
/// For `foo.*bar`, `bar` is at an unknown offset, so it was dropped from
/// both. This function recovers `bar` as a required suffix literal at
/// `min_offset >= 3`, which allows candidate quenching and direct confirmation
/// without running the Pike VM.
#[must_use]
pub fn trailing_literals(ast: &Ast) -> Vec<SuffixLiteral> {
    let mut root = ast;
    while let Ast::Group { node, .. } = root {
        root = node;
    }
    let Ast::Concat(items) = root else {
        return Vec::new();
    };

    let mut out: Vec<SuffixLiteral> = Vec::new();
    let mut min_pos = 0usize;
    let mut saw_variable = false;
    let mut cur_dot_all = false;
    let mut cur_entries: Vec<Entry> = Vec::new();
    let mut cur_min_start = 0usize;
    let mut rel_pos = 0usize;

    for item in items {
        let f = facts(item);
        if f.exact_len.is_some() && !saw_variable {
            min_pos = min_pos.saturating_add(f.min_len);
            continue;
        }

        if f.exact_len.is_none() {
            saw_variable = true;
            if is_repeat_dot_all(item) {
                cur_dot_all = true;
            }
            if let Some(r) = best_run(&cur_entries) {
                if !r.bytes.is_empty() {
                    out.push(SuffixLiteral {
                        bytes: r.bytes,
                        caseless: r.caseless,
                        min_offset: cur_min_start,
                        dot_all: cur_dot_all,
                    });
                }
            }
            cur_entries.clear();
            min_pos = min_pos.saturating_add(f.min_len);
            cur_min_start = min_pos;
            rel_pos = 0;
        } else {
            if cur_entries.is_empty() {
                cur_min_start = min_pos;
                rel_pos = 0;
            }
            cur_entries.extend(f.bytes.iter().map(|e| Entry {
                at: rel_pos + e.at,
                alts: e.alts.clone(),
                caseless: e.caseless,
            }));
            let len = f.exact_len.unwrap_or(f.min_len);
            rel_pos = rel_pos.saturating_add(len);
            min_pos = min_pos.saturating_add(len);
        }
    }

    if let Some(r) = best_run(&cur_entries) {
        if !r.bytes.is_empty() {
            out.push(SuffixLiteral {
                bytes: r.bytes,
                caseless: r.caseless,
                min_offset: cur_min_start,
                dot_all: cur_dot_all,
            });
        }
    }

    out
}

pub(crate) fn facts(ast: &Ast) -> Facts {
    match ast {
        // Neither consumes nor constrains anything.
        Ast::Empty | Ast::Assert(_) => Facts::empty(),
        Ast::Class(set) => {
            // A multi-byte class (e.g. `[abc]` or a parser-coalesced
            // `a|b|c`) populates BOTH the exact-offset bytes path AND
            // the alternation fallback when the class is small enough
            // to be useful as a prefilter. The bytes path is what
            // `best_run` consumes for the single-byte case; the alt
            // path is what the prefilter uses when the class is
            // disjoint single bytes. A wide range like `[0-9]` or
            // `\w+` should NOT fire the alt path -- scanning for ten
            // alternative bytes is not a useful prefilter and the
            // engine would have said so before. The threshold of
            // [`MAX_ALTS`] / 2 is the small-class sweet spot: it
            // covers the parser-coalesced alts the audit asks for
            // (`a|b|c` is three) and stops the regression on ranges.
            let bytes: Vec<Entry> = class_entry(set).into_iter().collect();
            let alt: Option<AltLiterals> = if (2..=MAX_ALTS as u32 / 2).contains(&set.len()) {
                let lits: Vec<Required> = (0..=255u8)
                    .filter(|&b| set.contains(b))
                    .map(|b| Required {
                        bytes: alloc::vec![b],
                        caseless: false,
                        at: 0,
                    })
                    .collect();
                if lits.len() >= 2 {
                    Some(AltLiterals { at: 0, lits })
                } else {
                    None
                }
            } else {
                None
            };
            Facts {
                min_len: 1,
                max_len: Some(1),
                exact_len: Some(1),
                bytes,
                alt,
            }
        }
        Ast::Concat(items) => {
            // `known` is "every sibling so far has a fixed length", which is
            // what makes the *next* sibling's offset exact. It starts true
            // and one variable-length sibling clears it for good.
            let mut pos = 0usize;
            let mut pos_max = Some(0usize);
            let mut known = true;
            let mut bytes: Vec<Entry> = Vec::new();
            let mut alt: Option<AltLiterals> = None;
            for item in items {
                let f = facts(item);
                if known {
                    bytes.extend(f.bytes.iter().map(|e| Entry {
                        at: e.at + pos,
                        alts: e.alts.clone(),
                        caseless: e.caseless,
                    }));
                    if alt.is_none() {
                        alt = f.alt.map(|a| AltLiterals {
                            at: a.at + pos,
                            lits: a.lits,
                        });
                    }
                }
                pos = pos.saturating_add(f.min_len);
                pos_max = f.max_len.and_then(|m| pos_max?.checked_add(m));
                known = known && f.exact_len.is_some();
            }
            Facts {
                min_len: pos,
                max_len: pos_max,
                exact_len: if known { Some(pos) } else { None },
                bytes,
                alt,
            }
        }
        Ast::Group { node, .. } => facts(node),
        Ast::Repeat { node, min, max, .. } => {
            let f = facts(node);
            let min_len = f.min_len.saturating_mul(*min as usize);
            // A BOUNDED repetition has a bounded length whatever the body is,
            // and the bound is the one the `max` side states: `x{0,}` of a
            // one-byte body is still unbounded, and reading the body for it
            // instead is how `x{2,}` would be mistaken for `x{2}`.
            let max_len = match (max, f.max_len) {
                (Some(m), Some(l)) => Some(l.saturating_mul(*m as usize)),
                _ => None,
            };
            // Only a *fixed* repetition has a fixed length. `x{2}` does;
            // `x{2,}` and `x{1,5}` do not, so anything after them is at an
            // offset the analysis cannot name.
            let exact_len = match (max, f.exact_len) {
                (Some(m), Some(l)) if m == min => Some(l.saturating_mul(*min as usize)),
                _ => None,
            };
            // The first iteration starts at offset 0, so a mandatory body's
            // own exact offsets carry over untouched. An optional one
            // contributes nothing: `a?bc` must not claim the `a`.
            let (bytes, alt) = if *min >= 1 {
                (f.bytes, f.alt)
            } else {
                (Vec::new(), None)
            };
            Facts {
                min_len,
                max_len,
                exact_len,
                bytes,
                alt,
            }
        }
        Ast::Alt(branches) => {
            let fs: Vec<Facts> = branches.iter().map(facts).collect();
            let min_len = fs.iter().map(|f| f.min_len).min().unwrap_or(0);
            // Every branch has to have one, and the answer is the LARGEST of
            // them: a group takes one branch or the other, never both, so
            // summing them is how `(pub|fn)` reports a maximum length of five
            // and the space behind it a range of 2 to 5.
            let mut max_len = Some(0usize);
            for f in &fs {
                let (Some(best), Some(l)) = (max_len, f.max_len) else {
                    max_len = None;
                    break;
                };
                max_len = Some(best.max(l));
            }
            // Every branch must agree on the length, not merely have one:
            // `(ab|c)` is two bytes for one branch and one for the other, so
            // `d` after it is at offset 2 or at offset 1 and neither is
            // usable.
            let lens: Vec<Option<usize>> = fs.iter().map(|f| f.exact_len).collect();
            let exact_len = if lens.windows(2).all(|w| w[0] == w[1]) {
                lens.first().copied().flatten()
            } else {
                None
            };
            // The intersection. Keyed by offset *and* value *and* fold, so a
            // branch that says `e` under `(?i)` does not merge with one that
            // says `E` case-sensitively — that is the same aliasing
            // `literal::NibbleMask::confirm_key` exists to refuse.
            //
            // Two branches agree about an offset when their sets are
            // *identical*, not merely non-empty. `[ab]x|[ac]x` intersects to
            // `{a}` at offset 0, which is sound, but it is a weaker fact than
            // either branch states, and the intersection of three sets can
            // walk all the way down to a byte no branch ever named as
            // required on its own. Requiring equality keeps the skeleton a
            // list of things the pattern says outright, and this is the one
            // place where the cheaper rule is not worth having.
            let mut bytes: Vec<Entry> = fs.first().map(|f| f.bytes.clone()).unwrap_or_default();
            for f in fs.iter().skip(1) {
                bytes.retain(|e| f.bytes.contains(e));
            }
            bytes.sort_unstable_by_key(|e| e.at);
            // The alternation fallback, built whenever every branch starts
            // with a single required run. It is consulted only when no
            // run in the intersection can be used, so building it
            // eagerly costs an allocation and changes nothing else.
            // Building it for `a|b` is the whole point: the branches
            // share no byte, so the intersection is empty, and what
            // remains is "one of these two literals, at offset 0".
            let alt = {
                let mut lits: Option<Vec<Required>> = Some(Vec::new());
                for f in &fs {
                    let Some(r) = run_from_zero(&f.bytes) else {
                        lits = None;
                        break;
                    };
                    lits.as_mut().expect("set above").push(r);
                }
                lits.map(|lits| AltLiterals { at: 0, lits })
            };
            Facts {
                min_len,
                max_len,
                exact_len,
                bytes,
                alt,
            }
        }
    }
}

/// A class contributes a byte-set when it admits few enough members to be
/// worth scanning for.
///
/// Two members are not merged: `(?i)e` parses to `{e, E}`, and a scan
/// that looked for `e` alone would miss every `E`. Handing the pair
/// over as a caseless literal is exactly as precise as the class it
/// came from.
///
/// Beyond that the set is kept AS A SET rather than dropped — the
/// change that makes `e[0-9]` fixable. The ten digits are ten of
/// the most selective bytes a real corpus has, and the offset is
/// exact whether the value is one byte or ten. A caller that scans
/// for the rarest member can act on that; a caller handed only the
/// longest contiguous run cannot.
fn class_entry(set: &super::byteclass::ByteSet) -> Option<Entry> {
    let mut alts: Vec<u8> = set.iter().collect();
    if alts.is_empty() || alts.len() > MAX_ALTS {
        return None;
    }
    alts.sort_unstable();
    alts.dedup();
    let caseless =
        alts.len() == 2 && alts[0].eq_ignore_ascii_case(&alts[1]) && alts[0].is_ascii_alphabetic();
    Some(Entry {
        at: 0,
        // A case pair is ONE byte with a fold flag, not a two-member
        // set: a contiguous run has to be able to cross it
        // (`(?i)Er` is the literal `er`), and a consumer scans it by
        // folding rather than by accepting either member.
        alts: if caseless {
            alloc::vec![alts[0].to_ascii_lowercase()]
        } else {
            alts
        },
        caseless,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;

    /// Whether `win` holds `lit`'s bytes, folding where the literal folds.
    fn lit_at(win: &[u8], lit: &Required) -> bool {
        if win.len() < lit.bytes.len() {
            return false;
        }
        win.iter().zip(lit.bytes.iter()).all(|(&a, &b)| {
            if lit.caseless {
                a.eq_ignore_ascii_case(&b)
            } else {
                a == b
            }
        })
    }

    fn req(pat: &[u8]) -> Prefilter {
        let parsed = super::super::syntax::parse(pat).expect("parses");
        required(&parsed.ast)
    }

    fn one(pat: &[u8]) -> Required {
        match req(pat) {
            Prefilter::One(r) => r,
            other => panic!("{pat:?} gave {other:?}, expected one literal"),
        }
    }

    /// Every pattern whose prefilter could be wrong, in one list.
    ///
    /// The trap shapes are not a random sample. Each one is a way a
    /// "byte at a known offset" analysis can be wrong, and each was found by
    /// asking what would make a prefilter lie:
    ///
    /// | shape | the lie it invites |
    /// |---|---|
    /// | `a\|b` | the `a` of one branch is not required by the other |
    /// | `a?bc`, `a*bc` | the optional byte, and the `bc` that slides |
    /// | `ab*c` | the mirror image: the `a` IS required, the `c` is not |
    /// | `(ab\|cd)ef` | branches of equal length, tail exact |
    /// | `(ab\|c)d` | branches of different length, tail not exact |
    /// | `(a\|(b\|c))d` | an alternation nested inside an alternation |
    /// | `^a.*b$` | anchors plus an unbounded repeat |
    /// | `\d+em` | a required literal behind a variable-length prefix |
    /// | `[a-z]\|[a-z]x` | two classes that overlap |
    /// | `e[0-9]`, `[ab]cd` | a narrow class next to a literal |
    /// | `(?i)e.`, `(?i)[ab]cd` | case folding turning a byte into a pair |
    const TRAPS: &[&[u8]] = &[
        b"e",
        b"e.",
        b"e..",
        b"foo.*bar",
        b"e[0-9]",
        b"a|b",
        b"a|b|c",
        b"a|bb|ccc",
        b"[a]bc",
        b"a?bc",
        b"a*bc",
        b"ab*c",
        b"(ab|cd)ef",
        b"(ab|c)d",
        b"(a|(b|c))d",
        b"(?:foo|fop)bar",
        b"^a.*b$",
        b"pub fn",
        b"pub.*fn",
        b"(pub|fn) [a-z]+",
        b"(?i)e.",
        b"(?i)[ab]cd",
        b"a{2,3}b",
        b"(ab)+c",
        b"[a-z]x",
        b"x[a-z]",
        b"a.b.c",
        b"\\d+em",
        b"[a-z]*xyz",
        b"[[:alpha:]]bc",
        b"(a)(b)c",
        b"[0-9][a-z]",
        b"a[0-9]b[0-9]c",
        b"(\\d|\\w)x",
    ];

    /// Haystacks built to hold the matches of the trap patterns, so the grid
    /// asserts against real matches rather than none at all.
    const HAYS: &[&[u8]] = &[
        b"e",
        b"x",
        b"abc",
        b"foofoobarfoo",
        b"foo bar fooXbar",
        b"a",
        b"b",
        b"c",
        b"abcabc",
        b"public fn",
        b"pub fn",
        b"pub Xfn",
        b"pubfn",
        b"function",
        b"aXbXc",
        b"1em 2em 3em",
        b"em 1em 12em",
        b"xyz 1xyz 22xyz",
        b"abbc",
        b"aabbc",
        b"XYabc",
        b"a b c",
        b"E. e. E.",
        b"..e..",
        b"aaab",
        b"0a 9z 5a9b7c",
        b"a1b2c",
        b"3x 5x",
        b"pub fn main() {}\n",
        b"    pub fn helper(&self) -> u32 {\n        42\n    }\n",
    ];

    // ---- the cases the whole module exists for -------------------------

    /// `e.` is 99% as common as `e` and used to have no prefilter at all,
    /// because the extractor could only read the pattern as text.
    #[test]
    fn a_metacharacter_after_a_literal_keeps_the_literal() {
        let r = one(b"e.");
        assert_eq!(r.bytes, b"e".to_vec());
        assert_eq!(r.at, 0);
        assert!(!r.caseless);
    }

    /// The run must be the *mandatory* prefix, not the interesting-looking
    /// one further in. `bar` is just as required as `foo`, but `.*` in
    /// front of it makes its offset unknowable, and a prefilter that claimed
    /// one would derive the wrong match start and drop matches.
    #[test]
    fn an_unbounded_repeat_hides_what_follows_it() {
        let r = one(b"foo.*bar");
        assert_eq!(r.bytes, b"foo".to_vec());
        assert_eq!(r.at, 0);
    }

    /// The class is ten bytes wide and contributes nothing, but the `e` in
    /// front of it is a byte and is exact.
    #[test]
    fn a_wide_class_contributes_nothing_and_the_byte_before_it_does() {
        let r = one(b"e[0-9]");
        assert_eq!(r.bytes, b"e".to_vec());
        assert_eq!(r.at, 0);
    }

    /// A single-member class is a literal byte, and the run continues
    /// through the `bc` after it.
    #[test]
    fn a_single_member_class_is_a_literal_byte() {
        assert_eq!(one(b"[a]bc").bytes, b"abc".to_vec());
        assert_eq!(one(b"[a]bc").at, 0);
    }

    /// `a|b` is two disjoint single-byte arms. The parser coalesces
    /// it into a single `Class({a, b})`, and the prefilter captures
    /// the union through the alternation fallback -- the same shape
    /// the prefilter had before the parser change. The class arm and
    /// the alt arm are independent consumers of the same `Facts`,
    /// and the prefilter's view is unchanged. The VM is the one that
    /// sees the win: a single class test instead of two threads.
    #[test]
    fn an_alternation_of_two_different_bytes_yields_only_the_alternation() {
        match req(b"a|b") {
            Prefilter::Alt(a) => {
                assert_eq!(a.at, 0);
                let mut got: Vec<Vec<u8>> = a.lits.iter().map(|l| l.bytes.clone()).collect();
                got.sort();
                assert_eq!(got, vec![b"a".to_vec(), b"b".to_vec()]);
            }
            Prefilter::None => panic!("a|b must not yield no literal"),
            other => panic!("a|b gave {other:?}"),
        }
    }

    /// `a` is optional, so it is not a prefilter — and neither is the `bc`
    /// after it, because its offset is 0 or 1 depending on whether the `a`
    /// ran. The honest answer is nothing at all.
    ///
    /// The mirror image is the one that is easy to get wrong: the `a` in
    /// `ab*c` is NOT optional, so the `a` *is* claimed, while the `c` behind
    /// the variable-length `b*` is not.
    #[test]
    fn an_optional_byte_is_never_required() {
        assert!(req(b"a?bc").is_none());
        assert!(req(b"a*bc").is_none());
        let r = one(b"ab*c");
        assert_eq!(r.bytes, b"a".to_vec());
        assert_eq!(r.at, 0, "`c` is at offset 2 or later and unusable");
    }

    /// Both branches are two bytes, so the group has a fixed length and the
    /// `ef` behind it is at exactly offset 2.
    #[test]
    fn equal_length_branches_leave_the_tail_exact() {
        let r = one(b"(ab|cd)ef");
        assert_eq!(r.bytes, b"ef".to_vec());
        assert_eq!(r.at, 2);
    }

    /// The same pattern with branches of different length. `(ab|c)d` puts
    /// the `d` at offset 2 or at offset 1, so nothing after the group is
    /// usable, and the group's own branches share nothing.
    #[test]
    fn unequal_length_branches_hide_the_tail() {
        match req(b"(ab|c)d") {
            Prefilter::Alt(a) => {
                // The alternation survives at its own exact offset, because
                // the group starts the match.
                assert_eq!(a.at, 0);
                let mut got: Vec<Vec<u8>> = a.lits.iter().map(|l| l.bytes.clone()).collect();
                got.sort();
                assert_eq!(got, vec![b"ab".to_vec(), b"c".to_vec()]);
            }
            other => panic!("(ab|c)d gave {other:?}"),
        }
    }

    /// `.*` slides, so only the anchored `a` is usable — and `b` further
    /// along, which is required but not at a fixed offset, must not be
    /// claimed.
    #[test]
    fn an_anchor_and_a_tail_leave_only_the_anchored_byte() {
        let r = one(b"^a.*b$");
        assert_eq!(r.bytes, b"a".to_vec());
        assert_eq!(r.at, 0);
    }

    /// Branches that agree on a prefix share those bytes, and the shared run
    /// is reported as one literal rather than an alternation — one needle
    /// scans faster than two.
    #[test]
    fn branches_sharing_a_prefix_share_the_prefilter() {
        let r = one(b"foo|fop");
        assert_eq!(r.bytes, b"fo".to_vec());
        assert_eq!(r.at, 0);
    }

    /// A two-member class under `(?i)` is a caseless literal, not nothing.
    /// A scan for the lower-case byte alone would miss every upper-case one.
    #[test]
    fn a_caseless_letter_is_a_caseless_literal() {
        let r = one(b"(?i)E.");
        assert_eq!(r.bytes, b"e".to_vec());
        assert!(r.caseless, "the two members are one folded literal");
        // A digit has no case partner, so it folds to nothing and stays
        // case-sensitive.
        let d = one(b"(?i)5.");
        assert!(!d.caseless);
    }

    /// A class wider than one byte contributes nothing even under `(?i)`:
    /// `[ab]` under `(?i)` is four members, not two, and a prefilter would
    /// have to be a set rather than a needle. The `cd` behind it is still
    /// exact -- a class consumes exactly one byte whether or not the analysis
    /// can name it -- so the tail survives and the head does not.
    #[test]
    fn a_wide_caseless_class_contributes_nothing() {
        let r = one(b"(?i)[ab]cd");
        assert_eq!(r.bytes, b"cd".to_vec());
        assert_eq!(r.at, 1);
        // The tail folds because every letter under `(?i)` is a case pair,
        // and it is spelled lower-case so a caseless confirm can fold it.
        assert!(r.caseless);
    }

    // ---- the property that matters, over a grid ------------------------

    /// **No false negatives, over a grid.** For every pattern in a set built
    /// to break the analysis and every haystack, every match the VM finds must
    /// contain the reported literal at the reported offset.
    ///
    /// This is the test the module is judged by. A prefilter that is wrong
    /// here does not merely search slower; it returns a *wrong answer*, which
    /// in a grep is indistinguishable from saying the file does not contain
    /// the thing you asked for.
    #[test]
    fn a_reported_literal_is_present_at_its_offset_in_every_match() {
        let pats: &[&[u8]] = TRAPS;
        let hays: &[&[u8]] = HAYS;
        for pat in pats {
            let Ok(parsed) = super::super::syntax::parse(pat) else {
                continue;
            };
            let prog = super::super::nfa::compile(&parsed.ast, parsed.groups);
            let pre = required(&parsed.ast);
            for hay in hays {
                let mut at = 0usize;
                while at <= hay.len() {
                    let Some(m) = super::super::vm::find(&prog, hay, at) else {
                        break;
                    };
                    match &pre {
                        Prefilter::None => {}
                        Prefilter::One(r) => {
                            let off = m.start + r.at;
                            let got = hay.get(off..off + r.bytes.len());
                            assert!(
                                got.is_some_and(|w| lit_at(w, r)),
                                "{:?} claims {:?} at offset {} of a match {:?} in {:?}",
                                String::from_utf8_lossy(pat),
                                String::from_utf8_lossy(&r.bytes),
                                r.at,
                                m,
                                String::from_utf8_lossy(hay),
                            );
                        }
                        Prefilter::Alt(a) => {
                            let off = m.start + a.at;
                            let end = (off + MAX_LITERAL).min(hay.len());
                            let got = hay.get(off..end);
                            assert!(
                                got.is_some_and(|w| a.lits.iter().any(|l| lit_at(w, l))),
                                "{:?} claims one of {:?} at offset {} of a match {:?} in {:?}",
                                String::from_utf8_lossy(pat),
                                a.lits.iter().map(|l| l.bytes.clone()).collect::<Vec<_>>(),
                                a.at,
                                m,
                                String::from_utf8_lossy(hay),
                            );
                        }
                    }
                    at = m.start + 1;
                }
            }
        }
    }

    /// **No false negatives, over a grid — for the SKELETON too.**
    ///
    /// [`required`] is judged by whether the one literal it picks is in every
    /// match; [`skeleton`] hands back all of them, and it is judged by the
    /// same property for every entry. This is the test the rarity-driven
    /// anchor rests on: an anchor is chosen by how RARE its bytes are, and
    /// rarity is measured on real input, so a single entry that were not
    /// truly required would be picked exactly when it is rarest — which is to
    /// say, it would be picked on the corpus where it does not occur, and
    /// would drop every match there. It is the worst possible failure and
    /// this is the test for it.
    #[test]
    fn a_reported_entry_is_present_at_its_offset_in_every_match() {
        for pat in TRAPS {
            let Ok(parsed) = super::super::syntax::parse(pat) else {
                continue;
            };
            let prog = super::super::nfa::compile(&parsed.ast, parsed.groups);
            for e in skeleton(&parsed.ast) {
                for hay in HAYS {
                    let mut at = 0usize;
                    while at <= hay.len() {
                        let Some(m) = super::super::vm::find(&prog, hay, at) else {
                            break;
                        };
                        let off = m.start + e.at;
                        let got = hay.get(off);
                        assert!(
                            got.is_some_and(|&b| {
                                e.alts.contains(&b)
                                    || (e.caseless
                                        && e.alts.iter().any(|a| b.eq_ignore_ascii_case(a)))
                            }),
                            "{:?} claims one of {:?} at offset {} of a match {:?} in {:?}",
                            String::from_utf8_lossy(pat),
                            e.alts,
                            e.at,
                            m,
                            String::from_utf8_lossy(hay),
                        );
                        at = m.start + 1;
                    }
                }
            }
        }
    }

    /// **No false negatives for the UNKNOWN-OFFSET answer, over a grid.**
    ///
    /// [`anywhere`] drops the one thing the rest of this module insists on --
    /// the offset -- so it needs its own proof, and the proof is different in
    /// kind: the literal must be present SOMEWHERE in every match, not at any
    /// particular place in it. A pattern and a haystack that disagree here
    /// produce a prefilter that skips lines, which is a wrong answer rather
    /// than a slow one.
    ///
    /// The haystacks are the ones that broke it: a match that does not start
    /// at the line's first byte, a match at the end, and a line with the
    /// literal in it that no match covers.
    #[test]
    fn a_reported_anywhere_literal_is_in_every_match() {
        for pat in TRAPS {
            let Ok(parsed) = super::super::syntax::parse(pat) else {
                continue;
            };
            let prog = super::super::nfa::compile(&parsed.ast, parsed.groups);
            let Some(r) = anywhere(&parsed.ast) else {
                continue;
            };
            for hay in HAYS {
                let mut at = 0usize;
                while at <= hay.len() {
                    let Some(m) = super::super::vm::find(&prog, hay, at) else {
                        break;
                    };
                    let got = hay.get(m.start..m.end).unwrap_or_default();
                    assert!(
                        lit_in(got, &r.bytes, r.caseless),
                        "{:?} claims {:?} is in the match {:?} of {:?}",
                        String::from_utf8_lossy(pat),
                        String::from_utf8_lossy(&r.bytes),
                        m,
                        String::from_utf8_lossy(hay),
                    );
                    at = m.start + 1;
                }
            }
        }
    }

    /// Whether `needle` occurs in `win`, folding where the literal folds.
    fn lit_in(win: &[u8], needle: &[u8], caseless: bool) -> bool {
        if needle.len() > win.len() {
            return false;
        }
        (0..=win.len() - needle.len()).any(|i| {
            win[i..i + needle.len()]
                .iter()
                .zip(needle.iter())
                .all(|(&a, &b)| {
                    if caseless {
                        a.eq_ignore_ascii_case(&b)
                    } else {
                        a == b
                    }
                })
        })
    }

    /// Whether one of `run`'s bytes sits at an offset of the match that lies
    /// inside the run's range.
    fn run_in_match(hay: &[u8], m: &super::super::vm::Match, run: &MinRun) -> bool {
        let from = m.start + run.min_at;
        let to = m.start + run.max_at.min(hay.len().saturating_sub(1));
        if from >= hay.len() {
            // The range starts past the haystack. A match cannot contain a
            // byte it does not have, so this is a failure and not a vacuous
            // truth -- which is why it is written out rather than folded into
            // the loop below as an empty window.
            return false;
        }
        (from..=to).any(|i| {
            hay.get(i).is_some_and(|&b| {
                run.alts.contains(&b)
                    || (run.caseless && run.alts.iter().any(|a| b.eq_ignore_ascii_case(a)))
            })
        })
    }

    /// **No false negatives for the RANGED answer, over a grid.**
    ///
    /// [`min_runs`] drops the one thing the rest of this module insists on --
    /// *where* -- and it needs its own proof, and the proof is different in
    /// kind from [`required`]'s: the byte must be present at SOME offset of
    /// the match that falls in the reported range, not at one of them. The
    /// range is the claim, so a range that is too NARROW is a false negative
    /// here exactly as a wrong offset is for [`required`].
    ///
    /// The grid is [`TRAPS`] over [`HAYS`], and it is judged against real
    /// matches found by the VM rather than against a hand-written list of
    /// expected offsets, because the whole risk is that the analysis and the
    /// matcher disagree about where a match begins.
    #[test]
    fn a_reported_min_run_is_in_every_match_somewhere_in_its_range() {
        for pat in TRAPS {
            let Ok(parsed) = super::super::syntax::parse(pat) else {
                continue;
            };
            let prog = super::super::nfa::compile(&parsed.ast, parsed.groups);
            for run in min_runs(&parsed.ast) {
                for hay in HAYS {
                    let mut at = 0usize;
                    while at <= hay.len() {
                        let Some(m) = super::super::vm::find(&prog, hay, at) else {
                            break;
                        };
                        assert!(
                            run_in_match(hay, &m, &run),
                            "{:?} claims one of {:?} at offset {}..={} of a match {:?} in {:?}",
                            String::from_utf8_lossy(pat),
                            run.alts,
                            run.min_at,
                            if run.max_at == UNBOUNDED {
                                UNBOUNDED
                            } else {
                                run.max_at
                            },
                            m,
                            String::from_utf8_lossy(hay),
                        );
                        at = m.start + 1;
                    }
                }
            }
        }
    }

    /// The range is the whole claim, so the shapes where a variable-length
    /// prefix widens it are pinned by hand.
    ///
    /// Without these the property test above passes on a `min_runs` that
    /// reports `b`'s offset in `foo.*bar` as exactly 3: the property is
    /// "somewhere in 3..=3", which is true of the match `foo` + `.*` +
    /// `bar` because the `.`s can be empty, and false of the match on
    /// `fooXbar` — so the property test does catch it. What the property test
    /// cannot say is WHICH range the analysis intended, and an
    /// accidentally-tight range is the failure that costs a match silently.
    /// These are the ranges, written out.
    #[test]
    fn a_variable_prefix_reports_a_range_and_not_a_point() {
        let runs = |pat: &[u8]| {
            let parsed = super::super::syntax::parse(pat).expect("parses");
            min_runs(&parsed.ast)
        };
        let find = |rs: &[MinRun], byte: u8| -> (usize, usize) {
            let r = rs
                .iter()
                .find(|r| r.alts == [byte])
                .unwrap_or_else(|| panic!("no entry for {:?} in {rs:?}", byte as char));
            (r.min_at, r.max_at)
        };

        // `foo` is exact: nothing in front of it slides. `bar` is behind `.*`,
        // so its offset is three or later, and `.*` is what makes it later.
        let rs = runs(b"foo.*bar");
        assert_eq!(
            find(&rs, b'b'),
            (3, UNBOUNDED),
            "`bar` is at offset 3 or later"
        );
        assert_eq!(find(&rs, b'f'), (0, 0), "`foo` is exact");

        // `\d+em`: one digit is the floor, so `em` is at offset 1 or later.
        let rs = runs(b"\\d+em");
        assert_eq!(find(&rs, b'e'), (1, UNBOUNDED));

        // `(pub|fn) [a-z]+`: `pub` is three and `fn` is two, so the space is
        // at offset 2 or at offset 3. This is the whole of the ranged
        // pre-confirm, and the range has to be exactly this width -- one
        // wider would test bytes nothing requires, and one narrower would
        // reject `fn x`, which does match.
        let rs = runs(b"(pub|fn) [a-z]+");
        let sp = rs
            .iter()
            .find(|r| r.alts == *b" ")
            .expect("the space after the alternation is required");
        assert_eq!(
            (sp.min_at, sp.max_at),
            (2, 3),
            "`fn ` puts it at 2, `pub ` at 3"
        );
        assert!(
            sp.bounded().is_some(),
            "a two-wide range is what a check can be made of"
        );

        // Equal-length branches leave the tail exact again, which is the
        // mirror of the case above and the reason the width is not a fudge.
        let rs = runs(b"(ab|cd)ef");
        assert_eq!(find(&rs, b'e'), (2, 2));
    }

    /// The shapes where a ranged entry would be WRONG, one per way of being
    /// wrong. Each is a case where a literal the pattern does not require
    /// would be claimed, and each has to come back with nothing.
    #[test]
    fn nothing_is_ranged_that_the_pattern_does_not_require() {
        let runs = |pat: &[u8]| {
            let parsed = super::super::syntax::parse(pat).expect("parses");
            min_runs(&parsed.ast)
        };
        let find = |rs: &[MinRun], byte: u8| -> (usize, usize) {
            let r = rs
                .iter()
                .find(|r| r.alts == [byte])
                .unwrap_or_else(|| panic!("no entry for {:?} in {rs:?}", byte as char));
            (r.min_at, r.max_at)
        };
        // A literal BEFORE the variable part keeps its exact offset, and a
        // literal AFTER it starts at the variable part's minimum length. Both
        // halves are required, which is why `bar.*foo` reports the `r` of
        // `bar` exactly and the `f` of `foo` from 3 onwards -- and why a
        // single `f` entry cannot be one run, since `bar` holds one at 0.
        let rs = runs(b"bar.*foo");
        assert_eq!(find(&rs, b'r'), (2, 2), "`bar` is exact");
        assert_eq!(find(&rs, b'f'), (3, UNBOUNDED), "`foo` is after the `.*`");
        // An alternation that shares nothing shares nothing. The
        // parser coalesces `a|b` into `Class({a, b})`, so the run for
        // it is one entry with two alts; the test pins the same fact
        // (no literal is at an offset other than 0) under the new
        // shape, and asserts the entries are the union.
        assert!(runs(b"a|b").iter().all(|r| r.min_at == 0 && r.max_at == 0));
        let ab = runs(b"a|b");
        assert_eq!(ab.len(), 1, "the coalesced class is one run");
        let mut alts = ab[0].alts.clone();
        alts.sort();
        assert_eq!(alts, vec![b'a', b'b']);
        // An OPTIONAL literal is not required at all: `a?b` says nothing
        // about whether the `b` has an `a` in front of it -- and saying so
        // is exactly what this analysis adds over the exact-offset one, which
        // returns NOTHING here. The range is what makes it expressible: the
        // `b` is at offset 0 or at offset 1, and both are matches.
        assert_eq!(find(&runs(b"a?bc"), b'b'), (0, 1));
        // A body that may run any number of times leaves the tail unbounded,
        // which is sound and is what stops it becoming a CHECK -- the range
        // is `0..=∞` and a check over it would be a line scan.
        assert_eq!(find(&runs(b"a*bc"), b'b'), (0, UNBOUNDED));
        // A pattern with NO required byte has nothing to range over, and what
        // it does have sits at offset 0 exactly. That is the explicit refusal
        // the new path depends on and not "it happens not to help": a range
        // of one is already in the exact-offset skeleton, so
        // `RangedCheck::new` drops it on `lo == hi` and a pattern like
        // `\w+` reaches the VM with exactly the checks it had before.
        for pat in [&b"\\w+"[..], b".", b"x*", b"[0-9]*", b"(a|b|)"] {
            let rs = runs(pat);
            assert!(
                rs.iter().all(|r| r.min_at == 0 && r.max_at == 0),
                "{:?} has nothing to range over, got {rs:?}",
                String::from_utf8_lossy(pat)
            );
        }
    }

    /// The caseless property, stated on its own: a caseless literal must be
    /// present at its offset for every case spelling, or the scan misses
    /// matches.
    #[test]
    fn a_caseless_literal_is_present_for_every_spelling() {
        let parsed = super::super::syntax::parse(b"(?i)Er.").expect("parses");
        let pre = required(&parsed.ast);
        let Prefilter::One(r) = pre else {
            panic!("(?i)Er. must yield one literal");
        };
        assert_eq!(r.bytes, b"er".to_vec());
        assert!(r.caseless);
        for hay in [b"ER!", b"er!", b"Er!", b"eR!"] {
            let got = hay.get(r.at..r.at + r.bytes.len()).expect("in range");
            assert!(got.eq_ignore_ascii_case(&r.bytes), "{:?}", hay);
        }
    }

    /// A skeleton must hold **one** byte per offset, strictly ascending. A
    /// repeat of an offset would let two runs fuse into a needle no match
    /// contains -- `a{2,4}` unrolled would otherwise read as one `a` at
    /// offset 0, one at 1, one at 2, when the body repeats and only the first
    /// iteration is at offset 0.
    #[test]
    fn no_offset_appears_twice_in_a_skeleton() {
        for pat in [
            &b"aa"[..],
            b"(ab|ab)c",
            b"a{2,4}b",
            b"(?:aa)+b",
            b"(a)(a)b",
            b"(a*)*b",
            b"a{3}",
            b"(?:abc){2,3}d",
        ] {
            let parsed = super::super::syntax::parse(pat).expect("parses");
            assert_skeleton_sane(&parsed.ast, pat);
        }
    }

    /// The invariant, checked on every subtree rather than only the root, so
    /// a composition that fuses offsets cannot hide behind a parent that
    /// happens not to.
    fn assert_skeleton_sane(ast: &Ast, pat: &[u8]) {
        let f = facts(ast);
        for w in f.bytes.windows(2) {
            assert!(
                w[1].at > w[0].at,
                "{:?} repeats or unsorts offsets: {:?}",
                String::from_utf8_lossy(pat),
                f.bytes,
            );
        }
        match ast {
            Ast::Concat(items) | Ast::Alt(items) => {
                for it in items {
                    assert_skeleton_sane(it, pat);
                }
            }
            Ast::Group { node, .. } => assert_skeleton_sane(node, pat),
            Ast::Repeat { node, .. } => assert_skeleton_sane(node, pat),
            Ast::Class(_) | Ast::Empty | Ast::Assert(_) => {}
        }
    }

    /// The extractor must never report something for a pattern that cannot
    /// match at all, and must report nothing for the two shapes whose whole
    /// point is that nothing is required.
    #[test]
    fn shapes_with_nothing_required_report_nothing() {
        for pat in [
            &b"a?b"[..],
            b"a*b",
            b".",
            b"(a|)",
            b"[0-9]",
            b"\\w+",
            b"(a|b|)c",
        ] {
            let p = req(pat);
            assert!(
                matches!(p, Prefilter::None | Prefilter::Alt(_)),
                "{:?} gave {:?}",
                String::from_utf8_lossy(pat),
                p,
            );
            assert!(
                !matches!(p, Prefilter::Alt(_)),
                "{:?} has no single byte in common",
                String::from_utf8_lossy(pat),
            );
        }
    }

    /// A pattern that matches the empty string has no required byte, and
    /// reporting one for it would be a lie rather than merely a bad filter.
    #[test]
    fn a_pattern_that_can_match_nothing_but_empty_claims_no_byte() {
        assert!(req(b"a*").is_none());
        assert!(req(b"(a|)").is_none());
        assert!(req(b"").is_none());
    }

    /// **The mask's law, over the same trap grid as the other two, against
    /// real matches found by the VM.**
    ///
    /// Two properties, and they are different questions:
    ///
    /// - **Every match begins where the mask says.** A bit that is not a
    ///   match start is a false candidate and costs a confirm; a match start
    ///   that is not a bit is a DROPPED MATCH, which is the failure this whole
    ///   module is built to make impossible. This holds for a plan that
    ///   decides and for one that does not.
    /// - **Where the plan DECIDES, the two sets are the same.** Every bit is
    ///   a match and every match is a bit, so a searcher that settles a line
    ///   from a bit is right rather than nearly right. A plan that does not
    ///   decide says only the first: its bits are offsets the pattern's
    ///   required bytes fit at, which is not the same claim at all -- the mask
    ///   of `foo.*bar` is `foo`, and `foo` with no `bar` behind it is a bit
    ///   and not a match.
    ///
    /// The check is per LINE, because a mask works on the buffer and a match
    /// may not cross a terminator. A bit at `o` says a match BEGINS at `o` in
    /// the buffer, and a consumer that reports a LINE wants a match inside it,
    /// so the last `width - 1` bytes of a line are outside the claim. **The
    /// cut is the NARROWEST branch and not [`MatchMask::width`]**, which is the
    /// widest: `(pub|fn) [a-z]+` is four bytes wide in its `fn ` branch and
    /// five in its `pub ` branch, so cutting five drops every `fn x` that ends
    /// a line -- a match, and one `searcher::Candidates::of_mask` would lose.
    /// [`MatchMask::line_cut`] is where that number comes from and where the
    /// shapes it cannot cut are refused.
    ///
    /// A mask with no cut is checked at the width instead, which is the
    /// smaller range and so still says everything it said before.
    #[test]
    fn a_reported_mask_holds_for_every_match_and_is_exact_when_it_decides() {
        for pat in TRAPS {
            let Ok(parsed) = super::super::syntax::parse(pat) else {
                continue;
            };
            let prog = super::super::nfa::compile(&parsed.ast, parsed.groups);
            let Some(plan) = match_mask(&parsed.ast) else {
                continue;
            };
            let mask = super::super::scan::MatchMask::new(
                plan.branches
                    .iter()
                    .map(|b| super::super::scan::MaskBranch {
                        terms: b
                            .iter()
                            .map(|s| super::super::scan::MaskTerm {
                                class: s.class,
                                shift: s.at,
                            })
                            .collect(),
                    })
                    .collect(),
                plan.decides,
            )
            .expect("the plan is inside the producer's budget");
            for hay in HAYS {
                let mut ls = 0usize;
                while ls < hay.len() {
                    let le = hay[ls..]
                        .iter()
                        .position(|&b| b == b'\n')
                        .map_or(hay.len(), |i| ls + i);
                    let line = &hay[ls..le];
                    // The cut a CONSUMER applies, which is the narrowest
                    // branch and is narrower than `width` whenever the
                    // branches disagree. A mask with no cut is checked at the
                    // width instead, which is the smaller range and so still
                    // says everything it said before.
                    let width = mask.line_cut().unwrap_or_else(|| mask.width());
                    // The law every plan owes.
                    let mut at = 0usize;
                    while let Some(m) = super::super::vm::find(&prog, line, at) {
                        assert!(
                            mask.holds(line, m.start),
                            "{:?} drops the match {m:?} of {:?}",
                            String::from_utf8_lossy(pat),
                            String::from_utf8_lossy(line),
                        );
                        at = m.start + 1;
                    }
                    // And the one only a deciding plan owes.
                    if plan.decides {
                        for at in 0..line.len().saturating_sub(width - 1) {
                            assert_eq!(
                                mask.holds(line, at),
                                super::super::vm::matches_at(&prog, line, at),
                                "{:?} DECIDES and disagrees at {at} of {:?}",
                                String::from_utf8_lossy(pat),
                                String::from_utf8_lossy(line),
                            );
                        }
                    }
                    ls = le + 1;
                }
            }
        }
    }

    /// The masks of the nine acceptance patterns, read off the analysis
    /// rather than off the pattern text -- the table `benchmark/status.md` §4
    /// spells out, term for term.
    #[test]
    fn the_published_patterns_lower_to_the_published_masks() {
        let named = |pat: &[u8], _width: usize| -> Vec<Vec<(usize, String)>> {
            let parsed = super::super::syntax::parse(pat).expect("parses");
            let plan = match_mask(&parsed.ast).unwrap_or_else(|| panic!("{pat:?} has no mask"));
            assert!(plan.decides, "{pat:?} does not decide");
            plan.branches
                .iter()
                .map(|b| {
                    b.iter()
                        .map(|s| {
                            let members: String = (0..=255u8)
                                .filter(|&x| s.class.contains(x))
                                .map(|x| x as char)
                                .collect();
                            (s.at, members)
                        })
                        .collect()
                })
                .collect()
        };
        assert_eq!(
            named(b"e[0-9]", 2),
            vec![vec![(0, "e".into()), (1, "0123456789".into())]]
        );
        // Three disjoint single bytes: the parser coalesces `a|b|c`
        // into a single `Class({a,b,c})`, and the mask is one branch
        // of one class with three members. The Pike VM used to run
        // three threads for this; the parser now hands it one node.
        assert_eq!(named(b"a|b|c", 1), vec![vec![(0, "abc".into())]]);
        assert_eq!(named(b"e", 1), vec![vec![(0, "e".into())]]);
        assert_eq!(
            named(b"(pub|fn) [a-z]+", 5),
            vec![
                vec![
                    (0, "p".into()),
                    (1, "u".into()),
                    (2, "b".into()),
                    (3, " ".into()),
                    (4, "abcdefghijklmnopqrstuvwxyz".into()),
                ],
                vec![
                    (0, "f".into()),
                    (1, "n".into()),
                    (2, " ".into()),
                    (3, "abcdefghijklmnopqrstuvwxyz".into()),
                ],
            ]
        );
        // `let mut` is seven single bytes and `e.` is a byte and a class, and
        // both decide -- the second because `.` cannot be the terminator, and
        // the searcher only ever offers offsets inside a line's content.
        assert_eq!(named(b"let mut", 7).len(), 1);
        assert_eq!(named(b"e.", 2).len(), 1);
    }

    /// The shapes the mask must refuse or truncate, one per way of being
    /// wrong. A mask that claims more than it can back is a dropped match; one
    /// that claims less of itself than it can is a slower search.
    #[test]
    fn a_mask_is_never_more_than_the_pattern() {
        let plan = |pat: &[u8]| {
            let parsed = super::super::syntax::parse(pat).expect("parses");
            match_mask(&parsed.ast)
        };
        // An assertion: `^` is the start of a line to the searcher and the
        // start of a buffer to the mask.
        assert!(plan(b"^pub fn").is_none());
        assert!(plan(b"pub fn$").is_none());
        assert!(plan(b"\\bpub").is_none());
        // A capture is invisible to the mask and invisible to the line walk,
        // so it is NOT a refusal -- and refusing it would refuse
        // `(pub|fn) [a-z]+`, which is the pattern the mask exists for.
        assert!(plan(b"(pub) fn").is_some());
        // A pattern that matches the empty string matches at every offset, and
        // there is no set of offsets left to hold.
        assert!(plan(b"a*").is_none());
        assert!(plan(b"x?").is_none());
        assert!(plan(b"").is_none());
        assert!(plan(b"a|").is_none());
        // A middle repetition is a barrier: what is behind it slides, so the
        // mask keeps `foo` and says so.
        let p = plan(b"foo.*bar").expect("the prefix still masks");
        assert!(!p.decides, "`.*` slides, so `bar` cannot be placed");
        assert_eq!(p.branches.len(), 1);
        assert_eq!(p.branches[0].len(), 3);
        assert!(p.branches[0].iter().all(|s| s.at < 3));
        // And the same behind a variable ALTERNATION, which is the shape that
        // made `e.` a Pike VM run per line in the first place: the branch that
        // slides must not lend its offset to what follows it.
        let p = plan(b"(?:a|bc.*d)e").expect("the prefix still masks");
        assert!(!p.decides);
        assert_eq!(
            p.branches
                .iter()
                .map(|b| b.iter().map(|s| s.at).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            vec![vec![0], vec![0, 1]],
            "the sliding branch keeps its own exact bytes and nothing behind them"
        );
        // `a{2,5}` needs TWO bytes, not one: claiming one would claim a match
        // on a single `a`.
        let p = plan(b"a{2,5}").expect("a fixed lower bound still lowers");
        assert!(p.decides);
        assert_eq!(p.branches[0].len(), 2);
        // ...and a lower bound of one at the tail is ONE more copy of the
        // body, laid from the width the prefix reached. `ab+` needs one `b`
        // and the prefix already has an `a`, so the mask is two bytes -- and
        // `[a-z][a-z]+` needs two letters, which is the shape that would go
        // wrong if the repeat were read as adding nothing.
        let p = plan(b"ab+").expect("lowers");
        assert!(p.decides);
        assert_eq!(
            p.branches[0].iter().map(|s| s.at).collect::<Vec<_>>(),
            vec![0, 1]
        );
        let p = plan(b"[a-z][a-z]+").expect("lowers");
        assert!(p.decides);
        assert_eq!(
            p.branches[0].iter().map(|s| s.at).collect::<Vec<_>>(),
            vec![0, 1],
            "a `+` after an identical class is a SECOND letter, not a repeat of the first"
        );
    }

    /// The whole-pattern literal path still has to come out of the same
    /// analysis, or the two would disagree about `pub fn`.
    #[test]
    fn a_plain_literal_is_reported_whole_and_at_zero() {
        let r = one(b"pub fn");
        assert_eq!(r.bytes, b"pub fn".to_vec());
        assert_eq!(r.at, 0);
    }
}
