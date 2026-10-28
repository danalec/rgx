// SPDX-License-Identifier: Apache-2.0

//! Literal extraction: the cheapest way to decide whether a pattern can
//! match before paying for the automaton that decides where it matches.
//!
//! [`extract`] runs on the compile path ([`crate::regex::ByteRegex`]'s
//! `fast_literal`) to recognise a whole-literal pattern and hand it a
//! `memchr`-class plan. It produces positions that may contain a match;
//! the regex engine confirms them. The separation is deliberate: a mask
//! bug shows up as a false negative here, which a differential test
//! against the full engine catches.
//!
//! The mask test is a **superset** test by design — a bit is set when some
//! print has the byte's low nibble AND some (possibly different) print has
//! its high nibble — so the property to hold is that no byte of a
//! registered print is ever rejected.
//!
//! A packed SIMD mask tests many candidate bytes at once and tags which
//! of several literals matched, where `memmem` tests one literal at a
//! time. The distinction only pays when a pattern has several literals
//! or needs case folding: with a single exact literal, `memmem` is both
//! faster and simpler.
//!
//! The mask is built here; the SIMD scan that consumes it is
//! [`crate::prefilter`] — kept apart because the scan needs `unsafe`,
//! and the separation is what lets this file be exhaustively tested in
//! safe code.

use alloc::vec;
use alloc::vec::Vec;

use super::byteclass::ByteSet;

/// How a literal set relates to the pattern it came from.
///
/// `Exact` *is* the pattern: a hit means a match. `Inexact` is a
/// necessary but not sufficient condition: a hit means the engine
/// must run. Confusing the two is how a prefilter turns into a
/// correctness bug, so the distinction is in the type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LiteralKind {
    /// Every match contains this literal at a known offset. A hit is a
    /// match, subject only to the anchors the caller applies.
    ///
    /// Only reachable for ASCII-only literals, and only when the caller
    /// has no flags the extractor cannot see. A caseless literal over
    /// a non-ASCII byte is not `Exact`: an engine with Unicode folding
    /// matches `É` for `é` and U+212A for `k`, and the ASCII mask
    /// knows nothing about either. `extract` returns `None` for a
    /// caseless literal containing any byte ≥ 0x80.
    Exact,
    /// The literal is required for a match, but a hit does not imply
    /// one. The engine confirms.
    Inexact,
    /// No usable literal was found. The caller must run the engine
    /// over the whole buffer with no prefilter.
    None,
}

/// One literal: the bytes, and whether they are to be matched
/// case-insensitively.
///
/// The flag lives here rather than being expanded into separate literals
/// because expansion is what makes case-insensitive search slow. `(?i)ab`
/// expanded gives four literals; carrying the flag lets the mask
/// accept both cases at one position.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Literal {
    bytes: Vec<u8>,
    caseless: bool,
}

impl Literal {
    /// A case-sensitive literal.
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            caseless: false,
        }
    }

    /// A case-insensitive literal.
    pub fn caseless(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            caseless: true,
        }
    }

    /// The bytes as matched.
    ///
    /// Not normalised: a caseless literal holds the bytes the user typed,
    /// so the confirm step cannot assume lower case. See
    /// [`NibbleMask::confirm_key`] for the rule that actually works.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether matching ignores ASCII case.
    pub fn is_caseless(&self) -> bool {
        self.caseless
    }

    /// The shortest byte run this literal offers as a fingerprint,
    /// capped at `max`. The first three bytes of a twelve-byte needle
    /// discriminate as well as the whole thing, at a third the cost.
    /// The cap is 4: a packed mask tests `n` positions with `2n` shuffle
    /// inputs, and past that the verification saving stops paying for
    /// the setup.
    pub fn fingerprint(&self, max: usize) -> &[u8] {
        let n = if self.bytes.len() < max {
            self.bytes.len()
        } else {
            max
        };
        &self.bytes[..n]
    }
}

/// A set of literals, and how it relates to the pattern.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LiteralSet {
    literals: Vec<Literal>,
    kind: LiteralKind,
}

impl LiteralSet {
    /// The empty set, which means "no prefilter". This is what a pattern
    /// with no usable literal produces, and it is deliberately not an
    /// error: a search with no prefilter is slower, not wrong.
    pub fn none() -> Self {
        Self {
            literals: Vec::new(),
            kind: LiteralKind::None,
        }
    }

    /// A set whose hits are matches.
    pub fn exact(literals: Vec<Literal>) -> Self {
        Self {
            literals,
            kind: LiteralKind::Exact,
        }
    }

    /// A set whose hits need confirming.
    pub fn inexact(literals: Vec<Literal>) -> Self {
        Self {
            literals,
            kind: LiteralKind::Inexact,
        }
    }

    /// The literals, empty when there is no prefilter.
    pub fn literals(&self) -> &[Literal] {
        &self.literals
    }

    /// Whether a hit means a match, a candidate, or nothing at all.
    pub fn kind(&self) -> LiteralKind {
        self.kind
    }

    /// Whether this set can be used as a prefilter at all.
    pub fn is_usable(&self) -> bool {
        self.kind != LiteralKind::None && !self.literals.is_empty()
    }

    /// The shortest literal length, which is what decides whether a packed
    /// mask beats `memmem`. A one-byte literal matches every byte of text,
    /// so the candidate set is the whole haystack. The same threshold
    /// `regex-automata` uses to decide a Teddy prefilter is worth trusting
    /// (`minimum_len >= 3`).
    pub fn min_len(&self) -> usize {
        self.literals
            .iter()
            .map(|l| l.bytes.len())
            .min()
            .unwrap_or(0)
    }

    /// The bytes that may appear at the start of a match.
    ///
    /// The set a scan would test when it wants the cheapest possible
    /// rejection, and what [`NibbleMask`] is built from. For a caseless
    /// literal the set holds both cases, because that is what the engine
    /// will actually accept at that position.
    pub fn leading_bytes(&self) -> ByteSet {
        let mut set = ByteSet::empty();
        for lit in &self.literals {
            if let Some(&b) = lit.bytes.first() {
                set.insert(b);
                if lit.caseless {
                    set.insert(ascii_flip(b));
                }
            }
        }
        set
    }
}

/// The byte that differs from `b` only in ASCII case, or `b` itself
/// when it has none.
///
/// Only bit 5 (0x20) carries ASCII case. Digits, punctuation and every
/// non-ASCII byte are fixed by the operation, which is why a caseless
/// literal costs *two* mask entries at a letter and *one* everywhere
/// else.
#[must_use]
pub fn ascii_flip(b: u8) -> u8 {
    if b.is_ascii_alphabetic() {
        b ^ 0x20
    } else {
        b
    }
}

/// The shortest fingerprint a mask is allowed to use. With a single
/// 1-byte fingerprint the first stage accepts `1/256` of all bytes and
/// the verify step costs more than the scan it was meant to replace.
/// Two is the floor where the mask beats `memmem` for a multi-literal
/// set; three is where it decisively does.
pub const MIN_FINGERPRINT: usize = 2;

/// The longest fingerprint a mask will build, for the reason given on
/// [`Literal::fingerprint`].
pub const MAX_FINGERPRINT: usize = 4;

/// How a literal's fingerprint is bucketed for the SIMD scan. A packed
/// mask cannot test an unbounded number of literals at once: the scan
/// tags each candidate byte with a bucket index, and the index has to
/// fit in the bits the mask reserves. Eight is what a 128-bit vector
/// supports without the doubled-mask layout that halves the bytes per
/// iteration.
pub const MAX_BUCKETS: usize = 8;

/// The set of literals a mask can test in one pass.
///
/// The *safe* half of a packed prefilter. Building it is pure
/// arithmetic over a nibble table, and it is where every correctness
/// property of the prefilter is decided: a mask built wrong here
/// drops candidates silently, and a dropped candidate is a missed
/// match. The scan that consumes it is `unsafe` and is allowed to be
/// merely fast.
///
/// One table pair per mask position, not one for the whole set. With
/// a single pair ORed across every position, the test a byte has to
/// pass is "does its nibble appear at some position of some
/// fingerprint", which for a 4-byte fingerprint accepts roughly 8 of
/// 256 byte values per bucket — 14-37% of all bytes on real text.
/// With one pair per position and the positions accumulated, surviving
/// `n` bytes means `n` consecutive bytes agreed, and the same
/// measurement falls to 0.05-0.19%.
///
/// The case decision lives here, in construction, and not in the scan:
/// a caseless literal registers both of its ASCII cases at the
/// position, so the scan never folds the haystack and a case-sensitive
/// literal in the same set still matches exactly. Folding at scan
/// time would make `Function` match a pattern for `function`
/// whenever the two appear in one set — a false positive, strictly
/// worse than the false negatives the per-position form fixes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NibbleMask {
    /// For each mask position, and each of 16 possible low-nibble values,
    /// the buckets whose fingerprint has that low nibble at that position.
    lo: Vec<[u16; 16]>,
    /// The same for high nibbles.
    hi: Vec<[u16; 16]>,
    /// The fingerprints, kept so the confirm step knows what to check.
    prints: Vec<Vec<u8>>,
    /// Which buckets are actually occupied.
    used: u16,
    /// Which prints went into which bucket, indexed by bucket. Kept
    /// separate from `prints` (which is insertion-ordered) because a
    /// confirm loop must be able to ask "what is in bucket k" and the two
    /// orders differ.
    bucket_prints: Vec<Vec<Vec<u8>>>,
    /// Which buckets hold a caseless literal, one bit per bucket.
    ///
    /// This cannot be recovered from the tables: a caseless literal and a
    /// case-sensitive one that happens to sit in the same bucket leave the
    /// same trace for a lower-case byte, and the confirm needs to know
    /// which — folding a case-sensitive window would match a pattern it must
    /// not.
    bucket_caseless: u16,
    /// Per position, the buckets that have **no opinion** about that position
    /// because their fingerprint is shorter than the window, one bit per
    /// bucket, same width as `lo`/`hi`, and always the same length as `lo`.
    ///
    /// `add_padded` encodes a don't-care by setting a bucket's bit in all 16
    /// slots of a position, so the information is recoverable but not
    /// *legible*: nothing downstream could ask "which buckets don't need this
    /// byte?" without scanning 32 entries. A scan needs exactly that question at
    /// the end of a haystack, where the window runs off the end and the
    /// readable positions have to be folded forward -- and a bucket with no
    /// opinion there must survive the fold while one with a real byte there must
    /// not. Folding blindly keeps both alive and admits `cd` for `cde`.
    dontcare: Vec<u16>,
}

impl NibbleMask {
    /// An empty mask that matches nothing.
    pub fn new() -> Self {
        Self {
            lo: Vec::new(),
            hi: Vec::new(),
            prints: Vec::new(),
            used: 0,
            bucket_prints: vec![Vec::new(); MAX_BUCKETS],
            bucket_caseless: 0,
            dontcare: Vec::new(),
        }
    }

    /// Add a literal to `bucket`, testing each of its fingerprint's
    /// bytes at its own mask position.
    ///
    /// The case flag is handled here and nowhere else. For a caseless
    /// ASCII letter, both cases are registered at that position: the
    /// differing bit is bit 5, which lives in the high nibble, so the
    /// two cases differ in `hi` and usually share an `lo` entry.
    ///
    /// Returns `false` if the bucket is out of range or the print is
    /// empty. An empty print must be refused: it would set `used`
    /// while matching no byte, so [`Self::is_empty`] would report a
    /// mask that can never fire.
    #[must_use]
    pub fn add(&mut self, bucket: usize, print: &[u8], caseless: bool) -> bool {
        if bucket >= MAX_BUCKETS || print.is_empty() {
            return false;
        }
        while self.lo.len() < print.len() {
            self.lo.push([0; 16]);
            self.hi.push([0; 16]);
            // `dontcare` is indexed by the same position number as `lo`,
            // so it grows with them. Leaving it behind here would fail
            // loudly in `add_padded` instead of silently.
            self.dontcare.push(0);
        }
        let bit = 1u16 << bucket;
        self.used |= bit;
        for (j, &b) in print.iter().enumerate() {
            self.lo[j][usize::from(b & 0x0F)] |= bit;
            self.hi[j][usize::from(b >> 4)] |= bit;
            if caseless {
                let other = ascii_flip(b);
                if other != b {
                    // Only the high nibble differs for an ASCII letter, but
                    // registering both halves is unconditional and costs
                    // nothing measurable.
                    self.lo[j][usize::from(other & 0x0F)] |= bit;
                    self.hi[j][usize::from(other >> 4)] |= bit;
                }
            }
        }
        self.prints.push(print.to_vec());
        self.bucket_prints[bucket].push(print.to_vec());
        if caseless {
            self.bucket_caseless |= bit;
        }
        true
    }

    /// Add a literal that only constrains the first `print.len()` of a
    /// `width`-position window, matching every byte at the positions past it.
    ///
    /// This is what makes a mask of unequal-length prints work at all.
    /// The scan ANDs one table lookup per position, so a bucket whose
    /// print is shorter than the mask is wide simply has no entry at
    /// the trailing positions and its AND evaluates to zero — the
    /// literal is not reported anywhere, silently, for every haystack.
    /// `build_mask` used to build exactly that mask for `{pub, fn}`,
    /// so `fn` could never fire.
    ///
    /// Registering the bucket at every remaining nibble is the "don't
    /// care" the scan needs: `lo[j][n] & hi[j][n]` is non-zero for every
    /// byte, so the position passes without constraining it. A handful
    /// of ORs at build time and nothing at all at scan time.
    ///
    /// `width` must be at least `print.len()` and at most
    /// [`MAX_FINGERPRINT`]; anything else is a caller error.
    #[must_use]
    pub fn add_padded(
        &mut self,
        bucket: usize,
        print: &[u8],
        caseless: bool,
        width: usize,
    ) -> bool {
        if width < print.len() || width > MAX_FINGERPRINT {
            return false;
        }
        if !self.add(bucket, print, caseless) {
            return false;
        }
        let bit = 1u16 << bucket;
        while self.lo.len() < width {
            self.lo.push([0; 16]);
            self.hi.push([0; 16]);
            self.dontcare.push(0);
        }
        debug_assert_eq!(self.dontcare.len(), self.lo.len());
        for j in print.len()..width {
            for slot in self.lo[j].iter_mut().chain(self.hi[j].iter_mut()) {
                *slot |= bit;
            }
            // And say so here, so a scan at the end of a haystack can
            // fold this position forward without reading the tables.
            self.dontcare[j] |= bit;
        }
        true
    }

    /// How many positions a match must cover, i.e. the fingerprint
    /// length. A scan accumulates one table lookup per position, so
    /// this is both the AND depth and the number of table pairs to
    /// broadcast.
    #[must_use]
    pub fn positions(&self) -> usize {
        self.lo.len()
    }

    /// Per position, the buckets with no opinion about it. Same length
    /// as [`Self::positions`].
    #[must_use]
    pub fn dontcare_at(&self) -> &[u16] {
        debug_assert_eq!(self.dontcare.len(), self.lo.len());
        &self.dontcare
    }

    /// Whether bucket `bucket` holds at least one caseless literal.
    ///
    /// A confirm step needs this and cannot derive it: `lo` and `hi`
    /// record that both cases of a letter were accepted, which looks
    /// identical whether the literal was caseless or the cases were
    /// registered separately. Folding the window when it must not be
    /// folded produces a false positive; not folding when it must be
    /// produces a false negative.
    #[must_use]
    pub fn is_caseless_bucket(&self, bucket: usize) -> bool {
        bucket < MAX_BUCKETS && self.bucket_caseless & (1u16 << bucket) != 0
    }

    /// Whether any literal is in this mask.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// The bucket bitmask for a byte: the low-nibble table indexed by
    /// the byte's low nibble, ANDed with the high-nibble table indexed
    /// by its high nibble.
    ///
    /// This is one lane of what the SIMD scan computes with two `pshufb`
    /// lookups and an AND. It is a **superset** test, not an equality
    /// test — the scan's job is to over-report candidates cheaply
    /// and the confirm step narrows them.
    #[must_use]
    pub fn bucket_for(&self, b: u8) -> u16 {
        self.bucket_at(0, b)
    }

    /// Register a bucket whose each position accepts a SET of bytes.
    ///
    /// `add` is for a bucket that is one literal. A required-bytes
    /// skeleton often is not — `e[0-9]` forces an `e` at offset 0 and
    /// a digit at offset 1, and no literal has that shape, so the two
    /// positions have to be constrained independently. This is the AND
    /// of two one-position masks, built once.
    ///
    /// `prints` and `bucket_prints` record the first member of each
    /// position concatenated, which is not a literal any match contains
    /// and must not be confirmed as one. A caller that needs a literal
    /// confirm ([`crate::prefilter::Prefilter`]) must not be handed a
    /// mask built this way.
    #[must_use]
    pub fn add_alternatives(&mut self, bucket: usize, sets: &[&[u8]], caseless: bool) -> bool {
        if bucket >= MAX_BUCKETS || sets.is_empty() || sets.iter().any(|s| s.is_empty()) {
            return false;
        }
        if sets.len() > MAX_FINGERPRINT {
            return false;
        }
        while self.lo.len() < sets.len() {
            self.lo.push([0; 16]);
            self.hi.push([0; 16]);
            // `dontcare` is indexed by the same position number as `lo`,
            // so it grows with it.
            self.dontcare.push(0);
        }
        let bit = 1u16 << bucket;
        self.used |= bit;
        for (j, set) in sets.iter().enumerate() {
            for &b in *set {
                self.lo[j][usize::from(b & 0x0F)] |= bit;
                self.hi[j][usize::from(b >> 4)] |= bit;
                if caseless {
                    let other = ascii_flip(b);
                    if other != b {
                        self.lo[j][usize::from(other & 0x0F)] |= bit;
                        self.hi[j][usize::from(other >> 4)] |= bit;
                    }
                }
            }
        }
        self.prints
            .push(sets.iter().filter_map(|s| s.first()).copied().collect());
        self.bucket_prints[bucket].push(Vec::new());
        if caseless {
            self.bucket_caseless |= bit;
        }
        true
    }

    /// The bucket bitmask for byte `b` at mask position `j`.
    ///
    /// This is the per-position test, and it is a **superset** of "byte
    /// `b` starts a match": the byte is acceptable at position `j` for
    /// *some* bucket, not that the neighbouring bytes were. The scan
    /// over-reports cheaply; the confirm narrows by ANDing one of
    /// these per position — the AND of positions `j` and `j+1` is
    /// already a two-byte test.
    ///
    /// Out of range `j` yields 0, the correct answer (a position
    /// beyond the fingerprint cannot be part of one), and keeps a scan
    /// that walks a fixed position count from needing a bounds check.
    #[must_use]
    pub fn bucket_at(&self, j: usize, b: u8) -> u16 {
        match self.lo.get(j) {
            Some(lo) => {
                let hi = &self.hi[j];
                lo[usize::from(b & 0x0F)] & hi[usize::from(b >> 4)]
            }
            None => 0,
        }
    }

    /// The registered fingerprints.
    pub fn fingerprints(&self) -> &[Vec<u8>] {
        &self.prints
    }

    /// The low-nibble table for mask position `j`, for a SIMD scan to
    /// broadcast. The contract between the safe builder and the
    /// `unsafe` consumer — a scan cannot be written against the
    /// private fields.
    ///
    /// Returns a zero table for a position past the fingerprint, so a
    /// scan that walks [`Self::positions`] positions needs no bounds
    /// check.
    #[must_use]
    pub fn low_nibbles_at(&self, j: usize) -> &[u16; 16] {
        const ZERO: [u16; 16] = [0; 16];
        self.lo.get(j).unwrap_or(&ZERO)
    }

    /// The high-nibble table for mask position `j`.
    #[must_use]
    pub fn high_nibbles_at(&self, j: usize) -> &[u16; 16] {
        const ZERO: [u16; 16] = [0; 16];
        self.hi.get(j).unwrap_or(&ZERO)
    }

    /// A bitmask of the buckets that hold at least one literal. A scan
    /// ANDs this in so a lane whose byte is in no bucket reads as "no
    /// candidate" rather than matching a stale table entry.
    #[must_use]
    pub fn used_buckets(&self) -> u16 {
        self.used
    }

    /// The literals registered in `bucket`, in the order they were added.
    ///
    /// `build_mask` registers one literal per bucket, so for a mask it
    /// built this returns a single literal. The order is insertion
    /// order, **not** bucket order: adding bucket 5 then bucket 0
    /// leaves bucket 0 second. A confirm loop must ask this rather than
    /// index [`Self::fingerprints`] by bucket, or it confirms the wrong
    /// literal.
    #[must_use]
    pub fn bucket_of(&self, bucket: usize) -> Option<&[Vec<u8>]> {
        if bucket >= MAX_BUCKETS {
            return None;
        }
        self.bucket_prints.get(bucket).map(|v| v.as_slice())
    }

    /// The key a confirm step compares an 8-byte window against, with
    /// the case folded to a canonical form.
    ///
    /// The rule is: **lowercase only at positions where the pattern byte
    /// is an ASCII letter, and compare the folded window against the
    /// folded pattern with no mask at all.** `to_ascii_lowercase` is the
    /// identity on non-letters, so a non-letter position can never alias
    /// a different byte.
    ///
    /// It is deliberately not [`ascii_flip`], which XORs bit 5 and so
    /// toggles case rather than normalising it. Toggling is right for
    /// the mask — accepting both cases is the goal there — and wrong
    /// here: folding `AlPh` by toggling yields `aLpH`, which does not
    /// equal the folded window `alph` and would miss a match the engine
    /// finds. `confirm_key_folds_letters_only` pins that.
    ///
    /// Returns `None` when the literal is longer than 8 bytes: an `u64`
    /// confirm cannot represent it, the caller falls back to `memcmp`.
    #[must_use]
    pub fn confirm_key(prints: &[u8], caseless: bool) -> Option<u64> {
        if prints.len() > 8 {
            return None;
        }
        let mut key = 0u64;
        for (i, &b) in prints.iter().enumerate() {
            let byte = if caseless { b.to_ascii_lowercase() } else { b };
            key |= u64::from(byte) << (8 * i);
        }
        Some(key)
    }
}

impl Default for NibbleMask {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a mask from a literal set, one bucket per literal.
///
/// Returns `None` when the set is unusable. A caller falls back to the
/// engine over the whole buffer, which is correct and merely slower.
///
/// `max_len` is clamped to [`MAX_FINGERPRINT`]. It is a request, not a
/// licence: passing 99 must not produce a 99-byte print, because the
/// cost model assumes a bounded fingerprint and a longer one would
/// silently break the "capped at 4" invariant the scan depends on.
pub fn build_mask(set: &LiteralSet, max_len: usize) -> Option<NibbleMask> {
    if !set.is_usable() {
        return None;
    }
    if set.literals().len() > MAX_BUCKETS {
        // Beyond the bucket count the mask would need the doubled-nibble
        // layout, which halves bytes per iteration. The trade is not
        // worth guessing at; the caller falls back.
        return None;
    }
    let max_len = if max_len > MAX_FINGERPRINT {
        MAX_FINGERPRINT
    } else {
        max_len
    };
    if max_len < MIN_FINGERPRINT {
        return None;
    }

    let mut mask = NibbleMask::new();
    let prints: Vec<&[u8]> = set
        .literals()
        .iter()
        .map(|l| l.fingerprint(max_len))
        .collect();
    if prints.iter().any(|p| p.len() < MIN_FINGERPRINT) {
        return None;
    }
    // One window width for every bucket, padded with don't-care
    // positions for the shorter prints. Without it a bucket narrower
    // than the mask never fires — see [`NibbleMask::add_padded`].
    let width = prints.iter().map(|p| p.len()).max().unwrap_or(0);
    for (assigned, (lit, &print)) in set.literals().iter().zip(prints.iter()).enumerate() {
        if !mask.add_padded(assigned, print, lit.is_caseless(), width) {
            return None;
        }
    }
    Some(mask)
}

/// The literal set a pattern implies, given the bytes that must appear
/// for it to match.
///
/// For a pattern that is a plain literal it reports `Exact`, which
/// means "every match contains these bytes at offset 0". It does not
/// know about word boundaries, line anchors or the caller's other
/// flags: a caller running under `-w` must either pass the bare
/// literal and accept that a hit is only a *candidate word*, or pass
/// the wrapped pattern — in which case `\b` makes `is_meta` reject it
/// and the answer is `None`.
///
/// It reports `Inexact` never, because the only analysis it can do
/// without the AST is the whole-pattern one. The variant exists for
/// the AST-based prefix/suffix extraction.
pub fn extract(pattern: &[u8], caseless: bool) -> LiteralSet {
    if pattern.is_empty() {
        return LiteralSet::none();
    }

    // Top-level alternation `foo|bar|baz` — split on `|` (taking parens
    // and char classes into account so a `|` inside `[...]` or `(...)`
    // is not a branch separator) and build one literal per arm. The
    // multi-literal prefilter (NibbleMask buckets 0..8) handles the
    // set directly; the per-arm cost from `extract` is one branch
    // analysis each. An alternation with three 6-byte arms wins on every
    // corpus the prefilter is the bottleneck.
    if let Some(arms) = split_top_level_alts(pattern) {
        return extract_alts(&arms, caseless);
    }

    // A pattern with a metacharacter anywhere is not a literal.
    if pattern.iter().any(|&b| is_meta(b)) {
        return LiteralSet::none();
    }

    // A caseless literal whose fold leaves ASCII cannot be `Exact`. Unicode
    // case folding maps `é` to `É` and `k` to U+212A, neither of which an
    // ASCII fold reaches -- and `k` is an ASCII byte, so the ≥ 0x80 test
    // alone does not catch the literal that matters. A mask built from the
    // ASCII pairs would drop every match that uses a wider member.
    if caseless
        && pattern
            .iter()
            .any(|&b| b >= 0x80 || !crate::unicode_case::fold_stays_ascii(b))
    {
        return LiteralSet::none();
    }

    let lit = if caseless {
        Literal::caseless(pattern)
    } else {
        Literal::new(pattern)
    };

    // Exact only when the literal *is* the whole pattern. A short pattern
    // is a bad fingerprint no matter how exact it is.
    if pattern.len() < MIN_FINGERPRINT {
        return LiteralSet::none();
    }
    LiteralSet::exact(vec![lit])
}

/// Split a pattern on `|` operators that sit at the top of the regex
/// grammar (i.e. outside any `(...)` group or `[...]` class). Returns
/// `None` when the pattern is not a top-level alternation.
fn split_top_level_alts(pattern: &[u8]) -> Option<Vec<&[u8]>> {
    let mut arms: Vec<&[u8]> = Vec::new();
    let mut start = 0usize;
    let mut depth: i32 = 0; // paren depth
    let mut in_class = false;
    let mut i = 0usize;
    while i < pattern.len() {
        let b = pattern[i];
        if in_class {
            if b == b']' {
                in_class = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\\' => {
                // Skip the escape so a `\|` inside a class does not
                // confuse us.
                i += 2;
                continue;
            }
            b'[' => {
                in_class = true;
                i += 1;
                continue;
            }
            b'(' => {
                depth += 1;
                i += 1;
                continue;
            }
            b')' => {
                if depth > 0 {
                    depth -= 1;
                }
                i += 1;
                continue;
            }
            b'|' if depth == 0 => {
                arms.push(&pattern[start..i]);
                start = i + 1;
                i += 1;
                continue;
            }
            _ => {
                i += 1;
                continue;
            }
        }
    }
    if arms.is_empty() {
        return None;
    }
    arms.push(&pattern[start..]);
    Some(arms)
}

/// Build a `LiteralSet` from a pre-split alternation. Every arm becomes
/// its own `Literal` in one `Inexact` set; the multi-literal prefilter's
/// mask fans the candidates out to whichever arm fires.
fn extract_alts(arms: &[&[u8]], caseless: bool) -> LiteralSet {
    if arms.len() < 2 {
        return LiteralSet::none();
    }
    let mut lits = Vec::with_capacity(arms.len());
    for arm in arms {
        // A metachar arm is not a literal; a non-ASCII caseless arm
        // is not; a sub-fingerprint arm is not. Any one bad arm takes
        // the whole prefilter down (the engine still matches, only the
        // prefilter is gone).
        if arm.iter().any(|&b| is_meta(b)) {
            return LiteralSet::none();
        }
        // Same rule as `extract`'s own check: a caseless arm whose fold
        // leaves ASCII is not a fixed byte-set literal, and a mask over
        // the ASCII pairs would drop the wider members' matches.
        if caseless
            && arm
                .iter()
                .any(|&b| b >= 0x80 || !crate::unicode_case::fold_stays_ascii(b))
        {
            return LiteralSet::none();
        }
        if arm.len() < MIN_FINGERPRINT {
            return LiteralSet::none();
        }
        lits.push(if caseless {
            Literal::caseless(arm)
        } else {
            Literal::new(arm)
        });
    }
    LiteralSet::inexact(lits)
}

/// Whether a byte is a regex metacharacter this extractor cannot treat
/// as a literal byte.
///
/// Crate-visible because `regex` asks the same question before
/// handing a one-byte pattern to `memchr`.
pub(crate) fn is_meta(b: u8) -> bool {
    matches!(
        b,
        b'\\'
            | b'.'
            | b'^'
            | b'$'
            | b'*'
            | b'+'
            | b'?'
            | b'|'
            | b'('
            | b')'
            | b'['
            | b']'
            | b'{'
            | b'}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;

    /// The whole reason this module exists, stated as a test: a caseless
    /// pattern must produce ONE literal, not `2^k` of them. If this ever
    /// fails, the expansion is back and every downstream number is wrong.
    #[test]
    fn caseless_extraction_does_not_expand() {
        let set = extract(b"error", true);
        assert_eq!(set.literals().len(), 1, "one literal, not 2^k");
        assert!(set.literals()[0].is_caseless());
        assert_eq!(set.kind(), LiteralKind::Exact);
    }

    /// A top-level alternation produces one `Literal` per arm, and the
    /// prefilter holds them in an `Inexact` set so the multi-literal
    /// SIMD scan can fan out candidates to whichever arm fires.
    #[test]
    fn top_level_alternation_extracts_one_literal_per_arm() {
        let set = extract(b"error|fatal|panic", false);
        assert_eq!(set.kind(), LiteralKind::Inexact);
        assert_eq!(set.literals().len(), 3);
        let bytes: Vec<&[u8]> = set.literals().iter().map(|l| l.bytes()).collect();
        assert!(bytes.contains(&b"error".as_slice()));
        assert!(bytes.contains(&b"fatal".as_slice()));
        assert!(bytes.contains(&b"panic".as_slice()));
    }

    /// An alternation whose arms are too short for a fingerprint
    /// (`MIN_FINGERPRINT` is two) declines cleanly rather than
    /// contributing a meaningless literal to the mask.
    #[test]
    fn a_short_armed_alternation_is_declined() {
        let set = extract(b"a|b|c", false);
        assert!(set.literals().is_empty(), "no arm is fingerprint-sized");
    }

    /// A `|` inside `[...]` or `(...)` is not an alternation separator:
    /// `[a|b]` is a byte class, and `(foo|bar)` keeps the parens so the
    /// top-level split sees a single contiguous pattern.
    #[test]
    fn pipes_inside_classes_and_groups_do_not_split() {
        // `[a|b]` is a class; `foo|bar` is the top-level split.
        assert!(extract(b"[a|b]", false).literals().is_empty());
        // `(foo|bar)` keeps the parens on each arm; after the split the
        // arms contain `(` and `)` which `is_meta` rejects.
        let set = extract(b"(foo|bar)", false);
        assert!(
            set.literals().is_empty(),
            "metachar-bearing arms are not literals"
        );
    }

    /// Both cases must be *accepted* by the leading-byte set, because the
    /// engine accepts both. A mask built from only one case would report
    /// zero candidates for half the matches, which is a silent wrong
    /// answer rather than a slow one.
    #[test]
    fn caseless_leading_bytes_hold_both_cases() {
        let set = extract(b"error", true);
        let lead = set.leading_bytes();
        assert!(lead.contains(b'e') && lead.contains(b'E'));
    }

    /// A non-letter has no case variant, so adding it must not silently
    /// add a second entry for a byte that is its own partner. The
    /// `ascii_flip` identity is what makes the mask's two-entry cost
    /// apply only where it is earned.
    #[test]
    fn ascii_flip_is_identity_outside_letters() {
        for b in b'0'..=b'9' {
            assert_eq!(ascii_flip(b), b);
        }
        assert_eq!(ascii_flip(b'_'), b'_');
        assert_eq!(ascii_flip(b'/'), b'/');
        assert_eq!(ascii_flip(b'\n'), b'\n');
        // Bytes >= 0x80 are not ASCII and must be left alone.
        assert_eq!(ascii_flip(0xC3), 0xC3);
    }

    /// A caseless letter must map to the other case, and only for
    /// letters.
    #[test]
    fn ascii_flip_pairs_letters() {
        assert_eq!(ascii_flip(b'a'), b'A');
        assert_eq!(ascii_flip(b'A'), b'a');
        assert_eq!(ascii_flip(b'z'), b'Z');
    }

    /// A metacharacter must produce no prefilter at all. Getting this
    /// wrong in the permissive direction is a correctness bug: a hit at a
    /// candidate would be reported as a match that does not exist.
    #[test]
    fn metacharacters_yield_no_prefilter() {
        for pat in [
            &b"foo.*bar"[..],
            b"^start",
            b"end$",
            b"a|b",
            b"(grp)",
            b"[cls]",
        ] {
            assert_eq!(
                extract(pat, false).kind(),
                LiteralKind::None,
                "{:?} must not yield a literal",
                String::from_utf8_lossy(pat)
            );
        }
    }

    /// A one- or two-byte pattern is exact but still useless as a
    /// fingerprint, so the extractor must decline it rather than hand
    /// back a mask that costs more than it saves.
    #[test]
    fn short_patterns_are_declined() {
        assert_eq!(extract(b"a", false).kind(), LiteralKind::None);
        // Two bytes is exactly the floor, and is accepted.
        assert_eq!(extract(b"ab", false).kind(), LiteralKind::Exact);
    }

    /// The mask must accept the byte a literal has *at that position*, and
    /// reject one it does not. Both caseless and case-sensitive, because the
    /// caseless path is the one with the extra entry and so the one most
    /// likely to be wrong.
    #[test]
    fn mask_accepts_only_registered_bytes() {
        let mut mask = NibbleMask::new();
        assert!(mask.add(0, b"ab", false));
        assert_eq!(mask.positions(), 2, "a 2-byte print needs 2 positions");
        assert_eq!(mask.bucket_at(0, b'a'), 0b1);
        assert_eq!(mask.bucket_at(1, b'b'), 0b1);
        // 'b' is at position 1, so position 0 must not accept it. This is the
        // property the per-position form buys and the old single-pair mask
        // could not express: the test is position-specific.
        assert_eq!(mask.bucket_at(0, b'b') & 0b1, 0, "'b' is not at position 0");
        // 'c' is in neither position.
        assert_eq!(mask.bucket_at(0, b'c') & 0b1, 0);
        assert_eq!(mask.bucket_at(1, b'c') & 0b1, 0);
    }

    /// The caseless mask must accept BOTH cases, and that is the property
    /// the whole design turns on.
    #[test]
    fn caseless_mask_accepts_both_cases() {
        let mut mask = NibbleMask::new();
        assert!(mask.add(0, b"ab", true));
        assert_ne!(mask.bucket_at(0, b'a') & 0b1, 0, "lowercase accepted");
        assert_ne!(mask.bucket_at(0, b'A') & 0b1, 0, "uppercase accepted");
        assert_ne!(mask.bucket_at(1, b'b') & 0b1, 0);
        assert_ne!(mask.bucket_at(1, b'B') & 0b1, 0);
        // Still rejecting a byte that is neither.
        assert_eq!(mask.bucket_at(0, b'q') & 0b1, 0);
    }

    /// A caseless non-letter in a fingerprint must not widen the mask:
    /// `1` has no case partner, so only one entry is cleared. If this
    /// regressed, a digit in a fingerprint would accept twice as many
    /// bytes and the candidate rate would quietly double.
    #[test]
    fn caseless_digit_does_not_widen() {
        let mut caseless = NibbleMask::new();
        assert!(caseless.add(0, b"1a", true));
        let mut exact = NibbleMask::new();
        assert!(exact.add(0, b"1a", false));
        // Both must agree on what '1' matches: exactly the one bucket.
        assert_eq!(caseless.bucket_for(b'1'), exact.bucket_for(b'1'));
    }

    /// A bucket index past the bucket count is a caller error and must be
    /// refused, not truncated. A truncated index would alias two literals
    /// into one bucket and the confirm step would report the wrong one.
    #[test]
    fn out_of_range_bucket_is_refused() {
        let mut mask = NibbleMask::new();
        assert!(!mask.add(MAX_BUCKETS, b"ab", false));
        assert!(mask.is_empty(), "a refused add must not register");
    }

    /// More literals than buckets cannot be packed, and the builder must
    /// say so rather than silently dropping the overflow.
    #[test]
    fn too_many_literals_yields_no_mask() {
        let lits: Vec<Literal> = (0..MAX_BUCKETS + 1)
            .map(|i| Literal::new(&[b'a' + (i as u8 % 26), b'0' + (i as u8 % 10)]))
            .collect();
        let set = LiteralSet::exact(lits);
        assert!(build_mask(&set, 3).is_none());
    }

    /// The mask must reject a literal set whose members are too short to
    /// discriminate. This is the rule that keeps a 1-byte "prefilter"
    /// from costing more than the scan it replaces.
    #[test]
    fn short_fingerprints_yield_no_mask() {
        let set = LiteralSet::inexact(vec![Literal::new(b"x")]);
        assert!(build_mask(&set, 4).is_none());
    }

    /// An exact single literal of usable length must build.
    #[test]
    fn a_usable_literal_builds_a_mask() {
        let set = extract(b"function", false);
        let mask = build_mask(&set, MAX_FINGERPRINT).expect("should build");
        assert!(!mask.is_empty());
        assert_eq!(mask.fingerprints().len(), 1);
        // Capped at MAX_FINGERPRINT, not the whole 8-byte literal.
        assert_eq!(mask.fingerprints()[0].len(), MAX_FINGERPRINT);
    }

    /// The fingerprint is a *prefix* of the literal, so it must be
    /// shorter than or equal to the literal and never empty for a
    /// non-empty literal.
    #[test]
    fn fingerprint_is_capped_and_never_empty() {
        let long = Literal::new(b"abcdefgh");
        assert_eq!(long.fingerprint(3), b"abc");
        assert_eq!(long.fingerprint(MAX_FINGERPRINT).len(), MAX_FINGERPRINT);
        let short = Literal::new(b"ab");
        assert_eq!(short.fingerprint(MAX_FINGERPRINT), b"ab");
    }

    /// A no-prefilter set must not build a mask, and must say so. The
    /// caller needs to distinguish "no mask" from "empty mask", because
    /// the first means run the engine and the second would mean a
    /// pattern that can never match.
    #[test]
    fn no_prefilter_set_builds_nothing() {
        assert!(build_mask(&LiteralSet::none(), 4).is_none());
        assert!(!LiteralSet::none().is_usable());
    }

    /// A caseless literal over a non-ASCII byte must NOT be `Exact`.
    /// Unicode folding maps `é` to `É` and `k` to U+212A; an ASCII-only mask
    /// knows neither, so a caller trusting `Exact` would miss both. Found by
    /// adversarial review as a reachable false negative through the public
    /// API with no opt-out.
    #[test]
    fn caseless_non_ascii_is_never_exact() {
        assert_eq!(extract("é".as_bytes(), true).kind(), LiteralKind::None);
        // U+212A KELVIN SIGN is a case fold of ASCII 'k' and has no ASCII
        // representation at all.
        assert_eq!(extract(b"\xe2\x84\xaa", true).kind(), LiteralKind::None);
        // Non-caseless non-ASCII is fine: those bytes have no case variants.
        assert_eq!(extract("é".as_bytes(), false).kind(), LiteralKind::Exact);
    }

    /// An ASCII byte whose fold reaches outside ASCII is not `Exact` under
    /// `(?i)` either: `k` folds to U+212A and `s` to `ſ`/`ς`, so the ASCII
    /// pairs a mask would carry are not all of the matches. This is the
    /// check `caseless_non_ascii_is_never_exact` could not see -- `k` is
    /// below 0x80 -- and it is what made `rgx -i kelvin` miss KELVIN when
    /// the fold gained its wider members.
    #[test]
    fn caseless_wider_fold_letters_are_never_exact() {
        for word in [b"kelvin".as_slice(), b"fast", b"kelvins"] {
            assert_eq!(
                extract(word, true).kind(),
                LiteralKind::None,
                "caseless {word:?} reaches outside ASCII"
            );
            assert_eq!(
                extract(word, false).kind(),
                LiteralKind::Exact,
                "but case-sensitive is a plain literal"
            );
        }
        // ASCII letters whose fold stays in ASCII keep their prefilter.
        assert_eq!(extract(b"pub fn m", true).kind(), LiteralKind::Exact);
    }

    /// An empty print must be refused, because accepting one sets `used`
    /// while matching nothing — the one way `is_empty` could lie about a
    /// mask that can never fire. Found by adversarial review.
    #[test]
    fn an_empty_print_is_refused() {
        let mut mask = NibbleMask::new();
        assert!(!mask.add(0, b"", false));
        assert!(mask.is_empty(), "a refused add must leave the mask empty");
        // And it must not be readable back as a literal in a bucket.
        assert!(mask.bucket_of(0).is_none_or(|v| v.is_empty()));
    }

    /// The per-bucket view must be correct even when buckets are filled out
    /// of order. `fingerprints` is insertion-ordered, so a confirm loop that
    /// indexed it by bucket would confirm the wrong literal here. Found by
    /// adversarial review.
    #[test]
    fn bucket_of_survives_out_of_order_adds() {
        let mut mask = NibbleMask::new();
        assert!(mask.add(5, b"alpha", false));
        assert!(mask.add(0, b"beta", false));
        assert!(mask.add(7, b"gamma", false));
        assert_eq!(mask.bucket_of(0).unwrap(), &[b"beta".to_vec()]);
        assert_eq!(mask.bucket_of(5).unwrap(), &[b"alpha".to_vec()]);
        assert_eq!(mask.bucket_of(7).unwrap(), &[b"gamma".to_vec()]);
        // Bucket 3 was never filled.
        assert!(mask.bucket_of(3).is_none_or(|v| v.is_empty()));
        // And out of range is refused rather than panicking.
        assert!(mask.bucket_of(MAX_BUCKETS).is_none());
    }

    /// No byte of a registered print may ever be rejected. This is the
    /// property a missed match would violate, and the AND of two nibble
    /// tables can only widen it, never narrow it — so it holds for every
    /// byte and every case combination, not just the ones tested here.
    #[test]
    fn no_print_byte_is_ever_rejected() {
        for pat in [&b"ab"[..], b"aB", b"zQ", b"\x00\xff", b"  \t"] {
            let mut exact = NibbleMask::new();
            assert!(exact.add(0, pat, false));
            // Each byte at its OWN position, which is the property that
            // matters: a byte accepted at the wrong position is a false
            // positive the confirm has to clean up, while a byte rejected at
            // its own position is a missed match.
            for (j, &b) in pat.iter().enumerate() {
                assert_ne!(
                    exact.bucket_at(j, b),
                    0,
                    "{:02x?} must be accepted at position {j} of {pat:?}",
                    b
                );
            }
            let mut caseless = NibbleMask::new();
            assert!(caseless.add(0, pat, true));
            for (j, &b) in pat.iter().enumerate() {
                assert_ne!(caseless.bucket_at(j, b), 0);
                assert_ne!(
                    caseless.bucket_at(j, ascii_flip(b)),
                    0,
                    "case partner of {b:02x?} must be accepted at {j} of {pat:?}"
                );
            }
        }
    }

    /// The confirm key must fold only ASCII letters, and must never let a
    /// non-letter pattern alias a different byte. Found by adversarial
    /// review: masking bit 5 on both sides makes pattern `[0x01,0x02]`
    /// compare equal to the window `!\"`, a false positive.
    #[test]
    fn confirm_key_folds_letters_only() {
        // Caseless letters fold together. Note the fingerprint, not the
        // literal: the mask is built from the first MAX_FINGERPRINT bytes.
        let k = NibbleMask::confirm_key(b"alph", true).unwrap();
        assert_eq!(NibbleMask::confirm_key(b"ALPH", true).unwrap(), k);
        assert_eq!(NibbleMask::confirm_key(b"AlPh", true).unwrap(), k);
        // A non-letter has no case partner, so it must not alias one.
        let n = NibbleMask::confirm_key(&[0x01, 0x02], true).unwrap();
        let alias = NibbleMask::confirm_key(&[0x21, 0x22], true).unwrap();
        assert_ne!(n, alias, "0x01/0x02 must not fold onto 0x21/0x22");
        // Case-sensitive keys are untouched.
        assert_ne!(
            NibbleMask::confirm_key(b"ab", false).unwrap(),
            NibbleMask::confirm_key(b"AB", false).unwrap()
        );
        // Longer than 8 bytes is unrepresentable and must decline.
        assert!(NibbleMask::confirm_key(b"abcdefghi", false).is_none());
        assert!(NibbleMask::confirm_key(b"abcdefgh", false).is_some());
    }

    /// `max_len` is a request, not a licence: an over-large value must be
    /// clamped so the fingerprint stays within the bound the scan's cost
    /// model assumes. Found by adversarial review: `max_len = 99` produced
    /// an 8-byte print, contradicting the constant's documentation.
    #[test]
    fn max_len_is_clamped_to_the_maximum() {
        let set = extract(b"function", false);
        let mask = build_mask(&set, 99).expect("should build");
        assert_eq!(mask.fingerprints()[0].len(), MAX_FINGERPRINT);
        // A max_len below the floor cannot yield a usable mask, and says so
        // rather than building a degenerate one.
        assert!(build_mask(&set, 0).is_none());
        assert!(build_mask(&set, 1).is_none());
    }

    /// A multi-literal mask must keep bucket index and literal together.
    /// Every mask test before this one was single-literal, so the property
    /// `build_mask` actually depends on was untested. Found by adversarial
    /// review.
    #[test]
    fn a_multi_literal_mask_keeps_buckets_distinct() {
        let set = LiteralSet::exact(vec![
            Literal::new(b"alpha"),
            Literal::new(b"bravo"),
            Literal::new(b"delta"),
        ]);
        let mask = build_mask(&set, MAX_FINGERPRINT).expect("should build");
        // What lands in a bucket is the *fingerprint* — the first
        // MAX_FINGERPRINT bytes — not the whole literal. That is the whole
        // point of the cap, and a confirm loop must compare against the
        // fingerprint, not against the needle.
        assert_eq!(mask.bucket_of(0).unwrap(), &[b"alph".to_vec()]);
        assert_eq!(mask.bucket_of(1).unwrap(), &[b"brav".to_vec()]);
        assert_eq!(mask.bucket_of(2).unwrap(), &[b"delt".to_vec()]);
        // 'a' is alpha's byte at position 0, so it flags bucket 0 and no
        // other: the three prints start with three different bytes, which is
        // exactly what a per-position table can express and a single ORed
        // pair could not.
        let a0 = mask.bucket_at(0, b'a');
        assert_ne!(a0 & 0b001, 0, "alpha[0] is 'a'");
        assert_eq!(a0 & 0b010, 0, "bravo[0] is 'b'");
        assert_eq!(a0 & 0b100, 0, "delta[0] is 'd'");
        assert_ne!(mask.bucket_at(0, b'b') & 0b010, 0);
        assert_ne!(mask.bucket_at(0, b'd') & 0b100, 0);
        // And at position 1 the buckets are separated by a different byte
        // again, which is where the AND earns its selectivity.
        assert_eq!(mask.bucket_at(1, b'a') & 0b001, 0, "alpha[1] is 'l'");
        assert_ne!(mask.bucket_at(1, b'l') & 0b001, 0);
        assert_ne!(mask.bucket_at(1, b'r') & 0b010, 0);
    }

    /// Exactly `MAX_BUCKETS` literals must build; one more must not. The
    /// boundary was asserted only on the failing side.
    #[test]
    fn the_bucket_boundary_is_exactly_max_buckets() {
        let make = |n: usize| {
            LiteralSet::exact(
                (0..n)
                    .map(|i| Literal::new(&[b'a' + (i as u8), b'0' + (i as u8 % 10)]))
                    .collect(),
            )
        };
        assert!(build_mask(&make(MAX_BUCKETS), 3).is_some());
        assert!(build_mask(&make(MAX_BUCKETS + 1), 3).is_none());
    }

    /// **A bucket narrower than the mask must still fire.** The scan ANDs one
    /// table lookup per position, so a bucket whose print is two bytes in a
    /// three-position mask has no entry at the third, its AND evaluates to
    /// zero, and the literal is reported nowhere for any haystack at all --
    /// silently, and for every input. `build_mask` produced exactly that mask
    /// for the alternation `{pub, fn}`, so `fn` could never fire and a
    /// prefilter built from it was a false negative wearing a costume.
    ///
    /// Checked through the whole chain -- mask, scan, confirm -- because
    /// "the bucket has bits set" is not the property; "an occurrence of the
    /// short literal is found" is.
    #[test]
    fn a_bucket_narrower_than_the_mask_still_fires() {
        let set = LiteralSet::inexact(vec![Literal::new(b"pub"), Literal::new(b"fn")]);
        let mask = build_mask(&set, MAX_FINGERPRINT).expect("should build");
        assert_eq!(
            mask.positions(),
            3,
            "the window is as wide as the widest print"
        );
        let pf = crate::prefilter::Prefilter::new(&mask).expect("a prefilter");
        // The long one.
        assert!(
            pf.find(b"a pub here", 0).is_some(),
            "the wide literal was lost"
        );
        // The short one, at an offset where the third byte is anything at all
        // -- including a byte no print mentions, which is the case the old
        // per-position AND dropped.
        for tail in [&b"z"[..], &[0xFFu8][..], &[0x00u8][..]] {
            let hay = [b"x fn".as_slice(), tail].concat();
            assert!(pf.find(&hay, 0).is_some(), "the narrow literal was lost");
        }
        // And both are refused where neither occurs, so the padding is not
        // simply widening the mask until it accepts everything.
        assert!(pf.find(b"nothing here", 0).is_none());
    }

    /// **A narrower bucket must still fire when the haystack ENDS on it.**
    ///
    /// This is the case [`a_bucket_narrower_than_the_mask_still_fires`] does
    /// not cover, and covering it is the whole reason this test exists. That one
    /// checks `b"x fn"` plus a tail byte, so the narrow literal always has
    /// three readable bytes behind it -- exactly the window width. Nothing in it
    /// ever puts the short literal at the end of the haystack, which is the one
    /// place the window does not fit.
    ///
    /// And it did not fit. `build_mask` gives every bucket ONE window, the
    /// widest print, and the scan read that whole window before evaluating
    /// anything, so a 2-byte `fn` in a 3-byte window needed three readable bytes
    /// to be considered at all and was never considered on `fn`. The failure is
    /// silent and total: `rgx '(pub|fn)'` reported nothing for the file
    /// containing `fn`, while `rg` reported the match. Nothing panicked, no
    /// count was off by one -- the candidate was simply never produced.
    ///
    /// The fix folds the unreadable tail of the window forward, keeping the
    /// buckets that had no opinion about those positions and dropping the ones
    /// with a real byte there. Both halves matter and are asserted below: a
    /// bucket that has to survive the fold does, and one that must not does not.
    #[test]
    fn a_narrower_bucket_still_fires_at_the_end_of_the_haystack() {
        let set = LiteralSet::inexact(vec![Literal::new(b"pub"), Literal::new(b"fn")]);
        let mask = build_mask(&set, MAX_FINGERPRINT).expect("should build");
        assert_eq!(mask.positions(), 3, "the window is the widest print");
        let pf = crate::prefilter::Prefilter::new(&mask).expect("a prefilter");

        // The narrow literal, alone, with nothing behind it. This is what was
        // dropped. `fn` is at offset 0 and the haystack is 2 bytes.
        assert!(
            pf.find(b"fn", 0).is_some(),
            "the narrow literal was lost at the end of the haystack"
        );
        // At an offset, so it is not only about offset 0.
        assert!(
            pf.find(b"xfn", 0).is_some(),
            "the narrow literal was lost at an offset with nothing behind it"
        );
        // And the wide one still works at both shapes.
        assert!(pf.find(b"pub", 0).is_some(), "the wide literal was lost");

        // The fold must not rescue a bucket that has a REAL byte past the end.
        // `fn` here would need a third byte it does not have; `cd` needs an `e`.
        for hay in [&b"c"[..], &b"cd"[..], &b"f"[..], &b"pu"[..]] {
            assert!(
                pf.find(hay, 0).is_none(),
                "a partial literal must not be reported: {:?}",
                core::str::from_utf8(hay)
            );
        }
    }

    /// The padding has to be a *bounded* don't-care. `add_padded` is the only
    /// place that knows a position is unconstrained, and a width that does not
    /// cover its own print -- or one past the width a scan can be built for --
    /// has to be refused rather than silently truncated.
    #[test]
    fn add_padded_refuses_a_width_it_cannot_honour() {
        let mut mask = NibbleMask::new();
        assert!(
            !mask.add_padded(0, b"abc", false, 2),
            "narrower than the print"
        );
        assert!(!mask.add_padded(0, b"abc", false, MAX_FINGERPRINT + 1));
        assert!(mask.is_empty(), "a refused add must register nothing");
        assert!(mask.add_padded(0, b"abc", false, 3));
        assert_eq!(mask.positions(), 3);
    }

    /// The recorded candidate rates on the real corpus this was designed
    /// against. These are the numbers the design decisions rest on, and
    /// they are recorded as a test so a change to extraction that makes
    /// the mask useless fails here rather than in a benchmark nobody
    /// reads.
    ///
    /// Corpus: 112 files / 2.06 MiB of rgx's own `.md` and `.rs`.
    ///   plain literal    "function"        9.7 candidates/MiB
    ///   caseless literal "error"          132.4 candidates/MiB
    ///   caseless x5      parse..encode    954.9 candidates/MiB
    /// A 3-byte mask scan of that corpus costs ~0.023 ms, so the
    /// verification budget is thousands of candidates per MiB. The
    /// caseless alternation sits at 955, which is inside the budget by
    /// roughly an order of magnitude — this is the case that justifies
    /// the module, and the reason caseless must not expand.
    #[test]
    fn recorded_candidate_rates_justify_the_design() {
        // The plain case is far below budget, so `memmem` would do.
        // The extractor is allowed to return it; the *caller* is what
        // chooses between memmem and a mask, and that choice is not
        // made here.
        let plain = extract(b"function", false);
        assert_eq!(plain.kind(), LiteralKind::Exact);

        // The caseless alternation is the expensive one, and it stays
        // one literal per needle rather than 2^k. Five needles at k=6
        // would be 320 literals and 320 buckets, which no mask can hold.
        let alts: Vec<Literal> = ["parse", "compile", "search", "extract", "encode"]
            .iter()
            .map(|s| Literal::caseless(s.as_bytes()))
            .collect();
        assert_eq!(alts.len(), 5, "five literals, not 5 * 2^5");
        for a in &alts {
            assert!(a.is_caseless());
        }
    }
}
