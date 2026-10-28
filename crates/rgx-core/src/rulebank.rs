// SPDX-License-Identifier: Apache-2.0

//! The multi-rule nibble-cover bank: one evaluated plane per distinct byte
//! class, every rule's AND-accumulator fed from the same registers.
//!
//! A [`RuleBank`] is a prefilter over MANY rules at once — the
//! "RuleBankMask" of the post-SOTA roadmap. Each rule compiles twice:
//! once to the necessary byte classes of its matches
//! ([`required::match_mask`] — the same plan the single-pattern
//! `scan::MatchMask` consumes) and once to the [`ByteRegex`] that confirms
//! candidates. Each required class becomes a **plane**, the
//! `(lo_lut, hi_lut)` nibble-grid pair in `scan::ByteClass::tables`' scheme,
//! and identical planes are deduplicated across the whole bank, so one
//! evaluated plane feeds every rule that references it.
//!
//! # The contract: zero false negatives
//!
//! [`RuleBank::candidates`] may over-report — a candidate offset is
//! confirmed by the rule's own matcher, exactly as a single-pattern
//! prefilter's is — but it must never under-report: **every offset where
//! any rule's matcher finds a match is a candidate of that rule.**
//! [`RuleBank::search`] is that composition and reports exactly what each
//! rule's matcher reports over the same haystack run independently. The
//! paper proves FNR = 0 for the single-pattern mask (Theorem 4.1); the
//! bank inherits it because every stage is a superset: the nibble plane
//! accepts exactly the class (never fewer bytes), a branch's conditions
//! are each REQUIRED of every match that branch covers, the per-rule mask
//! is an OR over branches, and the confirm is the rule's own matcher.
//!
//! # The three stages
//!
//! 1. **Cross-rule plane dedup.** [`Plane::from_class`] compiles a class to
//!    its `(lo_lut, hi_lut)` pair; [`RuleBank::build`] interns identical
//!    pairs once for the whole bank. A rule never evaluates a plane another
//!    rule already paid for.
//! 2. **Single-pass register bank.** [`RuleBank::candidates`] walks the
//!    haystack in 64-byte blocks of candidate starts. Per block, every
//!    unique plane is evaluated ONCE into one bitmask of byte positions;
//!    per rule, the branch conditions AND the shifted bitmasks together
//!    (condition at offset `k` reads the plane's mask shifted by `k`), and
//!    a block whose union of all rules' candidate masks is zero is
//!    early-outed before anything is emitted or confirmed.
//! 3. **Union upstream screen.** [`RuleBank::screen`] answers, from a
//!    file's stored [`NgramSig512`], which rules must be searched at all —
//!    the per-rule form of `ngram`'s filter. A rule whose
//!    `query_sig512` is `None` always survives and an all-zero file
//!    signature admits every rule, so the screen may over-report but never
//!    loses a rule that can match.
//!
//! # Calling it from a CLI
//!
//! Build the bank once per rule set (per process, shared across the walk),
//! then per file: `screen(&file_sig)` gives the surviving rule indices;
//! `search_subset(file_bytes, &survivors)` gives the confirmed hits. A
//! caller that wants its own confirm loop takes `candidates` plus
//! `matcher(rule)`. Hits are `(rule, start, end)` byte spans, leftmost-first
//! and non-overlapping per rule — the same enumeration the rule's matcher
//! produces alone.
//!
//! `match_mask` declines some shapes (an assertion anywhere, a pattern that
//! can match the empty string, a body that will not lower). Such a rule
//! compiles with no conditions and EVERY offset of a haystack is its
//! candidate — the bank cannot filter what the analysis cannot place, and
//! refusing the rule instead would be a false negative with a different
//! name.

use alloc::vec;
use alloc::vec::Vec;

use super::matcher::Matcher;
use super::ngram::{self, NgramSig512};
use super::regex::ByteRegex;
use super::required;
use super::scan::ByteClass;
use super::syntax;
use crate::Result;

/// Candidate starts per block. 64 bits is one `u64` of candidate mask, so
/// the shifted AND-accumulators are word operations and the plane masks
/// need no per-block heap traffic beyond the reused register bank.
const BLOCK: usize = 64;

/// One shared nibble-cover plane: the `(lo_lut, hi_lut)` pair that every
/// rule condition over the same byte class compiles to.
///
/// The scheme is `scan::ByteClass::tables`' — each distinct non-empty
/// low-nibble mask across the 16 high nibbles gets one bit; `hi_lut[h]`
/// names the bit of high nibble `h`'s row, and `lo_lut[l]` the bits of the
/// rows containing low nibble `l` — widened from its 8 mask bits to 16 so
/// **no class is refused**: its 8-bit form returns `None` for a class with
/// more than eight distinct rows and a bank that dropped one rule's
/// condition there would keep FNR = 0 only by accident of what it dropped.
///
/// The pair is exact, not a cover: `passes(b)` is true iff `b` is a member
/// of the class. Two rules therefore share a plane exactly when they
/// require the same byte class, and one plane's evaluation feeds both.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Plane {
    lo_lut: [u16; 16],
    hi_lut: [u16; 16],
}

impl Plane {
    /// The plane of `class`, exact for every class.
    #[must_use]
    pub fn from_class(class: &ByteClass) -> Self {
        // Row `h` = the low nibbles the class holds at high nibble `h`.
        let mut rows = [0u16; 16];
        for b in 0..=u8::MAX {
            if class.contains(b) {
                rows[usize::from(b >> 4)] |= 1u16 << (b & 0x0F);
            }
        }
        // Up to 16 distinct rows exist and u16 holds 16 mask bits, so the
        // assignment is total and no class falls out of the scheme.
        let mut lo_lut = [0u16; 16];
        let mut hi_lut = [0u16; 16];
        let mut distinct = [0u16; 16];
        let mut num = 0usize;
        for (h, &row) in rows.iter().enumerate() {
            if row == 0 {
                continue;
            }
            let bit = match distinct[..num].iter().position(|&d| d == row) {
                Some(i) => 1u16 << i,
                None => {
                    distinct[num] = row;
                    num += 1;
                    1u16 << (num - 1)
                }
            };
            hi_lut[h] = bit;
            for (l, slot) in lo_lut.iter_mut().enumerate() {
                if row & (1u16 << l) != 0 {
                    *slot |= bit;
                }
            }
        }
        Self { lo_lut, hi_lut }
    }

    /// Whether `b` is a member of the class this plane was built from.
    #[inline]
    #[must_use]
    pub fn passes(&self, b: u8) -> bool {
        (self.hi_lut[usize::from(b >> 4)] & self.lo_lut[usize::from(b & 0x0F)]) != 0
    }

    /// The low-nibble LUT: `lo_lut[l]` names the row-mask bits containing
    /// low nibble `l`. Exposed so a caller can hash or compare planes.
    #[must_use]
    pub fn lo_lut(&self) -> &[u16; 16] {
        &self.lo_lut
    }

    /// The high-nibble LUT: `hi_lut[h]` names high nibble `h`'s row bit.
    #[must_use]
    pub fn hi_lut(&self) -> &[u16; 16] {
        &self.hi_lut
    }
}

/// One rule to compile: a byte-mode pattern and its case-fold flag.
#[derive(Clone, Copy, Debug)]
pub struct RuleSpec<'a> {
    /// The pattern, as rgx's byte-mode regex reads it.
    pub pattern: &'a str,
    /// Builder-level ASCII case folding (rgx's `-i`).
    pub case_insensitive: bool,
}

/// One confirmed match: which rule, and the byte span it covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleHit {
    /// Index into the `RuleSpec` slice the bank was built from.
    pub rule: usize,
    /// Byte offset of the match start.
    pub start: usize,
    /// Byte offset one past the match end.
    pub end: usize,
}

/// One compiled rule: its plane conditions, and the matcher that confirms.
struct RulePlan {
    /// One conjunction per branch: a match start satisfies EVERY `(plane,
    /// offset)` of SOME branch. The steps are `required::match_mask`'s,
    /// which reports only what every match of that branch must hold, so a
    /// candidate missing from all branches can start no match at all.
    branches: Vec<Vec<(usize, usize)>>,
    /// No conditions exist — `match_mask` declined the shape — so every
    /// offset `0..=hay.len()` is a candidate and only the matcher filters.
    unconditional: bool,
    matcher: ByteRegex,
}

/// A rule set compiled to shared nibble planes and per-rule accumulators.
///
/// See the module docs for the contract and the CLI flow. Build once per
/// rule set; every method takes `&self` and the bank is `Send + Sync` by
/// construction, so one bank serves every thread of a walk.
pub struct RuleBank {
    planes: Vec<Plane>,
    rules: Vec<RulePlan>,
    /// The `ngram` upstream screen per rule, `None` = stand down (always
    /// survives). Mirrors `ngram::query_sig512`'s law: `None` means "do
    /// not filter", never "nothing matches".
    queries: Vec<Option<NgramSig512>>,
    /// Every condition instance across every rule and branch — what the
    /// bank would evaluate per block without cross-rule dedup.
    total_conditions: usize,
    /// The furthest any condition reads past a candidate start.
    max_shift: usize,
}

impl RuleBank {
    /// Compile `rules`, deduplicating identical planes across the bank.
    ///
    /// Fails only when a pattern will not compile, naming the rule; a rule
    /// the mask analysis declines is NOT an error and compiles as
    /// unconditional.
    pub fn build(rules: &[RuleSpec<'_>]) -> Result<Self> {
        let mut planes: Vec<Plane> = Vec::new();
        let mut plans: Vec<RulePlan> = Vec::with_capacity(rules.len());
        let mut queries: Vec<Option<NgramSig512>> = Vec::with_capacity(rules.len());
        let mut total_conditions = 0usize;
        let mut max_shift = 0usize;
        for (idx, spec) in rules.iter().enumerate() {
            // The matcher parses with exactly these flags
            // (`ByteRegex::new_multiline`), so the AST lowered here and the
            // program that confirms candidates read the same classes.
            let matcher = ByteRegex::new_flags(spec.pattern.as_bytes(), spec.case_insensitive)
                .map_err(|e| crate::anyhow!("rule {idx} ({}): {e}", spec.pattern))?;
            let parsed = syntax::parse_with(
                spec.pattern.as_bytes(),
                syntax::Flags {
                    case_insensitive: spec.case_insensitive,
                    ..syntax::Flags::default()
                },
            )
            .map_err(|e| crate::anyhow!("rule {idx} ({}): {e}", spec.pattern))?;
            let mut branches: Vec<Vec<(usize, usize)>> = Vec::new();
            let mut unconditional = true;
            if let Some(plan) = required::match_mask(&parsed.ast) {
                unconditional = false;
                for branch in &plan.branches {
                    let mut conds = Vec::with_capacity(branch.len());
                    for step in branch {
                        // An empty class can be satisfied by no byte, so it
                        // constrains a match that cannot exist; dropping the
                        // step keeps the filter a superset whatever the
                        // analysis meant.
                        if step.class.is_empty() {
                            continue;
                        }
                        let plane = Plane::from_class(&step.class);
                        let pi = match planes.iter().position(|&p| p == plane) {
                            Some(i) => i,
                            None => {
                                planes.push(plane);
                                planes.len() - 1
                            }
                        };
                        conds.push((pi, step.at));
                        total_conditions += 1;
                        max_shift = if step.at > max_shift {
                            step.at
                        } else {
                            max_shift
                        };
                    }
                    branches.push(conds);
                }
            }
            plans.push(RulePlan {
                branches,
                unconditional,
                matcher,
            });
            queries.push(ngram::query_sig512(spec.pattern, spec.case_insensitive));
        }
        Ok(Self {
            planes,
            rules: plans,
            queries,
            total_conditions,
            max_shift,
        })
    }

    /// How many rules the bank holds.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// How many DISTINCT nibble planes the bank evaluates per block —
    /// after cross-rule dedup.
    #[must_use]
    pub fn unique_planes(&self) -> usize {
        self.planes.len()
    }

    /// How many `(plane, offset)` conditions exist in total — what the
    /// bank would evaluate without dedup. `unique_planes` is at most this.
    #[must_use]
    pub fn total_conditions(&self) -> usize {
        self.total_conditions
    }

    /// The per-rule upstream screen: the rule indices that must be
    /// searched in a file with stored signature `file_sig`, ascending.
    ///
    /// May over-report (a Bloom filter has false positives and a rule with
    /// no required literal always survives) and must never lose a rule that
    /// can match: `NgramSig512::contains_query` is only ever asked to
    /// REJECT, and it rejects only on a missing bit. An all-zero file
    /// signature stands down and admits every rule.
    #[must_use]
    pub fn screen(&self, file_sig: &NgramSig512) -> Vec<usize> {
        (0..self.rules.len())
            .filter(|&i| match &self.queries[i] {
                Some(q) => file_sig.contains_query(q),
                None => true,
            })
            .collect()
    }

    /// Raw candidates for every rule, as `(rule, match-start offset)`.
    ///
    /// A superset of the true match starts of each rule's matcher and a
    /// subset of nothing: false positives are confirmed by the matcher,
    /// and a candidate the scan dropped would be a missed match. Ordered
    /// by rule index, then ascending offset. For a rule the analysis
    /// declined (`unconditional`) every offset `0..=hay.len()` appears,
    /// including the empty-match start at the end.
    #[must_use]
    pub fn candidates(&self, hay: &[u8]) -> Vec<(usize, usize)> {
        let all: Vec<usize> = (0..self.rules.len()).collect();
        self.candidates_subset(hay, &all)
    }

    /// [`Self::candidates`] restricted to `rules` (as
    /// [`Self::screen`] returns them: ascending, unique).
    #[must_use]
    pub fn candidates_subset(&self, hay: &[u8], rules: &[usize]) -> Vec<(usize, usize)> {
        let groups = self.scan(hay, rules);
        let mut out = Vec::new();
        for (ri, &rule_idx) in rules.iter().enumerate() {
            for &off in &groups[ri] {
                out.push((rule_idx, off));
            }
        }
        out
    }

    /// Confirmed hits for every rule: exactly what each rule's matcher
    /// reports over `hay` run independently — leftmost-first,
    /// non-overlapping, per rule in bank order.
    #[must_use]
    pub fn search(&self, hay: &[u8]) -> Vec<RuleHit> {
        let all: Vec<usize> = (0..self.rules.len()).collect();
        self.search_subset(hay, &all)
    }

    /// [`Self::search`] restricted to `rules` (as [`Self::screen`] returns
    /// them: ascending, unique).
    #[must_use]
    pub fn search_subset(&self, hay: &[u8], rules: &[usize]) -> Vec<RuleHit> {
        let groups = self.scan(hay, rules);
        let mut out = Vec::new();
        for (ri, &rule_idx) in rules.iter().enumerate() {
            confirm_rule(&self.rules[rule_idx], rule_idx, hay, &groups[ri], &mut out);
        }
        out
    }

    /// The rule's own matcher, so a caller holding raw candidates can
    /// confirm them itself.
    ///
    /// # Panics
    ///
    /// Panics when `rule` is not a rule index of this bank.
    #[must_use]
    pub fn matcher(&self, rule: usize) -> &ByteRegex {
        &self.rules[rule].matcher
    }

    /// The single-pass register bank: per rule, the candidate offsets, in
    /// `rules` slice order and ascending per rule.
    ///
    /// One pass over the haystack in [`BLOCK`]-sized blocks of candidate
    /// starts. Per block: each unique plane is evaluated ONCE over the
    /// block's read window (the block plus the bank's widest condition
    /// shift — the bytes any condition of a start in this block can read),
    /// producing one bitmask; each rule AND-accumulates its branch
    /// conditions over the shifted masks; a block whose union of rule masks
    /// is zero emits nothing and, in [`Self::search_subset`], confirms
    /// nothing.
    fn scan(&self, hay: &[u8], rules: &[usize]) -> Vec<Vec<usize>> {
        let n = hay.len();
        let mut per_rule: Vec<Vec<usize>> = Vec::with_capacity(rules.len());
        for &ri in rules {
            let mut offs = Vec::new();
            if self.rules[ri].unconditional {
                // A pattern that can match the empty string matches at
                // `n` too; `0..=n` is the honest candidate set.
                offs.extend(0..=n);
            }
            per_rule.push(offs);
        }
        if self.planes.is_empty() || n == 0 {
            return per_rule;
        }
        // The window is `BLOCK` starts plus the widest reach; reads past it
        // (and past the haystack) read as zero bits, so a condition that
        // reaches past the end of the haystack fails rather than aliasing
        // an unrelated byte.
        let wwords = (BLOCK + self.max_shift).div_ceil(64);
        let mut regs = vec![0u64; self.planes.len() * wwords];
        let mut masks = vec![0u64; rules.len()];
        for base in (0..n).step_by(BLOCK) {
            let block_len = core::cmp::min(BLOCK, n - base);
            let win_end = core::cmp::min(n, base + BLOCK + self.max_shift);
            for (p, plane) in self.planes.iter().enumerate() {
                let bits = &mut regs[p * wwords..(p + 1) * wwords];
                bits.fill(0);
                for (i, &b) in hay[base..win_end].iter().enumerate() {
                    if plane.passes(b) {
                        bits[i >> 6] |= 1u64 << (i & 63);
                    }
                }
            }
            // Only starts inside the haystack are candidates.
            let valid = if block_len == BLOCK {
                u64::MAX
            } else {
                (1u64 << block_len) - 1
            };
            let mut union = 0u64;
            for (ri, &rule_idx) in rules.iter().enumerate() {
                let plan = &self.rules[rule_idx];
                if plan.unconditional {
                    masks[ri] = 0;
                    continue;
                }
                let mut rm = 0u64;
                for branch in &plan.branches {
                    // The rule's shifted AND-accumulator: one shift per
                    // condition, all of them over the SAME evaluated plane
                    // registers.
                    let mut bm = u64::MAX;
                    for &(p, shift) in branch {
                        bm &= shifted(&regs[p * wwords..(p + 1) * wwords], shift);
                        if bm == 0 {
                            break;
                        }
                    }
                    // Some branch, not every branch: a match start has to
                    // satisfy one way to start, and the OR is the union.
                    rm |= bm;
                }
                masks[ri] = rm & valid;
                union |= masks[ri];
            }
            if union == 0 {
                continue;
            }
            for (ri, &rule_idx) in rules.iter().enumerate() {
                let _ = rule_idx;
                let mut m = masks[ri];
                while m != 0 {
                    let bit = m.trailing_zeros() as usize;
                    per_rule[ri].push(base + bit);
                    m &= m - 1;
                }
            }
        }
        per_rule
    }
}

/// The low 64 bits of `words` shifted right by `shift`, zero-filled at the
/// high end: bit `i` of the result is bit `i + shift` of `words`.
///
/// A position past `words` reads as zero, which is what turns "the
/// condition reaches past the end of the window" into "no candidate here"
/// instead of an aliased bit.
fn shifted(words: &[u64], shift: usize) -> u64 {
    let j = shift / 64;
    let r = shift % 64;
    let lo = words.get(j).copied().unwrap_or(0) >> r;
    if r == 0 {
        lo
    } else {
        lo | (words.get(j + 1).copied().unwrap_or(0) << (64 - r))
    }
}

/// Confirm one rule's candidates into hits.
///
/// The enumeration is the matcher's own leftmost-first walk — the first
/// candidate at or after `at` that begins a match IS the matcher's next
/// match, because every match start is a candidate (the FNR = 0 law of
/// [`RuleBank::candidates`) and a candidate that fails the anchored confirm
/// begins no match. Extents come from `find_span_at`, so a tie inside one
/// start position resolves exactly as the matcher would alone.
fn confirm_rule(
    plan: &RulePlan,
    rule_idx: usize,
    hay: &[u8],
    cands: &[usize],
    out: &mut Vec<RuleHit>,
) {
    let n = hay.len();
    let m = &plan.matcher;
    let mut at = 0usize;
    let mut i = 0usize;
    while at <= n {
        while i < cands.len() && cands[i] < at {
            i += 1;
        }
        let Some(&c) = cands.get(i) else {
            break;
        };
        i += 1;
        // `find_span_at(c)` is the leftmost match at or after `c`; it
        // begins at `c` iff one does. The two halves are one question, and
        // asking it once is what `Matcher::is_match_at` would answer with
        // the same search.
        if let Some(span) = m.find_span_at(hay, c) {
            if span.start == c {
                out.push(RuleHit {
                    rule: rule_idx,
                    start: span.start,
                    end: span.end,
                });
                at = if span.end > span.start {
                    span.end
                } else {
                    c + 1
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! What the bank is judged by: zero false negatives against each
    //! rule's own matcher over a matrix of haystacks, a dedup margin on a
    //! real rule set, a screen that never loses a rule that can match, and
    //! a no-candidate haystack that reports nothing without panicking.

    use super::*;

    /// The oracle: the rule's matcher over the whole haystack with no bank
    /// in the way — leftmost-first, non-overlapping. `RuleBank::search`
    /// must reproduce it byte for byte.
    fn independent(re: &ByteRegex, hay: &[u8]) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while at <= hay.len() {
            match re.find_span_at(hay, at) {
                Some(sp) => {
                    out.push((sp.start, sp.end));
                    at = if sp.end > sp.start {
                        sp.end
                    } else {
                        sp.start + 1
                    };
                }
                None => break,
            }
        }
        out
    }

    /// Deterministic pseudo-random bytes (a mulberry-style LCG): dense
    /// accidental candidates without a `rand` dependency.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                s = s
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (s >> 33) as u8
            })
            .collect()
    }

    /// The haystack matrix: dense literals, alternations, char classes,
    /// hex/credential shapes, block-boundary straddles, and the sizes where
    /// the 64-bit block machinery can go wrong.
    fn haystacks() -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"no matches here at all, just prose about kittens.".to_vec(),
            b"AKIAABCDEFGHIJKLMNOP and AKIA0123456789ABCDEF tail".to_vec(),
            b"AKIAonlyseven01234".to_vec(),
            b"secret_id=abc secret_token=def secret_=nope".to_vec(),
            b"-----BEGIN RSA PRIVATE KEY-----\nbody\n-----END RSA PRIVATE KEY-----".to_vec(),
            b"deadbeefcafebabe0123456789abcdef then ZZZZZZZZZZZZZZZZZZZZ".to_vec(),
            b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U".to_vec(),
            b"mail foo.bar@example.com and x@y.zz plus a@b.co.uk".to_vec(),
            b"password=guess PASSWORD=UPPER Password=Mixed PwD=x".to_vec(),
            b"x*xxx x xxxx".to_vec(),
            b"abcd then b alone: abcd b".to_vec(),
            b"foobarbar and foobar and barbar".to_vec(),
        ];
        // A credential straddling each 64-byte seam: the block scanner
        // must see a match start whose conditions read into the next block.
        for pad in [0usize, 1, 2, 60, 61, 62, 63, 64, 65, 126, 127, 128, 129] {
            let mut h = vec![b'.'; pad];
            h.extend_from_slice(b"AKIAZZZZZZZZZZZZZZZZ");
            h.extend_from_slice(b"secret_id=tail");
            v.push(h);
        }
        // Dense literal carpet: candidates everywhere, few matches.
        v.push(b"AKIA".repeat(50));
        let mut hex = Vec::new();
        hex.extend_from_slice(b"0123456789abcdef".repeat(20).as_slice());
        v.push(hex);
        v.push(noise(257, 1));
        v.push(noise(64, 2));
        v.push(noise(65, 3));
        v
    }

    /// **The whole game: zero false negatives.** Every hit of every rule's
    /// own matcher is a bank hit at the same span, and every true match
    /// start is a bank candidate — over a rule bank with alternations,
    /// classes, folds, an assertion the analysis declines, and a pattern
    /// that matches the empty string, times a haystack matrix that crosses
    /// every block seam.
    #[test]
    fn every_match_of_every_rule_survives_the_bank_as_a_hit_and_a_candidate() {
        let specs: &[RuleSpec<'_>] = &[
            RuleSpec {
                pattern: "AKIA[0-9A-Z]{16}",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "secret_(id|token)=",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "[0-9a-fA-F]{32,}",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "-----BEGIN [A-Z ]+-----",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "eyJ[A-Za-z0-9_-]+\\.",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "(?i)password=",
                case_insensitive: false,
            },
            // An assertion anywhere declines the mask analysis: this rule
            // is unconditional and must survive on its own merits.
            RuleSpec {
                pattern: "\\bAKIA[0-9A-Z]{16}",
                case_insensitive: false,
            },
            // Matches the empty string: every offset, end of haystack
            // included, is a candidate and the enumeration must agree.
            RuleSpec {
                pattern: "x*",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "[a-z.]+@[a-z.]+\\.[a-z]{2,}",
                case_insensitive: false,
            },
            // Branches of different widths and a match that overlaps a
            // later candidate: leftmost-first skipping is under test.
            RuleSpec {
                pattern: "abcd|b",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "(foo|foobar)bar",
                case_insensitive: false,
            },
        ];
        let bank = RuleBank::build(specs).expect("the test rules compile");
        assert_eq!(bank.rule_count(), specs.len());
        let mut checked = 0usize;
        for hay in haystacks() {
            let hits = bank.search(&hay);
            let cands = bank.candidates(&hay);
            for (ri, spec) in specs.iter().enumerate() {
                let re = ByteRegex::new_flags(spec.pattern.as_bytes(), spec.case_insensitive)
                    .expect("the test rules compile");
                let want = independent(&re, &hay);
                let got: Vec<(usize, usize)> = hits
                    .iter()
                    .filter(|h| h.rule == ri)
                    .map(|h| (h.start, h.end))
                    .collect();
                assert_eq!(
                    got, want,
                    "rule {ri} ({}) diverges from its own matcher on {hay:?}",
                    spec.pattern
                );
                for &(s, _) in &want {
                    checked += 1;
                    assert!(
                        cands.contains(&(ri, s)),
                        "rule {ri} ({}) lost match start {s} on {hay:?}",
                        spec.pattern
                    );
                }
            }
        }
        // A matrix where nothing matches would pass vacuously; the property
        // is only held down by real matches the scan could have dropped.
        // Measured: 2916 true match starts checked on this grid.
        assert!(
            checked >= 50,
            "only {checked} true match starts checked; the grid has gone vacuous"
        );
    }

    /// The cross-rule dedup claim, on a bank of realistic
    /// secret/credential/PII rules written out in full: the unique planes
    /// must be fewer than the conditions, by a margin measured on THIS
    /// bank and asserted so the claim cannot rot into a rounding error.
    #[test]
    fn a_hundred_realistic_rules_compile_with_far_fewer_unique_planes_than_conditions() {
        const SECRET_RULES: &[&str] = &[
            // AWS and GCP-shaped keys
            "AKIA[0-9A-Z]{16}",
            "ASIA[0-9A-Z]{16}",
            "AGPA[A-Z0-9]{16}",
            "AROA[A-Z0-9]{16}",
            "AIDA[A-Z0-9]{16}",
            "ANPA[A-Z0-9]{16}",
            "AIPA[A-Z0-9]{16}",
            "A3T[A-Z0-9]{17}",
            "aws_secret_access_key[ \t]*=[ \t]*[0-9a-zA-Z/+=]{40}",
            "aws_access_key_id[ \t]*=[ \t]*[0-9A-Z]{20}",
            // GitHub / GitLab / CI tokens
            "ghp_[A-Za-z0-9]{36}",
            "gho_[A-Za-z0-9]{36}",
            "ghu_[A-Za-z0-9]{36}",
            "ghs_[A-Za-z0-9]{36}",
            "ghr_[A-Za-z0-9]{36}",
            "github_pat_[A-Za-z0-9_]{82}",
            "glpat-[A-Za-z0-9_-]{20}",
            "gloas-[A-Za-z0-9_-]{20}",
            "GRD-[A-Za-z0-9_-]{20}",
            "CI_JOB_TOKEN[ \t]*=[ \t]*[0-9a-zA-Z_-]{20,}",
            // OpenAI / Anthropic / Google / Hugging Face
            "sk-[A-Za-z0-9]{20,}",
            "sk-ant-[A-Za-z0-9-]{40,}",
            "sk-proj-[A-Za-z0-9_-]{20,}",
            "sk-legacy-[A-Za-z0-9]{48}",
            "AIza[0-9A-Za-z_-]{35}",
            "ya29\\.[0-9A-Za-z_-]{40,}",
            "hf_[A-Za-z0-9]{30,}",
            "huggingface_[A-Za-z0-9]{30,}",
            // Slack / Stripe / Twilio / SendGrid / Mailgun
            "xox[baprs]-[A-Za-z0-9-]{10,}",
            "xoxe-[0-9A-Za-z-]{40,}",
            "sk_live_[0-9a-zA-Z]{24}",
            "sk_test_[0-9a-zA-Z]{24}",
            "rk_live_[0-9a-zA-Z]{24}",
            "pk_live_[0-9a-zA-Z]{24}",
            "SK[0-9a-fA-F]{32}",
            "SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}",
            "key-[0-9a-zA-Z]{32}",
            "AC[0-9a-fA-F]{32}",
            // npm / PyPI / package registries
            "npm_[A-Za-z0-9]{36}",
            "pypi-[A-Za-z0-9_-]{40}",
            "dop_v1_[0-9a-fA-F]{64}",
            "doo_v1_[0-9a-fA-F]{64}",
            "dapi_v1_[0-9a-fA-F]{64}",
            // JWTs
            "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+",
            "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]+",
            "eyJhbGciOi[A-Za-z0-9_-]+",
            "eyJ0eXAiOi[A-Za-z0-9_-]+",
            "Bearer [A-Za-z0-9._-]{20,}",
            "Basic [A-Za-z0-9+/=]{20,}",
            // PEM markers and key formats
            "-----BEGIN [A-Z ]+-----",
            "-----END [A-Z ]+-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN PUBLIC KEY-----",
            "PuTTY-User-Key-File-2",
            "ssh-rsa AAAA[0-9A-Za-z+/]{100,}",
            "ssh-ed25519 AAAA[0-9A-Za-z+/]{60,}",
            "OPENSSH PRIVATE KEY",
            "PRIVATE KEY-----",
            // Hex, UUIDs, hashes
            "[0-9a-fA-F]{32,}",
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "[0-9a-fA-F]{64}",
            "[0-9a-fA-F]{40}",
            "[0-9a-fA-F]{128}",
            // Secret assignments
            "secret_(id|token|key)=",
            "secret_(id|token|key)[ \t]*[:=]",
            "client_secret[ \t]*=[ \t]*['\"]?[0-9a-zA-Z+/=_-]{16,}",
            "api[_-]?key[ \t]*[:=]",
            "apikey[ \t]*[:=]",
            "private_key[ \t]*[:=]",
            "access_token[ \t]*[:=]",
            "auth_token[ \t]*[:=]",
            "refresh_token[ \t]*[:=]",
            "password[ \t]*[:=]",
            "passwd[ \t]*[:=]",
            "pwd[ \t]*[:=]",
            "credentials?[ \t]*[:=]",
            "authorization:[ \t]*Bearer ",
            "x-api-key:[ \t]*[0-9a-zA-Z-]{16,}",
            "db_password[ \t]*[:=]",
            "mysql_pwd[ \t]*[:=]",
            "postgres_password[ \t]*[:=]",
            // Connection strings
            "mongodb://[0-9a-zA-Z:.@/]+",
            "postgres://[0-9a-zA-Z:.@/]+",
            "amqp://[0-9a-zA-Z:.@/]+",
            "redis://[0-9a-zA-Z:.@/]+",
            "jdbc:[a-z]+://[0-9a-zA-Z:.@/]+",
            // Base64-ish blobs
            "[A-Za-z0-9+/]{40,}={0,2}",
            "[A-Za-z0-9+/]{60,}={0,2}",
            "[A-Za-z0-9_-]{32,}",
            "[A-Za-z0-9+/=]{20,}",
            // PII
            "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
            "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
            "[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}",
            "([0-9]{4}[- ]?){3}[0-9]{4}",
            "[0-9]{3}-[0-9]{2}-[0-9]{4}",
            "\\+[0-9]{10,15}",
            "[0-9]{12,19}",
            "[0-9]{15,16}",
            "[0-9]{3}-[0-9]{3,4}-[0-9]{4}",
            // Auth headers and bearer material
            "Authorization:[ \t]*[A-Za-z]+ [A-Za-z0-9._-]{20,}",
            "X-Auth-Token:[ \t]*[0-9a-zA-Z-]{16,}",
            "Set-Cookie:[ \t]*session=[A-Za-z0-9+/=_-]{16,}",
            "webhook_[A-Za-z0-9]{30,}",
            "token [A-Za-z0-9._-]{20,}",
        ];
        assert!(
            SECRET_RULES.len() >= 100,
            "the dedup claim is only measured on a real-sized bank"
        );
        let specs: Vec<RuleSpec<'_>> = SECRET_RULES
            .iter()
            .map(|&pattern| RuleSpec {
                pattern,
                case_insensitive: false,
            })
            .collect();
        let bank = RuleBank::build(&specs).expect("the rule bank compiles");
        let total = bank.total_conditions();
        let unique = bank.unique_planes();
        // Measured on THIS bank: 73 unique planes over 2195 conditions =
        // 3.3%, and the margin is asserted at 5% — the measured number,
        // not a wish, so the claim cannot rot into a rounding error (see
        // rulebank-report.md).
        assert!(
            unique < total,
            "dedup did not dedup: {unique} unique planes over {total} conditions"
        );
        assert!(
            unique * 20 <= total,
            "expected unique planes <= 5% of conditions, got {unique}/{total}"
        );
    }

    /// The union upstream screen's three laws: a zero file signature
    /// admits every rule, a file holding one rule's literal keeps that rule
    /// and prunes only rules whose required literal is absent, and a rule
    /// whose `query_sig512` is `None` (folded literal here) survives
    /// always — `None` means "do not filter", never "nothing matches".
    #[test]
    fn the_union_screen_admits_every_rule_on_a_zero_signature_and_prunes_only_the_impossible() {
        let specs: &[RuleSpec<'_>] = &[
            RuleSpec {
                pattern: "needle",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "pub fn",
                case_insensitive: false,
            },
            // A folded literal: the stored signature is case-sensitive, so
            // `query_sig512` declines and the rule survives every file.
            RuleSpec {
                pattern: "(?i)needle",
                case_insensitive: false,
            },
        ];
        let bank = RuleBank::build(specs).expect("the test rules compile");
        // The all-zero signature is "unknown" and admits every rule.
        assert_eq!(bank.screen(&NgramSig512::default()), vec![0, 1, 2]);
        // A file holding rule 0's literal: 0 survives, 1 is pruned (its
        // `pub fn` run is absent), 2 survives by standing down.
        let sig = ngram::build_stored_sig512(b"prefix needle suffix");
        let s = bank.screen(&sig);
        assert!(s.contains(&0), "the file holds rule 0's literal");
        assert!(!s.contains(&1), "the file holds no `pub fn` run");
        assert!(s.contains(&2), "a rule with no query always survives");
        // A file holding rule 1's literal keeps 1 and prunes 0.
        let sig = ngram::build_stored_sig512(b"prefix pub fn suffix");
        let s = bank.screen(&sig);
        assert!(s.contains(&1));
        assert!(!s.contains(&0));
        // And the screen never loses what the search finds: on the file
        // above, every hit of every surviving rule is still a bank hit.
        let hay = b"prefix pub fn suffix".to_vec();
        let hits = bank.search_subset(&hay, &bank.screen(&ngram::build_stored_sig512(&hay)));
        assert!(hits.iter().any(|h| h.rule == 1));
    }

    /// The early-out path: a haystack where no block sets any rule's
    /// candidate mask still answers — zero hits, zero candidates, no
    /// panic — instead of walking confirms that cannot fire.
    #[test]
    fn a_haystack_with_no_candidates_reports_no_hits_and_never_panics() {
        let specs: &[RuleSpec<'_>] = &[
            RuleSpec {
                pattern: "AKIA[0-9A-Z]{16}",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "secret_(id|token)=",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "[0-9a-fA-F]{32,}",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "-----BEGIN [A-Z ]+-----",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "eyJ[A-Za-z0-9_-]+\\.",
                case_insensitive: false,
            },
        ];
        let bank = RuleBank::build(specs).expect("the test rules compile");
        // `!` satisfies the first required byte of no branch of any rule
        // above, so every block's union is zero.
        let hay = vec![b'!'; 300];
        assert!(bank.candidates(&hay).is_empty());
        assert!(bank.search(&hay).is_empty());
        // And the empty haystack is the degenerate block boundary.
        assert!(bank.candidates(b"").is_empty());
        assert!(bank.search(b"").is_empty());
    }

    /// The plane pair is exact for its class — the property every
    /// dedup and every accumulator rests on: a member always passes (FNR
    /// lives here) and a non-member fails (selectivity lives here).
    #[test]
    fn a_plane_accepts_exactly_the_bytes_of_its_class() {
        let mut class = ByteClass::empty();
        for b in b"AKIA0123456789" {
            class.insert(*b);
        }
        let plane = Plane::from_class(&class);
        for b in 0..=u8::MAX {
            assert_eq!(
                plane.passes(b),
                class.contains(b),
                "plane and class disagree about {b:#04x}"
            );
        }
    }
}

#[cfg(test)]
mod fuzz {
    //! The never-panic floor on arbitrary bytes, per AGENTS.md §6: the
    //! scanner, the confirm loop and the screen all run on mutated input.

    // The import is the one the only test in this module needs, and that
    // test needs `std`. A `no_std` test build would otherwise carry an
    // import nothing uses -- a warning the CI turns into an error.
    #[cfg(feature = "std")]
    use super::*;

    /// A small rule bank: one planned rule, one the analysis declines, one
    /// that matches the empty string — the three paths arbitrary bytes can
    /// reach.
    ///
    /// The gate is the one its only caller carries: the test that uses this
    /// needs `std`, and a `no_std` test build would otherwise carry a
    /// function nothing calls -- a warning the CI turns into an error.
    #[cfg(feature = "std")]
    fn fuzz_rules() -> Vec<RuleSpec<'static>> {
        vec![
            RuleSpec {
                pattern: "AKIA[0-9A-Z]{16}",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "\\bsecret_(id|token)=",
                case_insensitive: false,
            },
            RuleSpec {
                pattern: "x*",
                case_insensitive: false,
            },
        ]
    }

    #[cfg(feature = "std")]
    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: Vec<(&'static str, Vec<u8>)> = vec![
            ("akia", b"AKIAZZZZZZZZZZZZZZZZ tail".to_vec()),
            ("pem", b"-----BEGIN RSA PRIVATE KEY-----\nbody\n".to_vec()),
            ("hex", b"deadbeefcafebabe0123456789abcdef".to_vec()),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "rulebank", |data| {
            let bank = RuleBank::build(&fuzz_rules()).expect("fuzz rules compile");
            let _ = bank.candidates(data);
            let _ = bank.search(data);
            let _ = bank.screen(&ngram::build_stored_sig512(data));
        });
    }
}
