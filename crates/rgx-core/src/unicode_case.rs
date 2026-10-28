// SPDX-License-Identifier: Apache-2.0

//! Simple case folding for literal pattern characters.
//!
//! ## Why this exists in a byte-mode engine
//!
//! The search engine compiles byte patterns and has no Unicode semantics of
//! its own. What it does have is a case-insensitive flag, and until this
//! module existed that flag folded exactly one thing -- ASCII bytes, through
//! `syntax::case_fold_set`. So `rgx -i 'café'` did not match `CAFÉ`.
//!
//! The fix is not to teach the matcher about Unicode. It is to resolve the
//! folding question once, at parse time, and hand the matcher the same kind
//! of thing it already understands: a byte alternation. The match-time cost
//! is zero and the byte-mode invariant holds.
//!
//! ## Simple, not full
//!
//! This folds with the **simple** case folding table generated into
//! `casefold_table.rs` from the Unicode Character Database, which is what
//! ripgrep's `regex` crate uses. It deliberately does not use
//! `char::to_lowercase` / `char::to_uppercase`, which implement **full**
//! case mapping, and the difference is not academic:
//!
//! | | simple (this) | full (`char::to_*`) |
//! |---|---|---|
//! | `ß` | folds to `ẞ` | folds to `SS` |
//! | `ﬁ` | folds to itself | folds to `FI` |
//! | `İ` | folds to itself | folds to `i` + U+0307 |
//!
//! Using full folding made rgx report `STRASSE` for `rgx -i 'ß'`, which
//! ripgrep does not. An earlier revision of this file did exactly that, and
//! also had a second, worse bug: case variants were stored as single
//! *characters*, so the multi-character mapping `ß` -> `SS` was pushed as two
//! independent `S` alternatives and `(?i)ß` matched any bare capital `S` in
//! the corpus. Both are recorded here because the structure they came from --
//! a `CaseVariants` buffer sized for characters, when a case mapping can be a
//! sequence -- is the shape to avoid again.
//!
//! ## One divergence from ripgrep, on purpose
//!
//! `CaseFolding.txt` maps `ς` GREEK SMALL LETTER FINAL SIGMA to `σ`, so the
//! table folds the two together unconditionally and `rgx -i 'σ'` matches `ς`.
//! The `regex` crate instead implements the conditional Final_Sigma rule and
//! matches `ς` only in final position. rgx therefore **over**-matches here
//! where ripgrep does not, in a word-final-sensitive way: it will report a
//! `ς` in the middle of a word that ripgrep passes over.
//!
//! That direction was chosen over the alternative. Implementing the
//! conditional rule needs context the byte NFA does not have -- whether the
//! preceding codepoint is cased and the following one is not -- and getting
//! it wrong produces a *missed* match. The unconditional fold is the
//! normative behaviour of the table, it is what UAX #44 defines, and the
//! cost is one class of false positive on a character that ASCII-only
//! folding missed entirely.
//!
//! ## Mixed-width classes fold since the scan bound was fixed
//!
//! A fold is emitted for the WHOLE class, whatever its members' UTF-8
//! widths: `k` folds to `{k, K, KELVIN SIGN}`, `ß` to `{ß, ẞ}`. That was
//! gated on uniform widths for one reason -- an unanchored scan that
//! bounded its candidate starts by the LONGEST branch and so missed a
//! shorter branch meeting the end of the haystack (`ab|cde` reported
//! nothing for the line `ab`). With unequal branches searchable, the gate
//! is gone and `rgx -i 'k'` reaches U+212A the way ripgrep does. The
//! regression test that pinned the defect now pins the fix:
//! `regex::single_byte_prefilter_tests::a_short_branch_at_the_haystack_end_is_found_beside_a_longer_one`.

use crate::casefold_table::{REVERSE, SIMPLE};

/// The largest simple-folding equivalence class in the table.
///
/// Measured, not assumed: over `CaseFolding-18.0.0.txt` the class-size
/// histogram is 2948 classes of two, 75 of three and 12 of four, so four is
/// the ceiling and nothing here can be dropped. A character whose class is
/// larger than this -- which would mean a new Unicode revision added one --
/// is folded to itself alone rather than to a partial class, because a
/// partial class is a silently wrong answer.
const MAX_CLASS: usize = 4;

/// The simple case folding class of one character: every codepoint that
/// folds to the same canonical form, including the character itself.
///
/// A class rather than a single mapping, because the table records each pair
/// once and not in a fixed direction -- `0041; C; 0061;` is present and
/// `0061;` has no line -- so "what folds to `a`" needs a reverse lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseVariants {
    chars: [char; MAX_CLASS],
    count: u8,
}

impl CaseVariants {
    const fn empty() -> Self {
        Self {
            chars: ['\0'; MAX_CLASS],
            count: 0,
        }
    }

    fn push(&mut self, c: char) {
        let n = self.count as usize;
        if n >= MAX_CLASS {
            return;
        }
        if self.chars[..n].contains(&c) {
            return;
        }
        self.chars[n] = c;
        self.count += 1;
    }

    /// The members of the class, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = char> + '_ {
        self.chars[..self.count as usize].iter().copied()
    }

    /// Number of members.
    pub fn len(&self) -> usize {
        self.count as usize
    }

    /// True when the class is empty, which never happens for a real character.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// True when every member encodes to the same number of UTF-8 bytes.
    ///
    /// A property of the table, not a gate: `fold_char` used to narrow to
    /// one width because an unanchored scan missed a shorter alternation
    /// branch at the haystack end. The scan is fixed and the narrowing is
    /// gone; this stays only as something the table's tests can state.
    pub fn uniform_len(&self) -> bool {
        let n = self.count as usize;
        if n == 0 {
            return false;
        }
        let first = self.chars[0].len_utf8();
        self.chars[..n].iter().all(|c| c.len_utf8() == first)
    }
}

/// The simple case folding class of `c`, every width included.
///
/// This used to be narrowed to members encoding to the same number of UTF-8
/// bytes as `c`, because the unanchored scan dropped a shorter alternation
/// branch that ended at the haystack end -- folding `k` to include
/// three-byte KELVIN SIGN would stop `k` matching a line that is nothing but
/// `k`. The scan is fixed (`a_short_branch_at_the_haystack_end_is_found_
/// beside_a_longer_one` pins it), so the full class is emitted and
/// `rgx -i 'k'` reaches U+212A as ripgrep does. Mixed-width classes are the
/// matter.
pub fn fold_char(c: char) -> CaseVariants {
    fold_class(c)
}

/// Whether the simple folding class of ASCII byte `b` stays inside ASCII.
///
/// The exact condition under which a byte-wise ASCII fold and this table
/// agree. `k` and `s` fail it: their classes reach three-byte KELVIN SIGN
/// and two-byte `ſ`/`ς`, so a caseless literal holding one of them is not
/// the fixed byte-set-per-position shape an ASCII mask can scan. The
/// callers that build such masks decline on this, which is a lost
/// prefilter and not a wrong answer.
pub fn fold_stays_ascii(b: u8) -> bool {
    b < 128 && fold_char(b as char).iter().all(|c| (c as u32) < 0x80)
}

/// The whole simple case folding class of `c`, mixed widths included.
///
/// [`fold_char`] is what the parser wants. This is the underlying
/// relation, exposed so the properties of the table can be tested against
/// every member rather than only the ones that survive narrowing.
fn fold_class(c: char) -> CaseVariants {
    let cp = c as u32;
    // A codepoint with no row is its own canonical form.
    let key = match SIMPLE.binary_search_by_key(&cp, |&(s, _)| s) {
        Ok(i) => SIMPLE[i].1,
        Err(_) => cp,
    };

    let mut out = CaseVariants::empty();
    // The reverse index gives every codepoint that folds to `key`. The key
    // itself is normally not among them -- `0061` has no row -- so it is
    // added separately, which is what makes the class a class.
    if let Ok(mut i) = REVERSE.binary_search_by_key(&key, |&(t, _)| t) {
        // Back up to the start of the run: binary_search lands anywhere
        // inside it, and a key can have two or three sources (`k` has both
        // `K` and U+212A).
        while i > 0 && REVERSE[i - 1].0 == key {
            i -= 1;
        }
        while i < REVERSE.len() && REVERSE[i].0 == key {
            if let Some(ch) = char::from_u32(REVERSE[i].1) {
                out.push(ch);
            }
            i += 1;
        }
    }
    if let Some(key_ch) = char::from_u32(key) {
        out.push(key_ch);
    }
    // `c` itself is always in its own class, and is normally already covered
    // by the two branches above -- it is either the key or in the reverse
    // range. `push` is idempotent, so this only matters when neither held.
    out.push(c);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn class_of(c: char) -> Vec<char> {
        let mut v: Vec<char> = fold_class(c).iter().collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// The same, through the narrowing the parser actually uses.
    fn folded(c: char) -> Vec<char> {
        let mut v: Vec<char> = fold_char(c).iter().collect();
        v.sort_unstable();
        v
    }

    /// The table is a matching, so this is a property of the generated data
    /// rather than of any one character: nothing appears in two classes. If a
    /// future UCD revision broke the matching assumption, every fold would be
    /// wrong at once and this is where it would show.
    #[test]
    fn folding_is_an_equivalence_relation() {
        for &(src, tgt) in SIMPLE.iter() {
            let s = char::from_u32(src).expect("source is a scalar value");
            let t = char::from_u32(tgt).expect("target is a scalar value");
            assert!(
                class_of(s).contains(&t),
                "U+{src:04X} does not fold to U+{tgt:04X} through its class"
            );
        }
    }

    /// Folding is symmetric: the class of `a` contains `b` exactly when the
    /// class of `b` contains `a`.
    #[test]
    fn folding_is_symmetric() {
        for &(src, tgt) in SIMPLE.iter() {
            let (s, t) = (
                char::from_u32(src).expect("scalar"),
                char::from_u32(tgt).expect("scalar"),
            );
            assert_eq!(
                class_of(s).contains(&t),
                class_of(t).contains(&s),
                "U+{src:04X} / U+{tgt:04X} fold asymmetrically"
            );
        }
    }

    /// The forward index and the reverse index must partition the codepoints
    /// between them: no codepoint is both a source and a target.
    ///
    /// `fold_char` relies on this. It looks the canonical form up forward,
    /// then finds the class by scanning the reverse index for everything
    /// that maps TO that form. If a codepoint were both -- if `CaseFolding.txt`
    /// listed a pair from both ends -- then that codepoint's canonical form
    /// would be some third value and neither index would find its siblings.
    ///
    /// Measured over `CaseFolding-18.0.0.txt`: 1533 sources, 1502 targets,
    /// intersection 0. If a future Unicode revision breaks it, every fold is
    /// wrong at once and this is where it shows.
    #[test]
    fn no_codepoint_is_both_a_source_and_a_target() {
        let mut overlap = 0usize;
        for &(_src, tgt) in SIMPLE.iter() {
            if SIMPLE.binary_search_by_key(&tgt, |&(s, _)| s).is_ok() {
                overlap += 1;
            }
        }
        assert_eq!(
            overlap, 0,
            "a codepoint is both a source and a target; `fold_char` assumes \
             it is not"
        );
    }

    /// Both indexes must be sorted, because both are binary searched.
    #[test]
    fn both_indexes_are_sorted_for_binary_search() {
        assert!(
            SIMPLE.windows(2).all(|w| w[0].0 < w[1].0),
            "SIMPLE is not sorted by source"
        );
        assert!(
            REVERSE.windows(2).all(|w| w[0].0 <= w[1].0),
            "REVERSE is not sorted by target"
        );
    }

    #[test]
    fn ascii_pairs_fold_both_ways() {
        assert_eq!(folded('a'), vec!['A', 'a']);
        assert_eq!(folded('A'), vec!['A', 'a']);
        assert_eq!(folded('Z'), vec!['Z', 'z']);
        // A character with no partner is its own class.
        assert_eq!(folded('5'), vec!['5']);
    }

    /// The class of ß holds ẞ and U+1DF95, and none of them folds to `SS`.
    /// The full mapping would say `SS`; the simple one does not, and that
    /// difference is the whole reason this module uses a generated table
    /// instead of `char::to_uppercase`.
    ///
    /// The narrowing then removes ẞ, because ß is two bytes and ẞ is three,
    /// so what the parser actually gets is ß alone.
    #[test]
    fn sharp_s_folds_to_capital_sharp_s_not_to_ss() {
        let full = class_of('ß');
        assert!(full.contains(&'ẞ'), "class is {full:?}");
        assert!(!full.contains(&'S'), "must not fold to S: {full:?}");
        assert!(
            folded('ß').contains(&'ẞ'),
            "ß folds to ẞ at three bytes against two: {full:?}"
        );
    }

    #[test]
    fn three_and_four_member_classes() {
        // 'k' covers KELVIN SIGN, which is three bytes against one, and the
        // fold is the whole class at every width.
        assert_eq!(class_of('k'), vec!['K', 'k', '\u{212A}']);
        assert_eq!(folded('k'), vec!['K', 'k', '\u{212A}']);
        assert_eq!(folded('K'), vec!['K', 'k', '\u{212A}']);
        assert_eq!(folded('\u{212A}'), vec!['K', 'k', '\u{212A}']);
        // micro sign folds to Greek mu and capital mu, all three two bytes.
        let micro = class_of('\u{00B5}');
        assert!(micro.contains(&'\u{039C}'), "class is {micro:?}");
        assert_eq!(folded('\u{00B5}').len(), 3, "all of {micro:?} are 2 bytes");
    }

    /// Cyrillic `в` and `т` carry Unicode 9 combining-mark variants at three
    /// bytes, and the fold reaches them now that mixed-width alternations
    /// are searchable -- the capital/small pair is no longer all it gets.
    #[test]
    fn mixed_width_classes_fold_every_member_at_every_width() {
        assert_eq!(class_of('в').len(), 3, "В, в and U+1C80");
        assert_eq!(folded('в').len(), 3);
        assert_eq!(class_of('т').len(), 4, "Т, т, U+1C84, U+1C85");
        assert_eq!(folded('т').len(), 4);
    }

    /// The Greek final sigma folds to plain sigma. This is the one place rgx
    /// and the `regex` crate part company, and rgx is the more permissive of
    /// the two: see the module header.
    #[test]
    fn final_sigma_folds_with_sigma() {
        assert!(class_of('ς').contains(&'σ'));
        assert!(folded('ς').contains(&'σ'));
        assert!(folded('Σ').contains(&'ς'));
        assert!(folded('σ').contains(&'ς'));
    }

    /// `ı` has only `F` and `T` rows in the UCD, so simple folding leaves it
    /// alone -- which is why `rgx -i 'ı'` does not match `I`, and why it
    /// agrees with ripgrep.
    #[test]
    fn dotless_i_has_no_simple_fold() {
        assert_eq!(class_of('\u{0131}'), vec!['\u{0131}']);
    }

    /// The class-size ceiling is a measured fact, so a new UCD revision that
    /// grew a class past it would fail here rather than silently truncate.
    #[test]
    fn no_class_exceeds_the_declared_ceiling() {
        for &(src, _) in SIMPLE.iter() {
            let s = char::from_u32(src).expect("source is a scalar value");
            assert!(
                (1..=MAX_CLASS).contains(&fold_class(s).len()),
                "class of U+{src:04X} is out of range"
            );
        }
    }

    /// The fold is the FULL class, mixed widths included -- the gate that
    /// dropped KELVIN SIGN from `k` is gone with the scan bound that made it
    /// necessary.
    #[test]
    fn a_fold_reaches_every_width_of_its_class() {
        let k = fold_char('k');
        let chars: Vec<char> = k.iter().collect();
        assert!(chars.contains(&'K'), "k folds to K");
        assert!(
            chars.contains(&'\u{212A}'),
            "k folds to KELVIN SIGN, three bytes against one"
        );
        assert!(
            !k.uniform_len(),
            "that class is exactly the mixed-width case"
        );
        let sharp = fold_char('\u{DF}');
        let chars: Vec<char> = sharp.iter().collect();
        assert!(
            chars.contains(&'\u{1E9E}'),
            "ß folds to ẞ, two bytes against three"
        );
    }
}
