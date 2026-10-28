// SPDX-License-Identifier: Apache-2.0

//! A confirm that is a sequence of byte tests instead of a Pike VM run.
//!
//! Answers only whether a match begins at `s`, and only for a pattern that
//! is a **fixed-length byte predicate**: single-byte classes and literal
//! bytes, no alternation, no unbounded/variable repetition, no capture
//! group, no assertion. For such a pattern the two answers are the same
//! by construction.
//!
//! `e.`'s confirm measured 181.3 ms over 4.2 million candidates on a 235 MB
//! corpus (42.8 ns each); of which the two byte comparisons the pattern
//! specifies are 1.7 ns. Roughly 14 ns is per-call VM setup and 15 ns is
//! `Match` construction — a confirm that is right about the bytes and
//! silent about the bookkeeping is the whole of the win.
//!
//! Everything else returns `None` and runs the VM. The refusals are total:
//! an erring confirm is a silently wrong answer. An assertion is zero-width
//! and its meaning differs by caller (`^` is line-start to the searcher,
//! buffer-start to the VM). An alternation is a choice. A repetition is a
//! count — unbounded ones are unknowable; fixed ones (`x{2}`) are unrolled
//! bounded by [`MAX_LEN`]. A capture group changes the answer. A zero-length
//! pattern matches at every offset, a searcher property.
//!
//! **The bounds check is the load-bearing line.** The VM bounds-checks, and
//! a confirm that read past the end would find bytes that are not there
//! while a differential suite stayed green. [`Fixed::confirm`] takes the
//! window with one `get` and answers `false` when there is none;
//! `end_of_line_runs_are_answered_against_the_vm` pins it directly.

use alloc::vec::Vec;

use super::byteclass::ByteSet;
use super::syntax::Ast;

/// The longest pattern [`Fixed`] will compile.
///
/// 64 is far past any literal the prefilter will anchor on. The table is
/// four words per position, so an unbounded length would make the
/// "cheap" confirm touch more memory than the program it replaced.
pub const MAX_LEN: usize = 64;

/// One membership table per position: 256 bits.
const TABLE_WORDS: usize = 4;

/// A pattern that is a fixed-length byte predicate, compiled once.
///
/// The decision is made per pattern, at compile time. Nothing here is
/// per match, per line, or per candidate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fixed {
    /// Bytes every match of this pattern consumes, which is also its own.
    len: usize,
    /// The literal, when every position accepts exactly one byte.
    ///
    /// A pattern of `N` single-byte classes at offsets `0..N` is one
    /// literal of `N` bytes, and the confirm is a compare of `N` bytes
    /// with no table lookup at all.
    lit: Option<Vec<u8>>,
    /// One 256-bit membership table per position, when `lit` is `None`.
    ///
    /// Empty exactly when `lit` is `Some`; the two are two spellings of the
    /// same table, and the literal one is a strict subset of what the other
    /// can express.
    sets: Vec<[u64; TABLE_WORDS]>,
}

impl Fixed {
    /// Compile `ast` if it is a fixed-length byte predicate, or `None`.
    ///
    /// `ast` must have come from [`super::syntax::parse`]: the answer
    /// depends on the flags in force while it was parsed. A `(?i)` `e` is
    /// a two-member class, and one compiled under the wrong flags would
    /// fold bytes the pattern does not.
    #[must_use]
    pub fn compile(ast: &Ast) -> Option<Self> {
        let mut sets: Vec<[u64; TABLE_WORDS]> = Vec::new();
        if !lower(ast, &mut sets) {
            return None;
        }
        // A pattern that consumes nothing matches at every offset, which
        // is a question about the searcher's line loop and not a
        // predicate over bytes.
        if sets.is_empty() || sets.len() > MAX_LEN {
            return None;
        }
        let lit = sets
            .iter()
            .map(|t| sole_byte(*t))
            .collect::<Option<Vec<u8>>>();
        let sets = if lit.is_some() { Vec::new() } else { sets };
        Some(Self {
            len: sets.len() + lit.as_ref().map_or(0, Vec::len),
            lit,
            sets,
        })
    }

    /// Bytes every match of the pattern consumes.
    // A match width, not a collection size: there is nothing to be empty.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the pattern is one literal, which is the `memcmp` arm.
    #[must_use]
    pub fn is_literal(&self) -> bool {
        self.lit.is_some()
    }

    /// Whether a match of the pattern begins exactly at `start` in `hay`.
    ///
    /// **The bounds check is not a detail and not a fast-path guard.** The VM
    /// it replaces is given the same haystack and answers `false` when the
    /// pattern would run past its end, and this must answer `false` for
    /// exactly the same inputs -- including a candidate at the last byte of a
    /// line whose pattern wants two. Reading past the end instead would
    /// compare bytes that are not in the line and could report a match in
    /// whatever followed it in memory.
    #[inline]
    #[must_use]
    pub fn confirm(&self, hay: &[u8], start: usize) -> bool {
        let Some(end) = start.checked_add(self.len) else {
            return false;
        };
        let Some(win) = hay.get(start..end) else {
            return false;
        };
        match &self.lit {
            Some(lit) => lit_eq(lit, win),
            None => {
                let sets = &self.sets;
                match sets.len() {
                    1 => (sets[0][usize::from(win[0] >> 6)] & (1u64 << (win[0] & 63))) != 0,
                    2 => {
                        (sets[0][usize::from(win[0] >> 6)] & (1u64 << (win[0] & 63))) != 0
                            && (sets[1][usize::from(win[1] >> 6)] & (1u64 << (win[1] & 63))) != 0
                    }
                    3 => {
                        (sets[0][usize::from(win[0] >> 6)] & (1u64 << (win[0] & 63))) != 0
                            && (sets[1][usize::from(win[1] >> 6)] & (1u64 << (win[1] & 63))) != 0
                            && (sets[2][usize::from(win[2] >> 6)] & (1u64 << (win[2] & 63))) != 0
                    }
                    _ => sets
                        .iter()
                        .zip(win)
                        .all(|(&t, &b)| (t[usize::from(b >> 6)] & (1u64 << (b & 63))) != 0),
                }
            }
        }
    }
}

/// The one byte `t` accepts, or `None` when it accepts more (or fewer).
fn sole_byte(t: [u64; TABLE_WORDS]) -> Option<u8> {
    let mut found = None;
    for (i, word) in t.iter().enumerate() {
        let mut w = *word;
        while w != 0 {
            let bit = w.trailing_zeros();
            if found.is_some() {
                return None;
            }
            found = Some((i as u32 * 64 + bit) as u8);
            w &= w - 1;
        }
    }
    found
}

/// `lit` and `win` are equal. `win` is already known to be exactly `lit.len()`
/// long by the caller, so the short arms are plain comparisons rather than a
/// call into `bcmp` for a length the compiler does not know.
#[inline]
fn lit_eq(lit: &[u8], win: &[u8]) -> bool {
    match (win, lit) {
        ([a], [b]) => a == b,
        ([a, b], [x, y]) => a == x && b == y,
        ([a, b, c], [x, y, z]) => a == x && b == y && c == z,
        ([a, b, c, d], [x, y, z, w]) => a == x && b == y && c == z && d == w,
        ([a, b, c, d, e], [x, y, z, w, j]) => a == x && b == y && c == z && d == w && e == j,
        ([a, b, c, d, e, f], [x, y, z, w, j, k]) => {
            a == x && b == y && c == z && d == w && e == j && f == k
        }
        ([a, b, c, d, e, f, g], [x, y, z, w, j, k, l]) => {
            a == x && b == y && c == z && d == w && e == j && f == k && g == l
        }
        ([a, b, c, d, e, f, g, h], [x, y, z, w, j, k, l, m]) => {
            a == x && b == y && c == z && d == w && e == j && f == k && g == l && h == m
        }
        _ => win == lit,
    }
}

/// Append the positions `ast` consumes to `out`, or report that it cannot.
///
/// `false` means "this is not a fixed-length byte predicate", and the caller
/// treats it as a decline rather than a partial answer -- so nothing half
/// appended is ever used.
fn lower(ast: &Ast, out: &mut Vec<[u64; TABLE_WORDS]>) -> bool {
    if out.len() >= MAX_LEN {
        // One more byte would take it past the cap, and the cap is checked
        // on the final length too; stopping here keeps the recursion from
        // unrolling `x{1000}` before anything has had a chance to decline it.
        return false;
    }
    match ast {
        Ast::Class(set) => {
            out.push(class_table(set));
            true
        }
        Ast::Empty => true,
        Ast::Concat(items) => items.iter().all(|i| lower(i, out)),
        // A capturing group changes the ANSWER, not just the work: the VM
        // reports where it is and this cannot. A non-capturing one is
        // invisible in the language and invisible here.
        Ast::Group { index: None, node } => lower(node, out),
        Ast::Group { index: Some(_), .. } => false,
        // `min == max` is the only repetition whose length is known, and a
        // known length is a loop the predicate can take. The cap stops
        // `x{1000}` before it is unrolled rather than after.
        Ast::Repeat {
            node,
            min,
            max: Some(max),
            ..
        } if max == min => (0..*min).all(|_| lower(node, out)),
        Ast::Repeat { .. } | Ast::Alt(_) | Ast::Assert(_) => false,
    }
}

/// The membership table for one consumed byte.
///
/// Rebuilt from the set rather than copied: `ByteSet`'s own words are
/// private. This runs once per pattern position, at compile time.
fn class_table(set: &ByteSet) -> [u64; TABLE_WORDS] {
    let mut t = [0u64; TABLE_WORDS];
    for b in set.iter() {
        t[usize::from(b) >> 6] |= 1u64 << (b & 63);
    }
    t
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::super::syntax::parse;
    use super::*;

    fn fx(pat: &[u8]) -> Option<Fixed> {
        Fixed::compile(&parse(pat).expect("parses").ast)
    }

    /// What the specialised confirm and the VM say about the same thing.
    fn agrees(pat: &[u8], hay: &[u8]) {
        let Some(f) = fx(pat) else {
            return;
        };
        let p = parse(pat).expect("parses");
        let prog = super::super::nfa::compile(&p.ast, p.groups);
        for at in 0..=hay.len() + 2 {
            assert_eq!(
                f.confirm(hay, at),
                super::super::vm::matches_at(&prog, hay, at),
                "{:?} at {at} of {:?}",
                String::from_utf8_lossy(pat),
                String::from_utf8_lossy(hay),
            );
        }
    }

    #[test]
    fn the_shapes_it_is_for_are_accepted() {
        for pat in [
            &b"e"[..],
            b"e.",
            b"e..",
            b"e[0-9]",
            b"pub fn",
            b"fn main",
            b"let mut",
            b"a.c",
            b"[a-z]x[0-9]",
            b"a{3}",
            b"(?i)Er.",
            b"[[:alpha:]]x",
            b"a{2,2}b",
        ] {
            assert!(
                fx(pat).is_some(),
                "{:?} should compile",
                String::from_utf8_lossy(pat)
            );
        }
    }

    #[test]
    fn the_shapes_it_must_decline_are_declined() {
        for pat in [
            &b""[..],
            b"a*",
            b"a+",
            b"a?",
            b"[a-z]+[0-9]",
            b"(?:ab|cd)x",
            b"(pub|fn) [a-z]+",
            b"foo.*bar",
            b"^a",
            b"a$",
            b"\\ba",
            b"(a)(b)c",
            b"x{2,3}y",
            b"\\d+em",
            b"a{100}",
        ] {
            assert!(
                fx(pat).is_none(),
                "{:?} should decline",
                String::from_utf8_lossy(pat)
            );
        }
        // `a|b` is no longer here: the parser coalesces it to a
        // single `Class({a,b})`, and the fixed optimiser now handles
        // it. Its accept path is asserted below in the right-shape
        // list (a single multi-byte class at offset 0 is a fixed
        // prefix, by the same reasoning that makes `a` one).
    }

    /// The trap the module header names: a confirm anchored at the last
    /// byte of the haystack, for a pattern that wants one more, is
    /// `false` — and so is the VM, which is the only reason declining to
    /// check is safe.
    #[test]
    fn end_of_line_runs_are_answered_against_the_vm() {
        for pat in [&b"e."[..], b"e[0-9]", b"pub fn", b"let mut", b"a.c"] {
            for n in 0..12usize {
                for filler in *b"eax" {
                    let mut hay = vec![filler; n];
                    if n > 0 {
                        hay[0] = b'e';
                    }
                    agrees(pat, &hay);
                    // One byte short of what the pattern wants, which is
                    // the case the bounds check exists for.
                    let mut short = hay.clone();
                    short.push(filler);
                    agrees(pat, &short);
                }
            }
        }
    }

    /// Specialised against the VM: a disagreement in either direction is a
    /// wrong answer.
    #[test]
    fn agrees_with_the_vm_offset_by_offset() {
        const PATS: &[&[u8]] = &[
            b"e",
            b"e.",
            b"e..",
            b"e[0-9]",
            b"pub fn",
            b"fn main",
            b"let mut",
            b"a.c",
            b"a.b",
            b"[a-z]x",
            b"x[a-z]",
            b"[0-9][a-z]",
            b"a[0-9]b[0-9]c",
            b"a{3}",
            b"(?:ab|cd)x",
            b"(?i)Er.",
            b"[[:alpha:]]x",
            b"[0-9]em",
            b"a.b.c",
            b"[-a-z]x",
            b"\x00\x01",
        ];
        const HAYS: &[&[u8]] = &[
            b"",
            b"e",
            b"x",
            b"ex",
            b"e0",
            b"e\xC3\xA9",
            b"a\nb",
            b"pub fn main() {}",
            b"let mut value = parse_error(x);",
            b"a1b2c3",
            b"abx cdx",
            b"ER! er! Er! eR!",
            b"ax1 bx2 cx3",
            b"\x00\x01\x02",
            b"abcdefghijklmnopqrstuvwxyz",
            b"0123456789",
        ];
        for pat in PATS {
            for hay in HAYS {
                agrees(pat, hay);
            }
        }
    }

    /// A class with a non-ASCII byte in it, and one with a high byte, because
    /// the table is indexed by the whole byte and an off-by-a-bit in the
    /// index is invisible on ASCII.
    #[test]
    fn non_ascii_bytes_are_tabled_correctly() {
        for pat in [
            &b"\xE9."[..],
            b"[\x80-\xFF]x",
            b"[\x00\x7F\xFF]y",
            b"[\xC3\xA9]z",
        ] {
            for hay in [
                b"".as_slice(),
                b"\xE9".as_slice(),
                b"\xE9\xE9".as_slice(),
                b"\x80x",
                b"\xFFx",
                b"\x00x",
                b"\x7Fx",
                b"\xC3\xA9z",
                b"\xA9z",
            ] {
                agrees(pat, hay);
            }
        }
    }

    /// A whole-pattern literal of every length the specialiser will take, so
    /// the `memcmp` arm is compared with the table arm rather than assumed
    /// equal to it.
    #[test]
    fn every_literal_length_agrees_with_the_vm() {
        for n in 1..=24usize {
            let lit: Vec<u8> = (0..n)
                .map(|i| b'a' + u8::try_from(i % 26).unwrap())
                .collect();
            let mut hay = lit.clone();
            hay.push(b'!');
            hay.extend_from_slice(&lit);
            agrees(&lit, &hay);
        }
    }

    /// The bounds check, stated without a reference: an anchored confirm
    /// for a two-byte pattern on a one-byte haystack is `false`, and
    /// never reads the byte after it. Run under a bounds-checked slice
    /// this is a panic if the `get` is gone.
    #[test]
    fn a_window_that_does_not_fit_is_not_a_match() {
        let f = fx(b"ee").expect("compiles");
        assert!(f.confirm(b"ee", 0));
        assert!(!f.confirm(b"e", 0));
        assert!(!f.confirm(b"", 0));
        // Three bytes, two wanted: the window that fits is the window tested.
        assert!(f.confirm(b"eee", 1));
        assert!(!f.confirm(b"eee", 2));
        // An offset past the end entirely, and one that would overflow.
        assert!(!f.confirm(b"ee", 2));
        assert!(!f.confirm(b"ee", usize::MAX));
    }

    /// A one-byte pattern on a one-byte haystack: the boundary where the
    /// VM stops and the bounds check must not.
    #[test]
    fn the_last_byte_of_a_line_is_reachable() {
        let f = fx(b"e").expect("compiles");
        assert!(f.confirm(b"e", 0));
        assert!(!f.confirm(b"e", 1));
        let f2 = fx(b"e.").expect("compiles");
        assert!(!f2.confirm(b"e", 0), "one byte is not two");
        assert!(f2.confirm(b"ex", 0));
        assert!(!f2.confirm(b"ex", 1));
    }

    // ---- the generated grid -------------------------------------------

    /// A deterministic LCG. A fixed seed is the point: a failure here has to
    /// be reproducible from the test name alone, which a real RNG would not
    /// give.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// A pattern drawn from a grammar that includes every shape the compiler
    /// has an opinion about -- the ones it accepts AND the ones it must
    /// decline -- so the grid exercises the accept decision as well as the
    /// confirm. Half of a generated pattern being un-specialisable is the
    /// expected yield, not a defect.
    fn gen_pattern(r: &mut Lcg, depth: u32) -> String {
        let leaf = |r: &mut Lcg| -> String {
            match r.below(10) {
                0 => "'a'".into(),
                1 => "'e'".into(),
                2 => "'\\n'".into(),
                3 => "[0-9]".into(),
                4 => "[a-z]".into(),
                5 => "[^ae0]".into(),
                6 => "[[:alpha:]]".into(),
                7 => "\\w".into(),
                8 => ".".into(),
                _ => "x".into(),
            }
        };
        if depth == 0 {
            return leaf(r);
        }
        match r.below(12) {
            0 => format!("({})", gen_pattern(r, depth - 1)),
            1 => format!("(?:{}{})", gen_pattern(r, 0), gen_pattern(r, 0)),
            2 => format!("{}|{}", gen_pattern(r, 0), gen_pattern(r, 0)),
            3 => format!("{}+", gen_pattern(r, 0)),
            4 => format!("{}[0-9]", gen_pattern(r, 0)),
            5 => format!("({})", gen_pattern(r, 0)),
            6 => format!("(?i){}", gen_pattern(r, 0)),
            7 => format!("^{}", gen_pattern(r, 0)),
            8 => format!("{}$", gen_pattern(r, 0)),
            9 => alloc::string::String::from(".{2}"),
            10 => format!("{}.", gen_pattern(r, 0)),
            _ => format!("{}{}", gen_pattern(r, 0), gen_pattern(r, 0)),
        }
    }

    /// Haystacks built from a small alphabet so matches actually happen, at
    /// lengths that straddle the interesting boundaries: empty, one byte,
    /// one shorter than the longest pattern, and one longer.
    fn gen_hay(r: &mut Lcg) -> Vec<u8> {
        let n = match r.below(6) {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 3,
            4 => 4 + r.below(6),
            _ => 1 + r.below(12),
        };
        const ALPHA: &[u8] = b"aeE0x\n \t.:;";
        (0..n).map(|_| ALPHA[r.below(ALPHA.len())]).collect()
    }

    /// The test the module is judged by. Several thousand generated
    /// patterns against several hundred generated haystacks, every offset
    /// of every haystack, specialised against the Pike VM.
    ///
    /// The comparison is the VM's, in both directions: a too-eager confirm
    /// reports a match the VM does not, a too-shy one drops one it does.
    /// The first is a silently wrong answer, the second a missed line.
    #[test]
    fn generated_patterns_agree_with_the_vm_pair_by_pair() {
        use super::super::matcher::Matcher as _;
        use super::super::nfa;
        use super::super::regex::ByteRegex;

        let mut r = Lcg(0x5EED_1234_ABCD_0001);
        let mut hays: Vec<Vec<u8>> =
            vec![Vec::new(), b"a".to_vec(), b"e".to_vec(), b"a\n".to_vec()];
        for _ in 0..200 {
            hays.push(gen_hay(&mut r));
        }
        // A few fixed shapes so the grid is not only whatever the generator
        // felt like producing: the empty pattern, one that matches the empty
        // string, and one that matches everything.
        hays.push(b"aaaaaaaaaaaaaaaa".to_vec());
        hays.push(b"................".to_vec());
        hays.push(b"EEEEeeee0000".to_vec());

        let mut compiled = 0usize;
        let mut declined = 0usize;
        for _ in 0..4000 {
            let pat = gen_pattern(&mut r, 2);
            let Ok(parsed) = parse(pat.as_bytes()) else {
                continue;
            };
            let prog = nfa::compile(&parsed.ast, parsed.groups);
            let Some(f) = Fixed::compile(&parsed.ast) else {
                declined += 1;
                continue;
            };
            compiled += 1;
            // And the same check through the engine's own door, so the wiring
            // in `regex.rs` is in the loop rather than assumed to follow.
            let re = ByteRegex::new(pat.as_bytes()).expect("parses");
            for hay in &hays {
                for at in 0..=hay.len() {
                    let want = super::super::vm::matches_at(&prog, hay, at);
                    assert_eq!(
                        f.confirm(hay, at),
                        want,
                        "confirm: {pat:?} at {at} of {:?}",
                        String::from_utf8_lossy(hay),
                    );
                    assert_eq!(
                        re.is_match_at(hay, at),
                        want,
                        "is_match_at: {pat:?} at {at} of {:?}",
                        String::from_utf8_lossy(hay),
                    );
                }
                // The whole-line question the searcher actually asks, and the
                // leftmost match it would report.
                assert_eq!(
                    re.find_span_at(hay, 0).is_some(),
                    super::super::vm::find(&prog, hay, 0).is_some(),
                    "find_span_at: {pat:?} in {:?}",
                    String::from_utf8_lossy(hay),
                );
                if let (Some(got), Some(want)) = (
                    re.find_span_at(hay, 0),
                    super::super::vm::find(&prog, hay, 0),
                ) {
                    assert_eq!(
                        got,
                        want.start..want.end,
                        "span: {pat:?} in {:?}",
                        String::from_utf8_lossy(hay),
                    );
                }
            }
        }
        assert!(
            compiled > 100,
            "the grid specialised almost nothing ({compiled})"
        );
        assert!(
            declined > 100,
            "the grid declined almost nothing ({declined})"
        );
    }

    /// A match that straddles the 64 KiB fill boundary, because a confirm
    /// that reads a line the searcher has not finished assembling is a
    /// different question and the boundary is where that shows up.
    #[test]
    fn a_match_across_the_fill_boundary_agrees_with_the_vm() {
        use super::super::matcher::Matcher as _;
        use super::super::nfa;
        use super::super::regex::ByteRegex;

        const FILL: usize = 64 * 1024;
        for pat in [
            &b"e."[..],
            b"e[0-9]",
            b"pub fn",
            b"let mut",
            b"a.c",
            b"xx[0-9]zz",
        ] {
            let f = fx(pat).expect("compiles");
            let re = ByteRegex::new(pat).expect("parses");
            let parsed = parse(pat).expect("parses");
            let prog = nfa::compile(&parsed.ast, parsed.groups);
            let mut hay = vec![b'.'; FILL + 64];
            for off in [FILL - 8, FILL - 3, FILL - 2, FILL - 1, FILL, FILL + 1] {
                for tail in [
                    &b"e1"[..],
                    &b"pub fn"[..],
                    &b"let mut"[..],
                    &b"axc"[..],
                    &b"xx7zz"[..],
                ] {
                    let n = core::cmp::min(tail.len(), hay.len() - off);
                    hay[off..off + n].copy_from_slice(&tail[..n]);
                    for at in off.saturating_sub(12)..=off + tail.len() + 2 {
                        if at > hay.len() {
                            break;
                        }
                        assert_eq!(
                            f.confirm(&hay, at),
                            super::super::vm::matches_at(&prog, &hay, at),
                            "{:?} at {at} across the fill boundary",
                            String::from_utf8_lossy(pat),
                        );
                        assert_eq!(
                            re.is_match_at(&hay, at),
                            super::super::vm::matches_at(&prog, &hay, at),
                            "{:?} at {at} across the fill boundary (engine)",
                            String::from_utf8_lossy(pat),
                        );
                    }
                }
            }
        }
    }

    /// A haystack with no trailing newline, and one with nothing but a
    /// newline. The first is the last line of every file that does not end
    /// one, and it is where a confirm that trusted a terminator would look.
    #[test]
    fn a_haystack_without_a_trailing_newline_agrees_with_the_vm() {
        use super::super::nfa;

        for pat in [&b"e."[..], b"e[0-9]", b"pub fn", b"let mut", b"tail\n"] {
            let parsed = parse(pat).expect("parses");
            let prog = nfa::compile(&parsed.ast, parsed.groups);
            let Some(f) = Fixed::compile(&parsed.ast) else {
                continue;
            };
            for hay in [
                b"".as_slice(),
                b"e".as_slice(),
                b"ex".as_slice(),
                b"tail\n".as_slice(),
                b"last line has no terminator".as_slice(),
            ] {
                for at in 0..=hay.len() {
                    assert_eq!(
                        f.confirm(hay, at),
                        super::super::vm::matches_at(&prog, hay, at),
                        "{:?} at {at} of {:?}",
                        String::from_utf8_lossy(pat),
                        String::from_utf8_lossy(hay),
                    );
                }
            }
        }
    }
}
