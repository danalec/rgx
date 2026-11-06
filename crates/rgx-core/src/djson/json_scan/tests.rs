// SPDX-License-Identifier: Apache-2.0

//! Tests for the structural scanner.
//!
//! The load-bearing idea here is that there are **three** implementations of
//! the predicate — the byte-at-a-time [`scan_scalar`], the portable 64-byte
//! [`scan_swar`], and the AVX2 path — plus a fourth, [`oracle`], transcribed
//! from RFC 8259 without looking at any of them. Every hostile input below is
//! run through all four and the outputs compared bit for bit.
//!
//! The corpus is chosen from the ways this specific algorithm can be wrong,
//! not from the ways parsers in general go wrong:
//!
//! * a backslash run that starts in one 64-byte block and ends in the next,
//!   at every length and every offset around the boundary;
//! * a quote or a structural byte at every offset across four block
//!   boundaries, inside and outside a string, so the two carry bits are
//!   exercised on both sides;
//! * a byte that is structural in one row of the nibble grid and content in
//!   another (`0x2A` shares a row with `,`, `0x3A` shares a low nibble with
//!   `0x0A`) — the pairs that defeat a single lookup pair;
//! * bytes `>= 0x80`, including the multi-byte UTF-8 of a string's contents
//!   and a sequence split across a block boundary;
//! * unterminated strings, an escaped quote outside any string (which the
//!   output must *not* report as a delimiter), and empty strings.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::*;

// ---------------------------------------------------------------------------
// The oracle
// ---------------------------------------------------------------------------

/// The predicate, transcribed from RFC 8259. Deliberately written without
/// looking at any implementation in this module: it classifies bytes with a
/// literal `matches!`, keeps the backslash run as a *count* rather than a
/// parity, and reorders nothing.
fn oracle(bytes: &[u8]) -> StructuralIndex {
    let mut structural = BitSet::with_len(bytes.len());
    let mut quote = BitSet::with_len(bytes.len());
    let mut in_string = false;
    let mut run = 0usize;

    for (i, &b) in bytes.iter().enumerate() {
        let mut is_structural = false;
        let mut is_quote = false;
        // The run that ends at the *previous* byte decides whether this
        // quote is escaped. Reading it before the reset below is the whole
        // test: an oracle that clears the counter and then asks whether it
        // was even has quietly decided every quote opens a string.
        let escaped = run % 2 == 1;
        match b {
            b'"' => {
                run = 0;
                if !escaped {
                    is_quote = true;
                    is_structural = true;
                    in_string = !in_string;
                }
            }
            b'\\' => run += 1,
            _ => {
                run = 0;
                if !in_string && is_punctuation_or_space(b) {
                    is_structural = true;
                }
            }
        }
        if is_structural {
            structural.set(i);
        }
        if is_quote {
            quote.set(i);
        }
    }

    StructuralIndex {
        structural,
        quote,
        len: bytes.len(),
        end_in_string: in_string,
    }
}

/// RFC 8259's structural characters and whitespace, written out by hand so
/// that it is a second opinion on [`CLASS_TABLE`] rather than a copy of it.
fn is_punctuation_or_space(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t' | b'\n' | b'\r' | b'{' | b'}' | b'[' | b']' | b':' | b','
    )
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The AVX2 path, or `None` if this CPU cannot run it.
///
/// The AVX2 module exists only on x86_64, and on every other target the
/// answer is `None` for the same reason it is `None` on an x86_64 without the
/// feature: there is no vector path to run. The helper is defined on every
/// target so the corpus is the same corpus everywhere -- what changes is the
/// number of implementations it holds against the oracle.
#[cfg(target_arch = "x86_64")]
fn avx2_scan(bytes: &[u8]) -> Option<StructuralIndex> {
    if has_avx2_pclmulqdq() {
        // SAFETY: `has_avx2_pclmulqdq` just reported both features, which is
        // the precondition of `scan_avx2`; see its documentation.
        return Some(unsafe { avx2::scan_avx2(bytes) });
    }
    None
}

/// The AVX2 path on a target that has none. See [`avx2_scan`].
#[cfg(not(target_arch = "x86_64"))]
fn avx2_scan(_bytes: &[u8]) -> Option<StructuralIndex> {
    None
}

#[test]
fn cpuid_detection_matches_the_std_macro() {
    // The dispatch reads the hand-written CPUID/XGETBV probe in every build,
    // `std` or not, so the standard library's answer is the one this crate is
    // measured against. The probe lives in `crate::detect` and is tested
    // against the standard library there; what is checked here is the half
    // that is this module's own: the vector path is callable exactly when the
    // detection says it is. A no_std build that dispatched on a detection
    // that disagrees with `std`'s would trap on a kernel that reports AVX2
    // without saving the YMM state.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        assert_eq!(has_avx2(), std::is_x86_feature_detected!("avx2"));
        assert_eq!(crate::detect::avx2(), std::is_x86_feature_detected!("avx2"));
        assert_eq!(
            crate::detect::pclmulqdq(),
            std::is_x86_feature_detected!("pclmulqdq")
        );
        assert_eq!(
            has_avx2_pclmulqdq(),
            std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("pclmulqdq"),
        );
    }
    #[cfg(target_arch = "x86_64")]
    {
        // Whatever the answer, the vector path is callable exactly when it is
        // said to be.
        assert_eq!(avx2_scan(b"{}").is_some(), has_avx2_pclmulqdq());
        assert_eq!(
            has_avx2_pclmulqdq(),
            crate::detect::avx2() && crate::detect::pclmulqdq(),
        );
    }
}

/// The first byte at which two results disagree, if any.
fn first_difference(want: &StructuralIndex, got: &StructuralIndex) -> Option<usize> {
    (0..want.len).find(|&i| {
        want.structural.contains(i) != got.structural.contains(i)
            || want.quote.contains(i) != got.quote.contains(i)
    })
}

/// A short, printable sketch of an input, for a failure message.
///
/// No `format!`: a `for` loop pushing a hex table is a few hundred
/// nanoseconds, and this is on the path of a failure in a corpus of tens of
/// thousands of inputs.
fn sketch(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    out.push_str("len ");
    push_usize(&mut out, input.len());
    out.push_str(" [");
    for &b in input.iter().take(48) {
        match b {
            b' '..=b'~' => out.push(b as char),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            _ => {
                out.push_str("\\x");
                out.push(HEX[usize::from(b >> 4)] as char);
                out.push(HEX[usize::from(b & 0x0F)] as char);
            }
        }
    }
    if input.len() > 48 {
        out.push_str("...");
    }
    out.push(']');
    out
}

fn push_usize(out: &mut String, mut v: usize) {
    let mut digits = [0u8; 20];
    let mut n = 0;
    loop {
        digits[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for &d in digits[..n].iter().rev() {
        out.push(d as char);
    }
}

fn assert_same(name: &str, got: &StructuralIndex, want: &StructuralIndex, input: &[u8]) {
    if got == want {
        return;
    }
    let at = first_difference(want, got);
    let in_string_want = at.map(|i| want.structural.contains(i));
    let in_string_got = at.map(|i| got.structural.contains(i));
    let quote_want = at.map(|i| want.quote.contains(i));
    let quote_got = at.map(|i| got.quote.contains(i));
    panic!(
        "{name} disagrees with the oracle at byte {at:?} (structural {in_string_want:?} vs \
         {in_string_got:?}, quote {quote_want:?} vs {quote_got:?}); end_in_string {} vs {}; \
         input {}",
        want.end_in_string,
        got.end_in_string,
        sketch(input),
    );
}

/// Every implementation, on one input.
fn assert_agree(input: &[u8]) {
    let want = oracle(input);
    assert_same("scan_scalar", &scan_scalar(input), &want, input);
    assert_same("scan_swar", &scan_swar(input), &want, input);
    assert_same("scan", &scan(input), &want, input);
    if let Some(got) = avx2_scan(input) {
        assert_same("scan_avx2", &got, &want, input);
    }
    // Whatever the corpus, no byte inside a string is ever structural, and no
    // two adjacent quotes can both open a string.
    assert_string_invariant(input, &want);
}

/// A property that follows from the definition rather than from any of the
/// three implementations: between an opening quote and its closing quote
/// there is nothing structural.
///
/// The delimiter quotes alternate open, close, open... because the state
/// starts outside a string, so a position is inside a string exactly when it
/// lies strictly between an even-indexed quote and the one after it. Both
/// sets are walked in order, which keeps this linear -- the naive version,
/// testing every byte of every span, is quadratic and turned the corpus from
/// a second into a minute.
fn assert_string_invariant(input: &[u8], index: &StructuralIndex) {
    let quotes: Vec<usize> = index.quote_positions().collect();
    let mut j = 0usize; // the open quote of the span under consideration
    for i in index.structural_positions() {
        // Skip spans that closed strictly before `i`.
        while j + 1 < quotes.len() && quotes[j + 1] < i {
            j += 2;
        }
        if j + 1 < quotes.len() && quotes[j] < i && i < quotes[j + 1] {
            panic!(
                "byte {i} ({:#04x}) is structural inside the string opened at {} and closed at \
                 {}; input {}",
                input[i],
                quotes[j],
                quotes[j + 1],
                sketch(input),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// A deterministic PRNG, so a failure is always reproducible.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }
    fn below(&mut self, n: usize) -> usize {
        ((self.next_u64() >> 1) % n as u64) as usize
    }
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

#[test]
fn class_table_matches_a_hand_written_match_for_every_byte() {
    for b in 0..=255u8 {
        let expected = if b == b'"' {
            CLASS_QUOTE
        } else if b == b'\\' {
            CLASS_BACKSLASH
        } else if is_punctuation_or_space(b) {
            CLASS_STRUCTURAL
        } else {
            CLASS_OTHER
        };
        assert_eq!(CLASS_TABLE[b as usize], expected, "byte {b:#04x}");
        assert_eq!(class_of(b), expected, "byte {b:#04x}");
    }
}

#[test]
fn whitespace_and_punctuation_agree_with_the_table() {
    for b in 0..=255u8 {
        assert_eq!(
            is_whitespace(b),
            matches!(b, b' ' | b'\t' | b'\n' | b'\r'),
            "byte {b:#04x}",
        );
    }
}

#[test]
fn each_rectangle_selects_exactly_the_bytes_it_documents() {
    for (name, rect, expected) in RECTANGLES {
        let selected = rect_bytes(rect);
        let mut want = [0u8; 256];
        for &b in expected {
            want[b as usize] = 0xFF;
        }
        for b in 0..256usize {
            assert_eq!(selected[b], want[b], "rectangle {name}, byte {b:#04x}");
        }
    }
}

#[test]
fn the_planes_reconstruct_the_class_table() {
    // What the vector path computes: one OR of five rectangles for the
    // structural plane, one rectangle for the quote plane, compared against
    // the 256-entry table the scalar path uses. If a rectangle over-selected
    // — `0x2A` for the comma, say — this is where it shows.
    let mut structural = [0u8; 256];
    let mut quote = [0u8; 256];
    for rect in [
        RECT_SPACE,
        RECT_CTRL_WS,
        RECT_COMMA,
        RECT_COLON,
        RECT_BRACKET,
    ] {
        let selected = rect_bytes(rect);
        for b in 0..256usize {
            structural[b] |= selected[b];
        }
    }
    quote.copy_from_slice(&rect_bytes(RECT_QUOTE));
    for b in 0..=255u8 {
        let class = CLASS_TABLE[b as usize];
        assert_eq!(
            structural[b as usize],
            if class == CLASS_STRUCTURAL {
                0xFF
            } else {
                0x00
            },
            "structural plane, byte {b:#04x}",
        );
        assert_eq!(
            quote[b as usize],
            if class == CLASS_QUOTE { 0xFF } else { 0x00 },
            "quote plane, byte {b:#04x}",
        );
        // And the backslash is in neither plane, which is the property the
        // two masked comparisons got wrong: `CLASS_BACKSLASH & CLASS_STRUCTURAL`
        // is non-zero, so a `&` test puts every backslash in the structural
        // plane and the quote plane too, which turns a lone `\` into a
        // string delimiter.
        if class == CLASS_BACKSLASH {
            assert_eq!(b, b'\\');
            assert_eq!(
                structural[b as usize] | quote[b as usize],
                0,
                "backslash {b:#04x}"
            );
        }
    }
}

#[test]
fn class_codes_are_compared_not_masked() {
    // `CLASS_BACKSLASH` is `0b11`, so masking it with the other two constants
    // is non-zero. This is a property of the encoding, asserted so that the
    // choice is a decision rather than an accident: any future change that
    // makes the codes maskable has to update every `class & ...` in the
    // module, and this is where that would show up first.
    assert_eq!(CLASS_BACKSLASH & CLASS_STRUCTURAL, 0b01);
    assert_eq!(CLASS_BACKSLASH & CLASS_QUOTE, 0b10);
    // The codes the two planes produce are exactly 0, 1 and 2.
    for b in 0..=255u8 {
        if CLASS_TABLE[b as usize] != CLASS_BACKSLASH {
            assert!(CLASS_TABLE[b as usize] <= 2, "byte {b:#04x}");
        }
    }
    // `classify16` is the one place that packs all three, and it agrees with
    // the planes plus the separate backslash mask.
    let mut window = [b'.'; 16];
    for (i, slot) in window.iter_mut().enumerate() {
        *slot = match i % 4 {
            0 => b'\\',
            1 => b'"',
            2 => b'{',
            _ => b' ',
        };
    }
    let got = classify16(&window);
    assert_eq!(got.backslash, 0b0001_0001_0001_0001);
    for i in 0..16usize {
        let code = (got.code >> (2 * i)) & 0b11;
        let want = match CLASS_TABLE[window[i] as usize] {
            CLASS_BACKSLASH => 3,
            CLASS_QUOTE => 2,
            CLASS_STRUCTURAL => 1,
            _ => 0,
        };
        assert_eq!(code, want, "byte {i} ({:#04x})", window[i]);
    }
}

#[test]
fn hi_nibble_rows_above_7_are_inert() {
    // `pshufb` takes the low nibble of the index and zeroes the lane when bit
    // 7 is set, so a table entry can only ever be reached through a 4-bit
    // index. The other half of the hazard is the *high* nibble: `b >> 4` is
    // in `0..=15` for every `u8`, but the rows `8..=15` — every byte that can
    // appear in UTF-8 — must select nothing, or a continuation byte would
    // land in a structural class.
    for (name, (_, hi), _) in RECTANGLES {
        for (row, &val) in hi.iter().enumerate().skip(8) {
            assert_eq!(val, 0, "rectangle {name} has a row for high nibble {row}");
        }
    }
    for b in 0x80..=0xFFu8 {
        for (name, rect, _) in RECTANGLES {
            assert_eq!(
                rect_bytes(rect)[b as usize],
                0,
                "rectangle {name} selects the non-ASCII byte {b:#04x}",
            );
        }
    }
    // And the two nibbles really do partition the byte into indices that
    // address a 16-entry table. This was two `assert!((b & 0x0F) < 16)`
    // tautologies -- a 4-bit mask on a u8 is always under 16, so neither
    // line could fail. What is worth pinning is the split itself, and that
    // the halves reconstruct the byte.
    for b in 0..=255u8 {
        let hi = (b >> 4) as usize;
        let lo = (b & 0x0F) as usize;
        assert!(
            (0..16).contains(&hi) && (0..16).contains(&lo),
            "byte {b:#04x} split into {hi},{lo}, outside a 16-entry table"
        );
        assert_eq!(
            (hi << 4) | lo,
            usize::from(b),
            "nibble split must round-trip"
        );
    }
}

#[test]
fn classify16_packs_two_bits_per_byte() {
    let window: [u8; 16] = [
        b'{', b'"', b'a', b'\\', b'"', b'b', b':', 0x20, 0x09, 0x0A, 0x0D, 0x2C, 0x5B, 0x5D, 0xC3,
        0xA9,
    ];
    let got = classify16(&window);
    for (i, &b) in window.iter().enumerate() {
        let want = CLASS_TABLE[b as usize];
        let packed = ((got.code >> (2 * i)) & 0b11) as u8;
        assert_eq!(packed, want, "byte {i} ({b:#04x}) packs as {packed}");
        assert_eq!(
            got.whitespace >> i & 1 == 1,
            is_whitespace(b),
            "whitespace, byte {i}"
        );
        assert_eq!(
            got.backslash >> i & 1 == 1,
            b == b'\\',
            "backslash, byte {i}"
        );
    }
    // The 16 bytes are 32 bits, and the top byte's code occupies the top two.
    assert_eq!(got.code >> 30, 0);
}

/// The vector classification against the 256-entry table, on every window.
///
/// x86_64 only: `classify16_avx2` is the vector counterpart of `classify16`,
/// and there is no vector counterpart on a target without AVX2 -- the scalar
/// `classify16` *is* the implementation there, so there is nothing to hold it
/// against.
#[cfg(target_arch = "x86_64")]
#[test]
fn classify16_avx2_agrees_with_classify16_on_every_window() {
    // Every byte value at every position, so the tables are compared against
    // the 256-entry table in all 16 lanes and not only in the first.
    for offset in 0..16usize {
        for value in 0..=255u8 {
            let mut window = [b'.'; 16];
            window[offset] = value;
            assert_eq!(
                classify16_avx2(&window),
                classify16(&window),
                "window {window:?}",
            );
        }
    }
    // And a sweep of the whole byte range laid out across 16 lanes at once.
    for base in (0..=240u16).step_by(16) {
        let mut window = [0u8; 16];
        for (i, slot) in window.iter_mut().enumerate() {
            *slot = (base as u8).wrapping_add(i as u8);
        }
        assert_eq!(
            classify16_avx2(&window),
            classify16(&window),
            "window {window:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The prefix-XOR, the two ways
// ---------------------------------------------------------------------------

#[test]
fn prefix_xor_is_an_inclusive_prefix_parity() {
    let mut rng = Rng::new(0x5EED_1234_ABCD_0001);
    for _ in 0..2000 {
        let x = rng.next_u64();
        let got = prefix_xor(x);
        for i in 0..64usize {
            let mut want = 0u64;
            for j in 0..=i {
                want ^= (x >> j) & 1;
            }
            assert_eq!(got >> i & 1, want, "bit {i} of {x:#018x}");
        }
    }
    assert_eq!(prefix_xor(0), 0);
    assert_eq!(prefix_xor(1), u64::MAX);
    assert_eq!(prefix_xor(1 << 63), 0x8000_0000_0000_0000);
}

/// The carry-less-multiply prefix-XOR against the shift chain.
///
/// x86_64 only, for the same reason as the classification above: PCLMULQDQ is
/// the instruction this test compares against a chain of shifts, and the
/// scalar chain is the only implementation on a target without it.
#[cfg(target_arch = "x86_64")]
#[test]
fn clmul_prefix_xor_agrees_with_the_shift_chain() {
    if !has_avx2_pclmulqdq() {
        return;
    }
    let mut rng = Rng::new(0xC1E5_5EED_0000_0001);
    for _ in 0..5000 {
        let x = rng.next_u64();
        // SAFETY: `has_avx2_pclmulqdq` was just checked, which is this
        // function's precondition.
        let clmul = unsafe { avx2::prefix_xor_clmul(x) };
        assert_eq!(clmul, prefix_xor(x), "{x:#018x}");
    }
    for x in [
        0,
        1,
        u64::MAX,
        1 << 63,
        0x5555_5555_5555_5555,
        0xAAAA_AAAA_AAAA_AAAA,
    ] {
        // SAFETY: as above.
        assert_eq!(unsafe { avx2::prefix_xor_clmul(x) }, prefix_xor(x));
    }
}

// ---------------------------------------------------------------------------
// Hand-written cases
// ---------------------------------------------------------------------------

#[test]
fn trivial_documents() {
    let cases: &[&[u8]] = &[
        b"",
        b"null",
        b"{}",
        b"[]",
        b"1",
        b"  \t\r\n ",
        b"{\"a\":1}",
        b"{\"a\":[1,2,3],\"b\":{\"c\":null}}",
        b"[[[[[[]]]]]]",
        b"\"\"",
        b"\"\"\"\"",
        b"\"a\"\"b\"",
        b"[1,2,3]",
        b"-1.5e+10",
        b"{\"k\":\"v\"}",
        b"\"\\\"",
        b"\"\\\\\"",
        b"\"a\\\\\"",
        b"\"a\\\"",
    ];
    for case in cases {
        assert_agree(case);
    }
}

#[test]
fn the_predicate_on_a_small_document_is_what_it_looks_like() {
    // {"a":"b"} -- the structural bytes are the two braces, the colon and the
    // four quotes; `a` and `b` are content.
    let input = br#"{"a":"b"}"#;
    let want = [0usize, 1, 3, 4, 5, 7, 8];
    let got = scan_scalar(input);
    assert_eq!(got.structural_positions().collect::<Vec<_>>(), want);
    assert_eq!(got.quote_positions().collect::<Vec<_>>(), [1, 3, 5, 7]);
    assert_eq!(got.structural.count_ones(), want.len());
    assert!(!got.end_in_string);
    assert_eq!(scan(input), got);
    assert_eq!(scan_swar(input), got);
    // On x86_64 this holds the vector path to the same answer as well; on a
    // target without AVX2 there is no fourth implementation to compare.
    // The question is the *feature*, not the architecture: an x86_64 that
    // cannot run the vector path has no answer to compare, and asking it
    // for one failed on a CPU without AVX2 -- the two tests above ask
    // `has_avx2_pclmulqdq()` first, and this one did not.
    #[cfg(target_arch = "x86_64")]
    assert_eq!(avx2_scan(input), has_avx2_pclmulqdq().then(|| got.clone()));
}

#[test]
fn escaped_quote_outside_a_string_is_not_a_delimiter() {
    // `\"` is a backslash then a quote, but not the start of a string: the
    // quote is escaped, so it opens nothing and closes nothing, and the
    // scanner must not report it. This is the one case where "structural =
    // plane AND NOT in_string" would be wrong if the plane carried quotes --
    // the escaped quote is a quote byte that is not inside a string, and it
    // is still not a structural position.
    for input in [
        &b"\\\" "[..],  // \ " space
        &b"\\\"\""[..], // \ " "
        &b"\\\"{}"[..], // \ " { }
        &b"{}\\\""[..], // { } \ " "
    ] {
        assert_agree(input);
    }
    let cases: &[(&[u8], &[usize], &[usize])] = &[
        // (`\`, `"`, ` `): the quote opens nothing, the space is structural.
        (&b"\\\" "[..], &[2], &[]),
        // (`\`, `"`, `"`): the first quote is escaped, the second opens a
        // string, so the only delimiter is the last byte.
        (&b"\\\"\""[..], &[2], &[2]),
        // (`\`, `"`, `{`, `}`): the braces are outside a string.
        (&b"\\\"{}"[..], &[2, 3], &[]),
        // (`{`, `}`, `\`, `"`): the quote is escaped, so the braces are all
        // that is structural and nothing is a delimiter.
        (&b"{}\\\""[..], &[0, 1], &[]),
    ];
    for (input, structural, quote) in cases {
        let got = scan_scalar(input);
        assert_eq!(
            got.structural_positions().collect::<Vec<_>>(),
            structural.to_vec(),
            "structural of {:?}",
            sketch(input),
        );
        assert_eq!(
            got.quote_positions().collect::<Vec<_>>(),
            quote.to_vec(),
            "quotes of {:?}",
            sketch(input),
        );
    }
    // Two backslashes, then a quote: the quote is NOT escaped and does open a
    // string.
    let input = &b"\\\\\""[..];
    assert_agree(input);
    let got = scan_scalar(input);
    assert_eq!(got.quote_positions().collect::<Vec<_>>(), [2]);
    assert!(got.end_in_string);
}

#[test]
fn backslash_run_parity_at_every_length() {
    for run in 0..=17usize {
        let mut input = vec![b'"'];
        input.extend(core::iter::repeat_n(b'\\', run));
        input.push(b'"');
        input.push(b',');
        input.push(b'}');
        assert_agree(&input);
        let got = scan_scalar(&input);
        // An even run leaves the quote unescaped (it closes the string opened
        // at 0); an odd run makes it content and the string stays open.
        let expect_end = run % 2 == 1;
        assert_eq!(got.end_in_string, expect_end, "run of {run}");
        assert_eq!(
            got.quote.count_ones(),
            1 + usize::from(run % 2 == 0),
            "run of {run}"
        );
    }
}

#[test]
fn runs_of_backslashes_alone() {
    for run in 0..=17usize {
        let input: Vec<u8> = core::iter::repeat_n(b'\\', run).collect();
        assert_agree(&input);
        assert!(scan_scalar(&input).structural.is_empty());
    }
    // An odd run of backslashes swallows the quote that follows; an even one
    // does not. With nothing before them the same parity rule applies.
    for run in 0..=17usize {
        let mut input: Vec<u8> = core::iter::repeat_n(b'\\', run).collect();
        input.push(b'"');
        assert_agree(&input);
        assert_eq!(
            scan_scalar(&input).quote.count_ones(),
            usize::from(run % 2 == 0),
            "run of {run}",
        );
    }
}

#[test]
fn unterminated_strings() {
    // Documents that stop in the middle of a string. Written as byte strings
    // so the truncation point is the end of the literal: `{"a":"\""` -- which
    // *is* terminated, and which two of the earlier drafts of this list got
    // wrong -- is hard to read that way, because where the string ends and
    // the document stops is not visible without counting quotes.
    let cases: &[&[u8]] = &[
        b"\"",
        b"{\"a",
        b"{\"a\":\"bc",
        b"{\"a\":\"bc\\",
        b"[\"x",
        b"\"\\",
        b"{\"a\":1,\"b",
        b"\"a\\\"b",
        // An escaped quote that is the last byte: the string is still open.
        b"\"\\\"",
    ];
    for input in cases {
        assert_agree(input);
        assert!(scan_scalar(input).end_in_string, "{}", sketch(input));
    }
    // Documents that stop outside one, including a bare backslash -- whose
    // run is still open at the end but which never opened a string, so the
    // two pieces of carried state disagree and the output has to report
    // only the one that is exposed.
    for input in [
        &b"{"[..],
        &b"\\"[..],
        &b"\\\\\\[\\\\"[..],
        &b""[..],
        &b"{}"[..],
        &b"{\"a\":1,\"b\":"[..],
    ] {
        assert_agree(input);
        assert!(!scan_scalar(input).end_in_string, "{}", sketch(input));
    }
    // And a document that closes everything it opened.
    let input = br#"{"a":"b"}"#;
    assert_agree(input);
    assert!(!scan_scalar(input).end_in_string);
}

#[test]
fn multi_byte_utf8_inside_strings() {
    // "héllo€😀" -- 2-byte, 3-byte and 4-byte sequences, none of which may
    // ever be structural.
    let input = "{\"k\":\"héllo€😀\",\"é\":1}".as_bytes();
    assert_agree(input);
    let got = scan_scalar(input);
    for (i, &b) in input.iter().enumerate() {
        if b >= 0x80 {
            assert!(
                !got.structural.contains(i),
                "byte {i} ({b:#04x}) is structural"
            );
        }
    }
    // Raw (unquoted) UTF-8 outside strings is content too: `€` is 0xE2 0x82
    // 0xAC, and not one of those bytes is in a row any rectangle names.
    let input = "{€:1}".as_bytes();
    assert_agree(input);
    assert_eq!(
        scan_scalar(input)
            .structural_positions()
            .collect::<Vec<_>>(),
        [0, 4, 6]
    );
    // Every byte value 0x80..=0xFF on its own, and in a string.
    for b in 0x80..=0xFFu8 {
        assert_agree(&[b]);
        assert_agree(&[b'"', b, b'"']);
        assert_agree(&[b'"', b'\\', b, b'"']);
    }
}

#[test]
fn braces_inside_strings_are_content() {
    // {"key":"{[}][]:,\"a\""} -- the outer punctuation is structural and
    // everything between the first pair of delimiters -- brackets, colons and
    // commas included -- is content. The `\"` and the `\\"` in the middle do
    // not close anything, so the string runs on to the quote at 21 and the
    // `}` at 22 is outside it again.
    let input = br#"{"key":"{[}][]:,\"a\""}"#.to_vec();
    assert_agree(&input);
    let got = scan_scalar(&input);
    let open = got.quote_positions().collect::<Vec<_>>();
    assert_eq!(
        open,
        [1, 5, 7, 21],
        "four delimiters; the fifth quote is escaped"
    );
    assert_eq!(
        got.structural_positions().collect::<Vec<_>>(),
        [0, 1, 5, 6, 7, 21, 22],
        "only the outer punctuation and the delimiters",
    );
    for i in 8..21 {
        assert!(!got.structural.contains(i), "byte {i} inside the string");
    }
}

#[test]
fn empty_strings_and_runs_of_quotes() {
    for n in 0..=9usize {
        let input: Vec<u8> = core::iter::repeat_n(b'"', n).collect();
        assert_agree(&input);
        let got = scan_scalar(&input);
        // Every quote is a delimiter: they alternate open, close, open, ...
        assert_eq!(got.quote.count_ones(), n);
        assert_eq!(got.end_in_string, n % 2 == 1);
    }
    assert_agree(br#"{"":""}"#);
    assert_agree(br#"{"": "v", "": [""  ,  ""]}"#);
}

#[test]
fn a_long_string_spanning_many_blocks() {
    let mut input = Vec::new();
    input.extend_from_slice(b"{\"key\":\"");
    let body: Vec<u8> = core::iter::repeat_n(b'x', 5000).collect();
    input.extend_from_slice(&body);
    input.extend_from_slice(b"\",\"k2\":[1,2,{\"a\":\"b\"}]}");
    assert_agree(&input);

    let got = scan_scalar(&input);
    assert!(!got.end_in_string);
    // Nothing inside the 5000-byte body is structural, and the two quotes
    // that bracket it are the only structural bytes in that stretch.
    for i in 8..5008 {
        assert!(!got.structural.contains(i), "body byte {i}");
    }
    assert!(got.structural.contains(7));
    assert!(got.structural.contains(5008));

    // A body that is nothing but escaped quotes, long enough that the escape
    // parity and the string state have to survive every block boundary.
    let mut input = Vec::new();
    input.extend_from_slice(b"[");
    for _ in 0..600 {
        input.extend_from_slice(b"\\\"");
    }
    input.extend_from_slice(b"]");
    assert_agree(&input);
    assert!(!scan_scalar(&input).end_in_string);
    assert_eq!(
        scan_scalar(&input)
            .structural_positions()
            .collect::<Vec<_>>(),
        [0, 1201]
    );
}

// ---------------------------------------------------------------------------
// Boundary sweeps
// ---------------------------------------------------------------------------

/// The bytes that carry meaning, plus the ones that share a nibble with them.
const INTERESTING: &[u8] = &[
    b'"', b'\\', b'{', b'}', b'[', b']', b':', b',', b' ', b'\t', b'\n', b'\r', 0x21, 0x2A, 0x23,
    0x7E, 0x80, 0xC3, 0xA9, 0xFF, 0x00, 0x1F, 0x30, 0x40,
];

#[test]
fn structural_bytes_at_every_offset_across_block_boundaries() {
    // 192 bytes: three whole blocks, so offsets 63/64, 127/128 and 191 all
    // land on or beside a boundary, and 15/16 and 31/32 land on the internal
    // halves the AVX2 path folds together.
    for offset in 0..192usize {
        for &b in INTERESTING {
            // Outside a string.
            let mut input = vec![b'x'; 192];
            input[offset] = b;
            assert_agree(&input);

            // Inside a string that is opened at 0 and never closed.
            let mut input = vec![b'x'; 192];
            input[0] = b'"';
            if offset == 0 {
                input[0] = b;
            } else {
                input[offset] = b;
            }
            assert_agree(&input);

            // Immediately after a closing quote, so the state entering offset
            // is known-inside and the byte under test is a candidate
            // delimiter.
            let mut input = vec![b'x'; 192];
            if offset >= 1 {
                input[offset - 1] = b'"';
                input[0] = b'"';
            }
            input[offset] = b;
            assert_agree(&input);
        }
    }
}

#[test]
fn backslash_runs_at_every_offset_across_block_boundaries() {
    for offset in 0..192usize {
        for run in 0..=5usize {
            if offset + run >= 190 {
                continue;
            }
            let mut input = vec![b'x'; 192];
            for slot in input.iter_mut().skip(offset).take(run) {
                *slot = b'\\';
            }
            input[offset + run] = b'"';
            assert_agree(&input);

            // The same run inside a string, where the escaped quote is
            // content rather than a stray delimiter.
            let mut input = vec![b'x'; 192];
            input[0] = b'"';
            for slot in input.iter_mut().skip(offset).take(run) {
                *slot = b'\\';
            }
            if offset + run == 0 {
                continue;
            }
            input[offset + run] = b'"';
            input[191] = b'"';
            assert_agree(&input);
        }
    }
}

#[test]
fn quote_pairs_at_every_offset_across_block_boundaries() {
    for offset in 0..190usize {
        let mut input = vec![b'x'; 192];
        input[offset] = b'"';
        input[offset + 1] = b'"';
        assert_agree(&input);

        // An odd number of backslashes in front makes the pair inert.
        let mut input = vec![b'x'; 192];
        for slot in input.iter_mut().skip(offset.saturating_sub(3)).take(3) {
            *slot = b'\\';
        }
        input[offset] = b'"';
        assert_agree(&input);
    }
}

#[test]
fn lengths_around_the_block_size() {
    for len in [0usize, 1, 2, 63, 64, 65, 127, 128, 129, 191, 192, 193] {
        for pattern in [
            &b"{"[..],
            &b"\""[..],
            &b"\\"[..],
            &b"\"a\\\\\""[..],
            &b"{\"a\":\"b\\\"c\"}"[..],
        ] {
            let input: Vec<u8> = core::iter::repeat_n(pattern, len.div_ceil(pattern.len()) + 1)
                .flatten()
                .copied()
                .take(len)
                .collect();
            assert_agree(&input);
            let got = scan_scalar(&input);
            assert_eq!(got.len, len);
            assert_eq!(got.structural.len(), len);
            assert_eq!(got.quote.len(), len);
            // Bits past the end are never set.
            for i in len..len + 64 {
                assert!(!got.structural.contains(i));
                assert!(!got.quote.contains(i));
            }
            assert!(got.structural.words().len() >= len.div_ceil(64));
        }
    }
}

#[test]
fn a_utf8_sequence_split_across_a_block_boundary() {
    let mut input = vec![b'"'; 61];
    input.extend_from_slice("é€".as_bytes());
    input.push(b'"');
    input.push(b',');
    input.push(b'}');
    assert_agree(&input);
    // The two multi-byte sequences straddle bytes 63/64; nothing about them
    // may be structural.
    let got = scan_scalar(&input);
    for i in 61..66 {
        assert!(!got.structural.contains(i), "byte {i}");
    }
    assert_eq!(
        got.quote_positions().collect::<Vec<_>>(),
        (0..=60).chain(core::iter::once(66)).collect::<Vec<_>>(),
    );
    assert!(!got.end_in_string);
}

// ---------------------------------------------------------------------------
// The whole byte range, and random input
// ---------------------------------------------------------------------------

#[test]
fn every_byte_value_in_itself_and_in_context() {
    assert_agree(&(0..=255u8).collect::<Vec<u8>>());
    for b in 0..=255u8 {
        assert_agree(&[b]);
        assert_agree(&[b, b]);
        assert_agree(&[b'"', b, b'"']);
        assert_agree(&[b'"', b'\\', b, b'"']);
        assert_agree(&[b'"', b'\\', b'\\', b, b'"']);
        assert_agree(&[b'{', b, b':', b, b',', b, b'}']);
        assert_agree(&[b'"', b'\\', b'\\', b'\\', b, b'"', b'"']);
    }
}

#[test]
fn random_bytes_of_every_length() {
    let mut rng = Rng::new(0x0A11_CE0F_1CE5_EED0);
    for len in 0..200usize {
        let input: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        assert_agree(&input);
    }
    // Longer than one block, so the carry is exercised repeatedly.
    for _ in 0..300 {
        let len = 200 + rng.below(2000);
        let input: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        assert_agree(&input);
    }
}

#[test]
fn random_input_from_the_meaningful_alphabet() {
    let mut rng = Rng::new(0x00B0_A75E_ED5E_ED02);
    for _ in 0..3000 {
        let len = rng.below(200);
        let input: Vec<u8> = (0..len)
            .map(|_| INTERESTING[rng.below(INTERESTING.len())])
            .collect();
        assert_agree(&input);
    }
}

#[test]
fn random_json_soup() {
    // Tokens chosen so that escapes, quotes and punctuation are adjacent far
    // more often than a grammar would ever put them -- which is exactly the
    // distribution that makes the escape parity observable.
    const TOKENS: &[&str] = &[
        "{",
        "}",
        "[",
        "]",
        ",",
        ":",
        " ",
        "\t",
        "\n",
        "\r",
        "\"",
        "\\",
        "\\\"",
        "\\\\",
        "a",
        "1",
        "true",
        "null",
        "é",
        "€",
        "😀",
        "\"a\\\"b\"",
        "\"\\\\\\\\\"",
        "0.5e-1",
    ];
    let mut rng = Rng::new(0xC0FF_EE5E_ED5E_ED03);
    for _ in 0..3000 {
        let mut input = Vec::new();
        for _ in 0..rng.below(40) {
            input.extend_from_slice(TOKENS[rng.below(TOKENS.len())].as_bytes());
        }
        assert_agree(&input);
    }
}

#[test]
fn random_escape_heavy_input() {
    // Every run length, at every offset, in a random string body.
    let mut rng = Rng::new(0x00D0_0D5E_ED5E_ED04);
    for _ in 0..2000 {
        let mut input = vec![b'"'];
        while input.len() < 300 {
            match rng.below(4) {
                0 => {
                    let run = 1 + rng.below(6);
                    input.extend(core::iter::repeat_n(b'\\', run));
                }
                1 => input.push(b'"'),
                2 => input.push(rng.byte()),
                _ => input.extend_from_slice("é€😀".as_bytes()),
            }
        }
        assert_agree(&input);
    }
}

// ---------------------------------------------------------------------------
// Dispatch and the output type
// ---------------------------------------------------------------------------

#[test]
fn dispatch_is_the_vector_path_when_the_cpu_has_it() {
    let input = br#"{"a":[1,2,{"b":"c\\"}],"d":{}}"#;
    if let Some(avx2) = avx2_scan(input) {
        assert_eq!(scan(input), avx2, "scan() did not take the vector path");
    }
    // And when it does not, it is still right.
    assert_eq!(scan(input), oracle(input));
}

#[test]
fn bitset_basics() {
    let empty = BitSet::with_len(0);
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.count_ones(), 0);
    assert!(!empty.contains(0));
    assert_eq!(empty.words().len(), 0);

    let mut set = BitSet::with_len(200);
    for i in [0usize, 1, 63, 64, 65, 127, 128, 199] {
        set.set(i);
    }
    assert!(!set.is_empty());
    assert_eq!(set.len(), 200);
    assert_eq!(set.words().len(), 4);
    assert_eq!(set.count_ones(), 8);
    assert_eq!(
        set.iter_set().collect::<Vec<_>>(),
        [0, 1, 63, 64, 65, 127, 128, 199],
    );
    for i in 0..200usize {
        assert_eq!(
            set.contains(i),
            [0, 1, 63, 64, 65, 127, 128, 199].contains(&i)
        );
    }
    assert!(!set.contains(200));
    assert!(!set.contains(usize::MAX));
}

#[test]
fn an_empty_input_produces_empty_output() {
    for got in [scan_scalar(b""), scan_swar(b""), scan(b"")] {
        assert_eq!(got.len, 0);
        assert!(got.structural.is_empty());
        assert!(got.quote.is_empty());
        assert!(!got.end_in_string);
        assert_eq!(got.structural_positions().count(), 0);
    }
}

#[test]
fn the_scan_agrees_with_itself_across_repetition() {
    // Cheap, but it catches a `Builder` that leaks state between calls --
    // e.g. a `static` carry, or a `words` buffer that is not re-zeroed.
    let input = br#"{"a":"b\\c"}"#;
    let first = scan(input);
    for _ in 0..100 {
        assert_eq!(scan(input), first);
        assert_eq!(scan_scalar(input), first);
    }
    // A longer input after a short one, and the reverse.
    let long = vec![b'"'; 300];
    let _ = scan(&long);
    assert_eq!(scan(input), first);
    let _ = scan(input);
    assert_eq!(scan(&long), scan_scalar(&long));
}

/// Throughput of the three paths, in MB/s. Not an assertion -- it is here so
/// that the numbers this module is judged on can be reproduced instead of
/// quoted, and `#[ignore]`d so that a test run is not a benchmark run.
///
/// ```text
/// cargo test --release --lib json_scan --features std \
///     -- --ignored --nocapture --test-threads=1
/// ```
#[cfg(feature = "std")]
#[test]
#[ignore = "a measurement, not a check"]
fn throughput_probe() {
    /// How long to spend on each path.
    const SECONDS: f64 = 0.5;
    const CAP: usize = 4 << 20;

    // A document with the shape real JSON has: mostly string content, one
    // structural byte every eight or so.
    let mut input = Vec::with_capacity(CAP);
    let mut rng = Rng::new(0x007E_375E_ED5E_ED05);
    while input.len() < CAP - 64 {
        match rng.below(8) {
            0 => input.push(b'{'),
            1 => input.push(b'"'),
            2 => input.extend_from_slice(b"key"),
            3 => input.push(b':'),
            4 => input.push(b','),
            _ => input.extend_from_slice(b"value"),
        }
    }
    let mb = input.len() as f64 / (1024.0 * 1024.0);

    let measure = |name: &str, f: &dyn Fn(&[u8]) -> usize| {
        let mut rounds = 0u64;
        let mut sink = 0usize;
        let start = std::time::Instant::now();
        while start.elapsed().as_secs_f64() < SECONDS {
            for _ in 0..8 {
                sink = sink.wrapping_add(f(&input));
            }
            rounds += 8;
        }
        let secs = start.elapsed().as_secs_f64();
        let mbps = mb * rounds as f64 / secs;
        std::println!("{name:>12}: {mbps:8.1} MB/s  (sink {sink})");
    };

    measure("scan", &|b| scan(b).structural.count_ones());
    measure("scan_scalar", &|b| scan_scalar(b).structural.count_ones());
    measure("scan_swar", &|b| scan_swar(b).structural.count_ones());
    // The AVX2 path exists only on x86_64, so on any other target there is a
    // fourth line missing from this measurement rather than a fourth path.
    #[cfg(target_arch = "x86_64")]
    if has_avx2_pclmulqdq() {
        // SAFETY: both features were just detected, which is the
        // precondition of `scan_avx2`.
        measure("scan_avx2", &|b| unsafe {
            avx2::scan_avx2(b).structural.count_ones()
        });
    }
}
