// SPDX-License-Identifier: Apache-2.0

//! Correctly-rounded decimal-to-`f64`, without `std`.
//!
//! `f64::from_str` is std-only and `powi` with it, so a `no_std` build has no
//! correctly-rounded way to scale a mantissa by a power of ten. The
//! workaround used before here was repeated squaring, which is correct to
//! about a ULP for ordinary input and visibly wrong at the extremes:
//! `10^309` is not representable, so `1e308` came out as
//! 10000000000000006e290.
//!
//! This does it exactly instead. A decimal is a rational, `mant / 10^k`
//! for integer `mant` and `k`, so both sides are computed as integers and
//! rounded once, at the end. That is the only place a rounding decision can
//! be made, and it is the same decision the correctly-rounded parsers make.
//!
//! Limbs are little-endian base-2^32; the sizes here are small enough that
//! schoolbook algorithms are the right ones. A numerator is at most
//! `mant << SHIFT` bits and a denominator at most `10^400`, so nothing is
//! ever more than about 44 limbs.
//!
//! The fast path is Clinger's: when the mantissa is exact in `f64` and
//! `10^k` is too — `k <= 22`, which is where `10^22 = 5^22 * 2^22` still
//! fits 53 bits — one multiply or divide is already correctly rounded, and
//! almost every real JSON number takes it.

use alloc::vec::Vec;

/// Guard bits carried into the quotient before it is rounded.
///
/// The result's own binary exponent can be as low as -1074, so the quotient
/// needs at least `53 + 1074` bits before the bits that decide the rounding
/// are meaningful. 1200 leaves margin without cost: the bignum is a fixed
/// handful of limbs either way.
const SHIFT: usize = 1200;

/// Exponents past this cannot produce a finite `f64`, in either direction,
/// so they are clamped rather than carried into a hundred-limb denominator.
const MAX_SCALE: i32 = 400;

// --- bignum primitives, little-endian base-2^32 -----------------------------

fn trim(v: &mut Vec<u32>) {
    while v.len() > 1 && *v.last().unwrap() == 0 {
        v.pop();
    }
    if v.is_empty() {
        v.push(0);
    }
}

fn bit_len(v: &[u32]) -> usize {
    for (i, limb) in v.iter().enumerate().rev() {
        if *limb != 0 {
            return i * 32 + (32 - limb.leading_zeros() as usize);
        }
    }
    0
}

fn from_u128(mut v: u128) -> Vec<u32> {
    let mut out = Vec::with_capacity(4);
    while v > 0 {
        out.push((v & 0xFFFF_FFFF) as u32);
        v >>= 32;
    }
    if out.is_empty() {
        out.push(0);
    }
    out
}

/// `a * m`, with `m` a single limb. Returns a fresh vector.
fn mul_small(a: &[u32], m: u32) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len() + 1);
    let mut carry: u64 = 0;
    for limb in a {
        let p = *limb as u64 * m as u64 + carry;
        out.push((p & 0xFFFF_FFFF) as u32);
        carry = p >> 32;
    }
    if carry != 0 {
        out.push(carry as u32);
    }
    out
}

fn mul(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = vec![0u32; a.len() + b.len()];
    for (i, &ai) in a.iter().enumerate() {
        if ai == 0 {
            continue;
        }
        let mut carry: u64 = 0;
        for (j, &bj) in b.iter().enumerate() {
            let p = out[i + j] as u64 + ai as u64 * bj as u64 + carry;
            out[i + j] = (p & 0xFFFF_FFFF) as u32;
            carry = p >> 32;
        }
        let mut k = i + b.len();
        while carry != 0 {
            let p = out[k] as u64 + carry;
            out[k] = (p & 0xFFFF_FFFF) as u32;
            carry = p >> 32;
            k += 1;
        }
    }
    trim(&mut out);
    out
}

/// `a << bits`.
fn shl(a: &[u32], bits: usize) -> Vec<u32> {
    let limbs = bits / 32;
    let rem = bits % 32;
    let mut out = vec![0u32; limbs];
    if rem == 0 {
        out.extend_from_slice(a);
    } else {
        let mut carry = 0u32;
        for &limb in a {
            out.push((limb << rem) | carry);
            carry = limb >> (32 - rem);
        }
        if carry != 0 {
            out.push(carry);
        }
    }
    trim(&mut out);
    out
}

/// `10^k`, exact, for `k <= MAX_SCALE`.
fn pow10(k: u32) -> Vec<u32> {
    let mut v = vec![1u32];
    for _ in 0..k {
        v = mul_small(&v, 10);
    }
    v
}

fn cmp(a: &[u32], b: &[u32]) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    let la = {
        let mut n = a.len();
        while n > 0 && a[n - 1] == 0 {
            n -= 1;
        }
        n
    };
    let lb = {
        let mut n = b.len();
        while n > 0 && b[n - 1] == 0 {
            n -= 1;
        }
        n
    };
    if la != lb {
        return la.cmp(&lb);
    }
    for i in (0..la).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    Ordering::Equal
}

/// `a - b`, assuming `a >= b`.
fn sub_in_place(a: &mut Vec<u32>, b: &[u32]) {
    let mut borrow: i64 = 0;
    for i in 0..a.len() {
        let bi = if i < b.len() { b[i] as i64 } else { 0 };
        let d = a[i] as i64 - bi - borrow;
        if d < 0 {
            a[i] = (d + (1i64 << 32)) as u32;
            borrow = 1;
        } else {
            a[i] = d as u32;
            borrow = 0;
        }
    }
    trim(a);
}

/// `rem = rem * 2^32 + limb`, keeping `rem < d` so it never grows unbounded.
fn shl32_add(rem: &mut Vec<u32>, limb: u32) {
    // rem = rem * 2^32 + limb, so the incoming digit lands at the BOTTOM.
    // The caller reduces it afterwards, once the digit is known; reducing it
    // here instead would corrupt the very value the search reads.
    rem.insert(0, limb);
}

/// Long division, digit at a time, each digit found by binary search.
///
/// `divisor` here is a power of ten, so the quotient is at most one limb
/// longer than `rem` could suggest and this is comfortably fast for the
/// 44-limb sizes above. The binary search is 32 steps of a limb multiply;
/// Knuth's algorithm would be quicker and is not worth the correctness risk
/// for a parser that sees a handful of floats per document.
fn divmod(dividend: &[u32], divisor: &[u32]) -> (Vec<u32>, Vec<u32>) {
    let mut quotient = vec![0u32; dividend.len()];
    let mut rem: Vec<u32> = vec![0];
    for i in (0..dividend.len()).rev() {
        shl32_add(&mut rem, dividend[i]);
        let (mut lo, mut hi): (u64, u64) = (0, 0xFFFF_FFFF);
        // Invariant: lo*b <= rem < (hi+1)*b. Start hi at the max digit.
        let mut trial = Vec::with_capacity(divisor.len() + 1);
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            trial.clear();
            trial.extend_from_slice(&mul_small(divisor, mid as u32));
            if cmp(&trial, &rem) != core::cmp::Ordering::Greater {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        quotient[i] = lo as u32;
        sub_in_place(&mut rem, &mul_small(divisor, lo as u32));
    }
    trim(&mut quotient);
    trim(&mut rem);
    (quotient, rem)
}

// --- rounding ---------------------------------------------------------------

/// Round `value = n * 2^shift` to the nearest `f64`, ties to even.
///
/// `sticky` says whether bits below `n` were dropped and were nonzero. The
/// whole point of carrying an exact integer here is that this is the only
/// rounding the result ever sees.
fn round_to_f64(n: &[u32], shift: i32, sticky: bool) -> f64 {
    let bits = bit_len(n);
    if bits == 0 {
        return 0.0;
    }
    // Exponent of the leading bit, in the value's own terms.
    let exp = bits as i64 - 1 + shift as i64;
    if exp > 1023 {
        return f64::INFINITY;
    }

    // How many bits of significand survive. A normal number keeps 53. Below
    // 2^-1022 the leading bits stop counting -- they are the implicit bit
    // that a subnormal does not have -- so the budget shrinks with the
    // exponent: `room` is where the leading bit sits above 2^-1074, and the
    // bit itself is part of the budget, hence the +1.
    let subnormal = exp < -1022;

    let keep: usize = if subnormal {
        // A subnormal's grid is 2^-1074 and its fraction field is 52 bits,
        // so the budget runs from "the whole value is below the grid" (0) to
        // "52 bits above the grid". It must be allowed to reach zero: a value
        // under half of 2^-1074 rounds to zero, and forcing one kept bit here
        // turned 1e-324 into the smallest subnormal.
        (exp + 1075).clamp(0, 52) as usize
    } else {
        53
    };

    // With nothing kept the value is below the subnormal grid, and the
    // rounding question is not "half an ULP" but "is it at least half of the
    // smallest subnormal". The leading bit sits exactly there when
    // exp + 1074 == -1; below that the answer is zero regardless, and at
    // exactly half with nothing underneath it is a tie, which goes to zero
    // because zero is even. Without this the general path read the leading
    // bit as a half-ULP marker and rounded 1e-324 up to 5e-324.
    if keep == 0 {
        let up = exp + 1074 == -1 && (any_below(n, bits - 1) || sticky);
        return f64::from_bits(up as u64);
    }

    let drop = bits.saturating_sub(keep);
    let mut m = top_bits(n, bits, keep);

    if drop > 0 {
        // Round to nearest, ties to even, using the bit below the kept ones
        // and whether anything at all lives under it.
        let half = bit_at(n, drop - 1);
        let low_set = any_below(n, drop - 1) || sticky;
        if half && (low_set || (m & 1 == 1)) {
            m += 1;
        }
    }

    if subnormal {
        // `m` is already the fraction field: it counts units of 2^-1074.
        // A carry out to 2^52 needs no special case -- that encoding IS the
        // smallest normal.
        return f64::from_bits(m);
    }

    if m >= (1u64 << 53) {
        // Rounding 1.111... up carried into the next binade.
        m >>= 1;
        if exp + 1 > 1023 {
            return f64::INFINITY;
        }
        return f64::from_bits((((exp + 1 + 1023) as u64) << 52) | (m & 0x000F_FFFF_FFFF_FFFF));
    }
    f64::from_bits((((exp + 1023) as u64) << 52) | (m & 0x000F_FFFF_FFFF_FFFF))
}

/// The `keep` most significant bits of a `bits`-bit integer, as a u64.
fn top_bits(n: &[u32], bits: usize, keep: usize) -> u64 {
    let mut m = 0u64;
    for i in (bits - keep..bits).rev() {
        m = (m << 1) | bit_at(n, i) as u64;
    }
    m
}

/// Bit `i`, counting from the least significant.
fn bit_at(n: &[u32], i: usize) -> bool {
    let limb = n.get(i / 32).copied().unwrap_or(0);
    (limb >> (i % 32)) & 1 == 1
}

/// Whether any bit strictly below index `below` is set.
fn any_below(n: &[u32], below: usize) -> bool {
    let full = below / 32;
    if n[..full.min(n.len())].iter().any(|l| *l != 0) {
        return true;
    }
    let rem = below % 32;
    rem > 0 && full < n.len() && n[full] & ((1u32 << rem) - 1) != 0
}

/// The digits of a decimal number, as they are read.
///
/// A `u64` holds 19 decimal digits and a `u128` holds 39, so the number a
/// JSON document usually carries never leaves the narrow accumulator. The
/// overflow check is a *counter*: the 128-bit division per digit that this
/// replaced was the parser's whole cost, and the parser is on the path of
/// every number in the document.
///
/// Past what the accumulator holds, a digit is refused: the caller drops it
/// and the scale absorbs it.
pub(crate) struct Mantissa {
    /// The digits, while there are fewer than 19 of them.
    narrow: u64,
    /// The digits, once there are 19 or more.
    wide: u128,
    /// How many digits the accumulator holds.
    digits: u32,
    /// Whether a refused digit was nonzero. The truncated mantissa alone
    /// cannot tell a value that lands exactly on a rounding tie from one
    /// that is past it: a 39-digit midpoint with `+1` truncated back onto
    /// the tie rounded to even, where the standard parser rounds up.
    dropped_nonzero: bool,
}

impl Mantissa {
    /// An empty accumulator.
    pub(crate) fn new() -> Self {
        Self {
            narrow: 0,
            wide: 0,
            digits: 0,
            dropped_nonzero: false,
        }
    }

    /// Add one digit. `false` means the digit did not fit.
    pub(crate) fn push(&mut self, d: u8) -> bool {
        if self.digits < 19 {
            // 19 digits fit in a `u64` exactly: 10^19 - 1 < u64::MAX.
            self.narrow = self.narrow * 10 + u64::from(d);
            self.digits += 1;
            true
        } else if self.digits == 19 {
            // The 20th digit moves the accumulator to the wide one.
            self.wide = u128::from(self.narrow) * 10 + u128::from(d);
            self.digits += 1;
            true
        } else if self.digits < 38 {
            // 38 digits fit in a `u128` exactly: 10^38 - 1 < u128::MAX.
            self.wide = self.wide * 10 + u128::from(d);
            self.digits += 1;
            true
        } else if self.wide <= (u128::MAX - u128::from(d)) / 10 {
            self.wide = self.wide * 10 + u128::from(d);
            self.digits += 1;
            true
        } else {
            if d != 0 {
                self.dropped_nonzero = true;
            }
            false
        }
    }

    /// The digits, as the integer they spell.
    pub(crate) fn value(&self) -> u128 {
        if self.digits <= 19 {
            u128::from(self.narrow)
        } else {
            self.wide
        }
    }

    /// Whether any refused digit was nonzero — the value is strictly
    /// greater than the one [`Mantissa::value`] spells.
    pub(crate) fn dropped_nonzero(&self) -> bool {
        self.dropped_nonzero
    }
}

/// `mant * 10^scale`, correctly rounded.
///
/// `sticky` says the true value is strictly greater than `mant * 10^scale`
/// by something under the last digit's place — digits the mantissa refused.
/// It only matters at an exact tie, and there it is the difference between
/// rounding to even and rounding up.
pub fn scale_decimal(mant: u128, scale: i32, sticky: bool) -> f64 {
    let scale = scale.clamp(-MAX_SCALE, MAX_SCALE);

    // Clinger's fast path: both operands exact in f64 means the single
    // operation rounds once, which is all a correctly-rounded result needs.
    if mant != 0 && mant <= (1u128 << 53) && scale.unsigned_abs() <= 22 {
        let m = mant as f64;
        return if scale >= 0 {
            m * exact_pow10(scale as u32)
        } else {
            m / exact_pow10((-scale) as u32)
        };
    }

    let base = from_u128(mant);
    if scale >= 0 {
        round_to_f64(&mul(&base, &pow10(scale as u32)), 0, sticky)
    } else {
        let k = (-scale) as u32;
        let (q, r) = divmod(&shl(&base, SHIFT), &pow10(k));
        round_to_f64(&q, -(SHIFT as i32), r != [0] || sticky)
    }
}

/// `10^n` for `n <= 22`, which is exact in `f64`.
fn exact_pow10(n: u32) -> f64 {
    const T: [f64; 23] = [
        1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11, 1e12, 1e13, 1e14, 1e15, 1e16,
        1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
    ];
    T[n as usize]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc::string::{String, ToString};
    use std::println;

    #[test]
    fn pow10_is_exact_to_22() {
        for n in 0..=22u32 {
            // 10^n is exact in f64 iff 10^n == (10^n as integer) exactly;
            // check by dividing back and comparing with the integer value.
            let v = exact_pow10(n);
            let mut expect = 1u128;
            for _ in 0..n {
                expect *= 10;
            }
            assert_eq!(v, expect as f64, "10^{n} must be exact");
        }
    }

    #[test]
    fn bignum_multiply_agrees_with_u128() {
        for a in [0u128, 1, 7, u64::MAX as u128] {
            for b in [1u128, 3, 10, 1_000_000_007] {
                let got = mul(&from_u128(a), &from_u128(b));
                let mut expect: Vec<u32> = Vec::new();
                let mut v = a * b;
                while v > 0 {
                    expect.push((v & 0xFFFF_FFFF) as u32);
                    v >>= 32;
                }
                if expect.is_empty() {
                    expect.push(0);
                }
                assert_eq!(got, expect, "{a} * {b}");
            }
        }
    }

    #[test]
    fn division_is_exact_on_whole_quotients() {
        for (a, b) in [(10u128, 5u128), (1000, 8), (7, 7), (1, 3)] {
            let (q, r) = divmod(&from_u128(a), &from_u128(b));
            let qt = q.iter().fold(0u128, |acc, l| (acc << 32) | *l as u128);
            let rt = r.iter().fold(0u128, |acc, l| (acc << 32) | *l as u128);
            assert_eq!(qt * b + rt, a, "{a} / {b}");
            assert!(rt < b, "remainder must be below the divisor");
        }
    }

    #[test]
    fn scaling_matches_the_standard_parser() {
        // Values chosen to cross the fast path, the subnormal edge, and the
        // point where 10^k stops being exactly representable.
        let cases = [
            "1",
            "0",
            "-0",
            "3.14159",
            "1e23",
            "1e22",
            "1e-22",
            "1e-23",
            "1.5e300",
            "1e-300",
            "2.2250738585072014e-308",
            "5e-324",
            "9.999999999999999e22",
            "1.7976931348623157e308",
            "4.9e-324",
        ];
        for s in cases {
            let want: f64 = s.parse().expect("std parses");
            // Reuse the crate's parser via the public entry point.
            let got = crate::parse_decimal(s).unwrap();
            assert_eq!(got.to_bits(), want.to_bits(), "{s}");
        }
    }

    #[test]
    fn extremes_are_finite_and_right() {
        assert_eq!(scale_decimal(1, 308, false), 1e308);
        assert!(scale_decimal(1, 309, false).is_infinite());
        assert_eq!(scale_decimal(1, -324, false), 0.0);
        assert_eq!(scale_decimal(5, -324, false), 5e-324);
    }

    /// A 40-digit tie that truncation lands back on must still round up.
    ///
    /// The accumulator holds every number of 39 digits or fewer; refusal
    /// begins at the 40th digit. A midpoint whose last two decimal digits
    /// are `00` puts `midpoint + 1` one digit past the cut, and the
    /// truncated mantissa spells the midpoint itself. Without the sticky
    /// flag that tie rounded to even — down — where the standard parser,
    /// which sees the `+1`, rounds up.
    #[test]
    fn a_truncated_tie_rounds_up_when_the_dropped_digit_is_nonzero() {
        // A 40-digit midpoint cannot be built in a u128, so its decimal
        // form is doubled out one bit at a time. An odd 54-bit significand
        // on 2^77 is a midpoint in the 2^130 binade, and the first such
        // significand divisible by 25 puts two zeros at the end of it.
        let mut odd = (1u128 << 53) + 1;
        while !odd.is_multiple_of(25) {
            odd += 2;
        }
        let mut p = odd.to_string();
        for _ in 0..77 {
            p = double_the_digits(&p);
        }
        assert_eq!(p.len(), 40, "a 40-digit midpoint, got {p}");
        assert!(p.ends_with("00"), "the truncation drops onto the tie: {p}");

        let want: f64 = p.parse().unwrap();
        assert_eq!(
            crate::parse_decimal(&p).unwrap().to_bits(),
            want.to_bits(),
            "the tie itself still rounds to even"
        );

        let up = plus_one_digit(&p);
        let want: f64 = up.parse().unwrap();
        assert_eq!(
            crate::parse_decimal(&up).unwrap().to_bits(),
            want.to_bits(),
            "the dropped `01` is strictly past the tie: {up}"
        );
    }

    /// A decimal string doubled, by school arithmetic.
    fn double_the_digits(s: &str) -> String {
        let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
        let mut carry = 0u8;
        for d in digits.iter_mut().rev() {
            let v = *d * 2 + carry;
            *d = v % 10;
            carry = v / 10;
        }
        let mut out = String::new();
        if carry > 0 {
            out.push((b'0' + carry) as char);
        }
        out.extend(digits.iter().map(|d| (b'0' + d) as char));
        out
    }

    /// A decimal string plus one. The midpoint ends in `00`, so the carry
    /// never runs off the front.
    fn plus_one_digit(s: &str) -> String {
        let mut digits: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
        let mut i = digits.len();
        loop {
            i -= 1;
            if digits[i] < 9 {
                digits[i] += 1;
                break;
            }
            digits[i] = 0;
        }
        digits.iter().map(|d| (b'0' + d) as char).collect()
    }
    #[test]
    fn dbg_below_grid() {
        let base = from_u128(1);
        let num = shl(&base, SHIFT);
        let den = pow10(324);
        let (q, r) = divmod(&num, &den);
        println!(
            "q limbs {} bitlen {} r_nonzero {}",
            q.len(),
            bit_len(&q),
            r != [0]
        );
        let bits = bit_len(&q);
        let exp = bits as i64 - 1 - SHIFT as i64;
        println!("bits={bits} exp={exp} keep={}", (exp + 1075).clamp(0, 52));
        println!("value = {:?}", round_to_f64(&q, -(SHIFT as i32), r != [0]));
        println!("std 1e-324 = {:?}", "1e-324".parse::<f64>().unwrap());
    }

    /// A wide sweep against the standard library's parser.
    ///
    /// The fixed case list above is where the design was argued out; this is
    /// where it is held. Values are generated across the whole exponent
    /// range and both signs, and every one must come back bit-identical --
    /// this parser's only contract is that it agrees with `f64::from_str`.
    #[test]
    fn agrees_with_std_over_a_wide_sweep() {
        // A xorshift so the corpus is fixed and this stays a normal test.
        let mut state: u64 = 0x243F_6A88_85A3_08D3;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        let mut checked = 0u64;
        for _ in 0..6_000 {
            let digits = 1 + (next() % 25) as usize;
            // First digit nonzero: a leading zero is not a JSON number, and
            // neither parser should be asked about one here.
            let mut mant: u128 = u128::from(1 + (next() % 9) as u8);
            for _ in 1..digits {
                mant = mant * 10 + u128::from((next() % 10) as u8);
            }
            // `exp` already carries its own sign.
            let mut exp = (next() % 640) as i64 - 320;
            if next() % 2 == 0 {
                exp = -exp;
            }
            let text = format!("{mant}e{exp}");
            let want: f64 = text.parse().expect("std parses what we generate");
            let got = crate::parse_decimal(&text).unwrap_or_else(|_| panic!("rejected {text}"));
            assert_eq!(
                got.to_bits(),
                want.to_bits(),
                "{text}: no_std {got:?} vs std {want:?}"
            );
            checked += 1;

            let neg = format!("-{text}");
            let want: f64 = neg.parse().expect("std parses");
            let got = crate::parse_decimal(&neg).unwrap();
            assert_eq!(got.to_bits(), want.to_bits(), "{neg}");
            checked += 1;
        }

        // Fractions, where the scale is implied rather than written.
        for _ in 0..3_000 {
            let digits = 1 + (next() % 25) as usize;
            let mut mant: u128 = u128::from(1 + (next() % 9) as u8);
            for _ in 1..digits {
                mant = mant * 10 + u128::from((next() % 10) as u8);
            }
            let frac = 1 + (next() % 25) as usize;
            let mut pow = 1u128;
            for _ in 0..frac {
                pow *= 10;
            }
            let text = format!("{}.{}", mant, pow);
            let want: f64 = text.parse().expect("std parses");
            let got = crate::parse_decimal(&text).unwrap();
            assert_eq!(got.to_bits(), want.to_bits(), "{text}");
            checked += 1;
        }
        assert!(
            checked >= 15_000,
            "the sweep should be large, got {checked}"
        );
    }
}
