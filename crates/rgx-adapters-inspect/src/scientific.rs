// SPDX-License-Identifier: Apache-2.0

//! Scientific and geophysical binary containers: WMO FM 92-GRIB editions 1
//! and 2, WMO FM 94-BUFR message headers, SEG-Y seismic, CERN ROOT, and the
//! N5/N5Z HDF5 container.
//!
//! What each adapter is built from, and what it deliberately is not:
//!
//! * **GRIB** — section octet layouts, product template 4.0, data
//!   representation templates 5.0/5.2/5.3/5.4 and the
//!   discipline/category/parameter names come from the NCEP GRIB2
//!   documentation and the ECMWF codes GRIB1 section tables (URLs in the
//!   commit message). Values are decoded for edition 2 template 5.0 (simple
//!   packing), 5.2 and 5.3 (complex packing, with and without the spatial
//!   differencing) and 5.4 (IEEE), and for edition 1's simple packing, where
//!   the packed integers are the field scaled by the section's own binary
//!   scale factor. Edition 1 sections
//!   carry no section-number octet, so its product and binary data
//!   sections are found by the fixed order the standard mandates.
//!   The spherical-harmonic fields are decoded too, in both editions: the
//!   coefficients of the spectrum in the order of code table 3.7, with the
//!   Laplacian scale of the wave number -- edition 2's templates 5.50 and
//!   5.51, and edition 1's complex spectral packing.
//!   Edition 1's second-order packing and its reduced grids are
//!   refused by name: reading them needs the group structure, which this
//!   reader does not establish.
//! * **BUFR** — the 8-octet section 0 (indicator, length, edition) and the
//!   `7777` terminator are reported. The Table B / Table D mnemonics are *not*
//   resolved: they live in the WMO master tables, which are a separate data
//!   file that rgx does not ship, and the bit-level section 4/5 stream is not
//!   decoded. A BUFR file therefore gains its edition, size and end marker,
//!   and nothing that would have to be invented.
//! * **SEG-Y** — binary file header, sample-format codes, trace sorting codes
//!   and the 240-byte trace headers come from the SEG-Y revision 2 tables.
//!   The 3200-byte textual header is IBM EBCDIC CP037, which is the bug this
//!   format is famous for; `a_segy_text_header_is_ebcdic_not_ascii` pins it.
//! * **ROOT** — the `root` key and `fVersion`. Streamer/record information is
//!   not decoded: reading it needs the key record layout, which was not
//!   verified against the ROOT file format specification here.
//! * **N5 / N5Z** — the HDF5 file signature and superblock header. The group
//!   payload is not decoded and N5 is not told apart from N5Z, because the two
//!   differ in chunk filters rather than in the container header.
//!
//! **Zarr's metadata is plain text** (`.zarr`, `.zmetadata`, `.zarray`,
//! `.zattrs` are JSON) and ripgrep already reads it; an adapter here would
//! be a subset of ripgrep, so there is none. The array's *data* is not
//! text: it is in binary chunks, zlib- or blosc-compressed, and reading
//! those means walking the array's directory rather than one file -- a
//! different job, and not this module's.
//!
//! Every offset below goes through `be_uint`/`data.get(..)`. A truncated or
//! hostile file must degrade to a partial report, never to a panic.

use alloc::string::String;
#[cfg(feature = "segy")]
use alloc::string::ToString;
#[cfg(any(feature = "grib", feature = "segy"))]
use alloc::vec::Vec;
use core::fmt::Write as _;
#[cfg(any(feature = "bufr", feature = "n5", feature = "root"))]
use rgx_core::bail;
use rgx_core::{decline, Adapter, Outcome, Result};

/// `writeln!` into a `String` cannot fail; dropping the result keeps the
/// report code from threading `fmt::Result` through every line.
macro_rules! line {
    ($out:expr, $($arg:tt)*) => {{
        let _ = writeln!($out, $($arg)*);
    }};
}

/// Bounds for one `extract`: a GRIB file can hold thousands of messages, each
/// with millions of grid points, and the report must stay a report.
#[cfg(feature = "grib")]
const MAX_MESSAGES: usize = 32;
#[cfg(feature = "grib")]
const MAX_SECTIONS: usize = 64;
#[cfg(feature = "grib")]
const MAX_VALUES: usize = 24;
#[cfg(feature = "segy")]
const MAX_TRACES: usize = 16;
#[cfg(feature = "grib")]
const MAX_REPORT: usize = 512 * 1024;

// ---------------------------------------------------------------------------
// Big-endian readers. Every one is bounds-checked and returns `None` rather
// than panicking, because the callers are feeding on untrusted file bytes.
// ---------------------------------------------------------------------------

/// `n` bytes at `off`, big-endian, as a `u64`. `n` must be `<= 8`.
#[cfg(any(feature = "bufr", feature = "grib", feature = "root", feature = "segy"))]
fn be_uint(data: &[u8], off: usize, n: usize) -> Option<u64> {
    let end = off.checked_add(n)?;
    let slice = data.get(off..end)?;
    let mut v: u64 = 0;
    for &b in slice {
        v = (v << 8) | b as u64;
    }
    Some(v)
}

#[cfg(any(feature = "bufr", feature = "grib", feature = "n5", feature = "segy"))]
fn be_u8(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}

#[cfg(any(feature = "grib", feature = "segy"))]
fn be_u16(data: &[u8], off: usize) -> Option<u16> {
    be_uint(data, off, 2).map(|v| v as u16)
}

#[cfg(any(feature = "grib", feature = "root", feature = "segy"))]
fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    be_uint(data, off, 4).map(|v| v as u32)
}

/// GRIB scale factors are sign-and-magnitude, not two's complement: the
/// high-order bit of the left octet is the sign (FM 92-GRIB regulation 92.1.5,
/// and the GRIB1 binary data section spells the same rule out for octets 5-6).
#[cfg(feature = "grib")]
fn sign_magnitude(data: &[u8], off: usize, n: usize) -> Option<i32> {
    let raw = be_uint(data, off, n)?;
    let sign_bit = 1u64 << (n * 8 - 1);
    let magnitude = (raw & (sign_bit - 1)) as i32;
    Some(if raw & sign_bit != 0 {
        -magnitude
    } else {
        magnitude
    })
}

/// `2^e`. Built from the exponent bits because `powf`/`powi` are `std`; out of
/// the normal range the answer is 0 or infinity, which is what the arithmetic
/// it feeds would produce anyway.
#[cfg(feature = "grib")]
fn pow2(e: i32) -> f64 {
    if !(-1022..=1023).contains(&e) {
        return if e > 1023 { f64::INFINITY } else { 0.0 };
    }
    f64::from_bits(((e + 1023) as u64) << 52)
}

/// `10^d`, by repeated multiplication for the same `std` reason.
#[cfg(feature = "grib")]
fn pow10(d: i32) -> f64 {
    if !(-308..=308).contains(&d) {
        return if d > 0 { f64::INFINITY } else { 0.0 };
    }
    let mut v = 1.0f64;
    let mut i = 0i32;
    if d > 0 {
        while i < d {
            v *= 10.0;
            i += 1;
        }
    } else {
        while i > d {
            v *= 0.1;
            i -= 1;
        }
    }
    v
}

/// The coefficients of the exponential series, `1/n!` for `n` from 0 to 14.
#[cfg(feature = "grib")]
const EXP_SERIES: [f64; 15] = [
    1.0,
    1.0,
    0.5,
    1.0 / 6.0,
    1.0 / 24.0,
    1.0 / 120.0,
    1.0 / 720.0,
    1.0 / 5040.0,
    1.0 / 40320.0,
    1.0 / 362880.0,
    1.0 / 3628800.0,
    1.0 / 39916800.0,
    1.0 / 479001600.0,
    1.0 / 6227020800.0,
    1.0 / 87178291200.0,
];

/// `x^y`, for a positive `x`, without the standard library's `powf`.
///
/// The crate is `no_std` and `powf` is one of the functions `std` keeps.
/// What is here is the usual pair: the binary logarithm and the binary
/// exponential, each of them reduced to an argument of its own and each
/// with a series of its own. The result is good to a few parts in 10^16,
/// which is the accuracy a double carries anyway.
#[cfg(feature = "grib")]
fn powf(x: f64, y: f64) -> f64 {
    if x.is_nan() || x <= 0.0 || y == 0.0 {
        return 1.0;
    }
    exp2(y * log2(x))
}

/// The binary logarithm of a positive number.
///
/// The exponent comes off the bits and the mantissa is reduced to
/// `[sqrt(1/2), sqrt(2))`, so that the series below sees an argument of at
/// most 0.1716.
#[cfg(feature = "grib")]
fn log2(x: f64) -> f64 {
    let bits = x.to_bits();
    let mut exponent = ((bits >> 52) & 0x7ff) as i32 - 1023;
    let mut mantissa = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    if mantissa > core::f64::consts::SQRT_2 {
        mantissa *= 0.5;
        exponent += 1;
    }
    // ln(m) = 2 * (f + f^3/3 + f^5/5 + ...), with f = (m - 1) / (m + 1).
    let f = (mantissa - 1.0) / (mantissa + 1.0);
    let square = f * f;
    let mut term = f;
    let mut sum = 0.0;
    let mut divisor = 1.0;
    for _ in 0..12 {
        sum += term / divisor;
        term *= square;
        divisor += 2.0;
    }
    f64::from(exponent) + 2.0 * sum / core::f64::consts::LN_2
}

/// Two to a power.
///
/// The whole part of the exponent is a power of two, which is exact, and
/// the fraction is a small argument for the series: `2^f = e^(f ln 2)` with
/// `|f ln 2|` at most 0.347.
#[cfg(feature = "grib")]
fn exp2(y: f64) -> f64 {
    let whole = if y >= 0.0 { y.floor() } else { y.ceil() };
    let r = (y - whole) * core::f64::consts::LN_2;
    let mut acc = 0.0;
    for coefficient in EXP_SERIES.iter().rev() {
        acc = acc * r + coefficient;
    }
    acc * pow2(whole as i32)
}

/// IBM System/360 32-bit hexadecimal float, the GRIB1 reference value.
///
/// The format is sign bit, 7-bit excess-64 base-16 exponent, 24-bit fraction
/// with the leading nibble implicit: `value = (-1)^s * fraction * 2^(4e - 280)`.
/// Derivation: `0.f * 16^(e-64)` with `0.f = fraction / 2^24`, and
/// `16^(e-64) = 2^(4e-256)`.
#[cfg(feature = "grib")]
fn ibm_float(bits: u32) -> f64 {
    let sign = bits & 0x8000_0000 != 0;
    let exponent = ((bits >> 24) & 0x7f) as i32;
    let fraction = (bits & 0x00ff_ffff) as f64;
    let v = fraction * pow2(4 * exponent - 280);
    if sign {
        -v
    } else {
        v
    }
}

/// Most-significant-bit-first bit reader. Packed GRIB fields do not fall on
/// byte boundaries, and a bit-at-a-time loop over [`MAX_VALUES`] values is
/// not the hot path — being obviously correct is worth more here.
#[cfg(feature = "grib")]
struct BitReader<'a> {
    data: &'a [u8],
    bit: usize,
}

#[cfg(feature = "grib")]
impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader { data, bit: 0 }
    }

    fn remaining_bits(&self) -> usize {
        self.data.len().saturating_mul(8).saturating_sub(self.bit)
    }

    /// `n` bits (`n <= 64`), most significant first.
    fn read(&mut self, n: u32) -> Option<u64> {
        if n > 64 || self.remaining_bits() < n as usize {
            return None;
        }
        let mut v = 0u64;
        for i in 0..n as usize {
            let p = self.bit + i;
            let bit = (self.data[p / 8] >> (7 - (p % 8))) & 1;
            v = (v << 1) | bit as u64;
        }
        self.bit += n as usize;
        Some(v)
    }
}

// ===========================================================================
// GRIB — WMO FM 92-GRIB, editions 1 and 2
// ===========================================================================

/// GRIB weather messages, edition 1 and edition 2. The two editions share the
/// `GRIB` indicator and nothing else: edition 1 sections carry a 3-octet
/// length and no section number, edition 2 sections carry a 4-octet length
/// and a section number. Reusing one parser for both is the defect, so they
/// are separate code paths.
#[cfg(feature = "grib")]
pub struct Grib;

#[cfg(feature = "grib")]
impl Adapter for Grib {
    fn name(&self) -> &'static str {
        "grib"
    }

    fn extensions(&self) -> &'static [&'static str] {
        // `grib1` and `grib2` are the suffixes in real use -- pygrib's own
        // sample data, the NCEP inventory -- and a file named `x.grib1` that
        // the registry does not claim is a file the reader never reaches.
        &["grb", "grb1", "grb2", "grib", "grib1", "grib2"]
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !data.starts_with(b"GRIB") {
            decline!("no GRIB indicator at offset 0");
        }
        let mut out = String::new();
        let mut off = 0usize;
        let mut n = 0usize;
        while n < MAX_MESSAGES {
            let Some(len) = message_len(data, off) else {
                break;
            };
            if len == 0 {
                break;
            }
            let Some(end) = off.checked_add(len) else {
                line!(
                    out,
                    "message at offset {off} declares an unrepresentable length"
                );
                break;
            };
            if end > data.len() {
                line!(
                    out,
                    "message at offset {off} declares {len} bytes but the file holds {}: truncated",
                    data.len()
                );
                break;
            }
            match be_u8(data, off + 7) {
                Some(1) => {
                    line!(out, "grib edition 1 message at offset {off} ({len} bytes)");
                    grib1(data, off, &mut out);
                }
                Some(2) => {
                    line!(out, "grib edition 2 message at offset {off} ({len} bytes)");
                    grib2(data, off, len, &mut out);
                }
                Some(e) => {
                    line!(out, "grib edition {e} at offset {off}: edition not decoded");
                }
                None => break,
            }
            off = end;
            n += 1;
            if out.len() > MAX_REPORT {
                line!(out, "[report truncated at {} bytes]", MAX_REPORT);
                break;
            }
        }
        if n == 0 {
            // The indicator matched, so this is a GRIB file even if nothing
            // in it parsed. Returning an error here would hand the file to
            // the next adapter and drop it from the search.
            line!(out, "no GRIB message could be read from this file");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// Total message length declared in section 0: 3 octets for edition 1
/// (octets 5-7), 8 octets for edition 2 (octets 9-16).
#[cfg(feature = "grib")]
fn message_len(data: &[u8], off: usize) -> Option<usize> {
    let head = data.get(off..)?;
    if !head.starts_with(b"GRIB") {
        return None;
    }
    match be_u8(data, off + 7)? {
        1 => usize::try_from(be_uint(data, off + 4, 3)?).ok(),
        2 => usize::try_from(be_uint(data, off + 8, 8)?).ok(),
        _ => None,
    }
}

// -- GRIB edition 2 ---------------------------------------------------------

/// The truncation of a spectrum: the pentagonal resolution parameters J, K
/// and M (code table 3.7).
///
/// The parameters fix the order the coefficients come in: the row `m` runs
/// from 0 to M and, inside it, the wave number `n` runs from `m` to N(m);
/// each coefficient is stored as its real part followed by its imaginary
/// part. The triangular truncation -- M = J = K, the one both editions'
/// complex packing uses -- has N(m) = J, so the spectrum holds
/// (M+1)(M+2) values: the real and the imaginary part of each of the
/// (M+1)(M+2)/2 coefficients.
#[derive(Default, Clone, Copy)]
#[cfg(feature = "grib")]
struct Truncation {
    j: u32,
    k: u32,
    m: u32,
}

#[cfg(feature = "grib")]
impl Truncation {
    /// The number of values the spectrum holds, if the truncation is the
    /// triangular one this reader reads.
    fn values(&self) -> Option<usize> {
        if self.j != self.k || self.j != self.m {
            return None;
        }
        let m = u64::from(self.m);
        usize::try_from((m + 1) * (m + 2)).ok()
    }
}

/// The name of the shape of a truncation.
///
/// The notes of grid definition template 3.50 name three shapes: the
/// triangular one -- M = J = K --, the rhomboidal one -- K = J + M -- and the
/// trapezoidal one -- K = J with K > M. Any other relation between the three
/// parameters is a shape the specification does not name.
#[cfg(feature = "grib")]
fn truncation_shape(truncation: &Truncation) -> &'static str {
    if truncation.j == truncation.k && truncation.k == truncation.m {
        "triangular"
    } else if truncation.k == truncation.j + truncation.m {
        "rhomboidal"
    } else if truncation.j == truncation.k && truncation.k > truncation.m {
        "trapezoidal"
    } else {
        "undefined"
    }
}

/// The geometry of a bi-Fourier grid: the two resolution parameters and the
/// shape of the truncation.
///
/// Grid definition templates 3.61, 3.62 and 3.63 -- the grids of the limited
/// area models -- carry them where the spherical harmonics grid carries its
/// truncation: the resolution parameters N and M at octets 16-23 and the
/// shape of the truncation at octet 24.
#[derive(Default, Clone, Copy)]
#[cfg(feature = "grib")]
struct BiFourier {
    n: u32,
    m: u32,
    shape: u8,
}

/// What template 5.53 says about the bi-Fourier packing.
#[derive(Default, Clone, Copy)]
#[cfg(feature = "grib")]
struct BiFourierPacking {
    /// The shape of the truncation of the unpacked subset (code table 5.25).
    subset_shape: u8,
    /// The packing mode for the axes (code table 5.26): 0 packs the axes
    /// with the rest of the field, 1 leaves them in the unpacked subset.
    axes: u8,
    /// The resolution parameter N of the unpacked subset.
    subset_n: u32,
    /// The resolution parameter M of the unpacked subset.
    subset_m: u32,
    /// The number of values in the unpacked subset (octets 31-34).
    subset_values: u32,
}

/// The limits of a bi-Fourier truncation.
///
/// `rows[j]` is the largest wave number `i` the row `j` of the spectrum
/// reaches, and `columns[i]` the largest row `j` the column `i` reaches. A
/// limit of -1 is a row with nothing in it.
///
/// Code table 3.25 -- and code table 5.25, which says the same of the
/// unpacked subset -- knows three shapes: 77 the rectangle, 88 the ellipse
/// and 99 the diamond.
#[cfg(feature = "grib")]
fn bi_fourier_limits(shape: u8, ni: u32, nj: u32) -> Option<(Vec<i64>, Vec<i64>)> {
    // The two resolutions are u32s of the grid definition: a truncation
    // wider than every value this reader reads is a crafted geometry, not
    // a field, and both vectors are refused rather than reserved.
    if ni as u64 >= MAX_GRIB1_VALUES as u64 || nj as u64 >= MAX_GRIB1_VALUES as u64 {
        return None;
    }
    let ni = i64::from(ni);
    let nj = i64::from(nj);
    let mut rows = vec![0i64; usize::try_from(nj + 1).ok()?];
    let mut columns = vec![0i64; usize::try_from(ni + 1).ok()?];
    match shape {
        // The rectangle: every row reaches the same wave number.
        77 => {
            for row in rows.iter_mut() {
                *row = ni;
            }
            for column in columns.iter_mut() {
                *column = nj;
            }
        }
        // The ellipse: the limit of a row is the ordinate of the ellipse of
        // semi-axes ni and nj at that row.
        88 => {
            rows[0] = ni;
            if nj > 0 {
                rows[usize::try_from(nj).ok()?] = 0;
                for j in 1..nj {
                    let ordinate = ni as f64 / nj as f64 * ((nj * nj - j * j) as f64).sqrt();
                    rows[usize::try_from(j).ok()?] = (ordinate + 1e-10) as i64;
                }
            }
            columns[0] = nj;
            if ni > 0 {
                columns[usize::try_from(ni).ok()?] = 0;
                for i in 1..ni {
                    let ordinate = nj as f64 / ni as f64 * ((ni * ni - i * i) as f64).sqrt();
                    columns[usize::try_from(i).ok()?] = (ordinate + 1e-10) as i64;
                }
            }
        }
        // The diamond: the limit of a row falls away one wave number every
        // ni/nj rows.
        99 => {
            if nj == 0 {
                rows[0] = -1;
            } else {
                for j in 0..=nj {
                    rows[usize::try_from(j).ok()?] = ni - (j * ni) / nj;
                }
            }
            if ni == 0 {
                columns[0] = -1;
            } else {
                for i in 0..=ni {
                    columns[usize::try_from(i).ok()?] = nj - (i * nj) / ni;
                }
            }
        }
        _ => return None,
    }
    Some((rows, columns))
}

/// The name of a bi-Fourier truncation shape (code tables 3.25 and 5.25).
#[cfg(feature = "grib")]
fn bi_fourier_shape_name(shape: u8) -> &'static str {
    match shape {
        77 => "rectangle",
        88 => "ellipse",
        99 => "diamond",
        _ => "unknown",
    }
}

/// Whether the coefficient of the wave numbers `i` and `j` is one of the
/// values the unpacked subset holds.
///
/// The subset is the part of the spectrum the truncation of the subset covers,
/// and the packing mode for the axes (code table 5.26) decides whether the
/// two axes belong to it as well.
#[cfg(feature = "grib")]
fn bi_fourier_in_subset(
    i: i64,
    j: i64,
    packing: &BiFourierPacking,
    subset_rows: &[i64],
    subset_columns: &[i64],
) -> bool {
    let mut inside = i <= i64::from(packing.subset_n) && j <= i64::from(packing.subset_m);
    if inside {
        let row = subset_rows
            .get(usize::try_from(j).unwrap_or(usize::MAX))
            .copied();
        let column = subset_columns
            .get(usize::try_from(i).unwrap_or(usize::MAX))
            .copied();
        inside =
            matches!(row, Some(limit) if i <= limit) && matches!(column, Some(limit) if j <= limit);
    }
    if packing.axes != 0 {
        inside = inside || i == 0 || j == 0;
    }
    inside
}

/// What section 5 tells us about how to read section 7.
#[derive(Default, Clone, Copy)]
#[cfg(feature = "grib")]
struct Drs {
    template: u16,
    points: u32,
    reference: f64,
    binary_scale: i32,
    decimal_scale: i32,
    bits: u8,
    precision: u8,
    /// The number of groups the field is split into (templates 5.2 and 5.3).
    groups: u32,
    /// The number of bits each group's reference value is stored in.
    group_reference_bits: u8,
    /// The width each group's own bit width is counted from.
    group_width_reference: i32,
    /// The number of bits each group's width is stored in.
    group_width_bits: u8,
    /// The number of values each group's length is counted from.
    group_length_reference: i32,
    /// The step between two group lengths.
    group_length_increment: i32,
    /// The number of values in the last group, which the file states outright.
    last_group_length: i32,
    /// The number of bits each group's length is stored in.
    group_length_bits: u8,
    /// The order of the spatial differencing: 0 none, 1 first, 2 second.
    differencing: u8,
    /// The number of octets the spatial differences are stored in.
    difference_octets: u8,
    /// How the missing values are managed: 0 none, 1 one, 2 two.
    missing: u8,
    /// The real part of the (0.0) coefficient (template 5.50, octets 21-24).
    real_part: f64,
    /// The Laplacian scaling factor (template 5.51, octets 21-24), in units
    /// of 10^-6.
    laplacian: i32,
    /// The truncation of the unpacked subset (template 5.51, octets 25-30).
    subset: Truncation,
    /// The number of values in the unpacked subset (template 5.51, octets
    /// 31-34).
    subset_values: u32,
    /// The bi-Fourier packing of template 5.53, with its own parameters.
    bi_fourier: Option<BiFourierPacking>,
}

#[cfg(feature = "grib")]
fn grib2(data: &[u8], base: usize, total: usize, out: &mut String) {
    let discipline = be_u8(data, base + 6).unwrap_or(255);
    line!(
        out,
        "  discipline: {discipline} ({})",
        discipline_name(discipline)
    );
    line!(out, "  message length: {total} bytes");

    let Some(end) = base.checked_add(total) else {
        line!(
            out,
            "  message length overflows an address: no sections read"
        );
        return;
    };
    // Section 0 is 16 octets and the first section with a length field
    // follows it.
    let mut pos = base + 16;
    let mut count = 0usize;
    let mut drs = Drs::default();
    let mut bitmap: Option<Vec<bool>> = None;
    let mut grid_points = 0u32;
    // The truncation of a spherical-harmonics grid, which says how many
    // coefficients the data section of that field holds.
    let mut truncation: Option<Truncation> = None;
    // The geometry of a bi-Fourier grid, which says the same for the fields
    // of the limited area models.
    let mut bi_fourier: Option<BiFourier> = None;
    // A message can hold several products, each with its own section 4 and
    // the sections 5, 6 and 7 that go with it. The sections that follow a
    // section 4 belong to that field, so the fields are kept apart here.
    let mut have_drs = false;
    let mut saw_data = false;

    while count < MAX_SECTIONS {
        if pos >= end {
            line!(
                out,
                "  section walk stopped at offset {pos}: message ends before the next section"
            );
            break;
        }
        // Section 8 is the bare `7777`, with no length field before it.
        if data.get(pos..pos.saturating_add(4)) == Some(&b"7777"[..]) {
            line!(out, "  section 8: \"7777\" end marker");
            break;
        }
        let Some(slen) = be_uint(data, pos, 4).map(|v| v as usize) else {
            line!(out, "  section at offset {pos}: truncated length field");
            break;
        };
        let Some(number) = be_u8(data, pos + 4) else {
            line!(out, "  section at offset {pos}: no section-number octet");
            break;
        };
        // The 4-octet length field counts the whole section, the four length
        // octets and the section-number octet included (section 1 of a
        // template 3.0 product is 21 octets long and says 21). Advancing by
        // `slen` is what keeps the next section aligned; `slen - 1` is the
        // classic off-by-one and every later field lands one octet short.
        if slen < 5 {
            line!(
                out,
                "  section {number} at offset {pos}: length {slen} is below the 5-octet minimum"
            );
            break;
        }
        let Some(next) = pos.checked_add(slen) else {
            line!(
                out,
                "  section {number} at offset {pos}: length {slen} overflows an address"
            );
            break;
        };
        if next > end {
            line!(out, "  section {number} at offset {pos}: length {slen} runs past the end of the message");
            break;
        }
        let Some(sec) = data.get(pos..next) else {
            line!(out, "  section {number} at offset {pos}: outside the file");
            break;
        };
        line!(out, "  section {number}: {slen} octets at offset {pos}");
        match number {
            1 => grib2_s1(sec, out),
            3 => {
                grid_points = grib2_s3(sec, out);
                truncation = grib2_truncation(sec);
                bi_fourier = grib2_bi_fourier(sec);
            }
            4 => {
                grib2_s4(sec, discipline, out);
                // The next sections belong to this field.
                drs = Drs::default();
                bitmap = None;
                have_drs = false;
            }
            5 => {
                drs = grib2_s5(sec);
                have_drs = true;
            }
            6 => bitmap = grib2_s6(sec, out),
            7 => {
                saw_data = true;
                if have_drs {
                    decode_grib2_data(
                        data,
                        pos + 5,
                        next,
                        &drs,
                        &Grid {
                            points: grid_points,
                            bitmap: bitmap.as_deref(),
                            truncation,
                            bi_fourier,
                        },
                        out,
                    );
                } else {
                    line!(
                        out,
                        "  data: not decoded (the field has no data representation section)"
                    );
                }
            }
            _ => {}
        }
        pos = next;
        count += 1;
    }
    if !saw_data {
        line!(out, "  section 7 (data): not present");
    }
}

#[cfg(feature = "grib")]
fn grib2_s1(sec: &[u8], out: &mut String) {
    // Octets 6-7 centre, 8-9 subcentre, 13-14 year, 15-19 month..second,
    // 20 production status.
    let centre = be_u16(sec, 5).unwrap_or(0);
    let subcentre = be_u16(sec, 7).unwrap_or(0);
    line!(
        out,
        "    originating centre: {centre}, subcentre: {subcentre}"
    );
    if sec.len() >= 20 {
        let year = be_u16(sec, 12).unwrap_or(0);
        let month = be_u8(sec, 14).unwrap_or(0);
        let day = be_u8(sec, 15).unwrap_or(0);
        let hour = be_u8(sec, 16).unwrap_or(0);
        let minute = be_u8(sec, 17).unwrap_or(0);
        let second = be_u8(sec, 18).unwrap_or(0);
        line!(
            out,
            "    reference time: {year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
        );
        line!(
            out,
            "    production status: {}",
            be_u8(sec, 19).unwrap_or(0)
        );
    }
}

#[cfg(feature = "grib")]
fn grib2_s3(sec: &[u8], out: &mut String) -> u32 {
    // Octets 6 source, 7-10 data points, 11 optional list length,
    // 12 interpretation, 13-14 grid definition template number.
    //
    // The number of data points is the number of points of the grid, which
    // is not the number of values the data section holds when a bit map
    // leaves some of them without one.
    let source = be_u8(sec, 5).unwrap_or(0);
    let points = be_u32(sec, 6).unwrap_or(0);
    let list_octets = be_u8(sec, 10).unwrap_or(0);
    let interpretation = be_u8(sec, 11).unwrap_or(0);
    let gdt = be_u16(sec, 12).unwrap_or(0);
    line!(
        out,
        "    grid: source {source} (0 = specified here), {points} data points, grid definition template 3.{gdt}"
    );
    if gdt == 50 {
        // Grid definition template 3.50: the spherical harmonics grid. The
        // pentagonal resolution parameters J, K and M are at octets 15-26 and
        // the two octets that follow them say how the coefficients are
        // represented (code table 3.6) and in what order they come (code
        // table 3.7).
        grib2_spectral_geometry(sec, out);
        return points;
    }
    if matches!(gdt, 61..=63) {
        // Grid definition templates 3.61, 3.62 and 3.63: the bi-Fourier grids
        // of the limited area models. They share the resolution parameters N
        // and M at octets 16-23, the shape of the truncation at 24 and the
        // three domains of the grid at 25-72.
        grib2_bifourier_geometry(sec, out);
        return points;
    }
    let Some(template) = grid_template(gdt) else {
        line!(
            out,
            "    grid template 3.{gdt} geometry: not decoded (the length of the template is not known here, so where its list of numbers would begin is not known either)"
        );
        return points;
    };
    // The number of columns and the number of rows of the grid, four octets
    // each and in the same place in every template of the two families a
    // reduced grid belongs to.
    let columns = be_u32(sec, 14 + template.columns).unwrap_or(0);
    let rows = be_u32(sec, 14 + template.rows).unwrap_or(0);
    if columns == u32::MAX {
        line!(
            out,
            "    grid: {rows} rows, the number of columns is missing: the grid is reduced"
        );
    } else {
        line!(out, "    grid: {rows} rows, {columns} columns");
    }
    if list_octets != 0 {
        grib2_reduced_grid(
            sec,
            out,
            &template,
            points,
            rows,
            list_octets,
            interpretation,
        );
    }
    points
}

/// The geometry of a spherical-harmonics grid: the truncation, and the two
/// octets that say how the coefficients are represented and in what order
/// they come.
#[cfg(feature = "grib")]
fn grib2_spectral_geometry(sec: &[u8], out: &mut String) {
    let Some(truncation) = grib2_truncation(sec) else {
        return;
    };
    line!(
        out,
        "    grid: spherical harmonics, truncation J {}, K {}, M {}",
        truncation.j,
        truncation.k,
        truncation.m
    );
    if let Some(values) = truncation.values() {
        line!(
            out,
            "    grid: {} complex coefficients, the real and the imaginary part of each",
            values / 2
        );
    }
    let representation = be_u8(sec, 26).unwrap_or(0);
    let mode = be_u8(sec, 27).unwrap_or(0);
    line!(
        out,
        "    grid: representation type {representation} ({}), representation mode {mode} ({})",
        grib2_spectral_type_name(representation),
        grib2_spectral_mode_name(mode),
    );
}

/// The truncation of a spherical-harmonics grid: the pentagonal resolution
/// parameters J, K and M of grid definition template 3.50, at octets 15-26.
/// Any other grid has none, and says so by not being template 3.50.
#[cfg(feature = "grib")]
fn grib2_truncation(sec: &[u8]) -> Option<Truncation> {
    if be_u16(sec, 12).unwrap_or(0) != 50 {
        return None;
    }
    Some(Truncation {
        j: be_u32(sec, 14).unwrap_or(0),
        k: be_u32(sec, 18).unwrap_or(0),
        m: be_u32(sec, 22).unwrap_or(0),
    })
}

/// The geometry of a bi-Fourier grid: the resolution parameters N and M of
/// grid definition templates 3.61, 3.62 and 3.63, at octets 16-23, and the
/// shape of the truncation at octet 24. Any other grid has none, and says so
/// by not being one of those three.
#[cfg(feature = "grib")]
fn grib2_bi_fourier(sec: &[u8]) -> Option<BiFourier> {
    if !matches!(be_u16(sec, 12).unwrap_or(0), 61..=63) {
        return None;
    }
    Some(BiFourier {
        n: be_u32(sec, 15).unwrap_or(0),
        m: be_u32(sec, 19).unwrap_or(0),
        shape: be_u8(sec, 23).unwrap_or(0),
    })
}

/// The geometry of a bi-Fourier grid: its resolution parameters, the shape of
/// its truncation and the three domains it is made of.
#[cfg(feature = "grib")]
fn grib2_bifourier_geometry(sec: &[u8], out: &mut String) {
    let Some(geometry) = grib2_bi_fourier(sec) else {
        return;
    };
    line!(
        out,
        "    grid: bi-Fourier, resolution N {}, M {}, truncation of the shape {} ({})",
        geometry.n,
        geometry.m,
        geometry.shape,
        bi_fourier_shape_name(geometry.shape)
    );
    // The three domains: the full one, the useful one and the coupling one,
    // each of them two lengths of eight octets.
    let length = |offset: usize| be_uint(sec, offset, 8).unwrap_or(0);
    line!(
        out,
        "    grid: the full domain {} x {} metres, the useful domain {} x {} metres, the coupling domain {} x {} metres",
        length(24),
        length(48),
        length(32),
        length(56),
        length(40),
        length(64)
    );
}

/// The name of a representation type (code table 3.6).
#[cfg(feature = "grib")]
fn grib2_spectral_type_name(t: u8) -> &'static str {
    match t {
        1 => "the associated Legendre functions of the first kind",
        2 => "the bi-Fourier representation",
        _ => "a representation type this reader has no name for",
    }
}

/// The name of a representation mode (code table 3.7).
#[cfg(feature = "grib")]
fn grib2_spectral_mode_name(m: u8) -> &'static str {
    match m {
        1 => "the complex coefficients, the wave number n increasing inside the row m",
        _ => "a representation mode this reader has no name for",
    }
}

/// The fixed part of a grid definition template.
///
/// `octets` is how long the template is: the list of numbers that a reduced
/// grid carries follows the template, so the length of the template is what
/// says where that list begins. `columns`, `rows`, `basic_angle` and
/// `subdivisions` are the offsets of the number of columns, of the number of
/// rows, of the basic angle and of the number of subdivisions inside it.
///
/// The lengths are NOAA's g2c library's. That library is the one NCEP writes
/// these files with, and its `src/gridtemplates.c` holds the map of octets of
/// every template it knows; these are the sums of the maps of the
/// latitude/longitude and of the Gaussian families, which are the two
/// families a reduced grid belongs to.
#[cfg(feature = "grib")]
struct GridTemplate {
    octets: usize,
    columns: usize,
    rows: usize,
    basic_angle: usize,
    subdivisions: usize,
}

#[cfg(feature = "grib")]
fn grid_template(gdt: u16) -> Option<GridTemplate> {
    let octets = match gdt {
        0 | 40 => 58,
        1 | 2 | 41 | 42 => 70,
        3 | 43 => 82,
        _ => return None,
    };
    Some(GridTemplate {
        octets,
        columns: 16,
        rows: 20,
        basic_angle: 24,
        subdivisions: 28,
    })
}

/// The list of numbers that a reduced grid carries.
///
/// Code table 3.11 says what the numbers mean: the points of each row of the
/// grid, or -- for the third interpretation -- the latitude of each row. The
/// numbers are the section's own, the number of rows the grid description
/// declares is how many of them there are, and their sum is the number of
/// points of the grid -- which is the number of data points the section
/// declares when the two agree, and is not when they do not.
///
/// The numbers are reported as they stand. The latitudes of the third
/// interpretation are integers in the unit the code table names, and turning
/// them into degrees would want the basic angle and the number of
/// subdivisions of the grid, which is a reading this reader has no file to
/// check against.
#[cfg(feature = "grib")]
fn grib2_reduced_grid(
    sec: &[u8],
    out: &mut String,
    template: &GridTemplate,
    points: u32,
    rows: u32,
    list_octets: u8,
    interpretation: u8,
) {
    let (meaning, label) = match interpretation {
        1 => ("the points of each row", "points per row"),
        2 => (
            "the points of each row, between the extreme longitudes of the grid",
            "points per row",
        ),
        3 => ("the latitude of each row", "latitude of each row"),
        _ => {
            line!(
                out,
                "    grid: the list of numbers is not decoded (code table 3.11 interpretation {interpretation} is not one this reader knows)"
            );
            return;
        }
    };
    let start = 14 + template.octets;
    let width = list_octets as usize;
    let available = sec.len().saturating_sub(start);
    let count = rows as usize;
    // A number of more than eight octets does not fit in the reader's
    // unsigned 64-bit integer, and a section that claims one is not a
    // layout this reader knows.
    if width > 8 {
        line!(
            out,
            "    grid: the list of numbers is not decoded (the section says each of them takes {width} octets, which is more than this reader can hold)"
        );
        return;
    }
    if count == 0 || count > available / width {
        line!(
            out,
            "    grid: the list of numbers is not decoded (the section holds {available} octets after the template, which is not {count} numbers of {width} octets)"
        );
        return;
    }
    let mut numbers = Vec::with_capacity(count);
    for i in 0..count {
        numbers.push(be_uint(sec, start + i * width, width).unwrap_or(0));
    }
    line!(
        out,
        "    grid: the list of numbers gives {meaning} (code table 3.11 interpretation {interpretation})"
    );
    if interpretation == 3 {
        let basic = be_u32(sec, 14 + template.basic_angle).unwrap_or(0);
        let subdivisions = be_u32(sec, 14 + template.subdivisions).unwrap_or(0);
        if basic == 0 {
            line!(
                out,
                "    grid: the latitudes are integers of a microdegree, the grid declares no basic angle"
            );
        } else if subdivisions == 0 {
            line!(
                out,
                "    grid: the latitudes are integers of a microdegree, the grid declares no number of subdivisions"
            );
        } else {
            line!(
                out,
                "    grid: the latitudes are integers of {basic}/{subdivisions} of a microdegree"
            );
        }
    }
    let total: u64 = numbers.iter().sum();
    if total == points as u64 {
        line!(
            out,
            "    grid: the {count} rows hold {total} points, the number of data points the section declares"
        );
    } else {
        line!(
            out,
            "    grid: the {count} rows hold {total} points, and the section declares {points} data points: they do not agree"
        );
    }
    let low = numbers.iter().copied().min().unwrap_or(0);
    let high = numbers.iter().copied().max().unwrap_or(0);
    line!(out, "    grid: {low} to {high} {label}");
    let shown = count.min(MAX_VALUES);
    line!(out, "    grid: {label}, the first {shown} of {count}:");
    for number in &numbers[..shown] {
        line!(out, "      {number}");
    }
}

#[cfg(feature = "grib")]
fn grib2_s4(sec: &[u8], discipline: u8, out: &mut String) {
    // Octets 6-7 coordinate values, 8-9 product template number, then the
    // product template itself from octet 10 on.
    let coords = be_u16(sec, 5).unwrap_or(0);
    let pdt = be_u16(sec, 7).unwrap_or(0);
    line!(
        out,
        "    product: template 4.{pdt}, {coords} coordinate values"
    );
    // Templates 4.0-4.15 extend template 4.0's 34-octet prefix and append
    // after it; only the prefix is read here, and only when the section is
    // long enough to hold it.
    if pdt > 15 || sec.len() < 34 {
        if pdt > 15 {
            line!(
                out,
                "    product template 4.{pdt}: fields after the shared prefix are not decoded"
            );
        }
        return;
    }
    let category = be_u8(sec, 9).unwrap_or(0);
    let number = be_u8(sec, 10).unwrap_or(0);
    line!(
        out,
        "    parameter: discipline {discipline} category {category} number {number} ({})",
        category_name(discipline, category)
    );
    if let Some(name) = parameter_name(discipline, category, number) {
        line!(out, "    parameter name: {name}");
    }
    let gen = be_u8(sec, 11).unwrap_or(0);
    line!(out, "    generating process: code {gen}");
    let ftime = be_u32(sec, 18).unwrap_or(0);
    line!(
        out,
        "    forecast time: {ftime} (unit code {})",
        be_u8(sec, 17).unwrap_or(0)
    );
    let surface = be_u8(sec, 22).unwrap_or(255);
    let scale = sign_magnitude(sec, 23, 1).unwrap_or(0);
    let value = be_u32(sec, 24).unwrap_or(0);
    line!(
        out,
        "    first fixed surface: type {surface}, value {value} x 10^{scale}"
    );
}

#[cfg(feature = "grib")]
fn grib2_s5(sec: &[u8]) -> Drs {
    // Octets 6-9 data points, 10-11 data representation template number,
    // then the template from octet 12 on.
    let template = be_u16(sec, 9).unwrap_or(0);
    let points = be_u32(sec, 5).unwrap_or(0);
    let mut drs = Drs {
        template,
        points,
        ..Drs::default()
    };
    match template {
        // 5.0 grid point, simple packing: R at octets 12-15, E at 16-17,
        // D at 18-19, bits at 20, type of original field values at 21.
        0 => {
            if sec.len() >= 21 {
                if let Some(r) = be_u32(sec, 11) {
                    drs.reference = f32::from_bits(r) as f64;
                }
                drs.binary_scale = sign_magnitude(sec, 15, 2).unwrap_or(0);
                drs.decimal_scale = sign_magnitude(sec, 17, 2).unwrap_or(0);
                drs.bits = be_u8(sec, 19).unwrap_or(0);
            }
        }
        // 5.2 grid point, complex packing, and 5.3 the same with the
        // spatial differencing. Octets 12-15 the reference value, 16-17 the
        // binary scale factor, 18-19 the decimal scale factor, 20 the number
        // of bits each packed value is stored in, 21 the type of the original
        // field values, 22 the group splitting method, 23 the missing value
        // management, 24-27 the primary missing value substitute, 28-31 the
        // secondary one, 32-35 the number of groups, 36 the reference for
        // the group widths, 37 the number of bits they are stored in, 38-41
        // the reference for the group lengths, 42 the length increment, 43-46
        // the true length of the last group, 47 the number of bits the group
        // lengths are stored in, 48 the order of the spatial differencing and
        // 49 the number of octets the differences take.
        2 | 3 => {
            if sec.len() >= 49 {
                drs.reference = be_u32(sec, 11)
                    .map(|b| f32::from_bits(b) as f64)
                    .unwrap_or(0.0);
                drs.binary_scale = sign_magnitude(sec, 15, 2).unwrap_or(0);
                drs.decimal_scale = sign_magnitude(sec, 17, 2).unwrap_or(0);
                drs.bits = be_u8(sec, 19).unwrap_or(0);
                // The group reference values are stored with the same width
                // as the packed values: the template has no octet of its own
                // for them.
                drs.group_reference_bits = drs.bits;
                drs.missing = be_u8(sec, 22).unwrap_or(0);
                drs.groups = be_u32(sec, 31).unwrap_or(0);
                drs.group_width_reference = be_u8(sec, 35).unwrap_or(0) as i32;
                drs.group_width_bits = be_u8(sec, 36).unwrap_or(0);
                drs.group_length_reference = be_u32(sec, 37).unwrap_or(0) as i32;
                drs.group_length_increment = be_u8(sec, 41).unwrap_or(0) as i32;
                drs.last_group_length = be_u32(sec, 42).unwrap_or(0) as i32;
                drs.group_length_bits = be_u8(sec, 46).unwrap_or(0);
                drs.differencing = be_u8(sec, 47).unwrap_or(0);
                drs.difference_octets = be_u8(sec, 48).unwrap_or(0);
            }
        }
        // 5.4 grid point, IEEE: precision at octet 12.
        4 => {
            drs.precision = be_u8(sec, 11).unwrap_or(0);
        }
        // 5.50 spherical harmonics, simple packing: the reference value at
        // octets 12-15, the binary scale factor at 16-17, the decimal one at
        // 18-19, the number of bits at 20, and the real part of the (0.0)
        // coefficient at 21-24 -- it is kept out of the packed values so that
        // they are all the smaller.
        50 if sec.len() >= 24 => {
            if let Some(r) = be_u32(sec, 11) {
                drs.reference = f32::from_bits(r) as f64;
            }
            drs.binary_scale = sign_magnitude(sec, 15, 2).unwrap_or(0);
            drs.decimal_scale = sign_magnitude(sec, 17, 2).unwrap_or(0);
            drs.bits = be_u8(sec, 19).unwrap_or(0);
            if let Some(r) = be_u32(sec, 20) {
                drs.real_part = f32::from_bits(r) as f64;
            }
        }
        // 5.51 spherical harmonics, complex packing: the reference value, the
        // two scale factors and the number of bits where 5.50 has them, then
        // the Laplacian scaling factor at octets 21-24, the truncation of the
        // unpacked subset at 25-30, the number of values in that subset at
        // 31-34 and the precision of its values at 35.
        51 if sec.len() >= 35 => {
            if let Some(r) = be_u32(sec, 11) {
                drs.reference = f32::from_bits(r) as f64;
            }
            drs.binary_scale = sign_magnitude(sec, 15, 2).unwrap_or(0);
            drs.decimal_scale = sign_magnitude(sec, 17, 2).unwrap_or(0);
            drs.bits = be_u8(sec, 19).unwrap_or(0);
            drs.laplacian = sign_magnitude(sec, 20, 4).unwrap_or(0);
            drs.subset = Truncation {
                j: u32::from(be_u16(sec, 24).unwrap_or(0)),
                k: u32::from(be_u16(sec, 26).unwrap_or(0)),
                m: u32::from(be_u16(sec, 28).unwrap_or(0)),
            };
            drs.subset_values = be_u32(sec, 30).unwrap_or(0);
            drs.precision = be_u8(sec, 34).unwrap_or(0);
        }
        // 5.53 bi-Fourier, complex packing: the reference value, the two
        // scale factors and the number of bits where 5.50 has them, then the
        // shape of the truncation of the unpacked subset at 21 (code table
        // 5.25), the packing mode for the axes at 22 (code table 5.26), the
        // Laplacian scaling factor at 23-26, the resolution parameters N and
        // M of the unpacked subset at 27-30, the number of values in that
        // subset at 31-34 and the precision of its values at 35.
        53 if sec.len() >= 35 => {
            if let Some(r) = be_u32(sec, 11) {
                drs.reference = f32::from_bits(r) as f64;
            }
            drs.binary_scale = sign_magnitude(sec, 15, 2).unwrap_or(0);
            drs.decimal_scale = sign_magnitude(sec, 17, 2).unwrap_or(0);
            drs.bits = be_u8(sec, 19).unwrap_or(0);
            drs.bi_fourier = Some(BiFourierPacking {
                subset_shape: be_u8(sec, 20).unwrap_or(0),
                axes: be_u8(sec, 21).unwrap_or(0),
                subset_n: u32::from(be_u16(sec, 26).unwrap_or(0)),
                subset_m: u32::from(be_u16(sec, 28).unwrap_or(0)),
                subset_values: be_u32(sec, 30).unwrap_or(0),
            });
            drs.laplacian = sign_magnitude(sec, 22, 4).unwrap_or(0);
            drs.precision = be_u8(sec, 34).unwrap_or(0);
        }
        _ => {}
    }
    drs
}
#[cfg(feature = "grib")]
fn grib2_s6(sec: &[u8], out: &mut String) -> Option<Vec<bool>> {
    // Octet 6 bit-map indicator; octets 7-nn the bit map itself. Any
    // indicator other than zero means there is no map in the section.
    let indicator = be_u8(sec, 5).unwrap_or(255);
    if indicator != 0 {
        line!(
            out,
            "    bit map: none (indicator {indicator}); every grid point is present"
        );
        return None;
    }
    let Some(body) = sec.get(6..) else {
        line!(
            out,
            "    bit map: indicator 0 but the section carries no bit map"
        );
        return None;
    };
    let map: Vec<bool> = body
        .iter()
        .flat_map(|b| (0..8).map(move |i| (b >> (7 - i)) & 1 == 1))
        .collect();
    let present = map.iter().filter(|b| **b).count();
    line!(
        out,
        "    bit map: {present} of {} points present",
        map.len()
    );
    Some(map)
}

/// What the grid of a field says about the values of its data section.
///
/// The number of points is what the bit map indexes: the data section holds
/// a value for each point the map marks, and for every point when there is
/// no map. The truncation is what says how many coefficients the data
/// section of a spherical-harmonics field holds.
#[cfg(feature = "grib")]
struct Grid<'a> {
    points: u32,
    bitmap: Option<&'a [bool]>,
    truncation: Option<Truncation>,
    /// The geometry of a bi-Fourier grid, for the fields of the limited area
    /// models.
    bi_fourier: Option<BiFourier>,
}

/// Decode section 7. Only the templates whose layout is known here are
/// read; anything else is reported as the byte count it occupies rather than
/// guessed at.
#[cfg(feature = "grib")]
fn decode_grib2_data(
    data: &[u8],
    start: usize,
    stop: usize,
    drs: &Drs,
    grid: &Grid<'_>,
    out: &mut String,
) {
    let Some(payload) = data.get(start..stop) else {
        line!(out, "  section 7: payload outside the file");
        return;
    };
    if payload.is_empty() {
        line!(out, "  section 7: empty");
        return;
    }
    let bitmap = grid.bitmap;
    let grid_points = grid.points;
    let truncation = grid.truncation.as_ref();
    match drs.template {
        0 => {
            let bits = drs.bits;
            if bits == 0 || bits > 32 {
                line!(
                    out,
                    "  section 7: template 5.0 declares {bits} bits per value; not decodable"
                );
                return;
            }
            let missing = if bits == 32 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            // The points of the grid, and the ones the bit map says carry a
            // value. The section holds one value for each of those, in the
            // order the map marks them, so the map has to be walked over the
            // whole grid and not over the values alone.
            let total = match bitmap {
                Some(_) => grid_points as usize,
                None => drs.points as usize,
            };
            let present = match bitmap {
                Some(map) => (0..total)
                    .filter(|&i| map.get(i).copied().unwrap_or(false))
                    .count(),
                None => total,
            };
            if present != drs.points as usize {
                line!(
                    out,
                    "  data: the bit map marks {present} points and the section declares {} values",
                    drs.points
                );
            }
            let mut reader = BitReader::new(payload);
            let mut values: Vec<f64> = Vec::new();
            let mut skipped = 0usize;
            for i in 0..total {
                let is_present = bitmap
                    .map(|m| m.get(i).copied().unwrap_or(false))
                    .unwrap_or(true);
                if !is_present {
                    skipped += 1;
                    continue;
                }
                if values.len() >= MAX_VALUES {
                    break;
                }
                let Some(raw) = reader.read(bits as u32) else {
                    break;
                };
                if raw == missing {
                    continue;
                }
                let v = (drs.reference + raw as f64 * pow2(drs.binary_scale))
                    / pow10(drs.decimal_scale);
                values.push(v);
            }
            line!(
                out,
                "  data: template 5.0 simple packing, {} bits per value, reference {}, E {}, D {}, {} points",
                drs.bits, drs.reference, drs.binary_scale, drs.decimal_scale, drs.points
            );
            if skipped > 0 {
                line!(out, "  data: {skipped} points masked off by the bit map");
            }
            print_values(out, &values, "first values");
        }
        2 | 3 => {
            grib2_complex(payload, drs, out);
        }
        50 => {
            grib2_spectral_simple(payload, drs, out);
        }
        51 => {
            grib2_spectral_complex(payload, drs, truncation, out);
        }
        53 => {
            grib2_bifourier_complex(payload, drs, grid, out);
        }
        4 => {
            let width = match drs.precision {
                1 => Some(4usize),
                2 => Some(8),
                _ => None,
            };
            let Some(width) = width else {
                line!(
                    out,
                    "  data: template 5.4 IEEE with precision {}; only precision 1 (32-bit) and 2 (64-bit) are read",
                    drs.precision
                );
                return;
            };
            line!(
                out,
                "  data: template 5.4 IEEE, precision {} ({width}-byte floats), {} points",
                drs.precision,
                drs.points
            );
            let total = match bitmap {
                Some(_) => grid_points as usize,
                None => drs.points as usize,
            };
            let mut values = Vec::new();
            let mut emitted = 0usize;
            let mut read = 0usize;
            for i in 0..total {
                if emitted >= MAX_VALUES {
                    break;
                }
                let is_present = bitmap
                    .map(|m| m.get(i).copied().unwrap_or(false))
                    .unwrap_or(true);
                if !is_present {
                    continue;
                }
                let off = read * width;
                let v = if width == 4 {
                    be_u32(payload, off).map(|b| f32::from_bits(b) as f64)
                } else {
                    be_uint(payload, off, 8).map(f64::from_bits)
                };
                read += 1;
                if let Some(v) = v {
                    values.push(v);
                    emitted += 1;
                }
            }
            print_values(out, &values, "first values");
        }
        t => {
            line!(
                out,
                "  section 7: {} bytes of payload in data representation template 5.{t}, which is not decoded",
                payload.len()
            );
        }
    }
}

/// The edition 2 complex packing: data representation templates 5.2 and 5.3.
///
/// The field is split into groups of values that share a bit width. Each
/// group carries a reference value, a width and a length, and the values of
/// the group are stored as the difference between the group's reference value
/// and the value itself, in the group's own width. The three group tables
/// come first in the data section, each a run of numbers of its own width
/// that starts on an octet boundary.
///
/// Template 5.3 stores the values as spatial differences instead: the
/// difference from the value before (first order) or from twice the value
/// before minus the one before that (second order). The smallest of those
/// differences is subtracted from all of them before they are stored, and
/// added back when the field is read.
///
/// The layout is the one NOAA's own g2c library reads, and the values it
/// produces are the ones this reader was checked against.
#[cfg(feature = "grib")]
fn grib2_complex(payload: &[u8], drs: &Drs, out: &mut String) {
    let groups = drs.groups as usize;
    let differencing = match (drs.template, drs.differencing) {
        (2, _) => "no spatial differencing",
        (_, 0) => "no spatial differencing",
        (_, 1) => "first order spatial differencing",
        (_, 2) => "second order spatial differencing",
        (_, other) => {
            line!(
                out,
                "  data: template 5.{} complex packing declares an order of spatial differencing of {other}; not decoded",
                drs.template
            );
            return;
        }
    };
    if groups == 0 {
        // A constant field: there is no group, so every point of the grid
        // holds the reference value.
        line!(
            out,
            "  data: template 5.{} complex packing, no groups, {differencing}, reference {}, E {}, D {}, {} points",
            drs.template, drs.reference, drs.binary_scale, drs.decimal_scale, drs.points
        );
        // The point count is four octets of the file and the field is
        // constant, so no payload bit ever contradicts it: the cap is the
        // reader's, on the same number edition 1 holds.
        let values = vec![drs.reference; (drs.points as usize).min(MAX_GRIB1_VALUES)];
        print_field(out, &values);
        return;
    }
    if drs.missing != 0 {
        // The missing values are inside the groups: the largest value a
        // group can hold is the marker for one of them. That layout is not
        // read here.
        line!(
            out,
            "  data: template 5.{} complex packing declares {} missing value management; the missing values inside the groups are not decoded",
            drs.template, drs.missing
        );
        return;
    }
    line!(
        out,
        "  data: template 5.{} complex packing, {groups} groups, {} bits per group reference, {} bits per group width, {} bits per group length, {differencing}, reference {}, E {}, D {}, {} points",
        drs.template,
        drs.group_reference_bits,
        drs.group_width_bits,
        drs.group_length_bits,
        drs.reference,
        drs.binary_scale,
        drs.decimal_scale,
        drs.points
    );
    let Some(values) = grib2_complex_values(payload, drs, groups) else {
        line!(
            out,
            "  data: not decoded (the group tables of the complex packing do not add up to the {} values the section holds)",
            drs.points
        );
        return;
    };
    print_field(out, &values);
}

/// The range of a decoded field, and the first values of it.
///
/// The whole field is scanned for the range: the values that are printed are
/// only the first few, so the range is the one thing the report says about
/// all of them.
#[cfg(feature = "grib")]
fn print_field(out: &mut String, values: &[f64]) {
    if values.is_empty() {
        line!(out, "    value range: none (the section holds no values)");
        return;
    }
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    for value in values {
        if *value < min {
            min = *value;
        }
        if *value > max {
            max = *value;
        }
    }
    line!(out, "    value range: minimum {min}, maximum {max}");
    let shown = values.len().min(MAX_VALUES);
    print_values(out, &values[..shown], "first values");
}

/// The values of a complex-packed field.
///
/// The spatial differencing needs the whole chain of values, so the field is
/// read to the end even though only the first few are printed.
#[cfg(feature = "grib")]
fn grib2_complex_values(payload: &[u8], drs: &Drs, groups: usize) -> Option<Vec<f64>> {
    let mut reader = BitReader::new(payload);
    // The spatial differencing header (template 5.3 only): the first value
    // of the field, the second value when the order is two, the sign of the
    // smallest difference and the difference itself.
    let mut first = 0i64;
    let mut second = 0i64;
    let mut minimum = 0i64;
    if drs.template == 3 && drs.difference_octets > 0 {
        let nbits = drs.difference_octets as u32 * 8;
        if nbits > 64 {
            return None;
        }
        first = reader.read(nbits)? as i64;
        if drs.differencing == 2 {
            second = reader.read(nbits)? as i64;
        }
        let sign = reader.read(1)?;
        let magnitude = reader.read(nbits - 1)? as i64;
        minimum = if sign == 1 { -magnitude } else { magnitude };
    }
    // The three group tables.
    let references = read_group_run(&mut reader, drs.group_reference_bits, groups)?;
    let mut widths = read_group_run(&mut reader, drs.group_width_bits, groups)?;
    let mut lengths = read_group_run(&mut reader, drs.group_length_bits, groups)?;
    for width in widths.iter_mut() {
        *width += drs.group_width_reference as u64;
    }
    for length in lengths.iter_mut() {
        *length = *length * drs.group_length_increment as u64 + drs.group_length_reference as u64;
    }
    if let Some(last) = lengths.last_mut() {
        *last = drs.last_group_length as u64;
    }
    // The group's lengths have to add up to the number of values the section
    // holds. A count that does not add up means the section is not the
    // layout this reader knows, and a number read from a layout that is not
    // known is a guess.
    let total: u64 = lengths.iter().sum();
    if total != drs.points as u64 {
        return None;
    }
    // The values, group by group. The capacity and the per-group count
    // are both ceilinged: a sign-extended group length can wrap the
    // total into agreement with a huge `points` while a width-0 group
    // consumes no bits, and the loop below would run forever pushing.
    let mut values: Vec<i64> = Vec::with_capacity((drs.points as usize).min(MAX_GRIB1_VALUES));
    for group in 0..groups {
        let width = widths[group] as u32;
        if width > 64 {
            return None;
        }
        let count = lengths[group] as usize;
        if count > MAX_GRIB1_VALUES.saturating_sub(values.len()) {
            // A group longer than every value the reader reads is not
            // this layout.
            return None;
        }
        for _ in 0..count {
            let raw = if width == 0 {
                0
            } else {
                reader.read(width)? as i64
            };
            values.push(raw + references[group] as i64);
        }
    }
    // The spatial differencing: the stored values are the differences, and
    // the smallest of them was taken off all of them before they were
    // stored.
    if drs.template == 3 && drs.differencing > 0 {
        if values.is_empty() {
            return None;
        }
        values[0] = first;
        if drs.differencing == 2 {
            if values.len() < 2 {
                return None;
            }
            values[1] = second;
            for i in 2..values.len() {
                values[i] = values[i] + minimum + 2 * values[i - 1] - values[i - 2];
            }
        } else {
            for i in 1..values.len() {
                values[i] = values[i] + minimum + values[i - 1];
            }
        }
    }
    // The scale factors: the value is (reference + packed * 2^E) / 10^D.
    let scale = pow2(drs.binary_scale);
    let divisor = pow10(drs.decimal_scale);
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        out.push((drs.reference + value as f64 * scale) / divisor);
    }
    Some(out)
}

/// A run of numbers of one width, the way the complex packing stores its
/// group tables.
///
/// The numbers are packed one after another, most significant bit first, and
/// the run ends on an octet boundary: the next table starts at the next
/// octet, not at the next bit. A run whose width is zero holds zeros.
#[cfg(feature = "grib")]
fn read_group_run(reader: &mut BitReader<'_>, bits: u8, count: usize) -> Option<Vec<u64>> {
    let mut out = Vec::with_capacity(count);
    if bits == 0 {
        out.resize(count, 0);
        return Some(out);
    }
    for _ in 0..count {
        out.push(reader.read(bits as u32)?);
    }
    let used = reader.bit % 8;
    if used != 0 {
        reader.read((8 - used) as u32)?;
    }
    Some(out)
}

// -- Spherical harmonics -----------------------------------------------------
//
// Both editions carry the coefficients of a spectrum, and both editions pack
// them the same way: the coefficients the unpacked subset holds are stored
// as they are, and the rest are scaled by the Laplacian operator of their
// wave number and packed as integers. What differs is the arithmetic of the
// floating point -- edition 1's subset is an IBM hex float and edition 2's
// is an IEEE one -- and the unit of the Laplacian factor, which is 10^-3 in
// edition 1 and 10^-6 in edition 2.

/// Everything the reading of a spherical-harmonics field needs.
#[cfg(feature = "grib")]
struct Spectral {
    /// The truncation of the spectrum.
    whole: Truncation,
    /// The truncation of the unpacked subset.
    subset: Truncation,
    /// The Laplacian operator: the factor P of the template, in the unit of
    /// the edition it comes from.
    operator: f64,
    /// Whether the "GRIBEX sh bug" workaround applies: the last line of the
    /// subset of every row was scaled in the file and has to be unscaled.
    bug: bool,
    /// The number of bits each packed coefficient is stored in.
    bits: u8,
    /// The reference value of the packing.
    reference: f64,
    /// The binary and the decimal scale factors.
    binary_scale: i32,
    decimal_scale: i32,
}

/// The values of a spherical-harmonics field.
///
/// `subset` holds the unpacked subset, already decoded, and `packed` the
/// packed part that follows it in the data section.
///
/// The section holds the subset first and the packed part after it: the
/// subset holds the coefficients of the rows up to Ms and of the wave
/// numbers up to Js, as they are, without the Laplacian scale, and the
/// packed part holds the rest of the coefficients, one integer of `bits`
/// bits each. The field puts the two back in the order of code table 3.7:
/// the row `m` from 0 to M, and inside it the wave number `n` from `m` to
/// N(m), each coefficient as its real part followed by its imaginary part.
///
/// The retrieval formula is the one of note 3 of data representation
/// template 5.51:
///
/// ```text
/// Y = (R + X * 2^E) * 10^-D * (n * (n+1))^-p
/// ```
///
/// with X the packed integer, R the reference value, E and D the two scale
/// factors, p the Laplacian operator, and n the wave number of the
/// coefficient -- its degree, not the row it is in.
#[cfg(feature = "grib")]
fn spectral_values(subset: &[f64], packed: &[u8], spec: &Spectral) -> Option<Vec<f64>> {
    let total = spec.whole.values()?;
    let in_subset = spec.subset.values()?;
    if subset.len() != in_subset {
        return None;
    }
    // The truncation numbers are three u32s of the file and the whole-
    // spectrum count is their product: the reservation is ceilinged on
    // the same number edition 1 holds, so a crafted truncation is
    // refused here rather than paid for in gigabytes.
    if total > MAX_GRIB1_VALUES {
        return None;
    }
    let mut values = Vec::with_capacity(total);
    let mut reader = BitReader::new(packed);
    let scale = pow2(spec.binary_scale);
    let divisor = pow10(-spec.decimal_scale);
    let mut at = 0usize;
    for m in 0..=spec.whole.m {
        for n in m..=spec.whole.j {
            if m <= spec.subset.m && n <= spec.subset.j {
                let real = *subset.get(at)?;
                let imag = *subset.get(at + 1)?;
                at += 2;
                // The "GRIBEX sh bug": the last line of the subset of the row
                // was scaled in the file, and the scale is undone here.
                let factor = if spec.bug && n == spec.subset.j {
                    laplacian_scale(n, spec.operator)
                } else {
                    1.0
                };
                values.push(real * factor);
                values.push(imag * factor);
            } else {
                let x = reader.read(spec.bits as u32)?;
                let y = reader.read(spec.bits as u32)?;
                let factor = laplacian_scale(n, spec.operator);
                let real = (spec.reference + x as f64 * scale) * divisor * factor;
                // The imaginary part of the row m = 0 is zero by
                // construction; the file packs it anyway.
                let imag = if m == 0 {
                    0.0
                } else {
                    (spec.reference + y as f64 * scale) * divisor * factor
                };
                values.push(real);
                values.push(imag);
            }
        }
    }
    // Every value the section holds has to be accounted for: the subset is
    // read whole, and the packed part holds exactly the coefficients that
    // are not in it.
    if at != in_subset {
        return None;
    }
    let packed_bits = total
        .checked_sub(in_subset)?
        .checked_mul(spec.bits as usize)?;
    if reader.bit != packed_bits {
        return None;
    }
    Some(values)
}

/// The Laplacian scale of the coefficient of wave number `n`:
/// `(n * (n+1))^(-operator)`.
#[cfg(feature = "grib")]
fn laplacian_scale(n: u32, operator: f64) -> f64 {
    if n == 0 {
        // The wave number zero has no scale -- the operator would divide by
        // zero -- and the coefficient of that wave number is always in the
        // subset, where the scale does not apply.
        return 0.0;
    }
    let wave = f64::from(n);
    1.0 / powf(wave * (wave + 1.0), operator)
}

/// The edition 2 spherical harmonics with the simple packing: data
/// representation template 5.50.
///
/// The field holds the coefficients of the spectrum in the order of code
/// table 3.7. The real part of the (0.0) coefficient is not in the data
/// section: it is in the template, at octets 21-24, because taking it out
/// of the packed values makes them all the smaller. The rest of the values
/// are packed as integers, most significant bit first, and each of them is
/// `(reference + packed * 2^E) * 10^-D`.
#[cfg(feature = "grib")]
fn grib2_spectral_simple(payload: &[u8], drs: &Drs, out: &mut String) -> Option<Vec<f64>> {
    let count = drs.points as usize;
    if count == 0 {
        line!(
            out,
            "  data: template 5.50 simple packing, the template declares no value"
        );
        return None;
    }
    if drs.bits == 0 || drs.bits > 32 {
        line!(
            out,
            "  data: template 5.50 declares {} bits per value; not decodable",
            drs.bits
        );
        return None;
    }
    let needed = count.saturating_sub(1).saturating_mul(drs.bits as usize);
    if payload.len() * 8 < needed {
        line!(
            out,
            "  data: template 5.50 holds {} values, but the section carries only {} bits",
            count,
            payload.len() * 8
        );
        return None;
    }
    let mut reader = BitReader::new(payload);
    let scale = pow2(drs.binary_scale);
    let divisor = pow10(-drs.decimal_scale);
    let mut values = Vec::with_capacity(count);
    values.push(drs.real_part);
    for _ in 1..count {
        let Some(raw) = reader.read(drs.bits as u32) else {
            break;
        };
        values.push((drs.reference + raw as f64 * scale) * divisor);
    }
    line!(
        out,
        "  data: template 5.50 simple packing, {count} values, reference {}, E {}, D {}, {} bits per value",
        drs.reference, drs.binary_scale, drs.decimal_scale, drs.bits
    );
    print_field(out, &values);
    Some(values)
}

/// The edition 2 spherical harmonics with the complex packing: data
/// representation template 5.51.
///
/// The data section holds the unpacked subset first and the packed part
/// after it. The subset holds the coefficients of the rows up to Ms and of
/// the wave numbers up to Js, as IEEE floats, and it is stored without the
/// Laplacian scale. The packed part holds the rest of the coefficients, one
/// integer of `bits` bits each.
#[cfg(feature = "grib")]
fn grib2_spectral_complex(
    payload: &[u8],
    drs: &Drs,
    truncation: Option<&Truncation>,
    out: &mut String,
) -> Option<Vec<f64>> {
    let Some(truncation) = truncation else {
        line!(
            out,
            "  data: template 5.51 complex packing, but the grid is not a spherical harmonics grid, so the number of coefficients is not known"
        );
        return None;
    };
    let Some(in_subset) = drs.subset.values() else {
        line!(
            out,
            "  data: template 5.51 complex packing, but the truncation of the unpacked subset is not triangular (J {}, K {}, M {}, a {} truncation); not decoded",
            drs.subset.j,
            drs.subset.k,
            drs.subset.m,
            truncation_shape(&drs.subset)
        );
        return None;
    };
    if drs.subset_values as usize != in_subset {
        line!(
            out,
            "  data: template 5.51 complex packing declares {} values in the unpacked subset, but its truncation gives {in_subset}; not decoded",
            drs.subset_values
        );
        return None;
    }
    // The precision of the values of the subset (code table 5.7): 1 is the
    // IEEE 32-bit float.
    if drs.precision != 1 {
        line!(
            out,
            "  data: template 5.51 complex packing declares a precision of {} for the unpacked subset; only the IEEE 32-bit one (code table 5.7 number 1) is read",
            drs.precision
        );
        return None;
    }
    // The Laplacian factor the template declares, in units of 10^-6.
    if drs.laplacian == -2147483647 {
        line!(
            out,
            "  data: template 5.51 complex packing declares no Laplacian scaling factor; not decoded"
        );
        return None;
    }
    let operator = f64::from(drs.laplacian) / 1e6;
    let Some(subset_octets) = in_subset.checked_mul(4) else {
        line!(
            out,
            "  data: template 5.51 complex packing, the subset is too large"
        );
        return None;
    };
    let Some(subset_bytes) = payload.get(..subset_octets) else {
        line!(
            out,
            "  data: template 5.51 complex packing holds {} octets, which is not enough for the {in_subset} values of the unpacked subset",
            payload.len()
        );
        return None;
    };
    let subset: Vec<f64> = subset_bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| f32::from_bits(be_u32(c, 0).unwrap_or(0)) as f64)
        .collect();
    let packed = &payload[subset_octets..];
    let spec = Spectral {
        whole: *truncation,
        subset: drs.subset,
        operator,
        bug: false,
        bits: drs.bits,
        reference: drs.reference,
        binary_scale: drs.binary_scale,
        decimal_scale: drs.decimal_scale,
    };
    match spectral_values(&subset, packed, &spec) {
        Some(values) => {
            line!(
                out,
                "  data: template 5.51 complex packing, {} values, the unpacked subset {in_subset} of them, reference {}, E {}, D {}, {} bits per value, Laplacian operator {operator}",
                values.len(),
                drs.reference,
                drs.binary_scale,
                drs.decimal_scale,
                drs.bits
            );
            print_field(out, &values);
            Some(values)
        }
        None => {
            line!(
                out,
                "  data: template 5.51 complex packing, but the section does not hold the values its own parameters say it holds; not decoded"
            );
            None
        }
    }
}

/// The values of a bi-Fourier field.
///
/// Template 5.53 is the bi-Fourier variant of the complex packing, the one
/// the limited area models use. It has its own resolution parameters -- N and
/// M instead of the pentagonal J, K and M of the spherical harmonics -- and
/// its own code tables: the shape of the truncation of the whole field (code
/// table 3.25), the shape of the truncation of the unpacked subset (code
/// table 5.25) and the packing mode for the axes (code table 5.26).
///
/// The section holds the unpacked subset first and the packed part after it.
/// The subset holds the values of the coefficients it covers, as they are,
/// and the packed part holds the rest, one integer of `bits` bits each. The
/// coefficients come in the order of the wave numbers: the row `j` from 0 to
/// M, and inside it the wave number `i` from 0 to the limit of that row, four
/// values to a coefficient.
///
/// The retrieval formula is the one of note 3 of the template:
///
/// ```text
/// Y = (R + X * 2^E) * 10^-D * (i * i + j * j)^-p
/// ```
///
/// with X the packed integer, R the reference value, E and D the two scale
/// factors, p the Laplacian operator, and i and j the two wave numbers of
/// the coefficient.
#[cfg(feature = "grib")]
fn grib2_bifourier_complex(
    payload: &[u8],
    drs: &Drs,
    grid: &Grid<'_>,
    out: &mut String,
) -> Option<Vec<f64>> {
    let Some(geometry) = grid.bi_fourier else {
        line!(
            out,
            "  data: template 5.53 bi-Fourier packing, but the grid is not a bi-Fourier grid, so the number of coefficients is not known"
        );
        return None;
    };
    let Some(packing) = drs.bi_fourier else {
        line!(
            out,
            "  data: template 5.53 bi-Fourier packing, but the section does not carry its own parameters"
        );
        return None;
    };
    // The precision of the values of the subset (code table 5.7): 1 is the
    // IEEE 32-bit float.
    if drs.precision != 1 {
        line!(
            out,
            "  data: template 5.53 bi-Fourier packing declares a precision of {} for the unpacked subset; only the IEEE 32-bit one (code table 5.7 number 1) is read",
            drs.precision
        );
        return None;
    }
    // The Laplacian factor the template declares, in units of 10^-6.
    if drs.laplacian == -2147483647 {
        line!(
            out,
            "  data: template 5.53 bi-Fourier packing declares no Laplacian scaling factor; not decoded"
        );
        return None;
    }
    let Some((rows, _columns)) = bi_fourier_limits(geometry.shape, geometry.n, geometry.m) else {
        line!(
            out,
            "  data: template 5.53 bi-Fourier packing declares a truncation of the shape {} (code table 3.25), which is not known here",
            geometry.shape
        );
        return None;
    };
    let Some((subset_rows, subset_columns)) =
        bi_fourier_limits(packing.subset_shape, packing.subset_n, packing.subset_m)
    else {
        line!(
            out,
            "  data: template 5.53 bi-Fourier packing declares a truncation of the shape {} for the unpacked subset (code table 5.25), which is not known here",
            packing.subset_shape
        );
        return None;
    };
    // The number of values of the field: four to a coefficient.
    let mut total = 0usize;
    for row in rows.iter() {
        if *row < 0 {
            continue;
        }
        total = total.checked_add(4 * (*row as usize + 1))?;
    }
    // The number of values of the unpacked subset.
    let mut in_subset = 0usize;
    for (j, row) in rows.iter().enumerate() {
        if *row < 0 {
            continue;
        }
        for i in 0..=*row {
            if bi_fourier_in_subset(i, j as i64, &packing, &subset_rows, &subset_columns) {
                in_subset = in_subset.checked_add(4)?;
            }
        }
    }
    if packing.subset_values as usize != in_subset {
        line!(
            out,
            "  data: template 5.53 bi-Fourier packing declares {} values in the unpacked subset, but its truncation gives {in_subset}; not decoded",
            packing.subset_values
        );
        return None;
    }
    let subset_octets = in_subset.checked_mul(4)?;
    let Some(subset_bytes) = payload.get(..subset_octets) else {
        line!(
            out,
            "  data: template 5.53 bi-Fourier packing holds {} octets, which is not enough for the {in_subset} values of the unpacked subset",
            payload.len()
        );
        return None;
    };
    let subset: Vec<f64> = subset_bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| f32::from_bits(be_u32(c, 0).unwrap_or(0)) as f64)
        .collect();
    let packed = &payload[subset_octets..];
    let operator = f64::from(drs.laplacian) / 1e6;
    let scale = pow2(drs.binary_scale);
    let divisor = pow10(-drs.decimal_scale);
    let mut reader = BitReader::new(packed);
    let mut values = Vec::with_capacity(total);
    let mut at = 0usize;
    for (j, row) in rows.iter().enumerate() {
        if *row < 0 {
            continue;
        }
        for i in 0..=*row {
            if bi_fourier_in_subset(i, j as i64, &packing, &subset_rows, &subset_columns) {
                for _ in 0..4 {
                    values.push(*subset.get(at)?);
                    at += 1;
                }
            } else {
                // The Laplacian scale of the coefficient: the wave numbers of
                // both of its axes, squared and added.
                let wave = (i * i + j as i64 * j as i64) as f64;
                if wave == 0.0 {
                    // The coefficient of the wave numbers (0,0) is normally
                    // in the unpacked subset, where the scale does not
                    // apply; a subset that leaves it out would ask for a
                    // division by zero.
                    line!(
                        out,
                        "  data: template 5.53 bi-Fourier packing, but the coefficient of the wave numbers (0,0) is packed, and its Laplacian factor would be a division by zero; not decoded"
                    );
                    return None;
                }
                let factor = powf(wave, operator);
                for _ in 0..4 {
                    let x = reader.read(drs.bits as u32)?;
                    values.push((drs.reference + x as f64 * scale) * divisor / factor);
                }
            }
        }
    }
    // Every value the section holds has to be accounted for: the subset is
    // read whole, and the packed part holds exactly the coefficients that
    // are not in it.
    if at != in_subset {
        line!(
            out,
            "  data: template 5.53 bi-Fourier packing, but the section does not hold the values its own parameters say it holds; not decoded"
        );
        return None;
    }
    let packed_bits = total
        .checked_sub(in_subset)?
        .checked_mul(drs.bits as usize)?;
    if reader.bit != packed_bits {
        line!(
            out,
            "  data: template 5.53 bi-Fourier packing, but the section does not hold the values its own parameters say it holds; not decoded"
        );
        return None;
    }
    line!(
        out,
        "  data: template 5.53 bi-Fourier packing, {} values, the unpacked subset {in_subset} of them, reference {}, E {}, D {}, {} bits per value, Laplacian operator {operator}",
        values.len(),
        drs.reference,
        drs.binary_scale,
        drs.decimal_scale,
        drs.bits
    );
    print_field(out, &values);
    Some(values)
}

#[cfg(feature = "grib")]
fn print_values(out: &mut String, values: &[f64], label: &str) {
    if values.is_empty() {
        line!(out, "    {label}: none decoded");
        return;
    }
    line!(out, "    {label}:");
    for v in values {
        line!(out, "      {v}");
    }
}

// -- GRIB edition 1 ---------------------------------------------------------

/// How many values one edition 1 field may hold. The scan that produces the
/// minimum and the maximum walks the whole field, so it needs a ceiling: a
/// header that claims four billion points must not turn into four billion
/// iterations, and a report is not a place to carry them.
#[cfg(feature = "grib")]
const MAX_GRIB1_VALUES: usize = 4_000_000;

/// The edition 1 sections a value decode needs: the product definition
/// section for the decimal scale factor, the grid description for the number
/// of points, the bit map when the field has one, and the binary data
/// section itself.
#[cfg(feature = "grib")]
struct Sections1<'a> {
    pds: Option<&'a [u8]>,
    grid: Option<&'a [u8]>,
    bitmap: Option<&'a [u8]>,
    bds: &'a [u8],
}

/// Edition 1 sections carry a 3-octet length and no section-number octet, so
/// a block cannot name itself. What does identify them is the fixed order the
/// standard mandates: product definition, grid description, an optional bit
/// map, binary data, `7777`. The first block after section 0 is therefore the
/// product definition section and the last one before `7777` is the binary
/// data section — by position, not by guessing at a length.
///
/// The blocks are returned as well, with the offset of each, because the
/// report says where every section is.
#[cfg(feature = "grib")]
fn grib1_sections<'a>(
    data: &'a [u8],
    base: usize,
    out: &mut String,
) -> (Sections1<'a>, Vec<(usize, &'a [u8])>) {
    let mut pos = base + 8; // section 0 is 8 octets in edition 1
    let mut blocks: Vec<(usize, &'a [u8])> = Vec::new();
    let mut ended = false;
    while blocks.len() < MAX_SECTIONS {
        if data.get(pos..pos.saturating_add(4)) == Some(&b"7777"[..]) {
            line!(out, "  section: \"7777\" end marker");
            ended = true;
            break;
        }
        let Some(slen) = be_uint(data, pos, 3).map(|v| v as usize) else {
            line!(out, "  section at offset {pos}: truncated length field");
            break;
        };
        if slen < 4 {
            line!(
                out,
                "  section at offset {pos}: length {slen} is implausible"
            );
            break;
        }
        let Some(next) = pos.checked_add(slen) else {
            break;
        };
        let Some(sec) = data.get(pos..next) else {
            line!(
                out,
                "  section at offset {pos}: length {slen} runs past the end of the file"
            );
            break;
        };
        line!(out, "  section: {slen} octets at offset {pos}");
        blocks.push((pos, sec));
        pos = next;
    }
    // The product definition section's flag octet says which of the two
    // optional sections are in the message (code table 1): bit 1 for the grid
    // description, bit 2 for the bit map. The standard puts them in that
    // order, and that flag is what tells the two apart — without it they are
    // the same octets in the same place, and the grid would be read from a
    // bit map or the other way round.
    let pds = blocks.first().map(|(_, sec)| *sec);
    let flags = pds.and_then(|sec| be_u8(sec, 7)).unwrap_or(0);
    let bds_index = if ended && blocks.len() > 1 {
        Some(blocks.len() - 1)
    } else {
        None
    };
    let mut grid = None;
    let mut bitmap = None;
    if let Some(bds) = bds_index {
        let mut index = 1usize;
        if flags & 0x80 != 0 && index < bds {
            grid = blocks.get(index).map(|(_, sec)| *sec);
            index += 1;
        }
        if flags & 0x40 != 0 && index < bds {
            bitmap = blocks.get(index).map(|(_, sec)| *sec);
        }
    }
    let bds = bds_index
        .and_then(|index| blocks.get(index).map(|(_, sec)| *sec))
        .unwrap_or(&[]);
    (
        Sections1 {
            pds,
            grid,
            bitmap,
            bds,
        },
        blocks,
    )
}

#[cfg(feature = "grib")]
fn grib1(data: &[u8], base: usize, out: &mut String) {
    let (sections, blocks) = grib1_sections(data, base, out);
    let bds_index = if sections.bds.is_empty() {
        None
    } else {
        Some(blocks.len() - 1)
    };
    for (i, (_, sec)) in blocks.iter().enumerate() {
        if i == 0 {
            grib1_pds(sec, out);
        } else if Some(i) == bds_index {
            grib1_bds(&sections, out);
        } else {
            line!(
                out,
                "    grid description or bit map section: {0} octets, not decoded",
                sec.len()
            );
        }
    }
}

#[cfg(feature = "grib")]
fn grib1_pds(sec: &[u8], out: &mut String) {
    // Octets 4 table 2 version, 5 centre, 9 parameter (code table 2),
    // 10 level type (code table 3), 11-12 level, 13-17 year..minute,
    // 26 subcentre, 27-28 decimal scale factor.
    let parameter = be_u8(sec, 8).unwrap_or(0);
    let level_type = be_u8(sec, 9).unwrap_or(0);
    let level = be_u16(sec, 10).unwrap_or(0);
    line!(out, "    product definition section");
    line!(
        out,
        "    centre: {}, parameter: code table 2 number {parameter}, level type {level_type}, level {level}",
        be_u8(sec, 4).unwrap_or(0)
    );
    if sec.len() >= 17 {
        line!(
            out,
            "    reference time: {}-{}-{}-{}:{}",
            be_u8(sec, 12).unwrap_or(0),
            be_u8(sec, 13).unwrap_or(0),
            be_u8(sec, 14).unwrap_or(0),
            be_u8(sec, 15).unwrap_or(0),
            be_u8(sec, 16).unwrap_or(0)
        );
    }
    // The decimal scale factor is the other half of the pair with the binary
    // scale factor in the binary data section: the two together say how a
    // packed integer becomes a value.
    if sec.len() >= 28 {
        line!(
            out,
            "    decimal scale factor D {}",
            sign_magnitude(sec, 26, 2).unwrap_or(0)
        );
    }
    line!(
        out,
        "    edition 1 code table 2 parameter names: not shipped (the master table is a separate WMO data file)"
    );
}

/// The edition 1 binary data section header. Octet 4 is the code table 11
/// flag: bit 1 grid point or spectral, bit 2 simple or complex packing, bit 3
/// float or integer, bit 4 additional flags; the low nibble is the number of
/// unused bits at the end of the section. Octets 5-6 are the binary scale
/// factor, 7-10 the reference value in IBM hex float, octet 11 the number of
/// bits per packed value.
///
/// The reference value is an IBM 360 hexadecimal float, which is what the
/// section has always said and what the ECMWF files in `testdata/grib`
/// hold: decoded as IBM they are surface temperatures in kelvin, decoded as
/// IEEE they are temperatures no surface reaches.
#[cfg(feature = "grib")]
fn grib1_bds(sec: &Sections1, out: &mut String) {
    let bds = sec.bds;
    if bds.len() < 11 {
        line!(
            out,
            "    binary data section: only {} octets, header not readable",
            bds.len()
        );
        return;
    }
    let flag = be_u8(bds, 3).unwrap_or(0);
    let data_kind = if flag & 0x80 != 0 {
        "spectral"
    } else {
        "grid point"
    };
    let packing = if flag & 0x40 != 0 {
        "complex"
    } else {
        "simple"
    };
    let representation = if flag & 0x20 != 0 { "integer" } else { "float" };
    let unused = flag & 0x0f;
    let e = sign_magnitude(bds, 4, 2).unwrap_or(0);
    let reference = be_u32(bds, 6).map(ibm_float).unwrap_or(0.0);
    let bits = be_u8(bds, 10).unwrap_or(0);
    line!(out, "    binary data section");
    line!(
        out,
        "    code table 11 flag: {data_kind} data, {packing} packing, {representation} values, {unused} unused bits at end"
    );
    line!(
        out,
        "    binary scale factor E {e}, reference value {reference}, {bits} bits per value"
    );
    grib1_values(sec, flag, e, reference, bits, out);
}

/// The packed values of an edition 1 field.
///
/// Simple packing is one unsigned integer per value, most significant bit
/// first, and the value is `(reference + packed * 2^E) / 10^D`, with E the
/// binary scale factor of the binary data section and D the decimal scale
/// factor of the product definition section.
///
/// The number of values is written nowhere in an edition 1 message: it is the
/// number of grid points the grid description names. That is why the count
/// is checked against the bits the section actually holds before a single
/// number is printed. A count that does not add up means the section is not
/// the layout this reader knows, and a number read from a layout that is not
/// known is a guess.
#[cfg(feature = "grib")]
fn grib1_values(sec: &Sections1, flag: u8, e: i32, reference: f64, bits: u8, out: &mut String) {
    let Some(grid) = sec.grid else {
        line!(
            out,
            "    packed values: not decoded (the message has no grid description section, so the number of values is not known)"
        );
        return;
    };
    let rep = be_u8(grid, 5).unwrap_or(255);
    if rep == 50 || flag & 0x80 != 0 {
        // The truncation parameters: the pentagonal resolution of the
        // triangle the coefficients belong to. They are three fields of two
        // octets in the grid description, and they are what says how many
        // coefficients the section holds.
        let j = be_u16(grid, 6).unwrap_or(0);
        let k = be_u16(grid, 8).unwrap_or(0);
        let m = be_u16(grid, 10).unwrap_or(0);
        line!(
            out,
            "    grid: type {rep} ({}), truncation J {j}, K {k}, M {m}",
            grib1_grid_type_name(rep)
        );
        if let Some(values) = grib1_spectral(sec, grib1_truncation(grid), out) {
            line!(out, "    packed values: {} values", values.len());
            print_field(out, &values);
        }
        return;
    }
    let ni = be_u16(grid, 6).unwrap_or(0);
    let nj = be_u16(grid, 8).unwrap_or(0);
    if ni == 0xffff {
        line!(
            out,
            "    grid: type {rep} ({}), reduced grid",
            grib1_grid_type_name(rep)
        );
        line!(
            out,
            "    packed values: not decoded (a reduced grid keeps its points per row in a list, which is not read here)"
        );
        return;
    }
    let Some(points) = (ni as usize).checked_mul(nj as usize) else {
        line!(
            out,
            "    grid: type {rep} ({}), the point count overflows",
            grib1_grid_type_name(rep)
        );
        line!(
            out,
            "    packed values: not decoded (the grid names more points than can be counted)"
        );
        return;
    };
    line!(
        out,
        "    grid: type {rep} ({}), {ni} x {nj} = {points} points",
        grib1_grid_type_name(rep)
    );
    // The refusals. A number printed from a layout this reader has not
    // established is worse than no number at all.
    if flag & 0x40 != 0 {
        // The second-order packing: the values of a group are stored as
        // differences, and octet 14 says which of the layouts of that
        // packing this section is. The flags are read so that the refusal
        // names the layout instead of the packing in general.
        let extended = be_u8(sec.bds, 13).unwrap_or(0);
        line!(out, "    octet 14 flags: {}", grib1_octet14_flags(extended));
        line!(
            out,
            "    packed values: not decoded (second-order packing: the values are stored as differences inside groups of one width each, and the groups are not decoded here)"
        );
        return;
    }
    if flag & 0x10 != 0 {
        line!(
            out,
            "    packed values: not decoded (octet 14 carries additional flags, so the section is not the one-value-per-point layout)"
        );
        return;
    }
    let packed = sec.bds.get(11..).unwrap_or(&[]);
    let budget = packed
        .len()
        .saturating_mul(8)
        .saturating_sub((flag & 0x0f) as usize);
    let d = sec
        .pds
        .and_then(|pds| sign_magnitude(pds, 26, 2))
        .unwrap_or(0);
    if bits == 0 {
        // A constant field: nothing is packed, every point holds the
        // reference value.
        if budget != 0 {
            line!(
                out,
                "    packed values: not decoded (the section declares no bits per value but holds {budget} bits)"
            );
            return;
        }
        line!(out, "    packed values: {points} values, all {reference}");
        return;
    }
    if bits > 32 {
        line!(
            out,
            "    packed values: not decoded ({bits} bits per value: only 1 to 32 bits are read)"
        );
        return;
    }
    if budget % bits as usize != 0 {
        line!(
            out,
            "    packed values: not decoded (the section holds {budget} bits, which is not a whole number of {bits}-bit values)"
        );
        return;
    }
    let count = budget / bits as usize;
    if let Some(bitmap) = sec.bitmap {
        // A bit map says which points carry a value; the packed data holds
        // exactly those, in the order the map marks them.
        let Some(map) = grib1_bitmap(bitmap, points) else {
            line!(
                out,
                "    packed values: not decoded (the bit map section is too short to hold {points} points)"
            );
            return;
        };
        let coded = map.iter().filter(|present| **present).count();
        line!(out, "    bit map: {coded} of {points} points carry a value");
        if coded != count {
            line!(
                out,
                "    packed values: not decoded (the bit map marks {coded} points but the section holds {count} values)"
            );
            return;
        }
    } else if count != points {
        line!(
            out,
            "    packed values: not decoded (the grid names {points} points but the section holds {count} values)"
        );
        return;
    }
    let scale = pow2(e);
    let divisor = pow10(d);
    let mut reader = BitReader::new(packed);
    let mut values: Vec<f64> = Vec::new();
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    let read = count.min(MAX_GRIB1_VALUES);
    for _ in 0..read {
        let Some(raw) = reader.read(bits as u32) else {
            break;
        };
        let value = (reference + raw as f64 * scale) / divisor;
        if value < min {
            min = value;
        }
        if value > max {
            max = value;
        }
        if values.len() < MAX_VALUES {
            values.push(value);
        }
    }
    if read < count {
        line!(
            out,
            "    packed values: {count} values (the first {read} were read)"
        );
    } else {
        line!(out, "    packed values: {count} values");
    }
    if values.is_empty() {
        line!(out, "    value range: none (the section holds no values)");
        return;
    }
    line!(out, "    value range: minimum {min}, maximum {max}");
    print_values(out, &values, "first values");
}

/// The truncation of an edition 1 spherical-harmonics grid: the pentagonal
/// resolution parameters J, K and M of the grid description, at octets 7-12.
#[cfg(feature = "grib")]
fn grib1_truncation(grid: &[u8]) -> Truncation {
    Truncation {
        j: u32::from(be_u16(grid, 6).unwrap_or(0)),
        k: u32::from(be_u16(grid, 8).unwrap_or(0)),
        m: u32::from(be_u16(grid, 10).unwrap_or(0)),
    }
}

/// The edition 1 spherical-harmonics field: the complex spectral packing.
///
/// The binary data section holds the header of octets 1-18 and then the
/// data. The header's octets 12-18 are the ones this packing adds: N, the
/// pointer to the packed data, P, the Laplacian scaling factor, and JS, KS
/// and MS, the truncation of the unpacked subset.
///
/// The data holds the unpacked subset first and the packed part after it.
/// The subset holds the coefficients of the rows up to MS and of the wave
/// numbers up to JS, as IBM hex floats of four octets each, and it is
/// stored without the Laplacian scale. The packed part holds the rest of
/// the coefficients, one integer of `bits` bits each, in the same order.
///
/// The "GRIBEX sh bug" is a quirk of the files GRIBEX wrote: the last line
/// of the subset of every row was scaled there, and the scale is undone
/// here.
#[cfg(feature = "grib")]
fn grib1_spectral(sec: &Sections1, truncation: Truncation, out: &mut String) -> Option<Vec<f64>> {
    let bds = sec.bds;
    // The header of the binary data section: the code table 11 flag at
    // octet 4, the binary scale factor at 5-6, the reference value at 7-10
    // and the number of bits per value at 11.
    let flag = be_u8(bds, 3).unwrap_or(0);
    let e = sign_magnitude(bds, 4, 2).unwrap_or(0);
    let reference = be_u32(bds, 6).map(ibm_float).unwrap_or(0.0);
    let bits = be_u8(bds, 10).unwrap_or(0);
    // The representation mode of the grid description (code table 10): 1 is
    // the simple packing, 2 the complex one this reader reads, 3 the IEEE
    // one.
    match sec.grid.and_then(|grid| be_u8(grid, 13)).unwrap_or(0) {
        0 | 2 => {}
        1 => {
            line!(
                out,
                "    packed values: not decoded (the spherical harmonics with the simple packing: the coefficients are packed one integer each, and the real part of the (0.0) coefficient is in the header of the section instead of in an unpacked subset)"
            );
            return None;
        }
        3 => {
            line!(
                out,
                "    packed values: not decoded (the spherical harmonics with the IEEE packing: the unpacked subset of that variant holds IEEE floats, and this reader reads the IBM ones)"
            );
            return None;
        }
        other => {
            line!(
                out,
                "    packed values: not decoded (the spherical harmonics with a representation mode of {other}: code table 10 knows the simple, the complex and the IEEE packings)"
            );
            return None;
        }
    }
    // The header's octets 12-18. N is the pointer the file gives to the
    // packed data; the packed part is found by its own count here, because
    // the pointer is not stated the same way by every file.
    let n = be_u16(bds, 11).unwrap_or(0);
    let p = sign_magnitude(bds, 13, 2).unwrap_or(0);
    let subset = Truncation {
        j: u32::from(be_u8(bds, 15).unwrap_or(0)),
        k: u32::from(be_u8(bds, 16).unwrap_or(0)),
        m: u32::from(be_u8(bds, 17).unwrap_or(0)),
    };
    line!(
        out,
        "    spectral: the pointer to the packed data N {n}, the Laplacian factor {p}, the unpacked subset J {}, K {}, M {}",
        subset.j, subset.k, subset.m
    );
    if p == -32767 {
        line!(
            out,
            "    packed values: not decoded (the section declares no Laplacian scaling factor)"
        );
        return None;
    }
    let Some(total) = truncation.values() else {
        line!(
            out,
            "    packed values: not decoded (the truncation is not triangular: J {}, K {}, M {}; its shape is {}, and this reader reads the triangular one only)",
            truncation.j,
            truncation.k,
            truncation.m,
            truncation_shape(&truncation)
        );
        return None;
    };
    let Some(in_subset) = subset.values() else {
        line!(
            out,
            "    packed values: not decoded (the truncation of the unpacked subset is not triangular: J {}, K {}, M {}, a {} truncation)",
            subset.j,
            subset.k,
            subset.m,
            truncation_shape(&subset)
        );
        return None;
    };
    // The data area: the unpacked subset first, the packed part after it.
    let data = bds.get(18..).unwrap_or(&[]);
    let Some(subset_octets) = in_subset.checked_mul(4) else {
        line!(
            out,
            "    packed values: not decoded (the subset is too large)"
        );
        return None;
    };
    let Some(subset_bytes) = data.get(..subset_octets) else {
        line!(
            out,
            "    packed values: not decoded (the section holds {} octets of data, which is not enough for the {in_subset} values of the unpacked subset)",
            data.len()
        );
        return None;
    };
    let subset_values: Vec<f64> = subset_bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| ibm_float(be_u32(c, 0).unwrap_or(0)))
        .collect();
    let packed = &data[subset_octets..];
    // The bits the section holds have to be the bits the values need. A
    // count that does not add up means the section is not the layout this
    // reader knows.
    let Some(needed) = total
        .checked_sub(in_subset)
        .and_then(|count| count.checked_mul(bits as usize))
    else {
        line!(out, "    packed values: not decoded (the counts overflow)");
        return None;
    };
    let unused = usize::from(flag & 0x0f);
    if data.len() * 8 != subset_octets * 8 + needed + unused {
        line!(
            out,
            "    packed values: not decoded (the section holds {} bits of data, and the values it declares need {} bits)",
            data.len() * 8,
            subset_octets * 8 + needed + unused
        );
        return None;
    }
    let Some(packed) = packed.get(..needed.div_ceil(8)) else {
        line!(
            out,
            "    packed values: not decoded (the section holds fewer octets than the values it declares need)"
        );
        return None;
    };
    let d = sec
        .pds
        .and_then(|pds| sign_magnitude(pds, 26, 2))
        .unwrap_or(0);
    let spec = Spectral {
        whole: truncation,
        subset,
        // The Laplacian factor of edition 1 is in units of 10^-3, and the one
        // of edition 2 in units of 10^-6.
        operator: f64::from(p) / 1000.0,
        bug: true,
        bits,
        reference,
        binary_scale: e,
        decimal_scale: d,
    };
    match spectral_values(&subset_values, packed, &spec) {
        Some(values) => Some(values),
        None => {
            line!(
                out,
                "    packed values: not decoded (the section does not hold the values its own parameters say it holds)"
            );
            None
        }
    }
}

/// The edition 1 bit map: one bit per grid point, 1 where the point carries a
/// value and 0 where it is missing, with the section's trailing unused bits at
/// the end. Octets 1-3 are the section length, octet 4 the number of unused
/// bits and octets 5-6 the table reference.
/// What the extra flags of octet 14 say (code table 11-2).
///
/// A section that packs its values with the second-order packing says in
/// octet 14 which of the several layouts of that packing it is, and the
/// order of the spatial differencing is in the last two bits.
#[cfg(feature = "grib")]
fn grib1_octet14_flags(flags: u8) -> String {
    let mut out = Vec::new();
    out.push(if flags & 0x40 != 0 {
        "a matrix of values at each grid point"
    } else {
        "a single datum at each grid point"
    });
    if flags & 0x20 != 0 {
        out.push("a secondary bit map");
    }
    out.push(if flags & 0x10 != 0 {
        "second-order values of different widths"
    } else {
        "second-order values of one width"
    });
    if flags & 0x08 != 0 {
        out.push("the general extended packing");
    }
    out.push(if flags & 0x04 != 0 {
        "boustrophedonic ordering"
    } else {
        "the standard ordering"
    });
    out.push(match flags & 0x03 {
        0 => "no spatial differencing",
        1 => "the first order of the spatial differencing",
        2 => "the second order of the spatial differencing",
        _ => "the third order of the spatial differencing",
    });
    out.join(", ")
}

#[cfg(feature = "grib")]
fn grib1_bitmap(bms: &[u8], points: usize) -> Option<Vec<bool>> {
    if bms.len() < 7 {
        return None;
    }
    let unused = be_u8(bms, 3)? as usize;
    let map_bits = bms
        .len()
        .saturating_sub(6)
        .saturating_mul(8)
        .saturating_sub(unused);
    if map_bits < points {
        return None;
    }
    let body = bms.get(6..)?;
    let mut map = Vec::with_capacity(points);
    for i in 0..points {
        let byte = body.get(i / 8)?;
        map.push((byte >> (7 - i % 8)) & 1 == 1);
    }
    Some(map)
}

/// The edition 1 grid representation types, from the ECMWF code table 6. A
/// type with no name here is reported by number alone: inventing a name for
/// it would be worse than saying nothing.
#[cfg(feature = "grib")]
fn grib1_grid_type_name(t: u8) -> &'static str {
    match t {
        0 => "lat/lon",
        1 => "Mercator",
        3 => "Lambert conformal",
        4 => "Gaussian",
        5 => "polar stereographic",
        6 => "UTM",
        7 => "simple polyconic",
        8 => "Albers equal area",
        10 => "rotated lat/lon",
        14 => "rotated Gaussian",
        20 => "stretched lat/lon",
        24 => "stretched Gaussian",
        30 => "stretched rotated lat/lon",
        34 => "stretched rotated Gaussian",
        50 => "spherical harmonics",
        60 => "rotated spherical harmonics",
        70 => "stretched spherical harmonics",
        80 => "stretched rotated spherical harmonics",
        90 => "space view",
        _ => "grid type with no transcribed name",
    }
}

// -- GRIB2 code tables ------------------------------------------------------
//
// Names transcribed from the NCEP GRIB2 code table 4.1/4.2 pages. A
// discipline/category/number with no entry here is reported by number alone;
// inventing a name for it would be worse than saying nothing.

#[cfg(feature = "grib")]
fn discipline_name(discipline: u8) -> &'static str {
    match discipline {
        0 => "meteorological products",
        1 => "hydrologic products",
        2 => "land surface products",
        3 => "satellite remote sensing products",
        10 => "oceanographic products",
        20 => "health and socioeconomic impacts",
        191 => "computational parameters",
        _ => "unknown discipline",
    }
}

#[cfg(feature = "grib")]
fn category_name(discipline: u8, category: u8) -> &'static str {
    if discipline != 0 {
        return "category outside the meteorological discipline";
    }
    match category {
        0 => "temperature",
        1 => "moisture",
        2 => "momentum",
        3 => "mass",
        4 => "shortwave radiation",
        5 => "longwave radiation",
        6 => "cloud",
        7 => "thermodynamic stability indices",
        13 => "aerosols",
        15 => "radar",
        16 => "forecast radar imagery",
        17 => "electrodynamics",
        18 => "nuclear/radiology",
        19 => "physical atmospheric properties",
        21 => "thermodynamic properties",
        22 => "drought indices",
        190 => "CCITT IA5 string",
        191 => "miscellaneous",
        _ => "category with no transcribed name",
    }
}

/// Code table 4.2, discipline 0 category 0 (temperature).
#[cfg(feature = "grib")]
const PARAMS_MET_TEMPERATURE: &[(u8, &str)] = &[
    (0, "Temperature"),
    (1, "Virtual Temperature"),
    (2, "Potential Temperature"),
    (3, "Pseudo-Adiabatic Potential Temperature"),
    (4, "Maximum Temperature"),
    (5, "Minimum Temperature"),
    (6, "Dew Point Temperature"),
    (7, "Dew Point Depression"),
    (8, "Lapse Rate"),
    (9, "Temperature Anomaly"),
    (10, "Latent Heat Net Flux"),
    (11, "Sensible Heat Net Flux"),
    (12, "Heat Index"),
    (13, "Wind Chill Factor"),
    (14, "Minimum Dew Point Depression"),
    (15, "Virtual Potential Temperature"),
    (16, "Snow Phase Change Heat Flux"),
    (17, "Skin Temperature"),
    (18, "Snow Temperature"),
    (19, "Turbulent Transfer Coefficient for Heat"),
    (20, "Turbulent Diffusion Coefficient for Heat"),
    (21, "Apparent Temperature"),
    (22, "Temperature Tendency due to Shortwave Radiation"),
    (23, "Temperature Tendency due to Longwave Radiation"),
    (
        24,
        "Temperature Tendency due to Shortwave Radiation, Clear Sky",
    ),
    (
        25,
        "Temperature Tendency due to Longwave Radiation, Clear Sky",
    ),
    (26, "Temperature Tendency due to parameterizations"),
    (27, "Wet-Bulb Temperature"),
    (28, "Unbalanced Component of Temperature"),
    (29, "Temperature Advection"),
    (30, "Latent Heat Net Flux Due to Evaporation"),
    (31, "Latent Heat Net Flux Due to Sublimation"),
    (32, "Wet-Bulb Potential Temperature"),
];

/// Code table 4.2, discipline 0 category 1 (moisture). Entries 63 and 89 are
/// reserved in the table and are deliberately absent.
#[cfg(feature = "grib")]
const PARAMS_MET_MOISTURE: &[(u8, &str)] = &[
    (0, "Specific Humidity"),
    (1, "Relative Humidity"),
    (2, "Humidity Mixing Ratio"),
    (3, "Precipitable Water"),
    (4, "Vapor Pressure"),
    (5, "Saturation Deficit"),
    (6, "Evaporation"),
    (7, "Precipitation Rate"),
    (8, "Total Precipitation"),
    (9, "Large-Scale Precipitation"),
    (10, "Convective Precipitation"),
    (11, "Snow Depth"),
    (12, "Snowfall Rate Water Equivalent"),
    (13, "Water Equivalent of Accumulated Snow Depth"),
    (14, "Convective Snow"),
    (15, "Large-Scale Snow"),
    (16, "Snow Melt"),
    (17, "Snow Age"),
    (18, "Absolute Humidity"),
    (19, "Precipitation Type"),
    (20, "Integrated Liquid Water"),
    (21, "Total Condensate"),
    (22, "Cloud Mixing Ratio"),
    (23, "Ice Water Mixing Ratio"),
    (24, "Rain Mixing Ratio"),
    (25, "Snow Mixing Ratio"),
    (26, "Horizontal Moisture Convergence"),
    (27, "Maximum Relative Humidity"),
    (28, "Maximum Absolute Humidity"),
    (29, "Total Snowfall"),
    (30, "Precipitable Water Category"),
    (31, "Hail"),
    (32, "Graupel"),
    (33, "Categorical Rain"),
    (34, "Categorical Freezing Rain"),
    (35, "Categorical Ice Pellets"),
    (36, "Categorical Snow"),
    (37, "Convective Precipitation Rate"),
    (38, "Horizontal Moisture Divergence"),
    (39, "Percent frozen precipitation"),
    (40, "Potential Evaporation"),
    (41, "Potential Evaporation Rate"),
    (42, "Snow Cover"),
    (43, "Rain Fraction of Total Cloud Water"),
    (44, "Rime Factor"),
    (45, "Total Column Integrated Rain"),
    (46, "Total Column Integrated Snow"),
    (47, "Large Scale Water Precipitation"),
    (48, "Convective Water Precipitation"),
    (49, "Total Water Precipitation"),
    (50, "Total Snow Precipitation"),
    (51, "Total Column Water"),
    (52, "Total Precipitation Rate"),
    (53, "Total Snowfall Rate Water Equivalent"),
    (54, "Large Scale Precipitation Rate"),
    (55, "Convective Snowfall Rate Water Equivalent"),
    (56, "Large Scale Snowfall Rate Water Equivalent"),
    (57, "Total Snowfall Rate"),
    (58, "Convective Snowfall Rate"),
    (59, "Large Scale Snowfall Rate"),
    (60, "Snow Depth Water Equivalent"),
    (61, "Snow Density"),
    (62, "Snow Evaporation"),
    (64, "Total Column Integrated Water Vapor"),
    (65, "Rain Precipitation Rate"),
    (66, "Snow Precipitation Rate"),
    (67, "Freezing Rain Precipitation Rate"),
    (68, "Ice Pellets Precipitation Rate"),
    (69, "Total Column Integrated Cloud Water"),
    (70, "Total Column Integrated Cloud Ice"),
    (71, "Hail Mixing Ratio"),
    (72, "Total Column Integrated Hail"),
    (73, "Hail Precipitation Rate"),
    (74, "Total Column Integrated Graupel"),
    (75, "Graupel (Snow Pellets) Precipitation Rate"),
    (76, "Convective Rain Rate"),
    (77, "Large-Scale Rain Rate"),
    (78, "Total Column Integrated Water"),
    (79, "Evaporation Rate"),
    (80, "Total Condensate"),
    (81, "Total Column Integrated Condensate"),
    (82, "Cloud Ice Mixing Ratio"),
    (83, "Specific Cloud Liquid Water Content"),
    (84, "Specific Cloud Ice Water Content"),
    (85, "Specific Rain Water Content"),
    (86, "Specific Snow Water Content"),
    (87, "Stratiform Precipitation Rate"),
    (88, "Categorical Convective Precipitation"),
    (90, "Total Kinematic Moisture Flux"),
    (91, "U-Component (Zonal) Kinematic Moisture Flux"),
    (92, "V-Component (Meridional) Kinematic Moisture Flux"),
    (93, "Relative Humidity With Respect to Water"),
    (94, "Relative Humidity With Respect to Ice"),
    (95, "Freezing or Frozen Precipitation Rate"),
    (96, "Mass Density of Rain"),
    (97, "Mass Density of Snow"),
    (98, "Mass Density of Graupel"),
    (99, "Mass Density of Hail"),
    (100, "Specific Number Concentration of Rain"),
    (101, "Specific Number Concentration of Snow"),
    (102, "Specific Number Concentration of Graupel"),
    (143, "Potential evaporation rate"),
    (198, "Minimum Relative Humidity"),
    (199, "Potential Evaporation"),
    (200, "Potential Evaporation Rate"),
    (201, "Snow Cover"),
    (225, "Freezing Rain"),
    (227, "Frozen Rain"),
    (231, "Precipitation Potential Index"),
    (241, "Total Snow"),
    (242, "Relative Humidity with Respect to Precipitable Water"),
    (
        245,
        "Hourly Maximum of Column Vertical Integrated Graupel on Entire Atmosphere",
    ),
];

#[cfg(feature = "grib")]
fn parameter_name(discipline: u8, category: u8, number: u8) -> Option<&'static str> {
    if discipline != 0 {
        return None;
    }
    let table = match category {
        0 => PARAMS_MET_TEMPERATURE,
        1 => PARAMS_MET_MOISTURE,
        _ => return None,
    };
    table
        .iter()
        .find(|(n, _)| *n == number)
        .map(|(_, name)| *name)
}

// ===========================================================================
// BUFR — WMO FM 94-BUFR message header
// ===========================================================================

/// BUFR meteorological messages, edition 2/3/4. Reports the section 0 header
/// and the `7777` terminator.
///
/// The mnemonics a BUFR file is really about — Table B entries and Table D
/// operator descriptors such as `001001` or `201001` — resolve to names only
/// through the WMO master tables, which are a separate data file rgx does not
/// ship, and the section 4 data is a bit stream whose layout depends on those
/// same tables. Naming them here would mean shipping a partial, unversioned
/// copy of a WMO data file; the descriptor numbers themselves stay in the
/// bytes and ripgrep can already match them.
#[cfg(feature = "bufr")]
pub struct Bufr;

#[cfg(feature = "bufr")]
impl Adapter for Bufr {
    fn name(&self) -> &'static str {
        "bufr"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["bufr", "bufr4"]
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !data.starts_with(b"BUFR") {
            decline!("no BUFR indicator at offset 0");
        }
        let mut out = String::new();
        // Section 0 is four indicator octets, a three-octet total length and
        // the edition number.
        let Some(length) = be_uint(data, 4, 3).map(|v| v as usize) else {
            bail!("BUFR indicator present but the section 0 length is truncated");
        };
        let Some(edition) = be_u8(data, 7) else {
            bail!("BUFR indicator present but there is no edition octet");
        };
        line!(out, "bufr edition {edition}");
        line!(out, "  section 0 declares {length} bytes");
        match data.get(4..length) {
            Some(_) => {}
            None => {
                line!(
                    out,
                    "  the declared length runs past the {} bytes in the file: truncated",
                    data.len()
                );
                return Ok(Outcome::Text(out.into_bytes()));
            }
        }
        let tail = length - 4;
        match data.get(tail..tail.saturating_add(4)) {
            Some(b"7777") => line!(out, "  terminator: \"7777\" present at the declared end"),
            _ => line!(
                out,
                "  terminator: no \"7777\" at the declared end of the message"
            ),
        }
        line!(
            out,
            "  sections 1-5, Table B entries and Table D operators: not decoded"
        );
        line!(
            out,
            "  the mnemonics resolve only through the WMO master tables, which rgx does not ship"
        );
        Ok(Outcome::Text(out.into_bytes()))
    }
}

// ===========================================================================
// SEG-Y
// ===========================================================================

/// SEG-Y seismic reflection data. The 3200-byte textual header is IBM EBCDIC
/// CP037 in the standard and in most files written since 1975; reading it as
/// ASCII is the format's best-known trap, and it is what a `.sgy` search
/// would silently miss.
#[cfg(feature = "segy")]
pub struct Segy;

#[cfg(feature = "segy")]
impl Adapter for Segy {
    fn name(&self) -> &'static str {
        "segy"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["sgy", "seg", "segy"]
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // The textual header is the part every writer produces, so it is
        // what the signature rests on. A file cut short before the binary
        // header is still a SEG-Y and is reported with the fields it does
        // have, rather than dropped from the search.
        if data.len() < 3200 {
            decline!(
                "only {} bytes: a SEG-Y file needs a 3200-byte textual header",
                data.len()
            );
        }
        let Some(textual) = data.get(..3200) else {
            decline!("no 3200-byte textual header");
        };
        // A SEG-Y binary header that carries its own little-endian marker
        // reversed, or a revision of zero, is still a SEG-Y. The textual
        // header is the only part every writer produces, so it is what the
        // signature rests on: the card column ("C 1", "C10", ...) in whichever
        // of the two encodings it turns out to be.
        if !looks_like_segy_header(textual) {
            decline!("the 3200-byte textual header is neither EBCDIC nor ASCII SEG-Y cards");
        }

        let mut out = String::new();
        out.push_str("seg-y\n");
        let ebcdic = !textual_is_ascii(textual);
        line!(
            out,
            "text header: 3200 bytes, {}",
            if ebcdic { "IBM EBCDIC CP037" } else { "ASCII" }
        );
        for card in textual_cards(textual, ebcdic) {
            line!(out, "  {card}");
        }

        let binary = data.get(3200..3600).unwrap_or(&[]);
        line!(out, "binary header:");
        line!(out, "  job id: {}", be_i32(binary, 0).unwrap_or(0));
        line!(out, "  line number: {}", be_i32(binary, 4).unwrap_or(0));
        line!(out, "  reel number: {}", be_i32(binary, 8).unwrap_or(0));
        let per_ensemble = be_u16(binary, 12).unwrap_or(0);
        line!(out, "  data traces per ensemble: {per_ensemble}");
        let interval = be_u16(binary, 16).unwrap_or(0);
        let samples = be_u16(binary, 20).unwrap_or(0);
        line!(out, "  sample interval: {interval} us");
        line!(out, "  samples per trace: {samples}");
        let format = be_u16(binary, 24).unwrap_or(0);
        line!(
            out,
            "  sample format: {format} ({})",
            sample_format_name(format)
        );
        line!(out, "  ensemble fold: {}", be_u16(binary, 26).unwrap_or(0));
        let sorting = be_i16(binary, 28).unwrap_or(0);
        line!(
            out,
            "  trace sorting: {sorting} ({})",
            trace_sorting_name(sorting)
        );
        // Octets 97-100 hold 0x01020304 in the file's byte order; a different
        // value is how a writer declares that every integer in the header is
        // byte-swapped, which is worth surfacing rather than guessing at.
        match be_u32(binary, 96) {
            Some(0x0102_0304) => line!(out, "  byte order: big endian"),
            Some(0x0403_0201) => line!(out, "  byte order: little endian (declared by the marker)"),
            Some(v) => line!(
                out,
                "  byte order marker: {v:#010x} (neither 0x01020304 nor 0x04030201)"
            ),
            None => line!(out, "  byte order marker: absent"),
        }
        line!(
            out,
            "  format revision: {}.{}",
            be_u8(binary, 300).unwrap_or(0),
            be_u8(binary, 301).unwrap_or(0)
        );
        let extended = be_u16(binary, 302).unwrap_or(0);
        if extended > 0 {
            line!(out, "  extended textual records: {extended}");
        }

        // Traces start after the binary header and the optional extended
        // textual records; the sample width comes from the sample format.
        let data_start = 3600usize + extended as usize * 3200;
        let width = sample_width(format);
        match width {
            0 => line!(
                out,
                "traces: sample format {format} has no known byte width; trace headers not located"
            ),
            w => {
                line!(
                    out,
                    "trace headers (240 bytes each, {w} bytes of samples between them):"
                );
                let mut pos = data_start;
                let mut n = 0usize;
                while n < MAX_TRACES {
                    let Some(header) = data.get(pos..pos.saturating_add(240)) else {
                        line!(
                            out,
                            "  trace {}: header runs past the end of the file",
                            n + 1
                        );
                        break;
                    };
                    if header.iter().all(|&b| b == 0) && pos >= data.len() - 240 {
                        break;
                    }
                    trace_header(header, n + 1, &mut out);
                    n += 1;
                    pos = match pos.checked_add(240 + w * samples as usize) {
                        Some(p) => p,
                        None => break,
                    };
                }
                line!(out, "  {} trace header(s) reported", n);
            }
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(any(feature = "root", feature = "segy"))]
fn be_i32(data: &[u8], off: usize) -> Option<i32> {
    be_u32(data, off).map(|v| v as i32)
}

#[cfg(feature = "segy")]
fn be_i16(data: &[u8], off: usize) -> Option<i16> {
    be_u16(data, off).map(|v| v as i16)
}

#[cfg(feature = "segy")]
fn sample_format_name(code: u16) -> &'static str {
    match code {
        1 => "4-byte IBM floating-point",
        2 => "4-byte two's complement integer",
        3 => "2-byte two's complement integer",
        4 => "4-byte fixed-point with gain",
        5 => "4-byte IEEE floating-point",
        6 => "8-byte IEEE floating-point",
        7 => "3-byte two's complement integer",
        8 => "1-byte two's complement integer",
        9 => "8-byte two's complement integer",
        10 => "4-byte unsigned integer",
        11 => "2-byte unsigned integer",
        12 => "8-byte unsigned integer",
        15 => "3-byte unsigned integer",
        16 => "1-byte unsigned integer",
        _ => "not a sample format code in the SEG-Y revision 2 table",
    }
}

#[cfg(feature = "segy")]
fn sample_width(code: u16) -> usize {
    match code {
        1 | 2 | 4 | 5 | 10 => 4,
        3 | 11 => 2,
        6 | 9 | 12 => 8,
        7 | 15 => 3,
        8 | 16 => 1,
        _ => 0,
    }
}

#[cfg(feature = "segy")]
fn trace_sorting_name(code: i16) -> &'static str {
    match code {
        -1 => "other",
        0 => "unknown",
        1 => "as recorded",
        2 => "CDP ensemble",
        3 => "single fold continuous profile",
        4 => "horizontally stacked",
        5 => "common source point",
        6 => "common receiver point",
        7 => "common offset point",
        8 => "common mid-point",
        9 => "common conversion point",
        _ => "not a trace sorting code in the SEG-Y revision 2 table",
    }
}

#[cfg(feature = "segy")]
fn trace_header(h: &[u8], n: usize, out: &mut String) {
    line!(
        out,
        "  trace {n}: seq-in-line {}, seq-in-file {}, field record {}, shot {}, ensemble {}, CDP {}",
        be_i32(h, 0).unwrap_or(0),
        be_i32(h, 4).unwrap_or(0),
        be_i32(h, 8).unwrap_or(0),
        be_i32(h, 12).unwrap_or(0),
        be_i32(h, 16).unwrap_or(0),
        be_i32(h, 20).unwrap_or(0)
    );
    line!(
        out,
        "    trace in ensemble {}, identification code {}, offset {}, sample interval {} us, {} samples",
        be_i32(h, 24).unwrap_or(0),
        be_i16(h, 28).unwrap_or(0),
        be_i32(h, 36).unwrap_or(0),
        be_u16(h, 116).unwrap_or(0),
        be_u16(h, 114).unwrap_or(0)
    );
    if h.len() >= 166 {
        // The trace header carries a year and a day of year, not a month, so
        // no month is invented here. Octets 73-88 are the source and group
        // coordinates in SEG-Y revision 1; in revision 2 those octets carry
        // different fields, which is why the label names the revision.
        let year = be_u16(h, 156).unwrap_or(0);
        let doy = be_u16(h, 158).unwrap_or(0);
        let hh = be_u16(h, 160).unwrap_or(0);
        let mm = be_u16(h, 162).unwrap_or(0);
        let ss = be_u16(h, 164).unwrap_or(0);
        let sx = be_i32(h, 72).unwrap_or(0);
        let sy = be_i32(h, 76).unwrap_or(0);
        let gx = be_i32(h, 80).unwrap_or(0);
        let gy = be_i32(h, 84).unwrap_or(0);
        line!(
            out,
            "    recorded in year {year}, day {doy} of the year, {hh}:{mm}:{ss}; source X {sx} Y {sy}, group X {gx} Y {gy} (revision 1 octets 73-88)"
        );
    }
}

// -- IBM EBCDIC CP037 -------------------------------------------------------

/// CP037 to ASCII. Built as a `const fn` from the code points a SEG-Y
/// textual header can contain. CP037 is not one contiguous letter run: it
/// has four uppercase runs and four lowercase runs with punctuation wedged
/// between them, so each run is placed separately — a single `A + i` loop
/// would spell K as "." and every card after a hyphen as noise.
///
/// Anchored on encodings that are not in dispute: "Hello" is
/// `C8 85 93 93 96`, digits are `F0`-`F9`, blank is `40`.
#[cfg(feature = "segy")]
const fn cp037_table() -> [u8; 256] {
    let mut t = [b' '; 256];
    let mut i = 0usize;
    while i < 9 {
        t[0x41 + i] = b'A' + i as u8;
        i += 1;
    }
    let mut i = 0usize;
    while i < 8 {
        t[0x51 + i] = b'J' + i as u8;
        i += 1;
    }
    let mut i = 0usize;
    while i < 9 {
        t[0x62 + i] = b'a' + i as u8;
        i += 1;
    }
    let mut i = 0usize;
    while i < 7 {
        t[0x70 + i] = b'j' + i as u8;
        i += 1;
    }
    let mut i = 0usize;
    while i < 9 {
        t[0x81 + i] = b'a' + i as u8;
        i += 1;
    }
    let mut i = 0usize;
    while i < 8 {
        t[0x91 + i] = b'j' + i as u8;
        i += 1;
    }
    let mut i = 0usize;
    while i < 8 {
        t[0xa2 + i] = b's' + i as u8;
        i += 1;
    }
    let mut i = 0usize;
    while i < 9 {
        t[0xc1 + i] = b'A' + i as u8;
        i += 1;
    }
    let mut i = 0usize;
    while i < 8 {
        t[0xd1 + i] = b'J' + i as u8;
        i += 1;
    }
    let mut i = 0usize;
    while i < 8 {
        t[0xe2 + i] = b'S' + i as u8;
        i += 1;
    }
    let mut i = 0usize;
    while i < 10 {
        t[0xf0 + i] = b'0' + i as u8;
        i += 1;
    }
    // Punctuation. Only code points whose CP037 meaning is not in doubt are
    // listed; everything else stays a blank rather than becoming a letter.
    t[0x24] = b'$';
    t[0x28] = b'(';
    t[0x29] = b')';
    t[0x2a] = b'*';
    t[0x2b] = b'+';
    t[0x2c] = b',';
    t[0x2d] = b'-';
    t[0x2e] = b'.';
    t[0x2f] = b'/';
    t[0x3a] = b':';
    t[0x3b] = b';';
    t[0x3c] = b'<';
    t[0x3d] = b'=';
    t[0x3e] = b'>';
    t[0x3f] = b'?';
    t[0x40] = b' ';
    t[0x4a] = b'[';
    t[0x4b] = b'.';
    t[0x4c] = b'<';
    t[0x4d] = b'(';
    t[0x4e] = b'+';
    t[0x50] = b'&';
    t[0x5a] = b'!';
    t[0x5c] = b'*';
    t[0x5d] = b')';
    t[0x5e] = b';';
    t[0x60] = b'-';
    t[0x61] = b'/';
    t[0x6b] = b',';
    t[0x6c] = b'%';
    t[0x6d] = b'_';
    t[0x6e] = b'>';
    t[0x6f] = b'?';
    t[0x79] = b'(';
    t[0x7a] = b':';
    t[0x7b] = b'#';
    t[0x7c] = b'@';
    t[0x7d] = b'"';
    t[0x7e] = b'=';
    t[0x7f] = b'\'';
    t[0xc0] = b'{';
    t[0xd0] = b'}';
    t
}

/// True when the first card is a SEG-Y card written in plain ASCII. SEG-Y
/// cards start with `C`, a space and the card number, in both encodings; only
/// the byte values differ, so the ASCII test is unambiguous when it succeeds.
#[cfg(feature = "segy")]
fn textual_is_ascii(h: &[u8]) -> bool {
    matches!(
        h.get(0..3),
        Some(b"C 1") | Some(b"C 2") | Some(b"C 3") | Some(b"C 4")
    )
}

/// The signature. Either encoding is accepted, but only if the first card
/// really looks like a card, so an arbitrary 3200 bytes of binary cannot pass
/// for a SEG-Y file.
#[cfg(feature = "segy")]
fn looks_like_segy_header(h: &[u8]) -> bool {
    let ascii = textual_is_ascii(h);
    if ascii {
        return h.len() >= 3200;
    }
    let Some(card) = h.get(..3) else {
        return false;
    };
    let t = cp037_table();
    let c = t[card[0] as usize];
    let sp = t[card[1] as usize];
    let digit = t[card[2] as usize];
    c == b'C' && sp == b' ' && digit.is_ascii_digit()
}

/// 40 cards of 80 characters, decoded, with trailing blanks trimmed and empty
/// cards dropped.
#[cfg(feature = "segy")]
fn textual_cards(h: &[u8], ebcdic: bool) -> Vec<String> {
    let t = cp037_table();
    let mut out = Vec::new();
    for card in 0..40usize {
        let Some(start) = card.checked_mul(80) else {
            break;
        };
        let Some(bytes) = h.get(start..start.saturating_add(80)) else {
            break;
        };
        let decoded: String = if ebcdic {
            bytes.iter().map(|&b| t[b as usize] as char).collect()
        } else {
            bytes.iter().map(|&b| b as char).collect()
        };
        let trimmed = decoded.trim_end();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
        if out.len() >= MAX_TRACES * 2 {
            break;
        }
    }
    out
}

// ===========================================================================
// CERN ROOT
// ===========================================================================

/// CERN ROOT files. The header report is the honest deliverable here: the
/// `root` key and `fVersion` are fixed by the format, while streamer and
/// record information lives in the key record table, whose layout was not
/// verified against the ROOT file format specification here.
#[cfg(feature = "root")]
pub struct Root;

#[cfg(feature = "root")]
impl Adapter for Root {
    fn name(&self) -> &'static str {
        "root"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["root"]
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !data.starts_with(b"root") {
            decline!("no ROOT key at offset 0");
        }
        let Some(version) = be_i32(data, 4) else {
            bail!("ROOT key present but the 4-octet version field is truncated");
        };
        let mut out = String::new();
        line!(out, "CERN ROOT file");
        line!(out, "  key: \"root\"");
        line!(out, "  file format version: {version}");
        line!(out, "  file size: {} bytes", data.len());
        line!(
            out,
            "  streamers, keys and object data: not decoded (the key record layout was not verified here)"
        );
        Ok(Outcome::Text(out.into_bytes()))
    }
}

// ===========================================================================
// N5 / N5Z
// ===========================================================================

/// NeTTL N5 seismology files, and their zarr-packaged N5Z form. Both are HDF5
/// containers: the 8-octet HDF5 file signature is the whole of the signature
/// available, and the two cannot be told apart from the container header,
/// because the difference is in the chunk filters of the stored groups.
#[cfg(feature = "n5")]
pub struct N5;

#[cfg(feature = "n5")]
impl Adapter for N5 {
    fn name(&self) -> &'static str {
        "n5"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["n5", "n5z"]
    }

    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        const HDF5_SIG: &[u8] = b"\x89HDF\r\n\x1a\n";
        if !data.starts_with(HDF5_SIG) {
            decline!("no HDF5 file signature at offset 0");
        }
        let mut out = String::new();
        line!(out, "N5/N5Z seismology file (HDF5 container)");
        line!(out, "  HDF5 file signature: 89 48 44 46 0d 0a 1a 0a");
        let Some(superver) = be_u8(data, 8) else {
            bail!("HDF5 signature present but the superblock version octet is missing");
        };
        line!(out, "  superblock version: {superver}");
        if let (Some(offsets), Some(lengths)) = (be_u8(data, 9), be_u8(data, 10)) {
            line!(
                out,
                "  address size: {offsets} bytes, length size: {lengths} bytes"
            );
        }
        line!(out, "  file size: {} bytes", data.len());
        line!(out, "  groups, datasets and attributes: not decoded");
        line!(
            out,
            "  N5 and N5Z share this container; the difference is in the chunk filters of the stored groups"
        );
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(test)]
#[cfg(any(
    feature = "bufr",
    feature = "grib",
    feature = "n5",
    feature = "root",
    feature = "segy"
))]
mod tests {
    use super::*;
    #[cfg(feature = "grib")]
    use alloc::string::ToString;
    #[cfg(any(feature = "bufr", feature = "n5", feature = "root"))]
    use alloc::vec::Vec;

    #[cfg(any(
        feature = "bufr",
        feature = "grib",
        feature = "n5",
        feature = "root",
        feature = "segy"
    ))]
    fn text(outcome: Result<Outcome>) -> String {
        match outcome {
            Ok(Outcome::Text(t)) => String::from_utf8_lossy(&t).into_owned(),
            Ok(_) => panic!("expected text, got a different outcome"),
            Err(e) => panic!("expected text, got an error: {e}"),
        }
    }

    // ---- GRIB fixtures ---------------------------------------------------

    #[cfg(any(feature = "grib", feature = "segy"))]
    fn be16(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }
    #[cfg(any(feature = "grib", feature = "segy"))]
    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }
    #[cfg(feature = "grib")]
    fn be64(v: u64) -> [u8; 8] {
        v.to_be_bytes()
    }

    /// A section with the 4-octet length field counting the whole section,
    /// which is what the NCEP tables specify.
    #[cfg(feature = "grib")]
    fn grib2_section(number: u8, body: &[u8]) -> Vec<u8> {
        let len = (4 + 1 + body.len()) as u32;
        let mut s = Vec::new();
        s.extend_from_slice(&be32(len));
        s.push(number);
        s.extend_from_slice(body);
        s
    }

    /// Section 1: the fixed 16-octet body after the section header, so the
    /// section is the standard 21 octets. Section 1 has no template — the
    /// product template lives in section 4, which is the confusion that made
    /// an earlier version of this fixture put product fields here.
    #[cfg(feature = "grib")]
    fn grib2_section1() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&be16(7)); // octets 6-7 centre
        body.extend_from_slice(&be16(0)); // octets 8-9 subcentre
        body.push(2); // octet 10 master tables version
        body.push(1); // octet 11 local tables version
        body.push(1); // octet 12 significance of reference time
        body.extend_from_slice(&be16(2026)); // octets 13-14 year
        body.extend_from_slice(&[10, 18, 12, 30, 0]); // octets 15-19 month..second
        body.push(0); // octet 20 production status
        body.push(2); // octet 21 type of processed data
        assert_eq!(body.len(), 16);
        grib2_section(1, &body)
    }

    #[cfg(feature = "grib")]
    fn grib2_section3(points: u32, gdt: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0); // octet 6 source of grid definition
        body.extend_from_slice(&be32(points)); // octets 7-10
        body.push(0); // octet 11 optional list length
        body.push(0); // octet 12 interpretation
        body.extend_from_slice(&be16(gdt)); // octets 13-14 grid template number
        grib2_section(3, &body)
    }

    /// Section 4: coordinate-value count, product template number, then
    /// product template 4.0 from octet 10 to octet 34. The template is 25
    /// octets, so the section is 34 — which is exactly the length the
    /// decoder guards on.
    #[cfg(feature = "grib")]
    fn grib2_section4(category: u8, number: u8, surface: u8, level: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&be16(0)); // octets 6-7 coordinate values
        body.extend_from_slice(&be16(0)); // octets 8-9 product template 4.0
        let t = vec![
            category, // octet 10 parameter category
            number,   // octet 11 parameter number
            2,        // octet 12 type of generating process
            0,        // octet 13 background generating process
            255,      // octet 14 generating process identifier
            0, 0, // octets 15-16 hours of cutoff
            0, // octet 17 minutes of cutoff
            1, // octet 18 unit of time range
        ];
        let mut t = t;
        t.extend_from_slice(&be32(6)); // octets 19-22 forecast time
        t.push(surface); // octet 23 type of first fixed surface
        t.push(0); // octet 24 scale factor
        t.extend_from_slice(&be32(level)); // octets 25-28 scaled value
        t.push(255); // octet 29 type of second fixed surface
        t.push(0); // octet 30 scale factor
        t.extend_from_slice(&be32(0)); // octets 31-34 scaled value
        assert_eq!(t.len(), 25);
        body.extend_from_slice(&t);
        grib2_section(4, &body)
    }

    /// Section 5: data-point count, data representation template number, then
    /// template 5.0 from octet 12 (reference value, binary and decimal scale
    /// factors, bits per value, type of the original field values).
    #[cfg(feature = "grib")]
    fn grib2_section5(points: u32, bits: u8) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&be32(points)); // octets 6-9 data points
        body.extend_from_slice(&be16(0)); // octets 10-11 template 5.0
        body.extend_from_slice(&0.0f32.to_be_bytes()); // octets 12-15 reference value
        body.extend_from_slice(&be16(0)); // octets 16-17 binary scale factor
        body.extend_from_slice(&be16(0)); // octets 18-19 decimal scale factor
        body.push(bits); // octet 20
        body.push(0); // octet 21 type of original field values
        grib2_section(5, &body)
    }

    #[cfg(feature = "grib")]
    fn grib2_section6_none() -> Vec<u8> {
        grib2_section(6, &[255])
    }

    /// Section 3 with the spherical harmonics grid definition template 3.50:
    /// the truncation J, K and M at octets 15-26, and the two octets that
    /// say how the coefficients are represented at 27 and 28.
    #[cfg(feature = "grib")]
    fn grib2_section3_spectral(points: u32, j: u32, k: u32, m: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0); // octet 6 source of grid definition
        body.extend_from_slice(&be32(points)); // octets 7-10
        body.push(0); // octet 11 optional list length
        body.push(0); // octet 12 interpretation
        body.extend_from_slice(&be16(50)); // octets 13-14 grid template number
        body.extend_from_slice(&be32(j)); // octets 15-18 J
        body.extend_from_slice(&be32(k)); // octets 19-22 K
        body.extend_from_slice(&be32(m)); // octets 23-26 M
        body.push(1); // octet 27 representation type
        body.push(1); // octet 28 representation mode
        grib2_section(3, &body)
    }

    /// Section 5 with the spherical harmonics data representation template
    /// 5.50: the reference value, the two scale factors and the number of
    /// bits, and then the real part of the (0.0) coefficient.
    #[cfg(feature = "grib")]
    fn grib2_section5_spectral_simple(points: u32, bits: u8, real_part: f32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&be32(points)); // octets 6-9 data points
        body.extend_from_slice(&be16(50)); // octets 10-11 template 5.50
        body.extend_from_slice(&0.0f32.to_be_bytes()); // octets 12-15 reference value
        body.extend_from_slice(&be16(0)); // octets 16-17 binary scale factor
        body.extend_from_slice(&be16(0)); // octets 18-19 decimal scale factor
        body.push(bits); // octet 20
        body.extend_from_slice(&real_part.to_be_bytes()); // octets 21-24 the real part of (0.0)
        grib2_section(5, &body)
    }

    /// Section 5 with the spherical harmonics data representation template
    /// 5.51: the reference value, the two scale factors and the number of
    /// bits, the Laplacian scaling factor, the truncation of the unpacked
    /// subset, the number of values in it and their precision.
    #[cfg(feature = "grib")]
    fn grib2_section5_spectral_complex(
        points: u32,
        bits: u8,
        laplacian: i32,
        js: u32,
        subset_values: u32,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&be32(points)); // octets 6-9 data points
        body.extend_from_slice(&be16(51)); // octets 10-11 template 5.51
        body.extend_from_slice(&0.0f32.to_be_bytes()); // octets 12-15 reference value
        body.extend_from_slice(&be16(0)); // octets 16-17 binary scale factor
        body.extend_from_slice(&be16(0)); // octets 18-19 decimal scale factor
        body.push(bits); // octet 20
        body.extend_from_slice(&laplacian.to_be_bytes()); // octets 21-24 Laplacian factor
        body.extend_from_slice(&be16(js as u16)); // octets 25-26 JS
        body.extend_from_slice(&be16(js as u16)); // octets 27-28 KS
        body.extend_from_slice(&be16(js as u16)); // octets 29-30 MS
        body.extend_from_slice(&be32(subset_values)); // octets 31-34 TS
        body.push(1); // octet 35 the precision of the subset: the IEEE 32-bit one
        grib2_section(5, &body)
    }

    #[cfg(feature = "grib")]
    fn grib2_section7(values: &[u16]) -> Vec<u8> {
        let mut packed = Vec::new();
        for v in values {
            packed.extend_from_slice(&v.to_be_bytes());
        }
        grib2_section(7, &packed)
    }

    /// Assemble a complete edition 2 message and fix up section 0's total
    /// length, which is the only field that depends on the rest.
    #[cfg(feature = "grib")]
    fn grib2_message(sections: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for s in sections {
            body.extend_from_slice(s);
        }
        body.extend_from_slice(b"7777");
        let total = 16 + body.len();
        let mut out = Vec::new();
        out.extend_from_slice(b"GRIB");
        out.extend_from_slice(&[0, 0]);
        out.push(0); // discipline
        out.push(2); // edition
        out.extend_from_slice(&be64(total as u64));
        out.extend_from_slice(&body);
        out
    }

    /// The canonical six-section edition 2 message: 1, 3, 4, 5, 6, 7 and the
    /// `7777` terminator. Section lengths here are 21, 14, 34, 21, 6 and
    /// `4 + 2 * packed.len()`, so a walk that is off by one octet lands
    /// somewhere else entirely and the assertions below stop matching.
    #[cfg(feature = "grib")]
    fn simple_grib2(category: u8, number: u8, points: u32, bits: u8, packed: &[u16]) -> Vec<u8> {
        grib2_message(&[
            grib2_section1(),
            grib2_section3(points, 0),
            grib2_section4(category, number, 100, 2),
            grib2_section5(points, bits),
            grib2_section6_none(),
            grib2_section7(packed),
        ])
    }

    #[test]
    #[cfg(feature = "grib")]
    fn a_grib2_message_names_its_parameter_from_code_table_4_2() {
        // discipline 0, category 0 (temperature), parameter 6 = dew point.
        let msg = simple_grib2(0, 6, 4, 16, &[0, 1, 2, 3]);
        let out = text(Grib.extract(&msg, "t.grb2"));
        assert!(out.contains("grib edition 2"), "{out}");
        assert!(
            out.contains("discipline: 0 (meteorological products)"),
            "{out}"
        );
        assert!(out.contains("product: template 4.0"), "{out}");
        assert!(out.contains("Dew Point Temperature"), "{out}");
        assert!(out.contains("type 100, value 2"), "{out}");
        // The centre and reference time come from section 1, the product
        // fields from section 4; conflating the two octet-10s is what this
        // fixture is here to keep apart.
        assert!(out.contains("originating centre: 7"), "{out}");
        assert!(out.contains("reference time: 2026-10-18 12:30:00"), "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_simple_packing_decodes_the_values_it_packs() {
        // Reference 0, E 0, D 0, 16 bits per value: the packed integers are
        // the values, so a correct decoder must print them back unchanged.
        // 65535 is not used as a sample value: all ones is the missing
        // marker at this width, which the next test covers.
        let msg = simple_grib2(0, 0, 4, 16, &[0, 1, 1000, 60000]);
        let out = text(Grib.extract(&msg, "t.grb2"));
        assert!(out.contains("16 bits per value"), "{out}");
        for want in ["0", "1", "1000", "60000"] {
            assert!(
                out.lines().any(|l| l.trim() == want),
                "missing decoded value {want} in:\n{out}"
            );
        }
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_section_lengths_are_advanced_by_exactly_their_declared_length() {
        // The declared length counts the whole section, the four length
        // octets and the section-number octet included. Advancing by
        // `length - 1` is the classic GRIB defect; section 3's data point
        // count would then be read one octet early.
        let msg = grib2_message(&[
            grib2_section1(),
            grib2_section3(4321, 0),
            grib2_section4(0, 6, 100, 2),
            grib2_section5(4321, 16),
            grib2_section6_none(),
            grib2_section7(&[7]),
        ]);
        let out = text(Grib.extract(&msg, "t.grb2"));
        assert!(out.contains("4321 data points"), "{out}");
        assert!(out.contains("grid definition template 3.0"), "{out}");
        assert!(out.contains("section 5: 21 octets"), "{out}");
        assert!(out.contains("\"7777\" end marker"), "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_all_ones_packed_values_are_missing_not_numbers() {
        // 0xFFFF is the missing marker for 16-bit values; it must not be
        // printed as 65535.
        let msg = simple_grib2(0, 0, 2, 16, &[0xffff, 42]);
        let out = text(Grib.extract(&msg, "t.grb2"));
        assert!(!out.lines().any(|l| l.trim() == "65535"), "{out}");
        assert!(out.lines().any(|l| l.trim() == "42"), "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn a_bit_map_masks_values_out_of_the_decoded_output() {
        // Indicator 0 means a bit map follows in section 6, one bit per grid
        // point, 1 = present.
        let s6 = [0u8, 0b0100_0000];
        let msg = grib2_message(&[
            grib2_section1(),
            grib2_section3(2, 0),
            grib2_section4(0, 0, 100, 2),
            grib2_section5(2, 16),
            grib2_section(6, &s6),
            grib2_section7(&[11, 22]),
        ]);
        let out = text(Grib.extract(&msg, "t.grb2"));
        assert!(out.contains("points present"), "{out}");
        // A masked point is not packed, so the one word that is present is
        // the first one in section 7, and the second word is never read.
        assert!(out.contains("masked off by the bit map"), "{out}");
        assert!(out.lines().any(|l| l.trim() == "11"), "{out}");
        assert!(!out.lines().any(|l| l.trim() == "22"), "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn a_grib2_message_that_claims_more_bytes_than_it_has_is_reported_truncated() {
        let mut msg = simple_grib2(0, 0, 4, 16, &[1, 2, 3, 4]);
        msg[8..16].copy_from_slice(&be64(4096));
        let out = text(Grib.extract(&msg, "t.grb2"));
        assert!(out.contains("truncated"), "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn a_grib2_message_with_only_an_indicator_still_reports_instead_of_bailing() {
        // The magic matched, so handing the file back as an error would drop
        // it from the search entirely.
        let out = text(Grib.extract(b"GRIB\x00\x00\x02\x00", "t.grb2"));
        assert!(out.contains("no GRIB message could be read"), "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn a_grib1_message_reports_its_product_definition_section() {
        // Edition 1: 8-octet section 0, then sections with a 3-octet length
        // and no section-number octet.
        let mut pds = vec![
            0, 0, 28,  // octets 1-3 section length
            128, // octet 4 table 2 version
            98,  // octet 5 centre: ECMWF
            128, // octet 6 generating process identifier
            255, // octet 7 grid definition
            128, // octet 8 section 1 flags
            11,  // octet 9 parameter: code table 2 number 11
            103, // octet 10 level type: code table 3 number 103
        ];
        pds.extend_from_slice(&be16(500)); // octets 11-12 level value
        pds.extend_from_slice(&[
            26,  // octet 13 year of century
            10,  // octet 14 month
            18,  // octet 15 day
            12,  // octet 16 hour
            30,  // octet 17 minute
            1,   // octet 18 unit of time range
            0,   // octet 19 P1
            0,   // octet 20 P2
            128, // octet 21 time range indicator
        ]);
        pds.extend_from_slice(&be16(0)); // octets 22-23 number included in average
        pds.extend_from_slice(&[
            0,  // octet 24 number missing
            20, // octet 25 century
            0,  // octet 26 subcentre
        ]);
        pds.extend_from_slice(&be16(0)); // octets 27-28 decimal scale factor
        assert_eq!(pds.len(), 28);

        // A 32-octet grid description section, which the walk must not
        // mistake for the product definition section, followed by the binary
        // data section that the fixed section order puts last.
        let mut gds = vec![0u8; 32];
        gds[0] = 0;
        gds[1] = 0;
        gds[2] = 32;

        let mut bds = vec![0u8; 15];
        bds[0] = 0;
        bds[1] = 0;
        bds[2] = 15;
        bds[3] = 0; // grid point, simple packing, float, no unused bits
        bds[4..6].copy_from_slice(&be16(0)); // binary scale factor
        bds[6..10].copy_from_slice(&[0x42, 0x14, 0x00, 0x00]); // IBM float
        bds[10] = 16; // bits per value

        let mut body = Vec::new();
        body.extend_from_slice(&pds);
        body.extend_from_slice(&gds);
        body.extend_from_slice(&bds);
        body.extend_from_slice(b"7777");

        let mut msg = Vec::new();
        msg.extend_from_slice(b"GRIB");
        // Edition 1 section 0: octets 5-7 are the total length, octet 8 is
        // the edition. There is no discipline octet in edition 1.
        let total = 8 + body.len();
        msg.push((total >> 16) as u8);
        msg.push((total >> 8) as u8);
        msg.push(total as u8);
        msg.push(1);
        msg.extend_from_slice(&body);

        let out = text(Grib.extract(&msg, "t.grb"));
        assert!(out.contains("grib edition 1"), "{out}");
        assert!(out.contains("code table 2 number 11"), "{out}");
        assert!(out.contains("level type 103"), "{out}");
        assert!(out.contains("level 500"), "{out}");
        // The grid description section in the middle is reported as neither
        // product nor data, and the binary data section is found by position.
        assert_eq!(
            out.matches("product definition section").count(),
            1,
            "{out}"
        );
        assert!(out.contains("grid description or bit map section"), "{out}");
        assert!(out.contains("grid point data, simple packing"), "{out}");
        assert!(out.contains("16 bits per value"), "{out}");
        assert!(out.contains("packed values: not decoded"), "{out}");
        assert!(out.contains("\"7777\" end marker"), "{out}");
    }

    /// An edition 1 message with a lat/lon grid and simple packing, holding
    /// the given packed integers. The binary scale factor is -10 and the
    /// reference value is 40, so the packed integer 1024 is the value 41 and
    /// the integer 0 is the value 40.
    #[cfg(feature = "grib")]
    fn grib1_message(ni: u16, nj: u16, flag: u8, values: &[u16]) -> Vec<u8> {
        let mut pds = vec![0u8; 28];
        pds[0..3].copy_from_slice(&[0, 0, 28]); // octets 1-3 section length
        pds[3] = 128; // octet 4 table 2 version: the local table
        pds[4] = 98; // octet 5 centre: ECMWF
        pds[5] = 130; // octet 6 generating process identifier
        pds[6] = 255; // octet 7 grid definition
        pds[7] = 0x80; // octet 8 section 1 flags: the grid description is there
        pds[8] = 167; // octet 9 parameter: code table 2 number 167
        pds[9] = 1; // octet 10 level type: code table 3 number 1
        pds[10..12].copy_from_slice(&be16(0)); // octets 11-12 level value
        pds[26..28].copy_from_slice(&be16(0)); // octets 27-28 decimal scale factor

        let mut gds = vec![0u8; 32];
        gds[0..3].copy_from_slice(&[0, 0, 32]); // octets 1-3 section length
        gds[3] = 0; // octet 4: no vertical coordinate values
        gds[4] = 255; // octet 5: PV/PL location, neither present
        gds[5] = 0; // octet 6: data representation type, lat/lon
        gds[6..8].copy_from_slice(&be16(ni)); // octets 7-8
        gds[8..10].copy_from_slice(&be16(nj)); // octets 9-10

        let mut bds = vec![0u8; 11];
        bds[3] = flag;
        bds[4..6].copy_from_slice(&[0x80, 0x0a]); // octets 5-6: scale factor -10
        bds[6..10].copy_from_slice(&[0x42, 0x28, 0x00, 0x00]); // octets 7-10: 40, IBM float
        bds[10] = 16; // octet 11: bits per value
        for value in values {
            bds.extend_from_slice(&value.to_be_bytes());
        }
        if bds.len() % 2 == 1 {
            // A section is padded to an even length, and the padding is
            // declared in the flag's low nibble.
            bds.push(0);
            bds[3] |= 8;
        }
        let len = bds.len();
        bds[0..3].copy_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);

        let mut body = Vec::new();
        body.extend_from_slice(&pds);
        body.extend_from_slice(&gds);
        body.extend_from_slice(&bds);
        body.extend_from_slice(b"7777");

        let mut msg = Vec::new();
        msg.extend_from_slice(b"GRIB");
        let total = 8 + body.len();
        msg.push((total >> 16) as u8);
        msg.push((total >> 8) as u8);
        msg.push(total as u8);
        msg.push(1);
        msg.extend_from_slice(&body);
        msg
    }

    /// A message whose data section is packed with the second-order packing.
    ///
    /// The section holds the width of the first-order values in octet 11, the
    /// number of them in octets 12-13, and the flags that say which of the
    /// layouts of that packing the section is in octet 14.
    #[cfg(feature = "grib")]
    fn grib1_second_order_message(octet14: u8) -> Vec<u8> {
        let mut msg = grib1_message(2, 3, 0x40, &[0; 6]);
        // The data section follows section 0, the product definition section
        // and the grid description section.
        let bds = 8 + 28 + 32;
        msg[bds + 13] = octet14;
        msg
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib1_simple_packing_decodes_the_values_it_packs() {
        // The reference value is an IBM float and the binary scale factor is
        // a power of two, so the packed integers 0, 1024, 2048 ... are the
        // values 40, 41, 42 .... A reader that took the reference as an IEEE
        // float, or the scale as a decimal one, would print something else.
        let msg = grib1_message(2, 3, 0x08, &[0, 1024, 2048, 3072, 4096, 5120]);
        let out = text(Grib.extract(&msg, "t.grb"));
        assert!(
            out.contains("grid: type 0 (lat/lon), 2 x 3 = 6 points"),
            "{out}"
        );
        assert!(out.contains("packed values: 6 values"), "{out}");
        assert!(out.contains("minimum 40, maximum 45"), "{out}");
        for want in ["40", "41", "42", "43", "44", "45"] {
            assert!(
                out.lines().any(|line| line.trim() == want),
                "the decoded value {want} is missing from:\n{out}"
            );
        }
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib1_second_order_packing_is_refused_by_name() {
        // Complex packing stores differences inside groups of one width
        // each. Read as simple packing the same bytes are not the field, so
        // the section is refused with its reason rather than printed.
        let msg = grib1_message(2, 3, 0x40, &[0, 1024, 2048, 3072, 4096, 5120]);
        let out = text(Grib.extract(&msg, "t.grb"));
        assert!(out.contains("not decoded (second-order packing"), "{out}");
        assert!(!out.contains("value range"), "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_reduced_grid_fixture_reports_the_points_of_each_row() {
        // A reduced grid says how many points each of its rows holds, in the
        // list of numbers that follows the grid definition template. The
        // number of columns is missing -- all ones -- and the list gives the
        // shape of the grid instead: 501 rows, from none at the poles to a
        // thousand points at the widest, 313362 points in all.
        //
        // The oracle is the pair that writes and reads these files: NOAA's
        // g2c library and ECMWF's ecCodes. Both read the grid as a reduced
        // lat/lon grid of 501 rows whose list gives the points of each row,
        // both read the first rows of that list as zeroes, and both read the
        // widest row as a thousand points.
        let data = include_bytes!("../testdata/grib/reduced_latlon_surface.grib2");
        let out = text(Grib.extract(data, "reduced_latlon_surface.grib2"));
        assert!(
            out.contains(
                "grid: source 0 (0 = specified here), 313362 data points, grid definition template 3.0"
            ),
            "{out}"
        );
        assert!(
            out.contains("grid: 501 rows, the number of columns is missing: the grid is reduced"),
            "{out}"
        );
        assert!(
            out.contains(
                "grid: the list of numbers gives the points of each row (code table 3.11 interpretation 1)"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "grid: the 501 rows hold 313362 points, the number of data points the section declares"
            ),
            "{out}"
        );
        assert!(out.contains("grid: 0 to 1000 points per row"), "{out}");
        assert!(
            out.contains("grid: points per row, the first 24 of 501:"),
            "{out}"
        );
        // The list the oracle reads: the first rows hold no points at all.
        let rows: Vec<&str> = out
            .lines()
            .skip_while(|line| !line.trim().ends_with("the first 24 of 501:"))
            .skip(1)
            .take_while(|line| line.trim().parse::<u64>().is_ok())
            .map(|line| line.trim())
            .collect();
        assert_eq!(rows.len(), 24, "{out}");
        assert!(
            rows.iter().all(|row| *row == "0"),
            "the rows of the reduced grid are not the ones the oracle reads: {out}"
        );
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_spectral_simple_packing_decodes_the_coefficients_it_packs() {
        // A truncation J 1, K 1 and M 1: the coefficients of (0.0), (0.1) and
        // (1.1), six values. The real part of the (0.0) coefficient is in
        // the template, so the packed part holds the other five values: 1, 2,
        // 3, 4 and 5, and the field is 0.5, 1, 2, 3, 4, 5.
        let mut packed = Vec::new();
        for v in [1u8, 2, 3, 4, 5] {
            packed.push(v);
        }
        let msg = grib2_message(&[
            grib2_section1(),
            grib2_section3_spectral(6, 1, 1, 1),
            grib2_section4(0, 0, 100, 2),
            grib2_section5_spectral_simple(6, 8, 0.5),
            grib2_section6_none(),
            grib2_section(7, &packed),
        ]);
        let out = text(Grib.extract(&msg, "t.grib2"));
        assert!(
            out.contains("grid: spherical harmonics, truncation J 1, K 1, M 1"),
            "{out}"
        );
        assert!(
            out.contains("data: template 5.50 simple packing, 6 values, reference 0, E 0, D 0, 8 bits per value"),
            "{out}"
        );
        assert!(out.contains("value range: minimum 0.5, maximum 5"), "{out}");
        let values = reported_values(&out);
        assert_eq!(values, vec!["0.5", "1", "2", "3", "4", "5"], "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_spectral_complex_packing_decodes_the_coefficients_it_packs() {
        // A truncation J 1, K 1 and M 1 again, with an unpacked subset of
        // the truncation J 0, K 0 and M 0: it holds the coefficient of (0.0)
        // alone, 10 as its real part and 0 as its imaginary part.
        //
        // The packed part holds the other four values, 1, 2, 3 and 4. The
        // Laplacian factor of 1000000 is an operator of one, so the
        // coefficient of the wave number 1 is scaled by 1/(1 * 2): the real
        // part of (0.1) is 0.5 and the imaginary part of (1.1) is 2.
        //
        // The imaginary part of the row m = 0 is zero by construction, and
        // the file packs it anyway: the second packed integer is read and
        // dropped.
        let mut packed = Vec::new();
        // The unpacked subset: the real part and the imaginary part of the
        // coefficient of (0.0), as IEEE floats.
        packed.extend_from_slice(&10.0f32.to_be_bytes());
        packed.extend_from_slice(&0.0f32.to_be_bytes());
        for v in [1u8, 2, 3, 4] {
            packed.push(v);
        }
        let msg = grib2_message(&[
            grib2_section1(),
            grib2_section3_spectral(6, 1, 1, 1),
            grib2_section4(0, 0, 100, 2),
            grib2_section5_spectral_complex(6, 8, 1_000_000, 0, 2),
            grib2_section6_none(),
            grib2_section(7, &packed),
        ]);
        let out = text(Grib.extract(&msg, "t.grib2"));
        assert!(
            out.contains(
                "data: template 5.51 complex packing, 6 values, the unpacked subset 2 of them, reference 0, E 0, D 0, 8 bits per value, Laplacian operator 1"
            ),
            "{out}"
        );
        assert!(out.contains("value range: minimum 0, maximum 10"), "{out}");
        let values = reported_values(&out);
        assert_eq!(values, vec!["10", "0", "0.5", "0", "1.5", "2"], "{out}");
    }

    /// Section 3 with a bi-Fourier grid definition template 3.63: the
    /// resolution parameters N and M at octets 16-23, the shape of the
    /// truncation at 24, and the three domains of the grid at 25-72.
    #[cfg(feature = "grib")]
    fn grib2_section3_bi_fourier(points: u32, n: u32, m: u32, shape: u8) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0); // octet 6 source of grid definition
        body.extend_from_slice(&be32(points)); // octets 7-10
        body.push(0); // octet 11 optional list length
        body.push(0); // octet 12 interpretation
        body.extend_from_slice(&be16(63)); // octets 13-14 grid template number
        body.push(2); // octet 15 spectral type: the bi-Fourier representation
        body.extend_from_slice(&be32(n)); // octets 16-19 N
        body.extend_from_slice(&be32(m)); // octets 20-23 M
        body.push(shape); // octet 24 the shape of the truncation
        body.extend_from_slice(&be64(2000)); // octets 25-32 the full domain
        body.extend_from_slice(&be64(1800)); // octets 33-40 the useful domain
        body.extend_from_slice(&be64(100)); // octets 41-48 the coupling domain
        body.extend_from_slice(&be64(2000)); // octets 49-56
        body.extend_from_slice(&be64(1800)); // octets 57-64
        body.extend_from_slice(&be64(100)); // octets 65-72
        grib2_section(3, &body)
    }

    /// The parameters of the unpacked subset of a bi-Fourier field.
    #[cfg(feature = "grib")]
    struct BiFourierSubset {
        shape: u8,
        axes: u8,
        n: u16,
        m: u16,
        values: u32,
    }

    /// Section 5 with the bi-Fourier data representation template 5.53: the
    /// reference value, the two scale factors and the number of bits, the
    /// shape of the truncation of the unpacked subset at octet 21, the
    /// packing mode for the axes at 22, the Laplacian factor at 23-26, the
    /// resolution parameters N and M of the subset at 27-30, the number of
    /// values in it at 31-34 and its precision at 35.
    #[cfg(feature = "grib")]
    fn grib2_section5_bi_fourier(
        points: u32,
        bits: u8,
        laplacian: i32,
        subset: &BiFourierSubset,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&be32(points)); // octets 6-9 data points
        body.extend_from_slice(&be16(53)); // octets 10-11 template 5.53
        body.extend_from_slice(&0.0f32.to_be_bytes()); // octets 12-15 reference value
        body.extend_from_slice(&be16(0)); // octets 16-17 binary scale factor
        body.extend_from_slice(&be16(0)); // octets 18-19 decimal scale factor
        body.push(bits); // octet 20
        body.push(subset.shape); // octet 21 the shape of the truncation of the subset
        body.push(subset.axes); // octet 22 the packing mode for the axes
        body.extend_from_slice(&sign_magnitude32(laplacian)); // octets 23-26
        body.extend_from_slice(&be16(subset.n)); // octets 27-28 N of the subset
        body.extend_from_slice(&be16(subset.m)); // octets 29-30 M of the subset
        body.extend_from_slice(&be32(subset.values)); // octets 31-34
        body.push(1); // octet 35 the precision of the subset
        grib2_section(5, &body)
    }

    /// A sign-magnitude integer of four octets: the sign is the top bit of
    /// the first octet and the magnitude the thirty-one bits that follow.
    #[cfg(feature = "grib")]
    fn sign_magnitude32(v: i32) -> [u8; 4] {
        let magnitude = v.unsigned_abs();
        let mut out = [0u8; 4];
        out[0] = (magnitude >> 24) as u8;
        out[1] = (magnitude >> 16) as u8;
        out[2] = (magnitude >> 8) as u8;
        out[3] = magnitude as u8;
        if v < 0 {
            out[0] |= 0x80;
        }
        out
    }

    /// The values of a GRIB2 field, read with the reader's own functions, so
    /// that a test can look at the whole field and not only at the first
    /// values the report prints.
    #[cfg(feature = "grib")]
    fn grib2_field_values(data: &[u8]) -> Option<Vec<f64>> {
        let mut report = String::new();
        let mut pos = 16usize;
        let mut bitmap: Option<Vec<bool>> = None;
        let mut points = 0u32;
        let mut truncation = None;
        let mut bi_fourier = None;
        let mut drs = Drs::default();
        while pos + 5 <= data.len() {
            let slen = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
            let number = data[pos + 4];
            if slen < 5 || pos + slen > data.len() {
                return None;
            }
            let sec = &data[pos..pos + slen];
            match number {
                3 => {
                    points = grib2_s3(sec, &mut report);
                    truncation = grib2_truncation(sec);
                    bi_fourier = grib2_bi_fourier(sec);
                }
                4 => {
                    drs = Drs::default();
                    bitmap = None;
                }
                5 => drs = grib2_s5(sec),
                6 => bitmap = grib2_s6(sec, &mut report),
                7 => {
                    let grid = Grid {
                        points,
                        bitmap: bitmap.as_deref(),
                        truncation,
                        bi_fourier,
                    };
                    return grib2_bifourier_complex(&sec[5..], &drs, &grid, &mut report);
                }
                _ => {}
            }
            pos += slen;
        }
        None
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_bi_fourier_packing_decodes_the_values_it_packs() {
        // A bi-Fourier field of the resolution N 1 and M 1 with a rectangular
        // truncation: four coefficients of four values each, sixteen values.
        //
        // The unpacked subset holds the coefficients of the wave numbers
        // (0,0), (1,0) and (0,1) -- the axes are not packed -- and the
        // coefficient of (1,1) is packed. Its Laplacian factor is the sum of
        // the squares of the two wave numbers, 1 + 1 = 2, so the packed
        // integers are twice the values they stand for.
        let mut packed = Vec::new();
        for v in [
            1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0,
        ] {
            packed.extend_from_slice(&v.to_be_bytes());
        }
        for v in [20u8, 40, 60, 80] {
            packed.push(v);
        }
        let msg = grib2_message(&[
            grib2_section1(),
            grib2_section3_bi_fourier(16, 1, 1, 77),
            grib2_section4(0, 0, 100, 2),
            grib2_section5_bi_fourier(
                16,
                8,
                1_000_000,
                &BiFourierSubset {
                    shape: 77,
                    axes: 1,
                    n: 0,
                    m: 0,
                    values: 12,
                },
            ),
            grib2_section6_none(),
            grib2_section(7, &packed),
        ]);
        let out = text(Grib.extract(&msg, "t.grib2"));
        assert!(
            out.contains(
                "grid: bi-Fourier, resolution N 1, M 1, truncation of the shape 77 (rectangle)"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "data: template 5.53 bi-Fourier packing, 16 values, the unpacked subset 12 of them, reference 0, E 0, D 0, 8 bits per value, Laplacian operator 1"
            ),
            "{out}"
        );
        let values = reported_values(&out);
        assert_eq!(
            values,
            vec![
                "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "10", "20", "30",
                "40"
            ],
            "{out}"
        );
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_bi_fourier_fixture_decodes_the_values_the_oracle_reads() {
        // A bi-Fourier field of the limited area models: the grid definition
        // template 3.63 of a Lambert conformal grid with modelling
        // subdomains, the resolution N 31 and M 31 with an elliptic
        // truncation, and the data representation template 5.53 with a
        // diamond truncation of the unpacked subset. The field holds 3128
        // values: four to a coefficient, and 782 coefficients.
        //
        // The oracle is ECMWF's ecCodes, which reads the same file:
        //
        //     ECCODES_DEFINITION_PATH=target/fmt/eccodes-src/definitions \
        //       target/fmt/ecvenv/Scripts/python.exe -c \
        //       "import eccodes; gid = eccodes.codes_new_from_message(open(path,'rb').read()); \
        //        print(list(eccodes.codes_get_array(gid,'values')))"
        //
        // It gives 3128 values whose first four are 275.1813049316406, 0, 0
        // and 0, and whose last four are -0.0011775459861382842, 0,
        // 0.0008071336196735501 and 0.
        let data = include_bytes!("../testdata/grib/bifourier_lambert_ellipse_diamond.grib2");
        let out = text(Grib.extract(data, "bifourier_lambert_ellipse_diamond.grib2"));
        assert!(
            out.contains(
                "grid: bi-Fourier, resolution N 31, M 31, truncation of the shape 88 (ellipse)"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "grid: the full domain 2000 x 2000 metres, the useful domain 1800 x 1800 metres, the coupling domain 100 x 100 metres"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "data: template 5.53 bi-Fourier packing, 3128 values, the unpacked subset 432 of them, reference -0.00000000000002541107481498963, E -60, D -14, 16 bits per value, Laplacian operator 1.224014"
            ),
            "{out}"
        );
        assert!(
            out.contains("value range: minimum -0.07699500024318695, maximum 275.1813049316406"),
            "{out}"
        );
        let values = reported_values(&out);
        assert_eq!(values.len(), 24, "{out}");
        assert_eq!(values[0], "275.1813049316406", "{out}");
        assert_eq!(values[4], "-0.020003143697977066", "{out}");
        assert_eq!(values[5], "0.2209862619638443", "{out}");
        assert_eq!(values[12], "-0.07699500024318695", "{out}");

        // Every value of the field, and not a sample of them: the oracle's
        // own aggregates over all 3128. A change in the scale, in the
        // rounding or in the order the coefficients are read moves them,
        // and a change in one value the sample never reaches does not --
        // which is why the whole field is summed and not a few of its
        // values compared.
        //
        //     sum = 275.1093382515329
        //     sum of squares = 75725.00833182437
        let values = grib2_field_values(data).expect("the field decodes");
        assert_eq!(values.len(), 3128);
        assert_close(values[3124], -0.0011775459861382842);
        assert_close(values[3126], 0.0008071336196735501);
        assert_close(values.iter().sum::<f64>(), 275.1093382515329);
        assert_close(values.iter().map(|v| v * v).sum::<f64>(), 75725.00833182437);
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_bi_fourier_fixture_with_a_rectangular_truncation_decodes_the_values_the_oracle_reads()
    {
        // The same field with a rectangular truncation of the whole spectrum
        // and of the unpacked subset: 1024 coefficients of four values each,
        // 4096 values, of which the 652 of the subset are not packed.
        //
        // The oracle is ECMWF's ecCodes again, on the same file.
        let data = include_bytes!("../testdata/grib/bifourier_lambert_rectangle_rectangle.grib2");
        let out = text(Grib.extract(data, "bifourier_lambert_rectangle_rectangle.grib2"));
        assert!(
            out.contains(
                "grid: bi-Fourier, resolution N 31, M 31, truncation of the shape 77 (rectangle)"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "data: template 5.53 bi-Fourier packing, 4096 values, the unpacked subset 652 of them, reference -0.0000000005330320629326479, E -46, D -11, 16 bits per value, Laplacian operator 1.537005"
            ),
            "{out}"
        );
        let values = grib2_field_values(data).expect("the field decodes");
        assert_eq!(values.len(), 4096);
        assert_close(values[0], 275.1813049316406);
        assert_close(values[4095], 2.58963292925085e-9);
        //     sum = 275.109520319761
        //     sum of squares = 75725.0083297538
        assert_close(values.iter().sum::<f64>(), 275.109520319761);
        assert_close(values.iter().map(|v| v * v).sum::<f64>(), 75725.0083297538);
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib1_spherical_harmonics_are_refused_by_name() {
        // A spectral field holds coefficients, not grid points: the count
        // comes from the truncation parameters, not from the grid. This
        // message's truncation is not the triangular one -- J 2, K 3 and M 0
        // -- and the number of coefficients of every row does not follow from
        // them here, so the field is refused by name.
        let msg = grib1_message(2, 3, 0xc0, &[0, 1024, 2048, 3072, 4096, 5120]);
        let out = text(Grib.extract(&msg, "t.grb"));
        assert!(
            out.contains(
                "packed values: not decoded (the truncation is not triangular: J 2, K 3, M 0"
            ),
            "{out}"
        );
        assert!(!out.contains("value range"), "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib1_values_must_match_the_grid_they_are_packed_for() {
        // The grid names four points and the section holds six values. The
        // count is what says which layout the section is, so a count that
        // does not add up is a refusal and not six numbers.
        let msg = grib1_message(2, 2, 0x08, &[0, 1024, 2048, 3072, 4096, 5120]);
        let out = text(Grib.extract(&msg, "t.grb"));
        assert!(
            out.contains("not decoded (the grid names 4 points but the section holds 6 values)"),
            "{out}"
        );
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib1_fixture_decodes_its_whole_field() {
        // A real ECMWF file: 16 x 31 points of 2 metre temperature in kelvin,
        // simple packed with a binary scale factor of -10. The reference
        // value is an IBM float, so the field is 270.47 K to 311.10 K, which
        // is a surface temperature and not the 144.9 K an IEEE reading of
        // the same four octets would give.
        let data = include_bytes!("../testdata/grib/regular_latlon_surface.grib1");
        let out = text(Grib.extract(data, "regular_latlon_surface.grib1"));
        assert!(
            out.contains("grib edition 1 message at offset 0 (1100 bytes)"),
            "{out}"
        );
        assert!(
            out.contains("grid: type 0 (lat/lon), 16 x 31 = 496 points"),
            "{out}"
        );
        assert!(out.contains("packed values: 496 values"), "{out}");
        assert!(
            out.contains("minimum 270.466796875, maximum 311.0986328125"),
            "{out}"
        );
        assert!(out.lines().any(|line| line.trim() == "279"), "{out}");
        assert!(
            out.lines().any(|line| line.trim() == "270.466796875"),
            "{out}"
        );
    }

    /// The sections of an edition 2 message: the number of each and its
    /// bytes. The reader walks the message the same way; this is the walk a
    /// test needs to reach a section on its own.
    #[cfg(feature = "grib")]
    fn grib2_sections(data: &[u8]) -> Vec<(u8, &[u8])> {
        let mut out = Vec::new();
        let mut pos = 16usize;
        while pos + 5 <= data.len() {
            if data.get(pos..pos + 4) == Some(&b"7777"[..]) {
                break;
            }
            let Some(len) = be_uint(data, pos, 4).map(|v| v as usize) else {
                break;
            };
            let Some(number) = be_u8(data, pos + 4) else {
                break;
            };
            let Some(sec) = data.get(pos..pos + len) else {
                break;
            };
            out.push((number, sec));
            pos += len;
        }
        out
    }

    /// A value of the oracle's, to the precision this reader's own power
    /// carries. The Laplacian scale is computed with a series of its own,
    /// because the crate is `no_std` and `powf` is one of the functions
    /// `std` keeps, and a series is good to a few parts in 10^16.
    #[cfg(feature = "grib")]
    fn assert_close(got: f64, want: f64) {
        let tolerance = 1e-12 * want.abs().max(1.0);
        assert!(
            (got - want).abs() <= tolerance,
            "got {got:?}, want {want:?}"
        );
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib1_spectral_fixture_decodes_the_coefficients_the_oracle_reads() {
        // The spherical harmonics file: the coefficients of a spectrum of
        // truncation J 63, K 63 and M 63, packed with the complex spectral
        // packing. The field holds 4160 values: the real and the imaginary
        // part of each of the 2080 coefficients.
        //
        // The oracle is ECMWF's ecCodes, which reads the same file:
        //
        //     ECCODES_DEFINITION_PATH=target/fmt/eccodes-src/definitions \
        //       target/fmt/ecvenv/Scripts/python.exe -c \
        //       "import eccodes; gid = eccodes.codes_new_from_message(open(path,'rb').read()); \
        //        print(list(eccodes.codes_get_array(gid,'values')))"
        //
        // It gives 4160 values whose first eight are 286.55908203125, 0,
        // -3.9897279739379883, 0, -13.069560050964355, 0, -0.320359468460083
        // and 0, and whose last two are 0.0007079500248281357 and
        // -0.002295118846025265.
        let data = include_bytes!("../testdata/grib/spherical_pressure_level.grib1");
        let out = text(Grib.extract(data, "spherical_pressure_level.grib1"));
        assert!(
            out.contains("grid: type 50 (spherical harmonics), truncation J 63, K 63, M 63"),
            "{out}"
        );
        assert!(
            out.contains(
                "spectral: the pointer to the packed data N 1958, the Laplacian factor 712, the unpacked subset J 20, K 20, M 20"
            ),
            "{out}"
        );
        assert!(out.contains("packed values: 4160 values"), "{out}");
        assert!(
            out.contains("value range: minimum -13.069560050964355, maximum 286.55908203125"),
            "{out}"
        );
        let values = reported_values(&out);
        assert_eq!(values.len(), 24, "{out}");
        assert_eq!(values[0], "286.55908203125", "{out}");
        assert_eq!(values[1], "0", "{out}");
        assert_eq!(values[2], "-3.9897279739379883", "{out}");
        assert_eq!(values[4], "-13.069560050964355", "{out}");
        assert_eq!(values[6], "-0.320359468460083", "{out}");

        // The last two values are in the packed part, and the report prints
        // only the first ones.
        let mut report = String::new();
        let (sections, _) = grib1_sections(data, 0, &mut report);
        let grid = sections.grid.expect("the grid description section");
        let values = grib1_spectral(&sections, grib1_truncation(grid), &mut report)
            .expect("the field decodes");
        assert_eq!(values.len(), 4160);
        assert_close(values[4158], 0.0007079500248281357);
        assert_close(values[4159], -0.002295118846025265);
        // Every value of the field, and not a sample of them: the oracle's
        // own aggregates over all 4160. A change in the scale, in the
        // rounding or in the order the coefficients are read moves them,
        // and a change in one value the sample never reaches does not —
        // which is why the whole field is summed and not a few of its
        // values compared.
        //
        //     sum = 276.22320848654505
        //     sum of squares = 82317.709282314667
        assert_close(values.iter().sum::<f64>(), 276.22320848654505);
        assert_close(values.iter().map(|v| v * v).sum::<f64>(), 82317.70928231467);
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_spectral_fixture_decodes_the_coefficients_the_oracle_reads() {
        // The ECMWF sample of the same spectrum in edition 2: the
        // coefficients of a truncation J 63, K 63 and M 63, packed with data
        // representation template 5.51. The unpacked subset of 462 values
        // is in IEEE floats here, where the edition 1 file has it in IBM
        // ones.
        //
        // The oracle is ECMWF's ecCodes again, on the same file: 4160 values
        // whose first eight are 288.233642578125, 0, -1.2372474670410156, 0,
        // -12.765009880065918, 0, -0.14498311281204224 and 0, and whose last
        // two are -0.006673373380835431 and -0.00679756274442402.
        let data = include_bytes!("../testdata/grib/spherical_pressure_level.grib2");
        let out = text(Grib.extract(data, "spherical_pressure_level.grib2"));
        assert!(
            out.contains("grid: spherical harmonics, truncation J 63, K 63, M 63"),
            "{out}"
        );
        assert!(
            out.contains(
                "grid: 2080 complex coefficients, the real and the imaginary part of each"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "representation type 1 (the associated Legendre functions of the first kind), representation mode 1"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "data: template 5.51 complex packing, 4160 values, the unpacked subset 462 of them, reference -12.468270301818848, E -11, D 0, 16 bits per value, Laplacian operator 0.722"
            ),
            "{out}"
        );
        assert!(
            out.contains("value range: minimum -12.765009880065918, maximum 288.233642578125"),
            "{out}"
        );
        let values = reported_values(&out);
        assert_eq!(values.len(), 24, "{out}");
        assert_eq!(values[0], "288.233642578125", "{out}");
        assert_eq!(values[1], "0", "{out}");
        assert_eq!(values[2], "-1.2372474670410156", "{out}");
        assert_eq!(values[4], "-12.765009880065918", "{out}");
        assert_eq!(values[6], "-0.14498311281204224", "{out}");

        // The last two values are in the packed part, and the report prints
        // only the first ones.
        let sections = grib2_sections(data);
        let section = |number: u8| sections.iter().find(|(n, _)| *n == number).unwrap().1;
        let truncation = grib2_truncation(section(3)).expect("the truncation");
        let drs = grib2_s5(section(5));
        let mut report = String::new();
        let values = grib2_spectral_complex(&section(7)[5..], &drs, Some(&truncation), &mut report)
            .expect("the field decodes");
        assert_eq!(values.len(), 4160);
        assert_close(values[4158], -0.006673373380835431);
        assert_close(values[4159], -0.00679756274442402);
        // The whole field again, as the oracle gives it:
        //
        //     sum = 275.55654812152238
        //     sum of squares = 83258.383548307451
        assert_close(values.iter().sum::<f64>(), 275.5565481215224);
        assert_close(values.iter().map(|v| v * v).sum::<f64>(), 83258.38354830745);
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib1_rotated_grid_fixture_decodes_every_point() {
        // 496 x 372 points, so 184512 values in 369024 bytes of packed data.
        // The count, the bit budget and the grid all have to agree.
        let data = include_bytes!("../testdata/grib/rotated_ll.grib1");
        let out = text(Grib.extract(data, "rotated_ll.grib1"));
        assert!(
            out.contains("grid: type 10 (rotated lat/lon), 496 x 372 = 184512 points"),
            "{out}"
        );
        assert!(out.contains("packed values: 184512 values"), "{out}");
        assert!(
            out.contains("minimum 273.427490234375, maximum 308.972412109375"),
            "{out}"
        );
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_reduced_gaussian_grid_fixture_reports_its_rows_too() {
        // The same optional list of numbers, in a Gaussian grid: 196 rows
        // whose points run from 864 to 1280. The sum of them is not the
        // number of data points the section declares, and the reader says so
        // rather than making the two agree.
        //
        // The oracle is the pair again: NOAA's g2c library and ECMWF's
        // ecCodes both read 196 rows whose list runs from 864 to 1280 and
        // sums to 229287, against the 67001 data points the section declares.
        let data = include_bytes!("../testdata/grib/N320.area.grib");
        let out = text(Grib.extract(data, "N320.area.grib"));
        assert!(
            out.contains(
                "grid: source 0 (0 = specified here), 67001 data points, grid definition template 3.40"
            ),
            "{out}"
        );
        assert!(
            out.contains("grid: 196 rows, the number of columns is missing: the grid is reduced"),
            "{out}"
        );
        assert!(
            out.contains(
                "grid: the list of numbers gives the points of each row (code table 3.11 interpretation 1)"
            ),
            "{out}"
        );
        assert!(
            out.contains(
                "grid: the 196 rows hold 229287 points, and the section declares 67001 data points: they do not agree"
            ),
            "{out}"
        );
        assert!(out.contains("grid: 864 to 1280 points per row"), "{out}");
        assert!(
            out.contains("grid: points per row, the first 24 of 196:"),
            "{out}"
        );
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib1_octet_14_flags_say_which_layout_of_the_second_order_packing_it_is() {
        // A section that packs its values with the second-order packing says
        // in octet 14 which of the layouts of that packing it is, and the
        // order of the spatial differencing is in the last two bits. The
        // flags are read so that the refusal names the layout.
        //
        // The oracle is code table 11-2, the one ECMWF's ecCodes ships:
        // the second bit is a matrix of values at each grid point, the third
        // a secondary bit map, the fourth the widths of the second-order
        // values, the fifth the general extended packing, the sixth the
        // ordering and the last two the order of the spatial differencing.
        let msg = grib1_second_order_message(0b0111_1010);
        let out = text(Grib.extract(&msg, "t.grb"));
        assert!(
            out.contains(
                "octet 14 flags: a matrix of values at each grid point, a secondary bit map, second-order values of different widths, the general extended packing, the standard ordering, the second order of the spatial differencing"
            ),
            "{out}"
        );
        assert!(out.contains("not decoded (second-order packing"), "{out}");
        assert!(!out.contains("value range"), "{out}");

        // The other layout: a single datum at each point, one width for the
        // second-order values, boustrophedonic ordering and no spatial
        // differencing at all.
        let msg = grib1_second_order_message(0b0000_0100);
        let out = text(Grib.extract(&msg, "t.grb"));
        assert!(
            out.contains(
                "octet 14 flags: a single datum at each grid point, second-order values of one width, boustrophedonic ordering, no spatial differencing"
            ),
            "{out}"
        );
    }

    #[test]
    #[cfg(feature = "grib")]
    fn a_file_with_both_grib_editions_reports_both() {
        // The ECCWF test file holds edition 1 messages and edition 2
        // messages in one file. The edition 1 ones are constant fields: no
        // bits per value, every point holding the reference.
        let data = include_bytes!("../testdata/grib/regular_ll.grib");
        let out = text(Grib.extract(data, "regular_ll.grib"));
        assert!(out.contains("grib edition 1 message"), "{out}");
        assert!(out.contains("grib edition 2 message"), "{out}");
        assert!(out.contains("packed values: 4 values, all 0"), "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn a_file_without_the_grib_indicator_is_not_ours() {
        assert!(Grib
            .extract(b"NOTGRIB at all, just some bytes", "x.grb")
            .is_err());
    }

    /// The values the report prints under its "first values" line.
    #[cfg(feature = "grib")]
    fn reported_values(out: &str) -> Vec<String> {
        let mut values = Vec::new();
        let mut inside = false;
        for line in out.lines() {
            if line.trim() == "first values:" {
                inside = true;
                continue;
            }
            if inside {
                let trimmed = line.trim();
                if trimmed.parse::<f64>().is_err() {
                    break;
                }
                values.push(trimmed.to_string());
            }
        }
        values
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_complex_packing_fixture_matches_the_reference_decoder() {
        // A real NCEP message: the relative humidity at 3000 hPa of the GFS
        // 2.5 degree grid, packed with the complex packing and the first
        // order of the spatial differencing. The field is split into 547
        // groups, and each group carries its own reference value, its own
        // width and its own length.
        //
        // The oracle is NOAA's g2c library, the one NCEP writes these files
        // with: it reads the message as 10512 values between 0 and 4.5
        // percent, and the reader has to give the same ones back.
        let data = include_bytes!("../testdata/grib/gfs_complex_packing.grib2");
        let out = text(Grib.extract(data, "gfs_complex_packing.grib2"));
        // The grid of the message: 73 rows of 144 columns, which is what
        // both NOAA's g2c library and ECMWF's ecCodes read out of the same
        // bytes.
        assert!(out.contains("grid: 73 rows, 144 columns"), "{out}");
        assert!(
            out.contains(
                "data: template 5.3 complex packing, 547 groups, 5 bits per group reference, 3 bits per group width, 6 bits per group length, first order spatial differencing, reference 0, E 0, D 1, 10512 points"
            ),
            "{out}"
        );
        assert!(out.contains("value range: minimum 0, maximum 4.5"), "{out}");
        let values = reported_values(&out);
        assert_eq!(values.len(), 24, "{out}");
        assert!(
            values.iter().all(|value| value == "1"),
            "the first values are not the ones the reference decoder gives: {out}"
        );
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_message_with_two_fields_decodes_each_field_with_its_own_sections() {
        // A message can hold more than one product: the sections 4, 5, 6 and
        // 7 repeat. The two fields of this NCEP message are the u and the v
        // component of the wind, and each of them has its own group table:
        // 723 groups against 730, and reference values of -352 against -685.
        // Reading the last section 5 with the first section 7 would give the
        // first field's values with the second field's packing.
        let data = include_bytes!("../testdata/grib/gfs_complex_packing_two_fields.grib2");
        let out = text(Grib.extract(data, "gfs_complex_packing_two_fields.grib2"));
        assert!(
            out.contains("parameter: discipline 0 category 2 number 2 (momentum)"),
            "{out}"
        );
        assert!(
            out.contains(
                "data: template 5.3 complex packing, 723 groups, 8 bits per group reference, 4 bits per group width, 5 bits per group length, first order spatial differencing, reference -352, E 0, D 1, 10512 points"
            ),
            "{out}"
        );
        assert!(
            out.contains("value range: minimum -35.2, maximum 106"),
            "{out}"
        );
        assert!(
            out.contains("parameter: discipline 0 category 2 number 3 (momentum)"),
            "{out}"
        );
        assert!(
            out.contains(
                "data: template 5.3 complex packing, 730 groups, 8 bits per group reference, 3 bits per group width, 5 bits per group length, first order spatial differencing, reference -685, E 0, D 1, 10512 points"
            ),
            "{out}"
        );
        assert!(
            out.contains("value range: minimum -68.5, maximum 63"),
            "{out}"
        );
        // The first field is decoded before the second one.
        let first = out.find("723 groups").expect("the first field is missing");
        let second = out.find("730 groups").expect("the second field is missing");
        assert!(first < second, "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_second_order_spatial_differencing_fixture_decodes_the_field_it_came_from() {
        // The second order of the spatial differencing: every value is
        // stored as the difference from twice the value before it minus the
        // one before that, and the smallest of those differences was taken
        // off all of them before they were stored.
        //
        // The file was written by NOAA's g2c library from a field of whole
        // numbers -- 1000 plus three per column and two per row of a 40 by
        // 30 grid -- and the scale factors are zero, so the values have to
        // come back whole.
        let data = include_bytes!("../testdata/grib/second_order_spatial_differencing.grib2");
        let out = text(Grib.extract(data, "second_order_spatial_differencing.grib2"));
        assert!(
            out.contains(
                "data: template 5.3 complex packing, 60 groups, 7 bits per group reference, 4 bits per group width, 6 bits per group length, second order spatial differencing, reference 1000, E 0, D 0, 1200 points"
            ),
            "{out}"
        );
        assert!(
            out.contains("value range: minimum 1000, maximum 1175"),
            "{out}"
        );
        let values = reported_values(&out);
        assert_eq!(values.len(), 24, "{out}");
        assert_eq!(values[0], "1000", "{out}");
        assert_eq!(values[1], "1003", "{out}");
        assert_eq!(values[2], "1006", "{out}");
    }

    #[test]
    #[cfg(feature = "grib")]
    fn grib2_bit_map_lines_the_values_up_with_the_points_of_the_grid() {
        // Six points of the grid, one of them without a value: the section
        // holds five values, the ones of the points the map marks. The map
        // indexes the points of the grid, so it has to be walked over the
        // whole grid and not over the values alone.
        let data = include_bytes!("../testdata/grib/scanning_mode_with_bitmap.grib2");
        let out = text(Grib.extract(data, "scanning_mode_with_bitmap.grib2"));
        assert!(
            out.contains("data: template 5.0 simple packing, 16 bits per value, reference 0, E 0, D 0, 5 points"),
            "{out}"
        );
        assert!(
            out.contains("data: 1 points masked off by the bit map"),
            "{out}"
        );
        let values = reported_values(&out);
        assert_eq!(values.len(), 5, "{out}");
        assert_eq!(values.join(" "), "1 2 3 4 5", "{out}");
    }

    // ---- BUFR ------------------------------------------------------------

    /// A BUFR message whose `7777` lands exactly at the declared end, which
    /// is the only place the terminator can be if the length is right.
    #[cfg(feature = "bufr")]
    fn bufr_message(edition: u8, body_len: usize, terminator: &[u8]) -> Vec<u8> {
        assert!(body_len >= 4);
        let total = 8 + body_len;
        let mut msg = Vec::new();
        msg.extend_from_slice(b"BUFR");
        msg.push((total >> 16) as u8);
        msg.push((total >> 8) as u8);
        msg.push(total as u8);
        msg.push(edition);
        msg.extend_from_slice(&vec![0u8; body_len - 4]);
        msg.extend_from_slice(terminator);
        msg
    }

    #[test]
    #[cfg(feature = "bufr")]
    fn a_bufr_message_reports_its_edition_and_declared_length() {
        let msg = bufr_message(4, 8, b"7777");
        let out = text(Bufr.extract(&msg, "o.bufr"));
        assert!(out.contains("bufr edition 4"), "{out}");
        assert!(out.contains("section 0 declares 16 bytes"), "{out}");
        assert!(out.contains("\"7777\" present"), "{out}");
    }

    #[test]
    #[cfg(feature = "bufr")]
    fn a_bufr_message_without_the_terminator_says_so_instead_of_inventing_it() {
        let msg = bufr_message(4, 8, b"0000");
        let out = text(Bufr.extract(&msg, "o.bufr"));
        assert!(out.contains("no \"7777\""), "{out}");
        assert!(out.contains("not decoded"), "{out}");
    }

    #[test]
    #[cfg(feature = "bufr")]
    fn a_bufr_message_that_declares_more_than_it_holds_is_truncated_not_faked() {
        let mut msg = b"BUFR\xff\xff\xff\x04".to_vec();
        msg.extend_from_slice(&[0; 4]);
        let out = text(Bufr.extract(&msg, "o.bufr"));
        assert!(out.contains("truncated"), "{out}");
    }

    #[test]
    #[cfg(feature = "bufr")]
    fn a_file_without_the_bufr_indicator_is_not_ours() {
        assert!(Bufr.extract(b"BUFRX", "x.bufr").is_err());
    }

    // ---- SEG-Y -----------------------------------------------------------

    /// Encode an ASCII string as CP037 with the table the adapter uses. Only
    /// used for the round trip; the pins against real CP037 bytes are in
    /// `ebcdic_matches_the_codes_people_actually_write` below.
    #[cfg(feature = "segy")]
    fn to_ebcdic(s: &str) -> Vec<u8> {
        let t = cp037_table();
        let mut rev = [0u8; 256];
        for (i, &v) in t.iter().enumerate() {
            rev[v as usize] = i as u8;
        }
        s.bytes()
            .map(|b| if b == b' ' { 0x40 } else { rev[b as usize] })
            .collect()
    }

    #[cfg(feature = "segy")]
    fn segy_file(textual: &[u8], binary: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(textual);
        out.extend_from_slice(binary);
        out
    }

    /// Well-known CP037 encodings, written out literally rather than through
    /// the table under test. "Hello" is `C8 85 93 93 96`, so `H` is 0xC8,
    /// `e` is 0x85, `l` is 0x93 and `o` is 0x96; digits are `F0`-`F9` and a
    /// blank is `40`. If the table is wrong, this fails.
    #[test]
    #[cfg(feature = "segy")]
    fn ebcdic_matches_the_codes_people_actually_write() {
        let t = cp037_table();
        assert_eq!(t[0x40], b' ');
        assert_eq!(t[0xc8], b'H');
        assert_eq!(t[0x85], b'e');
        assert_eq!(t[0x93], b'l');
        assert_eq!(t[0x96], b'o');
        assert_eq!(t[0xc3], b'C');
        assert_eq!(t[0xf1], b'1');
        assert_eq!(t[0x4b], b'.');
        assert_eq!(t[0x6b], b',');
        assert_eq!(t[0x60], b'-');
        // The runs are separated by punctuation, so the letters on either
        // side of a separator are not one apart.
        assert_eq!(t[0x49], b'I');
        assert_eq!(t[0x4a], b'[');
        assert_eq!(t[0x51], b'J');
        assert_eq!(t[0x89], b'i');
        assert_eq!(t[0x91], b'j');
    }

    /// The bug class this format is famous for: a textual header written in
    /// EBCDIC read as ASCII. The card must come out as "C 1 LINE 3440" in
    /// ASCII, and the raw EBCDIC bytes must not survive into the report.
    #[test]
    #[cfg(feature = "segy")]
    fn a_segy_text_header_is_ebcdic_not_ascii() {
        let mut textual = vec![0x40u8; 3200];
        let line = to_ebcdic("C 1 LINE 3440");
        textual[..line.len()].copy_from_slice(&line);
        let mut binary = vec![0u8; 400];
        binary[20..22].copy_from_slice(&be16(10752)); // samples per trace
        binary[16..18].copy_from_slice(&be16(4000)); // sample interval
        binary[24..26].copy_from_slice(&be16(5)); // IEEE float
        let file = segy_file(&textual, &binary);

        let out = text(Segy.extract(&file, "s.sgy"));
        assert!(out.contains("IBM EBCDIC CP037"), "{out}");
        assert!(out.contains("C 1 LINE 3440"), "{out}");
        // 0xC3 is 'C' in EBCDIC and 0xE3 in Latin-1; if the header had been
        // passed through, the card would read "c 1 line" in garbage.
        assert!(
            out.contains("line 3440") || out.contains("LINE 3440"),
            "{out}"
        );
        assert!(out.contains("sample interval: 4000 us"), "{out}");
        assert!(out.contains("samples per trace: 10752"), "{out}");
        assert!(out.contains("4-byte IEEE floating-point"), "{out}");
    }

    #[test]
    #[cfg(feature = "segy")]
    fn an_ascii_segy_text_header_is_recognised_as_ascii() {
        let mut textual = vec![b' '; 3200];
        let line = b"C 20 CLIENT ACME SEISMIC";
        textual[..line.len()].copy_from_slice(line);
        let binary = vec![0u8; 400];
        let file = segy_file(&textual, &binary);
        let out = text(Segy.extract(&file, "s.sgy"));
        assert!(out.contains("ASCII"), "{out}");
        assert!(out.contains("C 20 CLIENT ACME SEISMIC"), "{out}");
    }

    #[test]
    #[cfg(feature = "segy")]
    fn segy_trace_headers_report_the_shot_and_the_cdp() {
        let mut textual = vec![0x40u8; 3200];
        let card = to_ebcdic("C 1 SURVEY 2026");
        textual[..card.len()].copy_from_slice(&card);
        let mut binary = vec![0u8; 400];
        binary[20..22].copy_from_slice(&be16(2)); // samples per trace
        binary[24..26].copy_from_slice(&be16(5)); // IEEE float
        let mut file = segy_file(&textual, &binary);

        let mut header = vec![0u8; 240];
        header[0..4].copy_from_slice(&be32(1)); // seq-in-line
        header[12..16].copy_from_slice(&be32(100)); // shot
        header[20..24].copy_from_slice(&be32(500)); // CDP
        file.extend_from_slice(&header);
        file.extend_from_slice(&[0u8; 8]); // two 4-byte samples

        let out = text(Segy.extract(&file, "s.sgy"));
        assert!(out.contains("shot 100"), "{out}");
        assert!(out.contains("CDP 500"), "{out}");
        assert!(out.contains("1 trace header(s) reported"), "{out}");
    }

    #[test]
    #[cfg(feature = "segy")]
    fn a_truncated_segy_is_reported_without_panicking() {
        let mut file = vec![0x40u8; 3200];
        let card = to_ebcdic("C 1 TRUNCATED");
        file[..card.len()].copy_from_slice(&card);
        file.extend_from_slice(&[0u8; 100]); // binary header cut short
        let out = text(Segy.extract(&file, "s.sgy"));
        assert!(out.contains("binary header"), "{out}");
    }

    #[test]
    #[cfg(feature = "segy")]
    fn a_short_or_non_segy_file_is_not_ours() {
        assert!(Segy.extract(b"short", "s.sgy").is_err());
        let mut junk = vec![0xa5u8; 3600];
        junk[0] = b'Z';
        assert!(Segy.extract(&junk, "s.sgy").is_err());
    }

    // ---- ROOT ------------------------------------------------------------

    #[test]
    #[cfg(feature = "root")]
    fn a_root_file_reports_its_key_and_version() {
        let mut data = Vec::new();
        data.extend_from_slice(b"root");
        data.extend_from_slice(&62824i32.to_be_bytes());
        data.extend_from_slice(&[0u8; 100]);
        let out = text(Root.extract(&data, "h.root"));
        assert!(out.contains("CERN ROOT file"), "{out}");
        assert!(out.contains("file format version: 62824"), "{out}");
        assert!(out.contains("not decoded"), "{out}");
    }

    #[test]
    #[cfg(feature = "root")]
    fn a_root_key_without_a_version_field_is_not_ours() {
        assert!(Root.extract(b"root", "h.root").is_err());
        assert!(Root.extract(b"roo", "h.root").is_err());
    }

    // ---- N5 --------------------------------------------------------------

    #[test]
    #[cfg(feature = "n5")]
    fn an_n5_file_reports_the_hdf5_superblock() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x89HDF\r\n\x1a\n");
        data.push(0); // superblock version
        data.push(8); // address size
        data.push(8); // length size
        data.extend_from_slice(&[0u8; 64]);
        let out = text(N5.extract(&data, "s.n5"));
        assert!(out.contains("HDF5 container"), "{out}");
        assert!(out.contains("superblock version: 0"), "{out}");
        assert!(out.contains("address size: 8 bytes"), "{out}");
        assert!(out.contains("not decoded"), "{out}");
    }

    #[test]
    #[cfg(feature = "n5")]
    fn a_file_without_the_hdf5_signature_is_not_ours() {
        assert!(N5.extract(b"\x89HDF", "s.n5").is_err());
        assert!(N5.extract(&[0u8; 64], "s.n5z").is_err());
    }

    // ---- cross-cutting ---------------------------------------------------

    /// Zarr metadata is JSON text. ripgrep already reads it, so no adapter
    /// in this module may claim it — an adapter that did would replace bytes
    /// ripgrep would have matched. (The array's data is in binary chunks,
    /// and reading those is not this module's job either.)
    #[test]
    #[cfg(all(
        feature = "bufr",
        feature = "grib",
        feature = "n5",
        feature = "root",
        feature = "segy"
    ))]
    fn json_zarr_metadata_is_not_claimed_by_any_scientific_adapter() {
        let zarr = br#"{"zarr_format": 2, "shape": [3, 4], "chunks": [[2, 2]]}"#;
        for data in [zarr.as_slice(), b"", b"null"] {
            assert!(Grib.extract(data, "a.zarr").is_err());
            assert!(Bufr.extract(data, "a.zmetadata").is_err());
            assert!(Segy.extract(data, "a.sgy").is_err());
            assert!(Root.extract(data, "a.root").is_err());
            assert!(N5.extract(data, "a.n5").is_err());
        }
    }

    #[cfg(any(
        all(
            feature = "bufr",
            feature = "grib",
            feature = "n5",
            feature = "root",
            feature = "segy"
        ),
        feature = "grib"
    ))]
    mod fuzz {
        use super::*;

        #[test]
        #[cfg(all(
            feature = "bufr",
            feature = "grib",
            feature = "n5",
            feature = "root",
            feature = "segy"
        ))]
        fn scientific_adapters_never_panic_on_mutation() {
            let seeds: Vec<(&str, Vec<u8>)> = vec![
                ("grib2", simple_grib2(0, 6, 4, 16, &[1, 2, 3, 4])),
                ("bufr", bufr_message(4, 16, b"7777")),
                ("ebcdic-header", {
                    let mut v = vec![0x40u8; 3200];
                    let card = to_ebcdic("C 1 LINE 3440");
                    v[..card.len()].copy_from_slice(&card);
                    v.extend_from_slice(&[0u8; 400]);
                    v
                }),
                ("root", {
                    let mut v = b"root".to_vec();
                    v.extend_from_slice(&62824i32.to_be_bytes());
                    v
                }),
                ("hdf5", {
                    let mut v = b"\x89HDF\r\n\x1a\n".to_vec();
                    v.push(0);
                    v.extend_from_slice(&[8, 8, 0, 0]);
                    v
                }),
                ("truncated-grib", b"GRIB\x00\x00\x02\x00\x00".to_vec()),
                ("empty", vec![]),
            ];
            for (label, _) in &seeds {
                rgx_core::fuzzkit::assert_never_panics(seeds.clone(), 1200, label, |data| {
                    let _ = Grib.extract(data, "f.grb");
                    let _ = Bufr.extract(data, "f.bufr");
                    let _ = Segy.extract(data, "f.sgy");
                    let _ = Root.extract(data, "f.root");
                    let _ = N5.extract(data, "f.n5");
                });
            }
        }

        /// A GRIB message is the most structured input this crate parses: the
        /// header walks offsets and the body walks a bit stream, so the state
        /// a hand-rolled index is most likely to panic in is a header that
        /// still parses and a body that no longer matches it. The real
        /// messages are the seeds because a mutation of them lands in that
        /// state far more often than a mutation of a synthetic one.
        #[test]
        #[cfg(feature = "grib")]
        fn grib_never_panics_on_mutation() {
            let corpus: Vec<(&'static str, Vec<u8>)> = vec![
                (
                    "grib1-latlon",
                    include_bytes!("../testdata/grib/regular_latlon_surface.grib1").to_vec(),
                ),
                (
                    "grib1-rotated",
                    include_bytes!("../testdata/grib/rotated_ll.grib1").to_vec(),
                ),
                (
                    "grib1-spectral",
                    include_bytes!("../testdata/grib/spherical_pressure_level.grib1").to_vec(),
                ),
                (
                    "grib1-and-grib2",
                    include_bytes!("../testdata/grib/regular_ll.grib").to_vec(),
                ),
            ];
            for (label, _) in &corpus {
                rgx_core::fuzzkit::assert_never_panics(corpus.clone(), 200, label, |data| {
                    let _ = Grib.extract(data, "f.grb");
                });
            }
        }
    }
}
