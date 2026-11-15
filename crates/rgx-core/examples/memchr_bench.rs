// SPDX-License-Identifier: Apache-2.0

//! The byte scan rgx used to write itself, against the crate it uses now.
//!
//! ```text
//! cargo run --release -p rgx-core --example memchr_bench
//! ```
//!
//! Both implementations link into this one binary and run over the same
//! buffers, so the comparison is same-process and same-input — the only
//! variable is the function under test.
//!
//! ## Why the code is inlined here
//!
//! `rgx-core` carried `src/memchr.rs`, 901 lines with an AVX2 path and a
//! SWAR fallback, and the crate decided to delete it: the crate's is
//! faster on every shape that scales with corpus size, which is every
//! shape rgx actually runs. The reasoning and the numbers are in the
//! `rgx-core` crate header.
//!
//! That leaves this benchmark measuring something no longer in the tree.
//! So the candidate implementation is inlined below rather than left as a
//! dead module in the library. It is the code as it stood when the
//! decision was taken — the same SWAR zero-byte test and the same AVX2
//! window order — copied verbatim, and it is here so the decision stays
//! re-runnable instead of becoming a claim in a comment. If the crate
//! ever regresses on one of these rows, this is the file that says so.
//!
//! ## What is being compared
//!
//! The two surfaces do not line up name for name, and pretending they do
//! would make the table lie:
//!
//! | crate          | in-house                        |
//! |----------------|---------------------------------|
//! | `memchr`       | `memchr` (AVX2 + SWAR)          |
//! | `memrchr`      | `memrchr` (SWAR only, no SIMD)  |
//! | `memchr2`/`3`  | `memmem_find`, 2-/3-byte needle |
//! | `memchr_iter`  | `memchr_iter` (restart loop)    |
//! | `memmem::find` | `memmem_find`                   |
//!
//! `memchr2` and `memchr3` have no counterpart in the in-house module
//! and nothing in the workspace calls them, so the 2- and 3-byte rows
//! measure the substring search on both sides — which is the same idea
//! those two functions implement, anchor-scan-then-confirm. `memchr2/3`
//! are not claimed as covered.
//!
//! ## Buffers
//!
//! * `buf64` — 64 KiB of line-oriented text. This is the searcher's read
//!   buffer (`buffer_capacity: 64 * 1024`, `rgx-core/src/searcher.rs`)
//!   and the size of the per-file NUL sniff (`src/main.rs`). It is what
//!   nearly every call site touches, once per read and once per file.
//! * `buf8m` — 8 MiB of the same text: one large file walked end to end.
//! * `blob8m` — 8 MiB of high-entropy bytes: an archive member or a
//!   vertex buffer, and the inspector's 45-signature scan shape.
//!
//! ## Method
//!
//! Warmup is run and discarded, then 7 timed rounds are taken and the
//! *minimum* is reported — the minimum is the round least disturbed by
//! scheduler noise, which is the number that describes the code.
//! `black_box` wraps both input and result so LLVM cannot hoist the call
//! out of the loop or fold it away.

use std::hint::black_box;
use std::time::Instant;

const ROUNDS: usize = 7;
const WARMUP: usize = 2;
/// Target milliseconds of work per round. The iteration count is
/// calibrated against one untimed call, so a 64 KiB case and an 8 MiB case
/// both get enough samples to be worth dividing.
const TARGET_MS: f64 = 40.0;

const KI: usize = 1024;
const MIB: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// The in-house implementation, verbatim from the module that was deleted.
// ---------------------------------------------------------------------------

const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;

fn ih_memchr(needle: u8, hay: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: the branch is taken only where AVX2 is present, and
            // the callee carries `#[target_feature(enable = "avx2")]`.
            return unsafe { avx2::memchr(needle, hay) };
        }
    }
    ih_memchr_swar(needle, hay)
}

/// Backwards, and SWAR in both directions — there is no SIMD path here in
/// either direction. That is the whole of the 7x on the absent-byte row.
fn ih_memrchr(needle: u8, hay: &[u8]) -> Option<usize> {
    let rep = LO.wrapping_mul(needle as u64);
    let n = hay.len();
    let mut end = n;
    while end >= 8 {
        let start = end - 8;
        let chunk = u64::from_le_bytes(hay[start..end].try_into().unwrap());
        let x = chunk ^ rep;
        let hit = x.wrapping_sub(LO) & !x & HI;
        if hit != 0 {
            // The subtraction borrows, so the byte above a real match can be
            // marked without being equal. Verify each marker.
            let mut rest = hit;
            loop {
                let k = 7 - (rest.leading_zeros() / 8) as usize;
                if hay[start + k] == needle {
                    return Some(start + k);
                }
                rest &= !(1u64 << (8 * k + 7));
                if rest == 0 {
                    break;
                }
            }
        }
        end = start;
    }
    while end > 0 {
        end -= 1;
        if hay[end] == needle {
            return Some(end);
        }
    }
    None
}

/// Eight bytes per 64-bit word.
fn ih_memchr_swar(needle: u8, hay: &[u8]) -> Option<usize> {
    let rep = LO.wrapping_mul(needle as u64);
    let n = hay.len();
    let mut i = 0;
    while i + 8 <= n {
        let chunk = u64::from_le_bytes(hay[i..i + 8].try_into().unwrap());
        // Set the high bit of every byte that is zero in `x`, then mask
        // out positions whose borrow could have set a false positive.
        let x = chunk ^ rep;
        let hit = x.wrapping_sub(LO) & !x & HI;
        if hit != 0 {
            return Some(i + (hit.trailing_zeros() / 8) as usize);
        }
        i += 8;
    }
    while i < n {
        if hay[i] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// 128 bytes per iteration in the interior — four 32-byte compares issued
/// together and then tested in window order — then 32 at a time, then a
/// byte loop over the sub-word tail.
#[cfg(target_arch = "x86_64")]
mod avx2 {
    use core::arch::x86_64::*;

    #[target_feature(enable = "avx2")]
    pub unsafe fn memchr(needle: u8, hay: &[u8]) -> Option<usize> {
        let n = hay.len();
        let vneedle = _mm256_set1_epi8(needle as i8);
        let base = hay.as_ptr();
        let mut i = 0usize;

        while i + 128 <= n {
            let a = _mm256_loadu_si256(base.add(i) as *const __m256i);
            let b = _mm256_loadu_si256(base.add(i + 32) as *const __m256i);
            let c = _mm256_loadu_si256(base.add(i + 64) as *const __m256i);
            let d = _mm256_loadu_si256(base.add(i + 96) as *const __m256i);
            // Four windows in flight, but their masks are tested in order
            // rather than folded together: OR-ing them would put every
            // window's hits in the same lanes, and a hit in the third
            // window's lane 1 would be reported as if it were in the first
            // — the scan would return an index 64 bytes early.
            let ma = _mm256_movemask_epi8(_mm256_cmpeq_epi8(a, vneedle)) as u32;
            let mb = _mm256_movemask_epi8(_mm256_cmpeq_epi8(b, vneedle)) as u32;
            let mc = _mm256_movemask_epi8(_mm256_cmpeq_epi8(c, vneedle)) as u32;
            let md = _mm256_movemask_epi8(_mm256_cmpeq_epi8(d, vneedle)) as u32;
            if ma != 0 {
                return Some(i + ma.trailing_zeros() as usize);
            }
            if mb != 0 {
                return Some(i + 32 + mb.trailing_zeros() as usize);
            }
            if mc != 0 {
                return Some(i + 64 + mc.trailing_zeros() as usize);
            }
            if md != 0 {
                return Some(i + 96 + md.trailing_zeros() as usize);
            }
            i += 128;
        }
        while i + 32 <= n {
            let a = _mm256_loadu_si256(base.add(i) as *const __m256i);
            let mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(a, vneedle)) as u32;
            if mask != 0 {
                return Some(i + mask.trailing_zeros() as usize);
            }
            i += 32;
        }
        // Fewer than 32 bytes left: a 32-byte load here would read past the
        // slice, so finish one byte at a time.
        while i < n {
            if *base.add(i) == needle {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

/// A restart loop: each `next` re-enters the scan at the byte after the
/// last hit. The crate's iterator instead keeps a candidate mask for a
/// block and yields bits out of it, which is the gap on dense input.
struct IhMemchrIter<'a> {
    needle: u8,
    hay: &'a [u8],
    pos: usize,
}

impl Iterator for IhMemchrIter<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        let found = ih_memchr(self.needle, &self.hay[self.pos..])?;
        let at = self.pos + found;
        self.pos = at + 1;
        Some(at)
    }
}

fn ih_memchr_iter(needle: u8, hay: &[u8]) -> IhMemchrIter<'_> {
    IhMemchrIter {
        needle,
        hay,
        pos: 0,
    }
}

/// Scan for the needle's *last* byte at SIMD speed, confirm on candidates.
/// The anchor is the last byte because for markup and OOXML — the streams
/// that dominate the hot callers — the trailing byte is the more selective.
fn ih_memmem_find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() == 1 {
        return ih_memchr(needle[0], hay);
    }
    let anchor = needle[needle.len() - 1];
    let prefix = &needle[..needle.len() - 1];
    let mut from = 0usize;
    while from < hay.len() {
        let rel = ih_memchr(anchor, &hay[from..])?;
        let at = from + rel;
        // The needle would end at `at`, so it starts at `at - prefix.len()`.
        // Guard the underflow before slicing.
        if at >= prefix.len() && hay[at - prefix.len()..at] == *prefix {
            return Some(at + 1 - needle.len());
        }
        from = at + 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Line-oriented text: the shape of everything the searcher reads. Lines
/// are short and newline-dense, the realistic worst case for a backwards
/// scan (the terminator is close behind, so the scan does not run long).
fn text_line(len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(len + 64);
    let mut x: u64 = 0x243f_6a88_85a3_08d3;
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if x.is_multiple_of(5) {
            v.push(b'\n');
        } else {
            v.extend_from_slice(b"<div class=\"row\"><span>text</span></div>\n");
        }
    }
    v.truncate(len);
    v
}

/// The same text with the last newline at the very end of the buffer.
///
/// The searcher calls `memrchr` on the bytes a read just added, looking for
/// the newest line terminator. That terminator is usually the last byte of
/// the new bytes, and the backwards scan finds it at once — measuring
/// "scan the whole buffer" there would report a number for a path that
/// does not run.
fn text_line_dense_tail(len: usize) -> Vec<u8> {
    let mut v = text_line(len);
    let n = v.len();
    v[n - 2] = b'x';
    v[n - 1] = b'\n';
    v
}

/// High-entropy bytes, no newlines. Bytes are `1 + x % 254`, so 0x00 and
/// 0xff are the two values that cannot occur — which is what makes them
/// usable as absent needles, and `assert_absent` checks that they are.
fn blob(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for b in v.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = 1 + (x % 254) as u8;
    }
    v
}

/// Microseconds per call, minimum over [`ROUNDS`] rounds.
fn time_us(f: impl Fn() -> usize) -> f64 {
    for _ in 0..WARMUP {
        black_box(f());
    }

    let t = Instant::now();
    black_box(f());
    let one = t.elapsed().as_secs_f64().max(1e-9);
    let iters = (TARGET_MS / 1e3 / one).clamp(1.0, 100_000.0) as usize;

    let mut best = f64::INFINITY;
    for _ in 0..ROUNDS {
        let t = Instant::now();
        let mut sink = 0usize;
        for _ in 0..iters {
            sink = sink.wrapping_add(black_box(f()));
        }
        black_box(sink);
        best = best.min(t.elapsed().as_secs_f64() * 1e6 / iters as f64);
    }
    best
}

struct Row {
    case: &'static str,
    in_house: f64,
    crate_: f64,
}

impl Row {
    fn new(case: &'static str, in_house: f64, crate_: f64) -> Self {
        Row {
            case,
            in_house,
            crate_,
        }
    }

    /// `in_house_time / crate_time`. Above 1.00 means the in-house module
    /// took *longer* and the crate won.
    fn ratio(&self) -> f64 {
        self.in_house / self.crate_
    }

    fn verdict(&self) -> &'static str {
        match self.ratio() {
            r if r > 1.02 => "crate",
            r if r < 0.98 => "in-house",
            _ => "tie",
        }
    }
}

fn main() {
    println!("rgx-core memchr: in-house (deleted) vs crate");
    println!(
        "buf64 = {} KiB text, buf64d = {} KiB text w/ newline at end, \
         buf8m = {} MiB text, blob8m = {} MiB blob",
        64 * KI / KI,
        64 * KI / KI,
        8 * MIB / MIB,
        8 * MIB / MIB
    );
    println!("min of {ROUNDS} timed rounds after {WARMUP} discarded warmup rounds\n");

    let buf64 = text_line(64 * KI);
    let buf64d = text_line_dense_tail(64 * KI);
    let buf8m = text_line(8 * MIB);
    let blob8m = blob(8 * MIB);

    /// Fails loudly if a row labelled "absent" actually hits.
    ///
    /// An earlier revision of this file labelled `b"\x0f\xa0"` an absent
    /// needle over the blob and measured 0.242 us for an 8 MiB scan, which
    /// is not a scan — the blob contains that pair, at offset 47. The
    /// assertion is here so a label cannot quietly become a lie again.
    fn assert_absent(hay: &[u8], needle: &[u8]) {
        assert!(
            ih_memmem_find(hay, needle).is_none()
                && rgx_core::memchr::memmem::find(hay, needle).is_none(),
            "row labelled `absent` actually finds {needle:?}"
        );
    }

    assert_absent(&buf64, b"\x0f\xa0");
    assert_absent(&buf64, b"\x0f\xa0\x01");
    assert_absent(&blob8m, b"\x00\xff");
    assert_absent(&blob8m, b"\x00\xff\x00");
    assert_absent(&blob8m, b"needle12345");
    assert!(
        ih_memmem_find(&buf64, b"div").is_some(),
        "markup needle `div` must be present"
    );
    assert_eq!(
        ih_memmem_find(&buf64, b"div"),
        rgx_core::memchr::memmem::find(&buf64, b"div")
    );

    let rows: Vec<Row> = vec![
        // ---- memchr, 1 byte ------------------------------------------------
        //
        // The per-file NUL sniff: one absent byte over one read buffer, once
        // per file. The highest-frequency memchr call in the binary.
        Row::new(
            "memchr 1B absent (NUL sniff), 64 KiB buf",
            time_us(|| ih_memchr(0, &buf64).unwrap_or(0)),
            time_us(|| rgx_core::memchr::memchr(0, &buf64).unwrap_or(0)),
        ),
        // The same sniff over a whole large file rather than one buffer.
        Row::new(
            "memchr 1B absent (NUL sniff), 8 MiB file",
            time_us(|| ih_memchr(0, &buf8m).unwrap_or(0)),
            time_us(|| rgx_core::memchr::memchr(0, &buf8m).unwrap_or(0)),
        ),
        // Present byte: the searcher's line scan stops at the first terminator.
        // Worst case for both is a hit on the last byte — full scan, then stop.
        Row::new(
            "memchr 1B present at end (line scan), 64 KiB buf",
            time_us(|| ih_memchr(b'\n', &buf64).unwrap_or(0)),
            time_us(|| rgx_core::memchr::memchr(b'\n', &buf64).unwrap_or(0)),
        ),
        // Hit on the first byte: the common shape when a file has more content
        // than one buffer.
        Row::new(
            "memchr 1B present at start, 64 KiB buf",
            time_us(|| ih_memchr(b'<', &buf64).unwrap_or(0)),
            time_us(|| rgx_core::memchr::memchr(b'<', &buf64).unwrap_or(0)),
        ),
        Row::new(
            "memchr 1B absent, 8 MiB blob",
            time_us(|| ih_memchr(0, &blob8m).unwrap_or(0)),
            time_us(|| rgx_core::memchr::memchr(0, &blob8m).unwrap_or(0)),
        ),
        // ---- 2- and 3-byte needles ----------------------------------------
        //
        // `memchr2`/`memchr3` are not implemented on the in-house side and are
        // not called anywhere, so these rows measure the substring search on
        // both sides. Absent over a blob is the inspector's shape: ~45
        // signatures, each a full pass, and the one you want is usually not
        // there.
        Row::new(
            "2-byte needle absent, 64 KiB buf",
            time_us(|| ih_memmem_find(&buf64, b"\x0f\xa0").unwrap_or(0)),
            time_us(|| rgx_core::memchr::memmem::find(&buf64, b"\x0f\xa0").unwrap_or(0)),
        ),
        Row::new(
            "2-byte needle absent, 8 MiB blob (inspector)",
            time_us(|| ih_memmem_find(&blob8m, b"\x00\xff").unwrap_or(0)),
            time_us(|| rgx_core::memchr::memmem::find(&blob8m, b"\x00\xff").unwrap_or(0)),
        ),
        Row::new(
            "3-byte needle absent, 64 KiB buf",
            time_us(|| ih_memmem_find(&buf64, b"\x0f\xa0\x01").unwrap_or(0)),
            time_us(|| rgx_core::memchr::memmem::find(&buf64, b"\x0f\xa0\x01").unwrap_or(0)),
        ),
        Row::new(
            "3-byte needle absent, 8 MiB blob (inspector)",
            time_us(|| ih_memmem_find(&blob8m, b"\x00\xff\x00").unwrap_or(0)),
            time_us(|| rgx_core::memchr::memmem::find(&blob8m, b"\x00\xff\x00").unwrap_or(0)),
        ),
        // Needles that *do* occur: the OOXML/pptx linear scan, where the spans
        // between hits are short. `div` rather than `</d>` for the 3-byte
        // row — the text ends the element `</div>`, so the `>` never follows
        // `</d`, and a "present" row labelled `</d>` is an absent one that
        // measures 24x worse.
        Row::new(
            "2-byte needle present (markup), 64 KiB buf",
            time_us(|| ih_memmem_find(&buf64, b"di").unwrap_or(0)),
            time_us(|| rgx_core::memchr::memmem::find(&buf64, b"di").unwrap_or(0)),
        ),
        Row::new(
            "3-byte needle present (markup), 64 KiB buf",
            time_us(|| ih_memmem_find(&buf64, b"div").unwrap_or(0)),
            time_us(|| rgx_core::memchr::memmem::find(&buf64, b"div").unwrap_or(0)),
        ),
        // A longer magic over a whole large file — a container signature
        // check. This is where the crate's longer-needle strategy pulls ahead
        // of anchor-and-confirm.
        Row::new(
            "5-byte needle absent, 8 MiB blob",
            time_us(|| ih_memmem_find(&blob8m, b"needle12345").unwrap_or(0)),
            time_us(|| rgx_core::memchr::memmem::find(&blob8m, b"needle12345").unwrap_or(0)),
        ),
        Row::new(
            "6-byte needle present (markup), 8 MiB file",
            time_us(|| ih_memmem_find(&buf8m, b"</div>").unwrap_or(0)),
            time_us(|| rgx_core::memchr::memmem::find(&buf8m, b"</div>").unwrap_or(0)),
        ),
        // ---- memrchr ------------------------------------------------------
        //
        // Backwards, for the line terminator. The dense-tail buffer is the
        // shape that actually runs: the newest terminator is the last byte of
        // the freshly read bytes.
        Row::new(
            "memrchr hit at end (terminator), 64 KiB buf",
            time_us(|| ih_memrchr(b'\n', &buf64d).unwrap_or(0)),
            time_us(|| rgx_core::memchr::memrchr(b'\n', &buf64d).unwrap_or(0)),
        ),
        // Terminator in the middle: the scan runs half the buffer first.
        Row::new(
            "memrchr hit mid-buffer, 64 KiB buf",
            time_us(|| ih_memrchr(b'\n', &buf64).unwrap_or(0)),
            time_us(|| rgx_core::memchr::memrchr(b'\n', &buf64).unwrap_or(0)),
        ),
        Row::new(
            "memrchr absent byte, 8 MiB file",
            time_us(|| ih_memrchr(0, &buf8m).unwrap_or(0)),
            time_us(|| rgx_core::memchr::memrchr(0, &buf8m).unwrap_or(0)),
        ),
        // ---- memchr_iter --------------------------------------------------
        //
        // Not named in the brief, but the paragraph-break walk in `main.rs` is
        // the only caller of the crate's iterator, so leaving it unmeasured
        // would mean deciding without the number that decides it. Newline-dense
        // text is the worst case for the in-house restart and the best case for
        // the crate's per-block candidate bitmap, which is why it is the largest
        // row in the table.
        Row::new(
            "memchr_iter newline-dense, 64 KiB buf",
            time_us(|| ih_memchr_iter(b'\n', &buf64).count()),
            time_us(|| rgx_core::memchr::memchr_iter(b'\n', &buf64).count()),
        ),
        Row::new(
            "memchr_iter newline-dense, 8 MiB file",
            time_us(|| ih_memchr_iter(b'\n', &buf8m).count()),
            time_us(|| rgx_core::memchr::memchr_iter(b'\n', &buf8m).count()),
        ),
    ];

    // ---- report -------------------------------------------------------

    println!(
        "{:<46} {:>10} {:>10} {:>8}  winner",
        "case", "in-house", "memchr", "ratio"
    );
    let mut in_house_wins = 0usize;
    let mut crate_wins = 0usize;
    let mut ties = 0usize;
    for r in &rows {
        match r.verdict() {
            "in-house" => in_house_wins += 1,
            "crate" => crate_wins += 1,
            _ => ties += 1,
        }
        println!(
            "{:<46} {:>7.3} us {:>7.3} us {:>7.2}x  {}",
            r.case,
            r.in_house,
            r.crate_,
            r.ratio(),
            r.verdict()
        );
    }

    println!();
    println!("in-house {in_house_wins} / crate {crate_wins} / tie {ties}");
    // The tally is misleading on its own: every row the in-house module
    // wins is one that returns within the first few bytes, where it wins by
    // nanoseconds, and every row it loses scans the whole buffer, where it
    // loses by microseconds. Both numbers are printed so the decision does
    // not rest on the count alone.
    let win_us: f64 = rows
        .iter()
        .filter(|r| r.ratio() <= 1.0)
        .map(|r| r.crate_ - r.in_house)
        .sum();
    let lose_us: f64 = rows
        .iter()
        .filter(|r| r.ratio() > 1.0)
        .map(|r| r.in_house - r.crate_)
        .sum();
    println!("total time the in-house side saves across all rows: {win_us:.3} us");
    println!("total time the in-house side loses across all rows:  {lose_us:.3} us");
}
