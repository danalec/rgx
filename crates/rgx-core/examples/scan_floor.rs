// SPDX-License-Identifier: Apache-2.0

//! One-off diagnostic: is `pair_offsets` the bottleneck, or the memory system?
//!
//! Times three things over the same 246 MB buffer:
//!   1. a raw byte walk (the memory floor),
//!   2. `scan::pair_offsets` for an absent 3-byte needle (the kernel),
//!   3. `scan::byte_bits` for an absent 1-byte set (a different kernel).
//!
//! If (2) tracks (1) the kernel is at the memory limit and the pipeline
//! is where the time goes. If (2) is well below (1) the kernel has room.
//!
//! Run: cargo run --release -p rgx-core --example scan_floor -- <file>

use std::time::Instant;

fn main() {
    // The corpus is the operator's: a path written into this file would be
    // one machine's, so it is named by the environment and by the argument.
    let path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("RGX_BENCH_CORPUS").ok())
        .unwrap_or_else(|| ".rgx-bench/big235.rs".to_string());
    let hay = std::fs::read(&path).expect("read corpus");
    let n = hay.len();
    println!("corpus {path}  {n} bytes");

    // Warm the pages in, so the timed runs are not measuring the fault-in.
    let mut warm = 0u64;
    for b in hay.iter().step_by(64) {
        warm = warm.wrapping_add(*b as u64);
    }
    println!("warm: {warm}");

    let rounds = 7;

    // 1. memory floor: sum every byte
    let mut lo = f64::MAX;
    for _ in 0..rounds {
        let t = Instant::now();
        let mut acc = 0u64;
        for b in &hay {
            acc = acc.wrapping_add(*b as u64);
        }
        std::hint::black_box(acc);
        lo = lo.min(t.elapsed().as_secs_f64());
    }
    report("byte walk (memory floor)", n, lo);

    // 2. pair_offsets, absent 3-byte needle
    let mut lo = f64::MAX;
    for _ in 0..rounds {
        let t = Instant::now();
        let mut out = Vec::new();
        rgx_core::scan::pair_offsets(b"zzz", &hay, &mut out);
        std::hint::black_box(out.len());
        lo = lo.min(t.elapsed().as_secs_f64());
    }
    report("pair_offsets zzz", n, lo);

    // 3. pair_offsets, absent 7-byte needle (what `let mut` takes)
    let mut lo = f64::MAX;
    for _ in 0..rounds {
        let t = Instant::now();
        let mut out = Vec::new();
        rgx_core::scan::pair_offsets(b"zzzzzzz", &hay, &mut out);
        std::hint::black_box(out.len());
        lo = lo.min(t.elapsed().as_secs_f64());
    }
    report("pair_offsets zzzzzzz", n, lo);

    // 4. byte_bits, absent 1-byte set -- a different SIMD kernel
    let mut lo = f64::MAX;
    for _ in 0..rounds {
        let t = Instant::now();
        let mut bits = rgx_core::scan::BitMap::new();
        rgx_core::scan::byte_bits(&[b'q', 0, 0], 1, &hay, &mut bits);
        std::hint::black_box(bits.count_set(0, n));
        lo = lo.min(t.elapsed().as_secs_f64());
    }
    report("byte_bits q", n, lo);

    // 5. pair_bits, absent 3-byte needle -- what the searcher's map path
    //    actually calls for a `Sub` literal
    let mut lo = f64::MAX;
    for _ in 0..rounds {
        let t = Instant::now();
        let mut bits = rgx_core::scan::BitMap::new();
        rgx_core::scan::pair_bits(b"zzz", &hay, &mut bits);
        std::hint::black_box(bits.count_set(0, n));
        lo = lo.min(t.elapsed().as_secs_f64());
    }
    report("pair_bits zzz", n, lo);

    let mut lo = f64::MAX;
    for _ in 0..rounds {
        let t = Instant::now();
        let mut bits = rgx_core::scan::BitMap::new();
        rgx_core::scan::pair_bits(b"zzzzzzz", &hay, &mut bits);
        std::hint::black_box(bits.count_set(0, n));
        lo = lo.min(t.elapsed().as_secs_f64());
    }
    report("pair_bits zzzzzzz", n, lo);

    // 6. term_bits -- the terminator map the line walk reads
    let mut lo = f64::MAX;
    for _ in 0..rounds {
        let t = Instant::now();
        let mut bits = rgx_core::scan::BitMap::new();
        rgx_core::scan::term_bits(b'\n', &hay, &mut bits);
        std::hint::black_box(bits.count_set(0, n));
        lo = lo.min(t.elapsed().as_secs_f64());
    }
    report("term_bits \\n (one call)", n, lo);

    // 7. the same, but at the searcher's real granularity: one call per
    //    64 KiB fill, reusing one map, exactly as `searcher.rs` does. The
    //    per-call `clear` is 8 KiB here against 31 MB above, so this
    //    separates "the kernel is slow" from "the map is big".
    for (label, run) in [("pair_bits zzz /64K", 0u8), ("term_bits \\n /64K", 1u8)] {
        let mut lo = f64::MAX;
        for _ in 0..rounds {
            let t = Instant::now();
            let mut bits = rgx_core::scan::BitMap::new();
            for chunk in hay.chunks(64 * 1024) {
                if run == 0 {
                    rgx_core::scan::pair_bits(b"zzz", chunk, &mut bits);
                } else {
                    rgx_core::scan::term_bits(b'\n', chunk, &mut bits);
                }
                std::hint::black_box(bits.count_set(0, chunk.len()));
            }
            lo = lo.min(t.elapsed().as_secs_f64());
        }
        report(label, n, lo);
    }

    // 8. both maps per fill, the searcher's actual shape (two passes)
    let mut lo = f64::MAX;
    for _ in 0..rounds {
        let t = Instant::now();
        let mut terms = rgx_core::scan::BitMap::new();
        let mut cands = rgx_core::scan::BitMap::new();
        for chunk in hay.chunks(64 * 1024) {
            rgx_core::scan::term_bits(b'\n', chunk, &mut terms);
            rgx_core::scan::pair_bits(b"zzz", chunk, &mut cands);
            std::hint::black_box(terms.count_set(0, chunk.len()) + cands.count_set(0, chunk.len()));
        }
        lo = lo.min(t.elapsed().as_secs_f64());
    }
    report("both maps /64K", n, lo);

    // 9. fused pair + term scan, one pass per fill
    let mut lo = f64::MAX;
    for _ in 0..rounds {
        let t = Instant::now();
        let mut terms = rgx_core::scan::BitMap::new();
        let mut cands = rgx_core::scan::BitMap::new();
        for chunk in hay.chunks(64 * 1024) {
            rgx_core::scan::pair_term_bits(b"zzz", b'\n', chunk, &mut cands, &mut terms);
            std::hint::black_box(terms.count_set(0, chunk.len()) + cands.count_set(0, chunk.len()));
        }
        lo = lo.min(t.elapsed().as_secs_f64());
    }
    report("fused pair+term /64K", n, lo);
}

fn report(label: &str, n: usize, secs: f64) {
    let gbs = (n as f64 / 1e9) / secs;
    let ms = secs * 1000.0;
    println!("{label:<28} {ms:7.1} ms  {gbs:6.2} GB/s");
}
