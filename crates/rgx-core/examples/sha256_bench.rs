// SPDX-License-Identifier: Apache-2.0

//! SHA-256 kernel throughput: Intel SHA-NI vs the scalar block function.
//!
//! Run with:
//! ```text
//! cargo run --release -p rgx-core --features sha256-hw --example sha256_bench
//! ```
//!
//! What this measures, precisely: how fast `Sha256::hash` runs when the
//! `sha256-hw` feature has selected the SHA-NI kernel, against the same
//! compression written out longhand in `src/sha256_ref.rs`. That is a
//! kernel-level number and nothing more.
//!
//! It is NOT a number about rgx. SHA-256 has two call sites in this
//! codebase: the ~256-byte extraction-cache key in `src/cache.rs`, which
//! only runs under `--cache` (off by default, because a wrong default
//! serves stale bytes), and the `CHECK_SHA256` stream check in
//! `compress/xz/container.rs`, which most xz files do not carry. The
//! pack store uses CRC32 throughout. This file therefore has no row
//! labelled "searcher buffer" and none labelled "pack store": neither is a
//! workload rgx performs -- the searcher never hashes, and a pack store
//! never hashes -- so such a row would describe a speedup rgx does not
//! collect. There is no rgx-shaped row to put in its place.
//!
//! The ratio is refused, not printed, when the hardware path did not run.
//! On a CPU without SHA-NI, or on aarch64 where there is no backend,
//! `Sha256::hash` falls back to scalar and the "speedup" column would
//! read 1.00x -- a number that looks like a measurement and is really an
//! absence of one.

#[path = "../src/sha256_ref.rs"]
mod sha256_ref;

use std::time::Instant;

/// Best-of-N per size. One sample per cell cannot support a verdict: the
/// project rule is that a winner is named only when every sample of one
/// engine is below every sample of the other, and a single sample has no
/// distribution to compare.
const SAMPLES: usize = 7;

/// Best (lowest elapsed) of SAMPLES runs, so a scheduler hiccup cannot
/// read as a slow backend.
fn best_of<F: FnMut() -> [u8; 32]>(mut f: F) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..SAMPLES {
        let t0 = Instant::now();
        std::hint::black_box(f());
        best = best.min(t0.elapsed().as_secs_f64());
    }
    best
}

fn mb_per_s(bytes: usize, seconds: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / seconds
}

fn main() {
    #[cfg(feature = "sha256-hw")]
    let hw = rgx_core::sha256_hw::hardware_available();
    #[cfg(not(feature = "sha256-hw"))]
    let hw = false;

    println!("sha256-hw feature : {}", cfg!(feature = "sha256-hw"));
    println!(
        "backend selected  : {}",
        if hw { "Intel SHA-NI" } else { "scalar" }
    );
    println!("samples per cell  : {SAMPLES} (best-of, so a scheduler stall cannot read as a loss)");

    if !hw {
        println!();
        println!("No hardware backend was selected, so both columns below would be the same");
        println!("scalar code and any ratio printed would be meaningless. This machine");
        println!("reports no `sha` extension, or is aarch64 where no backend exists yet --");
        println!("see `detect()` in sha256_hw.rs. The feature is in `default`, so there");
        println!("is nothing to rebuild with.");
        return;
    }

    // Sizes, not workloads: these are just block counts. 1 MiB is the
    // largest input the one real multi-block caller could hand this.
    let sizes: &[usize] = &[64 * 1024, 1024 * 1024, 16 * 1024 * 1024];

    println!();
    println!(
        "{:>12} {:>14} {:>14} {:>10}",
        "bytes", "scalar MB/s", "SHA-NI MB/s", "speedup"
    );
    println!("{:-<12} {:-<14} {:-<14} {:-<10}", "", "", "", "");

    for size in sizes {
        let mut data = vec![0u8; *size];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i.wrapping_mul(37) ^ 0x5a) as u8;
        }

        // Warm up both paths so neither pays for a cold cache.
        let _ = sha256_ref::reference_hash(&data);
        let _ = rgx_core::sha256::Sha256::hash(&data);

        let scalar_s = best_of(|| sha256_ref::reference_hash(&data));
        let hw_s = best_of(|| rgx_core::sha256::Sha256::hash(&data));

        let scalar = mb_per_s(*size, scalar_s);
        let accel = mb_per_s(*size, hw_s);

        println!(
            "{:>12} {:>14.1} {:>14.1} {:>9.2}x",
            size,
            scalar,
            accel,
            accel / scalar
        );
    }

    println!();
    println!("None of these sizes corresponds to work rgx does per unit of user-visible");
    println!("time. See the module header for the two call sites that exist.");
}
