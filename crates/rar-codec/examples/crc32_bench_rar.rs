// SPDX-License-Identifier: Apache-2.0

//! Timing comparison for `crc32`: the slice-by-8 fold against the
//! byte-at-a-time definition it is checked against.
//!
//! ```sh
//! cargo run --release -p rar-codec --example crc32_bench_rar
//! ```
//!
//! Not a harness with a gate: the tree carries no `benches/` directory and
//! no `[[bench]]` section, and `benchmark/` holds the engine's own
//! measurement harnesses, none of them about this crate's CRC-32. This is here
//! to answer "did the fold pay for itself" on the machine that is being
//! worked on, over the payload sizes `Archive::extract` actually hashes.

use std::time::Instant;

/// The definition, unoptimised. Mirrors `crc32.rs`'s `crc32_slow`, which is
/// the oracle the unit tests hold the optimised fold against.
fn crc32_slow(data: &[u8]) -> u32 {
    const POLY: u32 = 0xEDB8_8320;
    fn byte_table() -> [u32; 256] {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { POLY ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    }
    let t = byte_table();
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = t[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// Deterministic filler: no RNG, same bytes every run, so the two arms see
/// identical input and the comparison is not measuring data layout.
fn fill(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    let mut x: u32 = 0x1234_5678;
    for _ in 0..n {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        v.push(x as u8);
    }
    v
}

fn time_ms<F: FnMut() -> u32>(rounds: usize, mut f: F) -> f64 {
    // One discarded warmup so the first round does not pay page faults.
    let mut sink = 0u32;
    sink ^= f();
    let t = Instant::now();
    for _ in 0..rounds {
        sink ^= f();
    }
    let ms = t.elapsed().as_secs_f64() * 1000.0;
    // Keep the accumulator live so nothing folds the calls away.
    std::hint::black_box(sink);
    ms / rounds as f64
}

fn main() {
    println!("crc32 throughput: slice-by-8 (shipped) vs byte-at-a-time (the oracle)");
    println!(
        "{:>10} {:>12} {:>12} {:>10} {:>14}",
        "bytes", "slow ms", "fast ms", "speedup", "MB/s fast"
    );
    for size in [4 * 1024, 64 * 1024, 1024 * 1024, 8 * 1024 * 1024] {
        let data = fill(size);
        let rounds = match size {
            s if s <= 64 * 1024 => 2000,
            s if s <= 1024 * 1024 => 200,
            _ => 30,
        };
        let slow = time_ms(rounds, || crc32_slow(&data));
        let fast = time_ms(rounds, || rar_codec::crc32(&data));
        let mbps = (size as f64 / (1024.0 * 1024.0)) / (fast / 1000.0);
        println!(
            "{:>10} {:>12.4} {:>12.4} {:>9.2}x {:>13.0}",
            size,
            slow,
            fast,
            slow / fast,
            mbps
        );
    }
}
