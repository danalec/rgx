// SPDX-License-Identifier: Apache-2.0

//! Timing comparison for the 7z CRC-32: the slice-by-8 fold against the
//! byte-at-a-time definition it is checked against.
//!
//! ```sh
//! cargo run --release -p rgx-adapters-archive --example crc32_bench_7z
//! ```
//!
//! Not a harness with a gate -- this crate's gated benches live in
//! `benchmark/`. This is here to answer "did the fold pay for itself" on
//! the machine that is being worked on, over the payload sizes the 7z
//! reader actually hashes.
//!
//! The size that matters is the one the fixture declares:
//! `sevenz_multifolder.7z` is 24 KB on disk and expands to 107 MB, so
//! the per-member CRC runs over 107 MB. That is the row the fold has to
//! move; the 4 KB row is here to show the small-buffer case did not
//! regress.

use std::time::Instant;

use rgx_adapters_archive::sevenz::crc32::crc32;

/// The definition, unoptimised. Mirrors `crc32.rs`'s `crc32_slow`, which is
/// the oracle the unit tests hold the optimised fold against.
const POLY: u32 = 0xEDB8_8320;

const fn byte_table() -> [u32; 256] {
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

static T: [u32; 256] = byte_table();

fn crc32_slow(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = T[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

fn bench(data: &[u8], label: &str) {
    // Warm the code and the data, then take the best of three: the floor
    // of this machine is not what is being measured.
    let _ = crc32(data);
    let _ = crc32_slow(data);

    let mut fast = f64::MAX;
    let mut slow = f64::MAX;
    for _ in 0..3 {
        let t = Instant::now();
        let a = crc32(data);
        fast = fast.min(t.elapsed().as_secs_f64());
        assert_eq!(a, crc32_slow(data), "{label}: the two folds disagree");

        let t = Instant::now();
        let b = crc32_slow(data);
        slow = slow.min(t.elapsed().as_secs_f64());
        assert_eq!(a, b, "{label}: the two folds disagree");
    }
    let mbps = data.len() as f64 / 1e6 / fast;
    println!(
        "{label:>10}: slice-by-8 {:>8.2} ms ({:>7.0} MB/s)   \
         byte-at-a-time {:>8.2} ms   speedup {:>5.2}x",
        fast * 1e3,
        mbps,
        slow * 1e3,
        slow / fast
    );
}

fn main() {
    // The payload the 7z reader actually hashes on the fixture that
    // exposed the problem: 107,415,075 bytes across two folders.
    let big: Vec<u8> = (0..107_415_075u32).map(|i| (i % 251) as u8).collect();
    bench(&big, "107 MB");
    let small: Vec<u8> = big[..4096].to_vec();
    bench(&small, "4 KB");
}
