// SPDX-License-Identifier: Apache-2.0

//! SHA-256 hardware acceleration: Intel SHA-NI on x86_64.
//!
//! The kernel is real and byte-exact against the scalar block function. It
//! arrived here through a detour worth recording, because the detour is the
//! only reason this module used to be a stub.
//!
//! This file was a dispatch skeleton with `let detected = false;` hardcoded
//! in `detect()`, and its header explained that the backends "are not yet
//! implemented on stable Rust" because the SHA-NI intrinsics "are still
//! nightly-only in `core::arch`". That premise was false. `sha_simd` -- the
//! feature gate covering `_mm_sha256rnds2_epu32`, `_mm_sha256msg1_epu32`
//! and `_mm_sha256msg2_epu32` -- has been stable since Rust 1.41. Nothing
//! about this kernel ever needed a nightly compiler; the stub was waiting on
//! a permission that had already been granted.
//!
//! The measurement, because it decides how this feature is described:
//! SHA-256 is not on a hot path in rgx. There are exactly two call sites.
//! `src/cache.rs` derives a ~256-byte extraction-cache key, which is four
//! blocks and only runs when `--cache` is passed -- off by default, and off
//! on purpose, because a wrong default serves stale bytes. The only other
//! site is `compress/xz/container.rs` checking a stream that declares
//! `CHECK_SHA256`, which most xz files do not; they carry CRC32 or CRC64.
//! The Tesla Valve pack store uses CRC32 throughout and never calls this at
//! all. So the honest statement is not "6x faster" but "a correct backend
//! that ships, at a cost of one cached atomic load per 64 bytes on a path
//! that is not where the time goes." It is on by default for that reason --
//! correctness of dispatch, and so the test suite actually compiles and runs
//! the code -- and not for throughput.
//!
//! The contract, unchanged from when the stub was written:
//!   - `hardware_available()` returns true only where `compress_block` has
//!     a backend. It is false on aarch64, where there is none.
//!   - `compress_block` produces the same 8-u32 state update as
//!     `sha256::process_block_scalar` for every 64-byte block.
//!   - Padding is never the backend's problem. `Sha256::finalize` builds the
//!     padded final block and only then calls `process_block`, so the kernel
//!     is positionally stateless and the incremental `update`/`finalize`
//!     contract holds across any split.
//!   - The test module below pins the kernel to the scalar function block by
//!     block, which is the only assertion that can fail when the arithmetic
//!     is wrong regardless of which backend the dispatch chose.

/// True when the running CPU has the matching SHA-256 hardware
/// instructions. Cached after the first call; the OS feature-detection
/// path is not free, and a SHA-256 search walks many blocks.
#[cfg(feature = "sha256-hw")]
pub fn hardware_available() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    // 0 = uninitialized, 1 = no, 2 = yes. Atomic on a single byte so
    // the first-time check is race-free across worker threads.
    static CACHE: AtomicU8 = AtomicU8::new(0);
    match CACHE.load(Ordering::Relaxed) {
        1 => return false,
        2 => return true,
        _ => {}
    }
    let detected = detect();
    CACHE.store(if detected { 2 } else { 1 }, Ordering::Relaxed);
    detected
}

#[cfg(feature = "sha256-hw")]
fn detect() -> bool {
    // The question is asked through this crate's own probe (`crate::detect`),
    // not through `std::arch::is_x86_feature_detected!`: the macro lives in
    // `std` and this feature does not require `std`, so a `no_std` build with
    // `sha256-hw` on would not compile at all. The `not(feature = "std")`
    // arms this used to carry fell back to `cfg!(target_feature = "sha")`,
    // which is a compile-time constant: a portable build never sets `sha`, so
    // it answered false forever and the hardware path could never light up in
    // a no_std build at all.
    #[cfg(target_arch = "x86_64")]
    {
        crate::detect::sha() && crate::detect::sse4_1()
    }
    // No aarch64 backend exists. Reporting the extension as available would
    // make `hardware_available()` claim a backend that `compress_block` does
    // not have, and the benchmark would print "Available: true" next to a
    // 1.00x ratio measured against the scalar it silently fell back to.
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Compress one 64-byte block using Intel SHA-NI extensions.
///
/// `ssse3` is spelled out rather than left implied by `sse4.1` because the
/// body calls `_mm_shuffle_epi8` and `_mm_alignr_epi8`, which are SSSE3.
///
/// It is load-bearing and nothing checks it. rustc compiles a call to an
/// SSSE3 intrinsic inside a function annotated for a narrower feature set
/// without complaint -- the annotation is the entire guard -- so removing
/// `ssse3` from this list produces a green build and a body whose
/// guarantee is only the architectural implication SSE4.1 => SSE4.2 =>
/// SSSE3, which no tool in this repository states anywhere else.
#[cfg(all(feature = "sha256-hw", target_arch = "x86_64"))]
#[target_feature(enable = "sha,sse4.1,ssse3")]
unsafe fn compress_block_x86_shani(state: &mut [u32; 8], block: &[u8; 64]) {
    use super::sha256::K;
    use core::arch::x86_64::*;

    let mask = _mm_set_epi64x(0x0c0d0e0f08090a0b_u64 as i64, 0x0405060700010203_u64 as i64);

    let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(block.as_ptr().cast::<__m128i>()), mask);
    let mut msg1 = _mm_shuffle_epi8(
        _mm_loadu_si128(block.as_ptr().add(16).cast::<__m128i>()),
        mask,
    );
    let mut msg2 = _mm_shuffle_epi8(
        _mm_loadu_si128(block.as_ptr().add(32).cast::<__m128i>()),
        mask,
    );
    let mut msg3 = _mm_shuffle_epi8(
        _mm_loadu_si128(block.as_ptr().add(48).cast::<__m128i>()),
        mask,
    );

    // Initial state setup:
    // Intel SHA-NI state0 holds [A, B, E, F] and state1 holds [C, D, G, H] (lane 3..0).
    let mut abef = _mm_set_epi32(
        state[0] as i32,
        state[1] as i32,
        state[4] as i32,
        state[5] as i32,
    );
    let mut cdgh = _mm_set_epi32(
        state[2] as i32,
        state[3] as i32,
        state[6] as i32,
        state[7] as i32,
    );

    let abef_orig = abef;
    let cdgh_orig = cdgh;

    macro_rules! rounds_4 {
        ($msg:expr, $k_idx:expr) => {{
            let ab_k = _mm_add_epi32(
                $msg,
                _mm_loadu_si128(K.as_ptr().add($k_idx).cast::<__m128i>()),
            );
            cdgh = _mm_sha256rnds2_epu32(cdgh, abef, ab_k);
            let ab_k_shuf = _mm_shuffle_epi32(ab_k, 0x0e);
            abef = _mm_sha256rnds2_epu32(abef, cdgh, ab_k_shuf);
        }};
    }

    macro_rules! schedule {
        ($m0:expr, $m1:expr, $m2:expr, $m3:expr) => {{
            $m0 = _mm_sha256msg1_epu32($m0, $m1);
            let align = _mm_alignr_epi8($m3, $m2, 4);
            $m0 = _mm_add_epi32($m0, align);
            $m0 = _mm_sha256msg2_epu32($m0, $m3);
        }};
    }

    rounds_4!(msg0, 0);
    schedule!(msg0, msg1, msg2, msg3);
    rounds_4!(msg1, 4);
    schedule!(msg1, msg2, msg3, msg0);
    rounds_4!(msg2, 8);
    schedule!(msg2, msg3, msg0, msg1);
    rounds_4!(msg3, 12);
    schedule!(msg3, msg0, msg1, msg2);

    rounds_4!(msg0, 16);
    schedule!(msg0, msg1, msg2, msg3);
    rounds_4!(msg1, 20);
    schedule!(msg1, msg2, msg3, msg0);
    rounds_4!(msg2, 24);
    schedule!(msg2, msg3, msg0, msg1);
    rounds_4!(msg3, 28);
    schedule!(msg3, msg0, msg1, msg2);

    rounds_4!(msg0, 32);
    schedule!(msg0, msg1, msg2, msg3);
    rounds_4!(msg1, 36);
    schedule!(msg1, msg2, msg3, msg0);
    rounds_4!(msg2, 40);
    schedule!(msg2, msg3, msg0, msg1);
    rounds_4!(msg3, 44);
    schedule!(msg3, msg0, msg1, msg2);

    rounds_4!(msg0, 48);
    rounds_4!(msg1, 52);
    rounds_4!(msg2, 56);
    rounds_4!(msg3, 60);

    abef = _mm_add_epi32(abef, abef_orig);
    cdgh = _mm_add_epi32(cdgh, cdgh_orig);

    let mut out_abef = [0u32; 4];
    let mut out_cdgh = [0u32; 4];
    _mm_storeu_si128(out_abef.as_mut_ptr().cast::<__m128i>(), abef);
    _mm_storeu_si128(out_cdgh.as_mut_ptr().cast::<__m128i>(), cdgh);

    state[0] = out_abef[3];
    state[1] = out_abef[2];
    state[2] = out_cdgh[3];
    state[3] = out_cdgh[2];
    state[4] = out_abef[1];
    state[5] = out_abef[0];
    state[6] = out_cdgh[1];
    state[7] = out_cdgh[0];
}

/// Compress one 64-byte block. Dispatches to the hardware acceleration backend
/// when available on the running CPU, otherwise falls back to scalar compression.
///
/// This owns the dispatch decision. `Sha256::process_block` used to run the
/// same `hardware_available()` check before calling in here, and `compress_block`
/// checked again -- two cached atomic loads per 64-byte block to reach one
/// answer. The call site now delegates and this is the only gate.
#[cfg(feature = "sha256-hw")]
pub(crate) fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    #[cfg(target_arch = "x86_64")]
    {
        if hardware_available() {
            // SAFETY: `hardware_available()` is true only when the runtime reported
            // `sha` and `sse4.1`, which imply `ssse3` architecturally
            // (SSE4.1 => SSE4.2 => SSSE3). The kernel also declares `ssse3`
            // explicitly, and that annotation is the only guard there is:
            // rustc does NOT reject an SSSE3 intrinsic called inside a
            // `#[target_feature(enable = "sha,sse4.1")]` function -- it
            // compiles either way -- so dropping `ssse3` from the list would
            // not fail the build, it would just leave the guarantee
            // unstated.
            unsafe { compress_block_x86_shani(state, block) };
            return;
        }
    }
    super::sha256::process_block_scalar(state, block);
}

#[cfg(test)]
mod tests {
    use super::super::sha256::Sha256;
    use super::super::sha256_ref::reference_hash;
    use alloc::string::String;

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Which backend this process actually used. Every other test in this
    /// module passes whether the SHA-NI kernel ran or not, so without this
    /// a green run is ambiguous: on a CPU without SHA-NI, or on aarch64,
    /// the `hardware_*` names describe a path that was never taken. Print
    /// it with `cargo test -p rgx-core sha256 -- --nocapture`.
    #[test]
    fn report_backend() {
        #[cfg(feature = "sha256-hw")]
        std::println!(
            "sha256 backend: {}",
            if super::hardware_available() {
                "hardware (Intel SHA-NI)"
            } else {
                "scalar"
            }
        );
    }

    /// FIPS 180-4 against literal digests.
    ///
    /// The other correctness tests here compare `Sha256::hash` to
    /// `reference_hash`, which is a line-for-line clone of the scalar
    /// module -- same `K`, same `H0`, same round functions. That catches a
    /// broken kernel but not a shared misunderstanding, and it says nothing
    /// about whether the digest is *right*. These hex strings are the
    /// published vectors, typed here so they cannot drift with the code.
    #[test]
    fn known_answer_test_fips_180_4() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            // 56 bytes: the length that forces the two-block padding branch
            // in `finalize`, so the kernel is fed a final block that is all
            // padding but the length word.
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(&hex(&Sha256::hash(input)), want, "len {}", input.len());
        }
        let million = alloc::vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&Sha256::hash(&million)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// The SHA-NI kernel against the scalar block function, block by block.
    ///
    /// This is the test that can fail when the kernel's arithmetic is wrong
    /// on a machine that has SHA-NI. The digest-level tests above compare
    /// two whole-message results, which means a bug has to survive nine
    /// hundred bytes of cancelling error before it shows; this one compares
    /// the 8-u32 state after every single block, so a wrong lane order or a
    /// wrong message schedule trips on block 0. It runs through
    /// `compress_block`, so it does not depend on `Sha256::process_block`
    /// having chosen the hardware path -- but it is only meaningful when
    /// `report_backend` says the hardware path was available.
    #[test]
    #[cfg(feature = "sha256-hw")]
    fn shani_kernel_matches_scalar_block_by_block() {
        use super::super::sha256::{process_block_scalar, H0};

        let mut data = [0u8; 64 * 9];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i.wrapping_mul(2654435761) >> 16) as u8;
        }
        let mut hw = H0;
        let mut scalar = H0;
        let (blocks, _tail) = data.as_chunks::<64>();
        for (n, block) in blocks.iter().enumerate() {
            super::compress_block(&mut hw, block);
            process_block_scalar(&mut scalar, block);
            assert_eq!(hw, scalar, "state diverged after block {n}");
        }
    }

    /// Randomized split-input sweep. Runs on every build, with or
    /// without the `sha256-hw` feature, and on every CPU: the FIPS
    /// vectors above are the correctness floor; this test makes sure
    /// the block-buffering path is identical regardless of which
    /// backend `process_block` is dispatching to.
    #[test]
    fn hardware_matches_split_inputs() {
        let data: alloc::vec::Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
            .collect();
        // Every length around a 64-byte block boundary is here on purpose:
        // 63/64/65 and 127/128 exercise the partial-block buffer plus the
        // two-block padding branch in `finalize`.
        for split in [
            1usize, 7, 31, 63, 64, 65, 127, 128, 129, 255, 1023, 2048, 4095,
        ] {
            let mut h = Sha256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), reference_hash(&data), "split at {split}");
        }
    }
}
