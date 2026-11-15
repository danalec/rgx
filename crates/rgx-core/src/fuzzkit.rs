// SPDX-License-Identifier: Apache-2.0

//! Deterministic, dependency-free structural fuzzer for byte-slice parsers.
//!
//! This is deliberately *not* libFuzzer: it runs inside ordinary `cargo test`
//! on stable, needs no clang/nightly, and reproduces exactly from its seed.
//! Each round mutates a real fixture (the most structured starting point a
//! parser will ever see) with one of several byte-level mutations. Parsers
//! whose happy path came from a valid fixture are maximally likely to hit
//! half-valid states — header parsed, body truncated — which is where
//! hand-rolled indexing panics live.
//!
//! Usage in an adapter crate:
//!
//! ```text
//! #[cfg(test)]
//! mod fuzz {
//!     use super::*;
//!     #[test]
//!     fn never_panics_on_arbitrary_bytes() {
//!         let corpus: Vec<(&str, Vec<u8>)> = vec![("valid", fixture_bytes())];
//!         rgx_core::fuzzkit::assert_never_panics(corpus, 2000, "myadapter", |data| {
//!             let _ = MyAdapter.extract(data, "fuzz.bin"); // Err/Bail fine, panic = fail
//!         });
//!     }
//! }
//! ```
//!
//! `text` and not `ignore`: `ignore` means "this compiles and we chose not to
//! run it", while `text` means "this is a shape to copy". `fixture_bytes()` and
//! `MyAdapter` are placeholders that exist in no crate.

use alloc::string::String;
use alloc::vec::Vec;
/// xorshift64* PRNG: deterministic, tiny, good enough for mutation choice.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    pub fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

/// One structural mutation of `base`. The distribution favors corrupting
/// length fields and truncating — the failure modes of length-prefixed
/// binary formats.
pub fn mutate(rng: &mut Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    match rng.below(8) {
        // truncate anywhere (length fields pointing past EOF)
        0 | 1 => v.truncate(rng.below(v.len() + 1)),
        // flip a few bytes (magic survives, body corrupt)
        2 | 3 => {
            for _ in 0..=rng.below(4) {
                if !v.is_empty() {
                    let i = rng.below(v.len());
                    v[i] ^= rng.byte() | 1;
                }
            }
        }
        // zero a region (sparse corruption, kills big-endian length words)
        4 => {
            if !v.is_empty() {
                let i = rng.below(v.len());
                let n = (1 + rng.below(v.len() - i)).min(v.len() - i);
                for b in &mut v[i..i + n] {
                    *b = 0;
                }
            }
        }
        // 0xFF a region (kills little-endian length words)
        5 => {
            if !v.is_empty() {
                let i = rng.below(v.len());
                let n = (1 + rng.below(v.len() - i)).min(v.len() - i);
                for b in &mut v[i..i + n] {
                    *b = 0xFF;
                }
            }
        }
        // junk prepend/append (embedded-structure offsets shift)
        6 => {
            let n = rng.below(64);
            let junk: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
            if rng.below(2) == 0 {
                v.splice(0..0, junk);
            } else {
                v.extend_from_slice(&junk);
            }
        }
        // pure random bytes of similar size (magic gone — adapters must bail)
        _ => v = (0..v.len()).map(|_| rng.byte()).collect(),
    }
    v
}

/// The wall-clock budget one round of the fuzzer gets.
///
/// The budget is wall-clock and not a count of steps, so it says as much
/// about the machine as about the parser: a loaded runner, a guest under
/// KVM on a shared host, a laptop with the fan spinning -- all of them
/// make the same round take longer. It is generous for that reason, and
/// a round that overruns it is a hang worth failing on: the parser is
/// either looping or allocating without end.
#[cfg(feature = "std")]
pub const ROUND_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// The code the process leaves with when a round hangs.
///
/// The same code a failed test leaves with, so a harness that watches the
/// exit code cannot tell a hang from an assertion.
#[cfg(feature = "std")]
pub const HANG_EXIT_CODE: i32 = 101;

/// Run `rounds` mutated inputs per corpus entry through `f`, failing the
/// test with the round, seed and (hex) repro input on any panic.
/// `Err`/`Outcome::Bail` from the parser are expected and ignored — the
/// contract under test is only "never panic, never hang".
///
/// Each round runs on its own thread with a watchdog: a parser that loops
/// forever on hostile input fails the test instead of freezing the suite.
/// The closure must be `Send + Sync + 'static` because the watcher and
/// worker threads both reference it.
///
/// A round that overruns the budget takes the process down with it: a
/// thread in Rust cannot be killed, and a watchdog that gave up while the
/// thread kept running reported a failure *and* left the machine to the
/// thread that was known to be stuck. The repro is printed before the
/// process goes, because a hang is the case where the repro matters most.
///
/// Available with `feature = "std"` (the default). `rgx-core` is
/// `no_std + alloc`; this parallel runner is the only `std`-gated piece
/// of the fuzzkit, and a `no_std` build drops it entirely (callers in
/// that build get a compile error pointing here).
#[cfg(feature = "std")]
pub fn assert_never_panics(
    corpus: Vec<(&'static str, Vec<u8>)>,
    rounds: usize,
    name: &str,
    f: impl Fn(&[u8]) + Send + Sync + 'static,
) {
    assert_never_panics_within(corpus, rounds, name, ROUND_BUDGET, f)
}

/// [`assert_never_panics`] with the budget the caller chooses.
///
/// The budget is a parameter so that a test can watch the timeout path
/// without waiting out the real one.
#[cfg(feature = "std")]
pub fn assert_never_panics_within(
    corpus: Vec<(&'static str, Vec<u8>)>,
    rounds: usize,
    name: &str,
    budget: std::time::Duration,
    f: impl Fn(&[u8]) + Send + Sync + 'static,
) {
    let mut rng = Rng::new(0x9E37_79B9_7F4A_7C15);
    let f = std::sync::Arc::new(f);
    for (seed_name, data) in &corpus {
        for round in 0..rounds {
            let input = mutate(&mut rng, data);
            let (tx, rx) = std::sync::mpsc::channel();
            let work = input.clone();
            let f = std::sync::Arc::clone(&f);
            let handle = std::thread::spawn(move || {
                f(&work);
                let _ = tx.send(());
            });
            match rx.recv_timeout(budget) {
                Ok(()) => {
                    // propagate a parser panic with the repro input
                    if handle.join().is_err() {
                        panic!(
                            "{name}: panicked on round {round} (seed '{seed_name}')\n\
                             repro hex: {}\n",
                            repro_hex(&input)
                        );
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    // the worker panicked before sending; join to reap it
                    let _ = handle.join();
                    panic!(
                        "{name}: panicked on round {round} (seed '{seed_name}')\n\
                         repro hex: {}\n",
                        repro_hex(&input)
                    );
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // The worker is stuck and Rust cannot kill it. The only
                    // way to keep the invariant that no thread outlives
                    // the test is to take the process down with it -- and
                    // the repro is printed first, because a hang is where
                    // the repro matters most.
                    std::eprintln!(
                        "{name}: hung on round {round} (seed '{seed_name}')\n\
                         repro hex: {}\n",
                        repro_hex(&input)
                    );
                    std::process::exit(HANG_EXIT_CODE);
                }
            }
        }
    }
}

/// `assert_never_panics` is `std`-only because it spawns worker threads
/// with a watchdog. The data structures (`Rng`, `mutate`, `repro_hex`)
/// are `no_std + alloc`.
///
/// Compact hex dump for failure messages (first 256 bytes, enough to
/// reconstruct the input when pasted back through a hex decoder).
pub fn repro_hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len().min(256) * 2 + 32);
    use core::fmt::Write as _;
    for (i, b) in data.iter().take(256).enumerate() {
        if i > 0 && i % 32 == 0 {
            s.push('\n');
        }
        let _ = write!(s, "{b:02x}");
    }
    if data.len() > 256 {
        let _ = write!(s, "… ({} bytes total)", data.len());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutations_are_deterministic() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut r = Rng::new(7);
        let m1 = mutate(&mut r, b"hello world");
        let mut r = Rng::new(7);
        let m2 = mutate(&mut r, b"hello world");
        assert_eq!(m1, m2);
    }

    #[test]
    fn empty_input_is_safe() {
        let mut r = Rng::new(1);
        for _ in 0..64 {
            let _ = mutate(&mut r, b"");
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn parallel_runner_completes() {
        // The parallel runner spawns one worker thread per round, each
        // with its own timeout. This test exercises the spawn / join /
        // watchdog path with a no-op closure, so any deadlock or
        // thread-pool exhaustion would surface as a hang (caught by
        // the test runner) or a panic. The seeded mutation sequence
        // is checked by `mutations_are_deterministic` above; here we
        // only verify the harness itself runs end-to-end.
        assert_never_panics(vec![("seed", b"abc".to_vec())], 4, "t", |_data| {});
    }

    /// A round that hangs takes the process down with it: a thread in Rust
    /// cannot be killed, and a watchdog that gave up while the thread kept
    /// running reported a failure *and* left the machine to the thread
    /// that was known to be stuck.
    ///
    /// The child below hangs on purpose, and its worker counts what it
    /// does, so the parent can tell the two shapes apart: a runner that
    /// took the process down, and a runner that came back with the worker
    /// still in there.
    #[cfg(feature = "std")]
    #[test]
    fn a_hung_round_leaves_no_thread_running() {
        /// The code the child leaves with when the worker was still running
        /// after the runner came back: the shape this test forbids.
        const STILL_RUNNING: i32 = 43;
        const CHILD: &str = "RGX_FUZZKIT_HANG_CHILD";

        if std::env::var_os(CHILD).is_some() {
            // The child: a closure that never returns, and a counter that
            // says what it does while it is in there.
            let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let counted = std::sync::Arc::clone(&counter);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_never_panics_within(
                    vec![("hang", alloc::vec![1, 2, 3])],
                    1,
                    "hang",
                    std::time::Duration::from_millis(200),
                    move |_data| loop {
                        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    },
                );
            }));
            // The runner came back, which is the shape this test forbids:
            // the worker is still in there and still counting.
            let before = counter.load(std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(300));
            let after = counter.load(std::sync::atomic::Ordering::SeqCst);
            std::eprintln!("the worker went from {before} to {after}");
            std::process::exit(if after > before { STILL_RUNNING } else { 0 });
        }

        let exe = std::env::current_exe().expect("the test binary");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg("fuzzkit::tests::a_hung_round_leaves_no_thread_running")
            // Without this the harness would capture what the child
            // prints and take it with it when the process goes.
            .arg("--nocapture")
            .env(CHILD, "1")
            .output()
            .expect("the child runs");
        let err = String::from_utf8_lossy(&out.stderr);
        // The child is gone: the round that hung took the process down
        // with it, and nothing is still running behind it.
        assert!(!out.status.success(), "the child did not fail");
        assert_ne!(
            out.status.code(),
            Some(STILL_RUNNING),
            "the worker was still running after the timeout:\n{err}"
        );
        // The repro is what a hang is for: the round and the bytes that
        // hung it have to be in what the child left behind.
        assert!(
            err.contains("hung on round 0"),
            "the child did not say which round hung:\n{err}"
        );
        assert!(
            err.contains("repro hex:"),
            "the child did not print the repro:\n{err}"
        );
    }
}
