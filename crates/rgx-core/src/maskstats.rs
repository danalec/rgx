// SPDX-License-Identifier: Apache-2.0

//! Counters for the packed-mask first stage and its confirm.
//!
//! `docs/research/BEYOND-SOTA.md` §8 puts this first for a reason: frequency-aware bucket
//! assignment, the confirm hash, and the reinforcement mask are all argued
//! from quantities -- the candidate rate `r`, the expected confirm chain
//! length, what fraction of the time goes to verification -- and none of them
//! have ever been measured on rgx's own corpus. There is no published
//! analysis of verification time fraction anywhere in the Hyperscan
//! documentation either, so the model behind those arguments is the only
//! thing anyone has to go on.
//!
//! So this measures. Two numbers matter most:
//!
//! - **blocks** and **candidates**: the first stage's yield. A block that
//!   produces no candidate costs almost nothing; a block that produces one
//!   costs a confirm. Their ratio is the quantity the reinforcement mask
//!   (§1.4 of `docs/research/FASTER-THAN-RIPGREP.md`) claims to improve, and the quantity a
//!   frequency-aware objective would be optimising against.
//!
//! - **confirms** and **hits**: what the candidates cost. Confirms are
//!   counted per candidate-bucket pair, which is the same unit Hyperscan's
//!   `verify_bucket` uses; a low hit rate means the first stage is admitting
//!   candidates it should have rejected, and that is the gap the oversized
//!   confirm table (§1.3) closes.
//!
//! Everything is off by default and costs one relaxed load per call site: the
//! counters inside a scan are accumulated in locals and flushed once at the
//! end, so the inner loop never touches an atomic.
//!
//! [`Stats::summary`] is what a run should print; the raw fields are there so
//! a caller can derive whatever it wants instead.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

static ENABLED: AtomicBool = AtomicBool::new(false);

static SCANS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static BLOCKS: AtomicU64 = AtomicU64::new(0);
static CANDIDATES: AtomicU64 = AtomicU64::new(0);
static CONFIRMS: AtomicU64 = AtomicU64::new(0);
static HITS: AtomicU64 = AtomicU64::new(0);

/// One scan's contribution, tallied in locals and flushed together.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanDelta {
    /// Bytes handed to the first stage.
    pub bytes: u64,
    /// Vector blocks the first stage walked.
    pub blocks: u64,
    /// Offsets the first stage admitted as candidates.
    pub candidates: u64,
    /// Confirm invocations those candidates caused.
    pub confirms: u64,
    /// Confirms that succeeded.
    pub hits: u64,
}

impl ScanDelta {
    /// Add another delta in, so a caller can fold several scans into one.
    pub fn merge(&mut self, other: &ScanDelta) {
        self.bytes += other.bytes;
        self.blocks += other.blocks;
        self.candidates += other.candidates;
        self.confirms += other.confirms;
        self.hits += other.hits;
    }
}

/// What one buffer's scan cost, as counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub scans: u64,
    pub bytes: u64,
    pub blocks: u64,
    pub candidates: u64,
    pub confirms: u64,
    pub hits: u64,
}

impl Stats {
    /// Candidates admitted per vector block. The first stage's yield, and the
    /// number the reinforcement mask is supposed to push down.
    pub fn candidates_per_block(&self) -> f64 {
        if self.blocks == 0 {
            0.0
        } else {
            self.candidates as f64 / self.blocks as f64
        }
    }

    /// How often a block admitted anything at all, in `[0, 1]`.
    ///
    /// Approximate when several candidates land in one block; the scan knows
    /// the exact count and the count of non-empty blocks separately.
    pub fn productive_block_fraction(&self) -> f64 {
        if self.blocks == 0 {
            0.0
        } else {
            (self.candidates.min(self.blocks) as f64) / self.blocks as f64
        }
    }

    /// Confirms per candidate.
    ///
    /// NOT Hyperscan's `verify_bucket` fan-out, and the difference is worth
    /// knowing before this number is read as one. Hyperscan confirms each
    /// candidate against every literal in its bucket, so the ratio is the
    /// bucket width. rgx confirms a single literal and is driven per line,
    /// so a candidate below `at` is skipped rather than confirmed and the
    /// ratio lands below 1. The hit rate is the number to watch here; the
    /// fan-out only becomes a bucket-width question once there are several
    /// literals per bucket to confirm against.
    pub fn confirms_per_candidate(&self) -> f64 {
        if self.candidates == 0 {
            0.0
        } else {
            self.confirms as f64 / self.candidates as f64
        }
    }

    /// Confirms that succeeded, in `(0, 1]`. The first stage's precision;
    /// the rest is work the confirm threw away.
    pub fn hit_rate(&self) -> f64 {
        if self.confirms == 0 {
            0.0
        } else {
            self.hits as f64 / self.confirms as f64
        }
    }

    pub fn is_empty(&self) -> bool {
        self.blocks == 0 && self.confirms == 0
    }

    /// A report a run can print, with the ratios the arguments are made from.
    pub fn summary(&self) -> alloc::string::String {
        use alloc::format;
        format!(
            "mask: {} scans, {} bytes, {} blocks, {} candidates, {} confirms, {} hits\n\
             mask: {:.3} candidates/block, {:.1}% productive blocks, \
             {:.2} confirms/candidate, {:.2}% confirm hit rate",
            self.scans,
            self.bytes,
            self.blocks,
            self.candidates,
            self.confirms,
            self.hits,
            self.candidates_per_block(),
            self.productive_block_fraction() * 100.0,
            self.confirms_per_candidate(),
            self.hit_rate() * 100.0,
        )
    }
}

/// Turn counting on or off. Off by default; the hot path pays one relaxed
/// load per call site either way.
pub fn enable(on: bool) {
    ENABLED.store(on, Relaxed);
}

pub fn enabled() -> bool {
    #[cfg(test)]
    if LOCAL.with(|c| c.borrow().is_some()) {
        return true;
    }
    ENABLED.load(Relaxed)
}

/// Zero every counter. The flag is left alone.
pub fn reset() {
    for c in [&SCANS, &BYTES, &BLOCKS, &CANDIDATES, &CONFIRMS, &HITS] {
        c.store(0, Relaxed);
    }
}

/// Read the counters.
pub fn snapshot() -> Stats {
    Stats {
        scans: SCANS.load(Relaxed),
        bytes: BYTES.load(Relaxed),
        blocks: BLOCKS.load(Relaxed),
        candidates: CANDIDATES.load(Relaxed),
        confirms: CONFIRMS.load(Relaxed),
        hits: HITS.load(Relaxed),
    }
}

// A per-thread counter set, for tests.
//
// Plain comments, not `///`: rustdoc renders nothing for a macro invocation,
// and this is `cfg(test)` besides.
//
// The process-global counters are right for the binary, which counts work
// done on threads this crate does not own. They are wrong for a test that
// asserts exact numbers while other tests run in parallel: any other test
// calling `scan::candidates` flushes into the same counters, and the
// assertion fails on timing rather than on anything it is checking.
#[cfg(test)]
std::thread_local! {
    static LOCAL: std::cell::RefCell<Option<Stats>> = const { std::cell::RefCell::new(None) };
}

/// Start counting into this thread's own set, ignoring the global one.
#[cfg(test)]
pub fn begin_local() {
    LOCAL.with(|c| *c.borrow_mut() = Some(Stats::default()));
}

#[cfg(test)]
pub fn end_local() -> Stats {
    LOCAL.with(|c| c.borrow_mut().take().unwrap_or_default())
}

pub(crate) fn flush(delta: &ScanDelta) {
    #[cfg(test)]
    {
        let mut taken = false;
        LOCAL.with(|c| {
            if let Some(local) = c.borrow_mut().as_mut() {
                local.scans += 1;
                local.bytes += delta.bytes;
                local.blocks += delta.blocks;
                local.candidates += delta.candidates;
                local.confirms += delta.confirms;
                local.hits += delta.hits;
                taken = true;
            }
        });
        if taken {
            return;
        }
    }
    if !enabled() {
        return;
    }
    SCANS.fetch_add(1, Relaxed);
    BYTES.fetch_add(delta.bytes, Relaxed);
    BLOCKS.fetch_add(delta.blocks, Relaxed);
    CANDIDATES.fetch_add(delta.candidates, Relaxed);
    CONFIRMS.fetch_add(delta.confirms, Relaxed);
    HITS.fetch_add(delta.hits, Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the three tests below, because they are the only ones that
    /// touch the process-global counters, and the gate is global too.
    ///
    /// `flush` reaches a global only when `ENABLED` is set, and only when the
    /// calling thread has no `LOCAL` set, so this is a small closed world:
    /// these three tests, and no other. Without the lock they raced each
    /// other -- `a_neighbours_global_flush_cannot_move_this_threads_totals`
    /// deliberately drives 20k deltas through the globals, and the other two
    /// assert that the globals are empty. That showed up as 2 failures in 20
    /// runs of the full workspace suite.
    static GLOBALS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take [`GLOBALS`], ignoring poisoning: a neighbour test that panicked
    /// has left the globals wherever it got to, not locked forever, and the
    /// tests that follow reset them anyway.
    fn globals() -> std::sync::MutexGuard<'static, ()> {
        GLOBALS.lock().unwrap_or_else(|e| e.into_inner())
    }

    // The counters are process-global by design -- they have to be, to count
    // work done on threads this crate does not own -- which is exactly what
    // made this test flaky. It used to turn the global gate on and then assert
    // exact totals, and every other test in this binary that reaches
    // `scan::candidates`, `prefilter` or `regex` flushes into those same
    // globals the moment the gate is up. The assertion therefore raced: it
    // failed whenever a neighbour flushed inside the window, and passed when
    // the scheduler happened to keep them apart. 7 runs in 12 of
    // `cargo test -p rgx-core --lib` hit it.
    //
    // The split below is what makes it deterministic, and it splits along the
    // only line that is actually racy:
    //
    //   * the gate is one atomic, and this module's `enable` is its only
    //     writer, so flipping it and reading it back cannot race anything.
    //   * the arithmetic runs against the thread-local set, which `flush`
    //     diverts into and never merges, so a neighbour's flush is invisible.
    //
    // `ENABLED` is read raw rather than through `enabled()`, because
    // `enabled()` reports `true` for any thread that has called
    // `begin_local()` -- which is precisely the state the second half of this
    // test puts it in.
    //
    // Order matters and is the other half of the fix: the global assertions
    // come first, while the gate is still off. Nothing else in the crate
    // turns it on, so no neighbour can flush, so `snapshot()` is quiet and
    // `reset()` really empties it. The gate is raised only at the very end,
    // and only its own value is asserted afterwards.
    #[test]
    fn counters_are_off_by_default_and_count_when_enabled() {
        let _guard = globals();
        // --- the global side, with counting off ---
        enable(false);
        reset();
        assert!(!ENABLED.load(Relaxed), "counting is off by default");
        assert!(!enabled(), "enabled() agrees while no local set is open");

        let before = snapshot();
        flush(&ScanDelta {
            bytes: 1000,
            blocks: 31,
            candidates: 7,
            confirms: 56,
            hits: 2,
        });
        assert_eq!(snapshot(), before, "a disabled counter must not move");
        assert!(snapshot().is_empty());
        assert_eq!(snapshot(), Stats::default());

        // --- the arithmetic, on this thread's own counters ---
        begin_local();
        flush(&ScanDelta {
            bytes: 3200,
            blocks: 100,
            candidates: 20,
            confirms: 160,
            hits: 5,
        });
        flush(&ScanDelta {
            bytes: 3200,
            blocks: 100,
            candidates: 20,
            confirms: 160,
            hits: 5,
        });
        let s = end_local();

        assert_eq!(s.scans, 2);
        assert_eq!(s.bytes, 6400);
        assert_eq!(s.blocks, 200);
        assert_eq!(s.candidates, 40);
        assert_eq!(s.confirms, 320);
        assert_eq!(s.hits, 10);
        assert!((s.candidates_per_block() - 0.2).abs() < 1e-12);
        assert!((s.confirms_per_candidate() - 8.0).abs() < 1e-12);
        assert!((s.productive_block_fraction() - 0.2).abs() < 1e-12);
        assert!((s.hit_rate() - 10.0 / 320.0).abs() < 1e-12);
        assert!(s.summary().contains("320 confirms"));

        // The local set is what got the deltas; the globals never saw them.
        assert!(
            snapshot().is_empty(),
            "local deltas must not leak into the globals"
        );

        // --- the gate itself, last ---
        enable(true);
        assert!(ENABLED.load(Relaxed), "enable(true) must open the gate");
        enable(false);
        assert!(!ENABLED.load(Relaxed), "enable(false) must close it again");
    }

    /// A second `enable(true)` that runs while a neighbour is counting must
    /// not corrupt the neighbour's totals either. This is the property the
    /// flaky test was actually asserting by accident, and it is now stated:
    /// local counting and global counting are independent.
    #[test]
    fn local_counting_does_not_disturb_the_globals() {
        let _guard = globals();
        enable(false);
        reset();
        let quiet = snapshot();
        assert!(quiet.is_empty());

        begin_local();
        for _ in 0..100 {
            flush(&ScanDelta {
                bytes: 1,
                blocks: 1,
                candidates: 1,
                confirms: 1,
                hits: 1,
            });
        }
        let s = end_local();

        assert_eq!(s.scans, 100);
        assert_eq!(
            snapshot(),
            quiet,
            "the globals must be untouched while LOCAL is open"
        );
    }

    /// A neighbour flushing into the process-global counters cannot move this
    /// thread's numbers.
    ///
    /// This is the failure the flaky test hit, made deliberate and
    /// deterministic. `counters_are_off_by_default_and_count_when_enabled`
    /// used to raise the global gate and then assert exact totals on
    /// `snapshot()`; every other test in this binary that reaches
    /// `scan::candidates`, `prefilter` or `regex` flushes into those same
    /// globals as soon as the gate is up, so the totals it asserted were a
    /// function of the scheduler. It failed 7 runs in 12 of
    /// `cargo test -p rgx-core --lib`, and passed when run alone.
    ///
    /// The neighbour here is a real thread doing real global flushes for the
    /// whole window, so the assertion cannot pass by the interference simply
    /// not happening. It is `begin_local` that makes the result independent:
    /// `flush` folds into the thread's own set and returns before touching a
    /// global, so the deltas below are counted exactly no matter what the
    /// neighbour is doing.
    #[test]
    fn a_neighbours_global_flush_cannot_move_this_threads_totals() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let _guard = globals();
        enable(false);
        reset();
        assert!(snapshot().is_empty(), "globals start at zero");

        let open = Arc::new(AtomicBool::new(false));
        let neighbour = std::thread::spawn({
            let open = Arc::clone(&open);
            move || {
                while !open.load(Relaxed) {
                    std::hint::spin_loop();
                }
                enable(true);
                for _ in 0..20_000 {
                    flush(&ScanDelta {
                        bytes: 1,
                        blocks: 1,
                        candidates: 1,
                        confirms: 1,
                        hits: 1,
                    });
                }
                enable(false);
            }
        });

        open.store(true, Relaxed);
        begin_local();
        flush(&ScanDelta {
            bytes: 3200,
            blocks: 100,
            candidates: 20,
            confirms: 160,
            hits: 5,
        });
        flush(&ScanDelta {
            bytes: 3200,
            blocks: 100,
            candidates: 20,
            confirms: 160,
            hits: 5,
        });
        let s = end_local();
        neighbour.join().unwrap();

        assert_eq!(s.scans, 2, "the neighbour's scans leaked in");
        assert_eq!(s.bytes, 6400);
        assert_eq!(s.blocks, 200);
        assert_eq!(s.candidates, 40);
        assert_eq!(s.confirms, 320);
        assert_eq!(s.hits, 10);
    }

    #[test]
    fn zero_counters_do_not_divide_by_zero() {
        let s = Stats::default();
        assert_eq!(s.candidates_per_block(), 0.0);
        assert_eq!(s.confirms_per_candidate(), 0.0);
        assert_eq!(s.hit_rate(), 0.0);
        assert_eq!(s.productive_block_fraction(), 0.0);
    }

    #[test]
    fn merging_deltas_adds() {
        let mut a = ScanDelta {
            bytes: 1,
            blocks: 1,
            candidates: 1,
            confirms: 2,
            hits: 1,
        };
        a.merge(&ScanDelta {
            bytes: 10,
            blocks: 2,
            candidates: 3,
            confirms: 4,
            hits: 0,
        });
        assert_eq!(a.bytes, 11);
        assert_eq!(a.blocks, 3);
        assert_eq!(a.candidates, 4);
        assert_eq!(a.confirms, 6);
        assert_eq!(a.hits, 1);
    }
}
