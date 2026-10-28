// SPDX-License-Identifier: Apache-2.0

//! Search engine for aggregated packs preserving strict file boundaries.
//!
//! # Critical Correctness Invariant
//!
//! Storing files in contiguous packs does NOT mean treating them as one concatenated text.
//! For each file in the manifest, the matcher is given EXCLUSIVELY its isolated slice:
//! `&pack[offset .. offset + length]`.
//!
//! Under this architecture:
//! - Zero regex matches can cross file boundaries.
//! - Context lines (`-A`, `-B`, `-C`) cannot bleed into adjacent files.
//! - Line numbers are always 1-based and strictly local to the individual file.
//! - Anchors (`^`, `$`, `\b`, `\A`, `\z`) match relative to the file boundaries.
//!
//! # Where the bytes come from
//!
//! [`ReadMode`] picks one of three ways to get bytes in front of the matcher:
//!
//! - [`ReadMode::Mmap`] maps every pack in the coordinator and hands the workers
//!   pointers. Cheap to set up, but on Windows every mapping has to be torn down
//!   again before the query can return, and that teardown is serial.
//! - [`ReadMode::Buffered`] is what `--no-mmap` used to do: the coordinator reads
//!   every pack into RAM on its own thread, then the workers search RAM.
//! - [`ReadMode::ParallelBuffered`] has the coordinator read *nothing*. Each
//!   worker claims a whole pack, reads it into a buffer it keeps for the rest of
//!   the query, and searches the files the manifest assigns to that pack. There
//!   is no mapping and therefore no teardown.
//!
//! The unit of parallelism differs: the first two hand out file chunks, the
//! third hands out packs. A pack is the natural unit of I/O, but it is a coarse
//! one — see [`SearchConfig::packs_per_thread`].
//!
//! # Determinism
//!
//! Which worker wins a claim is a race, and a race must not reach stdout. Every
//! mode keys its result buckets by the claim itself — the chunk's file index, or
//! the pack's position in the manifest — and concatenates them in that order.
//! Two runs of the same query on the same store therefore print the same bytes
//! in the same order, and so do two different modes, even though they hand out
//! different units of work to different numbers of threads.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::collections::HashMap;
use std::eprintln;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::hybrid::{HybridMatcher, UnicodeMatcher};
use crate::memmap2::Mmap;
use crate::ngram::NgramSig512;
use crate::regex::{ByteRegex, Matcher as _};
use crate::searcher as rgxsearcher;
// The query vocabulary and the planner are `no_std` and live in `rgx-core`,
// so the same engine rule and the same boundary invariant answer for a
// process that links this thread pool and for one that cannot.
use crate::tv::plan::{merge_buckets, narrow, split_locs, split_owned, PackPlan};
use crate::tv::query::{EngineMode, ReadMode, SearchConfig, SearchMatch, Unmap};

use super::format::{FileLoc, FileRecord, Manifest, PackHeader, PackRecord, RawManifest};
use super::store::MappedStore;

/// The compiled pattern, in the in-house engine.
///
/// The pack store is byte-only: the in-house byte engine is the only
/// path, and the delegate is the byte engine itself (see `src/engine.rs`'s
/// `ByteDelegate` for the same construction on the main binary's path).
/// A pattern the in-house cannot compile is `io::Error::Unsupported` with
/// the same message the main binary's `Searcher::fallback` returns.
pub enum Engine {
    Hybrid {
        byte: Arc<ByteRegex>,
        /// Whether the in-house engine answers the first claim.
        ///
        /// Always `true` now: there is no other engine to move to, and the
        /// field stays so the engine-decision entry points below keep
        /// reading as the same shape they did when a `Grep` arm existed.
        start_inhouse: bool,
        /// The byte engine as its own delegate. The differential suite
        /// against `regex` pinned 54/54 patterns. The trade-off is the one
        /// `src/engine.rs` documents for `ByteDelegate`: a case-insensitive
        /// non-ASCII line uses byte-mode folding, which is what rgx ships.
        delegate: Arc<ByteRegex>,
        /// The n-gram query signature, or `None` when the pattern stands
        /// the filter down. Built once per query, from the literal every
        /// match must contain; see [`crate::ngram::query_sig512`].
        ngram_query: Option<NgramSig512>,
    },
}

impl Engine {
    /// A pattern the in-house engine cannot compile is an error, not a
    /// fallback: there is no second engine to hand the work to. The
    /// message is the same one rgx's direct `Searcher::fallback` returns,
    /// so a caller that learnt the rule on the main binary sees the same
    /// wording.
    pub fn new(pattern: &str, mode: EngineMode) -> io::Result<Engine> {
        let _ = mode;
        let compile = || -> io::Result<ByteRegex> {
            ByteRegex::new(pattern.as_bytes()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "rgx-tv: pattern is outside the in-house engine's subset; \
                         the in-house byte regex supports literals, alternation, \
                         character classes, anchors, bounded repetitions and capture \
                         groups, and refuses backreferences, look-around, Unicode \
                         property classes and the in-pattern `(?-u)` flag ({e})"
                    ),
                )
            })
        };
        // Compile the byte engine once and share it via Arc: `ByteRegex` is
        // not `Clone`, so a second compile would be the only way to give
        // the delegate its own regex. The cost is the same parse, the same
        // VM tables, and the same prefilter.
        let byte = Arc::new(compile()?);
        let delegate = Arc::clone(&byte);
        // The filter is not available to every pattern -- a folded literal
        // or a branch split stands it down -- and `None` here means "search
        // every file", never "search none"; see [`crate::ngram::query_sig512`].
        // `RGX_ABLATE_NGRAM` forces that stand-down state for the paper's
        // end-to-end tier ablation: cost may change, answers never do.
        let ngram_query = if crate::ablate_ngram() {
            None
        } else {
            crate::ngram::query_sig512(pattern, false)
        };
        Ok(Engine::Hybrid {
            start_inhouse: true,
            byte,
            delegate,
            ngram_query,
        })
    }

    /// The n-gram query signature this pattern can filter with, or `None`
    /// when it cannot filter at all.
    #[inline]
    pub(crate) fn ngram_query(&self) -> Option<NgramSig512> {
        match self {
            Engine::Hybrid { ngram_query, .. } => *ngram_query,
        }
    }

    /// The in-house matcher, exposed under the old `grep` name so call sites
    /// that wanted the matcher for a `grep-searcher` shim keep reading.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn grep(&self) -> &ByteRegex {
        match self {
            Engine::Hybrid { byte, .. } => byte,
        }
    }

    /// Compile for a test that pins a decision policy.
    #[doc(hidden)]
    pub fn new_for_test(pattern: &str) -> Engine {
        Engine::new(pattern, EngineMode::Auto).expect("the pattern compiles")
    }

    /// Compile for a test that pins a decision policy, with the mode asked for.
    #[doc(hidden)]
    pub fn new_for_test_mode(pattern: &str, mode: EngineMode) -> Engine {
        Engine::new(pattern, mode).expect("the pattern compiles")
    }

    /// Whether the in-house engine answers the first claim. Always `true`
    /// now: there is no other engine to defer to.
    #[doc(hidden)]
    pub fn starts_inhouse(&self) -> bool {
        matches!(
            self,
            Engine::Hybrid {
                start_inhouse: true,
                ..
            }
        )
    }

    /// Whether a claim is allowed to move the query onto the in-house engine.
    ///
    /// With no `Grep` arm to move onto, this is always `false`: the in-house
    /// engine already answers, and a flip is a no-op. The check stays so the
    /// [`Crew`] policy's text reads as the same shape it did.
    fn may_pick(&self) -> bool {
        false
    }

    /// Whether the pattern's prefilter is one `memchr`.
    fn has_single_byte_prefilter(&self) -> bool {
        match self {
            Engine::Hybrid { byte, .. } => byte.has_single_byte_prefilter(),
        }
    }
}

/// A per-thread driver over the in-house engine.
///
/// The in-house `Searcher` borrows the `HybridMatcher` it was built from, so
/// the two are locals of the same frame — the worker makes them and hands this
/// a reference. Constructing them in here instead would mean a struct that
/// refers to itself, and a box that outlives its own contents.
struct Engines<'e> {
    inhouse: &'e rgxsearcher::Searcher<'e>,
    scratch: rgxsearcher::Scratch,
    offsets: Vec<usize>,
}

/// The byte engine as its own `UnicodeMatcher` delegate.
///
/// `rgx_core::hybrid::HybridMatcher` pairs a byte engine with a `UnicodeMatcher`
/// the way `rgx-tv`'s old `GrepDelegate` paired the byte engine with
/// `grep-regex`. With the grep crates out of the build, the delegate is the
/// byte engine itself: every line the byte engine may not decide gets the
/// same answer the byte engine would give, which is the case
/// `src/engine.rs::ByteDelegate` documents for the main binary.
struct ByteDelegate<'a>(&'a ByteRegex);

impl UnicodeMatcher for ByteDelegate<'_> {
    fn find_span(&self, line: &[u8], at: usize) -> Option<core::ops::Range<usize>> {
        self.0.find_at(line, at).map(|i| i..i)
    }
}

fn inhouse_config_for(config: &SearchConfig) -> rgxsearcher::Config {
    rgxsearcher::Config {
        before: config.before_context,
        after: config.after_context,
        // `count` stays off even for `-c`: the collector counts the matches it
        // is handed, which is the same thing the direct path does, and the
        // searcher's own counting path is not what is under test here.
        line_numbers: config.line_numbers,
        // The pack decided binary at build time and filtered the manifest, so
        // the searcher is told not to decide it again: two rules for one word,
        // applied at two different times, is how §5.4's 1,516 lines happened.
        binary: rgxsearcher::BinaryDetection::None,
        buffer_capacity: inhouse_buffer_for(config),
        ..Default::default()
    }
}

/// The in-house searcher's read buffer, for the paths that use one.
///
/// The pack's worker hands the in-house engine a slice — the file's bytes
/// already in the claim's buffer — so it never goes through the reader
/// that `buffer_capacity` sizes, and the field cannot be on its cost.
/// 8 KiB is the size that would be right if this path ever did read,
/// and it is what the median pack file would want.
fn inhouse_buffer_for(config: &SearchConfig) -> usize {
    config.buffer_capacity.unwrap_or(8 * 1024)
}

impl<'e> Engines<'e> {
    fn new(inhouse: &'e rgxsearcher::Searcher<'e>) -> Engines<'e> {
        Engines {
            inhouse,
            scratch: rgxsearcher::Scratch::new(),
            offsets: Vec::new(),
        }
    }

    /// Searches one file's slice and returns how many matching lines it saw.
    fn search(&mut self, hay: &[u8], sink: &mut MatchCollector<'_>) -> Result<usize, io::Error> {
        let before = *sink.count;
        self.inhouse
            .search_slice_with_scratch(hay, sink, &mut self.scratch, &mut self.offsets)
            .map_err(io::Error::other)?;
        Ok(*sink.count - before)
    }
}

/// Configuration options for searching over a pack store.
/// The worker count a query starts with, and the one a bandwidth-bound query
/// never exceeds.
///
/// A pack query is memory-bandwidth-bound, and `available_parallelism` is
/// the wrong number to hand it. Measured on a 16C/32T machine over the
/// 1.99 GB, 117-pack registry store, `pub fn -c`, all six arms count-gated
/// against each other:
///
/// | threads | work stage | read cpu-ms | aggregate read | regex cpu-ms |
/// |---:|---:|---:|---:|---:|
/// | 1 | 286.7 ms | 210.3 | 9.5 GB/s | 73.7 |
/// | 2 | 172.9 ms | 257.2 | 15.5 GB/s | 83.0 |
/// | 4 | 126.6 ms | 385.4 | 20.6 GB/s | 105.4 |
/// | 8 | 117.5 ms | 740.1 | 21.5 GB/s | 159.3 |
/// | 16 | 113.0 ms | 1489.7 | 21.3 GB/s | 180.4 |
/// | 32 | 133.6 ms | 3211.0 | 19.6 GB/s | 414.6 |
///
/// The copies saturate the memory system at four threads and stay there.
/// Twelve is three quarters of the sixteen physical cores: enough to keep
/// the copies saturated with a quarter of the machine left for the
/// coordinator (whose filter and merge are serial) and for the OS, and
/// short of the point where SMT starts costing more than it returns.
///
/// Twelve is three quarters of the sixteen physical cores: enough to keep
/// the copies saturated with a quarter of the machine left for the
/// coordinator (whose filter and merge are serial) and for the OS, and
/// short of the point where SMT starts costing more than it returns. It
/// is the same shape the direct path's default has to be and is not: the
/// direct path scales to 24-32 threads because it moves the same 1.99 GB
/// through 87,769 `open`/`close` pairs and is bound by syscall latency
/// instead, so it keeps every logical processor.
///
/// This is the starting width, not the ceiling. A dense pattern is a
/// different query wearing the same store — see [`Crew`].
pub fn default_threads() -> usize {
    let logical = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    threads_for(logical, logical_per_core())
}

/// The rule, as a pure function, so the topology query is the only part that
/// touches the machine. `per_core` is logical processors per core; `None` means
/// the CPU would not say, which is treated as "no SMT to discount".
#[doc(hidden)]
pub fn threads_for(logical: usize, per_core: Option<usize>) -> usize {
    let physical = match per_core {
        Some(n) if n > 1 => logical / n,
        // No SMT to discount, or a topology that could not be read: three
        // quarters of the logical count is the plateau either way.
        _ => logical,
    };
    (physical * 3 / 4).max(1)
}

/// Logical processors per core, from CPUID leaf 0x0B subleaf 0 — the
/// SMT level of the extended topology enumeration. `None` when the CPU does
/// not implement it, which is a "count what you were given" answer rather than
/// a guess.
#[cfg(target_arch = "x86_64")]
#[allow(unused_unsafe)]
fn logical_per_core() -> Option<usize> {
    let max_leaf = unsafe { core::arch::x86_64::__cpuid(0) }.eax;
    if max_leaf < 0x0B {
        return None;
    }
    let leaf = unsafe { core::arch::x86_64::__cpuid_count(0x0B, 0) };
    smt_level(leaf.ecx, leaf.ebx)
}

/// The leaf's answer, as a function of the two registers that carry it.
///
/// The level type is `ECX[15:8]`, not `ECX[15:0]`. Reading the low half
/// finds `0x0100`'s low half, which is zero, and concludes on a two-thread-
/// per-core 7950X3D that the CPU reported no SMT at all.
#[doc(hidden)]
pub fn smt_level(ecx: u32, ebx: u32) -> Option<usize> {
    // 1 is the SMT level. Anything else -- including 0, which is what a CPU with
    // no extended topology reports for an empty subleaf -- is not an answer.
    if (ecx >> 8) & 0xFF != 1 {
        return None;
    }
    let per_core = (ebx & 0xFFFF) as usize;
    (per_core > 0).then_some(per_core)
}

#[cfg(not(target_arch = "x86_64"))]
fn logical_per_core() -> Option<usize> {
    None
}

/// The part of a query that decides how wide it is.
///
/// A pack query has two regimes, and the pattern does not say which one
/// you are in until you have run it. When the copies dominate, the memory
/// system saturates at four threads and twelve is the wall-clock minimum.
/// When the scan dominates — a dense single-byte literal — the scan is
/// real CPU that scales to the last logical processor.
///
/// So the query starts at the bandwidth optimum and the workers carry the
/// two numbers that tell the regimes apart already: every worker times
/// the read and the scan of every pack it claims, for the stats line. A
/// worker whose first pack cost more scan than read opens the rest of the
/// machine to the query, once.
#[doc(hidden)]
pub struct Crew {
    /// Set by whichever worker first gets the evidence. Nobody spawns twice.
    decided: AtomicBool,
    /// Handles of workers the query did not start with, for the coordinator.
    extra: Mutex<Vec<std::thread::JoinHandle<io::Result<WorkerOut>>>>,
    /// How many workers the query started with, and the most it may ever run.
    started: usize,
    cap: usize,
    /// Which engine the claims are answering on. Set by the text rule before
    /// the first claim and moved by [`Crew::maybe_pick_engine`] after one.
    inhouse_on: Arc<AtomicBool>,
    /// Set once the engine has been decided, so a flip is a decision and not a
    /// race between workers.
    engine_decided: AtomicBool,
}

/// The smallest pack whose read and scan timings are worth comparing. A pack
/// of the registry store is 16 MiB and takes about 26 ms to read; 256 KiB is
/// three orders of magnitude below the store and two above the point where an
/// `open` and a `read` dominate everything the matcher does.
const EVIDENCE_BYTES: usize = 256 * 1024;

/// How much more the scan has to cost than the copy before the query believes
/// it and opens the machine. See [`Crew::maybe_widen`].
const SCAN_MARGIN: u128 = 2;

/// Matching lines per kilobyte of claim above which the query moves onto the
/// in-house engine, if the pattern's prefilter is a single byte. The measured
/// shapes: `a+` at 8.9 flips, `w` at 3.4 does not, `q` at 1.25 must not.
const DENSITY_PER_KB: u64 = 6;

impl Crew {
    #[doc(hidden)]
    pub fn new(started: usize, cap: usize, inhouse_on: Arc<AtomicBool>) -> Crew {
        Crew {
            decided: AtomicBool::new(false),
            extra: Mutex::new(Vec::new()),
            started,
            cap,
            inhouse_on,
            engine_decided: AtomicBool::new(false),
        }
    }

    /// Move the query onto the in-house engine, if this claim is the evidence.
    ///
    /// The same measurement the width decision uses, asked a second question.
    /// A claim knows how many lines it matched and how many bytes it read,
    /// and the ratio of the two is the density the pattern's text cannot
    /// express. The single-byte prefilter is what says the in-house engine
    /// has nothing to add.
    ///
    /// Both conditions are needed. The density is what says the scan is
    /// the work; the single-byte prefilter is what says ripgrep's SIMD
    /// literal matcher has nothing to add.
    ///
    /// The threshold sits between `a+` at 8.9, which flips, and `w` at 3.4,
    /// which does not.
    #[doc(hidden)]
    pub fn maybe_pick_engine(
        &self,
        engine: &Engine,
        matched_lines: usize,
        claim_bytes: usize,
    ) -> bool {
        if !engine.may_pick() || !engine.has_single_byte_prefilter() {
            return false;
        }
        if self.engine_decided.load(Ordering::Relaxed) {
            return false;
        }
        // Per kilobyte, as a u64 so the comparison is exact.
        let per_kb = matched_lines as u64 * 1024 / claim_bytes.max(1) as u64;
        if per_kb < DENSITY_PER_KB {
            return false;
        }
        if self.engine_decided.swap(true, Ordering::Relaxed) {
            return false;
        }
        self.inhouse_on.store(true, Ordering::Relaxed);
        true
    }

    /// A worker finished its first pack. Open the machine, or do not.
    ///
    /// Returns whether this worker was the one that widened the query, which it
    /// needs to know only so that it stops asking.
    #[doc(hidden)]
    pub fn maybe_widen(
        &self,
        pack_bytes: usize,
        read_ns: u128,
        scan_ns: u128,
        unclaimed: usize,
        spawn: impl Fn() -> std::thread::JoinHandle<io::Result<WorkerOut>>,
    ) -> bool {
        if self.decided.load(Ordering::Relaxed) {
            return false;
        }
        // A ratio of two timings is only worth reading when the timings are
        // worth having. A 1 KiB pack is one `open` and a few microseconds of
        // scan, and which of the two is larger there is a property of the
        // syscall rather than of the query.
        if pack_bytes < EVIDENCE_BYTES {
            return false;
        }
        // The scan has to be the expensive half by a margin, not by a hair.
        // A margin of two separates the case that matters from the cases
        // that do not with room to spare, and buys the measurement room
        // to be noisy.
        if scan_ns <= read_ns.saturating_mul(SCAN_MARGIN) {
            return false;
        }
        let room = self.cap.saturating_sub(self.started);
        // Nothing to gain from a worker that finds an empty queue, which is
        // also the case for every store narrower than the crew.
        let n = room.min(unclaimed);
        if n == 0 || self.decided.swap(true, Ordering::Relaxed) {
            return false;
        }
        let mut extra = self.extra.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..n {
            extra.push((spawn)());
        }
        true
    }

    /// The workers the query added, so the coordinator joins them too.
    #[doc(hidden)]
    pub fn take_extra(&self) -> Vec<std::thread::JoinHandle<io::Result<WorkerOut>>> {
        std::mem::take(&mut *self.extra.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// Where the wall clock of one query went, in milliseconds.
///
/// `manifest_ms`, `filter_ms`, `map_ms` and `teardown_ms` are serial: they run
/// on the coordinator thread and nothing overlaps them. `work_ms` is the wall
/// clock of the parallel phase. `read_cpu_ms` and `scan_cpu_ms` are summed over
/// worker threads, so they are CPU milliseconds and are expected to exceed
/// `work_ms`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct StageTimes {
    pub manifest_ms: f64,
    pub filter_ms: f64,
    /// Coordinator-side pack open: `open`+`mmap` for [`ReadMode::Mmap`], the
    /// serial read for [`ReadMode::Buffered`], and zero for
    /// [`ReadMode::ParallelBuffered`] — that path's reads are in `read_cpu_ms`.
    pub map_ms: f64,
    pub work_ms: f64,
    pub read_cpu_ms: f64,
    pub scan_cpu_ms: f64,
    pub teardown_ms: f64,
    /// Everything from entering the public entry point to having the matches.
    /// Includes `teardown_ms`; `SearchStats::elapsed_ms` does not.
    pub in_process_ms: f64,
    /// Read plus scan for one claim, percentiles across the claims a buffered
    /// query actually touched. A claim is a [`Unit`](crate::tv::Unit): about a mebibyte of a
    /// pack, cut at file boundaries. Zero on the mapping paths, where the unit
    /// of work is a file chunk and there is no per-claim read to time.
    ///
    /// The field names say `pack` and the unit says `claim` because renaming a
    /// published field is a breaking change to every reader of `--stats`.
    pub pack_service_p50_ms: f64,
    pub pack_service_p99_ms: f64,
    pub pack_service_max_ms: f64,
    /// Summed claim service time over (threads x work window). 1.0 means every
    /// thread was busy for the entire parallel phase; lower means the tail, the
    /// ramp-up, or a coarse unit of work left somebody waiting. Measured on the
    /// registry store: 0.93 at pack claims, 0.95 at the default width, 0.89 to
    /// 0.96 on a query that widens itself.
    pub balance: f64,
}

/// Statistics reported after searching.
#[derive(Debug, Clone)]
pub struct SearchStats {
    /// Packs the store holds and the query covered, whether or not every one of
    /// them had a file to search.
    pub total_packs_scanned: usize,
    pub total_files_searched: usize,
    /// Files the n-gram filter rejected before their bytes were read. The
    /// filter never rejects a file that holds a match, so these are not
    /// files the query skipped -- they are files it answered without
    /// reading. `0` when the pattern stood the filter down.
    pub total_files_pruned: usize,
    pub total_files_matched: usize,
    pub total_lines_matched: usize,
    /// In-process wall clock from entry to "matches are ready", excluding the
    /// [`Unmap::Explicit`] teardown, which happens after this point. Prefer
    /// [`StageTimes`] when you want to know where the time went.
    pub elapsed_ms: f64,
    /// True when this call was served from a `MappedStore`'s warm mappings
    /// instead of opening them here.
    pub pooled: bool,
    /// Workers this query ran, after it widened itself. Equal to
    /// [`SearchConfig::threads`] when `-j` pinned the width, and a number the
    /// query chose from its own per-pack timings when it did not; see `Crew`.
    pub workers: usize,
    /// How many files validation stat'd and how many the filesystem disagreed
    /// about, when [`SearchConfig::validate_freshness`] asked for the answer.
    /// `None` when it did not, which is not the same as `(0, 0)`: a query that
    /// did not check has no idea.
    pub stale_files: Option<(usize, usize)>,
    /// Which engine answered, as it stood at the end of the query.
    ///
    /// `grep` is `grep-regex`, `rgx` is the in-house engine, and `rgx*` is
    /// `rgx` after a claim moved the query onto it — which is a decision a
    /// reader of a timing has to be able to see, because on this store it is
    /// worth 33% on `e` and nothing at all on `pub fn`.
    pub engine: &'static str,
    pub stages: StageTimes,
}

/// Collects one file's matches.
///
/// The name is decoded on the first match rather than before the search:
/// `-c` prints none, and a match-printing query prints the name of the
/// files that produced one. Everything else here is per match, so the one
/// branch is free next to the work already being done.
struct MatchCollector<'a> {
    name: Name<'a>,
    /// Decoded on first use, then kept for the rest of this file.
    path: Option<String>,
    matches: &'a mut Vec<SearchMatch>,
    count: &'a mut usize,
    count_only: bool,
}

/// Where a file's name comes from.
///
/// The query path has not decoded it and decodes it on demand; the mapping and
/// serial paths decoded the whole manifest already and have it in hand. One
/// sink serves both, because a sink that cannot be told which path it is on
/// would be a place for the two to answer differently.
enum Name<'a> {
    Undecoded { raw: &'a RawManifest, loc: FileLoc },
    Borrowed(&'a str),
}

impl<'a> MatchCollector<'a> {
    fn path(&mut self) -> &str {
        match self.name {
            Name::Borrowed(p) => p,
            Name::Undecoded { raw, loc } => {
                if self.path.is_none() {
                    self.path = Some(match raw.path_of(&loc) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("rgx-tv: warning: unreadable path in manifest: {}", e);
                            String::new()
                        }
                    });
                }
                self.path.as_deref().unwrap_or_default()
            }
        }
    }
}

impl<'a> rgxsearcher::Sink for MatchCollector<'a> {
    type Error = io::Error;

    fn matched(&mut self, mat: &rgxsearcher::SinkMatch<'_>) -> Result<bool, Self::Error> {
        *self.count += 1;
        if !self.count_only {
            let path = self.path().to_string();
            self.matches.push(SearchMatch {
                path,
                line_number: mat.line_number,
                line: mat.bytes.to_vec(),
            });
        }
        Ok(true)
    }

    fn context(&mut self, ctx: &rgxsearcher::SinkContext<'_>) -> Result<bool, Self::Error> {
        if !self.count_only {
            let path = self.path().to_string();
            self.matches.push(SearchMatch {
                path,
                line_number: ctx.line_number,
                line: ctx.bytes.to_vec(),
            });
        }
        Ok(true)
    }

    fn finish(&mut self, _fin: &rgxsearcher::SinkFinish<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Where the packs come from, and where the file list comes from.
// ---------------------------------------------------------------------------

/// A pack payload held open for the duration of one search.
enum PackStorage {
    Mmap(Arc<Mmap>),
    Buffered(Arc<Vec<u8>>),
}

impl PackStorage {
    fn payload(&self) -> &[u8] {
        match self {
            PackStorage::Mmap(m) => &m[PackHeader::SIZE..],
            PackStorage::Buffered(b) => b.as_slice(),
        }
    }
}

type OwnedPackMap = HashMap<u32, PackStorage>;

/// The packs a search reads through. `Owned` is the cold path that opens and
/// drops everything itself; `Pooled` borrows mappings a `MappedStore` is holding
/// on the query's behalf, optionally alongside the packs the pool's byte ceiling
/// excluded and this query had to open for itself.
enum PackIndex {
    Owned(OwnedPackMap),
    Pooled(Arc<Vec<Option<Arc<Mmap>>>>),
    Hybrid {
        warm: Arc<Vec<Option<Arc<Mmap>>>>,
        cold: OwnedPackMap,
    },
}

impl PackIndex {
    #[inline]
    fn payload(&self, pack_id: u32) -> Option<&[u8]> {
        match self {
            PackIndex::Owned(m) => m.get(&pack_id).map(|s| s.payload()),
            PackIndex::Pooled(v) => v
                .get(pack_id as usize)?
                .as_deref()
                .map(|m| &m[PackHeader::SIZE..]),
            PackIndex::Hybrid { warm, cold } => match warm.get(pack_id as usize) {
                Some(Some(m)) => Some(&m[PackHeader::SIZE..]),
                _ => cold.get(&pack_id).map(|s| s.payload()),
            },
        }
    }
}

/// The filtered file list a worker walks. `Owned` holds the records themselves,
/// which is what the cold path has always done; `Indexed` holds 4-byte indices
/// into a manifest the pool already has parsed.
trait FileSource: Send + Sync {
    fn len(&self) -> usize;
    fn get(&self, i: usize) -> &FileRecord;
}

struct OwnedFiles(Vec<FileRecord>);

impl FileSource for OwnedFiles {
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
    #[inline]
    fn get(&self, i: usize) -> &FileRecord {
        &self.0[i]
    }
}

struct IndexedFiles {
    manifest: Arc<Manifest>,
    idx: Arc<Vec<u32>>,
}

impl FileSource for IndexedFiles {
    #[inline]
    fn len(&self) -> usize {
        self.idx.len()
    }
    #[inline]
    fn get(&self, i: usize) -> &FileRecord {
        &self.manifest.files[self.idx[i] as usize]
    }
}

type Bucket = ((u32, u64), Vec<SearchMatch>);

/// What one worker of the mapping path hands back.
struct ChunkOut {
    buckets: Vec<(u32, Vec<SearchMatch>)>,
}

// ---------------------------------------------------------------------------
// The coordinator and worker pool over pack mappings. Identical for the cold
// and the pooled path; only where `packs` and `files` came from differs.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn run_search<F: FileSource + 'static>(
    total_packs: usize,
    packs: PackIndex,
    files: F,
    empty_files: F,
    engine: Arc<Engine>,
    config: &SearchConfig,
    head_extract_fp: u64,
    t0: Instant,
    stages: &mut StageTimes,
) -> io::Result<(Vec<SearchMatch>, SearchStats, Arc<PackIndex>)> {
    // Whether this query's rollup trust matches the catalog's: the per-file
    // half is `FileLoc::sig_covers_adapter`, this is the head's. A record
    // whose signature is the adapter rollup may be rejected only when both
    // say so; see the filter below.
    let rollup_ok = config.extract_fp == Some(head_extract_fp);
    let shared_storage = Arc::new(packs);
    let shared_files = Arc::new(files);
    let shared_empty = Arc::new(empty_files);
    let next_file_idx = Arc::new(AtomicUsize::new(0));

    let total_matched_files = Arc::new(AtomicUsize::new(0));
    let total_matched_lines = Arc::new(AtomicUsize::new(0));
    let total_files_searched = Arc::new(AtomicUsize::new(0));
    let total_files_pruned = Arc::new(AtomicUsize::new(0));

    let num_threads = config.threads.max(1);
    let chunk_size = if shared_files.len() == 0 {
        64
    } else {
        (shared_files.len() / (num_threads * 4)).clamp(16, 512)
    };

    let t_work = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..num_threads {
        let storage_map = Arc::clone(&shared_storage);
        let files = Arc::clone(&shared_files);
        let next_idx = Arc::clone(&next_file_idx);
        let matched_files = Arc::clone(&total_matched_files);
        let matched_lines = Arc::clone(&total_matched_lines);
        let searched_files = Arc::clone(&total_files_searched);
        let pruned_files = Arc::clone(&total_files_pruned);
        let cfg = config.clone();
        let e_clone = Arc::clone(&engine);

        let handle = std::thread::spawn(move || -> io::Result<ChunkOut> {
            let hybrid = match &*e_clone {
                Engine::Hybrid { byte, delegate, .. } => {
                    HybridMatcher::new(byte.as_ref(), ByteDelegate(delegate.as_ref()))
                }
            };
            let inhouse =
                rgxsearcher::Searcher::with_candidates(&hybrid, &hybrid, inhouse_config_for(&cfg));
            // The mapped and serial-buffered paths read a whole pack between
            // claims and never time one, so they keep the text rule and cannot
            // be flipped by a claim. Only the parallel-buffered path has a
            // per-claim read and scan to compare.
            let mut engines = Engines::new(&inhouse);
            let ngram_q = e_clone.ngram_query();

            let mut thread_matches: Vec<(u32, Vec<SearchMatch>)> = Vec::new();
            let mut cur: Vec<SearchMatch> = Vec::new();
            let mut thread_searched_files = 0usize;
            let mut thread_pruned_files = 0usize;
            let mut thread_file_matches = 0usize;
            let mut thread_line_matches = 0usize;

            loop {
                let start_idx = next_idx.fetch_add(chunk_size, Ordering::Relaxed);
                if start_idx >= files.len() {
                    break;
                }
                let end_idx = (start_idx + chunk_size).min(files.len());
                cur.clear();

                for i in start_idx..end_idx {
                    let f = files.get(i);
                    thread_searched_files += 1;

                    // The n-gram filter, before the file's bytes are touched:
                    // a signature missing a bit the pattern's holds is proof
                    // the file cannot match. `None` (and the all-zero file
                    // signature) stands the filter down -- see
                    // [`crate::ngram::query_sig512`]. One rule answers at
                    // every filter site: a record whose signature is the
                    // adapter rollup ([`FileLoc::SIG_COVERS_ADAPTER`]) is
                    // rejected only under a matching extraction fingerprint,
                    // and any other record is rejected on its own text's
                    // coverage. This search reads the record's own bytes and
                    // is covered either way; the gate is what keeps the
                    // adapter-aware store search, whose haystack is the
                    // pipeline's units, answering by the same line.
                    if let Some(q) = ngram_q {
                        if crate::ngram::may_reject(
                            &f.ngram,
                            crate::ngram::covered_raw_bytes(f.sig_covers_adapter, rollup_ok),
                            &q,
                        ) {
                            thread_pruned_files += 1;
                            continue;
                        }
                    }

                    let pack_bytes = match storage_map.payload(f.pack_id) {
                        Some(b) => b,
                        None => continue,
                    };

                    // STRICT FILE BOUNDARY: isolated slice of the pack
                    let start = f.offset as usize;
                    let end = start + f.length as usize;
                    if end > pack_bytes.len() {
                        eprintln!(
                            "rgx-tv: warning: file {} slice out of bounds in pack {}",
                            f.rel_path, f.pack_id
                        );
                        continue;
                    }

                    let file_slice = &pack_bytes[start..end];
                    let mut file_count = 0usize;

                    let mut collector = MatchCollector {
                        name: Name::Borrowed(&f.rel_path),
                        path: None,
                        matches: &mut cur,
                        count: &mut file_count,
                        count_only: cfg.count_only,
                    };

                    let res = engines.search(file_slice, &mut collector);
                    if let Err(e) = res {
                        eprintln!("rgx-tv: search error on {}: {}", f.rel_path, e);
                    }

                    if file_count > 0 {
                        thread_file_matches += 1;
                        thread_line_matches += file_count;
                    }
                }

                // Keyed by the claim itself, not by a per-thread counter: a per-thread
                // counter would let two workers' chunks 0 and 1 collide.
                if !cur.is_empty() {
                    thread_matches.push((start_idx as u32, std::mem::take(&mut cur)));
                }
            }

            searched_files.fetch_add(thread_searched_files, Ordering::Relaxed);
            pruned_files.fetch_add(thread_pruned_files, Ordering::Relaxed);
            matched_files.fetch_add(thread_file_matches, Ordering::Relaxed);
            matched_lines.fetch_add(thread_line_matches, Ordering::Relaxed);
            Ok(ChunkOut {
                buckets: thread_matches,
            })
        });

        handles.push(handle);
    }

    let mut buckets = Vec::new();
    // Reap every worker before propagating a failure, so a failing query never
    // leaves threads behind and never returns what the others found.
    let mut first_err: Option<io::Error> = None;
    for h in handles {
        match h.join() {
            Ok(Ok(mut out)) => buckets.append(&mut out.buckets),
            Ok(Err(e)) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
            Err(_) => {
                if first_err.is_none() {
                    first_err = Some(io::Error::other("a search worker thread panicked"));
                }
            }
        }
    }
    if let Some(e) = first_err {
        return Err(e);
    }
    stages.work_ms = t_work.elapsed().as_secs_f64() * 1000.0;

    let total_lines = total_matched_lines.load(Ordering::Relaxed);
    let mut final_matches = merge_buckets(buckets, total_lines);

    // Handle empty files if pattern matches empty slice
    let mut empty_matches: Vec<(u32, Vec<SearchMatch>)> = Vec::new();
    if shared_empty.len() > 0 {
        let hybrid = match &*engine {
            Engine::Hybrid { byte, delegate, .. } => {
                HybridMatcher::new(byte.as_ref(), ByteDelegate(delegate.as_ref()))
            }
        };
        let s =
            rgxsearcher::Searcher::with_candidates(&hybrid, &hybrid, inhouse_config_for(config));
        for i in 0..shared_empty.len() {
            let f = shared_empty.get(i);
            total_files_searched.fetch_add(1, Ordering::Relaxed);
            let mut count = 0usize;
            let mut dummy = Vec::new();
            let mut collector = MatchCollector {
                name: Name::Borrowed(&f.rel_path),
                path: None,
                matches: &mut dummy,
                count: &mut count,
                count_only: config.count_only,
            };
            let _ = s.search_slice(&[], &mut collector);
            if count > 0 {
                total_matched_files.fetch_add(1, Ordering::Relaxed);
                total_matched_lines.fetch_add(count, Ordering::Relaxed);
                if !dummy.is_empty() {
                    empty_matches.push((i as u32, dummy));
                }
            }
        }
    }
    for (_, v) in empty_matches {
        final_matches.extend(v);
    }

    let elapsed = t0.elapsed().as_secs_f64() * 1000.0;

    Ok((
        final_matches,
        SearchStats {
            total_packs_scanned: total_packs,
            total_files_searched: total_files_searched.load(Ordering::Relaxed),
            total_files_pruned: total_files_pruned.load(Ordering::Relaxed),
            total_files_matched: total_matched_files.load(Ordering::Relaxed),
            total_lines_matched: total_lines,
            elapsed_ms: elapsed,
            pooled: false,
            workers: config.threads,
            stale_files: None,
            engine: "rgx",
            stages: *stages,
        },
        shared_storage,
    ))
}

// ---------------------------------------------------------------------------
// The parallel buffered path: the coordinator reads no pack bytes.
// ---------------------------------------------------------------------------

/// One claimable piece of a pack: a byte range and the files inside it.
///
/// A pack is too coarse to be a claim: a unit is the same bytes cut at a
/// *file* boundary, which is the only place a cut is legal. The boundary
/// invariant is that a file's matches live in `pack[offset..offset+length]`
/// and nothing else.
///
/// 1 MiB is the default because it is two orders of magnitude above the size
/// at which a read syscall is the cost and two below the size at which a
/// worker holds enough of the store to matter.
///
/// This is why the reads can start before the file records are decoded: the
/// pack table is the first few kilobytes of `manifest.tvm`, and the file
/// records behind it say *which* files live in those packs, not how to read
/// the packs themselves. Only the former is needed to issue a read.
#[derive(Clone)]
struct PackTable {
    path: Arc<Vec<PathBuf>>,
    len: Arc<Vec<usize>>,
}

impl PackTable {
    fn new(store_dir: &Path, packs: &[PackRecord]) -> PackTable {
        // (The claim order is the unit table's, not this pack table's: a pack is
        // too coarse to claim. What is left here is which pack is which file on
        // disk, and how long its payload is.)
        //
        // Longest payload first. Shortest-first was measured and was worse in
        // both directions: shortest-first is the wrong order for a fixed
        // crew whatever else is true about it, and late workers on a
        // longest-first queue are handed the short packs that arrive later.
        PackTable {
            path: Arc::new(packs.iter().map(|p| store_dir.join(&p.filename)).collect()),
            len: Arc::new(packs.iter().map(|p| p.content_len as usize).collect()),
        }
    }
}

/// One pack reader: claims packs, reads each into a buffer it keeps, and searches
/// the files the manifest assigned to each.
#[allow(clippy::too_many_arguments)]
fn pack_worker(
    table: PackTable,
    plan: Arc<PackPlan>,
    next: Arc<AtomicUsize>,
    engine: Arc<Engine>,
    config: Arc<SearchConfig>,
    crew: Arc<Crew>,
    inhouse_on: Arc<AtomicBool>,
    head_extract_fp: u64,
) -> io::Result<WorkerOut> {
    let batch = config.packs_per_thread.max(1);
    let hybrid = match &*engine {
        Engine::Hybrid { byte, delegate, .. } => {
            HybridMatcher::new(byte.as_ref(), ByteDelegate(delegate.as_ref()))
        }
    };
    let inhouse =
        rgxsearcher::Searcher::with_candidates(&hybrid, &hybrid, inhouse_config_for(&config));
    let mut engines = Engines::new(&inhouse);
    let ngram_q = engine.ngram_query();
    // The same per-query gate `run_search` computes; see the filter below.
    let rollup_ok = config.extract_fp == Some(head_extract_fp);

    // One search of a throwaway byte, before the first claim, so that the
    // first pack a worker reads is measured as a scan and not as a scan
    // plus every matcher's one-time setup. On a 256 KiB pack that setup
    // is most of the scan, and a ratio between "the scan" and "the copy"
    // that is really a ratio between "the setup" and "the copy" is how a
    // bandwidth-bound query on a small store would talk itself into opening
    // the whole machine.
    {
        let mut count = 0usize;
        let mut lines = Vec::new();
        let mut warm = MatchCollector {
            name: Name::Borrowed(""),
            path: None,
            matches: &mut lines,
            count: &mut count,
            count_only: true,
        };
        let _ = engines.search(b"\n", &mut warm);
    }

    // One buffer per worker, grown to the largest pack it sees and then kept for
    // the rest of the query. No pack byte is memset twice and none is copied.
    let mut buf: Vec<u8> = Vec::new();
    let mut current_file: Option<(usize, File)> = None;
    let mut buckets: Vec<Bucket> = Vec::new();
    let mut searched = 0usize;
    let mut pruned = 0usize;
    let mut matched = 0usize;
    let mut lines = 0usize;
    let mut read_ns: u128 = 0;
    let mut scan_ns: u128 = 0;
    let mut bytes_read = 0u64;
    let mut units_read = 0u64;
    let mut service_ns: Vec<u64> = Vec::new();

    let n_units = plan.units.len();

    // One unit of evidence is enough for both decisions, and only the
    // first is asked: every later one would be answering questions that
    // have already been answered.
    let mut may_widen = true;
    let mut may_pick_engine = true;

    loop {
        let claim = next.fetch_add(batch, Ordering::Relaxed);
        if claim >= n_units {
            break;
        }
        let claim_end = (claim + batch).min(n_units);

        for ui in claim..claim_end {
            let unit = plan.units[ui];
            let p = unit.pack as usize;
            // A unit is a u64 range; a platform whose address space cannot
            // hold one skips it by name rather than reading a truncated
            // slice and answering from half the bytes.
            let Ok(len) = usize::try_from(unit.len) else {
                eprintln!(
                    "rgx-tv: warning: unit of {} bytes does not fit this platform",
                    unit.len
                );
                continue;
            };
            if buf.len() < len {
                buf.resize(len, 0);
            }

            let t_pack = Instant::now();
            let t = Instant::now();
            {
                let file = match current_file {
                    Some((cur_p, ref mut f)) if cur_p == p => f,
                    _ => {
                        #[cfg(windows)]
                        let f = {
                            use std::os::windows::fs::OpenOptionsExt;
                            const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x08000000;
                            std::fs::OpenOptions::new()
                                .read(true)
                                .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN)
                                .open(&table.path[p])?
                        };
                        #[cfg(not(windows))]
                        let f = File::open(&table.path[p])?;
                        current_file = Some((p, f));
                        &mut current_file.as_mut().unwrap().1
                    }
                };
                file.seek(SeekFrom::Start(PackHeader::SIZE as u64 + unit.start))?;
                file.read_exact(&mut buf[..len])?;
            }
            let read_pack_ns = t.elapsed().as_nanos();
            read_ns += read_pack_ns;
            bytes_read += len as u64;
            units_read += 1;

            let pack_bytes = &buf[..len];
            let mut mine: Vec<SearchMatch> = Vec::new();
            let lines_before = lines;
            let t = Instant::now();
            for k in unit.first..unit.last {
                let f = plan.locs[plan.files[k as usize] as usize];
                searched += 1;

                // The n-gram filter, at the same point as the mapping path:
                // before the file's bytes are read out of the pack. `None`
                // (and the all-zero file signature) stands it down, and an
                // adapter rollup record is rejected only under a matching
                // extraction fingerprint -- see the mapping path's filter.
                if let Some(q) = ngram_q {
                    if crate::ngram::may_reject(
                        &f.ngram,
                        crate::ngram::covered_raw_bytes(f.sig_covers_adapter(), rollup_ok),
                        &q,
                    ) {
                        pruned += 1;
                        continue;
                    }
                }

                // Relative to the unit, which starts at the first file's
                // offset. The saturating subtraction is for the manifest
                // that does not ascend: a file placed before its unit's
                // start is out of the unit, not a wrapped huge offset.
                let start = f.offset.saturating_sub(unit.start) as usize;
                let end = start + f.length as usize;
                if end > pack_bytes.len() {
                    eprintln!(
                        "rgx-tv: warning: file #{} slice out of bounds in pack {}",
                        f.file_id, f.pack_id
                    );
                    continue;
                }

                let mut file_count = 0usize;
                let mut collector = MatchCollector {
                    name: Name::Undecoded {
                        raw: &plan.raw,
                        loc: f,
                    },
                    path: None,
                    matches: &mut mine,
                    count: &mut file_count,
                    count_only: config.count_only,
                };
                if let Err(e) = engines.search(&pack_bytes[start..end], &mut collector) {
                    eprintln!("rgx-tv: search error on file #{}: {}", f.file_id, e);
                }

                if file_count > 0 {
                    matched += 1;
                    lines += file_count;
                }
            }
            let scan_pack_ns = t.elapsed().as_nanos();
            scan_ns += scan_pack_ns;
            service_ns.push(t_pack.elapsed().as_nanos() as u64);

            if may_pick_engine {
                // The same evidence gate as the width: a claim too small
                // to time cannot decide either question.
                if len >= EVIDENCE_BYTES {
                    may_pick_engine = false;
                    crew.maybe_pick_engine(&engine, lines - lines_before, len);
                }
            }

            if may_widen {
                // A unit too small to time is not a decision; ask the next one.
                if len >= EVIDENCE_BYTES {
                    may_widen = false;
                    let unclaimed = n_units.saturating_sub(next.load(Ordering::Relaxed));
                    crew.maybe_widen(len, read_pack_ns, scan_pack_ns, unclaimed, || {
                        std::thread::spawn({
                            let table = table.clone();
                            let plan = Arc::clone(&plan);
                            let next = Arc::clone(&next);
                            let engine = Arc::clone(&engine);
                            let config = Arc::clone(&config);
                            let crew = Arc::clone(&crew);
                            let inhouse_on = Arc::clone(&inhouse_on);
                            move || {
                                pack_worker(
                                    table,
                                    plan,
                                    next,
                                    engine,
                                    config,
                                    crew,
                                    inhouse_on,
                                    head_extract_fp,
                                )
                            }
                        })
                    });
                }
            }

            if !mine.is_empty() {
                buckets.push(((unit.pack, unit.start), mine));
            }
        }
    }

    Ok(WorkerOut {
        buckets,
        searched,
        pruned,
        matched,
        lines,
        read_ns,
        scan_ns,
        bytes_read,
        units_read,
        service_ns,
    })
}

/// What one worker hands back to the coordinator.
pub struct WorkerOut {
    buckets: Vec<Bucket>,
    searched: usize,
    pruned: usize,
    matched: usize,
    lines: usize,
    read_ns: u128,
    scan_ns: u128,
    /// What the sparse plan fetched: bytes in the units the worker claimed
    /// and how many units they were. `RGX_EXTENT_STATS` compares these
    /// against the pack payload to say what the plan did not read.
    bytes_read: u64,
    units_read: u64,
    /// Wall clock of one pack: the read plus the files inside it.
    service_ns: Vec<u64>,
}

impl WorkerOut {
    /// A worker that claimed nothing. Only the crew's spawn closure and the
    /// test that pins the widening policy ever ask for one.
    #[doc(hidden)]
    pub fn empty() -> WorkerOut {
        WorkerOut {
            buckets: Vec::new(),
            searched: 0,
            pruned: 0,
            matched: 0,
            lines: 0,
            read_ns: 0,
            scan_ns: 0,
            bytes_read: 0,
            units_read: 0,
            service_ns: Vec::new(),
        }
    }
}

/// The files the manifest claims that the filesystem disagrees about.
///
/// A file is stale when it is gone, when its length differs, or when its
/// modification time does. Size first because it is the cheap half of the
/// answer and catches an edit that kept the length; mtime second because it
/// catches the rest. What it cannot see is a file *added* after the build:
/// that needs the walk the store exists to avoid, and is the documented
/// boundary of this check rather than a hole it pretends to cover.
pub fn stale_files(store_dir: &Path) -> io::Result<(usize, usize)> {
    let m = super::format::load_manifest(store_dir)?;
    Ok(stale_in(&m))
}

/// [`stale_files`] over an already-loaded manifest, so a caller that has
/// one -- `run_tv_query` loads it a moment later anyway -- pays the stat
/// pass and not a second parse.
pub fn stale_in(m: &super::format::Manifest) -> (usize, usize) {
    let (checked, stale) = stale_list_in(m);
    (checked, stale.len())
}

/// [`stale_in`] as a list of the disagreeing records' indices into
/// `m.files`, which is what a caller re-reading the changed files one by
/// one -- the dirty-file overlay in `run_tv_query` -- needs; a count tells
/// it how many to re-read but not which. Same stat pass, same verdicts.
///
/// A member record (the `container!member` names a `--tv-pre-extract`
/// build writes) has no path of its own to stat, so it hangs off its owner
/// container and is stale exactly when the owner is: the mtime its row
/// carries is the owner's, signed at build. Judged by its own name instead,
/// every member of every store read as gone-on-disk and the overlay then
/// dropped the container's whole answer from a store nothing had changed
/// in. Length is deliberately no part of the member verdict -- the row's
/// length is the member's -- so a container resized while keeping its
/// mtime is the boundary this rule names and does not pretend to see.
pub fn stale_list_in(m: &super::format::Manifest) -> (usize, Vec<usize>) {
    let root = Path::new(&m.root_path);
    // One path buffer for the whole walk. `root.join(&f.rel_path)` built a
    // fresh PathBuf per record -- 20,000 allocations whose only job was to
    // name a file we are about to stat -- and the manifest stage measured 41
    // ms on a 20,000-record store, which is the wall clock this loop owns.
    // The stat itself is the floor below; this removes the part of the cost
    // that was never about the filesystem.
    let mut p = root.to_path_buf();
    let mut checked = 0usize;
    let mut stale = Vec::new();
    for (i, f) in m.files.iter().enumerate() {
        if f.is_deleted {
            continue;
        }
        checked += 1;
        p.clear();
        p.push(root);
        p.push(&f.rel_path);
        match std::fs::metadata(&p) {
            Ok(md) => {
                if md.len() != f.length || !mtime_matches(&md, f) {
                    stale.push(i);
                }
            }
            Err(_) => match owner_rel(root, &f.rel_path).and_then(|o| {
                p.clear();
                p.push(root);
                p.push(o);
                std::fs::metadata(&p).ok()
            }) {
                Some(md) => {
                    if !mtime_matches(&md, f) {
                        stale.push(i);
                    }
                }
                None => stale.push(i),
            },
        }
    }
    (checked, stale)
}

/// The record's mtime verdict: the modification time its row was signed
/// against, compared to the file's as the OS reports it now. A time the
/// OS will not hand over is not a disagreement.
fn mtime_matches(md: &std::fs::Metadata, f: &super::format::FileRecord) -> bool {
    match md.modified() {
        Ok(t) => match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() == f.mtime_secs && d.subsec_nanos() == f.mtime_nanos,
            Err(_) => true,
        },
        Err(_) => true,
    }
}

/// The owner a member record hangs off: the longest prefix of the record's
/// name, cut at a member separator, that exists on disk (`a.zip!b/c.txt`
/// and `a.zip#b/c.txt` both hang off `a.zip`). A name with no existing
/// prefix belongs to no owner -- its record is gone, not stale.
pub fn owner_rel(root: &Path, rel_path: &str) -> Option<String> {
    let mut owner = None;
    for (p, _) in rel_path.match_indices(super::builder::MEMBER_SEPARATORS) {
        // A prefix of nothing is the root itself, which owns nothing.
        if p == 0 {
            continue;
        }
        if std::fs::metadata(root.join(&rel_path[..p])).is_ok() {
            owner = Some(rel_path[..p].to_string());
        }
    }
    owner
}

/// The plan for a query: which records reach the workers and how the packs
/// are cut for reading. Returns the plan, the 0-byte records, and the number
/// of records the pre-plan filter rejected.
///
/// The pre-plan filter ([`crate::tv::plan::prune_by_ngram`]) is the same
/// rule the workers apply per file, asked once per record before any byte
/// is planned for reading: a rejected record leaves a hole in the plan and
/// [`crate::tv::plan::cut_units`] is what decides the hole is never paid
/// for.
fn raw_decode(
    raw: &Arc<RawManifest>,
    config: &SearchConfig,
) -> io::Result<(PackPlan, Vec<u32>, usize)> {
    let (head, locs) = raw.scan().map_err(super::format::to_io)?;
    let (active, empty) = split_locs(&locs, config);
    let (active, pruned) = crate::tv::plan::prune_by_ngram(
        active,
        &locs,
        config.ngram_query.as_ref(),
        config.extract_fp == Some(head.extract_fp),
    );
    Ok((
        PackPlan::build(Arc::clone(raw), &head, Arc::new(locs), &active),
        empty,
        pruned,
    ))
}

/// Runs a search with no mappings at all: every worker reads its own packs.
///
/// The manifest is read and its head decoded first — a few kilobytes — because
/// that is all a pack reader needs. The 8.7 MB of file records behind the head
/// are decoded on this thread while the workers are already pulling 1.87 GB out
/// of the page cache, so the decode comes out of the read's shadow instead of
/// sitting in front of it. The checksum still gates the answer: `decode`
/// verifies before it returns, and a manifest that fails to verify is an error
/// on this thread before a single match is assembled.
pub(crate) fn search_parallel_buffered(
    store_dir: &Path,
    pattern: &str,
    config: &SearchConfig,
    t0: Instant,
) -> io::Result<(Vec<SearchMatch>, SearchStats)> {
    let engine = Arc::new(Engine::new(pattern, config.engine)?);
    // The planner's copy of the configuration, carrying the query signature
    // the engine derived from the same pattern. Derived at exactly one place
    // so the pre-plan filter and the per-file filters can never stand in
    // different states.
    let mut config = config.clone();
    if config.ngram_query.is_none() {
        config.ngram_query = engine.ngram_query();
    }
    // Which engine a claim answers on. The text rule sets it before the first
    // claim and `Crew::maybe_pick_engine` may move it after one, so it is the
    // query's and not a worker's.
    let inhouse_on = Arc::new(AtomicBool::new(engine.starts_inhouse()));

    let t_manifest = Instant::now();
    let raw = super::format::load_raw_manifest(store_dir)?;
    let head = raw.head().map_err(super::format::to_io)?;
    let head_extract_fp = head.extract_fp;
    let table = PackTable::new(store_dir, &head.packs);
    let manifest_ms = t_manifest.elapsed().as_secs_f64() * 1000.0;
    let mut stages = StageTimes {
        manifest_ms,
        ..Default::default()
    };

    // Decoded before the crew exists, not beside it. A unit ends at a file
    // boundary, so a worker cannot know which bytes to read until the file
    // records are decoded.
    let t_decode = Instant::now();
    let raw = Arc::new(raw);
    let (plan, empty, plan_pruned) =
        raw_decode(&raw, &config).map(|(p, e, n)| (Arc::new(p), e, n))?;
    stages.filter_ms = t_decode.elapsed().as_secs_f64() * 1000.0;

    let n_units = plan.units.len();
    // Asked for, so paid for, and reported whether it is zero: a caller that
    // validated and found nothing is a different statement from a caller that
    // did not look.
    let freshness = if config.validate_freshness {
        Some(stale_files(store_dir)?)
    } else {
        None
    };
    let next_unit = Arc::new(AtomicUsize::new(0));
    // More workers than units buys idle threads, and on a store with fewer units
    // than workers it buys workers that never claim anything.
    let cap = config.threads.max(1).min(n_units.max(1));
    // `start_threads` is the width somebody asked for and never widens;
    // `None` is the bandwidth optimum, which the workers may open up to
    // `cap` once a unit says the scan is the expensive half. See `Crew`.
    let start = config
        .start_threads
        .unwrap_or_else(default_threads)
        .max(1)
        .min(cap);
    let mut num_threads = start;

    let crew = Arc::new(Crew::new(
        num_threads,
        if config.widen { cap } else { num_threads },
        Arc::clone(&inhouse_on),
    ));
    let cfg = Arc::new(config.clone());
    let mut handles: Vec<std::thread::JoinHandle<io::Result<WorkerOut>>> = Vec::new();
    let t_work = Instant::now();
    for _ in 0..num_threads {
        handles.push(std::thread::spawn({
            let table = table.clone();
            let plan = Arc::clone(&plan);
            let next = Arc::clone(&next_unit);
            let e_clone = Arc::clone(&engine);
            let cfg = Arc::clone(&cfg);
            let crew = Arc::clone(&crew);
            let inhouse_on = Arc::clone(&inhouse_on);
            move || {
                pack_worker(
                    table,
                    plan,
                    next,
                    e_clone,
                    cfg,
                    crew,
                    inhouse_on,
                    head_extract_fp,
                )
            }
        }));
    }

    // `bounds` has one slot per pack plus its end, so this is the pack count
    // without reaching back into the manifest head.
    let total_packs = plan.bounds.len().saturating_sub(1);
    // `head` and `decode` walk the same immutable pack table, so the two views
    // of it have to agree on how many packs there are.
    debug_assert_eq!(plan.bounds.len(), table.len.len() + 1);
    let mut buckets = Vec::with_capacity(n_units);
    let mut read_ns = 0u128;
    let mut scan_ns = 0u128;
    let mut bytes_read = 0u64;
    let mut units_read = 0u64;
    let mut n_searched = 0usize;
    // The pre-plan filter's rejects join the per-file filters' in one count:
    // they are the same rule asked at two points, and a caller reading
    // `total_files_pruned` must not care which point answered.
    let mut n_pruned = plan_pruned;
    let mut n_matched = 0usize;
    let mut n_lines = 0usize;
    let mut service_ns: Vec<u64> = Vec::with_capacity(n_units);
    // Join every worker before propagating a failure. One unreadable pack is a
    // failed query, never a partial answer. The second drain is the workers
    // the query opened for itself: they claim from the same counter as the
    // ones it started with, so there is nothing to order and nothing to
    // wait for.
    let mut first_err: Option<io::Error> = None;
    let mut reaped = |h: std::thread::JoinHandle<io::Result<WorkerOut>>| match h.join() {
        Ok(Ok(mut out)) => {
            buckets.append(&mut out.buckets);
            read_ns += out.read_ns;
            scan_ns += out.scan_ns;
            bytes_read += out.bytes_read;
            units_read += out.units_read;
            n_searched += out.searched;
            n_pruned += out.pruned;
            n_matched += out.matched;
            n_lines += out.lines;
            service_ns.extend_from_slice(&out.service_ns);
        }
        Ok(Err(e)) => {
            if first_err.is_none() {
                first_err = Some(e);
            }
        }
        Err(_) => {
            if first_err.is_none() {
                first_err = Some(io::Error::other("a pack reader thread panicked"));
            }
        }
    };
    for h in handles {
        reaped(h);
    }
    for h in crew.take_extra() {
        num_threads += 1;
        reaped(h);
    }
    if let Some(e) = first_err {
        return Err(e);
    }

    let total_lines = n_lines;
    let mut final_matches = merge_buckets(buckets, total_lines);

    // 0-byte files never reach a pack read; the matcher sees an empty slice.
    if !empty.is_empty() {
        let hybrid = match &*engine {
            Engine::Hybrid { byte, delegate, .. } => {
                HybridMatcher::new(byte.as_ref(), ByteDelegate(delegate.as_ref()))
            }
        };
        let s =
            rgxsearcher::Searcher::with_candidates(&hybrid, &hybrid, inhouse_config_for(&config));
        for &ei in empty.iter() {
            let f = plan.locs[ei as usize];
            n_searched += 1;
            let mut count = 0usize;
            let mut mine = Vec::new();
            let mut collector = MatchCollector {
                name: Name::Undecoded {
                    raw: &plan.raw,
                    loc: f,
                },
                path: None,
                matches: &mut mine,
                count: &mut count,
                count_only: config.count_only,
            };
            let _ = s.search_slice(&[], &mut collector);
            if count > 0 {
                n_matched += 1;
                n_lines += count;
                final_matches.append(&mut mine);
            }
        }
    }

    stages.work_ms = t_work.elapsed().as_secs_f64() * 1000.0;
    stages.read_cpu_ms = read_ns as f64 / 1e6;
    stages.scan_cpu_ms = scan_ns as f64 / 1e6;
    stages.in_process_ms = t0.elapsed().as_secs_f64() * 1000.0;

    // A store whose packs vary a lot in service time and whose pack count is
    // only a few per thread will not balance.
    service_ns.sort_unstable();
    let at = |q: f64| -> f64 {
        if service_ns.is_empty() {
            return 0.0;
        }
        let i = ((service_ns.len() - 1) as f64 * q).round() as usize;
        service_ns[i] as f64 / 1e6
    };
    let total_service_ms: f64 = service_ns.iter().sum::<u64>() as f64 / 1e6;
    stages.pack_service_p50_ms = at(0.50);
    stages.pack_service_p99_ms = at(0.99);
    stages.pack_service_max_ms = at(1.0);
    stages.balance = if stages.work_ms > 0.0 && num_threads > 0 {
        total_service_ms / (num_threads as f64 * stages.work_ms)
    } else {
        0.0
    };

    // The sparse plan's own account, asked for by name: how much of the
    // store the query actually fetched. Under `RGX_ABLATE_EXTENTS` these
    // are the whole payload, which is exactly the A/B's control arm.
    if std::env::var_os("RGX_EXTENT_STATS").is_some() {
        let payload: u64 = head.packs.iter().map(|p| p.content_len).sum();
        eprintln!(
            "rgx-extents: read {} bytes in {} units (store payload {} bytes, {} packs)",
            bytes_read, units_read, payload, total_packs
        );
    }

    Ok((
        final_matches,
        SearchStats {
            total_packs_scanned: total_packs,
            total_files_searched: n_searched,
            total_files_pruned: n_pruned,
            total_files_matched: n_matched,
            total_lines_matched: n_lines,
            elapsed_ms: stages.work_ms,
            pooled: false,
            workers: num_threads,
            stale_files: freshness,
            engine: "rgx",
            stages,
        },
    ))
}

// ---------------------------------------------------------------------------
// Public entry points.
// ---------------------------------------------------------------------------

/// Executes a search across all packs in `store_dir`.
///
/// Which arm runs is [`SearchConfig::read_mode`]. [`ReadMode::Mmap`] and
/// [`ReadMode::Buffered`] open or read every pack here in the coordinator and
/// — unless `config.unmap` says otherwise — release all of them before
/// returning; [`ReadMode::ParallelBuffered`] opens no pack here at all.
pub fn search_store(
    store_dir: &Path,
    pattern: &str,
    config: &SearchConfig,
) -> io::Result<(Vec<SearchMatch>, SearchStats)> {
    let t0 = Instant::now();

    let t_manifest = Instant::now();
    let manifest = Arc::new(super::format::load_manifest(store_dir)?);
    let manifest_ms = t_manifest.elapsed().as_secs_f64() * 1000.0;

    if config.read_mode == ReadMode::ParallelBuffered {
        return search_parallel_buffered(store_dir, pattern, config, t0);
    }

    let engine = Arc::new(Engine::new(pattern, config.engine)?);

    // Pre-map or pre-read all packs once so OS handles and mmaps are shared across threads
    let t_map = Instant::now();
    let mut pack_storage_map: OwnedPackMap = HashMap::new();

    for pack_rec in &manifest.packs {
        let pack_path = store_dir.join(&pack_rec.filename);
        if config.read_mode == ReadMode::Mmap {
            let f = File::open(&pack_path)?;
            let m = unsafe { Mmap::map(&f)? };
            pack_storage_map.insert(pack_rec.pack_id, PackStorage::Mmap(Arc::new(m)));
        } else {
            let mut f = File::open(&pack_path)?;
            f.seek(SeekFrom::Start(PackHeader::SIZE as u64))?;
            let mut buf = vec![0u8; pack_rec.content_len as usize];
            f.read_exact(&mut buf)?;
            pack_storage_map.insert(pack_rec.pack_id, PackStorage::Buffered(Arc::new(buf)));
        }
    }
    let map_ms = t_map.elapsed().as_secs_f64() * 1000.0;

    let total_packs = manifest.packs.len();
    let head_extract_fp = manifest.extract_fp;
    let t_filter = Instant::now();
    let (active, empty) = split_owned(Arc::try_unwrap(manifest).unwrap().files, config);
    let (active_files, empty_files) = (OwnedFiles(active), OwnedFiles(empty));
    let filter_ms = t_filter.elapsed().as_secs_f64() * 1000.0;

    let mut stages = StageTimes {
        manifest_ms,
        filter_ms,
        map_ms,
        ..Default::default()
    };

    let (matches, mut stats, packs) = run_search::<OwnedFiles>(
        total_packs,
        PackIndex::Owned(pack_storage_map),
        active_files,
        empty_files,
        Arc::clone(&engine),
        config,
        head_extract_fp,
        t0,
        &mut stages,
    )?;
    stats.pooled = false;

    // Unmapping many packs is serial and is the largest stage of a single-shot
    // query. `Leak` skips it and lets process exit do it instead.
    let t_unmap = Instant::now();
    match config.unmap {
        Unmap::Explicit => drop(packs),
        Unmap::Leak => std::mem::forget(packs),
    }
    stages.teardown_ms = t_unmap.elapsed().as_secs_f64() * 1000.0;
    stats.stages = stages;
    stats.stages.in_process_ms = t0.elapsed().as_secs_f64() * 1000.0;

    Ok((matches, stats))
}

/// Executes a search through a `MappedStore`'s already-open packs.
///
/// The manifest, the filtered file indexes and the mappings all come from the
/// pool, so a process that searches the same store repeatedly pays the mapping
/// once. Falls back to [`search_store`] when the pool is disabled, which is how
/// the `--no-pool` axis stays independent of the read-mode one.
///
/// A pooled query that asks for a read mode other than [`ReadMode::Mmap`]
/// still takes the pooled manifest — it is parsed either way — and then
/// runs `search_parallel_buffered` against the store directory, because the
/// pool holds exactly the thing that read mode was chosen to avoid.
pub fn search_store_pooled(
    store: &MappedStore,
    pattern: &str,
    config: &SearchConfig,
) -> io::Result<(Vec<SearchMatch>, SearchStats)> {
    if !store.enabled() {
        return search_store(store.dir(), pattern, config);
    }

    let t0 = Instant::now();
    let t_snap = Instant::now();
    let snap = store.snapshot()?;
    let manifest_ms = t_snap.elapsed().as_secs_f64() * 1000.0;

    if config.read_mode != ReadMode::Mmap {
        // A pool warmed for mappings has nothing to lend a query that asked for
        // buffered reads, so this goes back to the store directory and does the
        // whole job itself rather than half of it.
        return search_store(store.dir(), pattern, config);
    }

    let engine = Arc::new(Engine::new(pattern, config.engine)?);

    // A pack store is searched whole or not at all: if the pool's byte ceiling
    // left packs unmapped, this query opens those itself and gives them back.
    // Results are always complete; only the savings shrink.
    let packs = if snap.complete {
        PackIndex::Pooled(Arc::clone(&snap.packs))
    } else {
        let mut cold: OwnedPackMap = HashMap::new();
        for id in snap.cold_packs() {
            let Some(rec) = snap.manifest.packs.iter().find(|p| p.pack_id == id) else {
                continue;
            };
            let f = File::open(store.dir().join(&rec.filename))?;
            cold.insert(id, PackStorage::Mmap(Arc::new(unsafe { Mmap::map(&f)? })));
        }
        PackIndex::Hybrid {
            warm: Arc::clone(&snap.packs),
            cold,
        }
    };

    // The pool's cached index answers "not deleted, not binary under the limits
    // the pool was opened with". A query is allowed to ask for a different file
    // set -- `-M` narrows it, and the narrowing is per query, so a pool opened
    // once with no `-M` still honours a query that brings one. Filtering indices
    // rather than records means the manifest is not walked twice.
    let active = narrow(&snap.active, &snap.manifest, config);
    let empty = narrow(&snap.empty, &snap.manifest, config);

    let total_packs = snap.manifest.packs.len();
    let mut stages = StageTimes {
        manifest_ms,
        ..Default::default()
    };
    let (matches, mut stats, _packs) = run_search::<IndexedFiles>(
        total_packs,
        packs,
        IndexedFiles {
            manifest: Arc::clone(&snap.manifest),
            idx: Arc::new(active),
        },
        IndexedFiles {
            manifest: Arc::clone(&snap.manifest),
            idx: Arc::new(empty),
        },
        Arc::clone(&engine),
        config,
        snap.manifest.extract_fp,
        t0,
        &mut stages,
    )?;
    // Dropping the pool's clones is a refcount decrement. The mappings the pool
    // holds stay; any it did not hold were opened here and are unmapped here.
    stats.pooled = true;
    stats.stages.in_process_ms = t0.elapsed().as_secs_f64() * 1000.0;
    Ok((matches, stats))
}

// ---------------------------------------------------------------------------
// The sparse plan's end-to-end contract.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod sparse_tests {
    use super::*;
    use crate::tv_runtime::builder::{build_store, BuildConfig};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rgx-sparse-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The ablation changes the plan and never the answer: same matches and
    /// same prunes -- the pre-plan and the per-file filters are one rule
    /// asked twice, so where it fired changes only what was read.
    #[test]
    fn the_extent_ablation_changes_the_plan_and_never_the_answer() {
        let root = scratch("ablate");
        let store = root.join("store");
        std::fs::write(root.join("a.txt"), b"needle one\n").unwrap();
        std::fs::write(root.join("b.txt"), b"nothing to see here\n").unwrap();
        std::fs::write(root.join("c.txt"), b"needle two\n").unwrap();
        build_store(&root, &store, &BuildConfig::default()).unwrap();

        let cfg = SearchConfig::default();
        let (m1, s1) = search_store(&store, "needle", &cfg).unwrap();
        assert!(
            s1.total_files_pruned >= 1,
            "the fixture must give the filter something to prune or the \
             comparison means nothing (pruned {})",
            s1.total_files_pruned
        );

        let _guard = crate::ABLATE_EXTENTS_LOCK.lock().unwrap();
        crate::set_ablate_extents(true);
        let (m2, s2) = search_store(&store, "needle", &cfg).unwrap();
        crate::set_ablate_extents(false);

        assert_eq!(m1, m2, "the ablation may change cost, never answers");
        assert_eq!(
            s1.total_files_pruned, s2.total_files_pruned,
            "the same files are answered without reading either way"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
