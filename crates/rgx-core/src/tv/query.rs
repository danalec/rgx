// SPDX-License-Identifier: Apache-2.0

//! The vocabulary of one pack query: which engine, where the bytes come from,
//! what a hit looks like.
//!
//! Everything here is a decision about the *question*, made before any byte is
//! read, which is why it can live in a `no_std` crate: the answers that need a
//! filesystem or a clock — how many threads to start, where a pack file is —
//! are `rgx-tv`'s to give.

use alloc::string::String;
use alloc::vec::Vec;

/// What to do with the pack mappings when the search finishes.
///
/// On Windows each mapping is torn down by `UnmapViewOfFile`, and for 117 packs
/// over 1.87 GB that teardown is serial and large. Neither says anything
/// about [`ReadMode::ParallelBuffered`], which creates no mappings to leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Unmap {
    /// Drop every mapping before returning. The current, always-safe behaviour.
    #[default]
    Explicit,
    /// Never drop them; the OS reclaims them when the process exits. One-shot
    /// CLIs only: every query leaks a full set of mappings.
    Leak,
}

/// Where a search gets its bytes.
///
/// The unit of parallelism differs: the first two hand out file chunks,
/// the third hands out packs. A pack is the natural unit of I/O, but it
/// is a coarse one — see [`SearchConfig::packs_per_thread`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadMode {
    /// The coordinator opens and maps every pack; the workers search mappings.
    Mmap,
    /// The coordinator reads every pack into RAM itself, serially, then the
    /// workers search RAM. The `--no-mmap` behaviour this crate shipped with.
    Buffered,
    /// Each worker claims a whole pack and reads it into a buffer it reuses for
    /// the rest of the query. The coordinator reads no pack bytes at all.
    ParallelBuffered,
}

impl Default for ReadMode {
    /// The default: maps nothing, so no `UnmapViewOfFile` teardown to pay,
    /// and reads the packs on the same threads that then search them.
    fn default() -> Self {
        ReadMode::ParallelBuffered
    }
}

/// Which engine a query runs.
///
/// The in-house engine is the only path now that `grep-searcher` /
/// `grep-regex` / `grep-matcher` are out of the build. The enum is left with
/// `Auto` and `Rgx` because the public type is reachable from a CLI string
/// (`--engine auto` / `--engine rgx`) and from any caller that built
/// configuration against the old shape: every `EngineMode` value answers
/// `Rgx` in the runtime that compiles, and the `Auto` default routes through
/// `Engine::new` to the same place. A future session that re-introduces a
/// second engine will resurrect the variants here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EngineMode {
    /// The default, the in-house engine where the pattern compiles.
    #[default]
    Auto,
    /// The in-house byte engine.
    Rgx,
}

impl EngineMode {
    /// The engine a pattern of this shape should run on.
    ///
    /// **The rule is one answer now**: the in-house engine, where the pattern
    /// is in its subset. The sweep that separated the two on the registry
    /// store (`scripts/engine-sweep.sh`) is the same evidence that
    /// motivated dropping the `Grep` arm; with no other engine to defer to,
    /// the rule collapses to a single return.
    pub fn pick(_pattern: &str) -> EngineMode {
        EngineMode::Rgx
    }
}

/// Whether the pattern is pinned to a line boundary: `^` in front, `$`
/// behind, and neither one escaped or sitting inside a character class.
pub fn line_anchored(pattern: &str) -> bool {
    const BACKSLASH: u8 = b'\\';
    let b = pattern.as_bytes();
    if b.first() == Some(&b'^') {
        return true;
    }
    if b.last() != Some(&b'$') || b.len() < 2 {
        return false;
    }
    // An odd run of backslashes before the `$` escapes it; an even run is
    // escaped backslashes, and the `$` still anchors. Testing only the one
    // byte before the `$` read `\\$` — an escaped backslash, real anchor —
    // as an escaped anchor.
    let mut run = 0;
    let mut i = b.len() - 1;
    while i > 0 && b[i - 1] == BACKSLASH {
        run += 1;
        i -= 1;
    }
    if run % 2 == 1 {
        return false;
    }
    let mut in_class = false;
    let mut i = 0;
    while i < b.len() - 1 {
        match b[i] {
            BACKSLASH => i += 1,
            b'[' => in_class = true,
            b']' => in_class = false,
            _ => {}
        }
        i += 1;
    }
    !in_class
}

#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// The most workers this query may run. `-j` sets it, and `-j` also pins
    /// the start, so an explicit request is a ceiling and never a starting hint.
    pub threads: usize,
    /// The workers to start with. `None` starts at the width a bandwidth-bound
    /// query wants; `rgx-tv` decides what that is, because it owns the machine.
    pub start_threads: Option<usize>,
    /// Whether the query may open itself up to [`SearchConfig::threads`] when
    /// its own per-pack timings say the scan, rather than the copies, is the
    /// expensive half. `-j` turns this off, because a person who typed a number
    /// meant it.
    pub widen: bool,
    pub read_mode: ReadMode,
    /// How many packs a worker claims per [`ReadMode::ParallelBuffered`] claim.
    /// One is the best balance when packs are unevenly sized; larger values
    /// only help when the claim syscall itself is measurable, which it is not.
    pub packs_per_thread: usize,
    pub line_numbers: bool,
    pub count_only: bool,
    pub before_context: usize,
    pub after_context: usize,
    /// Which engine runs the pattern. `Rgx` uses the in-house byte engine
    /// where the pattern is in its subset.
    pub engine: EngineMode,
    /// Buffer the in-house engine searches in. `None` picks one from the
    /// store's file sizes.
    pub buffer_capacity: Option<usize>,
    /// Stat every file the manifest claims and report the ones the filesystem
    /// disagrees about. Off by default: it is a syscall per file, and the
    /// store's whole claim is that a query does not pay it.
    pub validate_freshness: bool,
    pub search_binary: bool,
    /// `-M` / `--max-filesize`. `None` is ripgrep's default. The direct path
    /// asks the filesystem the size of a file it is about to open; here the
    /// manifest already carries it, so the same question costs a comparison
    /// against a `u64` per record and reads nothing.
    pub max_file_size: Option<u64>,
    pub unmap: Unmap,
    /// The extraction fingerprint of the pipeline this query would run over
    /// a claimed file, as the build computed it into
    /// [`ManifestHead::extract_fp`](crate::tv::format::ManifestHead::extract_fp).
    /// `Some(fp)` lets the n-gram filter reject records flagged
    /// [`FileLoc::SIG_COVERS_ADAPTER`](crate::tv::format::FileLoc::SIG_COVERS_ADAPTER)
    /// only while `fp` equals the store head's; `None` says the caller
    /// states no extraction context and every rollup record stands unfiltered.
    /// A search over the records' own bytes is covered by either signature
    /// this format writes and may pass anything; this field exists so the
    /// one rule serves every search that may see adapter output.
    pub extract_fp: Option<u64>,
    /// The query's n-gram signature, from the literal every match must
    /// contain (see [`crate::ngram::query_sig512`]). The planner reads it to
    /// reject records before their bytes are planned for reading;
    /// `None` stands the filter down and is the only value a caller must
    /// never read as "nothing matches". The search entry points derive it
    /// from the pattern alongside the engine, so a caller that sets nothing
    /// gets today's behaviour and a plan that reads everything.
    pub ngram_query: Option<crate::ngram::NgramSig512>,
}

/// One hit, as the pack reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMatch {
    pub path: String,
    pub line_number: Option<u64>,
    pub line: Vec<u8>,
}

// `Default` for `SearchConfig` asks the machine how wide it is, which
// needs `std`. Without `std` the struct still exists and every field can
// still be set by hand.
#[cfg(feature = "std")]
impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            threads: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            start_threads: None,
            widen: true,
            read_mode: ReadMode::default(),
            packs_per_thread: 1,
            line_numbers: true,
            count_only: false,
            before_context: 0,
            after_context: 0,
            engine: EngineMode::default(),
            buffer_capacity: None,
            validate_freshness: false,
            search_binary: false,
            max_file_size: None,
            unmap: Unmap::Explicit,
            extract_fp: None,
            ngram_query: None,
        }
    }
}
