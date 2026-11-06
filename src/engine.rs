// SPDX-License-Identifier: Apache-2.0

//! A `grep-searcher`-shaped face on the in-house searcher.
//!
//! The binary was written against `grep-searcher` — the matcher is handed to
//! every call, the searcher is built once, and a sink's methods take the
//! searcher as their first argument. This module keeps that call shape
//! (`search_slice(matcher, hay, sink)`) and swaps only the engine underneath.
//!
//! **There is no second engine.** `grep-searcher` and `grep-regex` were removed
//! as dependencies and `Mode` below has one variant. What survives of the
//! two-engine design is a shape: [`HybridMatcher`] still takes a byte matcher
//! and a [`UnicodeMatcher`] delegate, and the delegate wraps the same
//! `ByteRegex`. Both arms are the byte engine.
//!
//! **Case folding is resolved at parse time.** `(?i)` turns each character
//! into the byte alternation of its whole simple case-folding class, mixed
//! UTF-8 widths included: `-i kelvin` reaches U+212A KELVIN SIGN and
//! `(?i)ß` reaches `ẞ`. What stays outside the fold is stated in
//! `unicode_case.rs`: full multi-character mappings (`ß` ≠ `SS`) and the
//! conditional final-sigma rule; a mixed character class (`[é]`) still
//! over-matches. `fold_risky` routes the caseless non-ASCII lines to the
//! delegate, which is where a real Unicode matcher goes.
//!
//! **No divergence claim can be made from here.** The claims this header used
//! to make — POSIX classes agreeing byte for byte, `^`/`$` anchoring the line —
//! were all stated against `grep-searcher`, and nothing is left to check them
//! against. `searcher/oracle.rs` compares against the `regex` crate instead.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use rgx_core::hybrid::{HybridMatcher, UnicodeMatcher};
use rgx_core::regex::ByteRegex;
use rgx_core::searcher::{Config, LineBuffer, Searcher as RgxSearcher, Sink as RgxSink};

/// K10 (memory-mapped file access). Declared from here rather than from the
/// crate root because `main.rs` is not this module's to edit, and the module
/// has exactly one caller.
#[path = "mmap.rs"]
pub(crate) mod mmap;

/// Where a file's bytes come from, once the mapping decision is made.
///
/// Both arms are read the same way -- `Read` into the searcher's 64 KiB
/// buffer -- so the choice is invisible to everything downstream, which is the
/// property that makes the fallback safe to leave in.
enum FileSource {
    Mapped(mmap::MappedFile),
    Read(std::fs::File),
}

impl FileSource {
    /// Decide how to read a file the caller has **already opened**, and how
    /// long it is.
    ///
    /// Takes the caller's `File` rather than a path: `raw_search` in
    /// `src/main.rs` has already opened the file with
    /// `FILE_FLAG_SEQUENTIAL_SCAN` and already holds its length, so opening a
    /// second handle here cost a redundant `stat` plus a `CreateFileW` without
    /// the hint, and dropped the first handle unread — `open` plus `close`
    /// measures 26.6 us on this machine.
    ///
    /// Mapping is behind `RGX_MMAP` because it measured slower on this
    /// platform (`src/mmap.rs::enabled_by_env` has the numbers), so the plain
    /// read is the default arm and mapping is the experiment.
    ///
    /// A mapping that fails for any reason — not a regular file, a file being
    /// rewritten, an exhausted address space — is not an event the user hears
    /// about: it becomes the ordinary read, reusing the same handle.
    fn new(file: std::fs::File, len: u64) -> Self {
        // **Rewind, always.** `search_path` reads from the handle's CURRENT
        // position, and the caller may already have read part of the file —
        // the binary-detection branch sniffs up to `SNIFF` (64 KiB) off the
        // front before deciding the file is not binary, then hands the same
        // handle here. Taking the caller's handle removed the free zero-start
        // an own-handle open gave, and a walked file between
        // `BUFFER_PATH_MAX` (16 MiB) and the mmap threshold (64 MiB) silently
        // lost its first 64 KiB to the searcher.
        //
        // Done here rather than at the call sites: it is a precondition of
        // `search_path` ("scans the whole file from its start"), and the mmap
        // arm needs it just as much.
        use std::io::Seek;
        let mut file = file;
        if file.seek(std::io::SeekFrom::Start(0)).is_err() {
            // A handle that cannot rewind is not usable for a whole-file scan;
            // the caller falls back rather than searching from wherever it was.
            return FileSource::Read(file);
        }
        if mmap::should_map(len) {
            if let Ok(m) = mmap::map_open_file(&file) {
                return FileSource::Mapped(m);
            }
        }
        FileSource::Read(file)
    }
}

/// Re-exported so `main.rs` builds its config without naming `rgx_core`.
pub use rgx_core::searcher::BinaryDetection as RgxBinaryDetection;

/// A `ByteRegex` seen as the delegate the hybrid hands a line to.
///
/// With `grep-regex` and `grep-searcher` gone, the Unicode
/// delegate is the in-house byte engine itself. The byte engine
/// answers every line the same way (bytes are bytes), and the
/// hybrid that drives the in-house searcher can pass every line
/// through the same matcher. The case-insensitive non-ASCII edge is closed
/// at parse time: `crates/rgx-core/src/unicode_case.rs` lowers each
/// character to the byte alternation of its whole case class, so
/// `/kelvin/i` matches U+212A KELVIN SIGN and `/(?i)ß/` matches `ẞ`.
/// The checks are in the tree now, not in a deleted suite:
/// `case_folding_reaches_every_width_the_oracle_does` in
/// `crates/rgx-core/src/regex.rs` compares against the `regex` crate.
struct ByteDelegate<'a>(&'a ByteRegex);

impl UnicodeMatcher for ByteDelegate<'_> {
    fn find_span(&self, line: &[u8], at: usize) -> Option<std::ops::Range<usize>> {
        use rgx_core::regex::Matcher as _;
        self.0.find_at(line, at).map(|i| i..i)
    }
}

/// Which engine to run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// The in-house engine — the only one there is.
    ///
    /// There used to be `Grep` and `Both` here. Both are gone with the
    /// `grep-*` dependencies, and **nothing was kept to parse the old names**:
    /// `--engine grep` is rejected by the CLI's value validation, and
    /// `RGX_ENGINE=grep` reaches `from_env`, which now says so on stderr and
    /// carries on. See the module header.
    Rgx,
}

impl Mode {
    /// Read `RGX_ENGINE`.
    ///
    /// **Only `rgx` is recognised, and it is recognised purely for the
    /// `RGX_RUNS` tally** it flips on the way out — `Mode::Rgx` is returned
    /// either way, so this cannot change which engine runs.
    ///
    /// The names that used to mean something are now said out loud instead of
    /// swallowed. `grep` and `both` named engines that were removed with the
    /// `grep-*` dependencies; `--engine grep` fails argument validation at the
    /// CLI, and this used to accept the same word and do nothing. That is the
    /// worst of the three outcomes: a user who set `RGX_ENGINE=grep` as an
    /// escape hatch has been running the in-house engine and finding it fast,
    /// which is the strongest possible reason to keep believing the variable
    /// works. So the names are recognised *as retired* and reported, and the
    /// run continues — an ambient variable should not be able to fail a search
    /// that would otherwise have succeeded.
    pub fn from_env() -> Mode {
        let var = std::env::var("RGX_ENGINE");
        if matches!(var.as_deref(), Ok("rgx")) {
            // Someone asked for this engine by name, so the tally on
            // the way out is a line they want to read.
            stats::EXPLICIT.store(true, Ordering::Relaxed);
        }
        match var.as_deref() {
            // `tv` and `tesla` are not retired: the detector honours
            // `RGX_ENGINE=tv` as a live pack-store selection, and warning
            // "no longer exists" while selecting it is a contradiction.
            // Only `grep` and `both` are gone.
            Ok("grep") | Ok("both") => {
                // Once per process: `from_env` is called from more than one
                // searcher-construction site (the raw and the convert path),
                // and a warning that arrives twice reads as two problems.
                static SAID: AtomicBool = AtomicBool::new(false);
                if !SAID.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "rgx: RGX_ENGINE={} names an engine that no longer exists; \
                         the in-house engine is the only one. \
                         Use --engine tv for the pack store.",
                        var.as_deref().unwrap_or_default()
                    );
                }
            }
            _ => {}
        }
        Mode::Rgx
    }
}

/// Counters for what the in-house `Rgx` engine actually managed.
///
/// Process-global, not per-searcher: the raw path builds one searcher per
/// worker thread, so per-instance counters would need aggregating back up and
/// would lose most of the walk. A walk over a real corpus is the measurement
/// these exist for, so the numbers have to survive to the end of it.
pub mod stats {
    use super::{AtomicBool, Ordering};
    use std::sync::atomic::AtomicU64;

    /// Searches the in-house engine ran.
    pub static RGX_RUNS: AtomicU64 = AtomicU64::new(0);
    /// Times the pattern was outside the subset and `grep` was used instead.
    pub static FALLBACKS: AtomicU64 = AtomicU64::new(0);
    /// Divergences `Both` found. Unused after the grep-*
    /// dep removal; `#[allow(dead_code)]` keeps the public surface
    /// for the bench transcript line in `stats::report`.
    #[allow(dead_code)]
    pub static DIVERGENCES: AtomicU64 = AtomicU64::new(0);
    /// True when somebody named the engine in `RGX_ENGINE`.
    ///
    /// The in-house engine is the default, so the tally would otherwise print
    /// a line on every search, and a tool that speaks on stderr when nobody
    /// asked is a tool whose stderr nobody reads. Setting `RGX_ENGINE=rgx` is
    /// the opt-in: it asks for this engine explicitly, and the numbers about
    /// it are the reason to ask.
    pub static EXPLICIT: AtomicBool = AtomicBool::new(false);

    /// Print the tally, if this run used the in-house engine at all.
    pub fn report() {
        if !EXPLICIT.load(Ordering::Relaxed) {
            return;
        }
        let runs = RGX_RUNS.load(Ordering::Relaxed);
        let fallbacks = FALLBACKS.load(Ordering::Relaxed);
        if runs == 0 && fallbacks == 0 {
            return;
        }
        eprintln!(
            "rgx engine: {runs} in-house searches, {fallbacks} pattern(s) the in-house refused",
        );
    }
}

/// The searcher the binary drives.
pub struct Searcher {
    config: Config,
    /// Pre-built in-house searcher, valid for the lifetime of `byte`.
    ///
    /// Field order matters: Rust drops struct fields in declaration order, so
    /// `searcher` and `hybrid` are dropped *before* `byte`. Both borrow from
    /// `byte` via the `unsafe` transmute in `new`, and the drop ordering is
    /// the invariant that keeps those borrows valid until last use.
    searcher: Option<RgxSearcher<'static>>,
    /// Pre-built hybrid matcher. Boxed so its internal `&ByteRegex` borrow
    /// has a stable heap address. See `searcher` above on drop ordering.
    /// Kept as a field (not just a local) so the allocation is owned by this
    /// `Searcher` and dropped before `byte`. `RgxSearcher` holds the same
    /// pointer through its `&dyn Matcher` so the live borrow tracks the same
    /// allocation.
    #[allow(dead_code)]
    hybrid: Option<Box<HybridMatcher<'static, ByteDelegate<'static>>>>,
    /// The in-house engine's compiled pattern, when the subset allows it.
    ///
    /// Behind an Arc because the call shape this module keeps needs
    /// `&mut self` for every call while the in-house searcher borrows its
    /// matcher: an owned handle
    /// lets both be live at once. It is borrowed rather than cloned into each
    /// [`HybridMatcher`], so building one per file does not recompile the
    /// pattern. Declared last so it is dropped last.
    #[allow(dead_code)]
    byte: Option<std::sync::Arc<ByteRegex>>,
    scratch: rgx_core::searcher::Scratch,
    offsets: Vec<usize>,
}

impl Searcher {
    /// Build from the settings `make_searcher` used to hand to
    /// `SearcherBuilder`. `byte` is the in-house matcher, or `None` when the
    /// pattern is outside its subset.
    ///
    /// **`byte` is an `Arc`, not an owned `ByteRegex`, so that every searcher
    /// in the process can be handed the one compiled instance.**
    /// `src/main.rs::compiled_byte_arc` already memoises `(pattern,
    /// ignore_case) -> Arc<ByteRegex>` for the whole process; the three
    /// searchers a worker builds (`make_searcher` plus `RawState`'s
    /// `text_searcher` and `convert_searcher`) each used to call
    /// `build_byte_regex` directly, which is a full NFA→DFA build plus its
    /// VM tables. At `-j32` that was 96 uncached compiles of one pattern.
    /// Three *shares* cost one compile.
    pub fn new(config: Config, byte: Option<std::sync::Arc<ByteRegex>>, _mode: Mode) -> Searcher {
        let (searcher, hybrid) = match byte.as_ref() {
            Some(re) => {
                // SAFETY: `hybrid` and `searcher` borrow `re: &ByteRegex`
                // for `'static`, but `re` lives in this `Searcher` and the
                // field declaration order (`searcher`/`hybrid` before `byte`)
                // drops the borrows *before* the `Arc<ByteRegex>` is
                // decremented. The borrow is valid for the entire lifetime of
                // the `Searcher`. The Box is leaked to give the borrowed
                // references a stable `'static` address; the `Searcher` owns
                // it via the `Box` slot so the leak is bounded to the
                // `Searcher`'s lifetime.
                let re_static: &'static ByteRegex = unsafe { std::mem::transmute(re.as_ref()) };
                let hybrid: Box<HybridMatcher<'static, ByteDelegate<'static>>> =
                    Box::new(HybridMatcher::new(re_static, ByteDelegate(re_static)));
                // `Box::leak` re-borrows the Box as `&'static`, then we
                // immediately convert it to a raw pointer for use in
                // `with_candidates` so the `&'m dyn Matcher` parameter can
                // be `'static`. The pointer is converted back to `&*hybrid`
                // on every search call, and the Box lives in this struct's
                // field for the entire `Searcher` lifetime.
                let hybrid_static: &'static HybridMatcher<'static, ByteDelegate<'static>> =
                    Box::leak(hybrid);
                let searcher =
                    RgxSearcher::with_candidates(hybrid_static, hybrid_static, config.clone());
                // We must rebuild the Box from the leaked pointer so the
                // struct owns the allocation and drops it. `Box::from_raw`
                // reclaims ownership at the same address.
                let hybrid: Box<HybridMatcher<'static, ByteDelegate<'static>>> =
                    unsafe { Box::from_raw(hybrid_static as *const _ as *mut _) };
                (Some(searcher), Some(hybrid))
            }
            None => (None, None),
        };
        Searcher {
            config,
            searcher,
            hybrid,
            byte,
            scratch: rgx_core::searcher::Scratch::new(),
            offsets: Vec::new(),
        }
    }

    /// Which binary-byte rule this searcher applies, so a caller that picks
    /// between two searchers can be held to the choice it made.
    #[cfg(test)]
    pub fn binary_detection(&self) -> RgxBinaryDetection {
        self.config.binary
    }

    /// Search an in-memory buffer. Same signature the call sites already use.
    pub fn search_slice<S>(&mut self, hay: &[u8], sink: &mut S) -> Result<bool, io::Error>
    where
        S: RgxSink<Error = io::Error>,
    {
        let Some(engine) = self.searcher.as_mut() else {
            return self.fallback();
        };
        if stats::EXPLICIT.load(Ordering::Relaxed) {
            stats::RGX_RUNS.fetch_add(1, Ordering::Relaxed);
        }
        // The delegate is now the in-house byte regex itself, not a
        // separate Unicode matcher. See `ByteDelegate` for the
        // trade-off (case-insensitive non-ASCII lines are
        // byte-matched, which can miss Unicode folding).
        engine.search_slice_with_scratch(hay, sink, &mut self.scratch, &mut self.offsets)
    }

    /// Search a file the caller has already opened, driving the in-house
    /// reader path over a `Read`.
    ///
    /// `len` is the length the caller already knows; it is consulted only to
    /// decide the mapping arm, so the call costs no extra syscall. The `Read`
    /// is a read-only mapping when the file is big enough to be worth one and
    /// ordinary `ReadFile` calls otherwise; see [`FileSource::new`]. This is
    /// the only path a file takes once it is larger than `BUFFER_PATH_MAX` --
    /// smaller files are read whole in `main.rs` and handed to
    /// [`Searcher::search_slice`], so nothing here changes for them.
    pub fn search_path<S>(
        &mut self,
        file: std::fs::File,
        len: u64,
        sink: &mut S,
    ) -> Result<bool, io::Error>
    where
        S: RgxSink<Error = io::Error>,
    {
        let Some(engine) = self.searcher.as_mut() else {
            return self.fallback();
        };
        // A file that could not be opened never reaches here -- the caller
        // opened it -- so the "missing or unreadable file is `grep`'s to
        // report, fall back rather than invent a message" branch this used to
        // carry is gone with the second open it existed for.
        let mut source = FileSource::new(file, len);
        if stats::EXPLICIT.load(Ordering::Relaxed) {
            stats::RGX_RUNS.fetch_add(1, Ordering::Relaxed);
        }
        // A mapping is searched IN PLACE, in line-aligned windows: copying
        // it into a rolling buffer is the floor itself (the fill stage is
        // 52 of the 64 ms a zero-match probe spends over the 246 MB
        // single-file corpus, and a pure read of those bytes is 40 ms of
        // it). The binary rule does NOT gate this entry any more --
        // `search_windows` carries it (Quit truncates at the byte, Convert
        // splits lines there, exactly the reader's rewrite) and answers it
        // per window, warm, after the candidate map has touched the pages.
        // What keeps the reader is only what the window walk cannot carry:
        // the roll's context and a multi-line match across a window
        // boundary.
        if let FileSource::Mapped(m) = &mut source {
            let hay = m.as_live_slice();
            if !self.config.multi_line && self.config.before == 0 && self.config.after == 0 {
                return engine.search_windows(hay, sink, &mut self.scratch, &mut self.offsets);
            }
        }
        let mut buf = LineBuffer::new_sized(&self.config, len);
        let mut read = |b: &mut [u8]| -> Result<usize, std::fmt::Error> {
            use std::io::Read as _;
            match &mut source {
                FileSource::Mapped(m) => m.read(b).map_err(|_| std::fmt::Error),
                FileSource::Read(f) => f.read(b).map_err(|_| std::fmt::Error),
            }
        };
        engine.search_reader(&mut read, sink, &mut buf)
    }

    /// Hand the work to `grep`. Returns an `Unsupported` error.
    ///
    /// The in-house engine is the only path; this method exists so the
    /// call sites that used to route here read as a single, recognizable
    /// word, and the error message tells the user that the pattern is
    /// outside the in-house subset. A future session that wires the
    /// missing shapes (`\p{...}`, backreferences, look-around) will
    /// resurrect the call into `self.grep`; for now it is dead code on
    /// the live path and the count is still recorded so the bench
    /// transcript shows how often the in-house had to refuse.
    fn fallback<T>(&mut self) -> Result<T, io::Error> {
        stats::FALLBACKS.fetch_add(1, Ordering::Relaxed);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "rgx: pattern is outside the in-house engine's subset; \
             the in-house byte regex supports literals, alternation, \
             character classes, anchors, bounded repetitions and capture \
             groups, and refuses backreferences, look-around, Unicode \
             property classes and the in-pattern `(?-u)` flag",
        ))
    }

    // The `Both` mode's `cross_check` and `cross_check_path` methods
    // used to live here, along with the `RecGrep` recorder and the
    // `GrepDelegate` that wrapped a `grep-regex::RegexMatcher`. The
    // in-house is now the only engine, so every caller implements
    // `RgxSink` and the in-house `RecRgx` is the only recorder.
}

// The block above is the end of `impl Searcher`. The recorder
// types below used to be the differential harness for the
// `Both` mode (the in-house `RecRgx` against the `grep-searcher`
// `RecGrep`); the in-house is now the only engine and the
// `crates/rgx-core/src/differential.rs` test was deleted, so the
// `Event` enum and the `DIVERGENCES` stat have no reader. Marked
// `#[allow(dead_code)]` rather than deleted so the public surface
// stays for the in-house sink contract and the bench transcript
// line in `stats::report`.

/// One reported event, in a form the in-house engine can be reduced to.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Match(Option<u64>, Vec<u8>),
    Context(Option<u64>, Vec<u8>),
    Other(Option<u64>, Vec<u8>),
    Finish(Option<u64>),
}

/// Compile the pattern with the in-house engine, or `None` when it is outside
/// the byte-mode subset.
///
/// `-F` and `-w` are resolved by the caller into the pattern text, so this only
/// deals with case folding and `-U`'s `dot_all`.
///
/// `dot_all` is the compile-time half of `-U`: a byte engine that compiles `.`
/// to `any_except_newline()` will not span lines whatever
/// `Config::multi_line` says. `main.rs` keeps it in the cache key — the two
/// halves travel together or the feature is broken in a way that looks like it
/// works.
pub fn build_byte_regex_flags(
    pattern: Option<&str>,
    ignore_case: bool,
    dot_all: bool,
) -> Option<ByteRegex> {
    let pat = pattern?;
    if ignore_case || dot_all {
        ByteRegex::new_multiline(pat.as_bytes(), ignore_case, dot_all).ok()
    } else {
        ByteRegex::new(pat.as_bytes()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rgx_core::searcher::{SinkContext as RgxCtx, SinkFinish as RgxFin, SinkMatch as RgxMat};

    /// Records what a search reported, so the compat layer can be asked what
    /// it hands a sink rather than what the sink does with it.
    #[derive(Default, Debug)]
    struct Recorded {
        matched: Vec<String>,
        binary_offset: Option<u64>,
    }

    impl RgxSink for Recorded {
        type Error = io::Error;
        fn matched(&mut self, m: &RgxMat<'_>) -> Result<bool, io::Error> {
            self.matched
                .push(String::from_utf8_lossy(m.bytes).into_owned());
            Ok(true)
        }
        fn context(&mut self, _c: &RgxCtx<'_>) -> Result<bool, io::Error> {
            Ok(true)
        }
        fn finish(&mut self, f: &RgxFin<'_>) -> Result<(), io::Error> {
            self.binary_offset = f.binary_byte_offset;
            Ok(())
        }
    }

    /// The compat layer, asked directly: does the in-house engine hand a sink
    /// the offset of the NUL under `Convert`?
    ///
    /// **Yes, and this test is why the answer is known.** Under the in-house
    /// engine a named binary file printed no `binary file matches` line, while
    /// the count, the listing, the exit status and `-a` all matched the
    /// reference — so nothing above this layer could see it, and the hunt went
    /// through the pack, the CRC, the walk and the OCR adapter before landing
    /// here.
    ///
    /// The answer is that this layer was fine and the one above was not:
    /// `HitSink` in `src/main.rs` had two `finish` methods - the
    /// `grep_searcher` one recorded `binary_offset`, and the `rgx-core` one
    /// set only `binary`. So under the in-house engine `hit.binary` was true
    /// and `hit.binary_offset` was `None`, and the printer's
    /// `if let Some(offset) = hit.binary_offset` never fired.
    ///
    /// The fix was that one line - `self.binary_offset =
    /// self.binary_offset.or(finish.binary_byte_offset);` beside the existing
    /// assignment, which is what the grep-side `finish` already did. It is in
    /// `HitSink::finish` now, and the CLI suite goes red without it.
    ///
    /// This test pins the thing below the sink in the in-house engine,
    /// so the next person starts at `HitSink::finish` in `src/main.rs`
    /// instead of at the pack. The grep arm is gone: `Mode::Grep` used to
    /// exercise the `grep-searcher` fallback, and the in-house is now the
    /// only engine, so the only thing left to assert is the in-house
    /// path's behaviour.
    #[test]
    fn convert_hands_the_sink_the_nul_offset() {
        let hay = b"before needle\0\nafter needle\n";
        let config = Config {
            binary: rgx_core::searcher::BinaryDetection::Convert(0),
            line_numbers: true,
            ..Config::default()
        };

        let mut s = Searcher::new(
            config.clone(),
            Some(std::sync::Arc::new(ByteRegex::new(b"needle").unwrap())),
            Mode::Rgx,
        );
        let mut r = Recorded::default();
        s.search_slice(hay, &mut r).unwrap();
        assert_eq!(r.matched.len(), 2, "both lines match");
        assert_eq!(
            r.binary_offset,
            Some(13),
            "the NUL's offset reaches the sink"
        );
    }
}
