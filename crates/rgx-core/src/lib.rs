// SPDX-License-Identifier: Apache-2.0

//! rgx-core: the adapter contract and the extraction pipeline.
//!
//! `no_std` + `alloc`. The `std` feature gates what genuinely needs it; see
//! `Cargo.toml` for what that costs on the way off.
//!
//! Design decisions:
//! - Adapters are **sync and work on byte slices** — no async, no streams,
//!   no subprocess in the core model. Heavy externals live in
//!   `rgx-adapters-docs` and spawn only when their binary is installed.
//! - Adapters never recurse themselves: archives return
//!   [`Outcome::Members`] and the pipeline recurses uniformly (depth limits,
//!   member caps, bail semantics all live in one place).
//! - `Outcome::Bail` mirrors rga's bail-out semantics: the file falls back
//!   to the next adapter and finally to raw-text search — an adapter
//!   declining a file is never an error.
//! - **Byte scanning is the upstream `memchr` crate, re-exported** —
//!   `pub mod memchr;` is the crate itself under an in-tree name, so every
//!   call site keeps the `rgx_core::memchr::*` path it has used since the
//!   in-house module was deleted. It is a re-export, not a vendored copy:
//!   the dependency graph still carries `memchr = "2"`. See below.
//!
//! ## Byte scanning: the crate wins
//!
//! This crate used to carry `src/memchr.rs` — a 901-line byte scanner of its
//! own, AVX2 behind runtime detection with a SWAR fallback. It was measured
//! and deleted, on the evidence of the table below rather than on an inherited
//! claim that it was "4–23× slower than the crate", which had never been run.
//!
//! `cargo run --release -p rgx-core --example memchr_bench` reproduces the
//! table. Both implementations link into that one binary and run over the
//! same buffers, so it is same-process and same-input. Shapes are the ones rgx
//! actually searches: `buf64` is the searcher's 64 KiB read buffer, `buf8m`
//! one large text file end to end, `blob8m` a binary blob. Best of 7 timed
//! rounds after 2 warmup rounds. `ratio` is `in-house / crate`, so above 1.00
//! means the crate was faster.
//!
//! | case                                    | in-house | crate  | ratio | winner   |
//! |-----------------------------------------|---------:|-------:|------:|----------|
//! | memchr 1B absent (NUL sniff), 64 KiB    |   0.637us| 0.426us| 1.50x | crate    |
//! | memchr 1B absent (NUL sniff), 8 MiB     |  82.051us| 66.073us| 1.24x | crate   |
//! | memchr 1B absent, 8 MiB blob            |  83.563us| 63.589us| 1.31x | crate    |
//! | 5-byte needle absent, 8 MiB blob        | 424.769us|146.246us| 2.90x | crate    |
//! | memrchr absent byte, 8 MiB file         | 445.497us| 63.186us| 7.05x | crate    |
//! | memchr_iter newline-dense, 64 KiB       |   8.062us| 1.118us| 7.21x | crate    |
//! | memchr_iter newline-dense, 8 MiB file   |1350.960us|139.882us| 9.66x | crate    |
//! | memchr 1B present at end, 64 KiB        |   0.003us| 0.006us| 0.48x | in-house |
//! | memchr 1B present at start, 64 KiB      |   0.003us| 0.003us| 0.87x | in-house |
//! | 2-byte needle absent, 64 KiB            |   0.637us| 0.897us| 0.71x | in-house |
//! | 2-byte needle absent, 8 MiB blob        |  83.580us|109.205us| 0.77x | in-house |
//! | 3-byte needle absent, 64 KiB            |   0.632us| 0.898us| 0.70x | in-house |
//! | 3-byte needle absent, 8 MiB blob        |  83.157us|109.242us| 0.76x | in-house |
//! | 2-byte needle present (markup), 64 KiB  |   0.005us| 0.022us| 0.23x | in-house |
//! | 3-byte needle present (markup), 64 KiB  |   0.005us| 0.023us| 0.22x | in-house |
//! | 6-byte needle present (markup), 8 MiB   |   0.015us| 0.027us| 0.56x | in-house |
//! | memrchr hit at end, 64 KiB              |   0.003us| 0.005us| 0.61x | in-house |
//! | memrchr hit mid-buffer, 64 KiB          |   0.003us| 0.005us| 0.71x | in-house |
//!
//! The 11–7 scoreboard is a bad way to read this. Every row in-house wins
//! returns within the first few bytes — a needle that occurs early, a
//! terminator near the end of a read — and wins by 2 ns to 260 ns on calls
//! already under half a microsecond. Every row it loses scans the whole
//! buffer, and loses by 16 us to 1211 us. The wins are in nanoseconds because
//! there is nothing left to win; the losses are in microseconds because a
//! whole 8 MiB file is being walked. And that is the shape of the work: every
//! call site rgx has is per-file over the corpus, per-read over a 64 KiB
//! buffer, or an iterator over a large haystack. None is the early-return
//! shape that is the module's one genuine advantage.
//!
//! Two specific findings:
//!
//! - **`memrchr` has no SIMD in-house.** SWAR in both directions, 8 bytes per
//!   word, where the crate scans backwards 32 at a time — the whole 7.05x on
//!   the absent-byte row. It costs little in practice (the searcher asks for
//!   the newest terminator in freshly read bytes, nearly always at the end,
//!   where the two are within 2 ns), but it is a real gap, not noise.
//! - **`memchr_iter` is a restart loop against a bitmap.** The in-house
//!   iterator re-enters the scan at each hit; the crate's keeps a candidate
//!   mask per block and yields bits out of it. Newline-dense text is the worst
//!   case for the restart and the best for the bitmap, which is why that row
//!   is the largest. The paragraph-break walk in `src/main.rs` is the only
//!   caller.
//!
//! On the 2- and 3-byte rows: `memchr2` and `memchr3` exist in neither
//! implementation in a form that lines up and nothing in the workspace calls
//! them, so the in-house side is the substring search — anchor-scan-then-
//! confirm, which is what those two functions are for. The crossover: in-house
//! is ahead at 2 and 3 bytes (0.70–0.77x), the crate is 2.90x ahead at 5.
//!
//! Two things this did not buy, recorded so they are not re-litigated: the
//! differential harness that held the two implementations to each other went
//! with the module, and the crate's prebuilt `Finder` — which amortises
//! matcher setup across many searches — is still unused, because every search
//! here is a one-shot over a buffer. `memmem::find` remains the right entry
//! point for a single search.

#![no_std]

// macro_use brings vec!/format!/write! into every submodule, which a
// no_std crate needs and the std prelude used to provide for free.
#[macro_use]
extern crate alloc;

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
// The crate is `no_std`, but the test harness is not: `cargo test` links
// `libtest`, which needs `std`. So `std` is linked for the tests even when
// the `std` feature is off -- the library's own code still cannot use it, and
// the `no_std` configuration still has to be *run*, not only built.
#[cfg(any(feature = "std", test))]
extern crate std;

pub mod base64;
pub mod byteclass;
pub mod cfb;
pub mod charset;
mod charset_mb_table;
mod charset_state_table;
mod charset_table;
pub mod compress;
pub mod crypt;
pub mod detect;
pub mod encoding;
pub mod error;
pub mod filetype;
pub mod filter;
pub mod fixed;
pub mod frequency;
pub mod memchr;
#[cfg(feature = "std")]
pub mod memmap2;

pub mod casefold_table;
pub mod djson;
pub mod facts_index;
pub mod fuzzkit;
pub mod fuzzy;
pub mod hybrid;
pub mod index;
pub mod index_io;
pub mod literal;
pub mod maskstats;
pub mod matcher;
pub mod mcp;
pub mod nfa;
pub mod ngram;
pub mod numparse;
pub mod png;
pub mod prefilter;
pub mod regex;
pub mod required;
pub mod rulebank;
pub mod scan;
pub mod searcher;
pub mod sha256;
pub mod sha256_hw;
// The independent scalar implementation exists only so the split-input and
// block-by-block tests have something that is not the code under test. It
// was unconditional, which put ~200 lines of test-only code in the shipped
// `rgx` binary and in `--no-default-features`.
#[cfg(any(test, doc))]
pub mod sha256_ref;
pub mod syntax;
pub mod tokenize;

#[cfg(feature = "tv")]
pub mod tv;
#[cfg(feature = "tv-runtime")]
pub mod tv_runtime;
pub mod unicode_case;
pub mod vm;
pub mod walk_policy;
// The ZIP reader, and with it the five compression methods the format
// defines: deflate, bzip2, lzma, xz and zstd. The feature is what carries
// them, so a binary that reads no zip archive carries no zip codec either.
#[cfg(feature = "zip")]
pub mod zip;

pub use error::{Context, Error, Result};

/// A fact about a file, as the filter's predicates see it.
///
/// Re-exported at the crate root because an adapter that has metadata to
/// report names it here, and `rgx_core::filter::Field` is a mouthful for
/// a type every adapter would spell.
pub use filter::Field;

/// `anyhow!` expands to `format!`, and a macro that names `alloc` only
/// works inside this crate. Re-exporting it under `$crate` is what lets the
/// macro work in a caller that is itself `no_std`.
#[doc(hidden)]
pub use alloc::format;

/// `f64::from_str` is in `std`, not `core`, so a `no_std` build cannot parse
/// a JSON float. This is the seam `json/parser.rs` was already written
/// against (`#[cfg(not(feature = "std"))] use crate::NoStdFloat`); the trait
/// it named had never been defined here, so this crate could not have
/// compiled without `std` no matter what its Cargo features claimed.
///
/// Under `std` the impl is the standard parser. Under `alloc` alone it is a
/// decimal parser over what RFC 8259 allows: an optional sign, an integer part
/// with no redundant leading zero, an optional fraction, an optional exponent.
/// Anything else is `Err`, which the caller turns into its own message.
pub trait NoStdFloat: Sized {
    /// Parse a float. The error carries no detail: the standard library's
    /// error type does not exist here, and the caller supplies the message.
    #[allow(clippy::result_unit_err)]
    fn parse(s: &str) -> Result<Self, ()>;
}

#[cfg(feature = "std")]
impl NoStdFloat for f64 {
    fn parse(s: &str) -> Result<Self, ()> {
        use core::str::FromStr;
        f64::from_str(s).map_err(|_| ())
    }
}

/// The `alloc`-only decimal parser behind the `no_std` impl.
///
/// Compiled under every feature, not just `no_std`, so that the tests can
/// hold it against the standard library's parser on a build that has one.
/// A `no_std` path nobody can test is a `no_std` path nobody should trust.
///
/// Parse a JSON number without `std`.
// `()` is the contract: see `NoStdFloat::parse`, the caller owns the message.
#[allow(clippy::result_unit_err)]
pub fn parse_decimal(s: &str) -> Result<f64, ()> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut neg = false;
    // '-' only: RFC 8259's number grammar has no leading '+', whatever the
    // standard library's parser does with one.
    if i < b.len() && b[i] == b'-' {
        neg = true;
        i += 1;
    }

    // One mantissa and one scale, applied once at the end. Accumulating into
    //  a digit at a time instead rounds at every step and is a ULP off
    // the standard parser on ordinary input -- 3.14159 came out as
    // 3.1415900000000003, which  caught.
    let mut mant = numparse::Mantissa::new();
    let mut scale: i32 = 0;

    let int_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        // Past what the accumulator holds the remaining digits are dropped
        // and the scale absorbs them; a JSON number with 39 integer digits
        // is not a real case.
        if !mant.push(b[i] - b'0') {
            scale += 1;
        }
        i += 1;
    }
    if i == int_start {
        return Err(());
    }
    if b[int_start] == b'0' && i - int_start > 1 {
        return Err(());
    }

    if i < b.len() && b[i] == b'.' {
        i += 1;
        let frac_start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            if mant.push(b[i] - b'0') {
                scale -= 1;
            }
            i += 1;
        }
        if i == frac_start {
            return Err(());
        }
    }

    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        let mut eneg = false;
        if i < b.len() && (b[i] == b'-' || b[i] == b'+') {
            eneg = b[i] == b'-';
            i += 1;
        }
        let exp_start = i;
        let mut exp: i32 = 0;
        while i < b.len() && b[i].is_ascii_digit() {
            // saturating: an exponent this large is infinity or zero anyway
            exp = exp
                .saturating_mul(10)
                .saturating_add(i32::from(b[i] - b'0'));
            i += 1;
        }
        if i == exp_start {
            return Err(());
        }
        scale = scale.saturating_add(if eneg { -exp } else { exp });
    }
    if i != b.len() {
        return Err(());
    }

    let value = numparse::scale_decimal(mant.value(), scale, mant.dropped_nonzero());
    Ok(if neg { -value } else { value })
}

#[cfg(not(feature = "std"))]
impl NoStdFloat for f64 {
    fn parse(s: &str) -> Result<Self, ()> {
        parse_decimal(s)
    }
}

/// What an adapter made of a file.
pub enum Outcome {
    /// Searchable plain text (already encoding-normalized by the adapter).
    Text(Vec<u8>),
    /// Archive members: `(virtual_inner_path, raw_bytes)` to recurse.
    Members(Vec<(String, Vec<u8>)>),
    /// "This file is not actually mine" — try the next adapter. The clean
    /// way to decline: the chain continues, and a file every adapter has
    /// declined reaches the raw searcher with its bytes intact.
    ///
    /// Declining with `bail!` also reaches the raw searcher — `process`
    /// treats an adapter `Err` as a decline plus a note rather than as a
    /// replacement for the file — but it stops the chain at the first
    /// failure, and it puts a line in the corpus that is not in the file.
    /// Reserve it for a failure worth reporting and use this for the rest.
    Bail(String),
}

/// Pipeline knobs shared by the CLI and tests.
pub struct Ctx {
    /// max archive nesting depth (rga default: 4)
    pub max_depth: usize,
    /// max members expanded per archive level
    pub max_members: usize,
    /// max bytes read from one real file before adapters see it
    pub max_file_size: usize,
    /// The structured filter, when one was given.
    ///
    /// It is part of the [`Ctx`] and not a global because the cache is keyed
    /// by the [`Ctx`]: two filters over the same file are two extractions
    /// as far as the cache is concerned, and a cache that handed the
    /// second one the first one's units would answer a question nobody
    /// asked.
    pub filter: Option<filter::Filter>,
    /// Where the facts of the files go, when the caller asked for them.
    ///
    /// The index builder needs every file's facts, not only the ones a
    /// filter kept, and the pipeline already assembles them — it has to,
    /// to ask the filter. This is where they go on the way past.
    ///
    /// It is `None` in every run that does not ask, and it is not part of
    /// the cache key: the sink decides where the facts are *written*,
    /// not what the extraction *is*, and a key that moved when the sink
    /// appeared would make the cache miss on a run that changed nothing.
    pub facts_sink: Option<Arc<dyn FactsSink>>,
}

/// Where the pipeline's facts go.
///
/// The sink is shared: the walk runs the pipeline on several threads, and
/// the facts of the files they handle have to end up in one place. So the
/// trait takes `&self` and the implementor owns the interior mutability —
/// a `Mutex` around a `Vec` is the obvious one.
pub trait FactsSink: Send + Sync {
    /// One file's facts, and the path they belong to.
    ///
    /// The path is the *logical* path: a member of an archive arrives
    /// here as `archive.zip!inner.txt`, because that is the path the
    /// filter saw and the path a query will ask about.
    fn record(&self, path: &str, facts: Vec<Field>);
}

impl Default for Ctx {
    fn default() -> Self {
        Self {
            max_depth: 4,
            max_members: 4096,
            max_file_size: 1 << 30,
            filter: None,
            facts_sink: None,
        }
    }
}

impl Ctx {
    /// Whether a file passes the structured filter.
    ///
    /// The facts are the ones the pipeline knows: the path, the extension
    /// and the adapter that answered for the file (`raw` when none did),
    /// plus whatever the adapter reported about the file itself. A file
    /// the filter rejects contributes nothing to the corpus, not even a
    /// note about why it could not be read: the question was not asked.
    pub fn passes(&self, facts: &[Field]) -> bool {
        match &self.filter {
            None => true,
            Some(f) => filter::matches(&f.expr, facts),
        }
    }

    /// Whether a filter is in play.
    ///
    /// The facts of a file are only worth assembling when something will
    /// look at them, and the adapter's own report is not free: an
    /// adapter that has to parse the file again to answer pays for that
    /// parse. So the question is asked only when there is a filter to
    /// answer it, and the run that has no filter pays nothing.
    pub fn wants_filter(&self) -> bool {
        self.filter.is_some()
    }

    /// Whether the facts of a file are wanted by anyone.
    ///
    /// The filter wants them, and so does the index builder: the index is
    /// the corpus's facts, and a file the filter would have rejected is
    /// still a file the index has to know about.
    pub fn wants_facts(&self) -> bool {
        self.filter.is_some() || self.facts_sink.is_some()
    }
}

/// A searchable unit produced by the pipeline.
#[derive(Debug)]
pub struct Found {
    /// e.g. `bundle.zip!inner/record.txt`
    pub path: String,
    pub bytes: Vec<u8>,
    /// adapter that produced it ("raw" = no adapter claimed the file)
    pub via: &'static str,
}

/// What an adapter's output is *for*, relative to the bytes on disk.
///
/// The distinction is the whole superset question, and it is a property of the
/// file, not of the code. A zip, a PDF, a PNG, a `.doc`: the bytes on disk are
/// not searchable text, so an adapter that reads them [`Reach::Reveal`]s
/// content ripgrep cannot reach at all, and swapping the rendering in for the
/// file costs the user nothing — rgx's answer is a strict superset of rg's and
/// that is the entire point. A `.md`, a `.html`, a `.tex`, a `.rtf`: the bytes
/// on disk *are* searchable text, so an adapter that reads them
/// [`Reach::Render`]s a second, lossy view of the same lines. Everything the
/// renderer drops is then unreachable — HTML `<script>` and `<style>` bodies,
/// LaTeX control words, RTF destination groups, Markdown link targets — and a
/// pattern that occurs only there is a line `rg` prints and rgx does not.
/// That is not a faster ripgrep, it is a strict subset of one, so the default
/// policy is to keep the file's own bytes and let the renderer be asked for
/// instead of answered with (see [`Policy`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reach {
    /// The file is not searchable as it stands (compressed, or a binary
    /// container); the adapter surfaces bytes the raw searcher cannot reach.
    Reveal,
    /// The file is searchable as it stands; the adapter produces a *lossy
    /// rendering* of it and the rendering can hide what the raw bytes say.
    Render,
}

/// Which view of an adapter-claimed file rgx searches.
///
/// `Source` is the default because it is the only one of the three under which
/// rgx is a superset of ripgrep on a [`Reach::Render`] format, and because it
/// is the only one that leaves every format which *already* matches rg byte for
/// byte untouched: a [`Reach::Reveal`] adapter is unaffected in all three.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy {
    /// Search the file's own bytes; a `Render` adapter does not get the file.
    Source,
    /// Search the adapter's rendering, whatever it is. This is what every rgx
    /// before `Source` did.
    Render,
    /// Search both and report both. Heavier and duplicate-heavy: a pattern
    /// that occurs in the rendering almost always occurs in the source too, so
    /// most matches print twice under two line numbers, and `-c` prints the
    /// same path twice. It is not even a strict superset — where the renderer
    /// *declines* the file it produces no `Text` at all, and the union falls
    /// back to `Source` for that file, which is the behaviour, so it only
    /// recovers what `Source` recovers (measured: 134% of ripgrep on markup
    /// against `Source`'s 100%, at 34% more lines printed).
    Both,
}

// 0 means "not resolved yet"; the enum values are stored as 1..=3.
static POLICY: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

// The `ablate_mask` override, raised only by [`set_ablate_mask`]. The
// environment is still read when it is down, so an unset override leaves
// `RGX_ABLATE_MASK` in charge.
static ABLATE_MASK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static ABLATE_EXTENTS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

const POLICY_SOURCE: u8 = 1;
const POLICY_RENDER: u8 = 2;
const POLICY_BOTH: u8 = 3;

fn policy_code(p: Policy) -> u8 {
    match p {
        Policy::Source => POLICY_SOURCE,
        Policy::Render => POLICY_RENDER,
        Policy::Both => POLICY_BOTH,
    }
}

fn policy_from_code(c: u8) -> Policy {
    match c {
        POLICY_RENDER => Policy::Render,
        POLICY_BOTH => Policy::Both,
        _ => Policy::Source,
    }
}

/// The environment variable that names the policy, and its accepted values.
pub const POLICY_ENV: &str = "RGX_ADAPTER_VIEW";

/// The active policy, resolved once from [`POLICY_ENV`].
///
/// `source` (the default) keeps a `Render` format's own bytes; `render` hands
/// the file to the adapter as before; `both` reports the two views side by
/// side. An unrecognised value is a `Source`, which is the conservative end:
/// it is the only policy that cannot lose a line `rg` prints.
pub fn policy() -> Policy {
    let cached = POLICY.load(core::sync::atomic::Ordering::Relaxed);
    if cached != 0 {
        return policy_from_code(cached);
    }
    let resolved = policy_from_env();
    // Two threads racing here compute the same value from the same
    // environment, so the plain store is enough.
    POLICY.store(policy_code(resolved), core::sync::atomic::Ordering::Relaxed);
    resolved
}

#[cfg(feature = "std")]
fn policy_from_env() -> Policy {
    match std::env::var(POLICY_ENV).ok().as_deref().map(str::trim) {
        Some("render") | Some("rendered") | Some("adapter") => Policy::Render,
        Some("both") | Some("union") => Policy::Both,
        _ => Policy::Source,
    }
}

#[cfg(not(feature = "std"))]
fn policy_from_env() -> Policy {
    Policy::Source
}

/// Set the policy programmatically, overriding [`POLICY_ENV`].
///
/// Intended for the CLI flag and for tests, which have to exercise both
/// policies in one process.
pub fn set_policy(p: Policy) {
    POLICY.store(policy_code(p), core::sync::atomic::Ordering::Relaxed);
}

/// Ablation instrumentation: the compiled-mask tier switched off at
/// pattern-compile time (`RGX_ABLATE_MASK`).
///
/// Set, the mask builder declines to produce a mask anchor and the
/// builder falls back to its next anchor, or to confirming every line when
/// there is none. It exists so the paper's end-to-end tier comparison can
/// run the same query with the tier present and absent.
///
/// **Contract: changing this may change cost, never answers.** The fallback
/// is a slower search over the same superset of candidates, so a result that
/// differs between settings is a bug in the fallback, not in the switch. It
/// is inert without `std`, where there is no environment to read.
#[cfg(feature = "std")]
pub fn ablate_mask() -> bool {
    ABLATE_MASK.load(core::sync::atomic::Ordering::Relaxed)
        || std::env::var_os("RGX_ABLATE_MASK").is_some()
}

#[cfg(not(feature = "std"))]
pub fn ablate_mask() -> bool {
    ABLATE_MASK.load(core::sync::atomic::Ordering::Relaxed)
}

/// Force [`ablate_mask`] on or off, overriding the environment.
///
/// For tests and in-process harnesses, which need the switch inside one
/// process the way [`set_policy`] needs the policy. Overriding off is the
/// reason this is not just a set-to-true: a test must be able to leave the
/// state it found.
pub fn set_ablate_mask(on: bool) {
    ABLATE_MASK.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// Ablation instrumentation: the per-file n-gram signature switched off at
/// query-build time (`RGX_ABLATE_NGRAM`).
///
/// Set, the query signature is `None`, which is the filter's own stand-down
/// state: every file is searched. Same contract as [`ablate_mask`]: cost
/// may change, answers never do, and without `std` the switch is inert.
#[cfg(feature = "std")]
pub fn ablate_ngram() -> bool {
    std::env::var_os("RGX_ABLATE_NGRAM").is_some()
}

#[cfg(not(feature = "std"))]
pub fn ablate_ngram() -> bool {
    false
}

/// Ablation instrumentation: the plan-time filter and the extent cuts
/// switched off (`RGX_ABLATE_EXTENTS`).
///
/// Set, no record is rejected before the read plan is built and no gap is
/// ever left unread: every planned unit covers exactly the span today's
/// full-pack read covers. It exists so the sparse-read separation can be
/// measured on the same query with the tier present and absent. Same
/// contract as [`ablate_mask`]: cost may change, answers never do.
#[cfg(feature = "std")]
pub fn ablate_extents() -> bool {
    ABLATE_EXTENTS.load(core::sync::atomic::Ordering::Relaxed)
        || std::env::var_os("RGX_ABLATE_EXTENTS").is_some()
}

#[cfg(not(feature = "std"))]
pub fn ablate_extents() -> bool {
    ABLATE_EXTENTS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Force [`ablate_extents`] on or off, overriding the environment.
///
/// For tests and in-process harnesses, which need the switch inside one
/// process; overridable in both directions so a test can leave the state
/// it found.
pub fn set_ablate_extents(on: bool) {
    ABLATE_EXTENTS.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// Serialises the tests that flip [`set_ablate_extents`]: the switch is
/// process-global, and two tests reading it mid-flip is a flake, not a bug.
#[cfg(all(test, feature = "tv"))]
pub(crate) static ABLATE_EXTENTS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A content adapter. Implementations must be cheap to construct; tool
/// detection for external-tool adapters happens in `available()`.
pub trait Adapter: Send + Sync {
    fn name(&self) -> &'static str;
    /// lowercased extensions this adapter claims, e.g. `&["zip", "jar"]`
    fn extensions(&self) -> &'static [&'static str];
    /// false if the adapter cannot run in this environment (missing binary).
    /// In-process adapters always return true.
    fn available(&self) -> bool {
        true
    }
    /// Whether this adapter reveals a file ripgrep cannot read, or renders one
    /// it can. Defaults to [`Reach::Reveal`], which is the answer for every
    /// adapter that reads a container or a binary format; see [`Reach`].
    fn reach(&self) -> Reach {
        Reach::Reveal
    }

    /// Whether the answer to [`Self::reach`] can change once the file's bytes
    /// are in hand.
    ///
    /// [`Reach`] is a property of the FILE, and an extension does not know
    /// what a file is. `.pem` and `.der` are the same adapter and not the same
    /// question: a PEM is base64 text ripgrep reads perfectly, so a renderer
    /// that replaces those bytes with nine lines of certificate description
    /// deletes thirty-nine lines of matches; a DER is binary, so the same
    /// renderer is a strict superset and the bytes it drops were never
    /// readable content. Only an adapter that says so pays a read to find
    /// out, which is what keeps `.html` and `.md` off the adapter path.
    fn reach_needs_bytes(&self) -> bool {
        false
    }

    /// [`Self::reach`] for a file whose bytes are in hand. The default defers
    /// to the static answer, so an adapter that does not ask for the bytes is
    /// unaffected by having them.
    fn reach_for(&self, _data: &[u8]) -> Reach {
        self.reach()
    }

    /// A byte prefix this adapter claims, for a file whose NAME says nothing
    /// about what it is.
    ///
    /// **The extension is the claim, and this is the claim behind it.** Almost
    /// every format names itself: `.zip` is a zip, `.pdf` is a PDF, and the
    /// dotted declarations (`scan.ocr.jpg`) cover the names that carry a
    /// second word. The formats that do not name themselves are the ones whose
    /// own layout carries the name: a borg segment is `data/0/2` — no
    /// extension, no dot, nothing in the path but a number — and the only
    /// evidence of what it is lives in its first eight bytes.
    ///
    /// An adapter that answers here is a candidate only when NO adapter
    /// claimed the file by name, and only when the bytes in hand start with
    /// the prefix. The prefix is a claim, not a decision: the adapter still
    /// runs, still reads the file, and still declines if the file is not
    /// really its own.
    fn magic(&self) -> Option<&'static [u8]> {
        None
    }

    /// The facts this adapter knows about the file, for the `--filter`.
    ///
    /// **What a fact is.** A name and a value: `author` and `Jane Doe`,
    /// `mail.from` and `admin@example.com`. The name is namespaced by
    /// whoever reports it, so two adapters that both have a `from` do not
    /// collide -- `mail.from` and `http.from` are different facts. The
    /// filter's grammar spells the namespace with `:` or `.`; both mean
    /// the same thing, so `mail:from` and `mail.from` are one path.
    ///
    /// **What a fact means to a predicate.** A predicate whose path is
    /// the fact's *name* compares the fact's *value*; a predicate whose
    /// path is the fact's *namespace* compares the fact's *name*. So
    /// `author:"Jane Doe"` asks for the author to be Jane Doe, and
    /// `exif:gps` asks whether the file has an EXIF fact called `gps` --
    /// the second is a question about the fact's existence, and the
    /// value beside it is the name it must have.
    ///
    /// **When it is asked.** Only when a filter is in play, and only for
    /// an adapter that answered for the file. A file that no adapter
    /// claims has no adapter to ask.
    ///
    /// **What it costs.** The adapter is asked *after* it extracted, so
    /// an implementation that has to parse the file again pays for a
    /// second parse. That is the price of not changing the shape of
    /// [`Outcome`] for the two hundred and eighty-odd call sites that
    /// build one, and it is paid only by the runs that ask the question.
    /// An adapter whose metadata is already in hand when it renders
    /// should keep it and hand it over cheaply.
    fn facts(&self, _data: &[u8], _path: &str) -> Vec<Field> {
        Vec::new()
    }

    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome>;
}

/// Ordered adapter registry; first matching available adapter wins, and a
/// bail falls through to the next candidate (rga issue #3 semantics).
///
/// Lookups go through a per-extension index so candidate resolution is
/// O(candidates for this extension), not O(all adapters) — matters when
/// hundreds of adapters accumulate.
pub struct Registry {
    adapters: Vec<Box<dyn Adapter>>,
    by_ext: alloc::collections::BTreeMap<String, Vec<usize>>,
    /// The adapters that claim a byte prefix rather than an extension, with the
    /// prefix itself, in registration order.
    by_magic: Vec<(usize, &'static [u8])>,
}

/// One adapter's extension list with repeats removed, order preserved.
///
/// `O(n^2)` on a list that is at most a few dozen entries long, and it borrows
/// rather than allocates, so it costs nothing on the startup path this guards.
/// See [`Registry::new`] for why a repeat is a cost and not a cosmetic issue.
fn dedup_exts(exts: &[&'static str]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::with_capacity(exts.len());
    for e in exts {
        if !out.contains(e) {
            out.push(e);
        }
    }
    out
}

impl Registry {
    /// Index `adapters` by extension.
    ///
    /// **A repeated extension in one adapter's list is collapsed, and that is
    /// a cost fix rather than tidiness.** The index pushes the adapter's index
    /// once per literal, so `"efi"` appearing twice in `Inspect::extensions`
    /// made `by_ext["efi"] = [inspect, inspect]`. A `.efi` file that then bails
    /// runs the *entire* inspection twice -- and `Inspect` is the most
    /// expensive adapter per byte in the tree, since it scans the file once
    /// per embedded signature (`inspect/src/lib.rs`). Two such lists shipped:
    /// `"efi"` in inspect and `"tlz"` in `archive`'s `Decompress`, the latter
    /// running a whole decompression twice. `dedup_exts` is the guard; the
    /// literals are fixed too, because a list that lists itself twice should
    /// not read as if it meant something.
    ///
    /// Collapsing is behaviour-preserving: the chain semantics for a repeated
    /// *identical* adapter are "run it again", which can only differ if the
    /// adapter is non-deterministic. Genuine pairs stay — `apk` is claimed by
    /// both `zip` and `inspect`, and both must run.
    pub fn new(adapters: Vec<Box<dyn Adapter>>) -> Self {
        Self::with_extra_claims(adapters, &[])
    }

    /// Index `adapters` by extension, plus `(adapter name, extension)` pairs
    /// the caller wants claimed that the adapter does not claim by default.
    ///
    /// **This exists because "which extensions should be read" is a policy
    /// question, and a hard-coded list makes it the adapter author's
    /// decision.** The concrete case: `Inspect` used to claim `o`, and every
    /// object file inside every static library reached it through the `ar`
    /// adapter -- 126,145 calls costing 641 ms on the cargo registry, all of it
    /// from two `winapi` crates that ship ~700 `.a` files between them. That is
    /// the wrong default for a corpus nobody asked to be triaged, and the wrong
    /// default is not a good enough reason to make the capability unreachable:
    /// someone reading object files out of a library on purpose is exactly who
    /// wants it, and they have no way to ask.
    ///
    /// `extra_claims` is therefore `(adapter, extension)` pairs appended after
    /// the built-in lists. Order matters and is preserved: the extra claim runs
    /// after the adapter's own, so a default claim still wins the chain's
    /// "first matching adapter" position, and an extension nobody claims
    /// simply gets no adapter.
    pub fn with_extra_claims(
        adapters: Vec<Box<dyn Adapter>>,
        extra_claims: &[(&str, &str)],
    ) -> Self {
        let mut by_ext: alloc::collections::BTreeMap<String, Vec<usize>> =
            alloc::collections::BTreeMap::new();
        let mut by_magic: Vec<(usize, &'static [u8])> = Vec::new();
        for (i, a) in adapters.iter().enumerate() {
            for ext in dedup_exts(a.extensions()) {
                by_ext.entry(ext.to_string()).or_default().push(i);
            }
            if let Some(magic) = a.magic() {
                by_magic.push((i, magic));
            }
        }
        for (name, ext) in extra_claims {
            let Some(i) = adapters.iter().position(|a| a.name() == *name) else {
                continue;
            };
            let slot = by_ext.entry((*ext).to_string()).or_default();
            if !slot.contains(&i) {
                slot.push(i);
            }
        }
        Self {
            adapters,
            by_ext,
            by_magic,
        }
    }

    /// Every adapter in registration order -- the chain as a caller
    /// *describes* it rather than resolves it. The manifest head's
    /// `extract_fp` folds this sequence to decide whether the rollup
    /// signatures a build wrote cover the units a query's pipeline will
    /// produce; resolution order decides units, so the description has to
    /// carry it, plus each adapter's extension list and whether its binary
    /// is present.
    pub fn chain(&self) -> impl Iterator<Item = &dyn Adapter> + '_ {
        self.adapters.iter().map(|a| &**a)
    }

    /// Every available adapter that could claim `ext`.
    ///
    /// The policy filter is NOT here. It used to be, and it could not be
    /// moved into [`process`] for free: under [`Policy::Source`] a `Render`
    /// adapter is dropped, and dropping it before the read is what lets the
    /// walker skip reading the file at all and go straight to the mmap path.
    /// An adapter whose answer depends on the bytes has to be asked after the
    /// read, which means the read happens -- so the cheap question is put
    /// back here, in [`Registry::may_claim`], and the real one is settled in
    /// `process` where the data is.
    pub fn candidates<'a>(&'a self, ext: &str) -> impl Iterator<Item = &'a dyn Adapter> + 'a {
        self.by_ext
            .get(ext)
            .into_iter()
            .flatten()
            .map(move |&i| &*self.adapters[i])
            .filter(|a| a.available())
    }

    /// true if any *available* adapter may claim this extension — lets callers
    /// skip reading the file entirely and use the raw mmap search path.
    ///
    /// "MAY", because an adapter that decides from the bytes cannot be
    /// answered here. It is still true for such an adapter under every
    /// policy: `Source` will drop it for a text file and `Reveal` for a
    /// binary one, and which one it is decides whether the file is read at
    /// all. The alternative -- answering "no" and never reading -- is the
    /// subset property on `.pem`.
    pub fn may_claim(&self, ext: &str) -> bool {
        let pol = policy();
        // `any`, not `next`: the list is ordered, and the policy filter used
        // to be applied before this, so the first surviving candidate was the
        // first candidate. It is not any more, and taking only the first
        // available adapter here would answer for the wrong one -- a `Render`
        // adapter ahead of a `Reveal` one for the same extension would send
        // the file down the raw path when a Reveal adapter was waiting
        // behind it to read it.
        self.candidates(ext)
            .any(|a| a.reach_needs_bytes() || pol != Policy::Source || a.reach() == Reach::Reveal)
    }

    /// Names of adapters that claim `ext` but whose external tool is not on
    /// `PATH`, so [`Self::candidates`] filters them out and [`Self::may_claim`]
    /// answers false.
    ///
    /// The file then goes down the raw passthrough, which is correct --
    /// nothing here can read it better -- but silent. A user who types
    /// `rgx ocrword scan.png` gets nothing and no reason, which is the same
    /// gap the adapter-failure note closes from the other side. A caller that
    /// wants to say WHY a claimed file was searched raw can ask here.
    #[must_use]
    pub fn unavailable_claimants(&self, ext: &str) -> Vec<&'static str> {
        self.by_ext
            .get(ext)
            .into_iter()
            .flatten()
            .map(move |&i| &*self.adapters[i])
            .filter(|a| !a.available())
            .map(|a| a.name())
            .collect()
    }

    /// [`Self::candidates`] over a whole path rather than one extension, so a
    /// dotted declaration is reachable.
    ///
    /// `scan.ocr.jpg` is offered to the adapter that declared `ocr.jpg` before
    /// the one that declared `jpg`; if the first bails, the second still runs.
    /// An ordinary filename has one dot, resolves to exactly one key, and pays
    /// no more than [`Self::candidates`] does.
    pub fn candidates_for_path<'a>(&'a self, path: &'a str) -> PathCandidates<'a> {
        self.path_candidates(path, true)
    }

    /// The same walk, with the file's first bytes in hand, so an adapter that
    /// claims a magic prefix gets its turn when the name claimed nobody.
    ///
    /// The magic phase runs LAST: the name is the stronger claim, and a file
    /// whose extension an adapter understands is that adapter's business. Only
    /// when the name is silent — `data/0/2`, `LICENSE`, `Makefile` — do the
    /// bytes get a say.
    pub fn candidates_for_path_bytes<'a>(
        &'a self,
        path: &'a str,
        head: &'a [u8],
    ) -> PathCandidates<'a> {
        let mut c = self.path_candidates(path, true);
        c.head = Some(head);
        c
    }

    /// true if any adapter claims a byte prefix rather than an extension.
    ///
    /// A caller that would rather not read a file to find out can ask this
    /// first: with no magic claimant there is nothing a peek could answer,
    /// and the file's first bytes are not worth a syscall.
    pub fn has_magic_claimants(&self) -> bool {
        !self.by_magic.is_empty()
    }

    /// true if an available adapter claims these bytes by their magic.
    ///
    /// This is the question a caller can only ask with the bytes in hand, so
    /// it is the one question the raw path may not answer for free — which is
    /// why the caller reads a short window rather than the whole file.
    pub fn claims_magic(&self, head: &[u8]) -> bool {
        self.by_magic
            .iter()
            .any(|(i, magic)| head.starts_with(magic) && self.adapters[*i].available())
    }

    /// The same walk with the availability filter removed.
    ///
    /// `unavailable_claimants*` exists to name the adapters that
    /// `candidates` drops, so it must see the dropped ones; routing it
    /// through the filtered view returns an empty list for exactly the
    /// files it was written to explain.
    fn path_candidates<'a>(&'a self, path: &'a str, only_available: bool) -> PathCandidates<'a> {
        PathCandidates {
            reg: self,
            keys: extension_candidates(path),
            seen: Vec::new(),
            pending: None,
            only_available,
            head: None,
            magic_at: 0,
        }
    }

    /// [`Self::may_claim`] for a whole path; see [`Self::candidates_for_path`].
    pub fn may_claim_for_path(&self, path: &str) -> bool {
        let pol = policy();
        // `any`, not `next`, for the reason spelled out on `may_claim`.
        self.candidates_for_path(path)
            .any(|a| a.reach_needs_bytes() || pol != Policy::Source || a.reach() == Reach::Reveal)
    }

    /// [`Self::unavailable_claimants`] for a whole path; see
    /// [`Self::candidates_for_path`]. A `scan.ocr.jpg` whose OCR binary is
    /// missing is named here rather than searched raw in silence.
    #[must_use]
    pub fn unavailable_claimants_for_path(&self, path: &str) -> Vec<&'static str> {
        self.path_candidates(path, false)
            .filter(|a| !a.available())
            .map(|a| a.name())
            .collect()
    }
}

/// The adapters a path's extension keys resolve to, in chain order.
///
/// **Why `seen` exists.** One adapter that declares both `ocr.jpg` and `jpg`
/// would otherwise run twice for `scan.ocr.jpg`, and that cost is not
/// uniform — `Inspect` is the most expensive adapter per byte in the tree.
/// The vector is empty for a path whose extension nobody claims and for the
/// single-dot case, so a corpus of source files pays nothing: only a file
/// that reaches an adapter allocates, and those are the rare extensions.
pub struct PathCandidates<'a> {
    reg: &'a Registry,
    keys: ExtensionCandidates<'a>,
    /// Adapter indices already offered, so a dotted claim and the plain
    /// claim underneath it cannot run the same adapter twice.
    seen: Vec<usize>,
    pending: Option<core::slice::Iter<'a, usize>>,
    /// false only for the view that has to name what the filtered one drops.
    only_available: bool,
    /// The file's first bytes, when the caller has them. The magic phase
    /// needs them, and without them the phase does not run at all.
    head: Option<&'a [u8]>,
    /// How far the magic phase has walked the registry's magic table.
    magic_at: usize,
}

impl<'a> Iterator for PathCandidates<'a> {
    type Item = &'a dyn Adapter;

    fn next(&mut self) -> Option<&'a dyn Adapter> {
        loop {
            if let Some(list) = &mut self.pending {
                if let Some(&i) = list.next() {
                    if !self.seen.contains(&i) {
                        self.seen.push(i);
                        let a = &*self.reg.adapters[i];
                        if !self.only_available || a.available() {
                            return Some(a);
                        }
                    }
                    continue;
                }
                self.pending = None;
            }
            if let Some(key) = self.keys.next() {
                let Some(list) = self.reg.by_ext.get(key.as_ref()) else {
                    continue;
                };
                self.pending = Some(list.iter());
                continue;
            }
            // The name is silent. The bytes get their say, and only then: a
            // magic is a claim about the file's CONTENT, so it cannot outrank
            // a claim about the file's NAME.
            let head = self.head?;
            while self.magic_at < self.reg.by_magic.len() {
                let (i, magic) = self.reg.by_magic[self.magic_at];
                self.magic_at += 1;
                if !head.starts_with(magic) || self.seen.contains(&i) {
                    continue;
                }
                self.seen.push(i);
                let a = &*self.reg.adapters[i];
                if !self.only_available || a.available() {
                    return Some(a);
                }
            }
            return None;
        }
    }
}

/// The basename of `path` — everything after the last `/`, `\` or `!`, so a
/// Windows path parses the same as a POSIX one and a member's own name is
/// not read as part of the container's.
///
/// The `!` is the member separator: `bundle.zip!script.py` is the container
/// `bundle.zip` and the member `script.py`, and the *member's* extension is
/// what decides which adapter claims it. Reading the container's extension
/// instead would route every member of a zip back to the zip reader, and
/// the recursion would never reach the file inside. The member's own name
/// may carry `/` of its own (`docs/report.pdf`), and the last separator of
/// either kind wins, which is the same rule a filesystem path follows.
fn basename_of(path: &str) -> &str {
    let mut start = path.len();
    for (i, b) in path.bytes().enumerate().rev() {
        if b == b'/' || b == b'\\' || b == b'!' {
            break;
        }
        start = i;
    }
    &path[start..]
}

/// Lowercases an extension slice, borrowing when there is nothing to convert.
///
/// The ASCII fast path is not a micro-optimisation: this runs once per
/// candidate per file, and `to_lowercase` allocates. A path that is already
/// lowercase ASCII — nearly every path — borrows the original bytes instead.
fn fold_ext(ext: &str) -> Cow<'_, str> {
    if ext
        .bytes()
        .all(|b| b.is_ascii_lowercase() || !b.is_ascii_alphabetic())
    {
        Cow::Borrowed(ext)
    } else {
        Cow::Owned(ext.to_lowercase())
    }
}

/// Every extension key `path` can match, most specific first.
///
/// A single dot yields one key, which is every ordinary filename. A second
/// dot yields a dotted key *ahead* of it, so `scan.ocr.jpg` is offered as
/// `ocr.jpg` and then as `jpg`: an adapter that declares `ocr.jpg` runs
/// before one that declares `jpg`, and a bail still falls through to the
/// plain one. That is what makes a declaration like `"ocr.jpg"` meaningful —
/// an adapter may name a dotted extension and nothing else has to change.
///
/// The dots are read left to right and each suffix is yielded in turn, so
/// `a.b.c.jpg` is offered as `b.c.jpg`, `c.jpg`, `jpg` — longest first,
/// which is the order a "first match wins" chain needs. A name with no dot
/// yields nothing; `.gitignore` yields `gitignore`, matching what
/// [`extension_of`] has always returned for it.
pub fn extension_candidates(path: &str) -> ExtensionCandidates<'_> {
    ExtensionCandidates {
        basename: basename_of(path),
        scanned: 0,
    }
}

/// Iterator over a path's dotted extension suffixes; see [`extension_candidates`].
pub struct ExtensionCandidates<'a> {
    basename: &'a str,
    /// Bytes of `basename` already consumed, i.e. the start of the next suffix.
    scanned: usize,
}

impl<'a> Iterator for ExtensionCandidates<'a> {
    type Item = Cow<'a, str>;

    fn next(&mut self) -> Option<Cow<'a, str>> {
        let rest = &self.basename[self.scanned..];
        let dot = rest.find('.')?;
        self.scanned += dot + 1;
        Some(fold_ext(&self.basename[self.scanned..]))
    }
}

/// Lowercased file extension of `path` (empty slice when none).
///
/// The last of [`extension_candidates`] — the single component after the final
/// dot. The returned `Cow` is `Borrowed` for the common case (path already
/// lowercased, ASCII, no case to convert) and `Owned` only when a
/// non-ASCII byte forces allocation. Splits on both `/` and `\`, so a
/// Windows path like `a\b.c` is parsed the same as a POSIX path.
pub fn extension_of(path: &str) -> Cow<'_, str> {
    extension_candidates(path)
        .last()
        .unwrap_or(Cow::Borrowed(""))
}

// --- opt-in per-adapter profiling (RGX_PROFILE=1) ---
static PROFILE_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn profile_enabled() -> bool {
    PROFILE_ON.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn profile_init() {
    PROFILE_ON.store(true, core::sync::atomic::Ordering::Relaxed);
}

/// The shared profile map. It used to be a `static MAP` declared INSIDE
/// each of `profile_add` and `profile_dump`, which made two independent
/// `OnceLock`s: the add side wrote one and the dump side read the other,
/// permanently empty. One module-level static, one map.
#[cfg(feature = "std")]
static PROFILE_MAP: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<&'static str, (u64, u64)>>,
> = std::sync::OnceLock::new();

// Per-thread nesting depth, published by `process` for the adapters below.
// See `current_depth` for why this exists and what it is for.
#[cfg(feature = "std")]
std::thread_local! {
    static DEPTH: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// The archive nesting depth of the unit currently being extracted on this
/// thread. `0` outside any [`process`] call.
///
/// **This exists because a resource budget has to know where it is being
/// spent, and the budget cannot be told.** `MemberSink::new()` (the archive
/// family's work budget) is handed a fresh allowance by every adapter, so a
/// container nested inside a container was granted a second full budget rather
/// than a share of the first — with the shipped defaults a 4 MiB zip of zips
/// reached 4 TiB of expansion, because `max_depth` bounds the DEPTH of a tree
/// and never its total width times height.
///
/// `Adapter::extract(&self, data, path)` has no room for a depth and
/// `rgx-core` is `no_std`, so a thread-local is the one place the two halves
/// can meet: [`process`] sets it on the way in, and the adapters read it when
/// they build a sink. Nothing about the `Adapter` contract changes.
///
/// Returns 0 with `std` off, which restores the pre-existing behaviour rather
/// than inventing a ceiling.
#[cfg(feature = "std")]
pub fn current_depth() -> usize {
    DEPTH.try_with(|d| d.get()).unwrap_or(0)
}

/// See the module-level docs.
#[cfg(not(feature = "std"))]
pub fn current_depth() -> usize {
    0
}

/// Restores the previous depth on drop, so an early return out of `process`
/// cannot leave a worker permanently "nested".
///
/// Only ever held across the recursion in [`process`], never across an
/// adapter call, so the value an adapter sees is the depth of the container it
/// is extracting and not the depth of the entry inside it.
#[cfg(feature = "std")]
pub struct DepthGuard {
    #[cfg(feature = "std")]
    previous: usize,
}

#[cfg(feature = "std")]
impl DepthGuard {
    pub fn enter(depth: usize) -> Self {
        let previous = DEPTH.try_with(|d| d.replace(depth)).unwrap_or(0);
        Self { previous }
    }
}

#[cfg(feature = "std")]
impl Drop for DepthGuard {
    fn drop(&mut self) {
        let _ = DEPTH.try_with(|d| d.set(self.previous));
    }
}

#[cfg(feature = "std")]
pub fn profile_add(name: &'static str, ns: u64) {
    let map = PROFILE_MAP.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut m = map.lock().unwrap();
    let e = m.entry(name).or_insert((0, 0));
    e.0 += 1;
    e.1 += ns;
}

#[cfg(feature = "std")]
pub fn profile_dump() -> Vec<(&'static str, u64, u64)> {
    let map = PROFILE_MAP.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let m = map.lock().unwrap();
    m.iter().map(|(&k, &(c, t))| (k, c, t)).collect()
}

/// Run `path`/`data` through the adapter chain, appending every searchable
/// unit to `out`. `depth` is the current archive nesting depth (0 = real
/// file). Unclaimed files are emitted as-is under `via = "raw"`.
///
/// Every outcome puts the file's own bytes somewhere the searcher will read
/// them. An adapter that answers with `Text` or `Members` answers *for* the
/// file, and an adapter that answers `Bail` or `Err` is followed by the raw
/// bytes. The note an `Err` leaves behind is an extra unit, never the only
/// one: a corpus where a file the walk found cannot be searched at all is
/// less searchable than a corpus with no adapter in it, which is the opposite
/// of what the adapters are for.
///
/// Returns `true` when *this* invocation fell through to the raw
/// passthrough — i.e. no adapter produced anything and the single appended
/// unit is the input bytes (modulo encoding normalization). Callers use
/// that to give the file the raw on-disk treatment instead of searching a
/// copy. A member that recursed to raw inside a `Members` expansion does
/// NOT count: the outer adapter did produce output.
///
/// **The single unit is the whole rule.** A note beside the bytes -- an
/// adapter that failed, or an adapter whose external tool is not on PATH --
/// is a second unit, so the return is `false` and the caller searches the
/// units. A caller that reads `true` as "the file's own bytes, search it
/// raw" and drops the units drops the note with them, and the note is the
/// only thing that says what happened.
pub fn process(
    reg: &Registry,
    path: &str,
    data: &[u8],
    depth: usize,
    ctx: &Ctx,
    out: &mut Vec<Found>,
) -> bool {
    process_scoped(reg, path, data, depth, ctx, out, &[])
}

/// The facts of a file: what the pipeline knows, what the adapter
/// reported, and what the file inherits from its containers.
///
/// The adapter's own report is passed in rather than asked for here,
/// because the caller already has it and asking twice would parse the
/// file twice.
fn scoped_facts(path: &str, format: &str, reported: Vec<Field>, inherited: &[Field]) -> Vec<Field> {
    let mut facts = filter::file_facts(path, format);
    facts.extend(reported);
    facts.extend(inherited.iter().cloned());
    facts
}

/// [`process`], with the facts the file inherits from the containers it is
/// inside.
///
/// **What is inherited.** The facts of the containers above this file, and
/// only the ones that are not about the file itself: a member of
/// `archive.zip` is inside a zip, whatever its own name says, so it
/// inherits the container's `container` and `archive.entry` and the
/// adapter's own report about the archive. It does not inherit the
/// archive's path or extension -- those are the archive's, and the member
/// has its own.
///
/// The wrapper exists because the inheritance only matters one level
/// down, and every other caller of [`process`] has no container above the
/// file.
fn process_scoped(
    reg: &Registry,
    path: &str,
    data: &[u8],
    depth: usize,
    ctx: &Ctx,
    out: &mut Vec<Found>,
    inherited: &[Field],
) -> bool {
    // Publish the nesting depth for the adapters below, which build their work
    // budget and cannot be told otherwise -- `Adapter::extract` has no depth
    // parameter and this crate is `no_std`. See [`current_depth`].
    #[cfg(feature = "std")]
    let _depth_guard = DepthGuard::enter(depth);
    let mut bailed: Vec<&str> = Vec::new();
    // Notes held until the bottom: an adapter that errors does not end the
    // chain, so its note only becomes a unit if nothing later answers. The
    // adapter's name rides along because `via` is what `--json`'s `adapter`
    // field prints and what `--explain-engine` names: a note filed under
    // `raw` would report "no adapter ran" about a file an adapter did run on
    // and fail on, which is the one thing the note exists to prevent.
    let mut notes: Vec<(&'static str, String)> = Vec::new();
    let pol = policy();
    // The bytes are in hand, so the adapters that claim a magic prefix get
    // their turn too — after the ones that claim the name, never before.
    for adapter in reg.candidates_for_path_bytes(path, data) {
        // The policy is applied HERE rather than in the registry, because an
        // adapter that answers from the bytes cannot be answered without
        // them. Under `Source` a `Render` adapter does not get the file: the
        // bytes ripgrep can already read are kept, and the rendering is
        // asked for instead of answered with. Falling through to the raw
        // passthrough at the bottom of this function is that answer.
        if pol == Policy::Source
            && adapter.reach_for(data) == Reach::Render
            && !adapter.reach_needs_bytes()
        {
            bailed.push(adapter.name());
            continue;
        }
        #[cfg(feature = "std")]
        let outcome = {
            let (o, elapsed) = if profile_enabled() {
                let t = std::time::Instant::now();
                let r = adapter.extract(data, path);
                (r, Some(t.elapsed()))
            } else {
                (adapter.extract(data, path), None)
            };
            if let Some(e) = elapsed {
                profile_add(adapter.name(), e.as_nanos() as u64);
            }
            o
        };
        #[cfg(not(feature = "std"))]
        let outcome = adapter.extract(data, path);
        match outcome {
            Ok(Outcome::Text(text)) => {
                // The filter is the last word on the file: a file it
                // rejects is not in the corpus, and neither is a note about
                // it.
                if ctx.wants_facts() {
                    let facts =
                        scoped_facts(path, adapter.name(), adapter.facts(data, path), inherited);
                    if let Some(sink) = ctx.facts_sink.as_ref() {
                        sink.record(path, facts.clone());
                    }
                    if ctx.wants_filter() && !ctx.passes(&facts) {
                        return false;
                    }
                }
                // `Policy::Both` is the union, and the only mode in which a
                // `Render` format is searched twice. It is deliberately
                // scoped to a `Render` adapter's `Text`: a `Reveal` adapter's
                // output is not a view of the same lines (it is a view of
                // bytes the file does not contain in that form), so adding
                // the container's own bytes there would be a second answer to
                // a different question, not a fallback.
                //
                // EXCEPT when the adapter asked for the bytes and the file
                // turned out to be one ripgrep can read. Then the rendering
                // is a view of text that is also in the file, and the union
                // is the only answer that is neither a subset nor a loss:
                // searching just the file's bytes matches rg exactly and
                // throws away what the renderer found, and searching just the
                // rendering drops 39 lines of matches down to 9 on
                // `hyper-rustls-0.27.7/examples/sample.pem`. Measured over
                // the registry this is the difference between 4 files that
                // are a strict subset and 89 files that stop being a strict
                // superset -- and the union is 4 and 0.
                if policy() == Policy::Both && adapter.reach_for(data) == Reach::Render
                    || (policy() == Policy::Source
                        && adapter.reach_needs_bytes()
                        && adapter.reach_for(data) == Reach::Render)
                {
                    out.push(Found {
                        path: path.to_string(),
                        bytes: normalize_encoding(data.to_vec()),
                        via: "raw",
                    });
                }
                out.push(Found {
                    path: path.to_string(),
                    bytes: normalize_encoding(text),
                    via: adapter.name(),
                });
                return false;
            }
            Ok(Outcome::Members(members)) => {
                if depth >= ctx.max_depth {
                    out.push(Found {
                        path: path.to_string(),
                        bytes: format!("[rgx: max archive depth reached ({})]\n", depth)
                            .into_bytes(),
                        via: adapter.name(),
                    });
                    return false;
                }
                // The container's facts are inherited by its members: a
                // file inside a zip is inside a zip, whatever its own
                // name says, so a filter that asks about the container
                // has to be able to see it from the member it kept.
                //
                // `container` is the kind of container -- the adapter
                // that opened it -- and `archive.entry` is how many
                // entries it holds. Both are facts about the container
                // and not about the member, which is why they travel
                // down and are not recomputed for each member.
                let mut container_facts: Vec<Field> = Vec::new();
                if ctx.wants_facts() {
                    container_facts = adapter.facts(data, path);
                    container_facts.push(Field::new("container", adapter.name()));
                    container_facts.push(Field::new("archive.entry", &members.len().to_string()));
                }
                for (inner, bytes) in members.into_iter().take(ctx.max_members) {
                    // The member path is a **logical** path, not a filesystem
                    // one: the container's path, then `!`, then the member's
                    // own name. A `/` between the two levels would be a lie
                    // -- `bundle.zip/script.py` reads as a directory called
                    // `bundle.zip` holding a file `script.py`, and it makes
                    // the member's own `docs/report.pdf` indistinguishable
                    // from a second level of nesting. The member's name keeps
                    // the separators it had inside the container.
                    let inner_path = format!("{path}!{inner}");
                    process_scoped(
                        reg,
                        &inner_path,
                        &bytes,
                        depth + 1,
                        ctx,
                        out,
                        &container_facts,
                    );
                }
                return false;
            }
            Ok(Outcome::Bail(reason)) => {
                bailed.push(adapter.name());
                let _ = reason;
            }
            Err(e) => {
                // A **decline** is not a failure, and it must leave the
                // corpus exactly as it found it: no note, no line that was
                // not in the file, and the chain continues to the next
                // candidate. `decline!` is how an adapter says "this file
                // is not mine" or "I found nothing in it" — the ordinary
                // event that must not be reported as a failure.
                //
                // This is the distinction the note machinery below exists
                // to make: the note is for a file that IS this format and
                // could not be decoded. An adapter stepping aside is not
                // that, and a `.ts` that turns out to be TypeScript is not
                // that either.
                if e.is_decline() {
                    bailed.push(adapter.name());
                    continue;
                }
                // The note is an *extra* unit, never a replacement for the
                // file. This arm used to push the note and stop, which read
                // as "keep the corpus searchable" and was the opposite: every
                // extractor declines with `bail!`, and `bail!` arrives here
                // as `Err`, so a file whose adapter merely found nothing —
                // a PNG with no EXIF, a PEM the x509 walker cannot parse, a
                // `.tex` without `\documentclass` — lost its bytes entirely.
                // rgx then reported nothing for a file ripgrep reads, which
                // is the subset property one more time, reached through a
                // different door, and it cost 14,251 lines over 1,387 of the
                // 4,881 claimed files in the registry corpus.
                //
                // So the file's own bytes go in beside the note and both are
                // searched: the note still says what happened, and the bytes
                // are still there for the pattern that lives in them. The
                // rga issue #151 lesson — one bad file must not kill the
                // corpus search — holds, and now it also holds for a file
                // that is merely not what the adapter wanted.
                //
                // It must NOT stop the chain, though, and that is the part
                // this arm still got wrong. Every extractor is documented to
                // decline with `bail!`, so "the first adapter declined" and
                // "the first adapter had a hard failure" were the same event
                // -- and a decline therefore shadowed every later claimant
                // for the extension. `rgx-adapters-media`'s single-page TIFF
                // reader refusing a two-page file so the chain walker could
                // answer it did exactly that: the file fell to raw bytes and
                // the page the reader wanted was silently not in the output.
                //
                // The note is held and the loop continues, so the bytes
                // below are only reached when nothing later answers. `Bail`
                // above is silent by design (it is the ordinary "not my
                // file" and says nothing about the corpus), which is exactly
                // why the two cannot be treated alike. A note that is held
                // and then dropped — because a later adapter DID answer —
                // is correct: there was no failure to report about the
                // corpus, only about a claimant the next one superseded.
                notes.push((
                    adapter.name(),
                    format!(
                        "[rgx: adapter '{}' failed: {}]\n",
                        adapter.name(),
                        format!("{e:#}").lines().next().unwrap_or("")
                    ),
                ));
            }
        }
    }
    // no adapter (or all bailed): raw passthrough — rg-compatible fallback.
    //
    // When the extension IS claimed but every claimant's tool is missing, the
    // raw path is still the right answer, but silence is not: the file type
    // was known and unreadable, which is a different situation from "nothing
    // here claims it". A one-line note beside the bytes says which, the same
    // contract the adapter-failure note above honours.
    //
    // The filter comes first: a file the filter rejects is not in the
    // corpus, and a note about a file nobody asked for is noise.
    if ctx.wants_facts() {
        let mut facts = filter::file_facts(path, "raw");
        facts.extend(inherited.iter().cloned());
        if let Some(sink) = ctx.facts_sink.as_ref() {
            sink.record(path, facts.clone());
        }
        if ctx.wants_filter() && !ctx.passes(&facts) {
            return false;
        }
    }
    let missing = reg.unavailable_claimants_for_path(path);
    if !missing.is_empty() {
        out.push(Found {
            path: path.to_string(),
            bytes: format!(
                "[rgx: adapter '{}' skipped: its external tool is not on PATH]\n",
                missing.join("', '")
            )
            .into_bytes(),
            via: "raw",
        });
    }
    // Anything an earlier adapter reported while declining comes first, so a
    // file nobody could read still says why before it says what it holds.
    // `raw_only` is decided BEFORE the notes are moved out: an adapter that
    // produced a record did produce a record, and the return value says
    // whether the caller may treat this file as its own bytes. Reading it
    // off the presence of a unit would have made every failure note a silent
    // downgrade, which is how the note came to be invisible in the first
    // place.
    //
    // The skip note counts as a record, and it used not to: `missing` was
    // empty for every file whose claimant was on PATH, so a file whose
    // external tool is absent returned `true` with TWO units appended -- the
    // note and the file's own bytes -- and every caller reads `true` as
    // "the units are the file's own bytes, search it raw instead". The note
    // was built, allocated and dropped on the floor: `rgx` on a `.pub` file
    // with no `soffice` on PATH printed nothing about the tool, which is the
    // silence the note above exists to end. The rule the house writes down is
    // that `true` means the SOLE unit is the file's own bytes, and two units
    // are not one.
    let raw_only = notes.is_empty() && missing.is_empty();
    for (via, note) in notes {
        out.push(Found {
            path: path.to_string(),
            bytes: note.into_bytes(),
            via,
        });
    }
    out.push(Found {
        path: path.to_string(),
        bytes: normalize_encoding(data.to_vec()),
        via: "raw",
    });
    let _ = bailed;
    raw_only
}

/// Encoding post-processing (rga `postproc_encoding` parity): UTF-16 content
/// (BOM `FF FE` LE / `FE FF` BE) is transcoded to UTF-8 so plain-text search
/// actually matches it. Everything else passes through untouched.
pub fn normalize_encoding(bytes: Vec<u8>) -> Vec<u8> {
    let (le, rest) = match bytes.get(0..2) {
        Some([0xFF, 0xFE]) => (true, &bytes[2..]),
        Some([0xFE, 0xFF]) => (false, &bytes[2..]),
        _ => return bytes,
    };
    let units: Vec<u16> = rest
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| {
            if le {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Upper;
    impl Adapter for Upper {
        fn name(&self) -> &'static str {
            "upper"
        }
        fn extensions(&self) -> &'static [&'static str] {
            &["up"]
        }
        fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
            Ok(Outcome::Text(
                String::from_utf8_lossy(data).to_uppercase().into_bytes(),
            ))
        }
    }

    /// An adapter whose answer depends on the FILE, not on the extension:
    /// text is a rendering of something ripgrep already reads, binary is a
    /// container it cannot. The `.pem` and the `.der` are the same adapter.
    struct ByBytes;
    impl Adapter for ByBytes {
        fn name(&self) -> &'static str {
            "bybytes"
        }
        fn extensions(&self) -> &'static [&'static str] {
            &["bb"]
        }
        fn reach_needs_bytes(&self) -> bool {
            true
        }
        fn reach_for(&self, data: &[u8]) -> Reach {
            if data.contains(&0) {
                Reach::Reveal
            } else {
                Reach::Render
            }
        }
        fn extract(&self, _data: &[u8], _path: &str) -> Result<Outcome> {
            Ok(Outcome::Text(
                b"RENDERED
"
                .to_vec(),
            ))
        }
    }

    /// One extension, two answers, and the default policy has to give each
    /// file the right one.
    ///
    /// The binary file has no readable bytes to keep, so it is rendered
    /// alone. The text file is searched TWICE under the default: once on its
    /// own bytes, which is what ripgrep reads, and once on the rendering,
    /// which is a view of text derived from those bytes. Either alone is
    /// wrong -- the file alone matches rg exactly and throws away what the
    /// renderer found, the rendering alone drops 39 lines of matches down to
    /// 9 on `hyper-rustls-0.27.7/examples/sample.pem` -- so the union is the
    /// only answer that is neither a subset nor a loss.
    #[test]
    fn reach_is_a_property_of_the_file_and_not_of_the_extension() {
        for (bytes, want) in [
            (
                b"plain text
"
                .as_slice(),
                "RENDERED
",
            ),
            (
                b"bin\0ary".as_slice(),
                "RENDERED
",
            ),
        ] {
            under_policy(Policy::Source, || {
                let reg = Registry::new(vec![Box::new(ByBytes)]);
                // The registry cannot answer without the bytes, so the file
                // is read: answering "no" here is the subset property again.
                assert!(reg.may_claim("bb"), "the file was never read");
                let mut out = Vec::new();
                process(&reg, "a.bb", bytes, 0, &Ctx::default(), &mut out);
                let binary = bytes.contains(&0);
                let expect = if binary { 1 } else { 2 };
                assert_eq!(out.len(), expect, "{want}");
                assert_eq!(&*out[out.len() - 1].bytes, want.as_bytes(), "{want}");
                if binary {
                    assert_eq!(out[0].via, "bybytes");
                } else {
                    // the file's own bytes first, then the rendering
                    assert_eq!(out[0].via, "raw");
                    assert_eq!(&*out[0].bytes, bytes);
                    assert_eq!(out[1].via, "bybytes");
                }
            });
        }
    }

    /// The rendering is still reachable, on request, for both files.
    #[test]
    fn the_rendering_is_still_asked_for_on_request() {
        for bytes in [
            b"plain text
"
            .as_slice(),
            b"bin\0ary".as_slice(),
        ] {
            under_policy(Policy::Render, || {
                let reg = Registry::new(vec![Box::new(ByBytes)]);
                let mut out = Vec::new();
                process(&reg, "a.bb", bytes, 0, &Ctx::default(), &mut out);
                assert_eq!(out.len(), 1);
                assert_eq!(out[0].via, "bybytes");
            });
        }
    }

    /// A `Render` adapter that does NOT ask for the bytes keeps the cheap
    /// answer, so `.html` and `.md` stay off the read path entirely.
    #[test]
    fn an_adapter_that_does_not_ask_is_still_answered_without_the_bytes() {
        struct Plain;
        impl Adapter for Plain {
            fn name(&self) -> &'static str {
                "plain"
            }
            fn extensions(&self) -> &'static [&'static str] {
                &["pl"]
            }
            fn reach(&self) -> Reach {
                Reach::Render
            }
            fn extract(&self, _d: &[u8], _p: &str) -> Result<Outcome> {
                Ok(Outcome::Text(
                    b"RENDERED
"
                    .to_vec(),
                ))
            }
        }
        under_policy(Policy::Source, || {
            let reg = Registry::new(vec![Box::new(Plain)]);
            assert!(!reg.may_claim("pl"), "a Render file is not read at all");
        });
    }

    /// A `Render` adapter ahead of a `Reveal` one for the same extension
    /// must not answer for the wrong one: the `Reveal` adapter behind it is
    /// the one that reads the file.
    #[test]
    fn may_claim_looks_past_a_render_adapter_at_a_reveal_one() {
        under_policy(Policy::Source, || {
            let reg = Registry::new(vec![Box::new(ByBytes), Box::new(Upper)]);
            assert!(
                reg.may_claim("up"),
                "the Reveal adapter behind it was missed"
            );
        });
    }

    struct Bailer;
    impl Adapter for Bailer {
        fn name(&self) -> &'static str {
            "bailer"
        }
        fn extensions(&self) -> &'static [&'static str] {
            &["up"]
        }
        fn extract(&self, _data: &[u8], _path: &str) -> Result<Outcome> {
            Ok(Outcome::Bail("not mine".into()))
        }
    }

    #[test]
    fn bail_falls_through_to_next_adapter() {
        let reg = Registry::new(vec![Box::new(Bailer), Box::new(Upper)]);
        let mut out = Vec::new();
        process(&reg, "a.up", b"hi", 0, &Ctx::default(), &mut out);
        assert_eq!(out[0].bytes, b"HI");
    }

    #[test]
    fn unclaimed_file_is_raw_passthrough() {
        let reg = Registry::new(vec![Box::new(Upper)]);
        let mut out = Vec::new();
        process(&reg, "a.txt", b"hello", 0, &Ctx::default(), &mut out);
        assert_eq!(out[0].via, "raw");
        assert_eq!(out[0].bytes, b"hello");
    }

    /// An adapter whose tool is missing: it claims the extension but
    /// `available()` is false, so `candidates` filters it out and the file
    /// goes raw. That is the right answer, but silence is not -- a user who
    /// named the file type gets a note saying which adapter was skipped, the
    /// same contract the adapter-failure note honours from the other side.
    struct Unavailable;
    impl Adapter for Unavailable {
        fn name(&self) -> &'static str {
            "unavailable"
        }
        fn extensions(&self) -> &'static [&'static str] {
            &["gone"]
        }
        fn available(&self) -> bool {
            false
        }
        fn extract(&self, _data: &[u8], _path: &str) -> Result<Outcome> {
            unreachable!("a filtered-out adapter is never asked to extract")
        }
    }

    #[test]
    fn a_claimed_extension_with_no_available_adapter_says_so() {
        let reg = Registry::new(vec![Box::new(Unavailable), Box::new(Upper)]);
        assert!(
            !reg.may_claim("gone"),
            "an unavailable claimant must not make may_claim true"
        );
        assert_eq!(
            reg.unavailable_claimants("gone"),
            vec!["unavailable"],
            "the name of the skipped adapter must be recoverable"
        );
        // The unclaimed extension stays silent: nothing claimed it.
        assert!(reg.unavailable_claimants("txt").is_empty());

        let mut out = Vec::new();
        let raw = process(&reg, "a.gone", b"payload", 0, &Ctx::default(), &mut out);
        assert_eq!(out.len(), 2, "note plus the file's own bytes, got {out:?}");
        assert!(
            !raw,
            "a file with a note beside it is not the raw passthrough: the caller \
             reads `true` as 'the units are the file's own bytes' and drops the \
             note, and the note is the only thing that says the tool is missing"
        );
        assert!(
            out[0]
                .bytes
                .starts_with(b"[rgx: adapter 'unavailable' skipped:"),
            "the note must name the skipped adapter, got {:?}",
            String::from_utf8_lossy(&out[0].bytes)
        );
        assert_eq!(out[1].bytes, b"payload", "the bytes must still be searched");
    }

    /// A `Render` adapter: it reads a file ripgrep can already read, and its
    /// output drops the half of it that is markup. The two bytes below are
    /// the whole disagreement — `visible` survives the render, `hidden` does
    /// not, and the file is plain text either way.
    struct Renderer;
    impl Adapter for Renderer {
        fn name(&self) -> &'static str {
            "renderer"
        }
        fn extensions(&self) -> &'static [&'static str] {
            &["ren"]
        }
        fn reach(&self) -> Reach {
            Reach::Render
        }
        fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
            let src = String::from_utf8_lossy(data);
            let kept: String = src
                .lines()
                .filter(|l| !l.contains("hidden"))
                .collect::<Vec<_>>()
                .join("\n");
            Ok(Outcome::Text(kept.into_bytes()))
        }
    }

    /// The policy is process-wide, so the tests that move it take this lock
    /// and put it back, or a test running beside them would see a registry
    /// resolve under the wrong rule.
    static POLICY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn under_policy<R>(p: Policy, f: impl FnOnce() -> R) -> R {
        struct Reset(Policy);
        impl Drop for Reset {
            fn drop(&mut self) {
                set_policy(self.0);
            }
        }
        let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let was = policy();
        set_policy(p);
        let _reset = Reset(was);
        f()
    }

    /// The defect this whole policy exists for. `Source` is the default, and
    /// under it a rendering adapter is not a candidate at all: the file keeps
    /// its own bytes, which is what makes rgx a superset of ripgrep here
    /// rather than a strict subset of it.
    #[test]
    fn a_render_adapter_does_not_get_a_file_ripgrep_already_reads() {
        let reg = Registry::new(vec![Box::new(Renderer)]);
        under_policy(Policy::Source, || {
            assert!(!reg.may_claim("ren"), "the walk must take the raw path");
            let mut out = Vec::new();
            assert!(process(
                &reg,
                "a.ren",
                b"visible\nhidden\n",
                0,
                &Ctx::default(),
                &mut out
            ));
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].via, "raw");
            assert_eq!(out[0].bytes, b"visible\nhidden\n");
        });
    }

    /// `Render` is the behaviour every rgx before this had, and it is what
    /// `RGX_ADAPTER_VIEW=render` restores.
    #[test]
    fn the_render_policy_keeps_the_adapter_view() {
        let reg = Registry::new(vec![Box::new(Renderer)]);
        under_policy(Policy::Render, || {
            assert!(reg.may_claim("ren"));
            let mut out = Vec::new();
            assert!(!process(
                &reg,
                "a.ren",
                b"visible\nhidden\n",
                0,
                &Ctx::default(),
                &mut out
            ));
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].via, "renderer");
            assert_eq!(out[0].bytes, b"visible");
        });
    }

    /// `Both` is the union, and its cost is the point of the measurement: the
    /// same line arrives twice, once from each view, under two line numbers.
    #[test]
    fn the_both_policy_reports_the_source_and_the_rendering() {
        let reg = Registry::new(vec![Box::new(Renderer)]);
        under_policy(Policy::Both, || {
            let mut out = Vec::new();
            process(
                &reg,
                "a.ren",
                b"visible\nhidden\n",
                0,
                &Ctx::default(),
                &mut out,
            );
            assert_eq!(out.len(), 2);
            assert_eq!(out[0].via, "raw");
            assert_eq!(out[0].bytes, b"visible\nhidden\n");
            assert_eq!(out[1].via, "renderer");
            assert_eq!(out[1].bytes, b"visible");
        });
    }

    /// The policy only ever takes files *away* from adapters that were already
    /// rendering; a `Reveal` adapter — every archive, every binary container —
    /// is untouched in all three policies. This is the test that keeps the
    /// `.zst` result (rgx reading compressed content that rg cannot) from
    /// being "fixed" into parity with rg by turning the raw path loose.
    #[test]
    fn a_reveal_adapter_keeps_the_file_in_every_policy() {
        for p in [Policy::Source, Policy::Render, Policy::Both] {
            under_policy(p, || {
                let reg = Registry::new(vec![Box::new(Upper)]);
                assert!(reg.may_claim("up"), "{p:?} took the file off the adapter");
                let mut out = Vec::new();
                process(&reg, "a.up", b"hi", 0, &Ctx::default(), &mut out);
                assert_eq!(out.len(), 1, "{p:?}");
                assert_eq!(out[0].via, "upper", "{p:?}");
            });
        }
    }

    /// An adapter that found nothing, which is what every `bail!` is.
    struct Nothing;
    impl Adapter for Nothing {
        fn name(&self) -> &'static str {
            "nothing"
        }
        fn extensions(&self) -> &'static [&'static str] {
            &["nul"]
        }
        fn extract(&self, _data: &[u8], _path: &str) -> Result<Outcome> {
            bail!("no readable text")
        }
    }

    /// A file no adapter can read is still a file ripgrep reads. The `Err`
    /// arm used to push its note and stop, and because every extractor
    /// declines with `bail!`, that is the arm nearly every "nothing here"
    /// took: rgx printed nothing at all for a file the walk had found, which
    /// is a strict subset of ripgrep reached through a different door than
    /// the rendering adapters. The note is still emitted — it is the record
    /// of what happened — and the file's own bytes go in beside it.
    #[test]
    fn a_failed_adapter_leaves_the_file_searchable() {
        let reg = Registry::new(vec![Box::new(Nothing)]);
        let mut out = Vec::new();
        // an adapter did produce a record, so this is not a raw passthrough
        assert!(!process(
            &reg,
            "a.nul",
            b"ripgrep reads all of this\n",
            0,
            &Ctx::default(),
            &mut out
        ));
        assert_eq!(out.len(), 2, "{out:?}");
        assert_eq!(
            out[0].via, "nothing",
            "the note records the failure: {out:?}"
        );
        assert!(
            out[0]
                .bytes
                .starts_with(b"[rgx: adapter 'nothing' failed: "),
            "{out:?}"
        );
        assert_eq!(out[1].via, "raw");
        assert_eq!(
            out[1].bytes, b"ripgrep reads all of this\n",
            "the file, byte for byte"
        );
        assert_eq!(out[0].path, out[1].path, "one file, two views: {out:?}");
    }

    /// `Bail` is the clean decline: the chain continues, and a file no
    /// adapter wants reaches the raw searcher on its own, with no note at
    /// all. `Err` differs in two ways — it stops the chain, and it leaves a
    /// record — which is why the record is not the file.
    #[test]
    fn a_bailed_adapter_falls_through_to_the_file() {
        let reg = Registry::new(vec![Box::new(Bailer)]);
        let mut out = Vec::new();
        assert!(process(&reg, "a.up", b"hi", 0, &Ctx::default(), &mut out));
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].via, "raw");
        assert_eq!(out[0].bytes, b"hi");
    }

    #[test]
    fn utf16_bom_is_transcoded() {
        let mut utf16le = vec![0xFF, 0xFE];
        utf16le.extend_from_slice(
            &"ZIRCALOY"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        let mut out = Vec::new();
        let reg = Registry::new(vec![]);
        process(&reg, "a.txt", &utf16le, 0, &Ctx::default(), &mut out);
        assert_eq!(out[0].bytes, b"ZIRCALOY");

        let mut utf16be = vec![0xFE, 0xFF];
        utf16be.extend_from_slice(
            &"rod"
                .encode_utf16()
                .flat_map(|u| u.to_be_bytes())
                .collect::<Vec<u8>>(),
        );
        let mut out = Vec::new();
        process(&reg, "b.txt", &utf16be, 0, &Ctx::default(), &mut out);
        assert_eq!(out[0].bytes, b"rod");
    }

    // -----------------------------------------------------------------------
    // The filter and the facts
    // -----------------------------------------------------------------------

    /// An adapter that reports facts about the file it was given, and
    /// hands over a container whose members are the file's own text.
    struct Container;
    impl Adapter for Container {
        fn name(&self) -> &'static str {
            "box"
        }
        fn extensions(&self) -> &'static [&'static str] {
            &["box"]
        }
        fn facts(&self, _data: &[u8], _path: &str) -> Vec<Field> {
            vec![Field::new("box.kind", "crate")]
        }
        fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
            Ok(Outcome::Members(vec![(
                "inner.txt".to_string(),
                data.to_vec(),
            )]))
        }
    }

    /// An adapter that reports a fact and renders the file.
    struct Tagger;
    impl Adapter for Tagger {
        fn name(&self) -> &'static str {
            "tagger"
        }
        fn extensions(&self) -> &'static [&'static str] {
            &["tag"]
        }
        fn facts(&self, _data: &[u8], _path: &str) -> Vec<Field> {
            vec![Field::new("author", "Jane Doe")]
        }
        fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
            Ok(Outcome::Text(data.to_vec()))
        }
    }

    fn ctx_with(filter_text: &str) -> Ctx {
        Ctx {
            filter: Some(filter::Filter::parse(filter_text).expect("the filter parses")),
            ..Ctx::default()
        }
    }

    #[test]
    fn a_file_the_filter_rejects_produces_no_unit() {
        let reg = Registry::new(vec![Box::new(Tagger)]);
        let mut out = Vec::new();
        let ctx = ctx_with("author:\"John Doe\"");
        assert!(!process(&reg, "a.tag", b"hello", 0, &ctx, &mut out));
        assert!(out.is_empty(), "a rejected file leaves no unit: {out:?}");
    }

    #[test]
    fn a_file_the_filter_keeps_produces_its_unit() {
        let reg = Registry::new(vec![Box::new(Tagger)]);
        let mut out = Vec::new();
        let ctx = ctx_with("author:\"Jane Doe\"");
        assert!(!process(&reg, "a.tag", b"hello", 0, &ctx, &mut out));
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].bytes, b"hello");
    }

    #[test]
    fn a_member_inherits_the_facts_of_its_container() {
        let reg = Registry::new(vec![Box::new(Container)]);
        let mut out = Vec::new();
        // The member's own facts do not mention the container; the
        // container's do, and they travel down to the member.
        let ctx = ctx_with("box:kind");
        process(&reg, "a.box", b"hello", 0, &ctx, &mut out);
        assert_eq!(out.len(), 1, "the member survived the filter: {out:?}");
        assert_eq!(out[0].path, "a.box!inner.txt");
    }

    #[test]
    fn a_member_is_filtered_by_its_own_facts_too() {
        let reg = Registry::new(vec![Box::new(Container)]);
        let mut out = Vec::new();
        // The member's extension is `txt`, and the container's are not
        // inherited: the archive is a `.box`, the member is a `.txt`.
        let ctx = ctx_with("ext:box");
        process(&reg, "a.box", b"hello", 0, &ctx, &mut out);
        assert!(
            out.is_empty(),
            "the member's own extension is `txt`: {out:?}"
        );
    }

    #[test]
    fn a_container_reports_its_kind_and_its_entry_count() {
        let reg = Registry::new(vec![Box::new(Container)]);
        let mut out = Vec::new();
        let ctx = ctx_with("container:box AND archive:entry");
        process(&reg, "a.box", b"hello", 0, &ctx, &mut out);
        assert_eq!(out.len(), 1, "the member kept both facts: {out:?}");
    }

    #[test]
    fn a_raw_file_is_filtered_by_its_path_and_extension() {
        // No adapter claims `.txt`, so the file is raw, and the raw path
        // in the pipeline is the one that answers for it.
        let reg = Registry::new(vec![]);
        let mut out = Vec::new();
        let ctx = ctx_with("ext:txt");
        assert!(process(&reg, "a.txt", b"hello", 0, &ctx, &mut out));
        assert_eq!(out.len(), 1, "{out:?}");

        let mut out = Vec::new();
        let ctx = ctx_with("ext:zip");
        process(&reg, "a.txt", b"hello", 0, &ctx, &mut out);
        assert!(out.is_empty(), "the raw file was filtered out: {out:?}");
    }

    #[test]
    fn no_filter_means_no_facts_are_assembled() {
        // The adapter's `facts` is not called when there is no filter, so
        // an adapter that would fail on the question is never asked it.
        struct Grumpy;
        impl Adapter for Grumpy {
            fn name(&self) -> &'static str {
                "grumpy"
            }
            fn extensions(&self) -> &'static [&'static str] {
                &["gmp"]
            }
            fn facts(&self, _data: &[u8], _path: &str) -> Vec<Field> {
                panic!("the facts are only asked when a filter is in play");
            }
            fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
                Ok(Outcome::Text(data.to_vec()))
            }
        }
        let reg = Registry::new(vec![Box::new(Grumpy)]);
        let mut out = Vec::new();
        process(&reg, "a.gmp", b"hello", 0, &Ctx::default(), &mut out);
        assert_eq!(out.len(), 1);
    }
}

// The oracle is the standard library's parser, and the `no_std` *test*
// build links the standard library even though the crate does not: the
// test harness is not `no_std`. Gating this on the `std` feature would
// take the only curated oracle out of the configuration the parser was
// written for.
#[cfg(test)]
mod no_std_float_tests {
    use super::*;

    /// The `no_std` float parser against the standard library's, over what
    /// RFC 8259 allows plus the shapes that must be refused.
    #[test]
    fn parse_decimal_agrees_with_std() {
        let ok = [
            "0",
            "-0",
            "1",
            "-1",
            "3.14159",
            "-3.14159",
            "0.5",
            "1e3",
            "1E3",
            "1e+3",
            "1e-3",
            "-2.5e10",
            "0.0",
            "123456789.123456789",
            "0.1",
            "0.2",
            "0.3",
            "1.5e-7",
            "9.999999999999999e22",
        ];
        for s in ok {
            let want: f64 = s.parse().expect("std should accept");
            let got = parse_decimal(s).unwrap_or_else(|_| panic!("rejected {s}"));
            assert_eq!(
                got.to_bits(),
                want.to_bits(),
                "{s}: no_std {got} vs std {want}"
            );
        }

        // The extremes are exact now, not merely close. They were the whole
        // reason this parser is written over a bignum: scaling by repeated
        // multiplication gave 1e308 a ULP of error and turned
        // 2.2250738585072014e-308 into zero.
        for s in [
            "1e308",
            "1e-308",
            "2.2250738585072014e-308",
            "1e300",
            "5e-324",
            "4.9e-324",
            "1e-324",
            "2.5e-324",
            "1.7976931348623157e308",
            "1e23",
            "1e-23",
            "9.999999999999999e22",
        ] {
            let want: f64 = s.parse().expect("std should accept");
            let got = parse_decimal(s).unwrap_or_else(|_| panic!("rejected {s}"));
            assert_eq!(
                got.to_bits(),
                want.to_bits(),
                "{s}: no_std {got:?} vs std {want:?}"
            );
        }

        // Refusals. RFC 8259 allows no leading `+`, no bare `.5` or `5.`, no
        // leading zero on a multi-digit integer part, and no infinities or
        // NaN. Rust's own parser is MORE permissive than that -- it accepts
        // `.5`, `+1`, `inf` and `NaN` -- so this is a case where the two
        // deliberately disagree, and `std` is not the oracle.
        for s in [
            "", ".", "-", "+1", ".5", "5.", "1e", "1e+", "01", "-01", "00", "1.2.3", "abc", "1 2",
            "--1", "1e1e1", "0x10", "inf", "NaN", "infinity", "1,5",
        ] {
            assert!(
                parse_decimal(s).is_err(),
                "{s:?}: a JSON number parser must refuse this"
            );
        }
    }
}

#[cfg(test)]
mod extension_of_tests {
    use super::{
        bail, extension_candidates, extension_of, process, Adapter, Ctx, Outcome, Registry, Result,
    };
    use alloc::borrow::Cow;
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn lowercases_uppercase_extension() {
        assert_eq!(extension_of("foo.RS").as_ref(), "rs");
        assert_eq!(extension_of("a/b/c.Py").as_ref(), "py");
    }

    #[test]
    fn handles_backslash_windows_paths() {
        assert_eq!(extension_of(r"a\b\c.rs").as_ref(), "rs");
    }

    #[test]
    fn returns_empty_for_no_extension() {
        assert_eq!(extension_of("Makefile").as_ref(), "");
        assert_eq!(extension_of("a/b/c").as_ref(), "");
    }

    #[test]
    fn empty_path_returns_empty() {
        assert_eq!(extension_of("").as_ref(), "");
    }

    #[test]
    fn ascii_lowercase_path_returns_borrowed() {
        let path = "a/b/c.rs";
        let ext = extension_of(path);
        assert!(matches!(ext, Cow::Borrowed(_)));
        assert_eq!(ext.as_ref(), "rs");
    }

    // --- composite (dotted) extensions ---

    /// Claims `ocr.jpg` only: the shape an OCR adapter needs, where the
    /// ordinary `jpg` reader must not fire on every photo.
    struct Ocr;
    impl Adapter for Ocr {
        fn name(&self) -> &'static str {
            "ocr"
        }
        fn extensions(&self) -> &'static [&'static str] {
            &["ocr.jpg"]
        }
        fn extract(&self, _d: &[u8], _p: &str) -> Result<Outcome> {
            Ok(Outcome::Text(b"ocr text".to_vec()))
        }
    }

    fn names<'a>(reg: &'a Registry, path: &str) -> Vec<&'a str> {
        reg.candidates_for_path(path).map(|a| a.name()).collect()
    }

    /// Claims plain `jpg` — the adapter the dotted claim sits in front of.
    struct Jpeg;
    impl Adapter for Jpeg {
        fn name(&self) -> &'static str {
            "jpeg"
        }
        fn extensions(&self) -> &'static [&'static str] {
            &["jpg"]
        }
        fn extract(&self, _d: &[u8], _p: &str) -> Result<Outcome> {
            Ok(Outcome::Text(b"jpeg meta".to_vec()))
        }
    }

    #[test]
    fn candidates_are_offered_longest_suffix_first() {
        let got: Vec<String> = extension_candidates("scan.ocr.jpg")
            .map(|c| c.into_owned())
            .collect();
        assert_eq!(got, vec![String::from("ocr.jpg"), String::from("jpg")]);
    }

    #[test]
    fn a_single_dot_yields_exactly_one_candidate() {
        let got: Vec<String> = extension_candidates("main.rs")
            .map(|c| c.into_owned())
            .collect();
        assert_eq!(got, vec![String::from("rs")]);
        assert!(
            matches!(
                extension_candidates("main.rs").next(),
                Some(Cow::Borrowed(_))
            ),
            "the common case must borrow, not allocate"
        );
    }

    #[test]
    fn extension_of_is_unchanged_by_the_candidate_iterator() {
        // The dots in `extension_of`'s contract are the ones a reader relies
        // on: a dotfile is all extension, a bare name is none, a Windows
        // separator is not part of it.
        assert_eq!(extension_of("scan.ocr.jpg").as_ref(), "jpg");
        assert_eq!(extension_of(".gitignore").as_ref(), "gitignore");
        assert_eq!(extension_of("Makefile").as_ref(), "");
        assert_eq!(extension_of(r"a\b\c.rs").as_ref(), "rs");
        assert_eq!(extension_of("").as_ref(), "");
    }

    #[test]
    fn a_dotted_declaration_is_reachable_from_a_double_extension() {
        let reg = Registry::new(vec![Box::new(Ocr)]);
        assert_eq!(names(&reg, "scan.ocr.jpg"), vec!["ocr"]);
        // ...and the plain name it shadows does not reach it.
        assert!(names(&reg, "scan.jpg").is_empty());
    }

    #[test]
    fn the_dotted_claim_runs_before_the_plain_one_and_bail_falls_through() {
        struct Bailer;
        impl Adapter for Bailer {
            fn name(&self) -> &'static str {
                "ocr"
            }
            fn extensions(&self) -> &'static [&'static str] {
                &["ocr.jpg"]
            }
            fn extract(&self, _d: &[u8], _p: &str) -> Result<Outcome> {
                // `Outcome::Bail`, not `bail!`: only a Bail falls through to
                // the next adapter. An Err is a failure worth reporting and
                // ends the chain with a note beside the file's own bytes.
                Ok(Outcome::Bail("no text in this image".into()))
            }
        }
        let reg = Registry::new(vec![Box::new(Bailer), Box::new(Jpeg)]);
        assert_eq!(names(&reg, "scan.ocr.jpg"), vec!["ocr", "jpeg"]);
        let mut out = Vec::new();
        let passthrough = process(
            &reg,
            "scan.ocr.jpg",
            b"raw bytes",
            0,
            &Ctx::default(),
            &mut out,
        );
        assert!(!passthrough, "the plain adapter answered after the bail");
        assert_eq!(out[0].via, "jpeg");
    }

    #[test]
    fn an_adapter_declaring_both_keys_runs_once() {
        struct Both;
        impl Adapter for Both {
            fn name(&self) -> &'static str {
                "both"
            }
            fn extensions(&self) -> &'static [&'static str] {
                &["ocr.jpg", "jpg"]
            }
            fn extract(&self, _d: &[u8], _p: &str) -> Result<Outcome> {
                Ok(Outcome::Text(b"x".to_vec()))
            }
        }
        let reg = Registry::new(vec![Box::new(Both), Box::new(Jpeg)]);
        assert_eq!(
            names(&reg, "scan.ocr.jpg"),
            vec!["both", "jpeg"],
            "running the dotted and the plain claim of one adapter twice is \
             the cost `dedup_exts` exists to avoid"
        );
    }

    #[test]
    fn an_unavailable_dotted_claimant_is_named_by_path() {
        struct Absent;
        impl Adapter for Absent {
            fn name(&self) -> &'static str {
                "absent"
            }
            fn extensions(&self) -> &'static [&'static str] {
                &["ocr.jpg"]
            }
            fn available(&self) -> bool {
                false
            }
            fn extract(&self, _d: &[u8], _p: &str) -> Result<Outcome> {
                bail!("never runs")
            }
        }
        let reg = Registry::new(vec![Box::new(Absent)]);
        assert_eq!(
            reg.unavailable_claimants_for_path("a.ocr.jpg"),
            vec!["absent"]
        );
    }
}
