// SPDX-License-Identifier: Apache-2.0

//! Automatic search algorithm and engine detector.
//!
//! Inspects query parameters, CLI flags, target paths, filesystem structures,
//! and pattern characteristics to dynamically choose the optimal search engine:
//!
//! - [`EngineChoice::PackStore`]: Contiguous prepared-pack storage with
//!   amortized sequential reading and zero per-file syscalls (~6x-50x speedup).
//! - [`EngineChoice::RgxDirect`]: In-process SIMD-accelerated search with
//!   zero packaging overhead for single files, streaming stdin, or ad-hoc walks.

use std::path::{Path, PathBuf};

use crate::Args;

/// The search engine selected for a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineChoice {
    /// Prepared-pack storage tier (`--engine tv`), the tier the paper calls the
    /// storage side of the diodic architecture.
    PackStore,
    /// Direct in-process SIMD byte search (`rgx-core`).
    RgxDirect,
}

impl EngineChoice {
    /// String identifier for this engine choice.
    pub fn as_str(&self) -> &'static str {
        match self {
            EngineChoice::PackStore => "tv",
            EngineChoice::RgxDirect => "rgx",
        }
    }
}

/// The result of automatic detection including rationale and resolved store path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionResult {
    /// The chosen search engine.
    pub engine: EngineChoice,
    /// Explanation of why this engine was selected.
    pub reason: String,
    /// Resolved path to the pack store directory, if applicable.
    pub store_path: Option<PathBuf>,
    /// Whether the caller asked for this engine by name.
    ///
    /// This is not cosmetic. The freshness gate below may decline an
    /// automatic promotion to the pack engine: a store whose manifest the
    /// filesystem disagrees with answers from bytes that no longer exist,
    /// and an automatic decision may not hand back that answer unannounced.
    /// An explicit request may still be honoured -- the user asked for the
    /// trade, and `run_tv_query` warns aloud -- so what the gate declines on
    /// its own, the caller can still name. Adapter-claimed files are not a
    /// reason to decline: `run_tv_query` runs the same adapter pipeline over
    /// each borrowed slice that the direct path runs over the file, so the
    /// two answers agree (see the equivalence test in `tests/cli.rs`).
    pub explicit: bool,
}

/// Automatic detector for selecting the most efficient search algorithm.
pub struct AutoDetector;

impl AutoDetector {
    /// Detects the optimal search engine for the given arguments.
    pub fn detect(args: &Args) -> DetectionResult {
        // 1. Explicit CLI override (--tv, --engine, --tv-store)
        if args.tv || args.tv_store.is_some() {
            let store = Self::find_store(args);
            return DetectionResult {
                engine: EngineChoice::PackStore,
                reason: if args.tv {
                    "explicit --tv flag passed on CLI".to_string()
                } else {
                    format!(
                        "explicit --tv-store specified ({})",
                        store
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "unindexed".to_string())
                    )
                },
                store_path: store,
                explicit: true,
            };
        }

        if let Some(engine_str) = &args.engine {
            match engine_str.to_ascii_lowercase().as_str() {
                "tv" | "tesla" | "tesla-valve" | "teslavalve" => {
                    let store = Self::find_store(args);
                    return DetectionResult {
                        engine: EngineChoice::PackStore,
                        reason: "explicit --engine tv passed on CLI".to_string(),
                        store_path: store,
                        explicit: true,
                    };
                }
                "rgx" | "direct" => {
                    return DetectionResult {
                        engine: EngineChoice::RgxDirect,
                        reason: "explicit --engine rgx passed on CLI".to_string(),
                        store_path: None,
                        explicit: true,
                    };
                }
                "auto" => {
                    // Fallthrough to automatic heuristic analysis below
                }
                other => {
                    eprintln!("rgx: warning: unrecognized engine '{other}', falling back to auto detector");
                }
            }
        }

        // 2. Check RGX_ENGINE environment variable (if --engine was not specified or was auto)
        if let Ok(env_engine) = std::env::var("RGX_ENGINE") {
            match env_engine.to_ascii_lowercase().as_str() {
                "tv" | "tesla" | "tesla-valve" => {
                    let store = Self::find_store(args);
                    return DetectionResult {
                        engine: EngineChoice::PackStore,
                        reason: "RGX_ENGINE=tv set in environment".to_string(),
                        store_path: store,
                        explicit: true,
                    };
                }
                "rgx" => {
                    return DetectionResult {
                        engine: EngineChoice::RgxDirect,
                        reason: "RGX_ENGINE=rgx set in environment".to_string(),
                        store_path: None,
                        explicit: true,
                    };
                }
                _ => {}
            }
        }

        // 3. Automatic Heuristics
        // A. Explicit '-' stdin token check
        let is_explicit_stdin = args.paths.iter().any(|p| p == "-");
        if is_explicit_stdin {
            return DetectionResult {
                engine: EngineChoice::RgxDirect,
                reason: "explicit stdin '-' passed; direct pipeline required".to_string(),
                store_path: None,
                explicit: false,
            };
        }

        // B. Single regular file target
        if args.paths.len() == 1 {
            let p = Path::new(&args.paths[0]);
            if p.is_file() {
                return DetectionResult {
                    engine: EngineChoice::RgxDirect,
                    reason: format!(
                        "target '{}' is a single regular file; direct SIMD search achieves optimal sub-millisecond latency (zero packaging overhead)",
                        p.display()
                    ),
                    store_path: None,
                    explicit: false,
                };
            }
        }

        // C. Probe for existing valid pack store
        //
        // The gate before the probe: the pack engine has no type filter of
        // its own and reads every record the store holds, so promoting over
        // a store while `-t/-T` or a non-default `-M` is in play would
        // change what the query means — and the store is never allowed to
        // do that. An explicit `--tv` is the user's own choice; this gate
        // is the detector's.
        if !args.types.is_empty() || args.max_filesize != "1G" {
            return DetectionResult {
                engine: EngineChoice::RgxDirect,
                reason: "a type filter or a non-default --max-filesize is in play, and the \
                         pack store answers those differently; the direct path keeps the \
                         query's meaning"
                    .to_string(),
                store_path: None,
                explicit: false,
            };
        }
        if let Some(store) = Self::find_store(args) {
            // The previous shape called `rgx_core::tv_runtime::format::load_manifest`
            // here to print "N indexed files across M packs" in the
            // detector's reason. That deserialised the whole
            // catalog (often millions of file records) only to throw
            // the parsed manifest away. The actual query path in
            // `run_tv_query` re-loads the same manifest a moment
            // later -- every `rgx` invocation over a pack store
            // paid for the parse twice. The summary string is
            // diagnostic; dropping the count keeps the message
            // informative and halves the work on the auto-detect
            // hot path.
            //
            // Freshness gate: a store whose manifest the filesystem
            // disagrees with is still promoted -- `run_tv_query`'s
            // dirty-file overlay re-reads the changed files off disk and
            // answers those from the bytes there, so drift costs reads and
            // never correctness -- and the reason names the count. What
            // neither this nor the overlay can see is a file *added* after
            // the build -- that needs the walk the store exists to avoid --
            // so the reason names the snapshot the answer is about.
            let (fresh_checked, fresh_stale) = match rgx_core::tv_runtime::stale_files(&store) {
                Ok(v) => v,
                Err(_) => {
                    // The manifest could not be re-read against the
                    // filesystem; treating it as fresh would be a guess.
                    return DetectionResult {
                        engine: EngineChoice::RgxDirect,
                        reason: format!(
                            "a pack store exists at '{}' but its manifest could not be checked against the filesystem; direct search selected",
                            store.display()
                        ),
                        store_path: None,
                        explicit: false,
                    };
                }
            };
            let reason = if fresh_stale == 0 {
                format!(
                    "pre-packed store detected at '{}' (valid manifest, fresh against the filesystem); sequential pack reading bypasses open/stat/close overhead (~6x-50x speedup)",
                    store.display()
                )
            } else {
                format!(
                    "pre-packed store detected at '{}' ({} of {} files changed since it was built; those are answered from the disk as it is now by the dirty-file overlay, the rest from the store, and --tv-build refreshes it)",
                    store.display(),
                    fresh_stale,
                    fresh_checked
                )
            };
            return DetectionResult {
                engine: EngineChoice::PackStore,
                reason,
                store_path: Some(store),
                explicit: false,
            };
        }

        // D. Streaming stdin fallback (no paths specified, stdin is a pipe or
        // a redirected file, and no store found). `readable_stdin` is the
        // test: `!is_terminal()` also fires for NUL and for an inherited
        // console handle, which are "no stdin here" rather than input.
        if args.paths.is_empty() && crate::readable_stdin() {
            return DetectionResult {
                engine: EngineChoice::RgxDirect,
                reason: "streaming stdin input detected; direct pipeline required".to_string(),
                store_path: None,
                explicit: false,
            };
        }

        // D. Pattern complexity / ByteRegex compatibility check.
        // Uses the process-wide compiled pattern memo (`compiled_byte_arc`),
        // which honours `-F`, `-w`, `-S`, `-i` and `--multiline-dotall` and
        // avoids compiling the NFA/DFA tables a second time before the walk.
        let can_byte_engine = if args.pattern.is_some() {
            crate::compiled_byte_arc(args).is_some()
        } else {
            true
        };

        if !can_byte_engine {
            return DetectionResult {
                engine: EngineChoice::RgxDirect,
                reason: "pattern contains regex syntax outside ByteRegex subset; in-house engine will route internally".to_string(),
                store_path: None,
                explicit: false,
            };
        }

        // E. Default for unindexed directory tree: direct parallel walk
        DetectionResult {
            engine: EngineChoice::RgxDirect,
            reason: "unindexed directory tree; direct parallel walk selected to minimize cold-start latency (Q=1 < Q*). Tip: Use '--tv' or '--tv-build' to prepare pack store for recurring queries".to_string(),
            store_path: None,
            explicit: false,
        }
    }

    /// Locates an existing, valid pack store directory if present.
    pub fn find_store(args: &Args) -> Option<PathBuf> {
        // Explicit --tv-store has highest priority
        if let Some(custom) = &args.tv_store {
            let p = PathBuf::from(custom);
            if Self::is_valid_store(&p) {
                return Some(p);
            }
        }

        let candidates: Vec<PathBuf> = if args.paths.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            args.paths.iter().map(PathBuf::from).collect()
        };

        for target in &candidates {
            let tv_dir = target.join(".rgx-tv");
            if Self::is_valid_store(&tv_dir) {
                return Some(tv_dir);
            }
            let rgx_store = target.join(".rgx").join("store");
            if Self::is_valid_store(&rgx_store) {
                return Some(rgx_store);
            }
        }

        let cwd_tv = PathBuf::from(".rgx-tv");
        if Self::is_valid_store(&cwd_tv) {
            return Some(cwd_tv);
        }

        None
    }

    /// Checks if `dir` contains a valid, readable pack manifest.
    pub fn is_valid_store(dir: &Path) -> bool {
        let manifest_path = dir.join("manifest.tvm");
        if !manifest_path.is_file() {
            return false;
        }
        rgx_core::tv_runtime::format::load_manifest(dir).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_args() -> Args {
        Args {
            pattern: Some("fn main".to_string()),
            paths: Vec::new(),
            ignore_case: false,
            smart_case: false,
            fixed_strings: false,
            word_regexp: false,
            invert_match: false,
            multiline: false,
            multiline_dotall: false,
            max_count: None,
            threads: None,
            only_matching: false,
            replace: None,
            files_with_matches: false,
            files_without_match: false,
            list_files: false,
            count: false,
            sort: None,
            sort_reversed: false,
            quiet: false,
            json: false,
            serve: false,
            null_data: false,
            column: false,
            encoding: None,
            color: None,
            after_context: 0,
            before_context: 0,
            context: None,
            chunk: None,
            glob: Vec::new(),
            no_hidden: false,
            no_ignore: false,
            follow: false,
            text: false,
            max_depth: None,
            max_filesize: "1G".to_string(),
            no_filename: false,
            line_number: false,
            no_line_number: false,
            heading: None,
            max_adapter_depth: 4,
            filter: None,
            cache: None,
            cache_clear: false,
            cache_prune: false,
            cache_max_age: 30,
            pick: false,
            fzf_binary: None,
            fzf_args: Vec::new(),
            completions: None,
            engine: None,
            tv: false,
            tv_store: None,
            tv_build: false,
            tv_pre_extract: false,
            index_build: None,
            index_dir: None,
            index_store: None,
            tv_verify: None,
            explain_engine: false,
            stats: false,
            tv_assume_fresh: false,
            types: Vec::new(),
            type_add: Vec::new(),
            type_clear: false,
            type_list: false,
            facts_build: None,
            facts_index: None,
            facts_export: None,
            facts_store: None,
            mcp: false,
        }
    }

    #[test]
    fn test_explicit_tv_flag() {
        let mut args = dummy_args();
        args.tv = true;
        let res = AutoDetector::detect(&args);
        assert_eq!(res.engine, EngineChoice::PackStore);
        assert!(res.reason.contains("--tv"));
    }

    #[test]
    fn test_explicit_engine_options() {
        let mut args = dummy_args();
        args.engine = Some("tv".to_string());
        assert_eq!(AutoDetector::detect(&args).engine, EngineChoice::PackStore);

        args.engine = Some("rgx".to_string());
        assert_eq!(AutoDetector::detect(&args).engine, EngineChoice::RgxDirect);
    }

    #[test]
    fn test_single_file_target() {
        let mut args = dummy_args();
        args.paths = vec!["Cargo.toml".to_string()];
        let res = AutoDetector::detect(&args);
        assert_eq!(res.engine, EngineChoice::RgxDirect);
        assert!(res.reason.contains("single regular file"));
    }

    #[test]
    fn test_stdin_target() {
        let mut args = dummy_args();
        args.paths = vec!["-".to_string()];
        let res = AutoDetector::detect(&args);
        assert_eq!(res.engine, EngineChoice::RgxDirect);
        assert!(res.reason.contains("stdin"));
    }

    #[test]
    fn test_unindexed_directory() {
        let mut args = dummy_args();
        args.paths = vec!["src".to_string()];
        let res = AutoDetector::detect(&args);
        // Assuming no .rgx-tv in src/
        if AutoDetector::find_store(&args).is_none() {
            assert_eq!(res.engine, EngineChoice::RgxDirect);
            assert!(res.reason.contains("unindexed directory tree"));
        }
    }
}
