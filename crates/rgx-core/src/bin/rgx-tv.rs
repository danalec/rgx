// SPDX-License-Identifier: Apache-2.0

//! rgx-tv CLI application.
//!
//! Subcommands:
//! - `build <root> --store <dir>`: Ingests directory into aggregated packs.
//! - `search <pattern> --store <dir>`: Searches aggregated packs preserving file boundaries.
//! - `update <root> --store <dir>`: Incrementally publishes new generation.
//! - `inspect --store <dir>`: Verifies integrity of packs and manifest.

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;

use rgx_core::tv_runtime::{
    build_store, inspect_store, search_store, search_store_pooled, update_store, BuildConfig,
    EngineMode, MappedStore, PoolLimits, ReadMode, SearchConfig, Unmap,
};

/// `-M` / `--max-filesize`, with ripgrep's suffixes: a bare number is bytes,
/// `k`/`kb`/`kib` are 1024, `m`/`mb`/`mib` are 1024^2, `g`/`gb`/`gib` 1024^3.
fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let split = t.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(t.len());
    let (num, mult) = t.split_at(split);
    let n: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("bad size '{}'", s))?;
    let m = match mult.trim().to_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        other => return Err(format!("unknown size suffix {}", other)),
    };
    Ok((n * m) as u64)
}

fn print_usage() {
    eprintln!(
        "\
rgx-tv: prepared-pack storage search engine

USAGE:
    rgx-tv build <root> --store <dir> [options]
    rgx-tv search <pattern> --store <dir> [options]
    rgx-tv update <root> --store <dir> [options]
    rgx-tv inspect --store <dir>

SUBCOMMANDS:
    build       Ingest raw directory tree into aggregated verified packs
    search      Search aggregated packs preserving strict file boundaries
    update      Incrementally update packs from modified/new files on disk
    inspect     Verify pack CRC32 checksums and report storage statistics

OPTIONS:
    --store <dir>         Path to aggregated pack store directory (required)
    --pack-size-mb <N>    Target pack size in MiB (default: 16)
    --max-depth <N>       Maximum directory depth, as rgx's own walker reads it
    -g, --glob <PATTERN>  Include/exclude glob, repeatable, gitignore-style
    --hidden              Ingest hidden files, as rgx's --hidden means it
    -L, --follow          Follow symbolic links
    --no-ignore           Do not read .gitignore, .ignore or parents'
    -j, --threads <N>     Number of search threads. Default: three quarters of
                          the physical cores, opened up to every logical
                          processor when the pack's own timings say the scan,
                          not the copy, is the expensive half. -j pins it.
    -c, --count           Only print count of matching lines per file
    -n, --line-number     Show 1-based line numbers (default: true)
    -A, --after-context   Number of lines of after-context
    -B, --before-context  Number of lines of before-context
    -C, --context         Number of lines of before and after context
    -a, --text            Search files the build marked binary
    --engine <which>      auto (the default) or rgx (always in-house). The
                          retired names grep and both still parse, resolve to
                          the in-house engine and say so on stderr; there is
                          no cross-check engine and no divergence report
    -M, --max-filesize N  Skip files larger than N (suffixes k/m/g, as in rg)
    --validate           Stat every file the manifest claims and report the ones
                          the filesystem disagrees about. A stat per file, the
                          cost the pack exists to avoid: it buys the difference
                          between this generation and now.
    --mmap                Map every pack instead of reading it. Maps are torn
                          down on Windows, which is the largest single stage of
                          a one-shot query; this is here for comparison and for
                          processes that hold a store open across queries.
    --no-mmap             Buffered reads (the default). Workers claim whole
                          packs and read them in parallel; nothing is mapped, so
                          there is nothing to unmap.
    --serial-buffered     Buffered reads done by the coordinator, one pack at a
                          time. The `--no-mmap` behaviour before this flag existed.
    --packs-per-thread N  Packs a worker claims per claim, buffered mode only
                          (default: 1)
    --pool                Reuse one set of pack mappings across queries in this
                          process. Only useful with --mmap, and only when the
                          process queries a store more than once: a one-shot
                          process drops the mappings on its way out either way.
    --no-pool             Deprecated. The pool is off by default, so this asks
                          for what a bare invocation already does; accepted with
                          a note on stderr so old scripts notice.
    --leak-mmap           Skip the explicit unmap; let process exit reclaim the
                          mappings. Only for a single-shot process, and a no-op
                          in buffered mode.
    --stats               Print the stage breakdown to stderr
    -h, --help            Print help information
"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "build" => run_build(&args[2..]),
        "search" => run_search(&args[2..]),
        "update" => run_update(&args[2..]),
        "inspect" => run_inspect(&args[2..]),
        "-h" | "--help" | "help" => {
            print_usage();
            process::exit(0);
        }
        cmd => {
            eprintln!("rgx-tv: unknown command '{}'", cmd);
            print_usage();
            process::exit(1);
        }
    }
}

/// The five flags that decide which files belong to the store, read in one
/// pass so `build` and `update` cannot disagree about them.
///
/// `update` has to take the same ones as `build`: the store records their
/// fingerprint and refuses an update whose fingerprint differs, so a
/// `build -g '*.rs'` followed by a bare `update` fails loudly instead of
/// tombstoning everything the glob excluded.
fn walk_filters(args: &[String]) -> (bool, bool, bool, Option<usize>, Vec<String>) {
    let mut hidden = false;
    let mut follow = false;
    let mut no_ignore = false;
    let mut max_depth = None;
    let mut globs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--hidden" => hidden = true,
            "-L" | "--follow" => follow = true,
            "--no-ignore" => no_ignore = true,
            "--max-depth" if i + 1 < args.len() => max_depth = args[i + 1].parse().ok(),
            "-g" | "--glob" if i + 1 < args.len() => globs.push(args[i + 1].clone()),
            _ => {}
        }
        i += 1;
    }
    (hidden, follow, no_ignore, max_depth, globs)
}

fn run_build(args: &[String]) {
    let mut root: Option<PathBuf> = None;
    let mut store: Option<PathBuf> = None;
    let mut pack_size_mb: u64 = 16;
    let (hidden, follow, no_ignore, max_depth, globs) = walk_filters(args);

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--store" if i + 1 < args.len() => {
                store = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--pack-size-mb" if i + 1 < args.len() => {
                pack_size_mb = args[i + 1].parse().unwrap_or(16);
                i += 2;
            }
            // Read by `walk_filters`; consumed here so the loop does not
            // report them as unrecognised.
            "--max-depth" if i + 1 < args.len() => i += 2,
            "-g" | "--glob" if i + 1 < args.len() => i += 2,
            "--hidden" => i += 1,
            "-L" | "--follow" => i += 1,
            "--no-ignore" => i += 1,
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            arg if !arg.starts_with('-') && root.is_none() => {
                root = Some(PathBuf::from(arg));
                i += 1;
            }
            other => {
                eprintln!("rgx-tv build: unrecognized option '{}'", other);
                process::exit(1);
            }
        }
    }

    let root_path = match root {
        Some(r) => r,
        None => {
            eprintln!("rgx-tv build: missing root directory");
            process::exit(1);
        }
    };
    let store_path = match store {
        Some(s) => s,
        None => {
            eprintln!("rgx-tv build: missing --store <dir>");
            process::exit(1);
        }
    };

    let cfg = BuildConfig {
        target_pack_size: pack_size_mb * 1024 * 1024,
        hidden,
        gitignore: !no_ignore,
        // `--no-ignore` reaches the parent directories' ignore files too, the
        // same way the direct walker binds it.
        parents: !no_ignore,
        follow_symlinks: follow,
        max_depth,
        globs,
        compact_after_update: false,
    };

    println!(
        "rgx-tv: building packs from '{}' into '{}'...",
        root_path.display(),
        store_path.display()
    );
    match build_store(&root_path, &store_path, &cfg) {
        Ok(stats) => {
            println!(
                "rgx-tv: build complete in {:.2} ms. Ingested {} files ({:.2} MB) into {} packs ({:.2} MB).",
                stats.elapsed_ms,
                stats.total_files,
                stats.total_bytes_ingested as f64 / 1_000_000.0,
                stats.total_packs,
                stats.total_pack_bytes as f64 / 1_000_000.0,
            );
        }
        Err(e) => {
            eprintln!("rgx-tv: build error: {}", e);
            process::exit(1);
        }
    }
}

/// A value-taking option, whether it arrives as two tokens or one.
///
/// ripgrep, and rgx, both take `-j8` and `-j 8`; this only took the second, so
/// `rgx-tv search -c -j1 'pub fn' --store ...` was an unrecognised option and
/// exited 1 against a binary the pack is supposed to be interchangeable with.
/// The bundled form is the one a script writes, because it is shorter and
/// because every other flag on the line is bundled.
///
/// Returns `Some((name, value))` when `arg` carries its own value.
///
/// **A token is an option only when it starts with `-`.** Patterns contain
/// `=` routinely (`status=200`, `foo=bar`), and splitting those into a
/// name and a value turned the pattern into an unrecognised option: the
/// query `rgx-tv search -c 'status=200' --store ...` exited 1 against a
/// corpus its own direct arm matched 500,429 times. The leading dash is
/// what makes the difference an option name can have.
fn split_bundled(arg: &str) -> Option<(&str, &str)> {
    let (name, value) = arg.split_once('=')?;
    if name.is_empty() || value.is_empty() || !name.starts_with('-') {
        return None;
    }
    Some((name, value))
}

/// A thread count, with ripgrep's spelling: `0` asks the operating system.
///
/// Silently coercing a bad value to a default is how `-jxyz` used to become
/// one thread and exit 0 — a mistyped flag that reads as a fast search is
/// worse than one that is refused. So a number that is not a number is an
/// error, and `0` means what it means in rg.
fn parse_threads(value: &str, whole: &str) -> usize {
    match value.parse::<usize>() {
        Ok(0) => std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        Ok(n) => n,
        Err(_) => {
            eprintln!("rgx-tv search: {whole}: '{value}' is not a thread count");
            process::exit(1);
        }
    }
}

/// `-j` is a request, so it pins both ends of the width.
///
/// Without `-j` the query starts at the bandwidth optimum and opens itself up
/// to every logical processor when its own per-pack timings say the scan, not
/// the copies, is the expensive half. A person who typed `-j8` meant eight
/// workers and did not ask to be second-guessed by a measurement taken while
/// they were waiting, so the flag sets the start, sets the ceiling to the same
/// number, and turns the widening off.
fn pin_threads(config: &mut SearchConfig, n: usize) {
    config.threads = n;
    config.start_threads = Some(n);
    config.widen = false;
}

/// A number of context lines. Zero is a real answer — `-C 0` is how rg spells
/// "no context" — so it is accepted, and only a value that is not a number is
/// refused.
fn parse_lines(value: &str, whole: &str) -> usize {
    match value.parse::<usize>() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("rgx-tv search: {whole}: '{value}' is not a line count");
            process::exit(1);
        }
    }
}

/// A claim granularity, which must be at least one: a worker claiming zero
/// packs would do no work and look like a search that found nothing.
fn parse_claims(value: &str, whole: &str) -> usize {
    match value.parse::<usize>() {
        Ok(n) if n >= 1 => n,
        _ => {
            eprintln!("rgx-tv search: {whole}: '{value}' is not a positive count");
            process::exit(1);
        }
    }
}

fn run_search(args: &[String]) {
    let mut pattern: Option<String> = None;
    let mut store: Option<PathBuf> = None;
    let mut config = SearchConfig::default();
    // The default is the buffered parallel path and no pool, because `search`
    // runs exactly one query in a process that then exits. A pool only pays for
    // itself when a process asks the same store more than once: for one query
    // the mappings still have to be torn down on the way out, so keeping them
    // warm until the end moves the cost, it does not remove it.
    let mut pool = false;
    let mut show_stats = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--store" if i + 1 < args.len() => {
                store = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--pool" => {
                pool = true;
                i += 1;
            }
            "--no-pool" => {
                // Accepted, and named as the deprecated spelling of the
                // default. It used to turn the pool OFF; the pool is off by
                // default now, so the flag asks for what a bare invocation
                // already does. Saying so beats accepting it silently: a
                // script written against the old default and running against
                // this one should learn that its flag stopped meaning
                // something, not discover it by timing.
                eprintln!(
                    "rgx-tv search: --no-pool is the default and does nothing; it is kept so old scripts keep working"
                );
                pool = false;
                i += 1;
            }
            "-j" | "--threads" if i + 1 < args.len() => {
                pin_threads(&mut config, parse_threads(&args[i + 1], &args[i]));
                i += 2;
            }
            "--validate" => {
                config.validate_freshness = true;
                i += 1;
            }
            // `-M` and `--max-filesize` are handled together further down, in
            // every spelling: `-M 300`, `-M300`, `--max-filesize 300` and
            // `--max-filesize=300` are the same flag. There used to be an arm
            // here that consumed the value and did nothing with it, and
            // because it matched first **the space-separated long form was the
            // one that did not work**: `-M 300` dropped `big.txt` and
            // `--max-filesize 300` answered for both files, with no error
            // anywhere. A flag that quietly widens the answer is worse than one
            // that is refused, because the script that used it was right about
            // what it asked for.
            //
            // `-j8`, `-j=8`, `--threads=8`, and the short form of every other
            // value-taking option below, so a flag copied from an `rg` line
            // works here too.
            other if split_bundled(other).is_some() => {
                let (name, value) = split_bundled(other).unwrap();
                match name {
                    "-j" | "--threads" => pin_threads(&mut config, parse_threads(value, other)),
                    "--packs-per-thread" => config.packs_per_thread = parse_claims(value, other),
                    "-A" | "--after-context" => config.after_context = parse_lines(value, other),
                    "-B" | "--before-context" => config.before_context = parse_lines(value, other),
                    "-C" | "--context" => {
                        let c = parse_lines(value, other);
                        config.before_context = c;
                        config.after_context = c;
                    }
                    "-M" | "--max-filesize" => match parse_size(value) {
                        Ok(n) => config.max_file_size = Some(n),
                        Err(e) => {
                            eprintln!("rgx-tv search: {}: {}", other, e);
                            process::exit(1);
                        }
                    },
                    "--engine" => {
                        config.engine = match value {
                            "auto" => EngineMode::Auto,
                            "rgx" => EngineMode::Rgx,
                            // Legacy aliases from the era when the
                            // in-house engine shared a stage with the
                            // `grep` delegate. Both names now resolve
                            // to the in-house engine so old scripts
                            // that name them still run, with a
                            // warning to stderr so the change is loud.
                            "both" | "grep" => {
                                eprintln!("rgx-tv search: --engine {value} is gone, using rgx");
                                EngineMode::Rgx
                            }
                            _ => {
                                eprintln!("rgx-tv search: --engine {value} (want auto or rgx)");
                                process::exit(1);
                            }
                        }
                    }
                    other => {
                        eprintln!("rgx-tv search: unrecognized option '{other}'");
                        process::exit(1);
                    }
                }
                i += 1;
            }
            // `-j8`, `-C2`, `-M1M`: a short option and its value in one
            // token, no `=`. The name is two bytes and the value is the rest,
            // which is where `-M1M`'s size suffix lives.
            other
                if other.len() > 2
                    && other.starts_with('-')
                    && !other.starts_with("--")
                    && !other[1..].starts_with('-') =>
            {
                let (name, value) = other.split_at(2);
                match name {
                    "-j" => pin_threads(&mut config, parse_threads(value, other)),
                    "-C" => {
                        let c = parse_lines(value, other);
                        config.before_context = c;
                        config.after_context = c;
                    }
                    "-A" => config.after_context = parse_lines(value, other),
                    "-B" => config.before_context = parse_lines(value, other),
                    "-M" => match parse_size(value) {
                        Ok(n) => config.max_file_size = Some(n),
                        Err(e) => {
                            eprintln!("rgx-tv search: {other}: {e}");
                            process::exit(1);
                        }
                    },
                    _ => {
                        eprintln!("rgx-tv search: unrecognized option '{other}'");
                        process::exit(1);
                    }
                }
                i += 1;
            }
            "-c" | "--count" => {
                config.count_only = true;
                i += 1;
            }
            "-n" | "--line-number" => {
                config.line_numbers = true;
                i += 1;
            }
            "--mmap" => {
                config.read_mode = ReadMode::Mmap;
                i += 1;
            }
            "--no-mmap" => {
                config.read_mode = ReadMode::ParallelBuffered;
                i += 1;
            }
            "--serial-buffered" => {
                config.read_mode = ReadMode::Buffered;
                i += 1;
            }
            "--packs-per-thread" if i + 1 < args.len() => {
                config.packs_per_thread = parse_claims(&args[i + 1], &args[i]);
                i += 2;
            }
            "--stats" => {
                show_stats = true;
                i += 1;
            }
            "--leak-mmap" => {
                // Single-shot process only: skips the serial unmap of every
                // pack and lets process exit reclaim the address space.
                config.unmap = Unmap::Leak;
                i += 1;
            }
            "--engine" if i + 1 < args.len() => {
                let v = args[i + 1].as_str();
                config.engine = match v {
                    "auto" => EngineMode::Auto,
                    "rgx" => EngineMode::Rgx,
                    "both" | "grep" => {
                        eprintln!("rgx-tv search: --engine {v} is gone, using rgx");
                        EngineMode::Rgx
                    }
                    other => {
                        eprintln!("rgx-tv search: --engine {other} (want auto or rgx)");
                        process::exit(1);
                    }
                };
                i += 2;
            }
            "-a" | "--text" => {
                config.search_binary = true;
                i += 1;
            }
            "-M" | "--max-filesize" if i + 1 < args.len() => {
                let s = &args[i + 1];
                match parse_size(s) {
                    Ok(n) => config.max_file_size = Some(n),
                    Err(e) => {
                        eprintln!("rgx-tv search: --max-filesize {}: {}", s, e);
                        process::exit(1);
                    }
                }
                i += 2;
            }
            "-A" | "--after-context" if i + 1 < args.len() => {
                config.after_context = parse_lines(&args[i + 1], &args[i]);
                i += 2;
            }
            "-B" | "--before-context" if i + 1 < args.len() => {
                config.before_context = parse_lines(&args[i + 1], &args[i]);
                i += 2;
            }
            "-C" | "--context" if i + 1 < args.len() => {
                let c = parse_lines(&args[i + 1], &args[i]);
                config.before_context = c;
                config.after_context = c;
                i += 2;
            }
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            arg if !arg.starts_with('-') && pattern.is_none() => {
                pattern = Some(arg.to_string());
                i += 1;
            }
            other => {
                eprintln!("rgx-tv search: unrecognized option '{}'", other);
                process::exit(1);
            }
        }
    }

    let pat = match pattern {
        Some(p) => p,
        None => {
            eprintln!("rgx-tv search: missing pattern");
            process::exit(1);
        }
    };
    let store_path = match store {
        Some(s) => s,
        None => {
            eprintln!("rgx-tv search: missing --store <dir>");
            process::exit(1);
        }
    };

    // The pool exists to keep mappings alive across queries in one process.
    // A buffered query wants no mappings at all, so asking the pool for them
    // would be asking for exactly the teardown the read mode was chosen to
    // avoid: the pool's own switch is what keeps the two axes from colliding.
    let warm = if pool && config.read_mode == ReadMode::Mmap {
        MappedStore::open(
            &store_path,
            PoolLimits {
                search_binary: config.search_binary,
                ..PoolLimits::default()
            },
        )
        .ok()
        .filter(|m| m.enabled())
    } else {
        None
    };
    let result = match &warm {
        Some(m) => search_store_pooled(m, &pat, &config),
        None => search_store(&store_path, &pat, &config),
    };
    match result {
        Ok((matches, stats)) => {
            if show_stats {
                print_stages(&config, &stats);
            }
            let mut stdout = io::stdout().lock();
            if config.count_only {
                println!("{}:{}", store_path.display(), stats.total_lines_matched);
            } else {
                for m in matches {
                    let text = String::from_utf8_lossy(&m.line);
                    let trimmed = text.trim_end_matches(&['\r', '\n'][..]);
                    if let Some(ln) = m.line_number {
                        let _ = writeln!(stdout, "{}:{}:{}", m.path, ln, trimmed);
                    } else {
                        let _ = writeln!(stdout, "{}:{}", m.path, trimmed);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("rgx-tv: search error: {}", e);
            process::exit(1);
        }
    }
}

/// The in-process decomposition, on stderr so it never joins the answer.
/// These are `Instant` readings inside the process; process start and exit are
/// not in here, which is exactly why they cannot decide a single-shot question.
fn print_stages(config: &SearchConfig, stats: &rgx_core::tv_runtime::SearchStats) {
    let s = &stats.stages;
    let mode = match config.read_mode {
        ReadMode::Mmap => "mmap",
        ReadMode::Buffered => "buffered-serial",
        ReadMode::ParallelBuffered => "buffered-parallel",
    };
    // `threads=12->32` is the query widening itself from its own timings;
    // `threads=8` is a `-j8` that stayed exactly as wide as it was told to be.
    let start = config
        .start_threads
        .unwrap_or_else(rgx_core::tv_runtime::default_threads);
    let width = if start == stats.workers {
        format!("{}", stats.workers)
    } else {
        format!("{start}->{}", stats.workers)
    };
    eprintln!(
        "rgx-tv: mode={} pool={} engine={} threads={} packs={} files_searched={} files_pruned={} lines={}",
        mode,
        stats.pooled,
        stats.engine,
        width,
        stats.total_packs_scanned,
        stats.total_files_searched,
        stats.total_files_pruned,
        stats.total_lines_matched,
    );
    eprintln!(
        "rgx-tv: in-process {:.1} ms = manifest {:.1} + filter {:.1} + map {:.1} + work {:.1} + teardown {:.1}",
        s.in_process_ms, s.manifest_ms, s.filter_ms, s.map_ms, s.work_ms, s.teardown_ms,
    );
    eprintln!(
        "rgx-tv: work {:.1} ms wall = {:.1} ms read + {:.1} ms regex (cpu-ms, summed over threads)",
        s.work_ms, s.read_cpu_ms, s.scan_cpu_ms,
    );
    if let Some((checked, stale)) = stats.stale_files {
        eprintln!("rgx-tv: validated {checked} files, {stale} stale");
    }
    if s.balance > 0.0 {
        eprintln!(
            "rgx-tv: claim service p50 {:.2} / p99 {:.2} / max {:.2} ms; balance {:.2} of {} threads busy for the whole phase",
            s.pack_service_p50_ms, s.pack_service_p99_ms, s.pack_service_max_ms, s.balance, stats.workers,
        );
    }
}

fn run_update(args: &[String]) {
    let mut root: Option<PathBuf> = None;
    let mut store: Option<PathBuf> = None;
    let mut compact = false;
    let (hidden, follow, no_ignore, max_depth, globs) = walk_filters(args);

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--store" if i + 1 < args.len() => {
                store = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--max-depth" if i + 1 < args.len() => i += 2,
            "-g" | "--glob" if i + 1 < args.len() => i += 2,
            "--hidden" => i += 1,
            "-L" | "--follow" => i += 1,
            "--no-ignore" => i += 1,
            // Updates are append-only, so a store that is updated often
            // grows without bound. This reclaims the superseded payloads.
            "--compact" => {
                compact = true;
                i += 1;
            }
            arg if !arg.starts_with('-') && root.is_none() => {
                root = Some(PathBuf::from(arg));
                i += 1;
            }
            other => {
                eprintln!("rgx-tv update: unrecognized option '{}'", other);
                process::exit(1);
            }
        }
    }

    let root_path = match root {
        Some(r) => r,
        None => {
            eprintln!("rgx-tv update: missing root directory");
            process::exit(1);
        }
    };
    let store_path = match store {
        Some(s) => s,
        None => {
            eprintln!("rgx-tv update: missing --store <dir>");
            process::exit(1);
        }
    };

    let cfg = BuildConfig {
        hidden,
        gitignore: !no_ignore,
        parents: !no_ignore,
        follow_symlinks: follow,
        max_depth,
        globs,
        compact_after_update: compact,
        ..Default::default()
    };
    println!(
        "rgx-tv: updating packs in '{}' from '{}'...",
        store_path.display(),
        root_path.display()
    );
    match update_store(&root_path, &store_path, &cfg) {
        Ok(stats) => {
            println!(
                "rgx-tv: update complete in {:.2} ms. Generation {} published. Added: {}, Modified: {}, Deleted: {}. New packs: {} ({:.2} MB).",
                stats.elapsed_ms,
                stats.new_generation,
                stats.files_added,
                stats.files_modified,
                stats.files_deleted,
                stats.new_packs_written,
                stats.new_bytes_written as f64 / 1_000_000.0,
            );
        }
        Err(e) => {
            eprintln!("rgx-tv: update error: {}", e);
            process::exit(1);
        }
    }
}

fn run_inspect(args: &[String]) {
    let mut store: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--store" if i + 1 < args.len() => {
                store = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            other => {
                eprintln!("rgx-tv inspect: unrecognized option '{}'", other);
                process::exit(1);
            }
        }
    }

    let store_path = match store {
        Some(s) => s,
        None => {
            eprintln!("rgx-tv inspect: missing --store <dir>");
            process::exit(1);
        }
    };

    match inspect_store(&store_path) {
        Ok(rep) => {
            println!("rgx-tv Store Report: {}", store_path.display());
            println!("==================================================");
            println!("Root Path:            {}", rep.root_path);
            println!("Generation:           {}", rep.generation);
            println!("Timestamp:            {} (Unix)", rep.timestamp_secs);
            println!("Corpus fingerprint:   {:#018x}", rep.corpus);
            println!("Total Files:          {}", rep.total_files);
            println!("Active Files:         {}", rep.active_files);
            println!("Empty (0-byte) Files: {}", rep.empty_files);
            println!("Deleted Files:        {}", rep.deleted_files);
            println!("Total Packs:          {}", rep.total_packs);
            println!(
                "Total Payload:        {:.2} MB",
                rep.total_payload_bytes as f64 / 1_000_000.0
            );
            if rep.corrupted_packs.is_empty() {
                println!("Integrity Status:     ALL PACKS VERIFIED (CRC32 OK)");
            } else {
                println!("Integrity Status:     CORRUPTION DETECTED!");
                for (pack, err) in rep.corrupted_packs {
                    println!("  - {}: {}", pack, err);
                }
            }
        }
        Err(e) => {
            eprintln!("rgx-tv: inspect error: {}", e);
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split_bundled;

    /// A pattern may hold `=` and must stay a pattern. Only a leading dash
    /// makes a token an option; `status=200` is what the query is about,
    /// and splitting it turned a corpus that matched 500,429 times into a
    /// query that matched none.
    #[test]
    fn an_equals_in_a_pattern_is_not_an_option() {
        assert_eq!(split_bundled("status=200"), None);
        assert_eq!(split_bundled("foo=bar"), None);
        assert_eq!(split_bundled("a=b=c"), None);
    }

    #[test]
    fn a_bundled_option_still_splits() {
        assert_eq!(split_bundled("--threads=8"), Some(("--threads", "8")));
        assert_eq!(
            split_bundled("--max-filesize=300"),
            Some(("--max-filesize", "300"))
        );
        // Empty halves are not options either.
        assert_eq!(split_bundled("-j="), None);
        assert_eq!(split_bundled("=8"), None);
    }
}
