// SPDX-License-Identifier: Apache-2.0

//! Empirical harness for **candidate-stream diodicity**: how many false
//! candidates the engine discards, per byte it admits.
//!
//! # Where the vocabulary comes from, and where it stops
//!
//! The paper calls the architecture **diodic** and the ratio it measures
//!
//! ```text
//! Di = raw candidates / admitted candidates
//! ```
//!
//! and illustrates it with Tesla's 1920 valvular conduit (US Patent 1,329,559):
//! forward flow keeps to a streamlined channel, reverse flow separates at a
//! blunt edge and re-enters at an angle where its momentum is wasted.
//!
//! **The device is not a model of this engine and predicts nothing about it.**
//! What is borrowed is the *shape* — one-way work, the cheap direction kept
//! streamlined — and that only holds at the register tier, where it is a real
//! functional analogue: while candidates are being eliminated there is no
//! branch instruction, no branch-predictor state and no scalar state
//! transition. At the storage tier the same principle organises the work
//! without claiming that bytes are fluid. Every number this file prints is a
//! measurement; the picture is how it is read, not how it is justified.
//!
//! The two halves below measure the two places the shape appears:
//!
//! * **Part 1, the SIMD prefilter.** A candidate stream enters and false
//!   candidates are quenched in-register by secondary constraints before any
//!   scalar confirmation runs. The quantity is `Di = raw / admitted` per
//!   pattern, and it varies with pattern density — which is the point: the
//!   figure of merit is a property of the *constraint's* asymmetry, not a
//!   constant of the machine.
//! * **Part 2, the corpus n-gram index.** The same shape at file granularity:
//!   a query n-gram passes matching files freely while frequent, ambiguous
//!   noise is rejected in memory, with no disk I/O per file.
//!
//! Where the picture and the code disagree, the code is the claim.

use rgx_core::matcher::Matcher;
use rgx_core::regex::ByteRegex;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Part 1: Diodic SIMD Candidate Choker (Item 2)
// ---------------------------------------------------------------------------

struct PrefilterResult {
    pattern: &'static str,
    raw_candidates: usize,
    valve_candidates: usize,
    quenched_pct: f64,
    diodicity: f64,
    true_matches: usize,
}

fn test_diodic_simd_choker(corpus_path: &Path) {
    println!("==============================================================================");
    println!("Part 1: Diodic SIMD Candidate Choker (Item 2: Frequency Prefilters)");
    println!("Corpus: {}", corpus_path.display());
    println!("==============================================================================");

    let data = match fs::read(corpus_path) {
        Ok(d) => d,
        Err(e) => {
            println!(
                "Could not read corpus file {}: {}",
                corpus_path.display(),
                e
            );
            return;
        }
    };
    println!(
        "Corpus loaded: {} bytes ({:.2} MB)\n",
        data.len(),
        data.len() as f64 / 1_000_000.0
    );

    // Test specific complex patterns where candidate noise is high:
    // 1. `foo.*bar`: Forward stream searches `foo`; diodic loop collides presence of `bar` within line window.
    // 2. `(pub|fn) [a-z]+`: Forward stream searches `pub ` | `fn `; diodic loop collides trailing byte in `[a-z]`.
    // 3. `e[0-9]`: Forward stream searches `e`; diodic loop collides subsequent digit.

    // A. Pattern: `(pub|fn) [a-z]+`
    // Standard forward nozzle: matches "pub " or "fn "
    // diodic collision loop: trailing byte must be [a-z] (0x61..=0x7A)
    let pub_fn_res = {
        let mut raw_cands = 0usize;
        let mut valve_cands = 0usize;
        let mut true_hits = 0usize;

        let re = ByteRegex::new(br"(pub|fn) [a-z]+").unwrap();

        // SIMD-style chunked simulation
        let len = data.len();
        let mut i = 0usize;
        while i + 5 <= len {
            // Forward nozzle test: "pub " at i or "fn " at i
            let is_pub = data[i] == b'p'
                && data[i + 1] == b'u'
                && data[i + 2] == b'b'
                && data[i + 3] == b' ';
            let is_fn = data[i] == b'f' && data[i + 1] == b'n' && data[i + 2] == b' ';

            if is_pub {
                raw_cands += 1;
                // diodic loop: check trailing byte at i + 4
                let trailing = data[i + 4];
                let is_alpha = trailing.is_ascii_lowercase();
                if is_alpha {
                    valve_cands += 1;
                    if re.is_match_at(&data[i..std::cmp::min(i + 32, len)], 0) {
                        true_hits += 1;
                    }
                }
            } else if is_fn {
                raw_cands += 1;
                // diodic loop: check trailing byte at i + 3
                let trailing = data[i + 3];
                let is_alpha = trailing.is_ascii_lowercase();
                if is_alpha {
                    valve_cands += 1;
                    if re.is_match_at(&data[i..std::cmp::min(i + 32, len)], 0) {
                        true_hits += 1;
                    }
                }
            }
            i += 1;
        }
        PrefilterResult {
            pattern: "(pub|fn) [a-z]+",
            raw_candidates: raw_cands,
            valve_candidates: valve_cands,
            quenched_pct: 100.0 * (1.0 - valve_cands as f64 / raw_cands as f64),
            diodicity: raw_cands as f64 / valve_cands as f64,
            true_matches: true_hits,
        }
    };

    // B. Pattern: `foo.*bar`
    // Forward nozzle: matches "foo"
    // diodic collision loop: looks ahead within the same line for "bar"
    let foo_bar_res = {
        let mut raw_cands = 0usize;
        let mut valve_cands = 0usize;
        let mut true_hits = 0usize;

        let re = ByteRegex::new(br"foo.*bar").unwrap();
        let len = data.len();
        let mut i = 0usize;
        while i + 6 <= len {
            // Forward nozzle test: "foo"
            if data[i] == b'f' && data[i + 1] == b'o' && data[i + 2] == b'o' {
                raw_cands += 1;
                // diodic loop: scan forward until newline or max span (1024 bytes) for "bar"
                let end = std::cmp::min(i + 1024, len);
                let line_end = data[i..end]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map(|p| i + p)
                    .unwrap_or(end);
                let slice = &data[i + 3..line_end];
                let has_bar = rgx_core::memchr::memmem::find(slice, b"bar").is_some();
                if has_bar {
                    valve_cands += 1;
                    if re.is_match_at(&data[i..line_end], 0) {
                        true_hits += 1;
                    }
                }
            }
            i += 1;
        }
        PrefilterResult {
            pattern: "foo.*bar",
            raw_candidates: raw_cands,
            valve_candidates: valve_cands,
            quenched_pct: 100.0 * (1.0 - valve_cands as f64 / raw_cands as f64),
            diodicity: raw_cands as f64 / valve_cands.max(1) as f64,
            true_matches: true_hits,
        }
    };

    // C. Pattern: `e[0-9]`
    // Forward nozzle: 'e' (rank 253, high flow)
    // diodic loop: subsequent byte is digit (rank sum 1904, low flow)
    let e_digit_res = {
        let mut raw_cands = 0usize;
        let mut valve_cands = 0usize;
        let mut true_hits = 0usize;

        let len = data.len();
        let mut i = 0usize;
        while i + 2 <= len {
            if data[i] == b'e' {
                raw_cands += 1;
                let next = data[i + 1];
                if next.is_ascii_digit() {
                    valve_cands += 1;
                    true_hits += 1;
                }
            }
            i += 1;
        }
        PrefilterResult {
            pattern: "e[0-9]",
            raw_candidates: raw_cands,
            valve_candidates: valve_cands,
            quenched_pct: 100.0 * (1.0 - valve_cands as f64 / raw_cands as f64),
            diodicity: raw_cands as f64 / valve_cands.max(1) as f64,
            true_matches: true_hits,
        }
    };

    println!("| Pattern | Forward Stream (Raw) | Diodic Admitted | Quenched Noise | Diodicity (Di) | True Hits |");
    println!("|---|---:|---:|---:|---:|---:|");
    for res in &[&pub_fn_res, &foo_bar_res, &e_digit_res] {
        println!(
            "| `{}` | {} | {} | **{:.2}%** | **{:.1}x** | {} |",
            res.pattern,
            res.raw_candidates,
            res.valve_candidates,
            res.quenched_pct,
            res.diodicity,
            res.true_matches,
        );
    }
    println!();
}

// ---------------------------------------------------------------------------
// Part 2: Diodic Corpus N-Gram Index (Item 3)
// ---------------------------------------------------------------------------

// The signature filter itself lives in `rgx_core::ngram`, so the query
// path and this harness cannot drift apart. the `Sig*` aliases keep the short name
// the harness prints in its tables.
use rgx_core::ngram::{
    build_query256, build_query512, build_sig256, build_sig512, NgramSig256 as Sig256,
    NgramSig512 as Sig512,
};

fn test_diodic_corpus_index(tree_path: &Path) {
    println!("==============================================================================");
    println!("Part 2: Diodic Corpus N-Gram Index (Item 3: Multi-File Pruning)");
    println!("Corpus directory: {}", tree_path.display());
    println!("==============================================================================");

    let t_walk = Instant::now();
    let mut files = Vec::new();
    collect_rs_files(tree_path, &mut files);
    // Path order, not readdir order. The harvest selects by content digest
    // (`scripts/harvest-ngram-corpus.py`); the registry fallback cannot
    // promise that, but it can at least be stable within one snapshot.
    files.sort();
    let walk_ms = t_walk.elapsed().as_secs_f64() * 1000.0;
    println!("Found {} .rs files in {:.2} ms", files.len(), walk_ms);

    if files.is_empty() {
        println!("No .rs files found at {}", tree_path.display());
        return;
    }

    let test_set = if files.len() > 15000 {
        &files[..15000]
    } else {
        &files[..]
    };
    println!(
        "Benchmarking 256-bit and 512-bit diodic signatures over {} files...\n",
        test_set.len()
    );

    let mut sigs256: Vec<Sig256> = Vec::with_capacity(test_set.len());
    let mut sigs512: Vec<Sig512> = Vec::with_capacity(test_set.len());
    let mut contents: Vec<Vec<u8>> = Vec::with_capacity(test_set.len());
    let mut file_digests: Vec<String> = Vec::with_capacity(test_set.len());
    let mut total_bytes = 0usize;

    for path in test_set {
        let content = fs::read(path).unwrap_or_default();
        total_bytes += content.len();
        // The corpus name is computed the way the harvest computes it:
        // sha256 over the sorted per-file hex digests, so two runs can
        // prove they measured the same bytes.
        file_digests.push(hex(&rgx_core::sha256::Sha256::hash(&content)));
        sigs256.push(build_sig256(&content));
        sigs512.push(build_sig512(&content));
        contents.push(content);
    }
    file_digests.sort_unstable();
    let mut corpus_hasher = rgx_core::sha256::Sha256::new();
    for d in &file_digests {
        corpus_hasher.update(d.as_bytes());
        corpus_hasher.update(b"\n");
    }
    let mb = total_bytes as f64 / 1_000_000.0;
    println!(
        "Corpus subset loaded: {} files ({:.2} MB)",
        test_set.len(),
        mb
    );
    println!("Corpus digest: sha256:{}", hex(&corpus_hasher.finalize()));
    println!(
        "256-bit index size: {:.2} KB (32 bytes/file)",
        (sigs256.len() * 32) as f64 / 1024.0
    );
    println!(
        "512-bit index size: {:.2} KB (64 bytes/file)\n",
        (sigs512.len() * 64) as f64 / 1024.0
    );

    let patterns = ["fn main", "pub fn", "let mut", "struct "];

    bench_width(
        "256-bit Diodic Signature",
        &sigs256,
        &contents,
        &patterns,
        build_query256,
        |s: &Sig256, q| s.contains_query(q),
    );
    bench_width(
        "512-bit Diodic Signature",
        &sigs512,
        &contents,
        &patterns,
        build_query512,
        |s: &Sig512, q| s.contains_query(q),
    );
}

/// What the latency column measures, stated once: per file, one subset
/// test and one `Vec<bool>` push -- nothing else. Not the signature build,
/// not the ground truth, not the print. Both widths run THIS loop through
/// their own `contains`, so their latency columns are one measurement and
/// cannot drift apart the way two near-identical loops did.
fn bench_width<S, Q>(
    title: &str,
    sigs: &[S],
    contents: &[Vec<u8>],
    patterns: &[&str],
    build_query: impl Fn(&str) -> Option<Q>,
    contains: impl Fn(&S, &Q) -> bool,
) {
    println!("--- {} ---", title);
    println!(
        "| Query Pattern | Admitted Files | Pruned Files | Prune Efficiency | Valve Filter Latency | True Positive Files | False Negatives |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|");

    for &pat in patterns {
        let Some(q_sig) = build_query(pat) else {
            continue;
        };

        // Ground truth computed outside timing loop
        let ground_truth: Vec<bool> = contents
            .iter()
            .map(|c| rgx_core::memchr::memmem::find(c, pat.as_bytes()).is_some())
            .collect();
        let true_files: usize = ground_truth.iter().filter(|&&b| b).count();

        // Timed diodic filtering loop
        let t_query = Instant::now();
        let mut admitted = 0usize;
        let mut pruned = 0usize;
        let mut passes = Vec::with_capacity(sigs.len());

        for sig in sigs {
            let pass = contains(sig, &q_sig);
            passes.push(pass);
            if pass {
                admitted += 1;
            } else {
                pruned += 1;
            }
        }
        let q_us = t_query.elapsed().as_secs_f64() * 1_000_000.0;
        let prune_pct = 100.0 * pruned as f64 / (admitted + pruned) as f64;

        // Verify zero false negatives
        let mut false_neg = 0usize;
        for i in 0..sigs.len() {
            if !passes[i] && ground_truth[i] {
                false_neg += 1;
            }
        }

        println!(
            "| `{}` | {} | {} | **{:.2}%** | **{:.2} µs** ({:.2} ns/file) | {} | **{}** |",
            pat,
            admitted,
            pruned,
            prune_pct,
            q_us,
            (q_us * 1000.0) / sigs.len() as f64,
            true_files,
            false_neg
        );
    }
    println!();
}

/// Lowercase hex of a digest.
fn hex(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 15) as u32, 16).unwrap());
    }
    s
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn main() {
    println!("\n=== DIODIC SEARCH & INDEXING BENCHMARK ===");
    println!("Testing the fluidic diode principle applied to string search & indexing.\n");

    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    let big_path = PathBuf::from(&home).join(".rgx-bench").join("big235.rs");
    if big_path.exists() {
        test_diodic_simd_choker(&big_path);
    } else {
        println!(
            "Note: Single-file corpus not found at {}",
            big_path.display()
        );
    }

    let registry = PathBuf::from(&home)
        .join(".cargo")
        .join("registry")
        .join("src");
    // --corpus <dir> names a harvested, digest-named corpus
    // (scripts/harvest-ngram-corpus.py): the same bytes on every host, so
    // the prune-rate rows of two runs are comparable. Without it the
    // registry walk stands in, which is what the earlier runs used and why
    // their absolute rates were not comparable across machines.
    let corpus_override: Option<PathBuf> = {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        argv.iter()
            .position(|a| a == "--corpus")
            .and_then(|i| argv.get(i + 1))
            .map(PathBuf::from)
    };
    let tree_path = if let Some(dir) = corpus_override {
        dir
    } else if registry.exists() {
        // find largest dir under registry
        let mut best: Option<PathBuf> = None;
        if let Ok(rd) = fs::read_dir(&registry) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    best = Some(p);
                    break;
                }
            }
        }
        best.unwrap_or(PathBuf::from("crates"))
    } else {
        PathBuf::from("crates")
    };

    test_diodic_corpus_index(&tree_path);
}
