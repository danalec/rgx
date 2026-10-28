// SPDX-License-Identifier: Apache-2.0

//! Occupancy (balls-in-bins) model of the per-file n-gram signature.
//!
//! What this measures: `rgx_core::ngram` inserts each non-noise 4-gram twice
//! per file (forward hash into one half of the signature, reverse hash into
//! the other) and tests a query as a subset. Modelling each half as `h = B/2`
//! bins receiving `n` uniform balls, the fraction of files a query with `m`
//! tested bits cannot prune is
//!
//! ```text
//! P(non-prune | n, m) = (1 - (1 - 1/h)^n)^m
//! ```
//!
//! (inclusion-exclusion over the `m` bins under Poissonisation; see
//! `benchmark/findings.md` for the derivation). This harness compares that
//! prediction against the measured subset-test outcome on real corpora, per
//! width (256 / 512), per noise threshold, and it reports the two assumption
//! failures the model can have: hash-placement uniformity (occupancy check)
//! and vocabulary overlap between query and file (the calibrated column).
//!
//! The hash replica below is pinned to `rgx_core::ngram` by assertion on
//! every file: the replica's 512-bit words must equal `build_sig512`'s, and
//! the 256-bit replica must answer `contains_query` exactly as the real one
//! for every probe. If an assertion fires the harness is wrong, not the
//! filter. The threshold sweep is therefore trustworthy even though the
//! constants it sweeps are not compiled into the real builder.
//!
//! Deterministic over a corpus: paths sorted, one timer scope per phase, and
//! a sha256 corpus digest so two runs can prove they measured the same bytes.

use rgx_core::frequency::{cost, rank};
use rgx_core::ngram::{
    build_query256, build_query512, build_sig256, build_sig512, query_sig512, NgramSig512,
    NOISE_THRESHOLD_COST,
};
use rgx_core::sha256::Sha256;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Thresholds swept. The shipped gate sits in the middle so both directions
/// are measured; `u64::MAX` is the no-gate control (every gram counts).
const THRESHOLDS: [u64; 6] = [
    500_000_000,
    1_000_000_000,
    2_000_000_000,
    3_000_000_000,
    NOISE_THRESHOLD_COST,
    u64::MAX,
];

/// The query set: plain literals only (every byte is a literal-run byte), so
/// the spelling IS the required literal and `build_query*` is the deployed
/// `query_sig512` on these inputs (asserted). Lengths span the model's two
/// regimes: `q = 1` 4-gram (4-byte literals) up to `q = 12` (15 bytes).
/// `"u64"` is the stand-down control: no literal run of four bytes.
const PATTERNS: [&str; 13] = [
    "pub ",
    "todo",
    "fn main",
    "pub fn",
    "let mut",
    "struct ",
    "unwrap",
    "HashMap",
    "rgx_core",
    "ByteRegex",
    "compute_totals",
    "the quick brown",
    "u64",
];

/// Which patterns get the per-n calibration table (the model's SHAPE as a
/// function of file occupancy; the exponent `m` is the only per-pattern
/// degree of freedom, so four probes spanning `m` cover it).
const BIN_PROBES: [&str; 4] = ["pub ", "pub fn", "rgx_core", "the quick brown"];

/// n-bin edges over the file's distinct non-noise 4-gram count. `n = 0` is
/// its own bin: a zero signature stands the filter down and never prunes.
const BIN_EDGES: [u64; 8] = [16, 64, 256, 1024, 4096, 16384, 65536, u64::MAX];

const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Hash replica. Byte-for-byte the two functions in `rgx_core::ngram` (they
// are private there); the per-file assertion against `build_sig512` is what
// keeps this copy honest.
// ---------------------------------------------------------------------------

fn hash_forward(gram: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in gram {
        let r = rank(b) as u64;
        h ^= (b as u64) ^ (r << 4);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn hash_reverse(gram: &[u8]) -> u64 {
    let mut h = 0x9e3779b97f4a7c15u64;
    for &b in gram.iter().rev() {
        let r = rank(b) as u64;
        h ^= (b as u64) ^ (r << 5);
        h = h.rotate_left(11).wrapping_mul(0x517cc1b727220a95);
    }
    h
}

/// Insert one 4-gram into a signature laid out as `2 * half_words` u64
/// words: forward bits in `words[0..half_words]`, reverse bits in the rest.
fn insert(words: &mut [u64], half_words: usize, gram: &[u8]) {
    let h1 = hash_forward(gram);
    let word_fwd = ((h1 >> 6) as usize) & (half_words - 1);
    words[word_fwd] |= 1u64 << (h1 & 63);
    let h2 = hash_reverse(gram);
    let word_rev = half_words + (((h2 >> 6) as usize) & (half_words - 1));
    words[word_rev] |= 1u64 << (h2 & 63);
}

/// The real `contains_query` semantics: all query bits present, and an
/// all-zero file signature stands down rather than rejecting.
fn passes(file: &[u64], query: &[u64]) -> bool {
    if file.iter().all(|&w| w == 0) {
        return true;
    }
    file.iter().zip(query.iter()).all(|(&f, &q)| (f & q) == q)
}

fn popcount(words: &[u64]) -> u32 {
    words.iter().map(|w| w.count_ones()).sum()
}

/// Exact occupancy of one half after `n` uniform balls: `1 - (1 - 1/h)^n`.
fn occupancy(n: u64, half_bits: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }
    -((n as f64) * (-1.0 / half_bits as f64).ln_1p()).exp_m1()
}

/// The model: probability that all `m` tested bits are set after `n` balls.
fn pred_nonprune(n: u64, m: u32, half_bits: usize) -> f64 {
    if m == 0 {
        return 1.0;
    }
    occupancy(n, half_bits).powi(m as i32)
}

fn bin_index(n: u64) -> usize {
    if n == 0 {
        return 0;
    }
    BIN_EDGES
        .iter()
        .position(|&edge| n < edge)
        .unwrap_or(BIN_EDGES.len())
}

fn bin_label(i: usize) -> String {
    if i == 0 {
        return "0".to_string();
    }
    let lo = if i == 1 { 1 } else { BIN_EDGES[i - 2] };
    let hi = BIN_EDGES[i - 1];
    if hi == u64::MAX {
        format!("{lo}+")
    } else {
        format!("{lo}..{hi}")
    }
}

// ---------------------------------------------------------------------------
// Accumulators
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Default)]
struct Cell {
    total: u64,
    matched: u64,
    /// Files where the filter decided to skip scanning: `!q_stand_down && !pass`.
    /// The matched-file subset of this is the violation count, tracked separately.
    pruned: u64,
    /// matched file pruned -- the subset property violated. MUST stay 0.
    fn_bad: u64,
    nonmatch: u64,
    /// passes among non-matching files (false admits).
    fa: u64,
    pred_uniform: f64,
    pred_overlap: f64,
}

#[derive(Clone, Copy, Default)]
struct Bin {
    total: u64,
    nonmatch: u64,
    fa: u64,
    pred: f64,
}

#[derive(Clone, Copy, Default)]
struct Occ {
    n: u64,
    sum_abs: f64,
    sum_signed: f64,
}

/// Query side, precomputed per (pattern, threshold): the distinct passing
/// grams, the signature bits at both widths, and the tested-bit counts.
struct QuerySig {
    keys: Vec<u32>,
    words256: Vec<u64>,
    words512: Vec<u64>,
    m256: u32,
    m512: u32,
}

fn build_query_sig(pattern: &str, threshold: u64) -> QuerySig {
    let bytes = pattern.as_bytes();
    let mut seen: HashMap<u32, u64> = HashMap::new();
    for w in bytes.windows(4) {
        let key = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        seen.entry(key).or_insert_with(|| cost(w));
    }
    let mut keys = Vec::new();
    let mut words256 = vec![0u64; 4];
    let mut words512 = vec![0u64; 8];
    for (&key, &c) in &seen {
        if c <= threshold {
            let b = key.to_le_bytes();
            insert(&mut words256, 2, &b);
            insert(&mut words512, 4, &b);
            keys.push(key);
        }
    }
    QuerySig {
        m256: popcount(&words256),
        m512: popcount(&words512),
        keys,
        words256,
        words512,
    }
}

// ---------------------------------------------------------------------------
// Walk and digest
// ---------------------------------------------------------------------------

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            // `target` holds build artifacts, `.git` the object store; both
            // are noise this model is not about.
            if name == "target" || name == ".git" {
                continue;
            }
            walk(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

fn hex(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 15) as u32, 16).unwrap());
    }
    s
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let corpus = argv
        .iter()
        .position(|a| a == "--corpus")
        .and_then(|i| argv.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("crates"));

    println!("=== n-gram occupancy model harness ===");
    println!("corpus: {}", corpus.display());

    let t_walk = Instant::now();
    let mut files = Vec::new();
    walk(&corpus, &mut files);
    files.sort();
    let walk_ms = t_walk.elapsed().as_secs_f64() * 1000.0;

    let n_pat = PATTERNS.len();
    let n_thr = THRESHOLDS.len();
    let n_bins = BIN_EDGES.len() + 1;
    let mut cells256: Vec<Vec<Cell>> = vec![vec![Cell::default(); n_thr]; n_pat];
    let mut cells512: Vec<Vec<Cell>> = vec![vec![Cell::default(); n_thr]; n_pat];
    let mut bins512: Vec<Vec<Bin>> = vec![vec![Bin::default(); n_bins]; n_pat];
    let mut occ256 = Occ::default();
    let mut occ512 = Occ::default();
    let mut file_digests: Vec<String> = Vec::new();
    let mut total_bytes = 0usize;
    let mut skipped_big = 0usize;

    let t_build = Instant::now();
    for path in &files {
        let Ok(content) = std::fs::read(path) else {
            continue;
        };
        if content.len() > MAX_FILE_BYTES {
            skipped_big += 1;
            continue;
        }
        total_bytes += content.len();
        file_digests.push(hex(&Sha256::hash(&content)));

        // Distinct 4-gram -> cost. Duplicates are insertion no-ops, so the
        // model's ball count is this map's size under the threshold.
        let mut grams: HashMap<u32, u64> = HashMap::new();
        for w in content.windows(4) {
            let key = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            grams.entry(key).or_insert_with(|| cost(w));
        }

        // Ground truth per pattern: does the file hold the literal?
        let matched: Vec<bool> = PATTERNS
            .iter()
            .map(|p| rgx_core::memchr::memmem::find(&content, p.as_bytes()).is_some())
            .collect();

        // The real builders, for the pin below.
        let real256 = build_sig256(&content);
        let real512 = build_sig512(&content);

        for (ti, &threshold) in THRESHOLDS.iter().enumerate() {
            let mut s256 = vec![0u64; 4];
            let mut s512 = vec![0u64; 8];
            let mut n = 0u64;
            for (&key, &c) in &grams {
                if c <= threshold {
                    let b = key.to_le_bytes();
                    insert(&mut s256, 2, &b);
                    insert(&mut s512, 4, &b);
                    n += 1;
                }
            }
            let is_default = threshold == NOISE_THRESHOLD_COST;

            // Pin the replica to the real implementation at the shipped
            // threshold: identical words, not merely identical answers.
            if is_default {
                assert!(
                    real512 == NgramSig512::from_words(s512.clone().try_into().unwrap()),
                    "hash replica drifted from build_sig512 on {:?}",
                    path
                );
                // Measured occupancy is the set-bit fraction of the whole
                // signature, which equals the per-half fraction (both halves
                // receive every gram); the prediction is per half, so each
                // width gets its own `h = B/2`.
                let o256 = popcount(&s256) as f64 / 256.0;
                let o512 = popcount(&s512) as f64 / 512.0;
                occ256.sum_abs += (o256 - occupancy(n, 128)).abs();
                occ256.sum_signed += o256 - occupancy(n, 128);
                occ256.n += 1;
                occ512.sum_abs += (o512 - occupancy(n, 256)).abs();
                occ512.sum_signed += o512 - occupancy(n, 256);
                occ512.n += 1;
            }

            for (pi, pat) in PATTERNS.iter().enumerate() {
                let q = build_query_sig(pat, threshold);
                // The real query builders agree with the replica and with
                // each other on these literal patterns (shipped threshold).
                if is_default {
                    if let Some(real_q512) = build_query512(pat) {
                        assert!(
                            real_q512
                                == rgx_core::ngram::NgramSig512::from_words(
                                    q.words512.clone().try_into().unwrap()
                                ),
                            "query replica drifted from build_query512 on {pat:?}"
                        );
                        assert_eq!(
                            query_sig512(pat, false),
                            Some(real_q512),
                            "the deployed query builder must agree with \
                             build_query512 on the literal {pat:?}"
                        );
                    }
                    if let Some(real_q256) = build_query256(pat) {
                        let rep_pass = passes(&s256, &q.words256);
                        assert_eq!(
                            real256.contains_query(&real_q256),
                            rep_pass,
                            "256-bit replica drifted from the real contains_query \
                             on {pat:?} / {path:?}"
                        );
                    }
                }

                let q_stand_down = q.keys.is_empty();
                let pass = q_stand_down || passes(&s512, &q.words512);
                let pass256 = q_stand_down || passes(&s256, &q.words256);

                let cell512 = &mut cells512[pi][ti];
                let cell256 = &mut cells256[pi][ti];
                cell512.total += 1;
                cell256.total += 1;
                if !q_stand_down && !pass {
                    cell512.pruned += 1;
                }
                if !q_stand_down && !pass256 {
                    cell256.pruned += 1;
                }
                if matched[pi] {
                    cell512.matched += 1;
                    cell256.matched += 1;
                    if !pass {
                        cell512.fn_bad += 1;
                    }
                    if !pass256 {
                        cell256.fn_bad += 1;
                    }
                } else {
                    cell512.nonmatch += 1;
                    cell256.nonmatch += 1;
                    if pass {
                        cell512.fa += 1;
                    }
                    if pass256 {
                        cell256.fa += 1;
                    }
                    // The two model columns. `uniform` treats every tested
                    // bit as hit only by collision; `overlap` discounts the
                    // query bits the file's own grams already set (the file
                    // shares vocabulary with the query without holding the
                    // literal), which is where the uniform model is wrong.
                    let shared = q.keys.iter().filter(|k| grams.contains_key(k)).count() as u64;
                    let n_rand = n.saturating_sub(shared);
                    let mut m256 = q.m256;
                    let mut m512 = q.m512;
                    if shared > 0 {
                        let mut shared256 = vec![0u64; 4];
                        let mut shared512 = vec![0u64; 8];
                        for &k in &q.keys {
                            if grams.contains_key(&k) {
                                let b = k.to_le_bytes();
                                insert(&mut shared256, 2, &b);
                                insert(&mut shared512, 4, &b);
                            }
                        }
                        m256 = q
                            .words256
                            .iter()
                            .zip(shared256.iter())
                            .map(|(&qw, &sw)| (qw & !sw).count_ones())
                            .sum();
                        m512 = q
                            .words512
                            .iter()
                            .zip(shared512.iter())
                            .map(|(&qw, &sw)| (qw & !sw).count_ones())
                            .sum();
                    }
                    cell256.pred_uniform += pred_nonprune(n, q.m256, 128);
                    cell256.pred_overlap += pred_nonprune(n_rand, m256, 128);
                    cell512.pred_uniform += pred_nonprune(n, q.m512, 256);
                    cell512.pred_overlap += pred_nonprune(n_rand, m512, 256);

                    if is_default {
                        let bin = &mut bins512[pi][bin_index(n)];
                        bin.nonmatch += 1;
                        if pass {
                            bin.fa += 1;
                        }
                        bin.pred += pred_nonprune(n_rand, m512, 256);
                    }
                }
                if is_default {
                    // Every file lands in exactly one bin; the non-match
                    // counters above are its subset.
                    let bin = &mut bins512[pi][bin_index(n)];
                    bin.total += 1;
                }
            }
        }
    }
    let build_ms = t_build.elapsed().as_secs_f64() * 1000.0;

    file_digests.sort_unstable();
    let mut hasher = Sha256::new();
    for d in &file_digests {
        hasher.update(d.as_bytes());
        hasher.update(b"\n");
    }

    println!(
        "files: {} (skipped >{} bytes: {})  bytes: {:.2} MB",
        file_digests.len(),
        MAX_FILE_BYTES,
        skipped_big,
        total_bytes as f64 / 1_000_000.0
    );
    println!("corpus digest: sha256:{}", hex(&hasher.finalize()));
    println!("walk: {walk_ms:.1} ms   grams+models: {build_ms:.1} ms");
    println!(
        "thresholds: {:?}",
        THRESHOLDS
            .iter()
            .map(|t| if *t == u64::MAX {
                "inf".to_string()
            } else {
                format!("{:.2e}", *t as f64)
            })
            .collect::<Vec<_>>()
    );

    // -- occupancy check: assumption A (uniform placement) -------------
    println!("\n== occupancy check at the shipped threshold (bits set per half / predicted) ==");
    println!("| width | mean |measured - predicted| | mean signed error | files |");
    println!("|---|---:|---:|---:|");
    for (label, occ) in [("256", &occ256), ("512", &occ512)] {
        println!(
            "| {} | {:.4} | {:+.4} | {} |",
            label,
            occ.sum_abs / occ.n.max(1) as f64,
            occ.sum_signed / occ.n.max(1) as f64,
            occ.n
        );
    }

    // -- main table: measured vs predicted prune rate, both widths ------
    let ti_default = THRESHOLDS
        .iter()
        .position(|&t| t == NOISE_THRESHOLD_COST)
        .unwrap();
    println!(
        "\n== prune rate at T={:.2e} (predicted = uniform model over ALL files) ==",
        NOISE_THRESHOLD_COST as f64
    );
    println!("| pattern | q | m256 | m512 | matches | prune% 256 meas | prune% 256 pred | prune% 512 meas | prune% 512 pred |");
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|");
    for (pi, pat) in PATTERNS.iter().enumerate() {
        let c256 = &cells256[pi][ti_default];
        let c512 = &cells512[pi][ti_default];
        let q = build_query_sig(pat, NOISE_THRESHOLD_COST);
        let pred256 = if c256.total == 0 {
            0.0
        } else {
            100.0 * (1.0 - (c256.matched as f64 + c256.pred_uniform) / c256.total as f64)
        };
        let pred512 = if c512.total == 0 {
            0.0
        } else {
            100.0 * (1.0 - (c512.matched as f64 + c512.pred_uniform) / c512.total as f64)
        };
        println!(
            "| `{}` | {} | {} | {} | {} | {:.2} | {:.2} | {:.2} | {:.2} |",
            pat,
            q.keys.len(),
            q.m256,
            q.m512,
            c512.matched,
            100.0 * c256.pruned as f64 / c256.total.max(1) as f64,
            pred256,
            100.0 * c512.pruned as f64 / c512.total.max(1) as f64,
            pred512
        );
    }

    // -- false admits on non-matching files: the model's real test -----
    println!(
        "\n== false admits, non-matching files only (T={:.2e}) ==",
        NOISE_THRESHOLD_COST as f64
    );
    println!("| pattern | width | non-match | meas FA% | pred FA% uniform | pred FA% overlap-calibrated |");
    println!("|---|---|---:|---:|---:|---:|");
    for (pi, pat) in PATTERNS.iter().enumerate() {
        for (label, cells) in [("256", &cells256), ("512", &cells512)] {
            let c = &cells[pi][ti_default];
            if c.nonmatch == 0 {
                continue;
            }
            println!(
                "| `{}` | {} | {} | {:.3} | {:.3} | {:.3} |",
                pat,
                label,
                c.nonmatch,
                100.0 * c.fa as f64 / c.nonmatch as f64,
                100.0 * c.pred_uniform / c.nonmatch as f64,
                100.0 * c.pred_overlap / c.nonmatch as f64
            );
        }
    }

    // -- calibration by n-bin ------------------------------------------
    println!(
        "\n== calibration by file gram count (512-bit, T={:.2e}, non-matching only) ==",
        NOISE_THRESHOLD_COST as f64
    );
    for pat in BIN_PROBES {
        let pi = PATTERNS.iter().position(|p| *p == pat).unwrap();
        println!("pattern `{pat}`:");
        println!("| n bin | files | non-match | meas FA% | pred FA% |");
        println!("|---|---:|---:|---:|---:|");
        for (bi, bin) in bins512[pi].iter().enumerate() {
            if bin.total == 0 {
                continue;
            }
            if bin.nonmatch == 0 {
                println!("| {} | {} | 0 | - | - |", bin_label(bi), bin.total);
                continue;
            }
            println!(
                "| {} | {} | {} | {:.3} | {:.3} |",
                bin_label(bi),
                bin.total,
                bin.nonmatch,
                100.0 * bin.fa as f64 / bin.nonmatch as f64,
                100.0 * bin.pred / bin.nonmatch as f64
            );
        }
    }

    // -- threshold sweep -----------------------------------------------
    println!("\n== threshold sweep (512-bit) ==");
    println!("| T | pattern | q(T) | m(T) | meas prune% | pred prune% uniform | pred prune% calibrated |");
    println!("|---|---|---:|---:|---:|---:|---:|");
    for (ti, &threshold) in THRESHOLDS.iter().enumerate() {
        let t_label = if threshold == u64::MAX {
            "inf".to_string()
        } else {
            format!("{:.2e}", threshold as f64)
        };
        for (pi, pat) in PATTERNS.iter().enumerate() {
            let c = &cells512[pi][ti];
            let q = build_query_sig(pat, threshold);
            let pred_u = if c.total == 0 {
                0.0
            } else {
                100.0 * (1.0 - (c.matched as f64 + c.pred_uniform) / c.total as f64)
            };
            let pred_o = if c.total == 0 {
                0.0
            } else {
                100.0 * (1.0 - (c.matched as f64 + c.pred_overlap) / c.total as f64)
            };
            println!(
                "| {} | `{}` | {} | {} | {:.2} | {:.2} | {:.2} |",
                t_label,
                pat,
                q.keys.len(),
                q.m512,
                100.0 * c.pruned as f64 / c.total.max(1) as f64,
                pred_u,
                pred_o
            );
        }
    }

    // -- soundness: the whole sweep is worthless if any of these fired --
    println!("\n== soundness (matched file pruned) ==");
    let mut fn_total = 0u64;
    for cells in [&cells256, &cells512] {
        for row in cells {
            for c in row {
                fn_total += c.fn_bad;
            }
        }
    }
    println!("subset violations across every (pattern, threshold, width): {fn_total}");
    assert_eq!(
        fn_total, 0,
        "the subset property must hold at every threshold"
    );
}
