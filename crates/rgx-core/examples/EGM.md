# examples

## Overview
Twenty-two one-off diagnostics for the engine. They are not API demonstrations and they are not part of the published crate — the `include` list in `Cargo.toml` ships `/src/**` and the manifest, the README, the licence and the notice. Each one exists because a claim about the engine needed a number rather than an argument, and each writes that number to stdout in a form a human reads.

They share a shape: a corpus path or a pattern list comes from the command line or from an environment variable (`json_bench` takes neither: it generates its corpora in-process), and a warmup is run and discarded before the timed rounds. Most measure in-process, so no process-spawn floor is inside the interval; three do not — `status_table` spawns both binaries and times the wall clock, `thread_curve` spawns the `rgx` binary and subtracts a measured spawn floor, and `pipeline_profile` prices whole `rgx` invocations. Where a row could print a speed that is not measuring the work it claims to measure, the file carries a gate in front of it — `status_table` and `json_bench` both refuse to print a number whose consumer output is empty or differs across rounds.

## Interface
- `anchor_probe.rs` — prints `ByteRegex::anchor_info()` for a list of patterns; the anchors the engine would pick for each.
- `casefold_cost.rs` — what Unicode case folding costs the matcher: whether a fixed literal was found, the program size, and MB/s over a real corpus slice.
- `confirm_profile.rs` — what one confirm costs, and *which* confirm, on the candidate stream a real search actually builds.
- `cost_sensitivity.rs` — the cost model's arithmetic on the real corpus, with the prices taken apart and the crossover between any two anchors computed.
- `dense_ablate.rs` — where the in-house engine's time goes on dense input: each row switches one configuration off or on and the difference is that piece's price.
- `dense_pieces.rs` — the same question decomposed piece by piece, by rebuilding the line loop with one piece at a time and taking the marginal difference between consecutive rows; the last row of each ladder is the shipped code, measured through the real `Searcher`.
- `density_probe.rs` — the density estimator measured against the density: which bytes the density is counted over, for each pattern and each arm of `rgx_core::regex::Sampling`.
- `diodicity.rs` — the candidate-stream diodicity harness: how many false candidates the engine discards per byte it admits.
- `json_accept.rs` — the conformance gate for `rgx_core::djson`: read the document named as the first argument and exit 0 if it was accepted, nonzero if it was rejected. That is the whole interface a parser harness assumes — the `json-harness` suite it names is not in this tree.
- `json_bench.rs` — where a JSON parse spends its time (Stage 1 scan, full parse into an `Arena`, the consumer walk, the serialisation) and what the materialisation costs in bytes as well as in time.
- `json_dump.rs` — the differential JSON dump, byte-identical to the canonical line: the canonical tokens alone for an accepted document, `NO <error category>` for a rejected one, with the numbers carried in their original source spelling.
- `json_intern_bench.rs` — the JSON arena's string interning on a document with many distinct keys: the path where the `no_std` build used to scan the whole string table for every string.
- `json_probe.rs` — prints what the JSON parser does with a battery of awkward inputs, so a review can see the behaviour instead of inferring it from the source.
- `memchr_bench.rs` — the byte scan rgx used to write itself against the crate it uses now; both implementations link into one binary and run over the same buffers, so the comparison is same-process and same-input.
- `ngram_occ.rs` — the occupancy (balls-in-bins) model of the per-file n-gram signature: the predicted non-prune fraction against the measured subset-test outcome, per width and per noise threshold.
- `pipeline_profile.rs` — where the wall clock goes when `rgx` searches a real corpus, split at the boundaries the pipeline actually has; the answer decides where an optimisation can possibly pay.
- `scan_floor.rs` — whether `pair_offsets` is the bottleneck or the memory system: a raw byte walk against nine kernels over the same buffer — `scan::pair_offsets` with a 3- and a 7-byte needle, `scan::byte_bits`, `scan::pair_bits` with a 3- and a 7-byte needle, `scan::term_bits`, the 64 KiB-granularity variants of the last two, both maps per fill, and the fused `scan::pair_term_bits`.
- `sha256_bench.rs` — SHA-256 kernel throughput: Intel SHA-NI against the scalar block function in `src/sha256_ref.rs`. A kernel-level number and nothing more.
- `status_table.rs` — the two tables of `benchmark/status.md` §2 from one command, over three corpora, with a gate on every row that can refuse to print a speed.
- `straight_probe.rs` — what `fixed.rs` refuses, and what a straight-path predicate would decide instead, measured on the candidates the real searcher produces.
- `thread_curve.rs` — the `-j` saturation curve: where thread scaling stops buying, and whether `auto = all cores` is still the right default past that point.
- `vm_probe.rs` — what one `vm::find_at` costs per pattern with no searcher around it, and — in the ablation block — which part of that cost is the VM.

## Invariants
- Every example is a diagnostic: it reads, measures and prints. None of them is on the `rgx` binary's path, and none of them is linked into the library.
- A measurement runs in-process, with a warmup discarded and the *minimum* of the timed rounds reported — the minimum is the round least disturbed by the scheduler, and it is the number that describes the code rather than the machine. The three that measure the CLI instead (`status_table`, `thread_curve`, `pipeline_profile`) spawn the binaries and time the wall clock, and `thread_curve` subtracts a measured spawn floor. `scan_floor` is the exception on the warmup: it warms the pages in a separate pass and then takes the minimum of seven rounds, with no discarded round of the measured work.
- `black_box` wraps inputs and results so LLVM cannot hoist a measured row out of the loop.
- A row that cannot show it is measuring the work it claims to measure does not print a speed: the gate is in front of the number, not after it.
- The corpus is the operator's: a path is named by an argument or by an environment variable, so the example does not carry one machine's layout into the tree — `scan_floor` is the exception, falling back to the literal `.rgx-bench/big235.rs`.
- The examples print to stdout and read nothing but their arguments and the corpus they are given — `json_dump` is the exception, reading a list of document paths from stdin when given no argument. They change no configuration.
- Two of them write files: `status_table` writes the report to `--out PATH` and, with `--flush`, fills a 64 MB `rgx-status-flush.bin` in the temp directory; `thread_curve` writes its report to `--out`.

## Side Effects
- Read the corpus file or directory they are given, and write their report to stdout.
- Allocate their own buffers and hold the corpus in memory where the measurement needs it to be resident; several of them read a whole file into memory so every row runs over the same bytes in the same process.
- Touch no global configuration and no lock; the only files they write are their own reports (`status_table` and `thread_curve`, both through `--out`) and `status_table`'s `--flush` buffer in the temp directory.

## Verification
- Run: `cargo test --release --locked --workspace`
