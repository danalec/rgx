# N-gram signature runs — both hosts, one corpus

The transcripts behind `tab:ngram` of the paper (the `rgx-paper` repository). Both runs
are the same harness over the same corpus: 15,000
`.rs` files harvested by content digest with
`scripts/harvest-ngram-corpus.py`, 337,661,955 bytes, corpus
`sha256:b6b019452a602d3f9089c5bc7e11493b79fbd2e02d2266014a22db3e5f9656b0`
(both runs print the same name; `--verify` on the corpus directory
recomputes it).

The prune columns agree to the file across hosts — that is the point of
the named corpus — and the latency columns come from one timer scope
(`bench_width`: per file, one subset test and one `Vec<bool>` push).

## Run A — Windows (primary host)

Command: `cargo run --release -p rgx-core --example diodicity -- --corpus ~/.rgx-bench/ngram-corpus`

```
Corpus subset loaded: 15000 files (337.66 MB)
Corpus digest: sha256:b6b019452a602d3f9089c5bc7e11493b79fbd2e02d2266014a22db3e5f9656b0

--- 256-bit Tesla Valve Signature ---
| `fn main` | 12415 | 2585 | 17.23% | 3.02 ns/file | 1408 | 0 |
| `pub fn`  | 13013 | 1987 | 13.25% | 2.20 ns/file | 6584 | 0 |
| `let mut` | 12524 | 2476 | 16.51% | 2.76 ns/file | 6550 | 0 |
| `struct ` | 13243 | 1757 | 11.71% | 2.10 ns/file | 8207 | 0 |

--- 512-bit Tesla Valve Signature ---
| `fn main` | 10505 | 4495 | 29.97% | 4.31 ns/file | 1408 | 0 |
| `pub fn`  | 11355 | 3645 | 24.30% | 4.23 ns/file | 6584 | 0 |
| `let mut` | 10601 | 4399 | 29.33% | 4.25 ns/file | 6550 | 0 |
| `struct ` | 11660 | 3340 | 22.27% | 6.06 ns/file | 8207 | 0 |
```

## Run B — CachyOS (second host)

Machine: AMD Ryzen 7 255 w/ Radeon 780M, CachyOS `Linux 7.2.7-1-cachyos`.

Command:
`cargo run --release -p rgx-core --example diodicity -- --corpus ~/ngram-corpus`

```
Corpus subset loaded: 15000 files (337.66 MB)
Corpus digest: sha256:b6b019452a602d3f9089c5bc7e11493b79fbd2e02d2266014a22db3e5f9656b0

--- 256-bit Tesla Valve Signature ---
| `fn main` | 12415 | 2585 | 17.23% | 4.38 ns/file | 1408 | 0 |
| `pub fn`  | 13013 | 1987 | 13.25% | 2.49 ns/file | 6584 | 0 |
| `let mut` | 12524 | 2476 | 16.51% | 2.65 ns/file | 6550 | 0 |
| `struct ` | 13243 | 1757 | 11.71% | 2.51 ns/file | 8207 | 0 |

--- 512-bit Tesla Valve Signature ---
| `fn main` | 10505 | 4495 | 29.97% | 5.61 ns/file | 1408 | 0 |
| `pub fn`  | 11355 | 3645 | 24.30% | 4.81 ns/file | 6584 | 0 |
| `let mut` | 10601 | 4399 | 29.33% | 6.65 ns/file | 6550 | 0 |
| `struct ` | 11660 | 3340 | 22.27% | 7.08 ns/file | 8207 | 0 |
```

Zero false negatives on every row of both runs. The 512-bit signature
prunes strictly more than the 256-bit one on every pattern, in identical
counts on both hosts.
