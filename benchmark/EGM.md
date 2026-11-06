# benchmark

## Overview

`benchmark/` holds the measurements that shaped the code and the harnesses that
produce them. The bulk of it is written record: `status.md` and
`status-linux-ryzen7-255.md` are the two host dashboards, `findings.md` is the
question/evidence/conclusion log of every measurement and defect that moved the
code, and the `*-transcript.md` files are the raw runs those conclusions quote.
The tables live in `status.md` and are not repeated elsewhere, because a number
that exists in two files is a number that will exist in two versions.

Three programs live here as well, and they are the harness behind the
transcripts. `extent-ab.sh` and `extent-ab.ps1` are the extent-sparse A/B — one
binary, two arms, with `RGX_ABLATE_EXTENTS` as the control. `regress.py` is the
cross-run regression detector: it reads `tv-cold.sh` transcripts and reports what
moved, by how many sigma, and which arms held still and are therefore the
control. Its algorithm is not kept apart from its wiring — `median`,
`mad_flag` and the whole `ScalarKalman` class live inside `regress.py` itself.
The file `benchmark/kalman-drift.py` that once held them is named only by
`regress.py`'s docstring and by its printed footer, and it is not part of this
tree.

The differential harness against ripgrep is the child directory
[`diffrig`](./diffrig/EGM.md).

## Interface

- `bash benchmark/extent-ab.sh --corpus crates --rounds 7 [--store DIR] [--patterns "a,b"] [--ablate-var VAR]` — the extent-sparse A/B: builds a pack store once, measures the spawn floor, runs the count gate, then times both arms in rotated rounds. Prints the floor, the gate's verdict, per-arm min/median/median-floor and the verdict (`overlap`, `tie inside the +-3% floor`, `sparse wins`, `ablated wins`).
- `powershell -File benchmark/extent-ab.ps1 -Corpus ..\..\crates -Rounds 7 [-Store DIR] [-Patterns "a,b"] [-AblateVar VAR]` — the Windows twin of the same protocol, with the same rows.
- `python3 benchmark/regress.py RUN1 [RUN2 RUN3 …]` — compares `tv-cold.sh` transcripts in the order given, oldest first. Public surface: `median(xs)`, `mad_flag(pairs)`, `parse(path) -> (stamp, arms)`, `summarise(arms)`, `main(argv)`, and the class `ScalarKalman(x0, p0, q, r)` with `step(z_log)`. Prints one row per `(arm, stat)`, the `MOVED` list, the `HELD` control list, and the `Q`/`R`/threshold line. Stdlib only; nothing is written.
- `diffrig` — [diffrig](./diffrig/EGM.md) — the byte-for-byte differential harness against `rg`: `cmp.sh` (one case), `fuzz.py` (a pattern × flag matrix), `ptytest.py` (POSIX pty), `conpty.py` (Windows ConPTY), and the `fx/` fixture corpus.

## Invariants

- The count gate stands in front of every timing: an arm whose `-c` disagrees with the other arm or with the direct path prints no timing at all.
- The spawn floor is measured first and subtracted from both sides; a row whose floor-subtracted median is at or below zero is refused as `under the floor -- not a result`, and a ratio within ±3% is a tie.
- A winner is named only when every sample of one arm sits below every sample of the other. Overlapping distributions print `overlap`, which is not a result.
- The two twins (`extent-ab.sh` and `extent-ab.ps1`) run the same protocol and print the same rows for the same inputs.
- The rounds alternate their order (A,B then B,A), so no arm is permanently first or permanently last.
- A transcript quotes only what the harness printed. A number that is not in a transcript does not go into a table.
- A millisecond is always quoted with its host, and a ratio with both. The two dashboards do not agree on the sign of the engine-alone edge on six of nine pattern shapes, so a figure without its host is not a figure.
- `regress.py` fits each `(arm, stat)` series in log space; a series with fewer than two runs is not fitted at all, and the arms that did not move are printed as the control.

## Side Effects

- Builds a pack store with `rgx-tv build <corpus> --store <dir>`; the store is created in a temporary directory unless one is named, it is kept there, and its path is printed at the end.
- Spawns `rgx` and `rgx-tv`. Both twins make the same three refusals, each one line on stderr and exit status 2: no `rgx-tv` at the path, no `rgx` at the path, or no corpus.
- Prints its rows to stdout and writes no file into the repository; the transcript can be pasted into a transcript without dirtying the tree.
- Reads the checked-in corpus of `crates/` when no other corpus is named.
- The differential child writes `.rg.err` and `.rgx.err` inside `diffrig/` — both gitignored — and `fuzz.py` rewrites three of its tracked fixtures.

## Verification

- Run: `cargo test --release --locked --workspace`
- The differential harness is its own check: `cd benchmark/diffrig && bash cmp.sh "fn main" ../../src/main.rs` and `python fuzz.py`.
