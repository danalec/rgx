# rgx: Findings

Measurements and defects that shaped the code. One section each: the
question, the evidence, the conclusion. Working that no longer needs its own
file lives here; the tables live in [`status.md`](status.md).

---

## 1. Where a walk-dominated corpus spends its time

**Question.** The `crates` row prices as a tie against ripgrep and is called
per-walker fixed cost. Where does the time actually go?

**Evidence.** `scripts/walk_patterns.rs` against the same tree, varying one
input at a time: the walk is **85.7%** of a 12.43 ms run; `--no-ignore` takes
it to 3.54 ms, so **7.01 ms is `.gitignore` matching** against 0.88 ms for
read plus engine combined. The mechanism is the **COMPILE of the rule set**,
once per `.gitignore`, at ~58 µs per pattern — not a per-entry match. Holding
patterns at 65 and moving entries from 1 to 1024 moves 4.55 → 7.86 ms; a
per-(entry × pattern) cost would move 16×. It is gated on `.git` presence: a
tree without one has its `.gitignore` compiled and never consulted.

**Conclusion.** The fast-shape path for `.gitignore` existed and was
unreachable for years because the builder demanded *every* file glob have a
`*.ext` or `pre*` shape, and this repository's own ignore file was 17 of 35.
One anchored line cost the whole file its fast path. The per-glob split that
stops the demand is measured and **not in the tree** -- `Globs::build` still
stops the fast list at one complicated glob, so the walk above is what ships.
Where it lands the `crates` walk goes 10.73 to 6.09 ms with the ignore cost
down 58%, `last match wins` kept across both lists by index. Full working,
the measured patch, and the three unbuilt fixes (extend the shapes, cache the
compiled set across walks, a first-byte bitmap over the remainder): the
file's history in `git log -- benchmark/walk-cost-attribution.md`.

## 2. `--sort path` sorted `--files` and not search output

**Question.** Does `--sort path` make output order deterministic?

**Evidence.** `rgx --sort path 'needle' /tmp/so` printed `inner/b.txt` before
`a.txt` on every run — walk order, not path order. Caught by a flaky
equivalence test. The first fix sorted a `Vec<Msg>` at the printer: correct,
but it buffered every matched file, unbounded on a pattern matching a whole
tree.

**Conclusion.** The walker now emits in path order itself
(`Builder::ordered`), `--sortr path` walks backwards, and the printer streams
one message at a time. Peak working set is flat across 16× the matched files
(6432 / 6480 / 6716 KiB at 500 / 2000 / 8000). Engine impact: none — proved
with `status_table --rgx-base`, every row inside ±3.0%.

## 3. `--files` compiled a path as a regex

**Question.** Why does `rgx --files C:\src\p0` fail?

**Evidence.** `error: regex parse error at 9: unicode property \p is not
supported by the byte engine`. The path was passed to the regex compiler.
Any Windows path whose component begins with an escape introducer (`\p`,
`\x`, `\d`, …) failed outright.

**Conclusion.** Found by running the tool, not the suite. Fixed; regression
test added. The general question — every place a user string reaches a parser
— was audited afterwards (`user-string-to-regex`): no second defect in code,
but two wrong CLI claims in `AGENTS.md` §4 were corrected.

## 4. Picking a better pair for the literal prefilter does not help

**Question.** `scan.rs::pair_offsets` tests `needle[0]` and `needle[k]`. Does
testing two *other* offsets prune more candidates?

**Evidence.** Measured against `let mut` (the row the pair is tuned for) and
14 further patterns. Some patterns do have a rarer pair; none of them run
faster. The current pair is already the best of its 21 candidates on `let
mut`; `frequency::rarest_pair` is 22% worse. Candidates are only 12% of that
row — the line walk is the rest.

**Conclusion.** Negative result. Do not re-derive. The same reasoning killed
the rewrite of the pair kernels for throughput: `pair_offsets` measures
**40–46 GB/s** against a 10 GB/s naive byte walk, so the kernel is 7 ms of a
43 ms `search=` and the rest is the line walk.

## 5. Line-walk bookkeeping: three cuts, one negative

**Question.** The pair finding attributed ~57% of `search=` to "the line walk
and its per-fill bookkeeping". Can any of it be removed?

**Evidence.** Three cuts measured with `status_table --rgx-base`, interleaved,
±3% floor: hoisting `fast.plan` out of the per-line confirm is ~0.4%; the
per-file micro-optimisations (double `stat`+`open` above `BUFFER_PATH_MAX`,
three per-worker regex compiles, a `GetConsoleMode` per matched file) all
measure **inside the floor** — every published row came out "overlap, not a
result". Raising `LineBuffer::INITIAL_BUF` from 64 KiB to 256 KiB to cut
`ReadFile` syscalls is **slower**: the two bit maps scale with the fill and
evict the haystack from L2 (~50 ms against ~43 on the absent literal).

**Conclusion.** Redundant work is worth removing; it is not worth a number.
The `MAX_BITMAP_INPUT` verdict ("raising it loses 14%") was later reversed
after the LineBuffer drop fix - see §18 below. Both the old "raise
it and you lose" and "the fix is a windowed map" are superseded.

## 6. The engine-alone edge is not portable across hosts

**Question.** The Windows dashboard reports rgx ahead of ripgrep on all nine
single-file pattern shapes by +33% to +114%. Is that a property of the code?

**Evidence.** Same corpus (byte-identical `big235.rs`, sha256
`9c38d37f…`), same gated protocol (7 rounds, 2 warmups, ±3% floor, count
gate, `-j1`), same release build flags, on a second host: AMD Ryzen 7 255
w/ Radeon 780M, CachyOS, `ripgrep 15.2.0`. Results
([`status-linux-ryzen7-255.md`](status-linux-ryzen7-255.md) §1.1):

| shape class | Windows 7950X3D | Linux Ryzen 7 255 |
|---|---|---|
| single-byte (`e`, `a\|b\|c`) | rgx +86% / +114% | rgx +40% / +20% |
| `e.` | rgx +40% | tie |
| multi-byte literal (`pub fn`, `fn main`, `let mut`) | rgx +33% to +59% | **ripgrep −37% to −44%** |
| class / dot-star (`e[0-9]`, `foo.*bar`) | rgx +43% to +48% | **ripgrep −34% to −41%** |
| alternation-with-class (`(pub\|fn) [a-z]+`) | rgx +39% | **ripgrep −15%** |

All 18 rows pass their count gates and all 18 separate. The split is by
pattern shape, not by noise: ripgrep's packed-pair literal kernel is strong
when the needle offers two rare bytes, and rgx's in-house engine is strong
when the scan is dominated by a high-frequency byte whose candidates the
mask rectifies in-register.

**Conclusion.** The sign of the engine-alone edge is a property of the host
and the pattern shape together. What travels is the shape dependence. Any
claim of engine superiority must name the host; the Windows table's
headline is true of that machine and false of this one. The scale-separation
claim the paper actually needs — that on a many-small-file tree the engine
share is small — holds on both hosts and does not depend on which matcher
is ahead on a single file.

## 7. `ParallelBuffered` over mmap: direction two hosts, magnitude one

**Question.** [`optimal-techniques.md`](optimal-techniques.md) claims −44.3%
mean wall-clock for `ParallelBuffered` over memory mapping. Does it travel?

**Evidence.** Same three read modes, paired and order-rotated, 7 rounds,
`fn main`, `-j10`, on the digest-named generated tree (26 packs): mmap is
slower than `ParallelBuffered` on **every** paired round, by 3–18% (mean
≈12%). `serial-buffered` is ~8× slower than either. Full table:
[`status-linux-ryzen7-255.md`](status-linux-ryzen7-255.md) §3.

**Conclusion.** The direction reproduces on two hosts, two corpora and two
OSes; the magnitude does not. −44.3% is contradicted in magnitude by a
second host and stays withdrawn as a quotable figure. Quote ≈12% with the
host's name, or quote the direction alone. **Superseded by §14: the
magnitude is cell-dependent and both figures were their own cell.**

## 8. The 512-bit n-gram "inversion" was a column mislabel

**Question.** The paper's n-gram table had 512-bit admitting more files
than 256-bit, contradicting the Bloom model. Was the filter wrong, the
hash weak, or the measurement unreplicable?

**Evidence.** The harness prints `Admitted Files | Pruned Files | Prune
Efficiency`. The paper's table copied the **pruned** count and the
**prune efficiency** percent into a column labelled "admitted". The `fn
main` 256-bit row is the proof: paper "admitted 2,275 (15.17%)" against a
second-host re-run's **pruned 2,274 (15.16%)** — one count apart. Under
the correct labels the paper's own numbers already say 512-bit prunes more
(27.78% vs 15.17%).

**Conclusion.** Closed as a reporting error. There was never an inversion;
both runs show textbook ordering. The error manufactured a phenomenon and
invited a mechanism (weakly-avalanched half-selector) to explain a
non-event. Residual, narrower: absolute prune rates differ across hosts on
3 of 4 patterns because the harness samples 15,000 files in `readdir`
order (unstable); latency differs 4–6× in the opposite direction to host
speed (timer scope, not filter). Fix for the residual: digest-name the
n-gram subset the way `scripts/make-corpus.py` names the dashboard
corpora.

---

## 9. `--json` allocated six strings per matched record

**Question.** The dense shape -- few files, many matches each -- prices the
machine-readable path at roughly three times the text path for the same
400,000 matched lines. The text printer batches its sends and allocates
nothing per line; where does `--json` spend the difference?

**Evidence.** `scripts/bench-json-print.py dense`, count-gated at 400,000 in
all three modes, paired rotated rounds, the process floor measured and
subtracted (12.65 ms here): text **65.3 ms**, `--json` **189.3 ms**, `-c`
**8.8 ms**, every sample separated. Per record the printer allocated about
six strings -- the path and the adapter tag (identical on every record of
one file), the escaped line text, a second one appending the terminator,
each submatch text, and the `format!` temporary the submatch record was
built in -- and the escape walked one character at a time.

**Conclusion.** Hoisting the two per-file escapes out of the line loop,
reusing two scratch buffers for the line text and the `submatches` body,
copying plain runs of the escaped text in one pass, and formatting the four
integers of a record without `fmt` takes the paired A/B against the
pre-change binary to **-43.4%** (346.6 to 196.1 ms minus the floor, every
sample below every sample), with byte-identical output over 12 invocations
-- unterminated last line, CRLF, control characters, quotes, a binary file
with a NUL, and `-n`/`-A`/`--no-filename`/`-i`/`-o`/`-w`/`-F`/`--sort`.
The wide shape is where the lesson lives: 20,000 files with one match each
puts `--json` **11%** over text and `text`/`-c` in `overlap, not a result`,
because a per-line cost is invisible in a corpus with one line per file. The
first measurement of this defect ran on that shape and read
`overlap, not a result`.

---

## 10. What an Arena costs per JSON byte, and what lazy walking bought

**Question.** The `djson` suite parses whole documents into an `Arena` --
every string interned, every object a `BTreeMap<usize, _>` -- but the
adapters that consume it read a handful of fields. GLB wants seven fixed
keys, `name` per item and the `asset` fragment; safetensors wants the
`__metadata__` strings plus `dtype`/`shape` per tensor. Was the
materialisation a real share of the adapters' time, and does an on-demand
walk over the same Stage-1 index pay?

**Evidence.** `cargo run --release -p rgx-core --example json_bench`
decomposes one adapter-shaped run per corpus (best of 7, output-gated; a
counting `#[global_allocator]` reports total and peak-live bytes).
Stage 1 alone runs at 6-9 GB/s and is 2-6% of a parse; the rest is
Stage 2 plus materialisation, which allocates 9-16x the document size.

| corpus | scan | parse (arena) | adapter walk, arena | adapter walk, lazy | alloc, arena -> lazy |
|---|---|---|---|---|---|
| glTF 1.1 MB | 0.18 ms | 11.4 ms | 11.95 ms | 4.65 ms (2.6x) | 24.0 -> 4.2 MB |
| safetensors 2.4 MB | 0.36 ms | 21.1 ms | 25.66 ms | 9.73 ms (2.6x) | 38.5 -> 6.2 MB |
| tokenizer 1.5 MB | 0.16 ms | 22.7 ms | 21.94 ms | 3.64 ms (6.0x) | 35.2 -> 4.8 MB |
| config 24 KB | 0.003 ms | 0.23 ms | 0.27 ms (parse + pretty) | not taken | 0.5 -> 0.1 MB |

The lazy column is `djson::ondemand`: `root` pays one validating walk
(3.17 / 4.86 / 3.20 ms -- identical acceptance to the Arena parser,
held by the differential suite in `ondemand/tests.rs`), and every later
step navigates validated spans without re-checking. The tokenizer row
wins most because almost nothing in it is touched.

Two defects the differential caught before any adapter saw them: the
monotonic navigation hint anchored at the *query* position instead of
the *consumption* boundary, which made a seek-back read past its answer
(`"x" }` came back as one string), and `find_key` erroring on a
non-object where `object_get` returns `None`. Both are pinned by tests.

The adapter outputs are byte-identical to the Arena path, including the
Arena's key order: `BTreeMap<usize, _>` iterates keys by interned
index, which is first-appearance order of the key *string* anywhere in
the document -- not source order. `Ondemand::first_string_positions`
reproduces it, and the goldens in `rgx-adapters-threed` /
`rgx-adapters-llm` pin the divergence cases
(`glb_output_is_pinned_byte_for_byte`,
`safetensors_output_is_pinned_byte_for_byte`, both derived and checked
against the Arena implementation *before* the rewrite).

**Conclusion.** Materialisation was ~98% of a parse and the parse was
90-97% of an adapter walk. Removing it buys 2.6-6x on the two adapters
that read few fields and 4-7x less allocation, with output unchanged
byte for byte. Negative results in the same run: the KerasZip shape
(`parse` + `to_string_pretty` of the whole document) is 0.27 ms of JSON
work on a 24 KB config -- sub-millisecond per archive, zip inflate
dominates -- so it stays on the Arena parser; and re-serialisation is a
real cost (3.6-5.2 ms) only where the whole document must be re-emitted,
which is that same KerasZip shape and nothing else.

---

## 11. The single-file floor was a copy and a term map nobody read

The Linux bench host (CachyOS, 10 cores, `big235.rs` 246 MB, `-j1`,
base-vs-new interleaved) put §6's sparse rows in absolute numbers: `fn main`
74.0 ms against ripgrep's 41.6, `let mut` 70.5 against 40.4. The phase
counters (`RGX_PROFILE`, added for this) split the zero-match floor of 64 ms:

| stage | cost | what it is |
|---|---|---|
| `reader_fill` | 52.5 ms | the read copy (~40 ms of it sys) + two terminator scans |
| `reader_map` | 10.3 ms | the candidate map, both planes |
| walk | ~1 ms | a line walk the skip already avoided |

Three things came out of it, one of them negative:

- **Fill size is a measured null.** 64 KiB, 256 KiB and a file-sized 8 MiB
  fill are flat on the floor (base-vs-new interleaved, 0.995--1.02). Bigger
  fills move sys into user -- the two bit maps scale with the fill and evict
  the streaming haystack from L2 -- and smaller ones pay more syscalls; on
  this corpus the two cancel exactly. This reproduces the Windows record in
  `mmap.rs` from the other side.
- **ripgrep's sparse-row edge is mmap, and the ordering is platform-split.**
  `rg --no-mmap` drops to 51.0 ms where its default is 38.3. Windows's soft
  faults make the zero-copy shape the *worst* row of `mmap.rs`'s fill
  harness (13.2 against 9.0); Linux's cheap faults and `copy_to_user` make
  it the best. Both sides are now measured, which is what the switch in
  `should_map` is for: mapped on Linux, read elsewhere.
- **The fix is the same walk without the copy.** `Searcher::search_windows`
  searches a mapping in place in line-aligned windows -- one `Core` across
  windows, line numbers folded across skipped windows exactly as the
  reader's lazy skip does -- and a skipped window never builds the term map
  the skip cannot observe (8.7 million scattered line-end bits on this
  corpus, the expensive half of the fused fill).

Harness A/B on the bench host (`status_table --rgx-base`, count gates equal
on every row, ±3% floor), with the binary rule folded into the window walk
as well -- `Quit` truncates at the byte, `Convert` splits lines there, which
is exactly the reader's rewrite; the byte is asked per window, warm, after
the candidate map has touched the pages, instead of by one cold full-file
guard scan:

| pattern | base | new | change | vs ripgrep |
|---|---:|---:|---:|---|
| `fn main` | 74.3 ms | 52.8 ms | **-40.8%** | ripgrep -23.1% |
| `let mut` | 71.4 ms | 49.5 ms | **-44.4%** | ripgrep -22.3% |
| `e[0-9]` | 91.6 ms | 68.6 ms | **-33.5%** | ripgrep -22.9% |
| `foo.*bar` | 92.5 ms | 70.2 ms | **-31.8%** | ripgrep -15.5% |
| `pub fn` | 112.2 ms | 88.2 ms | **-27.3%** | ripgrep -22.4% |
| `(pub\|fn) [a-z]+` | 163.1 ms | 139.6 ms | **-16.8%** | tie |
| `a\|b\|c` | 177.6 ms | 159.6 ms | **-11.3%** | rgx +35.3% |
| `e` | 161.1 ms | 146.5 ms | **-10.0%** | rgx +54.3% |
| `e.` | 309.5 ms | 294.7 ms | **-5.0%** | tie |

Every row separates, the zero-match floor moved 65.5 to 41.3 against
ripgrep's 38.8 (parity), and the sparse rows ripgrep led by 33-36% now
lead by 22-23% with one row flipped to a tie. The 20k-file tree is all
ties: small files take the read-whole slice path and never reach this
code. Binary semantics were pinned by a 58-case battery (NULs at early,
mid, late and multiple positions, `Quit` and `Convert`, every output
format) byte-identical against the base build.

---

## 12. The many-files surface: syscall-bound walls and a 39 ns emission line

The 20k-file tree at `-j32` is **syscall-bound**, not bandwidth-bound:
rusage sums over 32 workers show ~600 ms of sys time against 67 ms of user
for 560 MB -- roughly 80k syscalls (open/read/close per file) on a 10-core
box, so wall time is CPU-sum divided by ~8.5 cores. ripgrep pays the same
three syscalls per file (its sys sum is 563 ms); the difference is one
extra path-based `stat` on rgx's side (`meta.len()` flowing lazily from
the walk) worth 38 ms of the 55 ms CPU gap, and the rest is user-side
per-file machinery. At `-j1` the engine is already ahead of ripgrep on
this corpus (zero-match 407 vs 424 ms); what loses at `-j1` is the walk
itself (50.3 vs 20.2 ms -- per-entry `String` work and a `.git` stat per
directory in the shared acceptance path).

The dense single-file rows split cleanly by mode: counting ties ripgrep
(`e.` at 298 vs 305) but **full output loses 25%** (554 vs 445) -- 6.9
million formatted lines cost 39 ns each against ripgrep's 20. The `fmt`
machinery in the per-line prefix was worth 3 of those nanoseconds
(`write!`-through-`Inline<24>` replaced by pushed bytes and a manual digit
push, outputs byte-identical over a 43-case flag matrix); what remains is
the collect-and-format pipeline itself -- the line text is copied once
into the hit buffer and again into the output batch -- which is the named
next step, along with the per-entry walk work above.

**The per-file `stat` is NOT reducible to a cheaper syscall -- only to no
syscall.** Swapping the walk's path-based `entry.metadata()` for an
`fstat` on the handle the search already opens measured flat-to-worse on
both thread counts (-j32 zero-match 76.1 -> 78.9, interleaved): on this
box a `stat` with a warm dentry cache and an `fstat` cost the same ~2 µs,
so the syscall COUNT is the only thing that matters and a one-for-one swap
buys nothing. It was reverted (it also made `--max-filesize` open the
files it exists to skip). The real version of the lever removes the
syscall outright: derive the length from the fill -- read into the reused
buffer, a short read is EOF and its length is the file's -- which answers
both the cap and the buffered/path decision for every file that fits the
buffer, and leaves the rare big file paying one `fstat` after the buffer
fills. That touches the head-sniff read choreography, so it is the named
next step rather than a guess.

**Four behavioural gaps found while verifying colour and column against
ripgrep** (all pre-existing): the walk's default output order is not
ripgrep's -- on a two-file directory rgx emits `b.txt` before `a.txt` and
rg the reverse, in plain output as much as coloured; `--heading` in the
batched text route prints `path:line` with the path dropped after the first
line, where rg prints a bare `path` header line and the matches under it
(the CLI help says "group matches under a single path header", so the
batched route owes rg's form); `--vimgrep` is folded into `--column` at
parse time and the doc calls it an alias, but rg's `--vimgrep` is a
different shape entirely -- one line per MATCH, always `path:line:col:`
prefixed -- and the per-match formatter does not exist in the text route;
and `-o` under `--color` is not coloured (the printer's only-matching arm
spans without styles). Each is named here rather than mixed into a colour
or column commit.

The fill-derived version landed and measured NEUTRAL in wall at both thread counts
(`-j32` zero-match 77.4 -> 76.5, interleaved; 58/58 binary-choreography
cases and 43/43 formatting cases byte-identical, 38 suites green). The
whole per-file size question was worth one syscall-class removal and a
length that is the bytes read, not a stale stat -- and worth no wall time:
a warm-dentry stat here is ~0.5 µs, not the 2 µs the rusage delta once
suggested. **Three attempts close the per-file path: the 20k-file tree's
remaining gap to ripgrep (77 vs 66 ms at -j32) is not the size, not the
fstat/stat choice, and not the read choreography.** What is left there is
the per-entry callback work (path construction, extension lookup, the
explicit-path and hidden tests) measured in tenths of a microsecond each,
plus a user-side per-file machinery of ~0.5 µs -- spread thin, and the
reason the named next step is the emission pipeline instead: 251 ms of
formatting against ripgrep's 140 on the dense full-output rows is the
largest single gap left on the surface.

**The emission line was a transport nobody needed.** The batched text route
formatted each line into a scratch buffer, copied it into a `FileHit`, then
copied it again into the output batch. `TextStream` formats at
`matched()`/`context()` through the same `push_fmt_line` the hit formatter
uses -- the line text is copied once, into the output, and no `Line`
content is built; the `FileHit` is transport only. Measured interleaved
against the same base on the dense rows: `e.` full output 557.6 -> 459.3
ms (-17.6%) and `e` 414.7 -> 312.1 ms (-24.7%).

**End of file is the only thing that may disarm the stream -- on every
exit.** The first version disarmed inside `take_hit`'s HIT branch alone,
and the fail-safe that an unarmed stream degrades to the collected path
was not enough: a file the raw path skipped (a size cap, a binary cut
before a NUL) ended without `take_hit`, the stream stayed armed with the
SKIPPED file's path, and the next file through the pre-read route -- the
adapter path ran on extension alone and totally bailed, so the walk kept
the bytes it probed and searched them from memory, a route with no
`begin_file` of its own -- streamed its hit under the wrong name. The
archive fixtures' `-i` cell caught it as a one-line diff: `zstd_noise.bin`
has exactly one case-insensitive hit (`FN ` in the noise, so only `-i`
sees it), `zstd_longrange.plain` has none at all, and the build printed
the hit as the second file. Fixed three ways, because one hole is a
lesson and two is a class: `take_hit` disarms on both branches, the skip
returns call `end_file`, and the pre-read route arms its own `begin_file`
so no call site depends on a previous file having disarmed.
`a_skipped_file_does_not_label_the_next_files_hit` in `tests/cli.rs` is
the regression, written red first (`a_skip.plain:UNIQUE needle line`).

**The count rows of the official harness tie against the pre-campaign
base, and the reason is where the wins live.** `status_table --rgx-base`
times `--no-filename -c` with stdout to the null device -- the search and
count surface, not the output pipeline -- so the streaming sink's
-17.6/-24.7% on dense full-output cannot appear in it, and every row it
does time is inside the floor against a base that already carries the
earlier single-file campaign. Three new negatives on the way to that
conclusion, all measured on the harness rows: `RGX_MMAP=1` on this
Windows box loses 1.23x-1.55x across `let mut`/`e`/`pub fn`/`fn main`,
extending `mmap.rs`'s table to the row shapes; a 1 MiB `INITIAL_BUF` is
worse than the 64 KiB one (`e` 150.6 -> 170.7, `let mut` 68.6 -> 74.3,
the fills 35.5 -> 43-46 ms) and the fill count barely moves (5,615 ->
3,763), so the read side returns about 64 KiB per call whatever the
buffer asks for -- bigger buffers cannot cut the syscalls, they only
evict the cache; and the fill's own two scans (the binary-byte search and
the last-terminator search) run over every byte in addition to the map
pass that already walks them.

**The named next step is the dense line walk, and it is quantified.** On
the 247 MB single-file row the `e` count pays 93.9 ms of search phase
after fill (35.5) and map (6.4): 24.6 M lines at ~3.8 ns each, 6.9 M of
them matching at ~13.6 ns of sink and line bookkeeping. The per-candidate
jump already stands itself down on this shape (`DENSE_RUN`), so the walk
cannot skip; what is left is a bulk question -- settling which lines hold
a candidate from the two bit maps a word at a time instead of walking
every line -- and it is the only lever left on the count rows that is
bigger than the floor. The sparse half of the same row (`let mut`, 3.1
ms of engine) says the floor is elsewhere: 35.5 fill + 14.5 map + 16 ms
of CLI spawn.

**The `e.`-shape's confirm resisted five rewires, all flat -- and the
probes now narrow the remaining question to one function.** What is
settled by measurement and probe: `ByteRegex::new(b"e.")` compiles
`fast=true fixed=true direct=false boolean_confirm=false`; the mask plan
is `Some(decides=true, branches=1)` (`required::match_mask` probe); the
lazy stream falls to `Candidates::every` for a mask-only anchor
(`regex.rs`, the `None` arm of the mask-anchor branch); and the map path
carries the whole answer already -- `map_candidates` stamps mask bits as
`Origin::Fixed(0)` because they are match starts, and `map_is_match_mask`
hands the line-cut that settles a line from a bit. Five rewires of the
confirm path were measured flat on all nine harness rows and are
reverted: `Fixed`-predicate confirms in `line_matches` and the
no-prefilter arm; a tight first-byte-filtered `any_in`; `Fixed`-derived
candidate offsets instead of the `every` fallback; per-candidate confirms
in the no-prefilter arm; and answering the map and the line-cut from the
mask anchor regardless of which anchor the plan chose. Flat means the
~20 ns a candidate line pays is not in the confirm machinery at all.
The last two probes close the case against the matcher:
`searcher::map_candidates_only` IS wired -- `map_is_match_mask`'s width
reaches `Candidates::of_mask` and lines settle from bits -- and the
plan-built `e.` mask has `line_cut=Some(2)` with no class holding the
terminator, so a mask-first `map_is_match_mask`/`map_candidates` really
does light the settling path. It ran, and the row did not move. So the
per-line cost of the `e.` walk (~9.5 ns/line against `e`'s 3.8, same
6.9 M reported of 24.6 M lines) is `Core::run`'s own per-line work --
map cursor, bookkeeping, report tail -- and no confirm-side change can
touch it. The named next step is the original one, no longer a guess: a
sampling profile of `Core::run`'s per-line work, or the bulk-settle
sketch above, where one word of the terminator map decides many lines at
once and only reported ones pay the tail. Keep the probes
(`fast`/`fixed`/`direct`, `plan.decides`, `line_cut`, the map wiring) as
tests when the path is finally lit.

**Sabotage, not reading, split the walk -- and the split does not fit the
models.** One-line sabotages of `Core::run` (wrong answers, measured
only) on the 247 MB single-file row: replacing the per-line `is_match`
computation with `false` leaves the walk at 211 ms for `e.` against
78.9 ms for `e` -- the same 24.6 M lines, the same zero reports, the
same line-finding code -- while the report tail of a real run is worth
only ~20 ms of the 290. The 2.7x survives `RGX_ABLATE_MASK=1` (199.5 ms)
and it is not the settle: lighting the deciding-mask path for `e.`
(`line_cut=Some(2)`, verified engaged by probe) moves nothing, and the
mask fill itself costs more -- `reader_map_ns` 7.2 -> 19.7 ms -- so that
rewire is reverted with the rest. What the numbers DO rule out, hard:
the confirm machinery, the report tail, the mask, and the map fill as
the home of the ~130 ms gap between two same-count patterns. What is
left is something in the per-line work that depends on the candidate
stream's shape, and finding it needs a real sampling profiler over
`Core::run` with both patterns side by side -- `perf`/VTune on the box,
not more arm reading. The sabotage recipe (`is_match := false`, then
`RGX_ABLATE_MASK`, then per-phase `profile_add` around the loop body)
is the instrument that already answered three questions in one build.

**Sabotage A had a hole, and closing it restores the chain as the
answer.** `let is_match = false; let _sab = if multi_line { ... }` still
EXECUTES the settle through `_sab` -- its cursor side effects kept it
alive -- so the 211 ms it left for `e.` included the whole
`line_matches`/`in_line`/`any_match_in` chain and its confirm, not pure
machinery. Forcing the settle to `Some(false)` at the call site (chain
and report both skipped, everything else identical) collapses `e.`'s
walk to 58 ms unnormalised, on a run whose fill had doubled to 71 ms --
the machine was loaded, so treat the absolute numbers as ~2x inflated,
but the collapse is 3-4x and cannot be load. The chain is ~130 ms of the
walk, and the machinery beneath it is tens of ms. What this does NOT
resolve: the mask-first rewire lit `line_cut=Some(2)` (probe-verified)
and still measured flat -- so either that measurement was polluted the
same way, or the run loop's `cands` is not the object
`map_candidates_only` built. The next measurement is one clean
interleaved A/B on a quiet machine: forced-settle vs mask-first-rewire
vs stock, `e` and `e.`, min-of-5, same session. Sabotage code goes in
through a scratch branch and never lands.

**The mechanism is now complete, and the A/B proved the prize before the
gate refused it.** Clean interleaved run (fill stable at ~40 ms, min-of-5,
three variants same session): forced-settle collapses `e.` from 291.6 to
100.2 ms wall -- the chain is 65% of the flagship row -- while the
mask-first rewire stays flat (299.8). Branch counters inside
`map_candidates_only` say why: only 1668 of 5614 fills take `of_mask`,
3946 stay `of_bits`, and a counter inside the rewire's own loop shows it
is reached exactly 1668 times and never once misses. The 3946 never run
the `ByteRegex` body at all: the CLI's matcher is `hybrid::HybridMatcher`,
and its `map_is_match_mask` gates per fill on
`!byte_always_decides && !buffer_ascii`, where
`byte_always_decides = (has_fast_literal() || is_pure_ascii()) &&
!case_insensitive`. `e.` is neither a fast literal nor pure-ASCII in the
language sense (its own comment: the byte engine reads `é` as two bytes
and `grep` as one codepoint), so every fill holding any non-ASCII byte --
70% of them in a 235 MB source corpus -- declines the mask settle and
pays the chain. The gate is CORRECT for the current contract: line
existence can genuinely diverge between the engines on non-ASCII lines
(`[^\x00-\x7F]{2}` over one 2-byte codepoint is the witness), so the
settle may only cover lines the byte engine may decide. The fix shapes,
in order of increasing risk: (1) per-LINE settle -- an ASCII check per
line, which the confirm path already does (`byte_decides`), moved into
the settle so mixed fills settle their ASCII lines from bits and only
non-ASCII lines take the chain; (2) a pattern-class proof that line
existence is engine-invariant (fixed-length shapes with byte-class
terms), which needs the maintainer because it is a semantics claim; (3)
a cheaper delegate path. Shape (1) alone is worth most of the 65%: the
non-ASCII LINES are rare even in mixed fills. The rewire plus shape (1)
is the change to write next; everything it needs is now named.

**A byte battery compares behaviour, not runs: pin `-j1` or compare
multisets, and feed the real grammar.** With `-j8` the walk emits files
in completion order and the same binary disagrees with itself on
thousands of lines, so a naive byte diff reports the schedule as a
regression -- an earlier 12/43 "diffs" against base was mostly that. And
a probe that passes `-e` is measuring parse errors: `PATTERN` is
positional, and every "result" it prints is the same `error: Unknown
argument` text from both builds. The corrected 30-case battery is
byte-exact at `-j1` against the pre-campaign base: 23/30 identical, and
the 7 diffs are exactly the six intentional colour/column fixes (the base
predates them) plus `--json`'s `elapsed_total` clock -- the sorted JSON
stream is identical modulo that clock. Against rg the remaining shape
gaps are the four already named, plus two by-design differences: the
Windows path separator (`/` where rg prints `\`, which `walk_diff`
normalises) and the adapter superset (matches inside `.br` members rg
cannot see).

---

## 13. The per-line settle landed at half the prize; the ASCII check it pays is 66 ms

**What landed is the change §12 named -- the rewire plus shape (1).**
`map_candidates`/`map_is_match_mask` answer from the mask anchor whichever
anchor the plan picked for the buffer (the `e.`-shape's chosen anchor is the
one-byte literal `e`, which is what sent it back to the confirm chain), and
the settle is per LINE: `Matcher::decides_line` lets a matcher reserve a
line for its delegate, the searcher's line loop vetoes a settle-`true` the
byte engine may not decide, and hybrid.rs's whole-buffer `buffer_ascii`
gate is gone. The contract is pinned by
`a_mask_bit_does_not_settle_a_line_the_byte_engine_may_not_decide`: the
witness line `eé` (65 C3 A9 -- `e.{2}` over TWO bytes to the byte engine,
over ONE codepoint to the delegate) is falsely reported if the veto is
removed, and the test asserts the delegate was ASKED, not only what it
answered.

**Evidence.** Interleaved, order-rotated, min-of-5, `-j1`, wall clock (the
~16 ms spawn floor sits in both arms and is not subtracted), count gate
base == new == rg before any timing. On `big235.rs` (246,541,116 B, 8,794,466
lines, 616,568 non-ASCII): `e.` 284.1 -> 236.2 ms (-16.8%) and `e[0-9]`
82.3 -> 77.2 (-6.1%) -- the two fixed-width non-literal shapes -- while the
seven literal and variable-width rows stay flat inside +-3%. On a derivative
with one high byte per 32 KiB (every fill mixed, only 7,497 non-ASCII
lines): `e.` 281.6 -> 225.6 (-19.9%), `e` flat. Three harnesses in the
scratch dir beside `base-fb57a0d.exe` and `sab-decide.exe`:
`perline_ab.py`, `sparse_ab.py`, `sab_ab.py`.

**The §12 accounting was wrong twice, and the new numbers close it.** The
forced-settle figure (291.6 -> 100.2) is not the confirm chain: `Some(false)`
skips the report tail too, and `e` -- the same 6.94 M reported lines, no
chain -- is 150.4 ms. On the sparse corpus the decomposition is exact:
chain = base - sab = 281.6 - 161.0 = **120.6 ms**; per-line ASCII check =
new - sab = 226.8 - 161.0 = **65.8 ms**; net shape (1) = 56 ms, which is
the measured 281.6 -> 225.6. The sabotage is `decides_line` returning `true`
unconditionally (measured on the sparse corpus so its 7.5 k delegate lines
cannot pollute the attribution; `e` stays flat at +0.3% because a fast
literal short-circuits the check). So "shape (1) is worth most of the 65%"
was wrong twice over: the 65% included the report tail, and the per-line
check that shape (1) pays eats half of the real chain.

**What is named next, with values.** The residual is NOT the delegate
(7.5 k lines on the sparse corpus change nothing) and not the mask: it is
`<[u8]>::is_ascii` over ~28 bytes, ~6.9 M times. Two shapes, in increasing
risk:

1. **LANDED, measured:** a per-fill non-ASCII bitmap (`scan::high_bits` --
   `pmovmskb` of the raw chunk IS the `>= 0x80` test, no compare), filled
   only for a matcher that may decline a line, with `decides_line` taking
   the fact as a hint. Contract-preserving. Measured (same A/B protocol):
   `e.` 227.3 -> 198.0 ms (−12.9%) on the real corpus and 218.9 -> 178.7
   (−18.4%) on the sparse one, against the ~195 predicted; the literal and
   byte-only rows stay flat (−2.6% to +0.3%). Cumulative on the flagship
   row: 284.1 pre-fix -> 236.2 per-line -> 198.0 with the map, and the
   remaining ~30 ms over the settle-forced floor is the delegate's
   non-ASCII lines plus the of_mask walk.
2. **LANDED, maintainer-approved, measured (three arms, one session):**
   the window rule -- the veto tests each bit's widest window instead of
   the whole line and delegates only when EVERY window is refused. The
   proof is the 1:1 alignment: on ASCII bytes a codepoint is a byte, so a
   pure-ASCII match window is a match in both engines. It supersedes
   shape 1 on the day shape 1 landed: the fill map had one consumer and
   the window rule does not need it (`high_bits` and the plumbing are
   removed again). Three-arm A/B (base = the per-line rescan, map =
   shape 1, win = shape 2; rotated, min-of-5, count gates ok):

   | corpus | pattern | base | map | win | win/map |
   |---|---|---:|---:|---:|---:|
   | big235 | `e.` | 229.6 | 203.0 | **190.1** | **−6.4%** |
   | big235 | `e` / `e[0-9]` / `pub fn` | — | — | — | −1.4% to +0.2% |
   | sparse | `e.` | 217.5 | 181.6 | 189.0 | **+4.1%** |
   | sparse | `e` / `e[0-9]` / `pub fn` | — | — | — | +0.5% to +2.3% |

   The flagship row: 284.1 pre-fix -> 236.2 per-line -> 203.0 with the
   map -> **190.1 with the window rule** (−33% cumulative). The sparse
   synthetic (7,497 non-ASCII lines in 246 MB) goes the other way: with
   almost no delegate pressure the window walk costs more than the map's
   single lookup it replaces and the map wins by 4.1%. Quote the corpus
   with the number.

**The named next lever** (not measured): the two rules compose -- a fill
map's line-range lookup settles the ~93% pure-ASCII lines outright and
the window walk runs only on the dirty minority. Expected `e.` ~185 on
big235 and ~181 on sparse: the best of both arms above, for shape 1's
map plus shape 2's walk behind one line-clean shortcut.

---

## 14. The read-mode magnitude is cell-dependent: −44.3% and ≈12% were each their own row

**Question.** §7 withdrew the −44.3% read-mode figure against a second
host's ≈12% and left "quote the direction alone". The 8.1 transcript at
the CLAIMED corpus scale was still missing; does the magnitude reproduce
there, and what reconciles the two numbers?

**Evidence.** [`tv-matrix-transcript.md`](tv-matrix-transcript.md): the
claimed shape regenerated under a named digest (seed `0x5eed1234abcd0001`,
93,234 files / 1,894.9 MB / 114 packs against the claim's 1.87 GB / 117),
`scripts/tv-matrix.sh --rounds 11 --threads 1,8,32`, all gates passed
(6,781,133 count parity; byte-identical full answers, md5 `1772dc8575f1`).
`ParallelBuffered` over mmap: scan-bound count rows **−43.5%** (`j1`),
**−61.1%** (`j8`), **−67.3%** (`j32`) on the miss pattern and −56.1/−54.0%
on `pub fn -c` at `j8`/`j32`; the output-bound full row **−9.8% to −11.2%**
at every thread count. The claimed −44.3% is the `-j1` count row to within
a point; the second host's ≈12% was `fn main` over the 20,000-file tree,
which is the output-bound row and matches the full row here. The one
`overlap` verdict (pub fn `-j1`) still has buf's median 26% under mmap's.

**Conclusion.** There is no contradiction to resolve: the two published
numbers were each measuring their own cell, and the cell — not the host —
sets the magnitude. Quote the cell with the number (count/scan rows
−43% to −67%, output-bound full rows ≈−10% at this scale); a bare "−44.3%"
or a bare "~12%" are both now the wrong shape. The teardown paradox
reproduces unchanged (mmap's unmap is 186.3 ms of its in-process total and
zero of the wall clock), and `serial-buffered` is confirmed a different
regime (34–52% slower than mmap at `j8`/`j32`). The transcript names a
pre-fix engine binary; the three cells are flat under the per-line settle
(§13) and every arm shares one engine, so the arm ratios stand.

---

## 15. Case folding landed, and the port exposed a prefilter that dropped matches

**Question.** Unicode case-folding was called blocked on nightly
`portable_simd`. The parked `dev` branch carried the design; what does it
take to land it on `main`?

**Evidence.** The design folds at PARSE time — `(?i)` turns each character
into the byte alternation of its simple case-folding class — and touches
no nightly feature at all: it compiled on stable at once. What the port
exposed was two defects the narrow `dev` fold had masked:

1. The width gate (`uniform_len`) kept mixed-width classes out of the fold
   because an unanchored scan bounded candidate starts by the LONGEST
   alternation branch and dropped a shorter one at the haystack end
   (`ab|cde` on `ab`). That scan is already fixed on `main` — the pinned
   test that documented the defect now passes — so the gate came out and
   `k` reaches three-byte KELVIN SIGN, `ß` reaches `ẞ`.
2. `literal::extract` called a caseless literal `Exact` when its fold
   stayed in ASCII — and `k` is ASCII. The old byte-wise fold and the
   table agree on `a`..`z` except `k` and `s`, so for every other letter
   the ASCII-pair fingerprint is a true necessary condition; for `kelvin`
   it was not, and the masked prefilter produced NO candidates for a
   haystack holding KELVIN SIGN (`offsets=[]` against a match the VM finds
   at 0). A fast prefilter that silently drops matches — the exact shape
   this file's law is about. `extract` now declines those literals and the
   pattern searches through the VM without a literal prefilter.

**Conclusion.** `-i kelvin` finds KELVIN and `(?i)ß` finds `ẞ`, pinned
against the `regex` crate as oracle (`case_folding_reaches_every_width_
the_oracle_does`); the prefilter decline is pinned by
`caseless_wider_fold_letters_are_never_exact` (and `k`/`s` are named in
`AGENTS.md` §2 as the ASCII letters whose caseless literal loses its
prefilter). Case-sensitive patterns take none of these paths, and a
caseless literal whose fold stays in ASCII keeps its prefilter — the
common `-i` rows are unchanged by construction. Remaining Unicode gaps
stay documented: mixed classes over-match (three ignored tests) and full
case mapping is not used (`ß` ≠ `SS`).

---

## 16. The SHA-NI kernel was waiting on a permission granted since Rust 1.41

**Question.** The hardware SHA-256 was called blocked on
`#![feature(sha2)]` nightly. `dev` carried a kernel with the commit note
"works on stable". Which is it?

**Evidence.** The `sha_simd` intrinsics (`_mm_sha256rnds2_epu32`,
`_mm_sha256msg1_epu32`, `_mm_sha256msg2_epu32`) have been stable since
Rust 1.41; the stub's header premise ("still nightly-only in `core::arch`")
was false the day it was written. The port compiles on stable unchanged,
the kernel is pinned to `process_block_scalar` block by block and to FIPS
180-4, and `sha256-hw` joins `default` so the dispatch compiles into what
the suite runs. `sha256_ref` was test-only code shipping in the binary
and is now `#[cfg(any(test, doc))]`.

**Conclusion.** Both parked "blocked" items (7.1 case folding, 7.2 SHA-NI)
were blocked on premises that had already dissolved — one a design that
never needed nightly, one a feature gate stable since 1.41. A `blocked`
label in this file is now a claim to re-verify against the toolchain
before anyone waits on it. The honest description of the kernel stays
what `dev`'s measurement said: SHA-256 has two call sites in rgx (the
`--cache` key and rare xz `CHECK_SHA256` streams), so this is dispatch
correctness, not a speed claim.

---

## 17. The composed lever lands: a `#[target_feature]` cost it 10x, and the count gate caught its bug

**Question.** §13's named lever said the two settled arms compose: a fill
map's line-range lookup settles the ~93% pure-ASCII lines outright and the
window walk runs only on the dirty minority. Measured naively it was parity
against the window rule alone (±5 ms) -- discard or keep?

**Evidence.** Kept, per the maintainer, and optimized. Three things came
out of the attempt:

1. **A real bug, caught by the count gate.** The composed shortcut settled
   `true` for every clean line without asking the mask, and `e.` answered
   7,754,363 where the arms agree on 6,927,072 -- 827k lines with no
   candidate reported as matches. It hides from sparse fixtures (the
   candidate walk jumps over no-bit lines) and lives only in dense regions,
   so the pin is a dense 200-line fixture with one clean line at position
   100 (`a_clean_line_without_a_candidate_is_not_a_match`). The fix
   consults the mask and takes its answer.
2. **The per-line virtual call, hoisted away.** `decides_window` was called
   once per settled line (6.9M calls on the flagship row). The policy
   "does a clean window settle?" is now asked once per buffer and the clean
   path answers from the fill maps alone.
3. **`#[target_feature]` is not cosmetic: it is 10x.** The fused
   `term_high_bits` kernel (one load, two masks) measured SLOWER than the
   two passes it replaces -- 17.6 ms against 3.6 ms per 2,000 fills. The
   cause was not the loop: calling `#[target_feature]`-gated intrinsics
   from a function without the attribute turns every intrinsic into an
   out-of-line call (~65 cycles per mask, measured by an inline
   masks-only probe). With `#[target_feature(enable = "avx512bw")]` the
   same kernel runs at **1.23 ms -- 3x faster than the two passes**. Both
   fused kernels (AVX-512BW and AVX-2) are kept.

**Conclusion.** The composed lever lands and beats the best state reached:
three arms in one session, `e.` **185.7 ms** against the window rule's
199.1 (−6.7%) on the 246 MB row and **175.7** against 194.7 (−9.8%) on the
sparse synthetic -- and 185.7 is below the 190.1 the window rule posted in
its own best session, so the bar of "equal or better than the maximum
achieved" holds even across the machine's ±6% session drift. Controls
within ±2.8%. The roadmap's suggested-order table is now empty.

---
3 - fixed, regression tested; 4 - negative, closed; 5 - one negative and two
sub-floor cuts; 6 - closed as a non-portability finding; 7 - direction
confirmed, magnitude withdrawn, then reinstated as cell-dependent by 14;
8 - closed as a reporting error; 9 - fixed,
-43.4% dense and 11% wide; 10 - measured, lazy walk landed with byte-identical
output, KerasZip negative; 11 - floor split by phase, fill size negative,
in-place windowed search landed at -40 to -44% on the sparse rows, every
harness row separated; 12 - measured anatomy, prefix formatter landed
(-3.7% full-output dense), remaining fat named, then the streaming sink
(-17.6/-24.7% on the dense rows), which its own battery caught labelling
hits with the wrong file -- fixed, end of file now disarms everywhere;
13 - per-line settle landed (-16.8% flagship, -19.9% sparse, contract
pinned by a test with teeth), the 66 ms it pays in per-line ASCII checks
measured and attributed, the two follow-up shapes priced and risk-ranked;
shape 1 then landed off that price list (e. 227.3 -> 198.0 with the fill
map, controls flat) and shape 2, maintainer-approved, superseded it the
same day (window rule: e. 229.6 -> 203.0 -> 190.1 across three arms of
one session, -33% cumulative; the sparse synthetic favours the map by
4.1% and that is filed with it);
14 - read-mode magnitude is cell-dependent, claimed-scale matrix filed,
quote the cell with the number;
15 - case folding landed on stable (the nightly blocker was stale), the
width gate went with the scan defect it worked around, and the port
exposed a caseless prefilter that silently dropped every wider-fold
match -- extract now declines those literals and the VM searches them;
16 - the SHA-NI kernel landed too: the intrinsics are stable since 1.41
and the stub had been waiting on a permission long granted. Both parked
"blocked" items dissolved on inspection; re-verify a blocker against the
toolchain before waiting on it;
17 - the composed lever lands BEATING the best state (e. 185.7 vs 199.1
in-session, and below the 190.1 of the window rule's best session): the
count gate caught its blind-settle bug, the per-line virtual call is
hoisted, and the fused kernel needed `#[target_feature]` to stop paying
~65 cycles per intrinsic call.*

---

## 18. The map decline was the drop bug, not the buffer

`reader_terms_on: 313` / `reader_terms_off: 1` on a 20.8 MiB file with one
300 KiB line and a pattern with candidates. The documented baseline was
**125 of 129 fills off**. The one remaining off-fill is the 300 KiB line
itself, which is genuinely over `MAX_BITMAP_INPUT`.

The windowed `BitMap` proposal would recover that single fill. The
`LineBuffer` shrink likewise. Neither is the headline win they were before
the `drop_before_next_fill` fix, and both should be measured against this
new baseline rather than against 125/129.

Reproduce: `RGX_PROFILE=1 rgx -c a <20.8 MiB file>` - the pattern MUST have
at least one prefilter candidate in the file, or `buffer_empty && core.is_none()`
skips every fill before the counters run and they read as zero.

---

## 19. Diodicity × candidate density, n-gram stage ablation, and the exact member-cap breakdown threshold

**Question.** Single-run characterisations in `examples/diodicity.rs` showed candidate-stream diodicity (`Di = raw / admitted`) varying across pattern density (`e[0-9]` `67.0x`, `foo.*bar` `2.0x`, `(pub|fn) [a-z]+` `1.1x`), and bracketed the `RGX_MAX_MEMBER_BYTES` breakdown on `crates/rgx-core/testdata/zip_text_deflate.zip` between `1,024 B` and `4,096 B`. What survives the full `benchmark/status.md` gate (thread-matched `-j 1`, 7 rounds, rotated order, match-count gate `base == ablated == rg`, `±3%` floor + non-overlapping `[min..max]` range verdict), and where is the exact byte boundary on the cap?

**Evidence.**

1. **Diodicity × candidate density (`base` vs `RGX_ABLATE_MASK=1` on `~/.rgx-bench/big235.rs`, `-j 1`, 7 rounds, rotated, 1 warmup each):**

   | Pattern | Shape | Count (`base == no-mask == rg`) | Base med (`min..max`) ms | No-Mask med (`min..max`) ms | No-Mask vs Base | Verdict |
   |---|---|---:|---:|---:|---:|---|
   | `e` | single-byte dense literal | 6,941,931 | 150.0 (148.7..156.4) | 148.1 (144.4..158.6) | -1.3% | within ±3% floor |
   | `e.` | dense prefix + any byte | 6,927,072 | 187.3 (181.5..188.4) | 280.3 (274.0..284.6) | **+49.6%** | **separated (+49.6%)** |
   | `a|b` | 2-branch dense byte class | 5,269,846 | 171.4 (165.0..180.3) | 211.7 (208.0..222.4) | **+23.5%** | **separated (+23.5%)** |
   | `pub fn` | multi-byte literal | 882,393 | 99.0 (96.7..101.2) | 98.5 (98.1..102.2) | -0.5% | within ±3% floor |
   | `(pub\|fn) [a-z]+` | alternation + trailing class | 1,236,465 | 148.1 (144.8..152.6) | 310.4 (307.8..316.0) | **+109.6%** | **separated (+109.6%)** |
   | `foo.*bar` | prefix + line-window suffix | 264,029 | 81.6 (80.1..84.3) | 82.5 (79.9..85.3) | +1.0% | within ±3% floor |
   | `e[0-9]` | dense prefix + selective digit class | 240,786 | 75.3 (74.2..80.2) | 81.0 (77.6..85.9) | +7.6% | **overlap, not a result** |
   | `let mut` | multi-byte literal | 39,795 | 65.5 (62.2..77.4) | 64.5 (63.8..68.0) | -1.5% | within ±3% floor |
   | `fn main` | sparse multi-byte literal | 175,860 | 67.6 (65.8..71.7) | 67.7 (66.3..70.2) | +0.2% | within ±3% floor |

2. **Stage composition (`RGX_ABLATE_NGRAM=1`, `-j 1`, 7 rounds, rotated, with `RGX_NGRAM_STATS=1` vacuity check):**
   - On direct walk (`rgx -c "e[0-9]" crates/rgx-core/src`, no `--tv-store`), `base` (`25.4 ms [24.6..27.0]`) and `no-ngram` (`25.8 ms [25.1..27.6]`) agree on `331` matches across `34` files (`+1.6%`, within `±3%` floor) because direct walk does not consult `.tv` manifest signatures.
   - Against a `--tv-store` built over `crates/rgx-core/src` (`103` files) and over `crates` (`586` pack records, `525` non-adapter-claimed files), `e[0-9]` is a stand-down control (`pruned 0 of 103` and `0 of 525` in both arms, `331 == 331` and `1,721 == 1,721` matches) because `query_sig512` requires a 4-byte literal in `required::anywhere`. Patterns carrying a 4-byte required literal prune in the base arm and prune `0` when `RGX_ABLATE_NGRAM=1`, with exact match-count parity (`pub fn`: `10/103` and `82/525` pruned, `835` and `1,143` matches; `fn main`: `12/103` and `91/525` pruned, `15` and `150` matches; `ByteRegex`: `11/103` and `85/525` pruned, `145` and `189` matches; `let mut`: `9/103` and `85/525` pruned, `1,586` and `3,797` matches).

3. **Exact byte threshold for `RGX_MAX_MEMBER_BYTES` on `crates/rgx-core/testdata/zip_text_deflate.zip`:**
   - Both archive members (`readme.txt` and `nested/inner.bin`) have `declared_size = 1,140` bytes (`compress_size = 33` bytes), checked via `MemberSink::fits` (`self.bytes + need <= self.budget.max_total_bytes` in `crates/rgx-adapters-archive/src/budget.rs`):
     - `RGX_MAX_MEMBER_BYTES <= 1139`: `0 of 2` members extracted + searchable `[rgx: archive truncated: 0 of 2 members extracted (...)]` note (`1` match for `-c "a"`).
     - `1140 <= RGX_MAX_MEMBER_BYTES <= 2279`: `1 of 2` members extracted (`readme.txt` = `60` matches + truncation note = `1` match).
     - `RGX_MAX_MEMBER_BYTES >= 2280`: `2 of 2` members extracted (`60 + 60` matches, no truncation note).

**Conclusion.** Raw candidate-stream diodicity (`Di`) measures in-register candidate selectivity, not end-to-end wall-clock speedup, because wall-clock cost under `RGX_ABLATE_MASK=1` is governed by **which fallback stage catches the stream when the mask is declined**: `(pub|fn) [a-z]+` (`Di = 1.1x` over `"pub "`/`"fn "` prefixes) suffers the largest wall-clock penalty (**`+109.6%`**, cleanly separated) because the alternation has no single literal prefix for `memchr` to fall back to, whereas `e[0-9]` (`Di = 67.0x`) falls back to `memchr('e')` + 1-byte digit check over `240,786` hits against a ~65 ms process/I/O floor (`+7.6%`, refused by the range-overlap gate). Quote `Di` for stage placement and selectivity; quote only the count-gated, range-separated wall-clock rows (`+109.6%` on `(pub|fn) [a-z]+`, `+49.6%` on `e.`, `+23.5%` on `a|b`) for speed.

---

## 20. The cold-cache asymmetry: the pack store pays 9% where the direct arms pay 30-32%

**Question.** `cold-transcript-linux.md` holds five `sync + drop_caches` / warm
pairs per arm on the 20k tree (`fn main`, `-j 10`, Linux Ryzen 7 255,
2026-10-14). The paper's two-term law writes per-file cost as a metadata tax
$\sigma N$; §12 above measured ~80k syscalls and ~600 ms of `sys` on this
corpus, then later corrected the warm-dentry `stat` to ~0.5 us and left most
of that `sys` time unexplained. Is the per-file cost a property of the corpus
and the filesystem, or of the page cache -- and does the pack store change the
answer?

**Evidence.**

1. **Cold/warm pairs, 5 samples per arm per condition.** `sync + drop_caches`
   before every cold reading, the paired warm reading immediately after.
   Medians with the harness's own minimum beside them; the penalty is the
   second component of a two-state fit `T = warm_base + is_cold * penalty`
   (observation rows `[1,0]` warm and `[1,1]` cold, so a plain Kalman), which
   agrees with the median difference the transcript already prints:

   | arm | warm min / med (ms) | cold min / med (ms) | Dmed | two-state fit (ms) | share of warm |
   |---|---:|---:|---:|---:|---:|
   | `tv` (pack store) | 50.0 / 51.0 | 54.0 / 56.0 | **4.50** | 4.12 +- 1.34 | **8.8%** |
   | `rgx` (direct) | 76.0 / 78.0 | 101.0 / 104.0 | **25.00** | 24.40 +- 1.34 | **32.1%** |
   | `rg` (ripgrep) | 63.0 / 70.0 | 88.0 / 91.0 | **21.00** | 24.46 +- 1.27 | **30.0%** |

   Two estimators of the same quantity are shown because they are not the
   same number. `Dmed` is the harness's own median difference -- the figure
   `scripts/tv-cold.sh` now prints -- and the two-state fit is the second
   component of `T = warm_base + is_cold * penalty` with its posterior
   spread. They agree to within a millisecond on `tv` and `rgx` and differ
   by 16% on `rg`, whose samples are the most spread; with five samples per
   cell that is the resolution available, so both are reported. Both run
   after the MAD pass of item 2.

   Both direct arms pay **4.7x-5.6x** the pack store's cold penalty in
   absolute ms, and the store's penalty is **~9%** of its warm latency
   against **30-32%** for the direct paths.

2. **Two of the fifteen cold readings are not from the same distribution, and
   a mean would hide it.** `tv` cold[0] = 100.0 ms against a ~55 ms
   neighbourhood; `rgx` cold[0] = 311.0 ms against ~103 ms. After
   `drop_caches` the first query also faults in the binary's own text and the
   store manifest, so it is not a reading of the corpus alone. A MAD pass at
   3 x 1.4826 x MAD names exactly those two samples and nothing else (`rg`
   drops none). The choice to drop them is visible in the fit above. Left in,
   `rgx`'s mean cold reads 124.6 ms against its median of 104.0, and the
   published "cache penalty" would be a first-cold artefact.

3. **The per-file cost is not syscall work.** §12 measured ~600 ms of `sys`
   over ~80k syscalls on this corpus -- 7.5 us per syscall in rusage -- while
   a measured warm-dentry `stat` is ~0.5 us, and a one-for-one
   `stat` -> `fstat` swap measured flat-to-worse (76.1 -> 78.9 ms, §12). The
   gap is page faults, dentry/inode work and memory management, all of which
   account as `sys` time. So the term the two-term law calls a metadata tax is
   mostly cache behaviour, and the split above is how much of it is cache
   state at all.

**Conclusion.** The pack store's advantage is in part **cache immunity**, not
cheaper per-file work: going cold costs the direct arms 30-32% of their warm
latency and the store ~9%. Quote the cold penalty beside any `sigma`-class
number -- a per-file cost measured warm is an upper bound on the filesystem's
share of it. The two-state fit makes the split explicit with an honest
uncertainty; the MAD pass is what keeps the first-cold artefact out of the
published number. This is an architecture claim with a falsifier (a corpus or
cache state where the asymmetry vanishes).

Reproduce: `bash scripts/tv-cold.sh` (Linux host; needs `drop_caches`). The
cold penalty is the median difference after a MAD pass at
3 x 1.4826 x MAD; `benchmark/regress.py` runs that pass and reports what
moved between two runs.

---

## 21. The cache asymmetry of §20 did not replicate: the pack store now pays 272% of its warm base going cold

**Question.** §20 measured the pack store's cold penalty at ~9% of its warm
latency against 30-32% for the per-file paths, and called the property
**cache immunity** -- the prepared query path close to insensitive to
page-cache state where the direct paths are not. Its falsifier was named:
"a corpus or cache state on which the asymmetry collapses." Does the
asymmetry survive a re-run?

It does not.

**Evidence.** Same host (Linux, Ryzen 7 255, CachyOS), same corpus
(`~/.rgx-bench/tree`, 20,000 files, 417,730,136 bytes), same pattern
(`fn main`), same `-j 10`, same 5-sample `sync + drop_caches` protocol, run
through the same `scripts/tv-cold.sh`.

| arm | 2026-10-14 warm / cold (med) | penalty | share | 2026-10-17 warm / cold (med) | penalty | share |
|---|---|---|---|---|---|---|
| `tv` (pack store) | 51.0 / 56.0 | 4.50 ms | 8.8% | 84.0 / 313.0 | **228.50 ms** | **272%** |
| `rgx` (direct) | 78.0 / 104.0 | 25.00 ms | 32.1% | 74.0 / 97.0 | 22.50 ms | 30.4% |
| `rg` (ripgrep) | 70.0 / 91.0 | 21.00 ms | 30.0% | 64.0 / 89.0 | 24.50 ms | 38.3% |

1. **The direct paths are the control, and they did not move.** `rgx`:
   25.00 -> 22.50 ms. `rg`: 21.00 -> 24.50 ms. Both inside their own
   five-sample spread. Host drift is therefore ruled out; whatever changed
   changed on the store path alone.

2. **The store moved 50x and inverted the ratio.** 4.50 -> 228.50 ms, and
   its penalty went from 8.8% of the warm base to 272% of it. The
   cache-immunity ratio the harness prints now reads 0.10x -- the prepared
   arm pays **10x more** cold penalty than the per-file paths, the exact
   reverse of §20's 4.7-5.6x.

3. **It is not layout and it is not size.** Both stores are 189M on disk,
   26 packs each, and `manifest.tvm` is 2,921,073 bytes (v4) against
   2,921,081 (v5) -- eight bytes, the version number. The pack corpus is
   identical. What differs is the query path.

4. **The store is also slower warm**: 51.0 -> 84.0 ms, +65%. So this is not
   purely a cache effect; there is per-query work in v5 that was not in v4,
   and the cold path amplifies it.

5. **A confound was caught before it was published.** The first re-run put
   the store in `/tmp`, which on this host is **tmpfs**; `~/.rgx-bench` is
   ZFS. That run showed the same inversion (141.50 ms) but measured RAM, not
   storage, and is discarded. The table above is the ZFS run, the only one
   comparable to §20. The harness does not record the filesystem under a
   store -- it should.

**Hypothesis, not a measurement.** The two runs differ by the manifest
version: the 2026-10-14 store is `manifest v4`, the 2026-10-17 store `v5`,
and the v5 change is described in `tv/format.rs` as storing "the rollup over
a file's raw text and every unit the adapters can produce, signed under an
extraction fingerprint a query must match before it may prune." Per-query
fingerprint
verification before pruning is exactly the shape of work that would cost
nothing warm and a great deal cold. **This is a hypothesis and is not
measured here** -- isolating it needs a build that can write both manifest
versions, which this tree cannot do.

**Conclusion.** §20's property did not survive a re-run. The direct arms
held, so the measurement is sound; the store changed underneath it. Two
consequences, and the first is the one that matters:

- **The paper's `sec:eval:cold` claim is falsified by its own stated
  falsifier.** It claims "the prepared query path is insensitive to
  page-cache state where the per-file paths are not" and names as its
  refutation "a corpus or cache state on which the asymmetry collapses."
  It collapsed. §20 is retained as the record of what was measured on
  2026-10-14 under manifest v4; it is not a property of the architecture
  as it stands today.
- The harness should record the manifest version and the store's filesystem
  beside every run. Neither is in the transcript header, and one of them
  decided the outcome.

Reproduce: `bash scripts/tv-cold.sh --store ~/.rgx-bench/cold-v5-disk
--root ~/.rgx-bench/tree --pattern 'fn main' --threads 10 --samples 5`,
against a store built with `rgx --tv-build --tv-store STORE CORPUS` on the
tree as it stood on that date.

## 22. The sparse plan is correct and active; the wall clock said "overlap, not a result" on every corpus measured

The post-sOTA work (§3.3 dirty-file overlay, manifest v5 adapter rollup,
extent-coalesced sparse reads) was closed out under the count-gated A/B
protocol: seven rounds rotated, the spawn floor measured first and
subtracted from both sides, and a verdict that may refuse. It refused.

**Correctness held everywhere the gate ran.** Count parity was exact in
every cell: `rgx-tv search -c` arm A == arm B == `rgx --engine rgx -c`
(3 = 3 = direct on `u32_7074`; 514,621 = direct on `struct` over the 20k
tree), and on the mixed corpus the CLI pack path matched the direct walk
(29 = 29 = direct on `HashMap`, 806 = 806 = direct on `needle`). Not one
gate refused a timing line for disagreement.

**The mechanism is verified active.** `RGX_EXTENT_STATS` on the buffered
path reports exactly what the plan decided to read (under
`RGX_ABLATE_EXTENTS` the read is the whole payload, 417,730,136 bytes in
493 units; with the sparse plan on, the units are the survivors' spans).
A trace of the container gate shows the rollup rejecting a container
before decompression (`brotli_text_q0.br`, `contains=false pruned=true`)
with `sig_covers_adapter` set and the query's extraction fingerprint equal
to the store head's.

**What the timings said** (Windows, `crates` dev box, floor 14.4-15.1 ms):

| corpus | pattern | ablated (median) | sparse (median) | floor-sub ratio | verdict |
|---|---|---|---|---|---|
| tree, 20k files / 417.7 MB | `u32_7074` (3 lines) | 43.12 ms | 41.35 ms | 1.07x | overlap, not a result |
| tree, 20k files / 417.7 MB | `struct` (514,621 lines) | 47.91 ms | 46.19 ms | 1.06x | overlap, not a result |
| crates, 587 files / 11.9 MB | `HashMap` (29 lines) | 518.00 ms | 508.07 ms | 1.02x | overlap, not a result |
| crates, 587 files / 11.9 MB | `needle` (806 lines) | 516.69 ms | 516.33 ms | 1.00x | overlap, not a result |

Two measured boundaries explain every row, and both are properties of the
corpora rather than of the code:

1. **The rejects are scattered, so the gap rule correctly declines to
   skip.** On the 20k tree, `u32_7074` rejects 8,698 of 20,000 records,
   but in walk order their runs average under one file -- far below
   `MAX_EXTENT_GAP` (64 KiB). The sparse arm read 417,460,225 of
   417,730,136 bytes: **0.06% saved**. On `ngram-corpus` (15,001 real
   `.rs` files) every candidate pattern read 98.5-99.9% of the payload
   for the same reason. Below the threshold the read is cheaper than one
   extent per surviving file -- the design's own trade, now measured.
2. **High-entropy fixtures saturate the signature.** The mixed corpus's
   containers are compressed and bomb fixtures: `brotli_rand_q0.br`'s
   stored signature has `w0 = 0xffffffffffffffff` -- a full Bloom word.
   A saturated signature cannot reject anything (by construction: it
   holds every bit), so the filter stands down exactly on the fixtures
   whose decompression is most expensive, and both arms pay it. This is
   the same behaviour that makes those fixtures good test material.

The stage decomposition (`--stats`) says where the milliseconds go when
the read is not the answer: `in-process 27.8 ms = manifest 1.6 + filter
3.1 + work 19.6`, where the work phase is 196 ms of read cpu spread over
12 threads -- warm-cache reads are cheap and the fixed costs dominate.
The roadmap's reachable-state claim (10-30x on mixed corpora) is
therefore **not verified** on these corpora: the win exists where rejects
cluster into runs of 64 KiB or more AND their signatures carry headroom,
which the fixture corpora deliberately lack. No number here claims a
speedup; the falsifier's non-overlapping-separation condition was not met.

Reproduce: `pwsh benchmark/extent-ab.ps1 -Corpus <tree> -Patterns
"u32_7074,struct"` and the same with `-AblateVar RGX_ABLATE_NGRAM` over
`crates`, both on the tree as it stood on that date, with `rgx-tv` built as
`cargo build --release -p rgx-core --features tv-runtime` (the bin is
`required-features`-gated and a plain `--release` leaves a stale one --
the first run of this bench priced a two-day-old binary and was thrown
away).

**Two more corpora on the same protocol, same verdict.** A re-run on
2026-10-17 over the 20k tree (`fn main`, count 297,851) and a fresh
`crates` store (587 files, `pub fn`, count 1,175), 7 rounds rotated at
`-j 8`, `RGX_ABLATE_EXTENTS` against the default:

| corpus | control [min..max] | extents [min..max] | verdict |
|---|---|---|---|
| 20k, `fn main` | 82..87 ms | 82..90 ms | overlap, not a result |
| crates, `pub fn` | 430..438 ms | 431..441 ms | overlap, not a result |

Both count gates passed exactly and the distributions interleave. Nothing
above changes: the sparse plan is correct, active, and its wall-clock
separation is not reachable on corpora whose rejects do not cluster and
whose signatures have no headroom. The roadmap's reachable-state claim
stays **not verified**, which is now the measured answer on four corpora
rather than two.

