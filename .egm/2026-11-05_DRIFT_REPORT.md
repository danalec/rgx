# Drift report -- the EGM contracts of `rgx`

The contracts the bootstrap corrected are checked against the code they
describe. Only the differences are reported; a contract with nothing
wrong with it says so and nothing else. This run covers the 43 contracts
whose verification sections were corrected on 2026-11-05. The review is
performed by fresh-context Goldfish reviewers using the
`egm-codebase-details` persona in REVIEW mode.

## EGM.md

No drift detected

## benchmark/EGM.md

No drift detected

## crates/rgx-adapters-pdf/src/jbig2/EGM.md

No drift detected

## crates/rgx-core/examples/EGM.md

No drift detected

## crates/rgx-core/fuzz/fuzz_targets/EGM.md

No drift detected

## crates/rgx-core/src/EGM.md

No drift detected

## crates/rgx-core/src/bin/EGM.md

No drift detected

## crates/rgx-core/src/compress/EGM.md

No drift detected

## crates/rgx-core/src/compress/xz/EGM.md

No drift detected

## crates/rgx-core/src/crypt/EGM.md

No drift detected

## crates/rgx-core/src/djson/EGM.md

No drift detected

## crates/rgx-core/src/djson/json_scan/EGM.md

No drift detected

## crates/rgx-core/src/djson/ondemand/EGM.md

No drift detected

## crates/rgx-core/src/regex/EGM.md

No drift detected

## crates/rgx-core/src/searcher/EGM.md

No drift detected

## crates/rgx-core/src/tv/EGM.md

No drift detected

## crates/rgx-core/src/tv_runtime/EGM.md

No drift detected

## crates/rgx-core/src/memchr/EGM.md

No drift detected

## crates/rgx-core/src/memmap2/EGM.md

No drift detected

## crates/rgx-core/src/memmap2/platform/EGM.md

No drift detected

## crates/rgx-adapters-media/src/EGM.md

No drift detected

## crates/rgx-adapters-media/src/exif/EGM.md

No drift detected

## crates/rgx-adapters-media/src/exif/makers/EGM.md

No drift detected

## crates/rgx-adapters-pdf/src/EGM.md

No drift detected

## crates/rgx-adapters-docs/src/EGM.md

No drift detected

## crates/rgx-adapters-inspect/src/EGM.md

No drift detected

## crates/rgx-adapters-llm/src/EGM.md

- Missing coverage of the `Adapter::facts` / `--filter` feature: `Gguf::facts` (`crates/rgx-adapters-llm/src/lib.rs:310`, fact `tensor.count`) and `Safetensors::facts` (`crates/rgx-adapters-llm/src/lib.rs:539`, facts `tensor.name`/`tensor.shape`/`tensor.dtype`, the user-facing `tensor:name` predicate) are public `impl Adapter` overrides with dedicated tests, yet the Interface section lists only `name()`/`extensions()` for these two adapters and no invariant mentions `facts()` or `Field`; the peer contracts `crates/rgx-adapters-mail/src/EGM.md` and `crates/rgx-adapters-media/src/EGM.md` document their own `facts()` implementations ("Also implements `facts()`").

## scripts/EGM.md

No drift detected

## src/EGM.md

- Stale line-number citations: the contract cites `fn main()` at `src/main.rs:6995`, `fn run()` at `src/main.rs:7671` and `fn registry()` at `src/main.rs:3667`; the current file has them at `src/main.rs:7006`, `src/main.rs:7682` and `src/main.rs:3678` respectively (all +11 lines, from a later insertion). All three symbols exist with the documented signatures, so this is positional metadata only, but the cited lines do not land on the symbols they name.

## src/cli/EGM.md

No drift detected

## crates/rgx-adapters-mail/src/EGM.md

- `EGM.md:39` claims "there is no sender or recipient extraction anywhere in the crate", but `pst.rs:message_text` resolves `PROP_SENDER_NAME`/`PROP_SENDER_EMAIL`/`PROP_DISPLAY_TO` and writes `from:`/`to:` lines (pst.rs:1082-1092), and `lib.rs:header_facts` reports `mail.from`/`mail.to` facts for `Eml`/`Mbox` (lib.rs:530-547). Sender/recipient extraction does exist in the crate.

## crates/rgx-adapters-office/src/EGM.md

No drift detected

## crates/rgx-adapters-tabular/src/EGM.md

- `EGM.md:134-136` states "The data of a dataset that is in chunks is **not** read — the chunks are indexed by a tree this reader does not walk — and the reader says so, dataset by dataset", and `EGM.md:127` says chunks are "indexed by a v1 B-tree". `hdf5.rs:dataset_values` (hdf5.rs:1156-1280) now walks the chunk index (`chunks_btree1`, `chunks_implicit`, `chunks_fixed_array`, `chunks_extensible_array`, `chunks_btree2`; `ChunkIndex` has six variants at hdf5.rs:2974-3017) and emits per-element values; tests `the_values_of_a_chunked_dataset_are_read` / `the_chunks_of_the_latest_format_are_read` pin it.
- `EGM.md:131-133` says "a bit set means a filter was applied, and this reader does not undo the filters". The code does the opposite: a **clear** bit means applied (`chunk.filter_mask & (1 << i) == 0`, hdf5.rs:1219-1222; the mask names *excluded* filters, hdf5.rs:2989), and `undo_filters` (hdf5.rs:3104) undoes shuffle, fletcher32 and deflate, refusing only unknown filters by name.

## crates/rgx-adapters-threed/src/EGM.md

No drift detected

## benchmark/diffrig/EGM.md

- **Stated behavior contradicted by code** — the doc (Overview + Invariants) asserts "the `.exe` suffix is hardcoded in all four" / "in every harness, so the rule resolves a Windows binary on any platform and `ptytest.py` finds no `rgx` on the Unix host it exists for". In code, `benchmark/diffrig/ptytest.py:_find_rgx`, `benchmark/diffrig/fuzz.py:_find_rgx` and `benchmark/diffrig/cmp.sh:RGX` each try `rgx.exe` first and then fall back to a bare `rgx` (their header comments say "the Unix host has no `.exe`, and this harness exists for the Unix host"); only `benchmark/diffrig/conpty.py:RGX` keeps a hardcoded `.exe`. The claimed Windows-only resolution and the "finds no rgx on the Unix host" behavior do not exist.

## Formula/EGM.md

No drift detected

## crates/rgx-adapters-archive/src/brotli/EGM.md

No drift detected

## crates/rgx-adapters-archive/src/lz4/EGM.md

No drift detected

## crates/rgx-adapters-archive/src/sevenz/EGM.md

No drift detected

## crates/rar-codec/examples/EGM.md

No drift detected

## crates/rar-codec/src/EGM.md

No drift detected

## crates/rgx-adapters-archive/examples/EGM.md

No drift detected

## crates/rgx-adapters-archive/src/EGM.md

No drift detected
