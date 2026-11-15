# Drift report -- the EGM contracts of `rgx`

Pass after the harness-parity commit (94afbc9) and the toolchain bump
(95a58a0). Scope: the contracts those commits changed (`src/EGM.md`,
`scripts/EGM.md`), the contract whose files they changed
(`crates/rgx-core/src/EGM.md` — `lib.rs` gained the soft-float allow,
`byteclass.rs` the iterator rewrite), and `MANUAL.md`, which the pass
read against the code. Every Interface signature, invariant and side
effect in scope was located in the current source and verified; only
the differences are reported.

**Review context.** This harness registers no fresh-context `subagent`
tool, and the user directed the pass to continue inline, so the review
ran in the parent context — it is a drift detection, not a Goldfish
review, and says so rather than claiming a fresh context it did not
have.

## src/EGM.md

- The `fn run()` dispatch item named the token-index query flag
  `--index-dir`; the grammar's flag is `--index` (the internal field is
  `index_dir`, `src/main.rs:fn app`). **Resolved:** the item now names
  `--index`.
- The Spawns side effect named only `soffice` and `tesseract` among the
  adapter crates' external tools; `rgx-adapters-docs` also reaches for
  `libreoffice` (the office binary's second name,
  `crates/rgx-adapters-docs/src/lib.rs:available`) and the rasterisers
  `pdftoppm`/`pdftocairo` (`RASTERISERS`). The root contract's inventory
  had been corrected for this before; this one had not. **Resolved:**
  the item names all four.
- Re-verified after the fixes: the JSON stream invariants (record
  shapes, the two stats field orders, `bytes_printed` from the records
  written, `Msg::JsonMiss`, the adapter tag only on adapter-claimed
  files, the streaming printer), the Interface signatures against
  `main.rs`, `engine.rs`, `walk.rs`, `detector.rs`, `cache.rs`,
  `mmap.rs`, `type_db.rs`, `rc.rs`, `pick.rs`, and the exit-status,
  field-order, rewind, config, hidden-file, cache, protocol-mode and
  tally invariants. No further drift detected.

## scripts/EGM.md

No drift detected. The pair list names seventeen pairs and every
`.sh`/`.ps1` pair exists; the `compare-rg`, `compare-json-stream.py`
and `use-with-dsh` rows match the scripts' current behaviour (the
comparator's exit codes and placeholders, the probe's three questions);
`bench.ps1` is absent as claimed; the new comparator imports the
standard library only, so the no-bytecode invariant holds.

## crates/rgx-core/src/EGM.md

No drift detected. The crate is still `#![no_std]` + `alloc` (the new
`allow` attributes are lint policy, not a configuration change — the
bare-metal `x86_64-unknown-none` builds prove it), `byteclass.rs` is
listed in the engine group and the contract makes no claim the
`negate` rewrite contradicts, and the pipeline, registry and policy
claims are untouched by the two commits.

## MANUAL.md

- §8's `RGX_ENGINE` row listed `tv` and `tesla` among the retired names
  that print "the engine no longer exists"; the detector honours
  `RGX_ENGINE=tv|tesla|tesla-valve` as a live pack-store selection
  (`src/detector.rs:AutoDetector::detect`) and `Mode::from_env` warns
  only for `grep` and `both` (`src/engine.rs:Mode::from_env`).
  **Resolved:** the row now says `tv`/`tesla` select the pack store and
  only `grep`/`both` are retired.
