# Adapter-signed n-gram rollup (Direction 1.1, manifest v5)

What the store's `FileRecord::ngram` now says, when a filter may believe it,
and what proves both. Written for the parent to fold into
`AGENTS.md`/`benchmark/findings.md`; those two files are untouched here.

## What changed

| File | Change |
|---|---|
| `crates/rgx-core/src/tv/format.rs` | `MANIFEST_VERSION = 5`; head field `extract_fp: u64`; `FileLoc::SIG_COVERS_ADAPTER = 8` (+ named `FLAG_EMPTY/DELETED/BINARY`); `FileRecord::sig_covers_adapter`; `MIN_MANIFEST_LEN` +8 |
| `crates/rgx-core/src/lib.rs` | `Registry::chain()` -- the chain in registration order, for a caller that must describe it |
| `crates/rgx-core/src/ngram.rs` | unchanged (the rollup is built from `build_stored_sig512` at the signing sites) |
| `crates/rgx-core/src/tv_runtime/builder.rs` | `UnitSigner` hook; `record_sig`/`member_rel` helpers; rollup signing at both record sites; `extract_fp` stamped into the head; `build_or_update_store_with_extractor` now really forwards the hooks (the comment claimed it; the code did not) |
| `crates/rgx-core/src/tv_runtime/update.rs` | `update_store_with` (extractor + signer + fingerprint, forwarded from the build); extract-fingerprint refusal; owner-aware tombstoning (member records of a live container survive an update); rollup signing on every record the update re-ingests |
| `crates/rgx-core/src/tv_runtime/searcher.rs` | the two `search_store`-family filter sites apply the same per-file rule; `SearchConfig.extract_fp: Option<u64>` threads the query's fingerprint |
| `crates/rgx-core/src/tv_runtime/compact.rs` | carries `extract_fp` through a rebuild of the head |
| `src/main.rs` | `extract_fingerprint`; `pipeline_units` (one closure for the storage and signing roles); both `--tv-build` paths sign rollups; `run_tv_query` per-file rule (below) |
| `tests/tv_overlay.rs` | two pre-existing `needless_borrows_for_generic_args` under the current clippy (1.99): dropped the `&`. Not this work's code, but the gate is the gate |
| `tests/sigroll.rs` | new: 4 CLI tests (below) |

## The v5 layout delta

- **Head**: `magic, version, generation, timestamp, corpus,` **`extract_fp`**
  **`, root_path, packs, ...`**. `decode`/`head`/`scan`/`encode` all agree;
  `MIN_MANIFEST_LEN` grew by the 8 bytes.
- **Record trailer**: unchanged at 101 bytes. Flag byte bit 8
  (`FileLoc::SIG_COVERS_ADAPTER`) was free and is now the rollup marker. Bits
  1/2/4 keep their meaning (`FLAG_EMPTY/DELETED/BINARY`, now named).
- **`FileRecord::ngram` semantics**: the OR rollup over the record's own
  decoded text **and** every unit and `[rgx: ...]` note
  `rgx_core::process` hands a search for it. Without the flag the field is
  the raw-text signature as before. An all-zero signature is still
  "unknown" and still never rejects.
- **Refusal**: a v4 catalog is refused on every read path with its version
  named ("unsupported manifest version 4 (this build reads 5)"), because its
  `ngram` answers a different question than v5 reads.

## `extract_fp` -- what is folded and why

64-bit FNV-1a (compared for equality, never preimage-resisted), over, in
order: a format tag, `MANIFEST_VERSION`, `Ctx { max_depth, max_members,
max_file_size }`, the archive producers' member budget (members + bytes,
which is where `RGX_MAX_MEMBERS`/`RGX_MAX_MEMBER_BYTES` move the units
without moving the `Ctx`), the adapter policy (`RGX_ADAPTER_VIEW` adds and
removes renderings from the haystack), and the adapter chain in registration
order: name, declared extraction version (`u64::MAX` when undeclared),
`available()` (a missing external tool changes the units), and the claimed
extensions, `RGX_CLAIM_EXT` extras included.

The rule is the conservative direction throughout: a query folds its own
fingerprint with the same function and may trust a rollup only on equality.
`0` in the head means "not stated" and trusts nothing. The build folds over
the `Ctx` its hooks ran under (`Ctx::default()` today, which is what the
default CLI flags resolve to: depth 4, members 4096, `-M` 1G), so a query
with default flags engages and a query that moved any component stands down.

**Boundary the fingerprint cannot see**: the version of an external tool on
PATH (soffice, tesseract, ocrs). Their presence is folded, their binary is
not. A tool upgraded in place between build and query can change the units
under an equal fingerprint. This is the same boundary the `--cache` key
documents for its unmemoisable adapters.

## The FNR argument

A filter may over-report; it must never lose a match. Per stand-down:

- **`-v`/`--files-without-match`**: `ngram_q` is `None` -- a "match" is a
  line the pattern does *not* cover, so nothing is required in one.
- **forced `-E`**: `ngram_q` is `None` -- the matcher sees transcoded text
  the build's signature did not cover.
- **`RGX_ABLATE_NGRAM`**: forces `ngram_q` to `None`; cost may change,
  answers never do.
- **all-zero signature**: `contains_query` answers `true`; an un-analysed
  record is unknown, and unknown never rejects.
- **dirty file**: never filtered -- the stored signature covers the bytes
  the build saw, and pruning on that loses matches to edits.
- **adapter-claimed file**: searched on the pipeline's units. Filtered only
  when (a) the record says its signature is the rollup, and (b) `head.extract_fp`
  equals the query's. (a) is what makes the subset test cover the units: a
  match in any unit has the query's bits in that unit's signature, and the
  OR carries them. (b) is what makes the units *the right units*: a rollup
  signed under a different `Ctx`/budget/policy/chain covers neither the
  units this query will search nor necessarily any of them. Missing either
  answer, the filter stands down -- today's behaviour, no slower and no
  less safe than before this work.
- **no required 4-byte literal / caseless literal**: `query_sig512` returns
  `None`; the pattern's spelling is not required of a match.

One rule answers at every filter site: `run_tv_query` (the CLI's store
search, which runs the adapter pipeline) and both `search_store`-family
sites in `searcher.rs`. Note the searcher's own haystack is the record's
bytes, which *every* signature this format writes covers (a rollup by
construction, a raw one trivially), so there the gate is conservative
rather than necessary -- it is enforced anyway so the three sites cannot
drift apart and so an adapter-aware caller of the library API is protected
by the same line. `SearchConfig.extract_fp: None` (the `rgx-tv` binary)
means "states no extraction context" and stands rollup records unfiltered.

## Update path

`build_or_update_store_with_extractor` now forwards the extractor **and**
the signer to `update_store_with` (item 5's mismatch: the comment claimed
forwarding, the code dropped both). A changed file re-derives its records
through the same hooks; a signer carrying a different `extract_fp` than the
head is refused exactly like a differing `corpus`, because an update
re-signs only changed files and the head can only name one context.

Tombstoning is owner-aware: a record is owned by its name, or by the
container prefix (`container!member`, `container#member`) its name hangs
off. A changed container supersedes its whole set; a deleted one takes its
members with it; an untouched one keeps them. The old rule (tombstone every
record whose own name the walk did not yield) deleted every member record
of every pre-extracted container on every pass, changed or not.

## Tests and their teeth

11 new tests: `tv/format.rs` 2, `tv_runtime/update.rs` 5, `tests/sigroll.rs` 4.

| Test | What it holds down | The assertion that would catch the regression |
|---|---|---|
| `a_v5_manifest_round_trips_the_extraction_fingerprint_and_the_rollup_flag` | encode/decode/scan agreement on `extract_fp` and flag bit 8 | any of the three readers dropping the field/bit fails the equality |
| `a_v4_store_is_refused_with_its_version_named` | v4 is a different question | all three read paths assert the message names version 4 and "reads 5" |
| `a_signed_record_covers_the_units_the_pipeline_produces` | the rollup at the build's signing sites | `contains_query` over the unit text: fails if the rollup drops the signer's units; the unsigned twin asserts the raw signature does *not* claim them, so the positive side cannot pass by fixture accident |
| `an_update_re_derives_a_changed_containers_members` | the extractor and signer are forwarded to the update | the old member is tombstoned, the new one is live **and** its rollup contains the new unit text; a raw-only re-sign or an un-forwarded extractor fails the record list |
| `an_update_keeps_an_untouched_containers_members` | owner-aware tombstoning | any pass that tombstones a live container's members fails the record-list equality |
| `a_deleted_container_takes_its_members` | the other side of the same rule | a leaked member record fails the live list |
| `an_update_under_a_different_extraction_fingerprint_is_refused` | the head carries one context | the refusal names the mismatch and publishes no generation |
| `the_rollup_finds_a_member_only_needle_and_prunes_the_container_that_lacks_it` | both directions of FNR=0 at the CLI | the fixture asserts the hit's **raw** signature would prune it (so a lost rollup loses the hit), count parity with `--engine rgx`, and `pruned == 1 of 3` -- 0 means the filter stood down for everything and the rest of the test was noise |
| `the_filter_stands_down_when_the_extraction_context_moves` | the `extract_fp` gate | same store queried under `RGX_MAX_MEMBERS=2`: the answer must be byte-identical and the prune counter must move 1 -> 0. A missing gate keeps the counter at 1; a gate that changes the answer fails the equality |
| `an_incremental_update_re_signs_a_changed_container` | the update's rollup signing end to end | parity with `--engine rgx` after the rewrite (a raw-only re-sign of the changed record prunes the fresh member and breaks parity), plus the tombstoned member's text answers nothing |
| `the_store_and_the_direct_engine_agree_on_a_mixed_tree` | the headline claim | `--tv` == `--engine rgx`, line for line, in `-c`/`-n`/`-n -F` over text + containers + an empty file |

Fixture honesty is asserted, not assumed: the gzip fixtures check that the
compressed bytes carry **none** of the needle's 4-grams (a fixture whose
stream leaks the literals proves nothing) and that the hit's raw signature
would prune it. The member filler is repeated common words on purpose --
varied filler saturates the 512-bit signature to all-ones (measured: an
all-ones record can never be pruned), and a saturated fixture would make
the prune assertion untestable.

## Deliberately left

- **`--cache` header integration** (out of scope per the task): a cache hit
  rehydrates units the rollup may or may not cover; the same
  `extract_fp` question applies there and should reuse this fold.
- **`--rules` CLI work** and **benchmark harness runs**: out of scope.
- **The dirty overlay vs. pre-extracted member records** (discovered, not
  fixed): the overlay re-reads `root/rel_path` for a stale record, and a
  pre-extracted member record's name (`container!member`) is not a disk
  path, so its re-read fails and the record is dropped ("a file gone from
  disk contributes nothing"). A `--tv-pre-extract` store therefore loses
  its container answers at query time today, rollup or not. Fixing it means
  the overlay recognising member records and re-deriving them from their
  owner's bytes (the update path now has the owner logic to build on). The
  unit tests here exercise the build/update hooks directly and the CLI
  tests use plain stores, so this work neither causes nor masks it.
- **Group freshness on the update path**: a pre-extracted container's
  records carry the member's length, so "unchanged" for a member group
  rests on mtime alone. A size change under a restored mtime is missed --
  the raw path's own hole, widened by the missing length check. The `corpus`
  and `extract_fp` refusals bound the blast radius; document before
  trusting an update for provenance-grade work.
- **`searcher.rs`'s gate is conservative by analysis** (see the FNR
  section): if the library search is ever given an adapter pipeline, the
  gate is already in the right place; if it stays raw-only, a future
  maintainer may lift it deliberately and gain the prune rate back on the
  `rgx-tv` binary, which passes `extract_fp: None` today.
