# fuzz

## Overview
The coverage-guided fuzzing setup for `rgx-core` and the whole adapter family. It is a Cargo package of its own — `rgx-core-fuzz`, `version = "0.0.0"`, `publish = false`, with its own `[workspace]` table so it is not a member of the main build and cannot disturb the main lockfile. It depends on `libfuzzer-sys` and on `rgx-core` itself, plus every adapter family: archive, office, threed, llm, media, tabular, docs, mail, inspect and pdf.

The directory holds the manifest, the lockfile, the `.gitignore` and the seed `corpus/`; the build `target/` it also carries is a gitignored artefact of a local fuzz run, not part of the tree. The code lives in the one target below. The seeds that are tracked — `seed-zip-eocd-tail` and `seed-safetensors-overflow` — contain NULs, which is the whole point of them, and `.gitattributes` marks `**/fuzz/corpus/**` as `-text` so a checkout that rewrote their line endings would not change the offsets a parser is being tested against.

## Subdirectories & Boundaries
- `fuzz_targets`: [fuzz_targets](./fuzz_targets/EGM.md) — the `process` fuzz target: the extension list, the registry it drives, and the `fuzz_target!` body that pushes arbitrary bytes through `rgx_core::process`.
