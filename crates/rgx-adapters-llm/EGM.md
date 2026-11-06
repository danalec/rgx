# rgx-adapters-llm

## Overview

The machine-learning model family of `rgx`. Its adapters never extract
weights — a multi-GB payload of floats is useless to a text search — they
extract *metadata*: tensors, shapes, hyperparameters, architecture strings,
vocabularies. That is what an LLM agent wants when it greps a model zoo.

The family covers the formats a model zoo is actually made of: GGUF
(llama.cpp), safetensors, NumPy `.npy`, Protocol Buffers, tiktoken
vocabularies, Keras v3 `.keras` archives, PyTorch `.pt`/`.pth`/`.pt2`
checkpoints and generic Python pickles.

The crate is `#![no_std]` + `alloc` and declares no `std` feature; the two
features that need the filesystem-independent budget machinery (`keras`,
`torch`) pull in `rgx-adapters-archive` with its `std` feature, because
their zip reading spends the archive crate's shared producer budget
(`-M` / `RGX_MAX_MEMBER_BYTES`). Every adapter sits behind a Cargo feature
named after the format it reads, and the default build carries all of them.

## Subdirectories & Boundaries

- `src`: [src/EGM.md](./src/EGM.md) — the whole implementation: the
  `adapters()` factory, the five core adapters (`Gguf`, `Safetensors`,
  `Npy`, `Protobuf`, `Tiktoken`) and the `extra` module with the
  harness-family adapters (`KerasZip`, `Torch`, `PickleStrings`) and the
  shared zip/printable-string helpers they use. Public symbols: `pub fn
  adapters()`, `pub struct Gguf`, `pub struct Safetensors`, `pub struct Npy`,
  `pub struct Protobuf`, `pub struct Tiktoken`, and `impl Adapter` for
  each. `extra` is a private module, so its three adapters are
  crate-internal and are not nameable from outside the crate.
