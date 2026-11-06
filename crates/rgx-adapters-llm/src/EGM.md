# rgx-adapters-llm/src

## Overview

The implementation of the model-file family. `lib.rs` holds the crate's
`no_std` shell, the `adapters()` factory and the five core adapters;
`extra.rs` holds the harness-family adapters (Keras, PyTorch, pickle) plus
the two helpers they share.

The rule the whole crate is built on: **metadata, never weights**. A GGUF
header yields its version, tensor count and key/value metadata; a
safetensors header yields every tensor name, shape and dtype; a `.npy`
header yields its dtype and shape; a protobuf yields its field names; a
tiktoken vocabulary yields every decoded token. The float payloads are left
alone, because they are not searchable text and reading them is the
expensive part.

## Interface

`extra` is a private module, so the three adapters it holds are
crate-internal and no item of them is nameable from outside the crate.

- `pub fn adapters() -> Vec<Box<dyn Adapter>>` — the factory the binary's
  registry consumes, in feature order: `Gguf`, `Safetensors`, `Npy`,
  `Protobuf`, `Tiktoken`, `extra::KerasZip`, `extra::Torch`,
  `extra::PickleStrings`.
- `pub struct Gguf` (feature `gguf`) — llama.cpp model container. `impl
  Adapter`: `name() == "gguf"`, `extensions() == &["gguf"]`. Also implements
  `facts()`: the `tensor.count` fact read from the header's tensor count.
  Header layout: magic `"GGUF"`, `u32` version, `u64` tensor count, `u64`
  key/value count, then the key/value entries (u64-length-prefixed string
  key, `u32` value type, value; array values are `u32` type + `u64` length +
  elements).
- `pub struct Safetensors` (feature `safetensors`) — `impl Adapter`:
  `name() == "safetensors"`, `extensions() == &["safetensors", "sft", "st"]`.
  Also implements `facts()`: `tensor.name`, `tensor.shape` and
  `tensor.dtype` for every tensor in the header — the facts behind the
  `tensor:name` filter predicate.
- `pub struct Npy` (feature `npy`) — NumPy array. `impl Adapter`:
  `name() == "npy"`, `extensions() == &["npy"]`.
- `pub struct Protobuf` (feature `protobuf`) — `impl Adapter`:
  `name() == "protobuf"`, `extensions() == &["pb", "onnx", "model", "mlmodel"]`.
- `pub struct Tiktoken` (feature `tiktoken`) — OpenAI tiktoken vocabulary.
  `impl Adapter`: `name() == "tiktoken"`, `extensions() == &["tiktoken"]`.
- `pub struct extra::KerasZip` (feature `keras`, crate-internal) — Keras v3
  `.keras` archive: a zip carrying `config.json` and `metadata.json`. `impl
  Adapter`: `name() == "keras"`, `extensions() == &["keras"]`.
- `pub struct extra::Torch` (feature `torch`, crate-internal) — PyTorch
  checkpoint. `impl Adapter`: `name() == "torch"`, `extensions() == &["pt",
  "pt2", "pth", "ptl", "bin"]`.
- `pub struct extra::PickleStrings` (feature `pickle`, crate-internal) —
  generic Python pickles (joblib dumps, legacy HF model files). `impl
  Adapter`: `name() == "pickle"`, `extensions() == &["pkl", "pickle"]`.
- Crate-internal helpers: `extra::printable_strings(data, max_out) ->
  String` (printable ASCII runs of at least 4 characters),
  `extra::zip_members(data) -> Result<Vec<(String, Vec<u8>)>>` (a zip read
  under the archive crate's shared producer budget), and the little-endian
  readers `rd_u16` and `rd_u32` (compiled when `gguf` or `npy` is on),
  `rd_u64` (when `gguf` or `safetensors` is on) and `rd_f32` and `rd_f64`
  (when `gguf` is on) — so a `safetensors`-only build has `rd_u64` of the
  five.

## Invariants

- The crate is `#![no_std]` + `alloc`: nothing here touches the filesystem,
  the clock, threads or `std::env`. The `keras` and `torch` features pull in
  `rgx-adapters-archive` (with `std`) only because they spend that crate's
  producer budget.
- Every adapter sits behind a Cargo feature named after the format it
  reads; the default build carries all of them.
- **Weights are never extracted.** A GGUF reports its header and key/value
  metadata, a safetensors file its tensor inventory, a `.keras` archive its
  `config.json`/`metadata.json` JSON parts, a torch checkpoint its member
  list and its printable strings — never a float payload.
- An adapter declines a file it does not recognise (bad magic, wrong shape)
  rather than answering, so the chain continues and the raw bytes stay
  searchable.
- `Gguf` and `Safetensors` are the only adapters in this crate that
  override `Adapter::facts`: the former reports `tensor.count`, the latter
  `tensor.name` / `tensor.shape` / `tensor.dtype`. These are the facts the
  `--filter` predicates `tensor:count` and `tensor:name` match on; a fact
  nobody reports is false, not an error.
- Every length that comes from the file is checked before it is used, and
  the arithmetic that could overflow is checked arithmetic: the GGUF key
  length goes through `checked_add` because `klen` comes from the file and
  may be `usize::MAX`, and the fixed-size value payload is bounds-checked
  separately from the type tag that precedes it.
- The GGUF key/value loop is bounded (at most 4096 entries) and the protobuf
  report is bounded (at most 1 MiB); the tiktoken vocabulary is read for at
  most 1 000 000 lines.
- The safetensors header length is taken from the file and validated against
  the file's own size before it is used — an absurd header length is
  refused rather than trusted.
- `extra::zip_members` spends the archive crate's shared producer budget
  (`budget::MemberSink`), so a `.keras`/`.pt` zip is capped by `-M` /
  `RGX_MAX_MEMBER_BYTES` exactly like every other container, and the
  truncation note reaches the pipeline as an ordinary member instead of
  being dropped in silence. A member larger than 4 MiB is skipped.
- A member of the zip that cannot be decoded does not sink the archive: a
  member the *byte budget* stopped is a different thing — it was readable
  up to a limit — and saying nothing about it would read as "no match in
  it".
- `extra::Torch` returns `Outcome::Members` for a zip checkpoint, so the
  pipeline recurses: `data.pkl` lands on the pickle adapter and plain
  members on raw search. A zip renamed to `.bin` — firmware, bundles,
  generic archives — used to get only a name listing, hiding all of its
  content from the search.
- A legacy (non-zip) torch checkpoint must start with the pickle `PROTO`
  opcode `0x80`; anything else returns `Outcome::Bail("no PROTO opcode")`
  so a plain `.bin` blob falls back to the raw search.
- `extra::PickleStrings` declines a zip-based pickle ("zip-based pickle
  belongs to the torch adapter") and bails on a file without the `PROTO`
  opcode.
- **An adapter must not claim an extension it cannot read.** `Protobuf`
  deliberately does not claim `tflite` (a TFLite model is FlatBuffers) nor
  `pt2` (a zipped torch archive): a reader that cannot parse the format
  prints its refusal as if the file were unreadable, or worse renders a
  FlatBuffers buffer as protobuf field names that do not exist. Leaving an
  extension unclaimed is not a gap — it falls through to the raw search and
  keeps `rg`'s answer. `pt2` belongs to `extra::Torch`, which reads it the
  same way as `.pt`.
- The protobuf plausibility check is cheap and conservative: the first byte
  must not be `0` (a field tag is a non-zero varint key) and the first 16
  bytes must hold no NUL.

## Side Effects

- None on the filesystem, the network, the clock or the environment. The
  crate allocates through `alloc` and returns text or member lists.
- The `keras` and `torch` features read the archive crate's **process-wide
  producer budget** (`rgx_adapters_archive::budget`), which is configured
  from `RGX_MAX_MEMBERS` and `RGX_MAX_MEMBER_BYTES` in the environment by
  the binary that owns it. The crate itself neither writes nor mutates it;
  the budget is a global the tests have to lock against.

## Verification

- Run: `cargo test --release --locked --workspace`
