# djson

## Overview
rgx's JSON value, parser, serializer and streaming layer. The suite is organised in two stages.

Stage 1 (`json_scan`) produces two bitsets over the document: which bytes are structural (`{ } [ ] : ,` and whitespace outside strings) and which are string-delimiter quotes. Stage 2 (`index_parser`) walks those two bitsets and populates an `Arena` with the parsed document. The walker holds two sorted `Vec<usize>` snapshots of the bitset iterations — one for structural, one for quotes — and a current byte offset, so every token is a question about a known structural position rather than a fresh scan.

The arena is the load-bearing data model. A parsed JSON value is a `Copy` handle into an `Arena { strings, arrays, objects, root }`. Object keys are `usize` slots into the arena's string table (deduped), so an escaped key whose source bytes needed decoding is owned by the arena just like a non-escaped one. The `BTreeMap` key type is `usize` and the arena's allocator owns every string in the document. `parse` returns the arena alone — `Result<Arena, JsonParseError>` — and the caller drops it when it is done with the values taken out of it.

The crate is `no_std` + `alloc`, and there is no `serde` dependency and no `serde` feature: there is nothing to opt into. The streaming layer (`stream`) is `no_std` + `alloc` as well; only `from_reader` is `std`-only, for its reader convenience.

## Interface
- `pub use parser::{parse, to_string, to_string_pretty}` — the entry points: `parse(input: &str) -> Result<Arena, JsonParseError>`, `to_string(v: Value, arena: &Arena) -> String`, `to_string_pretty(v: Value, arena: &Arena) -> String`.
- `pub use value::{escape_json_string, write_escaped, Arena, Number, Value}` — the data model.
  - `pub enum Number` — `as_f64()`, `as_i64()`, `as_u64()`, `is_integer()`.
  - `pub enum Value` — `is_null()`, `is_bool()`, `is_number()`, `is_string()`, `is_array()`, `is_object()`, `as_bool()`, `as_number()`, `as_number_ref()`, `num(f64)`, `as_str(arena)`, `as_f64()`, `as_i64()`, `as_u64()`, `as_array(arena)`, `as_object(arena)`, `get(arena, key)`, `get_path(arena, path)`, `get_index(arena, index)`, `len(arena)`, `is_empty(arena)`, `contains_key(arena, key)`, `keys(arena)`, `values(arena)`.
  - `pub struct Arena` — `new()`, `with_capacity(n_strings, n_arrays, n_objects)`, `root()`, `get_string(idx)`, `get_array(idx)`, `get_object(idx)`, `strings()`, `arrays()`, `objects()`, `intern(s: String) -> usize`, `object_get(obj_idx, key)`, `object_iter(obj_idx)`.
- `pub use error::{ErrorCategory, JsonError, JsonResult}` — the diagnostic layer: `ErrorCategory`, `JsonError` (`syntax`, `syntax_expected`, `eof`, `data`, `data_at`, `serialize`, `deserialize`, `deserialize_at`, `with_byte_offset`, `with_path`, `is_syntax`, `is_eof`, `is_data`, `is_io`, `position_string`, `context_string`).
- `pub use raw_value::RawValue` — `new(&str)`, `get() -> &str`, `from_str(&str) -> Option<Self>`; an owned handle to a JSON fragment kept as raw bytes.
- `pub use stream::{ndjson, NdJsonIter, StreamParser}` — `StreamParser::new()`, `feed(&mut self, bytes: &[u8])`, `next() -> Result<Option<Arena>, JsonParseError>`, `into_inner() -> Vec<u8>`; `ndjson(input: &str) -> NdJsonIter<'_>`.
- `pub fn from_reader<R: std::io::Read>(...)` — `std`-only convenience over the stream parser.
- `pub mod index_parser` — stage 2, the walker that populates the arena; its `parse_indexed` is `pub(super)`, so it is reached through `parse`.
- `pub mod parser` — the public parse entry point plus the serializer and the `Value` traversal code; the legacy char-based parser is kept behind `#[cfg(test)]`.
- `pub mod value`, `pub mod error`, `pub mod raw_value`, `pub mod stream` — the modules behind the re-exports above.
- `json_scan`: [json_scan](./json_scan/EGM.md) — stage 1, the structural/quote bitsets. Public symbols: `StructuralIndex`, `BitSet`, `Classified16`, `scan`, `scan_scalar`, `scan_swar`, `scan_avx2`, `classify16`, `classify16_avx2`, `class_of`, `is_whitespace`, `CLASS_TABLE`, `CLASS_OTHER`, `CLASS_STRUCTURAL`, `CLASS_QUOTE`, `CLASS_BACKSLASH`, `rect_bytes`, `prefix_xor`, `has_avx2`, `has_avx2_pclmulqdq`, `Carry`.
- `ondemand`: [ondemand](./ondemand/EGM.md) — the differential suite holding the lazy walk against the Arena parser. The `lazy_accepts` / `arena_accepts` / `arena_keys_in_order` / `lazy_keys_in_arena_order` / `lazy_compact` / `arena_find_compact` / `lazy_find_compact` helpers and the twelve differential tests live in its `#[cfg(test)]` module and are private to it.

## Invariants
- A parsed value never owns anything: it is a `Copy` handle into an `Arena`, and the arena must outlive every handle taken out of it.
- The arena owns every distinct string in the document, deduplicated; an object key is a `usize` slot into that table, so an escaped key is owned exactly like a non-escaped one and there is no `Box::leak`.
- Object iteration order is the interned-index order, which for distinct keys equals source-insertion order because the parser interns on first sight.
- The two stages are the only way a document is read: stage 2 never re-scans the document character by character, it asks the bitsets.
- A document rejected by the Arena parser is rejected by the lazy walk too — the two walks must agree on what is JSON, not only on the values they read.
- The float parser is `no_std`-capable: under `std` it is `f64::from_str`, otherwise `crate::parse_decimal`, a decimal parser over what RFC 8259 allows (optional sign, integer part with no redundant leading zero, optional fraction, optional exponent). `crate::NoStdFloat` is the seam both sides agree on.
- `RawValue` keeps the source bytes exactly — escapes and whitespace included — and never validates them.
- The streaming layer carries a `Vec<u8>` between feeds and hands out one `Arena` per complete document; a partial document is retained, not dropped.

## Side Effects
- None beyond allocation: the parser and the arena allocate, and the caller frees them when the arena is dropped.
- `stream::from_reader` reads from the `std::io::Read` the caller supplies and owns nothing else; the NDJSON iterator borrows its input string.
- No global state, no locks, no processes.

## Verification
- Run: `cargo test --release --locked --workspace`
