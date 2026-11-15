# ondemand

## Overview
The differential suite that holds the lazy (on-demand) JSON walk against the Arena parser. The module itself lives in `../ondemand.rs`; this directory holds its `#[cfg(test)] mod tests` — the file that makes the three contracts stated in the module header true rather than claimed: that the two walks accept and reject the same documents, that the lazy walk's key lookup returns the same value the Arena's `object_get` returns, and that the lazy walk's iteration order is the Arena's interned-index order.

The suite drives the two walkers through the same helpers — one that asks the lazy walk, one that asks the Arena — and compares their answers rather than comparing against a hand-written expectation, so a change that moves one walker without the other is caught here.

## Interface
- `fn lazy_accepts(doc: &str) -> bool` — whether the on-demand walk accepts the document.
- `fn arena_accepts(doc: &str) -> bool` — whether the Arena parser accepts the same document.
- `fn arena_keys_in_order(doc: &str) -> Vec<String>` — the Arena's object keys in `BTreeMap<usize, _>` (interned-index) order.
- `fn lazy_keys_in_arena_order(doc: &str) -> Vec<String>` — the lazy walk's keys, forced into the same order.
- `fn lazy_compact(doc: &str) -> String` — the lazy walk's compact serialisation.
- `fn arena_find_compact(doc: &str, key: &str) -> Option<String>` — the Arena's value for a key, compactly rendered.
- `fn lazy_find_compact(doc: &str, key: &str) -> Option<String>` — the lazy walk's value for the same key.
- Tests: `the_two_walks_reject_the_same_documents`, `raw_control_characters_in_strings_are_rejected_by_both`, `nesting_depth_agrees_at_the_boundary`, `the_walk_validates_values_the_consumer_never_reads`, `scalar_values_round_trip_identically`, `find_key_returns_the_last_duplicate_like_object_get`, `lookup_type_mismatches_are_none_not_errors`, `array_items_agree_with_the_arena`, `raw_returns_the_exact_source_bytes`, `key_order_is_intern_rank_not_source_order`, `compact_serialisation_reproduces_rank_order_and_dedupe`, `the_lazy_walk_never_panics_on_mutation` — the last one is gated on the `std` feature, so the `no_std` build of `rgx-core` runs the other eleven.

## Invariants
- The two walks must agree on *which documents are JSON*, not only on the values they read: a document the Arena parser rejects is rejected by the lazy walk too, including garbage under a value the consumer never reads.
- The nesting limit is the same in both walks (`MAX_DEPTH = 128`, mirroring `index_parser::MAX_DEPTH`), so they cannot disagree about which inputs are JSON.
- `find_key` returns the *last* entry of a duplicated key, matching `Arena::object_get`'s `BTreeMap` semantics — not the first, and not an error.
- A lookup whose type does not match returns `None`, not an error: the value exists and is of another type.
- Object key order is the interned-string index order (order of first appearance of the key *string* anywhere in the document), not source order.
- The lazy walk must never panic, whatever the document does to it.

## Side Effects
- None. The suite is compiled only under `#[cfg(test)]`, builds its documents in memory, and touches no file, process or global state. One of its tests is additionally gated on the `std` feature, so the `no_std` build runs the other eleven.

## Verification
- Run: `cargo test --release --locked --workspace`
