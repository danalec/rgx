# json_scan

## Overview
Stage 1 of the two-stage JSON parser. It answers one question about a byte slice and nothing else — which bytes are structural, and which are string delimiters — as one bit per byte for each. A stage-2 parser walks those two bitsets and never looks at the document again. Nothing in this module interprets JSON syntax, parses a value, or allocates anything except the two bitsets.

The predicate is defined for byte `b` at offset `i`, with `in_string` the state *before* `b`:

```text
escaped(i)    = (the run of backslashes ending at i-1 has odd length)
boundary(i)   = b is '"' and not escaped(i)
structural(i) = boundary(i) or (b is ws or punctuation and not in_string)
quote(i)      = boundary(i)
```

`scan_scalar` is that, one byte at a time, in the clearest form there is; `scan_swar` and `scan_avx2` are faster spellings of the same predicate over 64-byte blocks.

The escaped quote is the reason the module exists. The quote that delimits a string and the quote a `\` makes literal are the same byte, and only the run of backslashes in front of them tells them apart. An unescaped quote outside a string still *opens* one, so the state is a toggle and not a flag: a lone `"` at offset 0 sets both bits.

The classification uses a *union of rectangles* over the high-nibble × low-nibble grid — six of them, the five structural groups and the quote on its own — rather than one fused shuffle pair, because no single rectangle can be the structural set: `,` (0x2C) and `:` (0x3A) are both structural, so a rectangle holding both lights low nibbles `C` and `A` and selects rows 2 and 3, and row 2 then drags in `0x2A` (`#`), which is content.

## Interface
- `pub struct StructuralIndex` — `pub structural: BitSet`, `pub quote: BitSet`, `pub len: usize`, `pub end_in_string: bool`, `pub structural_positions() -> impl Iterator<Item = usize>`, `pub quote_positions() -> impl Iterator<Item = usize>`.
- `pub struct BitSet` — `with_len(len)`, `len()`, `is_empty()`, `contains(i)`, `count_ones()`, `words() -> &[u64]`, `iter_set() -> impl Iterator<Item = usize>`.
- `pub struct Classified16` — the 16-byte classification of one block; `pub fn classify16(bytes: &[u8; 16]) -> Classified16` (scalar) and `pub fn classify16_avx2(bytes: &[u8; 16]) -> Classified16` (vector, x86_64 only).
- `pub fn scan(bytes: &[u8]) -> StructuralIndex` — the dispatched entry point.
- `pub fn scan_scalar(bytes: &[u8]) -> StructuralIndex` — the reference implementation, one byte at a time.
- `pub fn scan_swar(bytes: &[u8]) -> StructuralIndex` — the SWAR spelling of the same predicate.
- `pub fn scan_avx2(bytes: &[u8]) -> StructuralIndex` — the vector spelling, x86_64 only.
- `pub const CLASS_OTHER: u8 = 0`, `CLASS_STRUCTURAL: u8 = 1`, `CLASS_QUOTE: u8 = 2`, `CLASS_BACKSLASH: u8 = 3` — the class codes.
- `pub const CLASS_TABLE: [u8; 256]` — the byte-to-class table.
- `pub const fn class_of(b: u8) -> u8`, `pub const fn is_whitespace(b: u8) -> bool`.
- `pub const fn rect_bytes((lo, hi): ([u8; 16], [u8; 16])) -> [u8; 256]` — the byte set a rectangle selects.
- `pub fn prefix_xor(x: u64) -> u64` — the SWAR carry helper.
- `pub fn has_avx2() -> bool`, `pub fn has_avx2_pclmulqdq() -> bool` — the CPU probe.
- `pub struct Carry` — the SWAR carry state between blocks.

## Invariants
- The class codes are compared, never masked. `CLASS_BACKSLASH` is `0b11`, so a single `class & CLASS_STRUCTURAL` would classify every backslash as structural *and* as a quote, turning a lone `\` into a string delimiter.
- Bytes >= 0x80 are OTHER by construction: no rectangle lights a row above `7`, so UTF-8 lead and continuation bytes never select. This also satisfies the `pshufb` high-bit rule, under which the instruction zeroes any lane whose index has bit 7 set.
- `scan`, `scan_swar` and `scan_avx2` compute the same predicate; the vector path is a faster spelling, not a different rule.
- The AVX2 path is guarded by the crate's own CPU probe (`crate::detect`, CPUID and XGETBV, no `std`), and that probe is shared with every other caller, so a `std` build and a `no_std` build reach the same kernel on the same machine.
- All `unsafe` is confined to the private `avx2` module: the `#[target_feature]` functions, each of which documents the check that guards it, and the two `unsafe fn` helpers `rect` and `rect128`, which carry no `#[target_feature]` and are reached only from such a function.
- The scanner allocates nothing but the two bitsets.

## Side Effects
- None beyond allocation of the two bitsets returned in `StructuralIndex`.
- Reads no files, spawns no processes, takes no locks and touches no global state. The CPU probe caches its answer in a process-global, which is a read-only cache after the first call.

## Verification
- Run: `cargo test --release --locked --workspace`
