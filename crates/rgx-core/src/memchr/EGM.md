# memchr

## Overview
The byte searches, dispatched by this crate's own CPU probe. `rgx-core` is `#![no_std]` + `alloc`, and the upstream `memchr` crate decides at *runtime* whether it may use AVX2 — but it can only ask the question through `std::is_x86_feature_detected!`, and that macro lives in `std`. So the upstream crate answers "no" to every `no_std` build, and the `no_std` configuration fell back to SSE2 on every byte scan: the same search over the same bytes was 37% slower in the build that is supposed to be the embedder's build.

The upstream crate does publish the AVX2 searchers themselves — `memchr::arch::x86_64::avx2::memchr::{One, Two, Three}` — behind an `unsafe` constructor whose contract is exactly the question this crate already answers: *may this CPU run the AVX2 instructions?* The answer comes from `crate::detect`, which is written out by hand (CPUID and XGETBV, no `std`) and cached.

There is no `feature = "std"` anywhere in the dispatch: a build with `std` and a build without it ask the same probe and reach the same kernel, so the numbers the two builds produce are comparable. Everything else the upstream crate offers is re-exported unchanged, so every call site keeps the `rgx_core::memchr::*` path it has used since the in-house module was deleted. The upstream crate's own dispatch still runs when the CPU has no AVX2 — it picks SSE2 there, and NEON on aarch64, both at compile time and both needing no probe.

The substring search is the one exception: `memmem` is this crate's own, because the upstream crate's packed-pair kernel cannot be reached without `std`. It runs only on x86_64 and only where the probe reports AVX2; every other case falls back to the upstream `::memchr::memmem::find`/`rfind`.

## Interface
- `pub use ::memchr::*` — the upstream crate, re-exported unchanged.
- `pub mod memmem` — this crate's own substring search, used on x86_64 where the probe reports AVX2, and falling back to the upstream one everywhere else.
  - `pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize>`.
  - `pub fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize>`.
  - `pub fn find_iter<'h, 'n, N: ?Sized + AsRef<[u8]>>(haystack: &'h [u8], needle: &'n N) -> FindIter<'h, 'n>`.
  - `pub fn rfind_iter<'h, 'n, N: ?Sized + AsRef<[u8]>>(haystack: &'h [u8], needle: &'n N) -> FindRevIter<'h, 'n>`.
  - `pub struct Finder<'n>` — `new`, `find`, `rfind`, `find_iter`, `rfind_iter`, `needle`.
  - `pub struct FinderRev<'n>` — `new`, `rfind`, `rfind_iter`, `needle`.
  - `pub struct FinderBuilder` — `new`, `build`, `build_rev`, `matcher`.
  - `pub struct Matcher<'h, 'n>` — `find`, `rfind`, `find_iter`, `rfind_iter`.
  - `pub struct FindIter<'h, 'n>`, `pub struct FindRevIter<'h, 'n>`.
- `pub mod dispatch` (private) — the probe-driven kernel choice, re-exported at the module root:
  - `pub fn memchr(needle: u8, haystack: &[u8]) -> Option<usize>`.
  - `pub fn memrchr(needle: u8, haystack: &[u8]) -> Option<usize>`.
  - `pub fn memchr2(needle1: u8, needle2: u8, haystack: &[u8]) -> Option<usize>`.
  - `pub fn memrchr2(needle1: u8, needle2: u8, haystack: &[u8]) -> Option<usize>`.
  - `pub fn memchr3(needle1: u8, needle2: u8, needle3: u8, haystack: &[u8]) -> Option<usize>`.
  - `pub fn memrchr3(needle1: u8, needle2: u8, needle3: u8, haystack: &[u8]) -> Option<usize>`.
  - `pub fn memchr_iter<'h>(needle: u8, haystack: &'h [u8]) -> Memchr<'h>`, `memchr2_iter` -> `Memchr2<'h>`, `memchr3_iter` -> `Memchr3<'h>`; the three reverse ones return `Rev<Memchr<'h>>`, `Rev<Memchr2<'h>>` and `Rev<Memchr3<'h>>`.
  - `pub struct Memchr<'h>`, `Memchr2<'h>`, `Memchr3<'h>` — the iterator types, wrapped in `Rev` for the reverse ones.

## Invariants
- The kernel is chosen at run time from `crate::detect`'s CPUID/XGETBV probe, and that probe is the same one every other caller in the crate uses — so the `std` build and the `no_std` build reach the same kernel on the same machine.
- No `feature = "std"` gate appears anywhere in the dispatch; the answer to "may this CPU run AVX2?" is the only input to the choice.
- On a CPU without AVX2 the upstream crate's own compile-time dispatch runs (SSE2 on x86_64, NEON on aarch64); this crate does not second-guess it.
- `memmem::find_iter` yields the *start* of each match and the matches do **not** overlap. A caller that wants the overlapping ones has to step one byte on, which is what `crate::regex`'s `sub_offsets` does.
- `memmem` uses this crate's own pair scanner (`crate::scan::pair_find` / `pair_rfind`), which tests the needle's two *rarest* bytes at once in 32-byte blocks (64 with AVX-512) and confirms every candidate — but only on x86_64 and only where the probe reports AVX2; every other case falls back to the upstream kernel, whose packed-pair form is unreachable without `std`.
- The upstream crate's prebuilt `Finder`, which amortises matcher setup across many searches, is deliberately unused here: every search in rgx is a one-shot over a buffer, so `memmem::find` remains the right entry point for a single search.

## Side Effects
- None beyond the iterator's own state. Every function reads a byte slice and returns offsets.
- The CPU probe caches its answer in a process-global; after the first call it is a read-only lookup.

## Verification
- Run: `cargo test --release --locked --workspace`
