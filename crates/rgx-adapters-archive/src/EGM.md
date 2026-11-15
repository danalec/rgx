# rgx-adapters-archive src

## Overview

The adapter chain itself. `lib.rs` holds the registry — `adapters()` returns
the adapters in chain order, and the order is the argument: the adapters that
claim by file name come first, `borg` comes last among those because it is
the one format rgx reaches by what a file *is* rather than by what it is
called, and the image adapters come after the real archives because each of
them declines on a magic it does not own, so `.img` only reaches the raw-dump
dispatch after the archives have declined it. The same file declares the
adapters whose implementation lives in `rgx-core` or needs no module of its
own: `Zip`, `SevenZ`, `Tar`, `Cpio` and `Decompress`.

Every module under this directory answers one format. `budget.rs` is the
shared spine: it owns the producer-side work budget that every adapter reads
through `MemberSink`, because `Ctx::max_members` caps how many members the
pipeline recurses into *after* the adapter has already built them, and
`Adapter::extract` never sees a `Ctx`. The format modules are `ar.rs`
(Unix `ar` and Debian packages), `backups.rs` (git bundles and Subversion
dumps), `borg.rs` with `msgpack.rs` (borg repository segments and the
MessagePack reader their metadata needs), `git_pack.rs` (git packfiles),
`pgdump.rs` (PostgreSQL custom dump archives), `rar.rs` (`.rar`, backed by
the `rar-codec` crate), `squashfs.rs` (SquashFS 4.0), `tar.rs` (usttar, pax
and GNU long names, with a writer kept for round-trip completeness) and
`images.rs` (ISO 9660, raw dumps, and the block-image containers).

Three in-house codec trees sit under this directory as well: `brotli` (an
RFC 7932 decoder), `lz4` (the LZ4 block, frame and legacy codecs) and
`sevenz` (the 7z container reader and its LZMA, DEFLATE, BZip2 and Huffman
codecs).

## Interface
- `pub fn adapters() -> Vec<Box<dyn Adapter>>` — the registry, in chain order.
- `pub struct Zip`, `pub struct SevenZ`, `pub struct Tar`, `pub struct Cpio`, `pub struct Decompress` — the adapters declared in `lib.rs`; each implements `rgx_core::Adapter` (`name`, `extensions`, `extract`).
- `pub mod budget` (the `std` feature only) — the producer-side work budget. `Budget { pub members: usize, pub bytes: u64 }`, `budget() -> Budget`, `set_budget(b: Budget)`, `reset_budget()`, `budget_for_depth(depth: usize) -> Budget`, `enum Stopped { MemberCount, Bytes, Examined }`, `const TRUNCATION_MEMBER: &str = "rgx-truncated-members.txt"`, `const DECOMPRESSION_NOTE: &str = "rgx-truncated-decompression.txt"`, `const UNSUPPORTED_MEMBER: &str = "rgx-unsupported-members.txt"`, `unsupported_note(refused: &[(String, String)]) -> (String, Vec<u8>)`, `decompression_note(emitted: u64, limit: u64, declared: Option<u64>) -> (String, Vec<u8>)`, and `MemberSink` with `new()`, `with_budget(limit: Budget)`, `declare(entries: usize)`, `remaining_bytes() -> u64`, `reserve(declared_size: u64) -> bool`, `push(name: String, bytes: Vec<u8>) -> bool`, `stop(reason: Stopped)` and `finish(self) -> Vec<(String, Vec<u8>)>`.
- `pub mod ar` — `pub struct Ar`.
- `pub mod backups` — `pub struct GitBundle`, `pub struct SvnDump`.
- `pub mod git_pack` — `pub struct GitPack`.
- `pub mod images` — `pub struct Iso9660`, `pub struct RawImage`, `pub struct AppleFs`, `pub struct Vhd`, `pub struct Vhdx`, `pub struct Qcow2`, `pub struct Vmdk`, `pub struct Vdi`, `pub struct Wim`, `pub struct Erofs`.
- `pub mod squashfs` — `pub struct Squashfs`.
- `pub mod brotli` — the in-house RFC 7932 decoder: [brotli](./brotli/EGM.md).
- `pub mod lz4` — the LZ4 block, frame and legacy codecs: [lz4](./lz4/EGM.md).
- `pub mod sevenz` — the 7z container reader and its codecs: [sevenz](./sevenz/EGM.md).
- Private modules: `mod borg` (`pub struct Borg`) and `mod msgpack` (`pub enum Value` with `get`/`as_bytes`/`as_i64`/`as_u64`/`as_array`, `pub struct Decoder<'a>` with `new`/`is_empty`/`decode`), `mod pgdump` (`pub struct PgDump`), `mod rar` (`pub struct Rar`), `mod tar` (`TMAGIC`, `GNUTMAGIC`, `enum TarEntryType` with `to_byte`, `struct TarHeader`, `struct TarEntry`, `enum TarError`, `type TarResult<T>`, `struct TarReader` with `read_all`/`read_all_limited`, `struct TarWriter` with `new`/`add_entry`/`add_directory`/`finish`).

## Invariants
- An adapter never recurses itself. Members come back as `Outcome::Members` and `rgx_core::process` owns the depth limits, the member caps and the bail semantics.
- `decline!` and `bail!` are not interchangeable. A decline is this adapter stepping aside from a file that is some other format — an ordinary event that must not mint a note and must not put a line in the corpus that is not in the file. A bail is a file that *is* this format and could not be decoded, which is exactly what a note is for.
- Neither arm may stop the chain. A format that is not this one's is declined, and a format that is this one's but is broken is a bail; in both cases the next adapter still gets its turn.
- "Not the format its name promises" is a bail, not an empty decode. A decoder handed bytes it does not recognise has two honest answers — an error, or, for the streaming ones, nothing at all — and `GzipReader::decode_bounded` walks `while pos < len && is_gzip(rest)`, so a text file named `.gz` returns `Ok` carrying zero bytes and the file vanishes with no match and no reason. The magic is therefore checked at the adapter boundary, before the decoder is called. Brotli is the one exception RFC 7932 excuses: it defines no magic, so that one is decided by the decoder's own error.
- Every producer reads the budget through `MemberSink`, and it reserves against the *declared* size before it decodes anything — so a container that advertises a huge uncompressed member never pays to produce it. A producer stops as soon as a `reserve` or a `push` returns false.
- The budget is halved once per nesting level, and depth 0 gets exactly the budget it always had. The sum over a tree of any depth stays under twice the process budget; without that, a 4 MiB zip holding 4096 small zips would pass the member cap at level 0 and then draw 4096 more full budgets at level 1.
- A truncated archive says so. `MemberSink::finish` prepends a searchable note member (`rgx-truncated-members.txt`) so a partial extraction is visible rather than looking complete; giving up the last real member for the note costs nothing, because the pipeline's own `.take(ctx.max_members)` drops that member anyway.
- A refusal is not truncation and must not borrow its wording: an entry a codec declined is named in `rgx-unsupported-members.txt`, because an entry that is silently absent and an entry that does not exist look identical to a search.
- The 7z adapter decodes a folder at most once. Entries are contiguous by folder, so a single slot that is replaced when the folder index moves turns a per-file re-decode (quadratic in files-per-folder) into one decode per folder, while keeping the peak at a single folder rather than the whole archive.
- A 7z folder's *declared* size is checked against the remaining budget before the folder is materialised, because a folder is decoded whole and the substream sizes are the file's own — a folder of `[1 byte, budget-sized]` substreams passes the per-entry reserve and then pays for the whole folder.
- The `.dump` extension is claimed by two adapters and the two magic numbers are disjoint: a Subversion dump starts with `SVN-fs-dump-format-version:` and a PostgreSQL custom archive with `PGDMP`, so whichever runs first declines the other's file.
- The image adapters answer two different questions. Filesystems with a catalogue (ISO 9660, SquashFS) hand back real members and are a `Reach::Reveal`. WIM is the odd one: it parses the XML metadata header and hands back a text report, not members. The block containers (VHD, VHDX, QCOW2, VMDK, VDI, EROFS, APFS, HFS+) report the container's own geometry, UUID, backing chain and file names, never the payload: reading a block device's contents means mounting it, and an adapter is a pure function over a byte slice.

## Side Effects
- Reads only the byte slice handed in; no adapter opens a file, spawns a process, mounts anything or needs privileges.
- Allocates the expanded members it returns, bounded by the budget.
- `budget.rs` reads two environment variables: `RGX_MAX_MEMBERS` and `RGX_MAX_MEMBER_BYTES` (both take a plain count or a `k`/`m`/`g` suffix). The module is `std`-only, so none of this exists in a `--no-default-features` build. The budget itself is process-wide state held in two atomics, so a test that changes it must hold the crate's test lock — the crate-internal `budget::testing::locked` / `budget::testing::under_budget`, which are `pub(crate)` — or it races every other test reading it.
- `set_budget` asserts `members >= 2` (a budget below 2 cannot hold the truncation note) and `bytes >= 1`.
- The decompression adapter reads `RGX_MAX_MEMBER_BYTES` through the same budget and caps every stream it decodes; the zstd branch may fall back to the `zstd` crate's streaming decoder for the one frame shape the in-house decoder declines.
- Nothing is written to disk and no state survives the process, apart from the process-wide budget override.

## Verification
- Run: `cargo test --release --locked --workspace`
