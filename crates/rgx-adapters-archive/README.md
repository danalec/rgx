# rgx-adapters-archive

Archive and single-file decompression adapters, all in-process. Members
come back as `Outcome::Members` and `rgx_core::process` recurses them, so
a `.docx` inside a `.zip` inside a `.tar.gz` is still a `.docx`. The
adapters never recurse themselves. The decompressor re-matches the
expanded stream by extension, so `outer.tar.gz` keeps unpacking into
`outer.tar`.

## What it claims

Registration order is the chain order, and the first matching available
adapter wins.

| adapter | extensions |
|---|---|
| `zip` | zip, zipx, jar, xpi, kra, snagx, 3mf, usdz, cbz, apk, aar, war, ear, ipa, whl, egg, kmz, sketch, pages, numbers, key, pk3, pk4, crx, msix, appx, snb, wsb, gem, nupkg, crate, e57, uof, uot, uos, uop |
| `7z` | 7z, cb7 |
| `tar` | tar, pax |
| `cpio` | cpio |
| `ar` | a, ar, deb |
| `git-pack` | pack |
| `git-bundle` | bundle |
| `decompress` | gz, tgz, bz2, tbz2, xz, txz, zst, zstd, tzst, lz4, br, z, taz, tbz, tpz, tz2, tb2, als, bz, bzip2, lzma |
| `rar` | rar |
| `svn-dump` | dump |
| `pgdump` | dump, pgdump |
| `borg` | — |
| `iso9660` | iso |
| `squashfs` | squashfs, sqsh, snap |
| `wim` | wim |
| `vhd` | vhd |
| `vhdx` | vhdx |
| `qcow2` | qcow2, qcow |
| `vmdk` | vmdk |
| `vdi` | vdi |
| `erofs` | erofs |
| `applefs` | apfs, hfs, hfsplus, dmg |
| `img` | img |

The image adapters come last on purpose: each declines on a magic it does
not own, so `.img` reaches the raw-dump dispatch only after the real
archives have declined it. `iso9660` and `squashfs` are the two that hand
back real members; the block-container ones (VHD, VHDX, QCOW2, VMDK, VDI,
WIM, EROFS, APFS, HFS+) answer with the container's own geometry, UUID,
backing chain and — where the filesystem has a readable catalogue — the
file names, never the payload.

The iWork packages `.pages`, `.numbers` and `.key` are claimed by `zip`
because they are zip containers; only their members are searchable, since
the document itself lives in a compressed IWA archive.

`borg` is the one row with no extension at all — the em dash is not a
placeholder, it is the claim: a borg segment is `data/0/2`, and the only
thing that says what it is lives in its first eight bytes. It goes after
the adapters that claim by name because the name is the stronger claim and
the magic only speaks when the name is silent. `svn-dump` and `pgdump` both
claim `.dump` and are told apart by their first bytes: a Subversion dump
starts with `SVN-fs-dump-format-version:` and a PostgreSQL custom archive
with `PGDMP`.

Every adapter declares `Reach::Reveal`: these are containers and
compressed streams, not text that ripgrep already reads. They do not
declare `available()`, so they are always available — there is no external
binary involved.

## How it works

The zip container is in-house: store, deflate, bzip2 and lzma entries,
zip64, CRC verified per entry. Methods that are not implemented (deflate64,
zstd, ppmd, xz) surface as a skipped member rather than as raw compressed
bytes. The tar reader is in-house too, and `cpio` checks for the
`070701`/`070702` newc magic before parsing.

`rar` opens strictly first, which verifies the RAR5 header CRCs and
catches corruption, and falls back to lenient parsing so a damaged archive
still lists. `sevenz` is vendored from the 7-Zip project and kept
byte-identical for easy re-sync, which is why it also carries the encoder
side that rgx never calls.

`pgdump` reads PostgreSQL's custom dump archive, the file `pg_dump -Fc`
writes: a common header, a table of contents, and one compressed block per
table. Its integers are sign-magnitude little-endian, not two's complement;
its "gzip" is zlib framing (RFC 1950) and not gzip (RFC 1952); and its
fields are gated by an archive version that grew over fifteen releases. The
corpus is what `pg_dump` wrote — one archive per compression algorithm it
offers — and the expected rows are the ones `pg_restore -a` prints, taken
from that output rather than retyped. A file that starts with the same five
bytes but names another archive format, as the directory format's `toc.dat`
does, is declined by name.

## Budget

`budget::budget()` is the producer-side work cap that every producer in
this crate reads through `MemberSink`: how many members one archive may
expand, and how many bytes in total. `Adapter::extract` never sees a
`Ctx`, so the cap has to live where the members are built. Defaults come
from `Ctx::default()`, `RGX_MAX_MEMBERS` and `RGX_MAX_MEMBER_BYTES`
override them, and `-M` wins over both. There is also a per-member
ceiling on entries *examined*, so a container whose entries all fail to
decode does not rescan its central directory once per entry.

## Feature flags

- `std` (default) — pulls in `rar-codec/std`; the `decompress` feature is
  the one that pulls in `zstd`.
- `isa-huffman` — routes the vendored 7z deflate encoder through a
  wrapper over this crate's own encoder. rgx searches inside compressed
  archives; it does not write them.

## Licence

Apache-2.0 only. Every file in the crate carries the SPDX header saying so,
the `src/sevenz/` tree included — that tree was written from the LZMA SDK,
which its publisher placed in the public domain. The layout of `src/borg.rs`
and `src/pgdump.rs` was learned from third-party implementations, which are
the descriptions of those formats that exist; the code in both files is the
crate's own. See the repository's [COPYING](https://github.com/danalec/rgx/blob/main/COPYING) and
[NOTICE](https://github.com/danalec/rgx/blob/main/NOTICE).
