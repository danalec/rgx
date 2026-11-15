# RAR fixtures

Two provenances, and they are not the same:

* The `rar5-*.rar` files were produced here by **RARLAB's own `Rar.exe` 7.20**
  (the copy installed at `C:\Program Files\WinRAR`) from the two text files
  named in `*.expected`.
* The `rar4-*.rar` files came out of a RAR 2.9/3.x corpus that was already on
  this machine. **Their writer is not known** — see the caveat at the bottom.

Every file was cross-checked against **RARLAB `UnRAR.exe` 7.20** regardless:
the bytes the in-process codec returns are byte-identical to what `UnRAR x`
writes, and the CRC-32 UnRAR reports for each member is the CRC the codec
computed. `.expected` files are UnRAR's output, kept so the tests compare
bytes rather than trusting the archive's own CRC field.

| Fixture | Format | What it holds down |
|---|---|---|
| `rar4-store.rar` | RAR 1.5, `METHOD=0x30`, `UNP_VER=20` | RAR4 **stored** members. The old rgx copy could not extract these at all: its RAR4 path gated the data offset on `LHD` bit `0x8000`, a bit that does not exist in RAR4, so every RAR4 entry came back `None` and raised "entry has no data area". |
| `rar4-lz29.rar` | RAR 2.9, `METHOD=0x33`, `UNP_VER=29` | The RAR 2.9/3.x LZ77+Huffman method — `unpack3.rs`. Previously `Error::Unsupported("RAR4 compressed payload ... needs the rar3 decoder")`. |
| `rar4-lz29-e8e9.rar` | RAR 2.9, `METHOD=0x33`, E8/E8E9 VM filter | `unpack3`'s standard-filter machinery on a 491 KB payload. |
| `rar5-store.rar` | RAR 5, `-ma5 -m0` | RAR5 store, from RARLAB rather than from this crate's own `ArchiveBuilder`. |
| `rar5-lz.rar` | RAR 5, `-ma5 -m3` | RAR5 LZ77+Huffman on a multi-block payload. |
| `rar5-solid.rar` | RAR 5, `-ma5 -m3 -s` | A **solid** group of three members. Previously `Error::Unsupported("solid stream (dictionary shared between members)")`; the second and third members now decode against the first member's dictionary. |

The multivolume set lives in `crates/rar-codec/testdata/rar/` instead: it is
only reachable through `Archive::open_multi`, which takes several volumes at
once, and the adapter contract is one byte slice per file.

## What is deliberately absent

**No PPMd fixture.** `ppmd7.rs` is the point of this sync, and nothing here
exercises it. RAR 3.x only emits a PPMd var-H block when the data is
favourable at a high enough `-m` level, and **RARLAB dropped RAR 4.x and RAR
2.9 archive *creation* in RAR 5.9** — `Rar.exe` 7.20 has no switch that
writes them (`rar -?` lists no `-ma4`), and no other RAR writer is available
on this machine. Every RAR 2.9 archive found here was probed with a counter
on `Ppmd7::new`, and every one reported zero PPMd blocks.

So "rgx decodes RAR PPMd" is a port that has never run against a real
stream — here or upstream: `upstream/rar-codec/src/ppmd7.rs` ships zero tests too.
Treat it as untested until someone supplies a RAR 2.9 archive carrying a PPMd
block, and re-pin the `ppmd7.rs` manifest row when they do.

## Caveat on the `rar4-*` fixtures

Their writer is unknown, so they carry no provenance claim beyond "real RAR
2.9/3.x bitstreams, verified against the reference decoder". The member
payload is synthetic log text, and UnRAR agrees byte-for-byte on all three.
If a maintainer wants fixtures with a documented lineage, these three are the
ones to replace — the test code does not need to change, only the bytes and
this table.
