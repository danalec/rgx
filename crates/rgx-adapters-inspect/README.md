# rgx-adapters-inspect

Forensic-style binary triage, in-process. The adapter never trusts the
extension, never spawns a subprocess and never ships a heavyweight parser:
it identifies a blob, carves what it recognises, and reports what is left.
Everything it emits is heuristic, and it declines with `Outcome::Bail` on
plain text so the raw path keeps ripgrep's binary semantics.

## What it claims

| adapter | extensions |
|---|---|
| `pe-resources` | rsrc |
| `inspect` | bin, dat, raw, img, rom, blob, payload, scratch, fw, objbin, exe, dll, sys, drv, efi, mui, ocx, cpl, apk, msi |
| `macho-strings` | macho, dylib |
| `elf-provenance` | so, elf, ko |
| `dex-strings` | dex, odex |
| `wasm` | wasm |
| `wasm-meta` | wasm, wat |
| `lnk` | lnk |
| `x509` | pem, crt, cer, der, cert |
| `ole2-compound` | one, nsf, hwp, mpp, pub, msp, vsdm, cdr, xltm, sxw, sxc, sxi, sxd |
| `bplist` | icloud, bplist, pref, plist, mobileconfig |
| `tiff-pages` | tif, tiff, nef, dng, arw, cr2, pef, srw, rw2 |
| `djvu` | djvu, djv |
| `isobmff` | heic, heif, avif, mp4, m4a, m4v, mov, 3gp |
| `dwg` | dwg |
| `parasolid-xt` | x_t, x_b, xt |
| `acis-sab` | sab |
| `rvt` | rvt |
| `dgn` | dgn |
| `dxf` | dxf |
| `step` | stp, step, ifc |
| `iges` | igs, iges |
| `acis-sat` | sat |
| `stl` | stl |
| `cgm` | cgm |
| `cals` | cal, ct1, ct2 |
| `edmics-c4` | c4 |
| `plt` | plt, hpgl, hgl |
| `grib` | grb, grb1, grb2, grib, grib1, grib2 |
| `bufr` | bufr, bufr4 |
| `segy` | sgy, seg, segy |
| `root` | root |
| `n5` | n5, n5z |
| `firebird` | fdb, gdb |
| `bam` | bam |
| `bcf` | bcf |
| `cram` | cram |
| `sam` | sam |
| `fasta` | fasta, fna, faa, fas, frn, ffn |
| `fastq` | fastq, fq |
| `vcf` | vcf |
| `gff` | gff, gff2, gff3, gtf |
| `pdb` | pdb, ent |
| `mmcif` | cif, mmcif |

The order is the contract: the registry resolves by extension and the first
matching available adapter wins, so a later entry only ever runs when every
earlier one for that extension has `bail!`ed. Two entries are ordered
against `Inspect` on purpose — `pe-resources` precedes it, and `wasm-meta`
follows `wasm`.

`o` is deliberately not claimed. An object file reaches the walker by the
thousand from the `ar` adapter — every `.a` static library yields one
member per object — and at that volume the raw passthrough is the right
answer. `objbin` stays; no archiver produces that extension, so it cannot
arrive the same way.

`x509` is the one adapter here whose reach depends on the bytes rather
than the extension. `reach_needs_bytes()` is true, and `reach_for()`
answers `Reach::Reveal` when the file contains a NUL and `Reach::Render`
when it does not: a `.pem` is base64 text ripgrep already reads, while a
`.der` is binary. The test is the searcher's own NUL heuristic.

## How it works

1. Identification — magic bytes plus a minimal header (PE machine and
   class, ELF class and type, image dimensions).
2. Embedded-structure scan — the whole blob is scanned for known
   signatures. Formats cheap to slice (ZIP via EOCD, GZIP, PDF via
   `%%EOF`) carve into `Outcome::Members`, so a ZIP buried in a `.bin` is
   searched through by the full adapter chain.
3. Strings — ASCII and UTF-16LE/BE runs.
4. Entropy triage — Shannon entropy per 4 KiB window flags compressed or
   encrypted regions.

The pass is budgeted: findings are capped at 64, a string run has a
minimum length and the string section a total byte cap, and entropy triage
only runs on blobs of at least 16 KiB. `wasm` walks the section sequence
with a LEB128 reader and indexes import, export and custom-section names
rather than decoding function bodies — the names are the greppable
payload. `lnk` decodes the header, string sections and `LinkInfo`, so
jump-list and Recent-Items binaries expose their target, arguments and
working directory.

## Licence

Apache-2.0 only. The layout of `src/cad_sat.rs` was learned from ezdxf,
which is the description of that format that exists; the code in the file is
the crate's own. See [LICENSE-APACHE](https://github.com/danalec/rgx/blob/main/crates/rgx-adapters-inspect/LICENSE-APACHE), and the
repository's [COPYING](https://github.com/danalec/rgx/blob/main/COPYING) for what the licence covers and what
it does not.
