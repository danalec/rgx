# rgx-adapters-inspect/src

## Overview

The implementation of the forensic-triage family. `lib.rs` holds the crate's
`no_std` shell, the `adapters()` factory, the generic `Inspect` triage
adapter, the `magic_classify` classifier and the two adapters that live in
`lib.rs` itself (`Wasm`, `Lnk`). Every other format has its own module.

The crate's own header states the method: identification by magic bytes and
minimal header; a full-blob scan for embedded signatures (ZIP, PNG, PDF,
GZIP, ELF, SQLite, …) with the cheap-to-slice formats (ZIP via EOCD, GZIP,
PDF via `%%EOF`) carved into `Outcome::Members` so a ZIP buried in a `.bin`
is searched through by the whole adapter chain; ASCII and UTF-16LE/BE string
extraction; and Shannon entropy per 4 KiB window to flag compressed,
encrypted or packed regions. Everything is heuristic and bail-safe.

## Interface

- `pub fn adapters() -> Vec<Box<dyn Adapter>>` — the factory the binary's
  registry consumes. **Order is the contract**: the registry resolves by
  extension and the first matching available adapter wins, so a later entry
  runs only when every earlier one for that extension has `bail!`ed.
- `pub struct Inspect` — the generic triage adapter (feature `inspect`).
  `impl Adapter`: `name() == "inspect"`, `extensions()` = `["bin", "dat",
  "raw", "img", "rom", "blob", "payload", "scratch", "fw", "objbin", "exe",
  "dll", "sys", "drv", "efi", "mui", "ocx", "cpl", "apk", "msi"]`.
- `pub fn magic_classify(data: &[u8]) -> Option<&'static str>` — maps a
  magic-byte prefix to the short type label the `-t`/`-T` filter
  understands (`pdf`, `zip`, `elf`, `sqlite`, `png`, `jpeg`, `gif`, `bmp`,
  `gzip`, `bzip2`, `xz`, `zstd`, `7z`, `rar`, `wasm`, `class`, `dex`,
  `blender`, `hdf5`, `webp`, `tiff`, `cfb`, `macho`, `psd`, `ogg`,
  `mpeg-ts`, `flac`, `mp3`, `midi`, `ico`, `wmf`).
- `pub struct Wasm` (feature `wasm`) — WebAssembly module: validates the
  magic and version, walks the section sequence with a LEB128 reader and
  indexes import module/name pairs, export names, and custom-section names.
  No function bodies are decoded.
- `pub struct Lnk` (feature `lnk`) — Windows shell-link shortcut.
- Re-exported adapter structs, each with its own `impl Adapter`:
  - `BamAlign`, `Sam`, `BcfVariants`, `CramAlign` — `bioinformatics`
    (features `bam`, `sam`, `bcf`, `cram`).
  - `Dwg`, `ParasolidXt`, `AcisSab`, `Rvt`, `Dgn` — `cad` (features `dwg`,
    `parasolid`, `acis-sab`, `rvt`, `dgn`).
  - `C4` (`c4`), `Cals` (`cals`), `Cgm` (`cgm`), `Dxf` (`dxf`),
    `Iges` (`iges`), `Plt` (`plt`), `AcisSat` (`acis-sat`), `Step` (`step`),
    `Stl` (`stl`) — the per-format CAD modules.
  - `Compound` (`compound`) — OLE2 compound files (MS-CFB).
  - `PeResources`, `MachOStrings`, `ElfProvenance`, `DexStrings`,
    `WasmMeta` — `executables` (features `pe`, `macho`, `elf`, `dex`,
    `wasm-meta`).
  - `Firebird` (`firebird`) — Firebird/InterBase page files.
  - `Fasta`, `Fastq`, `Vcf`, `Gff`, `Pdb`, `MmCif` — `flatfiles` (features
    `fasta`, `fastq`, `vcf`, `gff`, `pdb`, `mmcif`).
  - `IsoBmff` (`isobmff`) — HEIC, AVIF, and the `moov` metadata of
    MP4/M4A/MOV/3GP.
  - `BinaryPlist` (`bplist`) — binary property lists (`bplist00`).
  - `Tiff` (`tiff`), `Djvu` (`djvu`) — `rasters`.
  - `Grib`, `Bufr`, `Segy`, `Root`, `N5` — `scientific` (features `grib`,
    `bufr`, `segy`, `root`, `n5`).
  - `X509Cert` (`x509`) — X.509 certificate metadata (PEM/DER).
- Crate-internal, not part of the public surface: the CRAM codec modules
  `cram_arith` (`Model`, `RangeCoder`, `Reader`, flag constants), `cram_fqz`,
  `cram_rans`, `cram_rans16` and `cram_tokeniser` (token-type constants
  `TYPE`..`END`), and `firebird::looks_like_firebird`.

## Invariants

- The crate is `#![no_std]` + `alloc`. No adapter touches the filesystem, the
  clock, threads or `std::env`; every adapter is a pure function over
  `&[u8]`.
- Every adapter sits behind a Cargo feature named after the format it reads,
  so a binary that names the formats it needs carries only those; the default
  build keeps all of them.
- **`Reach` is part of the contract.** Binary formats declare
  `Reach::Reveal`: ripgrep cannot read them, so the adapter's answer *is*
  the answer, and every byte it surfaces is a byte ripgrep could never
  reach. Text formats declare `Reach::Render`: ripgrep already reads them,
  so under the default `Policy::Source` the file's own bytes are the answer
  and the renderer is not consulted at all, while under
  `RGX_ADAPTER_VIEW=render` the rendering is what gets searched. The text
  formats are DXF, IGES, PLT, ACIS `.sat`, STEP/IFC, ASCII STL, and the six
  flat files (FASTA, FASTQ, VCF, GFF/GTF, PDB, mmCIF).
- `X509Cert` decides its reach **from the bytes**: `reach_needs_bytes()` is
  true and `reach_for` returns `Reach::Reveal` when the input holds a NUL
  byte (DER) and `Reach::Render` otherwise (PEM).
- `Inspect` bails on plain text ("plain text, raw search is better") so the
  raw path keeps ripgrep's binary semantics, and returns
  `Outcome::Bail("no embedded structures, raw binary semantics")` when
  nothing was found — but only for the nine generic extensions (`bin`,
  `dat`, `raw`, `img`, `rom`, `blob`, `payload`, `scratch`, `fw`); the
  named ones (`objbin`, `exe`, `dll`, `sys`, `drv`, `efi`, `mui`, `ocx`,
  `cpl`, `apk`, `msi`) get the structural report instead. If it did find
  something it still returns a structural report rather than silence.
- `Inspect` is bounded: at most `MAX_FINDINGS` (64) findings, at most
  `MAX_STRINGS_BYTES` (64 KiB) of extracted strings, a minimum string run of
  `STR_MIN_RUN` (5) bytes, entropy triage only for blobs of at least
  `ENTROPY_MIN_SIZE` (16 KiB), and a window at or above `ENTROPY_HOT` (7.5)
  is flagged compressed/encrypted/packed. The carve pass has a total budget
  of its own: `CARVE_TOTAL_MAX` (16 MiB) caps every carved byte the pass may
  hold live at once.
- `Inspect` deliberately does **not** claim `o`: object files reach the
  walker by the thousand from the `ar` adapter, so they fall through to the
  raw passthrough. `objbin` stays claimed because no archiver produces it.
- A file that is not the format is **declined** (magic/version check), never
  answered — the decline is silent and the chain continues.
- `PeResources` precedes `Inspect` in `adapters()`, because `Inspect` claims
  `exe`/`dll`/`sys`/`drv`/`efi`/`mui`/`ocx`/`cpl` and its generic report
  carries no version strings, and a carved `.rsrc` blob cannot yield its
  leaves at all. `WasmMeta` follows `Wasm`, which bails when it finds no
  readable sections.
- `.stl` is claimed twice on purpose: the `threed` crate answers the binary
  form (which ripgrep cannot read) and this crate the ASCII form (which
  ripgrep reads perfectly). A `bail!` does not end the chain, so the ASCII
  file reaches the reader that can render it.
- The `.plt` adapter declines a file whose stream is not a run of plotter
  commands, so a gnuplot script (same extension) falls through to the raw
  search and is found there in its own words.
- The `.sam` adapter claims only the compressed form: a plain-text SAM is
  declined, and a BGZF one is inflated because ripgrep cannot see its
  records at all.
- The ASCII/binary STL question is decided by structure, not by extension or
  by the first word: a file is ASCII when it parses as the keyword grammar,
  and binary when its length is exactly `84 + 50 * count` for the count at
  offset 80. A file that is neither is declined.
- Nothing recurses: embedded payloads come back as `Outcome::Members` and
  the pipeline walks them through the whole adapter chain.

## Side Effects

- None. The crate allocates (through `alloc`), reads nothing from disk,
  spawns no process, opens no socket, takes no lock and consults neither the
  clock nor the environment.

## Verification

- Run: `cargo test --release --locked --workspace`
