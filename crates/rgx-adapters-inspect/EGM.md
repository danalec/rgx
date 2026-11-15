# rgx-adapters-inspect

## Overview

The forensic-triage family of `rgx`: an always-in-process adapter set that
never trusts a file's extension, never spawns a subprocess and never ships a
heavyweight parser. Its job is to look at bytes and say what they are —
identification by magic bytes and minimal header, a scan for embedded
structures, string extraction, and entropy triage per 4 KiB window to flag
compressed or encrypted regions.

The crate is `#![no_std]` + `alloc`: no adapter touches the filesystem, the
clock, threads or `std::env`, so there is no `std` feature of its own to
declare. It is not part of the `no_std` port, though: the manifest turns
`rgx-core`'s `std` feature on unconditionally, so the dependency graph always
carries `std` and the crate cannot be built for a target that has none. Every
adapter sits behind a Cargo feature named after the format it reads (`pe`,
`elf`, `dwg`, `grib`, `bam`, `cram`, `stl`, `fasta`, …), and the default build
carries all of them.

The family covers the containers whose text is not text: PE/COFF resources,
Mach-O and ELF provenance, DEX strings, wasm sections, Windows shortcuts,
X.509 certificates, OLE2 compound files, binary property lists, multi-page
TIFF and DjVu, ISO base media files, the CAD formats (DWG, Parasolid XT,
ACIS SAB/SAT, Revit, MicroStation DGN, DXF, STEP/IFC, IGES, STL, CGM, CALS,
C4, PLT), the scientific containers (GRIB 1/2, BUFR, SEG-Y, CERN ROOT,
N5/N5Z), Firebird/InterBase page files, and the sequencing containers
(BAM, BCF, CRAM, SAM) together with their flat text counterparts
(FASTA, FASTQ, VCF, GFF/GTF, PDB, mmCIF).

## Subdirectories & Boundaries

- `src`: [src/EGM.md](./src/EGM.md) — the whole implementation: the
  `adapters()` factory, the generic `Inspect` triage adapter, the
  `magic_classify` magic-byte classifier, and the per-format modules
  (`bioinformatics`, `cad*`, `compound`, `executables`, `firebird`,
  `flatfiles`, `isobmff`, `plist`, `rasters`, `scientific`, `x509`) with the
  CRAM 3.0/3.1 codec modules under the `cram` feature. Public symbols:
  `pub fn adapters()`, `pub struct Inspect`, `pub fn magic_classify(&[u8])
  -> Option<&'static str>`, `pub struct Wasm`, `pub struct Lnk`, and the
  re-exported format adapters (`BamAlign`, `Sam`, `BcfVariants`,
  `CramAlign`, `Dwg`, `ParasolidXt`, `AcisSab`, `Rvt`, `Dgn`, `C4`, `Cals`,
  `Cgm`, `Dxf`, `Iges`, `Plt`, `AcisSat`, `Step`, `Stl`, `Compound`,
  `PeResources`, `MachOStrings`, `ElfProvenance`, `DexStrings`,
  `WasmMeta`, `Firebird`, `Fasta`, `Fastq`, `Vcf`, `Gff`, `Pdb`, `MmCif`,
  `IsoBmff`, `BinaryPlist`, `Tiff`, `Djvu`, `Grib`, `Bufr`, `Segy`, `Root`,
  `N5`, `X509Cert`), each with `impl Adapter`.
