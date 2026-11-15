# rgx-adapters-threed/src

## Overview

The implementation of the 3D / point-cloud / volumetric family. Everything
is in `lib.rs`: the crate's `no_std` shell, the `adapters()` factory and
the eleven readers.

The premise is the crate's own header: **extract structure and names, not
geometry payloads**. A mesh, a point cloud and a volume are not text, and a
search over them wants the names, the counts and the header fields — not the
vertices. The readers therefore stop at the header and the directory
structure, and where a format carries a real index (the glTF JSON chunk,
the FBX node tree, the Blender block table) they walk it.

## Interface

- `pub fn adapters() -> Vec<Box<dyn Adapter>>` — the factory the binary's
  registry consumes, in feature order: `Glb`, `Stl`, `Ply`, `Fbx`, `Pcd`,
  `Las`, `Vtk`, `Blend`, `Threeds`, `Nifti`, `Mrc`.
- `pub struct Glb` (feature `glb`) — glTF binary container. `impl Adapter`:
  `name() == "glb"`, `extensions() == &["glb"]`. The answer is the JSON
  chunk summarized: the counts plus every name field.
- `pub struct Stl` (feature `stl`) — `impl Adapter`: `name() == "stl"`,
  `extensions() == &["stl"]`.
- `pub struct Ply` (feature `ply`) — `impl Adapter`: `name() == "ply"`,
  `extensions() == &["ply"]`.
- `pub struct Fbx` (feature `fbx`) — binary FBX. `impl Adapter`:
  `name() == "fbx"`, `extensions() == &["fbx"]`, magic
  `Kaydara FBX Binary  \0\x1a\0`.
- `pub struct Pcd` (feature `pcd`) — Point Cloud Data. `impl Adapter`:
  `name() == "pcd"`, `extensions() == &["pcd"]`.
- `pub struct Las` (feature `las`) — LAS / LASzip point clouds. `impl
  Adapter`: `name() == "las"`, `extensions() == &["las", "laz"]`, magic
  `LASF`.
- `pub struct Vtk` (feature `vtk`) — legacy VTK. `impl Adapter`:
  `name() == "vtk"`, `extensions() == &["vtk"]`.
- `pub struct Blend` (feature `blend`) — Blender scene file. `impl Adapter`:
  `name() == "blend"`, `extensions() == &["blend"]`, magic `BLENDER`.
- `pub struct Threeds` (feature `threeds`) — 3D Studio `.3ds`. `impl
  Adapter`: `name() == "3ds"`, `extensions() == &["3ds", "max3ds"]`.
- `pub struct Nifti` (feature `nifti`) — NIfTI-1 volume. `impl Adapter`:
  `name() == "nifti"`, `extensions() == &["nii"]`.
- `pub struct Mrc` (feature `mrc`) — MRC / CCP4 volume. `impl Adapter`:
  `name() == "mrc"`, `extensions() == &["mrc", "ccp4", "map"]`.
- Crate-internal helpers: `rd_u32`, `rd_f64`, `rd_i32`, `rd_f32`,
  `find_subslice`, and the LASzip machinery — the arithmetic coder
  (`Arith`, `ArithModel`, `IntComp`), the point decoders and the chunk
  table reader.

## Invariants

- The crate is `#![no_std]` + `alloc`: nothing here touches the filesystem,
  the clock, the environment, a socket or a process.
- Every adapter sits behind a Cargo feature named after the format it
  reads; the default build carries all of them.
- **Text-based formats need no adapter**: `.obj`, `.mtl`, `.off` and `.usda`
  are plain text and fall through to the raw search, which is `rg`'s own
  answer.
- The ASCII form of a binary format is handed back the same way: the ASCII
  STL and the ASCII PLY **bail** ("ascii stl is plain text", "ascii ply is
  plain text") and the ASCII FBX bails to a plain-text search; so do the ASCII
  PCD ("ascii pcd is plain text") and the ASCII VTK ("ascii vtk is plain
  text"), so the raw bytes are searched rather than a lossy rendering of them.
- A file that is not the format is declined (magic check) rather than
  answered, so the raw bytes stay searchable.
- Geometry payloads are never extracted: the STL reader reports the
  triangle count and the 80-byte header, the PLY reader reports the header
  lines (the element and property structure), the PCD reader reports the
  header, the FBX reader reports the node names and the string properties,
  the glTF reader reports the JSON chunk's counts and name fields, and the
  volumetric readers report their header fields and dimensions.
- The LAS reader reports the header, the point count, the bounds and the
  per-point report, and it **refuses what it cannot decode faithfully**:
  the LAS 1.4 native compressor (LASzip item versions 3 and 4 — the
  `POINT14` and `RGBNIR14` items) and the LASzip 1.x item compressors (item
  version 1). They are different item sets behind different chunk tables,
  and one decoder stretched over all of them is right about none of them.
  A refused file keeps its header numbers and says why the points are
  missing.
- **A LASzip time sequence is chosen by a symbol, and the reference's loop
  is bounded by a decoder that throws.** The GPS time item lives in one of
  four sequences and the `multi` symbol says which; a value of three or
  more means "the time continues in another sequence", so the reference's
  reader loops and switches. What bounds the reference's loop is its
  arithmetic decoder: it throws when the chunk's bytes run out. A decoder
  that does not throw can decode a symbol without reading a byte at all, and
  then the loop is bounded by nothing — a reader that followed one file's
  sequence switch 367 million times and took nearly three seconds, which is
  what the fuzz kit's watchdog calls a hang. The loop is bounded here
  (`GPS_TIME_MAX_SWITCHES = 64`; a point's time needs one), and a file that
  needs more is refused with the reason.
- Two more bounds belong to the LAS reader, and both are the file's own:
  the chunk table cannot declare more chunks than the file has points or
  bytes (a chunk holds at least one point and occupies at least one byte,
  so the point count and the file's own length bound the chunk count), and
  a chunk whose compressed bytes run out **stops the point loop where it
  runs out** rather than after the hundred thousand points the ceiling
  allows. A dead stream still yields a point per iteration and the point
  count comes from the file's own header, so a file that claims a hundred
  thousand points would cost seconds to refuse, on bytes that carry
  nothing.
- The LAS output is bounded: at most `MAX_LAS_POINTS` (100 000) points
  reported and at most `MAX_LAS_OUT` (16 MiB) of rendered report.
- The MRC header is 1024 bytes and the file is required to be at least that
  long; the NIfTI reader requires at least 348 bytes and a `sizeof_hdr` of
  348 or 540 in either byte order. The 4-byte magic that follows is
  copied and printed verbatim, never validated, and a NIfTI-2 file
  (`sizeof_hdr` 540, magic `n+2`) is answered as version 2.
- The Blender reader reads the block table, so it reports the file's own
  block names rather than the file's contents.
- The `.blend` reader is not a scene reader: it does not reconstruct
  objects, meshes or materials.

## Side Effects

- None. Every adapter is a pure function over `&[u8]`: nothing is read
  from disk, no process is spawned, no socket is opened, no clock or
  environment variable is consulted, and no lock is taken. The crate
  allocates through `alloc`.

## Verification

- Run: `cargo test --release --locked --workspace`
