# rgx-adapters-threed

## Overview

The 3D / point-cloud / volumetric family of `rgx`. Its premise is on the
crate's own header: **extract structure and names, not geometry payloads**. A
mesh, a point cloud and a volume are not text, and a search over them wants
the names, the counts and the header fields — not the vertices.

The family covers the mesh formats (glTF binary, binary STL, binary PLY,
binary FBX, 3D Studio), the point clouds and volumetric grids (PCD, LAS/LAZ,
VTK legacy, NIfTI, MRC/CCP4), and the scene format (Blender's `.blend`).

The text-based formats — `.obj`, `.mtl`, `.off`, `.usda` — are plain text
and need **no adapter**: they fall through to the raw search, which is
`rg`'s own answer. The ASCII forms of the binary formats (ASCII STL, ASCII
PLY, ASCII FBX, ASCII PCD, ASCII VTK) are handled the same way: the adapter
declines or bails and the raw bytes are searched.

The crate is `#![no_std]` + `alloc` and declares no `std` feature. Every
adapter sits behind a Cargo feature named after the format it reads, and the
default build carries all of them.

## Subdirectories & Boundaries

- `src`: [src/EGM.md](./src/EGM.md) — the whole implementation: the
  `adapters()` factory and the eleven readers (`Glb`, `Stl`, `Ply`, `Fbx`,
  `Pcd`, `Las`, `Vtk`, `Blend`, `Threeds`, `Nifti`, `Mrc`), including the
  in-house LASzip arithmetic decoder and the chunk-table reader. Public
  symbols: `pub fn adapters()`, `pub struct Glb`, `pub struct Stl`, `pub
  struct Ply`, `pub struct Fbx`, `pub struct Pcd`, `pub struct Las`, `pub
  struct Vtk`, `pub struct Blend`, `pub struct Threeds`, `pub struct Nifti`,
  `pub struct Mrc`, and `impl Adapter` for each reader.
