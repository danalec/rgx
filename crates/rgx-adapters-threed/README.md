# rgx-adapters-threed

3D-model adapters. They extract structure and names — node hierarchies,
material and object names, header fields — never geometry payloads. The
text-based formats (`obj`, `mtl`, `off`, `usda`) are plain text and need
no adapter at all: they fall through to raw search.

## What it claims

| adapter | extensions |
|---|---|
| `glb` | glb |
| `stl` | stl |
| `ply` | ply |
| `fbx` | fbx |
| `pcd` | pcd |
| `las` | las, laz |
| `vtk` | vtk |
| `blend` | blend |
| `3ds` | 3ds, max3ds |
| `nifti` | nii |
| `mrc` | mrc, ccp4, map |

Every adapter declares `Reach::Reveal`: a mesh is not text ripgrep reads
as it stands.

## How it works

Each format is checked by magic or by a header field before it is parsed,
and an adapter that does not recognise the file declines with `bail!` so
the raw searcher keeps the file's own bytes.

The GLB arm reads the JSON chunk and summarizes it — counts and every
name field — after checking that the declared chunk length fits both the
declared total length and the actual file, because fuzzed headers lie
about both. The `las` arm reads the point records of a point cloud, and
it decodes a `.laz` with the LASzip decompressor: the arithmetic coder
and the per-field compressors of the LASzip reference implementation, so
a `.laz` and the `.las` it was compressed from print the same lines for
the same cloud. The LAS 1.4 native compressor and the LASzip 1.x item
compressors are a different set of compressors and are refused with the
reason in the report, next to the header numbers that were read. The
`pcd`, `nifti` and `mrc` arms report the header and dimension fields
rather than the samples. The `blend` and `3ds` arms index their object
and material names.

## Test data

`testdata/` holds the PDAL test clouds, each in both forms where PDAL
ships both: `basefile.las` with `laszip-generated.laz` (and its padded
and libLAS-written twins), `simple.las` with `simple.laz`, the LAS 1.4
cloud `las_with_several_extra_byte_bloc.laz`, and the LASzip 1.x cloud
`simple-laszip-compressor-version-1.2r0.laz`. The `.las` twin is the
oracle: the two reports must be equal, byte for byte.
`laszip_spec_1.4.pdf` is the LAZ specification the decompressor
follows.

## Licence

Apache-2.0 only. See [LICENSE-APACHE](https://github.com/danalec/rgx/blob/main/crates/rgx-adapters-threed/LICENSE-APACHE), and the
repository's [COPYING](https://github.com/danalec/rgx/blob/main/COPYING) for what the licence covers and what
it does not.