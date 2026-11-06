# Fixtures: the Zarr arrays

These are **real arrays**: a `.zarray` manifest in JSON and the chunks
beside it, each compressed with the codec the manifest names. Most of them
are written by `scripts/gen_zarr_fixtures.py`, which uses the standard
library's codecs — no numpy, no `zarr` package — and the chunk layout is
the specification's, so the bytes are what a Zarr reader has to cope with.

The blosc array is written the same way: the frame of c-blosc and the LZ4
block inside it are written by the script, because the standard library has
neither. The frames were read back, before they were committed, by c-blosc
itself and by `numcodecs` — the two implementations that write them — so the
fixture is a frame the world agrees on and not one this repository invented.

The **blosc array of the zstd codec** is written the same way, and its
frames carry the codec code the **frame** names, which is not c-blosc's
library code: the frame's code 2 is snappy where the library's code 2 is
lz4hc, and the frame's code 4 is zstd where the library's code 5 is. A
reader that uses the library's codes hands the frame to the wrong decoder
and calls the data corrupt.

The v3 array is read back by zarr-python before it is committed, for the
same reason: an array in a layout only this repository writes proves
nothing about the layout.

The **sharded** array and the **rectilinear** array are written by
`zarr-python` itself, because the sharding codec and the rectilinear chunk
grid are zarr-python's own: a shard this repository wrote itself would
prove nothing about the shard, and a rectilinear grid likewise. The script
calls zarr-python with the two calls below, and reads the arrays back with
it before they are committed:

```python
zarr.create_array(shape=(4, 6), chunks=(2, 3),
                  shards={"shape": (4, 6), "index_location": "end"},
                  dtype="float64", zarr_format=3, compressors=None)

with zarr.config.set({"array.rectilinear_chunks": True}):
    zarr.create_array(shape=(6, 5), chunks=[[2, 1, 3], [2, 3]],
                      dtype="int32", zarr_format=3)
```

**Every array is read back after it is written.** The chunks are
decompressed and the values compared against the ones that went in. A
fixture that does not read back is a fixture that proves nothing, and the
point of these files is to be the reference the Rust reader is checked
against.

| array | what it is | what it is there for |
|---|---|---|
| `f64-zlib/` | 2-D doubles, a 4×6 shape in 2×3 chunks, zlib | the plain case, and the one every other array is checked against |
| `i16-raw/` | 1-D `int16`, uncompressed, a shape of five in chunks of two | the short last chunk, whose missing half is the fill value |
| `u1-gzip/` | 1-D bytes, gzip | a codec, and a dtype with no sign |
| `i4-delta/` | 1-D `int32` with the `delta` filter | the filter's running sum |
| `f32-bz2/` | 1-D `float32`, bzip2 | the last codec |
| `u8-slash/` | 2-D `uint64`, the chunks in sub-directories | the other dimension separator |
| `f64-blosc/` | 2-D doubles, a 4×4 shape in 2×2 chunks, blosc with LZ4 and the byte shuffle | the codec `zarr-python` asks for by default |
| `group-consolidated/` | a v2 group whose two arrays have their manifests in one `.zmetadata`, and whose chunks are in each array's own directory | the consolidated metadata: one file names every array of the group, and `zarr-python` reads the group back the same way |
| `f64-transpose-v3/` | the `f64-zlib` array in the **v3 layout**, every chunk stored with its axes permuted by the `transpose` codec | the transpose codec: the values come out with the array's own axes, and `zarr-python` reads them back the same way |
| `f64-zstd-v3/` | the same array in the **v3 layout**: a `zarr.json`, the chunks under `c/`, and a pipeline of codecs | the layout `zarr-python` writes by default |
| `f64-sharding-v3/` | the same array in the **v3 layout** with the `sharding_indexed` codec: one shard of 4×6 holds four inner chunks of 2×3 and the index that says where each of them is | the sharding codec: the order of the chunks inside a shard is not fixed, so the index is the only way to find them, and the index carries a `crc32c` checksum |
| `i4-rectilinear-v3/` | 2-D `int32` in the **v3 layout** with the `rectilinear` chunk grid: the first axis is cut into edges of 2, 1 and 3, the second into edges of 2 and 3 | the rectilinear chunk grid: the chunks are not all the same shape, and the edges are what the grid is |
| `f64-blosc-zstd-v3/` | the `f64-blosc` array in the **v3 layout**, its chunks in blosc frames of the **zstd** codec | the blosc frame with a codec other than LZ4: the frame's codes are the frame's own, and the code 4 is zstd |

The files are kept byte for byte: the directory is `-text` in
`.gitattributes`, so a checkout cannot rewrite a byte of them. The
manifests are written with LF, which is what the script writes and what
the array stays.
