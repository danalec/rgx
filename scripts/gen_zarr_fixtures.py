#!/usr/bin/env python3
"""Write the Zarr fixtures, and check that they are what they claim to be.

A Zarr array is a directory: a `.zarray` manifest in JSON and the chunks
beside it, each named by its index and each holding the array's values
compressed with the codec the manifest names. This writes a handful of
them, with no numpy and no zarr package -- the codecs are the standard
library's (`zlib`, `gzip`, `bz2`, `zstd` where the interpreter has it) and
the chunk layout is the specification's.

The blosc codec is the exception: the standard library has neither the
frame of c-blosc nor the LZ4 block inside it, so both are written here.
The frame is a header, a table of block offsets and the blocks, and a
block is the data with the byte shuffle applied -- the bytes of the same
place of each element next to each other -- compressed as one LZ4 block.

Every array is read back after it is written: the chunks are decompressed
and the values compared against the ones that went in. A fixture that does
not read back is a fixture that proves nothing, and the point of these
files is to be the reference the Rust reader is checked against.

Run it from anywhere:

    python scripts/gen_zarr_fixtures.py

It is deterministic: the same bytes come out every time, so a regenerated
tree is a no-op in `git status`.
"""

import bz2
import gzip
import json
import os
import shutil
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "crates", "rgx-adapters-tabular", "testdata", "zarr")

# dtype -> (struct format, itemsize)
DTYPES = {
    "<f8": ("d", 8),
    "<f4": ("f", 4),
    "<i2": ("h", 2),
    "<i4": ("i", 4),
    "|u1": ("B", 1),
    "<u8": ("Q", 8),
}


def write_bytes(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def write_text(path, text):
    write_bytes(path, text.encode("utf-8"))


def manifest_doc(shape, chunks, dtype, compressor=None, fill_value=0, order="C",
                 filters=None, sep=None):
    """The manifest, as the document it is.

    The consolidated metadata of a group holds the manifest of every array
    as one of its documents, so the document is what is written here and
    the file is made of it.
    """
    doc = {
        "zarr_format": 2,
        "shape": list(shape),
        "chunks": list(chunks),
        "dtype": dtype,
        "compressor": compressor,
        "fill_value": fill_value,
        "order": order,
        "filters": filters,
    }
    if sep is not None:
        doc["dimension_separator"] = sep
    return doc


def manifest(shape, chunks, dtype, compressor=None, fill_value=0, order="C",
             filters=None, sep=None):
    """The `.zarray` file, with the keys in the order zarr-python writes them."""
    return json.dumps(manifest_doc(shape, chunks, dtype, compressor, fill_value,
                                   order, filters, sep), indent=4) + "\n"


def product(dims):
    """Every coordinate of a grid, the last dimension counting fastest."""
    if not dims:
        yield ()
        return
    for i in range(dims[0]):
        for tail in product(dims[1:]):
            yield (i,) + tail


def grid(shape, chunks):
    return [-(-s // c) for s, c in zip(shape, chunks)]


def flat_index(coords, shape):
    """The row-major index of a coordinate in an array of this shape."""
    index = 0
    for coord, dim in zip(coords, shape):
        index = index * dim + coord
    return index


def chunk_coords(flat, g):
    """The grid coordinate of the flat'th chunk."""
    coords = []
    rest = flat
    for k in range(len(g) - 1, -1, -1):
        coords.insert(0, rest % g[k])
        rest //= g[k]
    return coords


# The v3 data types, and the struct format of each.
V3DTYPES = {
    "float64": ("d", 8),
    "float32": ("f", 4),
    "int64": ("q", 8),
    "int32": ("i", 4),
    "int16": ("h", 2),
    "uint8": ("B", 1),
    "uint16": ("H", 2),
    "uint32": ("I", 4),
    "uint64": ("Q", 8),
}


def v3_manifest(shape, chunks, dtype, fill=0.0, codecs=None):
    """The `zarr.json` of a v3 array, with the keys zarr-python writes.

    The pipeline is a list of codecs: the array-to-array codecs first (the
    transpose, which permutes the axes of the elements), then the
    array-to-bytes codec (the bytes, which says the byte order), then the
    bytes-to-bytes codecs (the compressions).
    """
    if codecs is None:
        codecs = [
            {"name": "bytes", "configuration": {"endian": "little"}},
            {"name": "zstd", "configuration": {"level": 1, "checksum": False}},
        ]
    doc = {
        "shape": list(shape),
        "data_type": dtype,
        "chunk_grid": {
            "name": "regular",
            "configuration": {"chunk_shape": list(chunks)},
        },
        "chunk_key_encoding": {
            "name": "default",
            "configuration": {"separator": "/"},
        },
        "fill_value": fill,
        "codecs": codecs,
        "attributes": {},
        "zarr_format": 3,
        "node_type": "array",
        "storage_transformers": [],
    }
    return json.dumps(doc, indent=2) + "\n"


def make_v3_array(name, shape, chunks, dtype, values):
    """Write a v3 array, then read it back and check it.

    The chunks live under `c/`, each named by its indices, and each holds
    the bytes of the chunk compressed with zstd -- the pipeline the manifest
    says: the bytes of the elements, and then the compression.
    """
    try:
        from compression import zstd
    except ImportError:
        print("skipping %s: no zstd in this interpreter" % name)
        return
    fmt, size = V3DTYPES[dtype]
    d = os.path.join(ROOT, name)
    write_text(os.path.join(d, "zarr.json"), v3_manifest(shape, chunks, dtype))

    g = grid(shape, chunks)
    nchunks = 1
    for x in g:
        nchunks *= x

    for flat in range(nchunks):
        coords = chunk_coords(flat, g)
        want = block_want(shape, chunks, values, 0, coords)
        raw = b"".join(struct.pack("<" + fmt, v) for v in want)
        blob = zstd.compress(raw, 1)
        write_bytes(os.path.join(d, "c", *["%d" % c for c in coords]), blob)

    # Read it back. The point of the fixture is to be the reference, so the
    # reference has to be checked against the values that went in.
    for flat in range(nchunks):
        coords = chunk_coords(flat, g)
        with open(os.path.join(d, "c", *["%d" % c for c in coords]), "rb") as f:
            raw = zstd.decompress(f.read())
        got = list(struct.unpack("<" + fmt * (len(raw) // size), raw))
        want = block_want(shape, chunks, values, 0, coords)
        if got != want:
            raise SystemExit(
                "%s: chunk %s reads back as %r, not %r" % (name, coords, got, want)
            )
    print("wrote", name)


def make_v3_blosc_array(name, shape, chunks, dtype, values, cname):
    """Write a v3 array whose chunks are blosc frames, then read it back.

    The pipeline is the one `zarr-python` writes for an array with a blosc
    compressor: the bytes of the elements, and then the blosc frame that
    holds them. The frame itself is written here, the way the `f64-blosc`
    array's frames are: the format is c-blosc's, and a frame this script
    wrote itself is the frame a reader has to take apart.

    The codec is the one the frame names, and the frame's codes are the
    frame's own: the code 4 is zstd, where c-blosc's library code 5 is.
    """
    fmt, size = V3DTYPES[dtype]
    d = os.path.join(ROOT, name)
    codec = {"cname": cname, "clevel": 5, "shuffle": 1, "typesize": 8}
    codecs = [
        {"name": "bytes", "configuration": {"endian": "little"}},
        {
            "name": "blosc",
            "configuration": {
                "cname": cname,
                "clevel": 5,
                "shuffle": "shuffle",
                "typesize": 8,
            },
        },
    ]
    write_text(os.path.join(d, "zarr.json"), v3_manifest(shape, chunks, dtype,
                                                         codecs=codecs))

    g = grid(shape, chunks)
    nchunks = 1
    for x in g:
        nchunks *= x

    for flat in range(nchunks):
        coords = chunk_coords(flat, g)
        want = block_want(shape, chunks, values, 0, coords)
        raw = b"".join(struct.pack("<" + fmt, v) for v in want)
        blob = blosc_frame(raw, codec)
        write_bytes(os.path.join(d, "c", *["%d" % c for c in coords]), blob)

    # Read it back. The point of the fixture is to be the reference, so the
    # reference has to be checked against the values that went in.
    for flat in range(nchunks):
        coords = chunk_coords(flat, g)
        with open(os.path.join(d, "c", *["%d" % c for c in coords]), "rb") as f:
            raw = blosc_unframe(f.read(), codec)
        got = list(struct.unpack("<" + fmt * (len(raw) // size), raw))
        want = block_want(shape, chunks, values, 0, coords)
        if got != want:
            raise SystemExit(
                "%s: chunk %s reads back as %r, not %r" % (name, coords, got, want)
            )
    print("wrote", name)


def make_v3_transposed_array(name, shape, chunks, dtype, values, order):
    """Write a v3 array whose chunks are stored with their axes permuted,
    then read it back and check it.

    The transpose codec is an array-to-array codec: it permutes the axes
    of the elements of a chunk, and it sits before the bytes codec in the
    pipeline, because it rearranges the elements and not the bytes. The
    stored chunk therefore holds the elements in the permuted order, and
    the reader has to put them back.

    The pipeline is the one `zarr-python` writes for an array with a
    filter and a compressor: the transpose, the bytes, and the zstd.
    """
    try:
        from compression import zstd
    except ImportError:
        print("skipping %s: no zstd in this interpreter" % name)
        return
    fmt, size = V3DTYPES[dtype]
    d = os.path.join(ROOT, name)
    codecs = [
        {"name": "transpose", "configuration": {"order": list(order)}},
        {"name": "bytes", "configuration": {"endian": "little"}},
        {"name": "zstd", "configuration": {"level": 1, "checksum": False}},
    ]
    write_text(os.path.join(d, "zarr.json"), v3_manifest(shape, chunks, dtype,
                                                         codecs=codecs))

    g = grid(shape, chunks)
    nchunks = 1
    for x in g:
        nchunks *= x

    for flat in range(nchunks):
        coords = chunk_coords(flat, g)
        want = block_want(shape, chunks, values, 0, coords)
        stored = transpose_elements(want, chunks, order)
        raw = b"".join(struct.pack("<" + fmt, v) for v in stored)
        blob = zstd.compress(raw, 1)
        write_bytes(os.path.join(d, "c", *["%d" % c for c in coords]), blob)

    # Read it back. The point of the fixture is to be the reference, so the
    # reference has to be checked against the values that went in.
    for flat in range(nchunks):
        coords = chunk_coords(flat, g)
        with open(os.path.join(d, "c", *["%d" % c for c in coords]), "rb") as f:
            raw = zstd.decompress(f.read())
        got = list(struct.unpack("<" + fmt * (len(raw) // size), raw))
        want = block_want(shape, chunks, values, 0, coords)
        if untranspose_elements(got, chunks, order) != want:
            raise SystemExit(
                "%s: chunk %s reads back as %r, not %r"
                % (name, coords, untranspose_elements(got, chunks, order), want)
            )
    print("wrote", name)


def make_v3_sharded_array(name, shape, chunks, shard_shape, dtype, values,
                          index_location="end"):
    """Write a v3 array whose chunks are shards, then read it back and check it.

    The sharding codec is the array-to-bytes step of the pipeline: a shard
    holds several inner chunks and an index that says where each of them
    is. The index is at the start or the end of the shard, and it holds two
    little-endian 64-bit numbers for every inner chunk -- the offset and
    the length -- with a crc32c checksum at the end of it. The order of
    the chunks inside the shard is not fixed by the specification, so the
    index is the only way to find them.

    The array is written by `zarr-python`: the codec is its own, and a
    shard this script wrote itself would prove nothing about it.
    """
    try:
        import numpy as np
        import zarr
    except ImportError:
        print("skipping %s: no zarr package in this interpreter" % name)
        return
    fmt, _size = V3DTYPES[dtype]
    d = os.path.join(ROOT, name)
    # zarr-python refuses to write over an array that is already there, so
    # the old one goes first: the tree is written from scratch every time,
    # and the bytes come out the same.
    if os.path.isdir(d):
        shutil.rmtree(d)
    z = zarr.create_array(
        shape=shape,
        chunks=chunks,
        shards={"shape": shard_shape, "index_location": index_location},
        dtype=dtype,
        fill_value=0,
        zarr_format=3,
        store=d,
        compressors=None,
    )
    z[:] = np.array(values, dtype=np.dtype(dtype)).reshape(shape)

    # Read it back. The point of the fixture is to be the reference, so the
    # reference has to be checked against the values that went in.
    got = [float(v) for v in np.array(z[:]).flatten()]
    if got != [float(v) for v in values]:
        raise SystemExit("%s: reads back as %r, not %r" % (name, got, values))

    # The shard, and its index: the offset and the length of every inner
    # chunk, and the checksum that says the index is whole.
    with open(os.path.join(d, "c", "0", "0"), "rb") as f:
        shard = f.read()
    per_shard = [s // c for s, c in zip(shard_shape, chunks)]
    nchunks = 1
    for x in per_shard:
        nchunks *= x
    index_size = 16 * nchunks + 4
    index = shard[-index_size:]
    try:
        import google_crc32c
    except ImportError:
        google_crc32c = None
    if google_crc32c is not None:
        stored = struct.unpack("<I", index[-4:])[0]
        if google_crc32c.value(index[:-4]) != stored:
            raise SystemExit("%s: the shard's index does not match its checksum" % name)
    for i in range(nchunks):
        offset, length = struct.unpack("<QQ", index[16 * i:16 * i + 16])
        coords = chunk_coords(i, per_shard)
        want = block_want(shard_shape, chunks, values, 0, coords)
        raw = shard[offset:offset + length]
        got = list(struct.unpack("<" + fmt * len(want), raw))
        if got != want:
            raise SystemExit(
                "%s: the inner chunk %s holds %r, not %r" % (name, coords, got, want)
            )
    print("wrote", name)


def make_v3_rectilinear_array(name, shape, edges, dtype, values):
    """Write a v3 array whose chunks have an edge of their own, then read it
    back and check it.

    The rectilinear chunk grid is specified in `zarr-extensions`: each axis
    of the grid is a list of edges, and the chunks are the blocks those
    edges make. The core specification has no chunk grid but the regular
    one, and `zarr-python` refuses to write this one unless the config says
    it may.

    The array is written by `zarr-python`: the grid is its own, and a grid
    this script wrote itself would prove nothing about it.
    """
    try:
        import numpy as np
        import zarr
    except ImportError:
        print("skipping %s: no zarr package in this interpreter" % name)
        return
    fmt, _size = V3DTYPES[dtype]
    d = os.path.join(ROOT, name)
    # zarr-python refuses to write over an array that is already there, so
    # the old one goes first: the tree is written from scratch every time,
    # and the bytes come out the same.
    if os.path.isdir(d):
        shutil.rmtree(d)
    with zarr.config.set({"array.rectilinear_chunks": True}):
        z = zarr.create_array(
            shape=shape,
            chunks=edges,
            dtype=dtype,
            fill_value=0,
            zarr_format=3,
            store=d,
        )
        z[:] = np.array(values, dtype=np.dtype(dtype)).reshape(shape)

    # Read it back. The point of the fixture is to be the reference, so the
    # reference has to be checked against the values that went in.
    got = [int(v) for v in np.array(z[:]).flatten()]
    if got != [int(v) for v in values]:
        raise SystemExit("%s: reads back as %r, not %r" % (name, got, values))

    # The chunk files: each one holds the bytes of its own elements,
    # compressed with the codec the manifest names.
    with open(os.path.join(d, "zarr.json")) as f:
        doc = json.load(f)
    import numcodecs
    config = doc["codecs"][-1].get("configuration", {})
    decoder = numcodecs.Zstd(level=config.get("level", 0),
                             checksum=config.get("checksum", False))

    # Where each edge of the grid starts.
    starts = []
    for axis in edges:
        at = 0
        s = []
        for e in axis:
            s.append(at)
            at += e
        starts.append(s)

    for coords in product([len(axis) for axis in edges]):
        with open(os.path.join(d, "c", *["%d" % c for c in coords]), "rb") as f:
            raw = decoder.decode(f.read())
        # The values of the chunk: the block its own edges make.
        want = []
        for inner in product([edges[k][coords[k]] for k in range(len(coords) - 1)]):
            for j in range(edges[-1][coords[-1]]):
                block_coords = inner + (j,)
                global_coords = tuple(
                    starts[k][coords[k]] + block_coords[k] for k in range(len(coords))
                )
                if any(gc >= shape[k] for k, gc in enumerate(global_coords)):
                    want.append(0)
                else:
                    want.append(values[flat_index(global_coords, shape)])
        got = list(struct.unpack("<" + fmt * len(want), raw))
        if got != want:
            raise SystemExit(
                "%s: the chunk %s holds %r, not %r" % (name, coords, got, want)
            )
    print("wrote", name)


def make_group(name, arrays):
    """Write a group with consolidated metadata, then read it back.

    The manifests of every array of the group are in one `.zmetadata`
    file, and the chunks are in each array's own directory. The per-array
    `.zarray` files are not written: the consolidated metadata is the only
    place the manifests live, which is the whole point of it.

    `arrays` is a list of dictionaries, each with the array's `path` in
    the group, its `shape`, its `chunks`, its `dtype`, its `values` and
    its `compressor`.
    """
    d = os.path.join(ROOT, name)
    metadata = {
        ".zgroup": {"zarr_format": 2},
        ".zattrs": {},
    }
    for a in arrays:
        # The consolidated metadata is a flat list of the files of the
        # group, and every group in it has an entry of its own: the
        # groups above the array, and then the array.
        parts = a["path"].split("/")
        for i in range(1, len(parts)):
            above = "/".join(parts[:i])
            metadata[above + "/.zgroup"] = {"zarr_format": 2}
            metadata[above + "/.zattrs"] = {}
        metadata[a["path"] + "/.zattrs"] = {}
        metadata[a["path"] + "/.zarray"] = manifest_doc(
            shape=a["shape"], chunks=a["chunks"], dtype=a["dtype"],
            compressor=a["compressor"], fill_value=0,
        )
    # The consolidated metadata is written compactly, the way zarr-python
    # writes it, and without a newline at the end.
    write_text(os.path.join(d, ".zmetadata"),
               json.dumps({"metadata": metadata, "zarr_consolidated_format": 1},
                          sort_keys=True))
    write_text(os.path.join(d, ".zgroup"), json.dumps({"zarr_format": 2}, indent=4) + "\n")

    for a in arrays:
        fmt, size = DTYPES[a["dtype"]]
        adir = os.path.join(d, *a["path"].split("/"))
        g = grid(a["shape"], a["chunks"])
        nchunks = 1
        for x in g:
            nchunks *= x
        for flat in range(nchunks):
            coords = chunk_coords(flat, g)
            want = block_want(a["shape"], a["chunks"], a["values"], 0, coords)
            raw = b"".join(struct.pack("<" + fmt, v) for v in want)
            blob = compress(raw, a["compressor"])
            write_bytes(chunk_path(adir, coords, None), blob)

    # Read it back: the chunks are decompressed and the values compared
    # against the ones that went in.
    for a in arrays:
        fmt, size = DTYPES[a["dtype"]]
        adir = os.path.join(d, *a["path"].split("/"))
        g = grid(a["shape"], a["chunks"])
        nchunks = 1
        for x in g:
            nchunks *= x
        for flat in range(nchunks):
            coords = chunk_coords(flat, g)
            with open(chunk_path(adir, coords, None), "rb") as f:
                raw = decompress(f.read(), a["compressor"])
            got = list(struct.unpack("<" + fmt * (len(raw) // size), raw))
            want = block_want(a["shape"], a["chunks"], a["values"], 0, coords)
            if got != want:
                raise SystemExit(
                    "%s: chunk %s reads back as %r, not %r"
                    % (a["path"], coords, got, want)
                )
    print("wrote", name)


def compress(raw, codec):
    if codec is None:
        return raw
    if codec["id"] == "zlib":
        return zlib.compress(raw, codec.get("level", 1))
    if codec["id"] == "gzip":
        return gzip.compress(raw, codec.get("level", 1), mtime=0)
    if codec["id"] == "bz2":
        return bz2.compress(raw, codec.get("level", 1))
    if codec["id"] == "zstd":
        try:
            from compression import zstd
        except ImportError:
            return None
        return zstd.compress(raw, codec.get("level", 1))
    if codec["id"] == "blosc":
        return blosc_frame(raw, codec)
    raise SystemExit("unknown codec " + codec["id"])


def decompress(raw, codec):
    if codec is None:
        return raw
    if codec["id"] == "zlib":
        return zlib.decompress(raw)
    if codec["id"] == "gzip":
        return gzip.decompress(raw)
    if codec["id"] == "bz2":
        return bz2.decompress(raw)
    if codec["id"] == "zstd":
        from compression import zstd
        return zstd.decompress(raw)
    if codec["id"] == "blosc":
        return blosc_unframe(raw, codec)
    raise SystemExit("unknown codec " + codec["id"])


# --- the blosc frame --------------------------------------------------------

# The codec the frame names, and the number the frame's flags carry.
#
# These are the frame's own codes, not c-blosc's library codes, and the two
# enumerations part company from the second code on: the frame's code 2 is
# snappy where the library's code 2 is lz4hc, and the frame's code 4 is zstd
# where the library's code 5 is. The frame's code 1 names both lz4 and
# lz4hc, which the frame cannot tell apart.
BLOSC_CODECS = {"blosclz": 0, "lz4": 1, "lz4hc": 1, "snappy": 2, "zlib": 3, "zstd": 4}

BLOSC_HEADER = 16


def blosc_frame(raw, codec):
    """A blosc frame around these bytes.

    The header says how the frame is put together: the version, the flags
    (the shuffle and the codec), the size of one element, the size of the
    data, the size of a block and the size of the frame. Then come the
    offsets of the blocks, and the blocks.
    """
    cname = codec.get("cname", "lz4")
    if cname not in BLOSC_CODECS:
        raise SystemExit("unknown blosc codec " + cname)
    shuffle = codec.get("shuffle", 1)
    typesize = codec.get("typesize", 1)
    if shuffle not in (0, 1):
        raise SystemExit("unknown blosc shuffle " + str(shuffle))

    flags = BLOSC_CODECS[cname] << 5
    if shuffle == 1:
        flags |= 0x1
    flags |= 0x10  # the block is not split

    block = byte_shuffle(raw, typesize)
    if cname == "lz4":
        payload = lz4_compress(block)
    elif cname == "zstd":
        payload = zstd_compress(block, codec.get("clevel", 5))
    else:
        raise SystemExit("this script writes the lz4 and zstd blosc frames only")
    # A block is the size of its compressed bytes and then those bytes.
    body = struct.pack("<I", len(payload)) + payload
    starts = BLOSC_HEADER + 4  # the offset of the only block
    header = struct.pack(
        "<BBBBIII",
        2,          # the format version
        1,          # the codec's version
        flags,
        typesize,
        len(raw),   # the size of the data
        len(raw),   # the size of a block
        starts + len(body),
    )
    return header + struct.pack("<I", starts) + body


def blosc_unframe(raw, codec):
    """The bytes of a blosc frame, the way the frame says to put them back."""
    typesize = codec.get("typesize", 1)
    shuffle = codec.get("shuffle", 1)
    if len(raw) < BLOSC_HEADER:
        raise SystemExit("the blosc frame is too short")
    version, _versionlz, flags, frame_typesize, nbytes, _blocksize, _cbytes = \
        struct.unpack("<BBBBIII", raw[:BLOSC_HEADER])
    if version != 2:
        raise SystemExit("the blosc frame has version %d" % version)
    if frame_typesize != typesize:
        raise SystemExit("the blosc frame has a type size of %d" % frame_typesize)
    cname = codec.get("cname", "lz4")
    names = [k for k, v in BLOSC_CODECS.items() if v == (flags & 0xE0) >> 5]
    if cname not in names:
        raise SystemExit("the blosc frame names another codec")
    if flags & 0x1 and shuffle != 1:
        raise SystemExit("the blosc frame shuffles and the manifest says otherwise")

    out = bytearray()
    at = BLOSC_HEADER
    while len(out) < nbytes:
        (start,) = struct.unpack("<I", raw[at:at + 4])
        at += 4
        (cbytes,) = struct.unpack("<I", raw[start:start + 4])
        block = raw[start + 4:start + 4 + cbytes]
        if cname == "lz4":
            out += lz4_decompress(block, nbytes - len(out))
        elif cname == "zstd":
            out += zstd_decompress(block)
        else:
            raise SystemExit("this script reads the lz4 and zstd blosc frames only")
    if shuffle == 1 and typesize > 1:
        out = byte_unshuffle(bytes(out), typesize)
    return bytes(out)


def byte_shuffle(raw, typesize):
    """The byte shuffle: the bytes of the same place of each element side by
    side. The bytes that do not fill an element are left where they are."""
    if typesize <= 1:
        return raw
    count = len(raw) // typesize
    out = bytearray(len(raw))
    for j in range(typesize):
        for i in range(count):
            out[j * count + i] = raw[i * typesize + j]
    out[count * typesize:] = raw[count * typesize:]
    return bytes(out)


def byte_unshuffle(raw, typesize):
    """The inverse of the byte shuffle."""
    if typesize <= 1:
        return raw
    count = len(raw) // typesize
    out = bytearray(len(raw))
    for i in range(count):
        for j in range(typesize):
            out[i * typesize + j] = raw[j * count + i]
    out[count * typesize:] = raw[count * typesize:]
    return bytes(out)


def lz4_compress(raw):
    """The LZ4 block format: a run of sequences.

    A sequence opens with a token whose high nibble is the length of the
    literals that follow and whose low nibble is the length of the match
    minus four. The literals come next, then the two-byte little-endian
    distance of the match, and the match copies that many bytes from that
    distance back. A length of fifteen means the real length follows in
    extra bytes.
    """
    out = bytearray()
    n = len(raw)
    if n == 0:
        return bytes(out)
    # The rules the format puts on the encoder: the last five bytes are
    # always literals, and a match never starts in the last twelve.
    literals_at_the_end = 5
    match_limit = n - 12
    table = {}
    anchor = 0
    pos = 0
    while pos < match_limit:
        seq = raw[pos:pos + 4]
        if len(seq) < 4:
            break
        candidate = table.get(seq)
        table[seq] = pos
        if candidate is None or pos - candidate > 65535:
            pos += 1
            continue
        length = 4
        while (pos + length < n - literals_at_the_end
               and raw[candidate + length] == raw[pos + length]):
            length += 1
        literals = raw[anchor:pos]
        out.append((min(len(literals), 15) << 4) | min(length - 4, 15))
        if len(literals) >= 15:
            out += lz4_length(len(literals) - 15)
        out += literals
        out += struct.pack("<H", pos - candidate)
        if length - 4 >= 15:
            out += lz4_length(length - 4 - 15)
        anchor = pos + length
        pos = anchor
    literals = raw[anchor:]
    out.append(min(len(literals), 15) << 4)
    if len(literals) >= 15:
        out += lz4_length(len(literals) - 15)
    out += literals
    return bytes(out)


def lz4_length(n):
    """The extra bytes of a length that does not fit in the token."""
    out = bytearray()
    while n >= 255:
        out.append(255)
        n -= 255
    out.append(n)
    return bytes(out)


def lz4_decompress(raw, size):
    """The bytes of an LZ4 block."""
    out = bytearray()
    at = 0
    n = len(raw)
    while at < n and len(out) < size:
        token = raw[at]
        at += 1
        literals = token >> 4
        if literals == 15:
            while True:
                code = raw[at]
                at += 1
                literals += code
                if code != 255:
                    break
        out += raw[at:at + literals]
        at += literals
        if at >= n:
            break
        (offset,) = struct.unpack("<H", raw[at:at + 2])
        at += 2
        match = (token & 0x0F) + 4
        if (token & 0x0F) == 15:
            while True:
                code = raw[at]
                at += 1
                match += code
                if code != 255:
                    break
        start = len(out) - offset
        for k in range(match):
            out.append(out[start + k])
    return bytes(out[:size])


def zstd_compress(raw, level=5):
    """A zstd frame, which is what a c-blosc piece of the zstd codec holds.

    The standard library has had zstd since Python 3.14; an interpreter
    without it cannot write the zstd blosc frames.
    """
    try:
        from compression import zstd
    except ImportError:
        raise SystemExit("no zstd in this interpreter")
    return zstd.compress(raw, level)


def zstd_decompress(raw):
    """The bytes of a zstd frame."""
    try:
        from compression import zstd
    except ImportError:
        raise SystemExit("no zstd in this interpreter")
    return zstd.decompress(raw)


def transpose_elements(values, shape, order):
    """The elements of a chunk with the axes permuted, the way the transpose
    codec stores them.

    The stored axis `i` holds the chunk's axis `order[i]`, so the stored
    buffer runs over the shape that permutation gives, and it runs over it
    in the chunk's own order.
    """
    n = len(shape)
    stored_shape = [shape[o] for o in order]
    out = []
    for coords in product(stored_shape):
        # the chunk's own coordinates of the element at these coordinates
        x = [0] * n
        for i in range(n):
            x[order[i]] = coords[i]
        out.append(values[flat_index(x, shape)])
    return out


def untranspose_elements(stored, shape, order):
    """The chunk's own elements, from the ones the transpose codec stored."""
    n = len(shape)
    stored_shape = [shape[o] for o in order]
    out = [None] * len(stored)
    for lin, value in enumerate(stored):
        coords = []
        rest = lin
        for k in range(n - 1, -1, -1):
            coords.insert(0, rest % stored_shape[k])
            rest //= stored_shape[k]
        # the chunk's own coordinates of this element
        x = [0] * n
        for i in range(n):
            x[order[i]] = coords[i]
        out[flat_index(x, shape)] = value
    return out


def block_want(shape, chunks, values, fill_value, coords):
    """The values of one chunk, in C order, with the fill for the elements
    that fall past the end of the array."""
    want = []
    for inner in product(chunks[:-1]):
        for j in range(chunks[-1]):
            block_coords = inner + (j,)
            global_coords = tuple(
                coords[k] * chunks[k] + block_coords[k] for k in range(len(coords))
            )
            if any(gc >= shape[k] for k, gc in enumerate(global_coords)):
                want.append(fill_value)
            else:
                want.append(values[flat_index(global_coords, shape)])
    return want


def make_array(name, shape, chunks, dtype, values, compressor=None, filters=None,
               fill_value=0, order="C", sep=None, delta=False, typesize=None):
    """Write one array, then read it back and check it.

    `delta` says the chunk holds the differences along the last axis and
    the running sum is the array -- which is what the delta filter does.
    `typesize` is the size of one element, which the blosc frame needs.
    """
    fmt, size = DTYPES[dtype]
    if typesize is None:
        typesize = size
    if compressor is not None and compressor.get("id") == "blosc":
        compressor = dict(compressor, typesize=typesize)
    d = os.path.join(ROOT, name)
    write_text(os.path.join(d, ".zarray"), manifest(
        shape=shape, chunks=chunks, dtype=dtype, compressor=compressor,
        fill_value=fill_value, order=order, filters=filters, sep=sep,
    ))
    write_text(os.path.join(d, ".zattrs"), json.dumps({"units": "m/s"}, indent=4) + "\n")
    write_text(os.path.join(d, ".zgroup"), json.dumps({"zarr_format": 2}, indent=4) + "\n")

    g = grid(shape, chunks)
    nchunks = 1
    for x in g:
        nchunks *= x

    for flat in range(nchunks):
        coords = chunk_coords(flat, g)
        want = block_want(shape, chunks, values, fill_value, coords)
        raw = b"".join(struct.pack("<" + fmt, v) for v in want)
        if delta:
            raw = delta_encode(raw, want)
        blob = compress(raw, compressor)
        if blob is None:
            print("skipping %s: no zstd in this interpreter" % name)
            return
        write_bytes(chunk_path(d, coords, sep), blob)

    # Read it back. The point of the fixture is to be the reference, so
    # the reference has to be checked against the values that went in.
    for flat in range(nchunks):
        coords = chunk_coords(flat, g)
        with open(chunk_path(d, coords, sep), "rb") as f:
            raw = decompress(f.read(), compressor)
        if delta:
            raw = delta_decode(raw)
        got = list(struct.unpack("<" + fmt * (len(raw) // size), raw))
        want = block_want(shape, chunks, values, fill_value, coords)
        if got != want:
            raise SystemExit(
                "%s: chunk %s reads back as %r, not %r" % (name, coords, got, want)
            )
    print("wrote", name)


def delta_encode(raw, vals):
    """The differences along the last axis, which is what delta stores."""
    out = bytearray()
    prev = 0
    for v in vals:
        out += struct.pack("<i", int(v) - prev)
        prev = int(v)
    return bytes(out)


def delta_decode(raw):
    """The running sum, which is what delta's decoder does."""
    ints = struct.unpack("<" + "i" * (len(raw) // 4), raw)
    out = bytearray()
    total = 0
    for v in ints:
        total += v
        out += struct.pack("<i", total)
    return bytes(out)


def chunk_path(directory, coords, sep):
    if sep == "/":
        return os.path.join(directory, *[str(c) for c in coords])
    return os.path.join(directory, ".".join(str(c) for c in coords))


def main():
    # 1. the plain case: 2-D doubles, zlib, a grid of four chunks
    make_array(
        "f64-zlib",
        shape=(4, 6),
        chunks=(2, 3),
        dtype="<f8",
        values=[float(i + 1) for i in range(24)],
        compressor={"id": "zlib", "level": 1},
    )

    # 2. no compressor at all, and a short last chunk: the fill value shows
    make_array(
        "i16-raw",
        shape=(5,),
        chunks=(2,),
        dtype="<i2",
        values=[10, 20, 30, 40, 50],
        compressor=None,
    )

    # 3. gzip, and bytes rather than words
    make_array(
        "u1-gzip",
        shape=(8,),
        chunks=(4,),
        dtype="|u1",
        values=[1, 2, 3, 4, 5, 250, 251, 252],
        compressor={"id": "gzip", "level": 1},
    )

    # 4. the delta filter: the chunk holds the differences, and the reader
    #    has to put the running sum back
    make_array(
        "i4-delta",
        shape=(4,),
        chunks=(4,),
        dtype="<i4",
        values=[4, 7, 11, 16],
        compressor=None,
        filters=[{"id": "delta", "dtype": "<i4"}],
        delta=True,
    )

    # 5. bzip2
    make_array(
        "f32-bz2",
        shape=(3,),
        chunks=(3,),
        dtype="<f4",
        values=[1.5, 2.25, -3.75],
        compressor={"id": "bz2", "level": 1},
    )

    # 6. the chunks in sub-directories, the other dimension separator
    make_array(
        "u8-slash",
        shape=(2, 2),
        chunks=(1, 1),
        dtype="<u8",
        values=[1, 2, 3, 4],
        compressor=None,
        sep="/",
    )

    # 7. the v3 layout: the one zarr-python writes by default. The
    #    metadata is in one file and the chunks are named by a key
    #    encoding, and the pipeline of codecs says how the bytes of a chunk
    #    become the elements.
    make_v3_array(
        "f64-zstd-v3",
        shape=(4, 4),
        chunks=(2, 2),
        dtype="float64",
        values=[float(i + 1) for i in range(16)],
    )

    # 8. blosc: the codec zarr-python asks for by default. The frame is
    #    written here, so the chunk is a real one and the reader has to
    #    take the frame apart to reach the values.
    make_array(
        "f64-blosc",
        shape=(4, 4),
        chunks=(2, 2),
        dtype="<f8",
        values=[float(i + 1) for i in range(16)],
        compressor={"id": "blosc", "cname": "lz4", "clevel": 5, "shuffle": 1},
        typesize=8,
    )

    # 9. the consolidated metadata of a group: the manifests of every array
    #    are in one file, and the chunks are in the arrays' own directories
    make_group(
        "group-consolidated",
        arrays=[
            {
                "path": "first",
                "shape": (2, 3),
                "chunks": (1, 3),
                "dtype": "<f8",
                "values": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
                "compressor": {"id": "zlib", "level": 1},
            },
            {
                "path": "nested/second",
                "shape": (4,),
                "chunks": (2,),
                "dtype": "<i4",
                "values": [10, 20, 30, 40],
                "compressor": None,
            },
        ],
    )

    # 10. the transpose codec of the v3 pipeline: the chunks are stored
    #     with their axes permuted, and the reader has to put them back
    make_v3_transposed_array(
        "f64-transpose-v3",
        shape=(4, 6),
        chunks=(2, 3),
        dtype="float64",
        values=[float(i + 1) for i in range(24)],
        order=(1, 0),
    )

    # 11. the sharding codec of the v3 pipeline: the chunk is a shard that
    #     holds several inner chunks and the index that says where each of
    #     them is. The order of the chunks inside the shard is not fixed, so
    #     the reader has to go through the index.
    make_v3_sharded_array(
        "f64-sharding-v3",
        shape=(4, 6),
        chunks=(2, 3),
        shard_shape=(4, 6),
        dtype="float64",
        values=[float(i + 1) for i in range(24)],
    )

    # 12. the rectilinear chunk grid of the v3 layout: the chunks have an
    #     edge of their own along each axis, and the edges are the grid
    make_v3_rectilinear_array(
        "i4-rectilinear-v3",
        shape=(6, 5),
        edges=[[2, 1, 3], [2, 3]],
        dtype="int32",
        values=list(range(30)),
    )

    # 13. a blosc frame of a codec other than lz4: the frame's codes are
    #     the frame's own, and the code 4 is zstd. The chunk is a frame
    #     like any other, and the reader has to reach the values through
    #     it.
    make_v3_blosc_array(
        "f64-blosc-zstd-v3",
        shape=(4, 4),
        chunks=(2, 2),
        dtype="float64",
        values=[float(i + 1) for i in range(16)],
        cname="zstd",
    )


if __name__ == "__main__":
    main()
