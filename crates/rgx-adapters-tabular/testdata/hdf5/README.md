# Fixtures: the HDF5 file of the latest format

These are **real files**, taken from the HDF5 library itself rather than
written by hand here: a hand-built HDF5 file would only prove that the
reader accepts what the test author already believed about it.

| file | what it is | what it is there for |
|---|---|---|
| `h5fc_ext1_f.h5` | an HDF5 file written with the latest format: its datasets are indexed by the chunk indexes of the latest format | the chunk indexes the reader had to learn: the implicit index, the fixed array, the extensible array and the v2 B-tree |
| `h5fc_ext1_f.ddl` | the data description the HDF5 library's own tool prints for that file | the oracle for the names, the shapes and the maximum shapes the reader has to give |

The files are kept byte for byte: the directory is `-text` in
`.gitattributes`, so a checkout cannot rewrite a byte of them.

## Where they come from

| file | where it comes from |
|---|---|
| `h5fc_ext1_f.h5` | `hdfgroup/hdf5`, `tools/h5format_convert/testfiles/h5fc_ext1_f.h5`, at the tag `hdf5-1_10_0` |
| `h5fc_ext1_f.ddl` | `hdfgroup/hdf5`, `tools/h5format_convert/testfiles/h5fc_ext1_f.ddl`, at the tag `hdf5-1_10_0` |

The HDF5 library is BSD-3-Clause.

## The chunk indexes of the latest format

A chunked dataset's chunks live in an index, and the layout message of
the dataset says which one. The third version of the layout message --
the one every file that does not use the latest format has -- always has
a v1 B-tree. The fourth version, which the latest format has, names the
index, and the file format specification gives five of them: the single
chunk, the implicit index, the fixed array, the extensible array and the
v2 B-tree.

The library picks the index from the shape of the dataset: a dataset
that is one chunk gets the single chunk index, a dataset with one
dimension of unlimited extent gets the extensible array, a dataset with
more than one gets the v2 B-tree, and a dataset of fixed shape gets the
implicit index when its chunks are allocated early, and the fixed array
otherwise.

`h5fc_ext1_f.h5` has one dataset of each kind, and the `.ddl` file says
which is which:

| dataset | shape | maximum shape | index |
|---|---|---|---|
| `DSET_NONE` | 4 by 6 | 4 by 6 | the implicit index |
| `DSET_FA` | 4 by 6 | 20 by 10 | the fixed array |
| `GROUP/DSET_BT2` | 4 by 6 | unlimited by unlimited | the v2 B-tree |
| `DSET_EA` | 4 by 6 | 10 by unlimited | the extensible array |
| `DSET_NDATA_BT2`, `GROUP/DSET_NDATA_EA`, `GROUP/DSET_NDATA_FA`, `GROUP/DSET_NDATA_NONE` | 4 by 6 | as above | the same indexes, with no data written |
| `DSET_CONTIGUOUS` | 10 | 10 | no index at all: the data is one block |

## The oracle for the values

The oracle is the producer's own source: the HDF5 library's
`tools/h5format_convert/h5fc_gentest.c` writes that file, with
`H5Pset_libver_bounds(fapl, H5F_LIBVER_LATEST, H5F_LIBVER_LATEST)`, and
writes a four by six dataset of native `int`, in chunks of two by three,
whose value at (i, j) is `i * 6 + j`. The test compares every one of the
twenty four values the reader gives with the value the generator wrote at
that coordinate, and the index of each one with the coordinate it belongs
to -- so a chunk that was placed in the wrong cells, or that was read
from the wrong index, is caught by the test rather than by a caveat.

The extensible array is the index of a dataset with a dimension of
unlimited extent, and its array puts that dimension first, so that the
array grows by appending. The reader has to place the chunks the same
way the library did. The reader reads the elements of the array's index
block, which is where they are while the array is small; past that they
live in data blocks, which the reader does not read, and it says so.

No file in the tree uses the single chunk index -- the library picks it
for a dataset that is one chunk, and none of the fixtures is -- so the
reader takes that one from the file format specification, and the test
builds the layout message the way the specification says it is.
