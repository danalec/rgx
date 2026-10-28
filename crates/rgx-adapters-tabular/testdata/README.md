# Fixtures: the HDF5-based scientific formats

These are **real files**, taken from the reference implementations rather
than written by hand, because the thing being tested is a reader against
files that the format's own tooling produces. A hand-built HDF5 file would
only prove that the reader accepts what the test author already believed.

Every file here is covered by its project's licence (netcdf-c and matio are
BSD-3-Clause, scipy is BSD-3-Clause, the HDF5 library is BSD-3-Clause, and the
NASA CDF files carry the CDF
library's own notice, reproduced in `nc/README.md`) and is kept byte for byte:
the directory is `-text` in `.gitattributes`, so a checkout cannot rewrite a
byte of them.

| file | what it is | where it comes from |
|---|---|---|
| `netcdf4-irish-rover.nc` | netCDF-4, small, whose names live in link messages inside a continuation chunk, and whose "cargo" member is a committed type with a v1 object header | `Unidata/netcdf-c`, `ncdump/ref_tst_irish_rover.nc` |
| `netcdf4-provenance.nc` | netCDF-4, small, with a group and an attribute | `Unidata/netcdf-c`, `ncdump/ref_provenance_v1.nc` |
| `netcdf4-fractal-heap.nc` | netCDF-4 written with the newest layout (v2 superblock, names in a fractal heap) | `Unidata/netcdf-c`, `ncdump/ref_nc_test_netcdf4_4_0.nc` |
| `netcdf4-fractal-heap.cdl` | the `ncdump` output the netCDF library ships for that file: the oracle the reader has to agree with | `Unidata/netcdf-c`, `ncdump/ref_nc_test_netcdf4.cdl` |
| `netcdf4-compact-links.nc` | netCDF-4 whose group keeps its names in the object header, as link messages, instead of in a fractal heap | `Unidata/netcdf-c`, `ncdump/ref_tst_compounds3.nc` |
| `netcdf4-compact-links.cdl` | the `ncdump` output the netCDF library ships for that file: the oracle the reader has to agree with | `Unidata/netcdf-c`, `ncdump/ref_tst_compounds3.cdl` |
| `netcdf3-360-day.nc` | netCDF classic (CDF-1), the layout the netCDF reader owns | `Unidata/netcdf-c`, `ncdump/ref_test_360_day_1900.nc` |
| `netcdf3-360-day.cdl` | the `ncdump` output the netCDF library ships for that file: the oracle the reader's values have to agree with | `Unidata/netcdf-c`, `ncdump/ref_test_360_day_1900.cdl` |
| `matlab-v7.mat` | MATLAB v7.3: 512 bytes of header, then the HDF5 file | `tbeu/matio`, `share/test_file_hdf5.mat` |
| `matlab-v73.mat` | MATLAB v7.3, little-endian, HDF5 schema 1.00 | `tbeu/matio`, `share/test_le_hdf5.mat` |
| `matlab-v70-hdf5.mat` | MATLAB v7.0 whose payload is HDF5 (schema 0.05) | `scipy/scipy`, `scipy/io/matlab/tests/data/testhdf5_7.4_GLNX86.mat` |
| `matlab-v5.mat` | MATLAB 5.0, the layout the v5 reader owns | `tbeu/matio`, `share/test_le.mat` |
| `group_old.h5` | a group in the old format: the names live in a symbol table, not in a heap | `hdfgroup/hdf5`, `test/testfiles/group_old.h5` |
| `test_filters_le.h5` | a dataset whose chunk carries a Fletcher-32 checksum | `hdfgroup/hdf5`, `test/testfiles/test_filters_le.h5` |
| `deflate.h5` | a dataset whose eight chunks are compressed with deflate, in the old layout, whose layout message counts the size of an element as a dimension of its own | `hdfgroup/hdf5`, `test/testfiles/deflate.h5` |
| `hdf5/h5fc_ext1_f.h5` | an HDF5 file written with the newest layout, whose two chunked datasets use the **extensible array** and the **v2 B-tree** chunk indexes | `hdfgroup/hdf5`, `test/testfiles/h5fc_ext1_f.h5` |
| `hdf5/h5fc_ext1_f.ddl` | the `h5dump` output the HDF5 library ships for that file: the oracle the reader's structure has to agree with | `hdfgroup/hdf5`, `test/testfiles/h5fc_ext1_f.ddl` |

## The compressed chunk, and the generator that wrote it

`deflate.h5` is the fixture for the deflate filter: a hundred by two
hundred dataset of native `int`, in eight chunks of fifty by fifty, and
every chunk is a zlib stream.

The oracle is the producer's own source: the HDF5 library's
`test/gen_deflate.c` writes that file, and the value it writes at (i, j)
is `j % 5`. The test compares every one of the 20 000 values the reader
gives with the value the generator wrote at that coordinate, and the
index of each one with the coordinate it belongs to -- so a chunk that
inflated to the wrong bytes, or that was placed in the wrong cells, is
caught by the test rather than by a caveat.

## Why the last two are here

`matlab-v5.mat` and `netcdf3-360-day.nc` carry the two extensions the HDF5
reader now claims (`.mat` and `.nc`). They are the rows that keep the
claim honest: a v5 `.mat` must still reach the v5 reader, and a netCDF-3
`.nc` must still reach the netCDF reader. A reader that claims an extension
without knowing when to step aside is a reader that answers the wrong
format.

## The one that gives up its names — and the oracle that says so

`netcdf4-fractal-heap.nc` is a netCDF-4 file written with the current
default layout. Its variable names live in a fractal heap, not in a plain
object header, so the reader used to report the superblock and the
attribute strings it could see and **did not** invent the names. It is in
the tree because that limit should be visible in a test rather than in a
caveat.

The reader now walks the heap — the v2 object header, the Link Info
message, the v2 B-tree that indexes the heap and the heap's own blocks,
one Link message each — and reports the real names:

```
link: Dr: dimension scale: float32 dims=[0]
link: c: dataset: char dims=[]
link: cr: dataset: char dims=[2]
```

`netcdf4-fractal-heap.cdl` is the **oracle** for that: the `ncdump`
output the netCDF library itself ships for exactly this file, from
`ncdump/ref_nc_test_netcdf4.cdl`. It lists the five dimensions
(`Dr`, `D1`..`D4`) and the 141 variables, in the order they were created.
The test compares the reader's names against it, name for name and in
order, so the claim is checked by the test suite and not by prose.

The same file is the oracle for the **attributes**: `ncdump` lists
thirteen of them — six global ones (`Gc`, `Gb`, `Gs`, `Gi`, `Gf`, `Gd`)
and seven on variables — and the test compares each value with the one
the reader gives, number for number and byte for byte. The two files
are byte for byte the ones the netCDF library ships: the library keeps
its binary fixtures in the tree as a list of decimal bytes, and the
copy here is that list decoded.

Both files come from netcdf-c, which is BSD-3-Clause: see the notice in
`nc/README.md`.

## The group that keeps its names in its own header

`netcdf4-compact-links.nc` is the other half of the same story. A group
with few enough members does not get a fractal heap: HDF5 keeps its
names in the group's own object header, as **link messages**, and leaves
the heap's address undefined in the Link Info message. The reader used
to look for the heap, find no heap, and fall back to the printable
strings it could see — which for this file are the fragments of the
object header itself.

It now reads the link messages, and the names are the real ones:

```
link: cmp_t: committed datatype: compound
link: n: dimension scale: float32 dims=[1]
link: var: dataset: compound dims=[1]
```

`netcdf4-compact-links.cdl` is the **oracle** for that, the same way
`netcdf4-fractal-heap.cdl` is for the other file: the `ncdump` output
the netCDF library itself ships for exactly this file, from
`ncdump/ref_tst_compounds3.cdl`. It lists the type `cmp_t`, the
dimension `n` and the variable `var`, and the test compares the reader's
names against it, in order.

The two files make the same point from the two sides: the names of a
netCDF-4 file live in one of two places, and the reader has to look in
both.

## The types, and the members they name

The same two files carry **types**, and a type names its members.

`netcdf4-irish-rover.nc` holds a committed **enumeration** called
`cargo`, with eight members. The upstream ships no `ncdump` reference
for that file, so the oracle is the source that wrote it: the netCDF
library's own `nc_test4/tst_enums.c`, which defines the type with
`nc_def_enum(ncid, NC_UINT64, "cargo", &typeid)` and gives it the eight
names and the values 1,000,000 to 8,000,000.

`netcdf4-compact-links.nc` holds a committed **compound** called
`cmp_t`, and its oracle is the `.cdl` beside it: `compound cmp_t { float
x ; double y ; };`.

The reader gives:

```
member: cargo: dogs = 5000000
member: cmp_t: x = float32
member: cmp_t: y = float64
```

The enumeration is stored twice in its file -- once as the committed
type, once inside the variable that uses it -- and the reader lists the
eight members once.

## The Zarr arrays

`zarr/` is a different kind of fixture: a Zarr array is a **directory**,
## The Visual FoxPro container and its companions

`foxpro/` holds a Visual FoxPro database container with the two files that
belong to it: the memo file beside it, whose blocks the container's rows
name, and the compound index that indexes the container's rows. The files
are the project's own, not written by hand here -- a hand-built container
would only prove that the reader accepts what the test author already
believed -- and their own README is `foxpro/README.md`.

The oracle is the producer's own: a row of the container names the block its
text is in, and the memo file has that block -- the block that holds the
name of the field the row is about, or the name of the file of the table the
row binds. The test walks every row and checks both, so a block read from
the wrong place, or a row that points at somebody else's block, is caught
by the test rather than by a caveat.
so the tree holds a `.zarray` manifest and the chunks beside it, and the
reader has to find the chunks by their index. They are written by
`scripts/gen_zarr_fixtures.py`, which reads every array back before it
leaves it there. Their own README is `zarr/README.md`.

## The values, and the oracle that says so

`netcdf3-360-day.cdl` is the **oracle** for the values of the netCDF classic
reader. It is the `ncdump` output the netCDF library itself ships for exactly
that file, from `ncdump/ref_test_360_day_1900.cdl`, and it renders the `time`
variable with the units and the calendar the file declares -- so the value at
index *i* is the date *i* days after 1900-01-01 in a **360-day** calendar:
twelve months of thirty days, so a year is 360 days and not 365. The test
reads those 2,300 dates out of the oracle and checks them against the ones
the reader gives, one by one.

The record variables of the `nctest` files have no `ncdump` reference, so
their oracle is the file's own header: it says where each record variable
starts and how big one record of it is -- and the last record of the file
ends at its last byte.

The `data:` section of `netcdf4-fractal-heap.cdl` is the **oracle** for the
values of the netCDF-4 reader, the same way the file is the oracle for its
names: it holds the value of every one of the 141 variables, and the reader
gives the same 1,403 values -- the ones the file stores in one block and the
ones it stores in chunks -- in the same order.

## The netCDF and NASA CDF files

`nc/` holds the two netCDF layouts and the NASA CDF-3 format, each taken
from the project that writes it rather than written by hand here: a
hand-built netCDF file would only prove that the reader accepts what the
test author already believed about it.

The two netCDF files are the *same* test CDF in the two layouts the
library writes, so the variable list has to read the same in both — that
is the row that keeps the claim honest. The CDF files are NASA's own
formats: CDF-3 is read, and NASA's CDF-2 and the netCDF library's CDF-5
are refused, with the reason written into the adapter's output rather
than a wrong number. Their own README is `nc/README.md`.
