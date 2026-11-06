# rgx-adapters-tabular

Tabular and geospatial adapters. Databases are dumped as grep-friendly
TSV — schema plus rows — rather than queried; the point is making them
greppable, not serving SQL.

## What it claims

| adapter | extensions |
|---|---|
| `sqlite` | sqlite, sqlite3, db, db3, sdb, rdb |
| `duckdb` | duckdb |
| `foxpro` | dbc, dct, fpt, dcx, cdx |
| `dbf` | dbf, dbc |
| `slk` | slk |
| `dif` | dif |
| `lotus123` | wks, wk1, wk2, wk3, wk4, 123, wkb |
| `mdb` | mdb, accdb, accde, accdt, mda |
| `lmdb` | mdb |
| `shp` | shp |
| `parquet` | parquet |
| `eri` | eri |
| `mat` | mat |
| `netcdf` | nc, cdf, netcdf |
| `arrow` | arrow, feather |
| `hdf5` | h5, hdf5, he5, h5ad, nc, mat |
| `bson` | bson |
| `redis-rdb` | rdb |
| `redis-aof` | aof |
| `leveldb` | ldb, log, sst |
| `zarr` | zarray, zmetadata, json |
Two extensions are claimed twice, and the chain is what tells them apart:
`.mdb` is both an Access database and an LMDB environment (the two have
different magics, so whichever is asked first declines on the other's
file), and `.rdb` is both a SQLite database and a Redis RDB dump.

Two more are claimed by readers of different families, and the *magic*
decides which one answers: `.nc` is a netCDF classic file (the `CDF` magic)
or a netCDF-4 file (an HDF5 file), and `.mat` is a MATLAB v5 file (the `IM`
endian marker at byte 126) or a MATLAB v7.3 file (an HDF5 file behind a
512-byte user block). The HDF5 reader comes last in the chain and declines
what is not HDF5, so the format-specific readers keep what is theirs.

The CDF family has four layouts of its own, and the reader walks each as the
layout it is: the **classic** netCDF one (`CDF\x01`), the **64-bit offset**
one (`CDF\x02`), the netCDF library's own **CDF-5** (`CDF\x05`, the classic
model with the counts and the lengths in 64 bits and the five types the
edition adds), and NASA's **CDF-1** (`00 00 FF FF`) and **CDF-2**
(`CD F2 60 02`), whose descriptor is a chain of internal records with the
record sizes and the offsets in 32 bits where CDF-3 has 64. The values were
checked against the `cdflib` oracle, value by value: 23 999 values of the
CDF-1 fixture and 21 of the CDF-2 one, with no divergence — the reader
declines that file's `Epoch` variable, 1 090 more values, because the type
carries an encoding of its own, and it says so in its own output.

Every adapter declares `Reach::Reveal` and returns `Outcome::Text`: none
of these files is text ripgrep reads as it stands.

## How it works

SQLite is deserialized in memory through `sqlite3_deserialize`, so there
is no temporary-file I/O at all: the header is checked, `sqlite_master` is
dumped, and then every table. The DuckDB arm is not a table dump — it
checks for the `DUCK` magic at offset 8 and extracts the printable runs
of the file, so it surfaces the strings a columnar store holds without
claiming to read its schema.

The remaining arms are format readers rather than database drivers:
A Visual FoxPro container is a dBase table with a different extension, so
the dBase reader reads it; what the `foxpro` adapter adds is the memo file
beside it, because that is where the text of a memo field lives. The memo
file -- `.dct` beside a container, `.fpt` beside a table -- is a 512-byte
header record and then fixed-size blocks, and a block sits at `number *
block_size` bytes into the file, so the header record takes the first `512 /
block_size` of them: with the 64-byte blocks Visual FoxPro writes, the
first memo is the eighth block of the file and not its first. A memo file
searched on its own is read as the blocks it holds, each with the number it
is in.

A memo field is four bytes, and they are the number of the block its text
is in, least significant byte first. A container read without the memo file
beside it therefore carries the number where the sentence is, because the
number is all the table has to give; read together with that memo file, the
row carries the sentence. The two ends of the same pair of files are read in
opposite byte orders: the memo field is little-endian, and the memo file's
own header -- the number of the next free block and the size of a block --
is most significant byte first.

The compound index (`.dcx`, and the table-level `.cdx`) **is** read. Its
layout -- a key expression pool and a B-tree whose keys are packed backwards
from the end of the page -- is established: each tag header carries its own
512-byte expression area, the leaf's entries are bit-packed, and the key
text lives in a prefix-compressed heap that grows down from the end of the
page. The reader names the index's tags, their key expressions, their key
widths and the rows they point at, and the keys it decodes are checked
against the container's own rows -- the 114 keys of `EXPENSES.DCX` are the
values of the 57 rows it points at, in both tags, with no divergence. The
numeric and the date keys are reported as their raw bytes, because the
transform the format applies to those two is not established here. The names
the index holds are the container's; the tags and the key expressions are
the index's own.

The oracle is the producer's own: the container's rows are the ones Visual
FoxPro wrote, and a row names the block its text is in -- the block that
holds the name of the field the row is about, or the name of the file of the
table the row binds. The test walks every row of the container and checks
that the block it names is a block the memo file holds, and that what the
block holds is the name the row gives. Three files agree, and none of them
was written by the test.
dBase tables, SYLK worksheets, shapefile records, Parquet metadata, the
ERI NTFS path index, MATLAB v5, NetCDF classic, the Arrow IPC stream format
and HDF5.

SYLK is the odd one out: it is a plain-text format, so nothing has to be
decompressed before a character of the sheet is visible. `X` accepts either a
column number or a column letter, and the two spellings are the same cell —
writers disagree, so both are read. Cell values come out as
`R<row>C<column>\t<value>`; formatting records (`B`, `I`, `U`, `S`, `F`) are
deliberately not emitted, because they are not what a grep for a value in a
sheet is looking for.

DIF is the older cousin of SYLK: text, VisiCalc-bred, also survives into
Lotus 1-2-3 and Excel. The parser walks the section keywords (`TABLE`,
`VECTORS`, `DATA`, `EOT`) and emits `C<col>\t<value>` per cell, accepting
both `-1,0` and `""` row sentinels because writers mix them.

Lotus 1-2-3 files are binary records, one opcode per row/col/type triple.
The adapter claims the magic for `wks` (v1.0), `wk1` (v2.x), `wk2`, `wk3`
(v3.x), `wk4` (v4.x), `123` (Millennium), and `wkb` (backup). Numeric,
integer, label, blank and formula cells are extracted — for the v1/v2
family, whose four-byte record framing is verified against real sheets, and
for the v3 and v4 families, whose cell layout is a different one: the row
first, then a block byte, then the column, and then either NUL-terminated
text or a number in the x87's own 80-bit format. That reading is pinned by
the corpus's own trio — `example.wk1`, `example.wk3` and `example.wk4` are
the same sheet, so every cell of one is the same cell of the others, at the
same address, with the same words. A v4 sheet is a document of several
tables and its address says which one the cell belongs to (`B3R24C27`): of
the 1 279 distinct (row, column) pairs of `DEMO.WK4`, 591 hold more than
one cell. The integer cell is left out and counted: its unit is not
established, and a cell read in the wrong unit is a wrong cell. The v4's
formulas are not decoded either — a formula's token stream and the result
it was last evaluated to are not read, and the result does not say whether
it holds a number or a string — so the reader says how many cells it left
out. The Millennium (`.123`) sheet has a cell layout of its own again —
the row, the column in 256ths of a character, and the payload — and the
six cells it stores indirectly are left out and counted too. A fabricated
cell address answers a search with something the file never said, so the
files that are not decoded fall through to the raw search: every byte
stays findable; only the cell decoding is missing. The formula token
stream is left as a length hint so a search for `[formula:` finds every
formula cell without
committing to the full token grammar.

Microsoft Access databases (Jet 3/4 and ACE/ACCDB) are page-oriented binary
files. The adapter validates the Jet magic, reads the engine version and
page size, then walks the data pages emitting printable runs of >= 4 bytes
(the same approach the DuckDB adapter uses) — every visible column value
sits inside one of those runs, so a grep for a row by name or email still
finds it without committing to the full Jet page format.

A Zarr array is a **directory**: a manifest that describes the array — the
shape, the dtype, the chunk size, the codec — and the values, which are read
from the chunks beside the manifest, compressed in a format that says nothing
at all about what they hold. The same eight bytes are eight `u1`, one `f8` or
a ten-character string depending on the `dtype` line, so the manifest has to
be read before the chunks mean anything. The manifest is JSON and `rg` reads
it, but it *describes* the array rather than holding it, so the adapter
leaves the file: it reads the manifest, decompresses the chunks with the
codec named there (zlib, gzip, zstd, bzip2 or blosc), puts the `delta`
filter's running sum back, and renders the values one chunk per line under
the manifest's own bytes — the JSON stays at the top of the answer, because
a search for a key in it still has to find it. It reads the chunks of the array it was handed, and the
consolidated metadata of a group beside it, and it is deliberately absent
from the cache's `MEMOISABLE` list: the key cannot see the chunks change.

There are **two layouts**. The **v2** one puts the manifest in a `.zarray`
beside the chunks and names the chunks by their indices joined by a
separator. The **v3** one — the one `zarr-python` writes by default — puts
the node's metadata in a `zarr.json`, names the chunks with a key encoding,
and says in a pipeline of codecs how the bytes of a chunk become the array's
elements. The v2 layout's manifest is a dotfile and the v3 layout's is not,
so the two are told apart by their content and not by their name, and every
JSON file in the tree is handed to the adapter to be declined.

The **consolidated metadata** of a v2 group is read too: one `.zmetadata`
holds the manifest of every array of the group, and the chunks of an array
are in the array's own directory, not beside the `.zmetadata`.

The v3 pipeline's **transpose** codec is read too. It permutes the axes of
a chunk's elements, and it is an array-to-array codec, so it sits before
the `bytes` codec in the pipeline — `[transpose, bytes, zstd]` and not
`[bytes, transpose, zstd]` — and the reader puts the axes back, so the
values come out with the array's own axes and not with the order they were
stored in.

What is refused is refused by name: a transpose whose order is not a
permutation of the array's axes, and a transpose that comes after the
`bytes` codec, which is a pipeline `zarr-python` refuses.

The oracle is `zarr-python` itself, version 3.4.1: the v3 array, the
transposed array and the consolidated group of the fixtures are read back by
it before they are committed, and the two refusals above are the ones it
makes too — `There must not be duplicates in the 'order' tuple` for an order
that is not a permutation, and `Invalid codec order` for a transpose that
comes after the bytes codec.

A netCDF classic file (CDF-1) or 64-bit-offset one (CDF-2) is a header and a
data section. The header says the dimensions, the variables with their types
and shapes, and the attributes; the data section holds the values, and the
reader reads them too -- **one line per element, with the index that locates
it**:

```
value time[0] = 0
value time[1] = 1
```

The trap is the record. A record variable -- one whose first dimension is the
record dimension, the one the header stores as length zero -- is not a block
of its own: a record holds one element of *every* record variable, in the
order the file lists them, and each of them is padded to four bytes. The
distance between two records is therefore the size of a whole record, and
the size of a record is the sum of what each record variable needs. The
file says both: the offset of every record variable, and the size of one
record of it.

The oracle is the `ncdump` output the netCDF library ships for the fixture,
`ncdump/ref_test_360_day_1900.cdl`: it renders the variable with the units
and the calendar the file itself declares, so the value at index *i* is the
date *i* days after 1900-01-01 in a 360-day calendar. The test reads the
dates out of that file and checks them against the ones the reader gives.

A dataset of an HDF5 file holds its data where the file's **layout
message** says: in the message itself (compact), in one block at an
address (contiguous), or in chunks. The first two are read, and the
values are one line per element, with the index that locates it:

```
value: var[0] = {x: 1, y: -2}
value: time[17] = 17
```

The trap is in the message itself: the class that says which of the three
it is sits in a **different byte depending on the version of the
message**. The first two versions put it after the dimensionality, and
the third and the fourth put it right after the version; reading it in
the wrong place gives a class that does not exist, and the data of the
dataset is never found.

The **values** of a NASA CDF-3 variable are read too: the blocks a chain
of index records points at, one line per element, with the index that
locates it. A variable whose data the file compressed, or whose records
are sparse, or whose type carries an encoding of its own, is not read --
and the report says which is which.

A dataset whose data is in **chunks** is read too: the chunks are indexed
by a v1 B-tree, whose key says how big each chunk is on the disk, which
filters were applied to it, and where it starts in the dataset.

The **filters** are undone where the reader can: the shuffle, which
interlaces the bytes of the elements, the Fletcher-32, which appends
a checksum of the data — the reader takes the checksum off and checks
it, and the file's own checksum is the oracle for the bytes — and the
**deflate**, which compresses the result. The HDF5 library's deflate
filter holds a zlib stream, not a raw DEFLATE one, and the reader
inflates it under the ceiling the chunk's own size gives: a chunk that
expands past it is refused, not expanded. A chunk in the **old
layout** is read too: a layout message of the first two versions counts
the size of an element as a dimension of its own, and the reader reads
the chunk's shape without it, so the index of a value is the dataset's
coordinate and not the chunk's.

The oracle is the `ncdump` output the netCDF library ships for the
fixture: its `data:` section holds the value of every variable, and the
reader gives the same 1,171 values, in the same order.

A group in the **old format** keeps its names in a symbol table: a tree
that indexes the nodes of the table, and a local heap that holds the
names. The reader walks both, and the groups below the root with them.

The trap is in the header of the objects of such a file: a **version 1**
object header says how many messages the whole object has, and how many
bytes of them are in the header itself — the rest are in the blocks that
a header continuation message names, and such a block has no signature.

HDF5 is the reader that grew teeth. The superblock is fixed-offset, so it
was always read, but the names were not: the newest netCDF-4 layout keeps
the group and dataset names in a **fractal heap** indexed by a **v2
B-tree**, and the object header carries only a Link Info message pointing
at both. The reader walks that chain — v2 object header, Link Info
message, B-tree (including the records a split moves up into an internal
node, which is why the tree holds more records than its leaves), and the
heap's direct blocks, one Link message each — and reports the names the
file actually holds:

```
link: Dr: dimension scale: float32 dims=[0]
link: c: dataset: char dims=[]
link: cr: dataset: char dims=[2]
```

A group with few enough members gets no heap: HDF5 keeps its names in
the group's own object header, as **link messages**, and leaves the
heap's address undefined. That is the common case in a small file, and
the reader reads that storage too:

```
link: cmp_t: committed datatype: compound
link: n: dimension scale: float32 dims=[1]
link: var: dataset: compound dims=[1]
```

The object header of a small object is also too small for all its
messages, and the file puts the rest in **continuation chunks**; those
are followed too, so a dataset whose layout message is over there is
still a dataset and not a committed type. A type the file shares with
other objects is followed to the object header that holds it, so a
variable on a committed type says `compound` and not nothing.

A group that keeps its links the old way (a symbol table in a v1 object
header) has no link message to read, and there the reader falls back to
the printable strings in the header window, labelled as the guess they
are. The `ncdump` output the netCDF library ships for the fixtures is
the oracle: the test compares the reader's names against it, name for
name and in order.

The **attributes** are read too, and they are the file's own words: the
file's own attributes and the ones of every member, each with the value
the attribute's own datatype gives it.

```
attribute: <root>: Gb = -128, 127
attribute: dim: CLASS = DIMENSION_SCALE
attribute: int_var: int_attr = 17
```

An attribute may hold several elements, and each one is decoded on its
own. A number is a number, a string is a string, and a value that is
neither — a reference, a variable-length value, a byte that is not text
— is reported as the bytes it is, in hex: a number that is not a number
is a lie. The same oracle lists the attributes, and the test compares
them one by one.

The **members of a type** are read too: the names of an enumeration with
the values the file gives them, and the names of a compound with the
types they hold. A file that stores the same type twice — once as a
committed type, once inside the variable that uses it — lists the
members of that type once.

```
member: cargo: dogs = 5000000
member: cmp_t: y = float64
```

The oracle for the compound is the same `ncdump` output: it declares the
type `cmp_t` and its members inside the braces. The enumeration has no
`ncdump` reference in the netCDF library, so its oracle is the source
that wrote the file — the library's own `nc_test4/tst_enums.c`, which
defines the type `cargo` and the eight members it gives.

## Feature flags

`std` is in `default` and pulls in `rusqlite`. With it off the crate
stays `no_std` + `alloc`, and the two database adapters and the Zarr one --
which reads the chunks beside the manifest -- are not compiled at all. The
rest are.

## Licence

Apache-2.0 only. The layout of `src/databases.rs` (Redis and liblzf) and
`src/lmdb.rs` (LMDB) was learned from those implementations, which are the
descriptions of those formats that exist; the code in both files is the
crate's own. See [LICENSE-APACHE](https://github.com/danalec/rgx/blob/main/crates/rgx-adapters-tabular/LICENSE-APACHE), and the
repository's [COPYING](https://github.com/danalec/rgx/blob/main/COPYING) for what the licence covers and what
it does not.
