# rgx-adapters-tabular/src

## Overview

The implementation of the tabular family. `lib.rs` holds the crate's
`no_std` shell, the `adapters()` factory and the five readers that live
there; the other modules hold one format family each.

The shape follows the premise: **databases are dumped as grep-friendly TSV
(schema + rows) rather than queried**. The output of every reader is a
table in text, so a search over a database file is a search over a table,
and the schema is in the answer because a column name is half of what a
row means.

## Interface

Only `dif`, `lotus`, `mdb` and `zarr` are public modules; the readers of
the other ones are crate-internal and no item of theirs is nameable from
outside the crate.

- `pub fn adapters() -> Vec<Box<dyn Adapter>>` — the factory the binary's
  registry consumes. **Order is part of the contract**: the registry
  resolves by extension and the first matching available adapter wins.
- `pub struct Sqlite` (feature `sqlite`, which implies `std`) — `impl
  Adapter`: `name() == "sqlite"`,
  `extensions() == &["sqlite", "sqlite3", "db", "db3", "sdb", "rdb"]`.
- `pub struct DuckDb` (feature `duckdb`, which implies `std`) — `impl
  Adapter`: `name() == "duckdb"`, `extensions() == &["duckdb"]`.
- `pub struct Dbf` (feature `dbf`) — `impl Adapter`: `name() == "dbf"`,
  `extensions() == &["dbf", "dbc"]`.
- `pub struct Shp` (feature `shp`) — `impl Adapter`: `name() == "shp"`,
  `extensions() == &["shp"]`.
- `pub struct Parquet` (feature `parquet`) — `impl Adapter`:
  `name() == "parquet"`, `extensions() == &["parquet"]`.
- `pub mod dif` (feature `dif`) — `pub struct Dif` — `impl Adapter`:
  `name() == "dif"`, `extensions() == &["dif"]`, `reach() == Reach::Render`.
- `pub mod lotus` (feature `lotus`) — `pub struct Lotus` — `impl Adapter`:
  `name() == "lotus123"`,
  `extensions() == &["wks", "wk1", "wk2", "wk3", "wk4", "123", "wkb"]`.
- `pub mod mdb` (feature `mdb`) — `pub struct Mdb` — `impl Adapter`:
  `name() == "mdb"`,
  `extensions() == &["mdb", "accdb", "accde", "accdt", "mda"]`.
- `pub mod zarr` (feature `zarr`, which implies `std`) — `pub struct Zarr`
  — `impl Adapter`: `name() == "zarr"`,
  `extensions() == &["zarray", "zmetadata", "json"]`.
- `mod databases` (private) — the container whose value is structure:
  - `pub struct Bson` (feature `bson`) — crate-internal: `impl Adapter`:
    `name() == "bson"`, `extensions() == &["bson"]`.
  - `pub struct RedisRdb` (feature `redis-rdb`) — crate-internal: `impl
    Adapter`: `name() == "redis-rdb"`, `extensions() == &["rdb"]`.
  - `pub(crate) struct Foxpro` (feature `foxpro`) — crate-internal: `impl
    Adapter`: `name() == "foxpro"`,
    `extensions() == &["dbc", "dct", "fpt", "dcx", "cdx"]`.
- `mod eri` (private, feature `eri`) — `pub struct Eri` — crate-internal:
  `impl Adapter`: `name() == "eri"`, `extensions() == &["eri"]`.
- `mod leveldb` (private, feature `leveldb`) — `pub struct LevelDb` —
  crate-internal: `impl Adapter`: `name() == "leveldb"`,
  `extensions() == &["ldb", "log", "sst"]`.
- `mod lmdb` (private, feature `lmdb`) — `pub struct Lmdb` — crate-internal:
  `impl Adapter`: `name() == "lmdb"`, `extensions() == &["mdb"]`.
- `mod redis_aof` (private, feature `redis-aof`, which implies `redis-rdb`)
  — `pub struct RedisAof` — crate-internal: `impl Adapter`:
  `name() == "redis-aof"`, `extensions() == &["aof"]`.
- `mod scientific` (private) — the scientific containers:
  - `pub struct MatV5` (feature `matv5`) — crate-internal: `impl Adapter`:
    `name() == "mat"`, `extensions() == &["mat"]`.
  - `pub struct NetCdf3` (feature `netcdf3`) — crate-internal: `impl
    Adapter`: `name() == "netcdf"`, `extensions() == &["nc", "cdf",
    "netcdf"]`.
  - `pub struct ArrowIpc` (feature `arrow`) — crate-internal: `impl
    Adapter`: `name() == "arrow"`, `extensions() == &["arrow", "feather"]`.
  - `pub struct Hdf5` (feature `hdf5`) — crate-internal: `impl Adapter`:
    `name() == "hdf5"`,
    `extensions() == &["h5", "hdf5", "he5", "h5ad", "nc", "mat"]`.
- `mod sylk` (private, feature `slk`) — `pub struct Slk` — crate-internal:
  `impl Adapter`: `name() == "slk"`, `extensions() == &["slk"]`,
  `reach() == Reach::Render`.
- `mod hdf5` (private) — crate-internal (`pub(crate)`): `Link`, `Attribute`,
  `Member`, `Value`, `Truncated`, `Report`, `Kind`, `Superblock`,
  `pub(crate) fn superblock(data: &[u8]) -> Result<Superblock, String>` and
  `pub(crate) fn report(data: &[u8], root_addr: u64, so: usize, sl: usize) ->
  Result<Option<Report>, String>`.

## Invariants

- The crate is `#![no_std]` + `alloc` by default. The `std` feature is
  pulled in by `sqlite`, `duckdb` and `zarr`, and by nothing else; every
  other reader is pure byte slicing.
- Every adapter sits behind a Cargo feature named after the format it
  reads; the default build carries all of them.
- **The order in `adapters()` is a contract.**
  - The Visual FoxPro container and its memo file come **before** `dbf`:
    the container's rows name the block their text is in and the memo file
    is where the text is — read together, the row carries the sentence
    instead of the number. The `dbf` reader still answers a container that
    has no memo file beside it.
  - `.mdb` is claimed by both Jet/Access and LMDB, and the order does not
    matter because the two magic numbers are disjoint: Jet is
    `00 01 00 00` at offset 0 and LMDB is `0xBEEFC0DE`, so whichever runs
    first declines a file belonging to the other.
- A file that is not the format is declined (magic check) rather than
  answered, so the raw bytes stay searchable.
- **The SQLite reader deserializes in memory** through `sqlite3_deserialize`
  (zero temp-file I/O), dumps `sqlite_master` and then every table as TSV.
- The DuckDB reader takes the printable strings of the file and stops
  there: the catalog is a DuckDB structure this adapter does not parse, so
  it has no column names to report as facts. Saying so is better than
  inventing them.
- **A netCDF-4 file keeps its names in a fractal heap, and the heap is not
  the only place.** Reading them means four structures in order, and a
  split moves the separator record up into the internal node, so the tree
  holds *more* records than its leaves and a walk that reads only the
  leaves comes up short. A small group has no heap at all, a small object
  header keeps its other messages in **continuation chunks** (`OCHK`), and
  a datatype the file shares with other objects is a pointer to the object
  header that holds it — so a reader that follows only one of those places
  finds no names, or no type, and falls back to the printable strings it
  can see, which are fragments of the header and not names.
- **The data of a dataset is not where the layout message says it is, in
  every version of the message.** The class of the layout message says
  whether the data is in the message itself (compact), in one block at an
  address (contiguous) or in chunks — and the class sits in a different
  byte depending on the version: the first two versions put it after the
  dimensionality, the third and the fourth put it right after the
  version. Reading it in the wrong place gives a class that does not exist
  (255, 124, 169), and the data of the dataset is never found.
- The chunks of a chunked dataset are indexed by a chunk index whose shape
  the layout message names: `Btree1` (the v1 B-tree), `Single`, `Implicit`,
  `FixedArray`, `ExtensibleArray` and `Btree2`. The key of a chunk says
  three things at once: the size of its data on the disk, the mask of the
  filters that were applied to it, and the offset of the chunk in each of
  the dataset's dimensions — an offset that has to start on a chunk
  boundary, or the tree is corrupt. The mask is a mask of **IDs**, not of
  names, and its sense is inverted from the obvious reading: a **clear**
  bit means that filter was applied and a **set** bit means it was skipped.
  `undo_filters` undoes shuffle, Fletcher-32 and deflate, and refuses an
  unknown filter by name rather than handing out compressed bytes as values.
- The values of a chunked dataset are read: `dataset_values` walks the chunk
  index and emits one line per element, with the index that locates it. The
  regression tests pin the values of a chunked dataset and of the newest
  chunk-index shapes.
- **A version 1 object header counts the messages of the whole object, and
  keeps only some of them.** The header says how many messages the object
  has and how many bytes of them are in the header itself; the rest are in
  the blocks that a header continuation message names, and such a block has
  no signature. A reader that takes the header's count as the number of
  messages in its own bytes reads a group as an object with no layout and
  no type.
- The symbol table of an old-style group is read: the tree that indexes
  the nodes of the table, the local heap that holds the names, and the node
  itself. The MATLAB v7.3 file, which used to report the internals of the
  file (`TREE`, `HEAP`, `SNOD`), reports its variables.
- **A file may open with a user block.** HDF5 lets the writer keep the
  first bytes for itself, and the library finds the superblock by looking
  for the signature at the powers of two from 512 up. MATLAB's v7.3 `.mat`
  is exactly that — 512 bytes of `MATLAB 7.3 MAT-file, Platform: …` and
  then the HDF5 file — so a reader that looks for the signature at offset 0
  refuses every real v7.3 file, and the `.mat` falls to the v5 reader,
  which finds the `IM` endian marker at byte 126 and walks HDF5 bytes as v5
  tags. **The magic decides which family a file belongs to; the extension
  only decides who is asked first, and the reader that does not own the
  file has to decline it rather than answer it.**
- A netCDF-4 file's attributes are in the object header, and they are the
  file's own words: a number as a number, a string as a string, and the
  bytes of a value that is neither as hex, because a number that is not a
  number is a lie. Two traps are load-bearing: the attribute's **version
  3** header, which puts a character set between the header and the name,
  and the **null dataspace** (`H5S_NULL`), which says the value has no
  elements at all and writes no bytes for it — an empty string attribute is
  exactly that.
- A type the file stores twice — once as a committed type, once inside the
  variable that uses it — is listed once.
- A netCDF classic file's values are in its data section, and **a record
  variable's are not where its own block would be.** A record variable —
  one whose first dimension is the record dimension, the one the header
  stores as length zero — is not a block of its own. A record holds one
  element of *every* record variable, in the order the file lists them, and
  each of them is padded to four bytes, so the distance between two
  records is the size of a whole record. The file says both: the offset of
  every record variable (`begin`) and the size of one record of it
  (`vsize`).
- The LevelDB reader is **routed on structure, not on the name**: a `.log`
  is a write-ahead log only if its records are framed the way one frames
  them, and a file whose records are framed differently is read as what it
  is.
- The Redis AOF reader prints the commands with their database selector
  kept, rather than replaying them into a keyspace: a replay would throw
  away the ordering and the arguments that make a log worth grepping.
- The DIF and SYLK adapters declare `Reach::Render`: they are plain text
  that ripgrep already reads, and the rendering is *lossy* about it (the
  section keywords and the formatting records are consumed rather than
  emitted), which is exactly why they are renderings and not answers.
- The `.eri` adapter decodes the bytes of an NTFS path index and does not
  open a volume: it is not a query engine, it runs unprivileged, on any
  platform, and needs no NTFS.
- The Zarr adapter reads the **values, not the manifest**: the manifest is
  JSON that ripgrep reads perfectly, and the chunks beside it are what say
  nothing about what they hold. It keeps the manifest's own bytes in the
  answer so the JSON is still there to be searched, and it **declines**
  every JSON file that is not Zarr metadata — the extension list claims
  `json` because the v3 layout's node metadata is a JSON file, so every
  JSON file in the world is handed to this adapter.
- The Zarr reader is bounded: at most `MAX_VALUES` (4 000 000) rendered
  values per array, at most `MAX_CHUNK_BYTES` (64 MiB) expanded per chunk
  and at most `MAX_OUT` (64 MiB) of rendered output.

## Side Effects

- **The Zarr adapter reads the filesystem**: it opens the chunk files
  beside the array's manifest (`std::fs::read` on
  `<the array's directory>/<the chunk name>`). It is the only adapter in
  this crate that touches the disk, and the only reason the `zarr` feature
  implies `std`.
- The SQLite reader uses `rusqlite` with the `bundled` feature and
  deserializes the bytes into an **in-memory** database — no temp file is
  written.
- Every other adapter is a pure function over `&[u8]`: nothing is read
  from disk, no process is spawned, no socket is opened, no clock or
  environment variable is consulted, and no lock is taken.
- The crate allocates through `alloc`.

## Verification

- Run: `cargo test --release --locked --workspace`
