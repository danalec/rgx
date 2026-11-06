# rgx-adapters-tabular

## Overview

The tabular / geospatial / database family of `rgx`. Its premise is on the
crate's own header: **databases are dumped as grep-friendly TSV (schema +
rows) rather than queried** — the whole point is making them greppable, not
serving SQL.

The family covers the SQL databases (SQLite, DuckDB), the file databases
(Visual FoxPro container + memo, DBF, Microsoft Access Jet/ACE, LMDB), the
spreadsheet interchange formats (SYLK, DIF, Lotus 1-2-3), the geospatial
shapefile, the columnar stores (Parquet, Arrow IPC / Feather), the
scientific containers (MATLAB v5, netCDF-3, NASA CDF-3, HDF5), the key-value
stores (BSON, Redis RDB, Redis AOF, LevelDB / RocksDB), the NTFS path index
(`.eri`) and the Zarr array.

The crate is `#![no_std]` + `alloc` by default. The `std` feature is not
cosmetic: it is pulled in by `sqlite` (which deserializes the database
into memory through `rusqlite`), by `duckdb` and by `zarr` (which reads the
array's chunk files from disk). Every other adapter is pure byte slicing.
Each adapter sits behind a Cargo feature named after the format it reads.

## Subdirectories & Boundaries

- `src`: [src/EGM.md](./src/EGM.md) — the whole implementation: the
  `adapters()` factory, the SQL and file database readers in `lib.rs`
  (`Sqlite`, `DuckDb`, `Dbf`, `Shp`, `Parquet`), and the per-family
  modules (`databases`, `dif`, `eri`, `hdf5`, `leveldb`, `lmdb`, `lotus`,
  `mdb`, `redis_aof`, `scientific`, `sylk`, `zarr`). Public symbols:
  `pub fn adapters()`, `pub struct Sqlite`, `pub struct DuckDb`, `pub struct
  Dbf`, `pub struct Shp`, `pub struct Parquet`, `pub mod dif` (`pub struct
  Dif`), `pub mod lotus` (`pub struct Lotus`), `pub mod mdb` (`pub struct
  Mdb`), `pub mod zarr` (`pub struct Zarr`), and `impl Adapter` for each
  adapter. The readers of the private modules — `databases::Bson`,
  `databases::RedisRdb`, `databases::Foxpro` (a `pub(crate)` struct),
  `eri::Eri`, `leveldb::LevelDb`, `lmdb::Lmdb`, `redis_aof::RedisAof`,
  `scientific::MatV5`, `scientific::NetCdf3`, `scientific::ArrowIpc`,
  `scientific::Hdf5` and `sylk::Slk` — are crate-internal and are not
  nameable from outside the crate.
