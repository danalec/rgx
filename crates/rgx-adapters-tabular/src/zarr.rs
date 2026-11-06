// SPDX-License-Identifier: Apache-2.0

//! Zarr arrays — the values, not the manifest.
//!
//! **What this is.** A Zarr array is a directory: a file that describes the
//! array — its shape, its dtype, its chunk size, the codec the chunks are
//! compressed with — and the chunks themselves, one file per chunk, each
//! named by its index. The description is the manifest; the data is in the
//! chunks, and the chunks are what this adapter reads.
//!
//! There are two layouts. The **v2** one puts the manifest in a `.zarray`
//! beside the chunks and names the chunks by their indices joined by a
//! separator. The **v3** one puts the node's metadata in a `zarr.json`,
//! names the chunks with a key encoding, and says in a pipeline of codecs
//! how the bytes of a chunk become the array's elements. The v3 layout is
//! what `zarr-python` writes by default.
//!
//! **Why the manifest is not the answer.** The manifest is JSON, and
//! ripgrep reads JSON perfectly well. But it *describes* the array rather
//! than holding it: the same eight bytes are eight `u1`, one `f8` or a
//! ten-character string depending on the `dtype` line, and a chunk says
//! nothing at all about which. An adapter that answered with the manifest
//! would report the array's shape and none of its values.
//!
//! **The manifest is kept in the answer.** The rendering starts with the
//! manifest's own bytes, so a search for a key in the JSON still finds
//! it: rgx is a superset of ripgrep, and that has to hold for the file
//! this adapter takes over.
//!
//! **What is read.** Both layouts, with a directory store: the manifest
//! and the chunks beside it. The codecs are the ones the `numcodecs`
//! package defines — zlib, gzip, zstd, bzip2, blosc, and the uncompressed
//! case — plus the `delta` filter, whose decoder is a running sum along the
//! last axis, and the v3 layout's `transpose` codec, which puts a chunk's
//! axes back the way the array has them.
//!
//! The v3 layout's **sharding** codec is read too: a shard holds several
//! inner chunks and an index that says where each of them is. The reader
//! goes through the index, because the specification does not fix the
//! order of the chunks inside a shard.
//!
//! The v3 layout's **rectilinear** chunk grid is read as well: its chunks
//! have an edge of their own along each axis, and the edges are what the
//! grid is. The core specification has no chunk grid but the regular one;
//! the rectilinear grid is specified in `zarr-extensions`, and that is
//! where its name comes from.
//!
//! The **consolidated metadata** of the v2 layout is read too: one
//! `.zmetadata` file holds the manifest of every array of a group, and the
//! chunks of an array are in the array's own directory.
//!
//! **What is refused.** The chunk grids that are neither regular nor
//! rectilinear, a transpose whose order is not a permutation of the
//! array's axes, and a sharding codec whose inner pipeline this reader
//! does not decode. They are a different layout, and one layout read
//! correctly is worth more than two read approximately.
//!
//! The **blosc** codec, the one `zarr-python` asks for by default, *is*
//! decoded: the frame is a header, a table of block offsets and the blocks,
//! and the blocks are LZ4 with the byte shuffle applied to them. The
//! frames were checked against the two implementations that write them --
//! c-blosc itself and `numcodecs`, the codec library `zarr-python` sits
//! on -- so the numbers are not a decoder's own opinion of its own output.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use std::path::Path;

use rgx_core::djson::{parse as parse_json, Arena, Value};
use rgx_core::{bail, decline, Adapter, Field, Outcome, Result};

/// Ceiling on the chunks read for one array. A grid of a billion chunks
/// is a refusal, not a truncation: an array whose values stop half way
/// through is indistinguishable from a small one, and a caller that
/// cannot tell those apart is worse off than one that is told no.
const MAX_CHUNKS: usize = 65_536;

/// Ceiling on the values rendered for one array.
const MAX_VALUES: usize = 4_000_000;

/// Ceiling on the bytes one chunk may expand to.
const MAX_CHUNK_BYTES: u64 = 64 << 20;

/// Ceiling on the rendered output.
const MAX_OUT: usize = 64 << 20;

pub struct Zarr;

impl Adapter for Zarr {
    fn name(&self) -> &'static str {
        "zarr"
    }

    fn extensions(&self) -> &'static [&'static str] {
        // The v2 layout's manifest, the v2 layout's consolidated metadata,
        // and the v3 layout's node metadata -- which is a JSON file, so
        // every JSON file in the world is handed to this adapter, and the
        // ones that are not Zarr metadata are declined.
        &["zarray", "zmetadata", "json"]
    }

    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(render(data, path)?))
    }

    fn facts(&self, data: &[u8], _path: &str) -> Vec<Field> {
        let Ok(text) = core::str::from_utf8(data) else {
            return Vec::new();
        };
        let Ok(arena) = parse_json(text) else {
            return Vec::new();
        };
        let root = arena.root();
        // The consolidated metadata holds the manifests of a whole group,
        // so it has a fact for each of the arrays it names.
        if root.get(&arena, "zarr_consolidated_format").is_some() {
            return group_facts(&arena, &root);
        }
        let Ok(m) = Manifest::from_json(&arena, &root) else {
            return Vec::new();
        };
        vec![
            Field::new("zarr.shape", &m.shape_text()),
            Field::new("zarr.chunks", &m.chunks_text()),
            Field::new("zarr.dtype", &m.dtype_text()),
            Field::new("zarr.compressor", &m.codec_text()),
            Field::new("zarr.order", &m.order.to_string()),
        ]
    }
}

/// The manifest: everything the `.zarray` or the `zarr.json` says about the
/// array.
struct Manifest {
    shape: Vec<u64>,
    /// The chunk grid: where the chunks are, and how big they are.
    grid: Grid,
    dtype: Dtype,
    /// How the bytes of a chunk become the array's elements.
    plan: Plan,
    /// The value a missing element takes, already formatted for the dtype.
    fill: String,
    order: char,
    /// The prefix every chunk's name carries, and the separator between the
    /// indices in it: `.` or `/`.
    prefix: String,
    sep: char,
    /// The `delta` filter's accumulator dtype, when the filter is there.
    delta: Option<Dtype>,
}

/// The chunk grid: where the chunks are, and how big they are.
#[derive(Clone)]
enum Grid {
    /// The regular grid: every chunk has the same shape, and the chunks
    /// tile the array from one end of it to the other.
    Regular(Vec<u64>),
    /// The rectilinear grid: each chunk has an edge of its own along each
    /// axis, and the edges run along the axis from one end of it to the
    /// other.
    Rectilinear {
        /// The length of each chunk's edge along each axis.
        edges: Vec<Vec<u64>>,
        /// The coordinate each edge starts at, along each axis.
        starts: Vec<Vec<u64>>,
        /// The number of chunks along each axis: the edges that reach into
        /// the array. The edges past the end of it hold nothing.
        counts: Vec<u64>,
    },
}

impl Grid {
    /// The shape of the chunk at these grid coordinates.
    fn chunk_shape(&self, indices: &[u64]) -> Vec<u64> {
        match self {
            Grid::Regular(shape) => shape.clone(),
            Grid::Rectilinear { edges, .. } => edges
                .iter()
                .enumerate()
                .map(|(k, axis)| axis[indices[k] as usize])
                .collect(),
        }
    }

    /// The coordinate of the chunk's first element, in the array.
    fn origin(&self, indices: &[u64]) -> Vec<u64> {
        match self {
            Grid::Regular(shape) => indices
                .iter()
                .zip(shape.iter())
                .map(|(i, c)| i * c)
                .collect(),
            Grid::Rectilinear { starts, .. } => starts
                .iter()
                .enumerate()
                .map(|(k, axis)| axis[indices[k] as usize])
                .collect(),
        }
    }

    /// The number of elements in the largest chunk of the grid.
    fn max_chunk_len(&self) -> usize {
        match self {
            Grid::Regular(shape) => shape.iter().map(|c| *c as usize).product(),
            Grid::Rectilinear { edges, .. } => edges
                .iter()
                .map(|axis| axis.iter().copied().max().unwrap_or(0) as usize)
                .product(),
        }
    }

    /// The grid's own text: the chunk shape of the regular grid, and the
    /// edges of the rectilinear one.
    fn text(&self) -> String {
        match self {
            Grid::Regular(shape) => bracket(shape),
            Grid::Rectilinear { edges, .. } => {
                let mut out = String::from("[");
                for (k, axis) in edges.iter().enumerate() {
                    if k > 0 {
                        out.push_str(", ");
                    }
                    out.push('[');
                    for (i, e) in axis.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        let _ = write!(out, "{e}");
                    }
                    out.push(']');
                }
                out.push(']');
                out
            }
        }
    }
}

/// How the bytes of a chunk become the array's elements.
enum Plan {
    /// The v2 layout: one compressor, and the filters after it.
    V2 { codec: Codec },
    /// The v3 layout: a pipeline of codecs, from the array's bytes outwards.
    V3 {
        steps: Vec<Step>,
        /// The permutation the pipeline's transpose codec applies to a
        /// chunk's elements: the stored axis `i` holds the chunk's axis
        /// `transpose[i]`. `None` when the pipeline has no transpose.
        transpose: Option<Vec<usize>>,
    },
}

/// One step of the v3 codec pipeline.
enum Step {
    /// The bytes themselves: the step that says the elements are in the
    /// byte order the data type names.
    Bytes,
    /// zstd.
    Zstd,
    /// gzip.
    Gzip,
    /// blosc.
    Blosc,
    /// The sharding codec: a shard holds several inner chunks, and an index
    /// that says where each of them is.
    Sharding(Sharding),
}

impl Step {
    /// The name the codec goes by.
    fn name(&self) -> &'static str {
        match self {
            Step::Bytes => "bytes",
            Step::Zstd => "zstd",
            Step::Gzip => "gzip",
            Step::Blosc => "blosc",
            Step::Sharding(_) => "sharding_indexed",
        }
    }
}

/// The sharding codec: the shape of an inner chunk, the pipeline an inner
/// chunk's bytes go through, and where the index is.
struct Sharding {
    /// The shape of one inner chunk.
    chunk_shape: Vec<u64>,
    /// The pipeline an inner chunk's bytes go through.
    steps: Vec<Step>,
    /// Whether the index is at the start of the shard. The default is the
    /// end of it.
    index_at_start: bool,
    /// Whether the index carries a crc32c checksum.
    crc32c: bool,
}

/// The bytes of a chunk, and the parts of it that are not there.
struct Decoded {
    /// The bytes of the chunk's elements.
    bytes: Vec<u8>,
    /// The regions of the chunk that are not there: their elements are the
    /// fill value. A shard's index says which of its inner chunks are
    /// missing.
    empty: Vec<Region>,
}

/// A region of a chunk: the part of it that is not there.
struct Region {
    /// Where the region starts, in the chunk's own coordinates.
    origin: Vec<u64>,
    /// How big the region is.
    shape: Vec<u64>,
}

impl Region {
    /// Whether a coordinate of the chunk falls in the region.
    fn holds(&self, coords: &[usize]) -> bool {
        coords.iter().enumerate().all(|(k, c)| {
            let start = self.origin[k] as usize;
            *c >= start && *c < start + self.shape[k] as usize
        })
    }
}

impl Manifest {
    /// Read the manifest, or decline: a file that is not a Zarr manifest is
    /// not this adapter's, and the next candidate should have it.
    ///
    /// The consolidated metadata of a group holds a manifest per array, so
    /// this is what reads each of them.
    fn from_json(arena: &Arena, root: &Value) -> Result<Manifest> {
        match root.get(arena, "zarr_format").and_then(|v| v.as_i64()) {
            Some(2) => Manifest::parse_v2(arena, root),
            Some(3) => Manifest::parse_v3(arena, root),
            Some(other) => bail!("zarr: zarr_format {other} is not a layout this adapter reads"),
            None => decline!("zarr: the manifest has no zarr_format"),
        }
    }

    /// The v2 layout: the `.zarray` beside the chunks.
    fn parse_v2(arena: &Arena, root: &Value) -> Result<Manifest> {
        let shape = numbers(arena, root, "shape")?;
        let chunks = numbers(arena, root, "chunks")?;
        if shape.is_empty() || shape.len() != chunks.len() {
            bail!(
                "zarr: the shape has {} dimensions and the chunk shape has {}",
                shape.len(),
                chunks.len()
            );
        }
        if chunks.contains(&0) {
            bail!("zarr: a chunk dimension of zero would make the grid empty");
        }

        let dtype = Dtype::parse(dtype_text(arena, root)?)?;
        let codec = Codec::parse(arena, root)?;
        let order = match root.get(arena, "order").and_then(|v| v.as_str(arena)) {
            None | Some("C") => 'C',
            Some("F") => 'F',
            Some(other) => bail!("zarr: the order {other:?} is neither C nor F"),
        };
        let sep = match root
            .get(arena, "dimension_separator")
            .and_then(|v| v.as_str(arena))
        {
            None | Some(".") => '.',
            Some("/") => '/',
            Some(other) => bail!("zarr: the dimension separator {other:?} is neither . nor /"),
        };

        let fill = fill_text(arena, root, &dtype)?;

        // The filters. Only the delta is decoded; the rest are named in
        // the manifest but not implemented, and an array whose values
        // would come out wrong is worse than one that is refused.
        let delta = match root.get(arena, "filters") {
            None | Some(Value::Null) => None,
            Some(v) => {
                let list = v
                    .as_array(arena)
                    .ok_or_else(|| rgx_core::Error::msg("zarr: the filters are not a list"))?;
                let mut delta = None;
                for f in list {
                    let id = f
                        .get(arena, "id")
                        .and_then(|v| v.as_str(arena))
                        .unwrap_or("");
                    match id {
                        "delta" => {
                            let acc = Dtype::parse(
                                f.get(arena, "dtype")
                                    .and_then(|v| v.as_str(arena))
                                    .unwrap_or(""),
                            )?;
                            if !acc.is_integer() {
                                bail!(
                                    "zarr: the delta filter accumulates in {acc}, which is not an integer type"
                                );
                            }
                            if let Some(ast) = f.get(arena, "astype").and_then(|v| v.as_str(arena))
                            {
                                if ast != dtype_text(arena, root)? {
                                    bail!(
                                        "zarr: the delta filter casts to {ast:?}, which is not the array's own type"
                                    );
                                }
                            }
                            delta = Some(acc);
                        }
                        other => bail!("zarr: the {other:?} filter is not decoded here"),
                    }
                }
                delta
            }
        };

        Ok(Manifest {
            shape,
            grid: Grid::Regular(chunks),
            dtype,
            plan: Plan::V2 { codec },
            fill,
            order,
            prefix: String::new(),
            sep,
            delta,
        })
    }

    /// The v3 layout: the `zarr.json` of an array.
    ///
    /// The metadata is in one file, the chunks are named by a key encoding,
    /// and a pipeline of codecs says how the bytes of a chunk become the
    /// array's elements. The pipeline runs from the array's bytes outwards:
    /// the `bytes` codec says the byte order the elements are in, and the
    /// codecs after it are the compressions.
    fn parse_v3(arena: &Arena, root: &Value) -> Result<Manifest> {
        let shape = numbers(arena, root, "shape")?;

        // The chunk grid: the shape of the chunks, in a regular grid, or
        // the edges of the chunks, in a rectilinear one.
        let grid = root
            .get(arena, "chunk_grid")
            .ok_or_else(|| rgx_core::Error::msg("zarr: the v3 manifest has no chunk grid"))?;
        let grid_name = grid
            .get(arena, "name")
            .and_then(|v| v.as_str(arena))
            .unwrap_or("");
        let grid_config = grid
            .get(arena, "configuration")
            .ok_or_else(|| rgx_core::Error::msg("zarr: the chunk grid has no configuration"))?;
        let grid = match grid_name {
            "regular" => {
                let chunks = numbers(arena, &grid_config, "chunk_shape")?;
                if shape.is_empty() || shape.len() != chunks.len() {
                    bail!(
                        "zarr: the shape has {} dimensions and the chunk shape has {}",
                        shape.len(),
                        chunks.len()
                    );
                }
                if chunks.contains(&0) {
                    bail!("zarr: a chunk dimension of zero would make the grid empty");
                }
                Grid::Regular(chunks)
            }
            "rectilinear" => rectilinear_grid(arena, &grid_config, &shape)?,
            other => bail!("zarr: the {other:?} chunk grid is not read here"),
        };

        // The codecs: the pipeline, and the byte order the elements are in.
        let list = root
            .get(arena, "codecs")
            .and_then(|v| v.as_array(arena))
            .ok_or_else(|| rgx_core::Error::msg("zarr: the v3 manifest has no codecs"))?;
        let mut steps: Vec<Step> = Vec::new();
        let mut big = false;
        let mut seen_bytes = false;
        let mut seen_sharding = false;
        let mut seen_compression = false;
        // The transpose codec's permutation of the axes, when the pipeline
        // has one. Several transposes make one permutation.
        let mut transpose: Option<Vec<usize>> = None;
        for step in list {
            let name = step
                .get(arena, "name")
                .and_then(|v| v.as_str(arena))
                .unwrap_or("");
            match name {
                "bytes" => {
                    if seen_sharding {
                        bail!(
                            "zarr: the bytes codec comes after the sharding codec, which is a pipeline zarr-python refuses"
                        );
                    }
                    big = parse_endian(arena, step)?;
                    seen_bytes = true;
                    steps.push(Step::Bytes);
                }
                "transpose" => {
                    // The transpose codec is an array-to-array codec: it
                    // rearranges the elements and not the bytes, so it
                    // sits before the bytes codec in the pipeline. One
                    // that comes after it is a pipeline `zarr-python`
                    // refuses, and it means something else entirely.
                    if seen_bytes {
                        bail!(
                            "zarr: the transpose codec comes after the bytes codec, which is a pipeline zarr-python refuses"
                        );
                    }
                    if seen_sharding {
                        bail!(
                            "zarr: the transpose codec comes after the sharding codec, which is a pipeline zarr-python refuses"
                        );
                    }
                    let order = transpose_order(arena, step, shape.len())?;
                    transpose = Some(match transpose {
                        None => order,
                        Some(prev) => compose_order(&prev, &order),
                    });
                }
                "zstd" | "gzip" | "blosc" => {
                    seen_compression = true;
                    steps.push(match name {
                        "zstd" => Step::Zstd,
                        "gzip" => Step::Gzip,
                        _ => Step::Blosc,
                    });
                }
                // The sharding codec is the array-to-bytes step of the
                // pipeline: it holds the inner chunks of a shard and the
                // index that says where each of them is. Its own pipeline
                // is the one that says the byte order the elements are
                // in. The codec was called `sharding` before zarr-python
                // 3.4, and the specification kept the old name too.
                "sharding_indexed" | "sharding" => {
                    if seen_bytes {
                        bail!(
                            "zarr: the sharding codec comes after the bytes codec, which is a pipeline zarr-python refuses"
                        );
                    }
                    if seen_compression {
                        bail!(
                            "zarr: the sharding codec comes after a compression, which is a pipeline zarr-python refuses"
                        );
                    }
                    if seen_sharding {
                        bail!("zarr: the sharding codec comes twice, which is a pipeline zarr-python refuses");
                    }
                    if transpose.is_some() {
                        bail!("zarr: the transpose codec with the sharding codec is not read here");
                    }
                    let (sharding, endian) = parse_sharding(arena, step)?;
                    big = endian;
                    seen_sharding = true;
                    steps.push(Step::Sharding(sharding));
                }
                other => bail!("zarr: the {other:?} codec is not decoded here"),
            }
        }
        if !seen_bytes && !seen_sharding {
            // The byte order is the one the elements are in, and without
            // the codec that says it there is none to be had.
            bail!("zarr: the v3 manifest has no bytes codec, so the byte order is not established");
        }

        // The chunk key encoding: the prefix the names carry and the
        // separator between their indices.
        let key = root.get(arena, "chunk_key_encoding");
        let key_name = key
            .and_then(|k| k.get(arena, "name"))
            .and_then(|v| v.as_str(arena))
            .unwrap_or("");
        if key_name != "default" {
            bail!("zarr: the {key_name:?} chunk key encoding is not read here");
        }
        let key_config = key.and_then(|k| k.get(arena, "configuration"));
        let separator = key_config
            .and_then(|c| c.get(arena, "separator"))
            .and_then(|v| v.as_str(arena))
            .unwrap_or("/");
        let dimension_separator = key_config
            .and_then(|c| c.get(arena, "dimension_separator"))
            .and_then(|v| v.as_str(arena))
            .unwrap_or("/");
        if dimension_separator.len() != 1 {
            bail!("zarr: the dimension separator is not one character");
        }
        let prefix = format!("c{separator}");

        let dtype = Dtype::parse_v3(
            root.get(arena, "data_type")
                .and_then(|v| v.as_str(arena))
                .unwrap_or(""),
            big,
        )?;
        let fill = fill_text(arena, root, &dtype)?;

        Ok(Manifest {
            shape,
            grid,
            dtype,
            plan: Plan::V3 { steps, transpose },
            fill,
            // The v3 layout has no order of its own: the transpose codec
            // does that.
            order: 'C',
            prefix,
            sep: dimension_separator.chars().next().unwrap_or('/'),
            delta: None,
        })
    }

    fn shape_text(&self) -> String {
        bracket(&self.shape)
    }

    fn chunks_text(&self) -> String {
        self.grid.text()
    }

    fn dtype_text(&self) -> String {
        self.dtype.to_string()
    }

    fn codec_text(&self) -> String {
        match &self.plan {
            Plan::V2 { codec } => codec.to_string(),
            Plan::V3 { steps, transpose } => {
                let mut names: Vec<&str> = Vec::new();
                // The transpose is the innermost codec of the pipeline, so
                // it comes first.
                if transpose.is_some() {
                    names.push("transpose");
                }
                names.extend(
                    steps
                        .iter()
                        .filter(|s| !matches!(s, Step::Bytes))
                        .map(|s| s.name()),
                );
                if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join("+")
                }
            }
        }
    }

    /// The number of chunks along each dimension.
    fn grid(&self) -> Vec<u64> {
        match &self.grid {
            Grid::Regular(shape) => self
                .shape
                .iter()
                .zip(shape.iter())
                .map(|(s, c)| s.div_ceil(*c))
                .collect(),
            Grid::Rectilinear { counts, .. } => counts.clone(),
        }
    }

    /// The name of a chunk: its indices joined by the separator, under the
    /// prefix the key encoding gives.
    fn chunk_name(&self, indices: &[u64]) -> String {
        let mut name = self.prefix.clone();
        for (i, n) in indices.iter().enumerate() {
            if i > 0 {
                name.push(self.sep);
            }
            let _ = write!(name, "{n}");
        }
        name
    }

    /// The bytes one element takes.
    fn itemsize(&self) -> usize {
        self.dtype.itemsize()
    }

    /// The coordinates of the element at a C-order index inside a chunk.
    fn coords(&self, linear: usize, shape: &[u64]) -> Vec<usize> {
        let mut coords = vec![0usize; shape.len()];
        self.coords_into(linear, shape, &mut coords);
        coords
    }

    /// The coordinates of the element at a C-order index inside a chunk,
    /// into a buffer the caller owns.
    fn coords_into(&self, linear: usize, shape: &[u64], coords: &mut [usize]) {
        let mut rest = linear;
        for (k, c) in shape.iter().enumerate().rev() {
            let c = *c as usize;
            coords[k] = rest % c;
            rest /= c;
        }
    }

    /// The offset of an element in the chunk's buffer. In C order that is
    /// the C-order index itself; in F order the last dimension is the
    /// slowest one, and the strides are the other way round.
    fn offset(&self, coords: &[usize], linear: usize, shape: &[u64]) -> usize {
        if self.order == 'C' {
            return linear;
        }
        let mut offset = 0usize;
        let mut stride = 1usize;
        for (k, c) in coords.iter().enumerate() {
            offset += c * stride;
            stride *= shape[k] as usize;
        }
        offset
    }

    /// Whether an element of a chunk is inside the array's shape. The last
    /// chunk along a dimension is usually short, and the elements past the
    /// shape are the fill value.
    fn inside(&self, coords: &[usize], indices: &[u64]) -> bool {
        let origin = self.grid.origin(indices);
        coords.iter().enumerate().all(|(k, c)| {
            let global = origin[k] as usize + c;
            global < self.shape[k] as usize
        })
    }

    /// The values of the array, one line per chunk.
    ///
    /// The label goes in front of the chunk's own name, so that the chunks
    /// of two arrays of a group do not look alike.
    fn write_chunks(&self, dir: &Path, label: &str, out: &mut String) -> Result<()> {
        let grid = self.grid();
        let total: u64 = grid.iter().product();
        if total > MAX_CHUNKS as u64 {
            bail!("zarr: the array has {total} chunks, over the {MAX_CHUNKS} ceiling");
        }
        if self.grid.max_chunk_len().saturating_mul(total as usize) > MAX_VALUES {
            bail!("zarr: the array holds more than the {MAX_VALUES} values this adapter renders");
        }

        let mut indices = vec![0u64; grid.len()];
        for _ in 0..total {
            let name = self.chunk_name(&indices);
            let raw = match std::fs::read(dir.join(&name)) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => bail!("zarr: cannot read the chunk {name}: {e}"),
            };
            let values = self.chunk_values(&raw, &indices)?;
            let _ = writeln!(out, "chunk {label}{name}: {}", values.join(" "));
            if out.len() > MAX_OUT {
                bail!("zarr: the rendered array is over the {MAX_OUT} byte ceiling");
            }
            // The next chunk, counting up with the last dimension fastest.
            let mut k = indices.len();
            loop {
                if k == 0 {
                    break;
                }
                k -= 1;
                indices[k] += 1;
                if indices[k] < grid[k] {
                    break;
                }
                indices[k] = 0;
            }
        }
        Ok(())
    }

    /// The values of one chunk.
    fn chunk_values(&self, raw: &[u8], indices: &[u64]) -> Result<Vec<String>> {
        let shape = self.grid.chunk_shape(indices);
        let count: usize = shape.iter().map(|c| *c as usize).product();
        if raw.is_empty() {
            // The chunk is not there. Zarr says an absent chunk is the
            // fill value, everywhere.
            return Ok(vec![self.fill.clone(); count]);
        }
        let (bytes, empty) = match &self.plan {
            Plan::V2 { codec } => (codec.decode(raw)?, Vec::new()),
            Plan::V3 { steps, transpose } => {
                let decoded = self.decode_pipeline(raw, steps, &shape)?;
                let bytes = self.untranspose(&decoded.bytes, transpose.as_deref(), &shape)?;
                (bytes, decoded.empty)
            }
        };
        let bytes = self.unfilter(&bytes, count, shape.last().copied().unwrap_or(1))?;
        let want = count * self.itemsize();
        if bytes.len() < want {
            bail!(
                "zarr: the chunk holds {} bytes, short of the {want} its shape asks for",
                bytes.len()
            );
        }
        let mut out = Vec::with_capacity(count);
        for linear in 0..count {
            let coords = self.coords(linear, &shape);
            // The elements past the end of the array are the fill value,
            // and so are the elements of an inner chunk that the shard's
            // index says is not there.
            if !self.inside(&coords, indices) || empty.iter().any(|r| r.holds(&coords)) {
                out.push(self.fill.clone());
                continue;
            }
            let at = self.offset(&coords, linear, &shape) * self.itemsize();
            out.push(self.dtype.value(&bytes, at)?);
        }
        Ok(out)
    }

    /// The v3 codec pipeline, undone: the codecs are applied from the last
    /// to the first, because the pipeline runs from the array's bytes
    /// outwards.
    fn decode_pipeline(&self, raw: &[u8], steps: &[Step], shape: &[u64]) -> Result<Decoded> {
        let mut bytes = raw.to_vec();
        let mut empty = Vec::new();
        for step in steps.iter().rev() {
            bytes = match step {
                // The bytes codec says the byte order, and changes
                // nothing.
                Step::Bytes => bytes,
                Step::Zstd => {
                    rgx_core::compress::zstd::ZstdDecoder::new()
                        .decode_bounded(&bytes, MAX_CHUNK_BYTES)
                        .map_err(|e| {
                            rgx_core::Error::msg(format!("zarr: the chunk does not decode: {e}"))
                        })?
                        .bytes
                }
                Step::Gzip => {
                    rgx_core::compress::gzip::GzipReader::decode_bounded(&bytes, MAX_CHUNK_BYTES)
                        .map_err(|e| {
                            rgx_core::Error::msg(format!("zarr: the chunk does not inflate: {e}"))
                        })?
                        .bytes
                }
                Step::Blosc => {
                    rgx_core::compress::blosc::BloscDecoder::new()
                        .decode_bounded(&bytes, MAX_CHUNK_BYTES)
                        .map_err(|e| {
                            rgx_core::Error::msg(format!("zarr: the chunk does not decode: {e}"))
                        })?
                        .bytes
                }
                // The sharding codec is the array-to-bytes step of the
                // pipeline, so it is the last one undone: what comes out
                // of it is the shard's elements, and the inner chunks the
                // index says are not there are the fill value.
                Step::Sharding(sharding) => {
                    let decoded = self.decode_shard(&bytes, sharding, shape)?;
                    empty.extend(decoded.empty);
                    decoded.bytes
                }
            };
        }
        Ok(Decoded { bytes, empty })
    }

    /// The bytes of a shard's elements: the inner chunks, each one where
    /// the index says it is.
    ///
    /// The order of the chunks inside a shard is not fixed by the
    /// specification, so the index is the only way to find them. The index
    /// holds the offset and the length of every inner chunk, and the ones
    /// whose offset and length are both the largest there is are not there
    /// at all: their elements are the fill value.
    fn decode_shard(&self, raw: &[u8], sharding: &Sharding, shape: &[u64]) -> Result<Decoded> {
        let inner = &sharding.chunk_shape;
        if inner.len() != shape.len() {
            bail!(
                "zarr: the sharding codec's chunk shape has {} dimensions and the shard has {}",
                inner.len(),
                shape.len()
            );
        }
        // The number of inner chunks in a shard: the shard's shape
        // divided by the inner chunk's.
        let per_shard: Vec<u64> = shape.iter().zip(inner.iter()).map(|(s, c)| s / c).collect();
        let count: u64 = per_shard.iter().product();

        // The index: two little-endian 64-bit numbers for every inner
        // chunk -- the offset and the length -- and the checksum.
        let checksum = if sharding.crc32c { 4 } else { 0 };
        let index_size = 16 * count as usize + checksum;
        if raw.len() < index_size {
            bail!(
                "zarr: the shard holds {} bytes, short of the {index_size} its index needs",
                raw.len()
            );
        }
        let index = if sharding.index_at_start {
            &raw[..index_size]
        } else {
            &raw[raw.len() - index_size..]
        };
        if sharding.crc32c {
            let body = &index[..index_size - 4];
            let stored = u32::from_le_bytes([
                index[index_size - 4],
                index[index_size - 3],
                index[index_size - 2],
                index[index_size - 1],
            ]);
            if crc32c(body) != stored {
                bail!("zarr: the shard's index does not match its checksum");
            }
        }

        // The shard's elements, and the inner chunks that are not there.
        let itemsize = self.itemsize();
        let shard_len: usize = shape.iter().map(|s| *s as usize).product();
        let inner_len: usize = inner.iter().map(|s| *s as usize).product();
        let mut bytes = vec![0u8; shard_len * itemsize];
        let mut empty = Vec::new();
        let mut coords = vec![0u64; per_shard.len()];
        for i in 0..count {
            // The inner chunk's place in the shard's grid.
            let mut rest = i as usize;
            for k in (0..per_shard.len()).rev() {
                coords[k] = (rest % per_shard[k] as usize) as u64;
                rest /= per_shard[k] as usize;
            }
            // The inner chunk's place in the shard.
            let origin: Vec<u64> = coords
                .iter()
                .zip(inner.iter())
                .map(|(c, s)| c * s)
                .collect();
            let at = i as usize * 16;
            let mut offset = [0u8; 8];
            let mut length = [0u8; 8];
            offset.copy_from_slice(&index[at..at + 8]);
            length.copy_from_slice(&index[at + 8..at + 16]);
            let (offset, length) = (u64::from_le_bytes(offset), u64::from_le_bytes(length));
            if offset == u64::MAX && length == u64::MAX {
                // The inner chunk is not in the shard: its elements are the
                // fill value.
                empty.push(Region {
                    origin,
                    shape: inner.clone(),
                });
                continue;
            }
            let end = offset.checked_add(length).ok_or_else(|| {
                rgx_core::Error::msg("zarr: the shard's index holds an offset that does not fit")
            })?;
            if end > raw.len() as u64 {
                bail!(
                    "zarr: the shard's index points at bytes {offset}..{end}, past the {} the shard holds",
                    raw.len()
                );
            }
            let chunk = &raw[offset as usize..end as usize];
            let decoded = self.decode_pipeline(chunk, &sharding.steps, inner)?;
            if decoded.bytes.len() < inner_len * itemsize {
                bail!(
                    "zarr: the inner chunk holds {} bytes, short of the {} its shape asks for",
                    decoded.bytes.len(),
                    inner_len * itemsize
                );
            }
            // The inner chunk's elements, where they belong in the shard.
            let mut inner_coords = vec![0usize; inner.len()];
            for linear in 0..inner_len {
                self.coords_into(linear, inner, &mut inner_coords);
                let mut at = 0usize;
                for k in 0..shape.len() {
                    at = at * shape[k] as usize + origin[k] as usize + inner_coords[k];
                }
                let (from, to) = (linear * itemsize, at * itemsize);
                bytes[to..to + itemsize].copy_from_slice(&decoded.bytes[from..from + itemsize]);
            }
        }
        Ok(Decoded { bytes, empty })
    }

    /// The bytes of a chunk with the axes put back the way the array has
    /// them.
    ///
    /// The transpose codec stores a chunk's elements with its axes
    /// permuted, so what comes out of the pipeline holds them in the
    /// permuted order. The stored axis `i` holds the chunk's axis
    /// `order[i]`, and the stored buffer runs over the shape that
    /// permutation gives -- so the element at the chunk's own coordinates
    /// sits where the permutation moved it.
    fn untranspose(&self, bytes: &[u8], order: Option<&[usize]>, shape: &[u64]) -> Result<Vec<u8>> {
        let Some(order) = order else {
            return Ok(bytes.to_vec());
        };
        let n = order.len();
        let size = self.itemsize();
        let count: usize = shape.iter().map(|c| *c as usize).product();
        if bytes.len() < count * size {
            bail!(
                "zarr: the chunk holds {} bytes, short of the {} its shape asks for",
                bytes.len(),
                count * size
            );
        }
        // The strides of the stored buffer: the shape the permutation
        // gives, in the chunk's own order.
        let mut stride = vec![1usize; n];
        for i in (0..n.saturating_sub(1)).rev() {
            stride[i] = stride[i + 1] * shape[order[i + 1]] as usize;
        }
        let mut out = vec![0u8; count * size];
        let mut coords = vec![0usize; n];
        for linear in 0..count {
            self.coords_into(linear, shape, &mut coords);
            let mut at = 0usize;
            for (i, o) in order.iter().enumerate() {
                at += coords[*o] * stride[i];
            }
            let (from, to) = (at * size, linear * size);
            out[to..to + size].copy_from_slice(&bytes[from..from + size]);
        }
        Ok(out)
    }

    /// Undo the filters. Only the delta is decoded, and only for the C
    /// order, where the last axis is the contiguous one.
    fn unfilter(&self, bytes: &[u8], count: usize, last: u64) -> Result<Vec<u8>> {
        let Some(acc) = &self.delta else {
            return Ok(bytes.to_vec());
        };
        if self.order != 'C' {
            bail!("zarr: the delta filter is not decoded for the F order");
        }
        let last = last as usize;
        let rows = count / last.max(1);
        let size = self.itemsize();
        let mut out = bytes.to_vec();
        for row in 0..rows {
            let base = row * last * size;
            for i in 1..last {
                let here = base + i * size;
                let prev = here - size;
                // The chunk holds the differences: this element is the
                // difference, and the one before it is what it is counted
                // from.
                let sum = acc.add(&out[here..here + size], &out[prev..prev + size])?;
                out[here..here + size].copy_from_slice(&sum);
            }
        }
        Ok(out)
    }
}

/// The dtype: what one element is.
#[derive(Clone)]
enum Dtype {
    Int {
        width: u8,
        signed: bool,
        big: bool,
    },
    Float {
        width: u8,
        big: bool,
    },
    Bool,
    /// A fixed-width run of bytes.
    Bytes(usize),
}

impl Dtype {
    fn parse(s: &str) -> Result<Dtype> {
        let bytes = s.as_bytes();
        let big = match bytes.first() {
            Some(b'<') => false,
            Some(b'>') => true,
            Some(b'|') => false,
            _ => bail!("zarr: the dtype {s:?} has no byte order"),
        };
        let rest = &s[1..];
        if let Some(n) = rest.strip_prefix('S') {
            let n: usize = n
                .parse()
                .map_err(|_| rgx_core::Error::msg(format!("zarr: the dtype {s:?} has no width")))?;
            return Ok(Dtype::Bytes(n));
        }
        if rest.starts_with('U') {
            bail!("zarr: the fixed-width unicode dtype {s:?} is not decoded here");
        }
        if rest.starts_with('M') || rest.starts_with('m') {
            bail!("zarr: the datetime dtype {s:?} is not decoded here");
        }
        if rest.starts_with('O') {
            bail!("zarr: the object dtype {s:?} is not decoded here");
        }
        let kind = &rest[..rest.len().min(1)];
        let width: u8 = rest[1..]
            .parse()
            .map_err(|_| rgx_core::Error::msg(format!("zarr: the dtype {s:?} has no width")))?;
        match (kind, width) {
            ("i", 1 | 2 | 4 | 8) => Ok(Dtype::Int {
                width,
                signed: true,
                big,
            }),
            ("u", 1 | 2 | 4 | 8) => Ok(Dtype::Int {
                width,
                signed: false,
                big,
            }),
            ("f", 4) => Ok(Dtype::Float { width: 4, big }),
            ("f", 8) => Ok(Dtype::Float { width: 8, big }),
            ("b", 1) => Ok(Dtype::Bool),
            _ => bail!("zarr: the dtype {s:?} is not one this adapter decodes"),
        }
    }

    /// A v3 data type: the name says the width and whether the type is
    /// signed, and the byte order is the one the `bytes` codec says.
    fn parse_v3(name: &str, big: bool) -> Result<Dtype> {
        match name {
            "bool" => Ok(Dtype::Bool),
            "int8" => Ok(Dtype::Int {
                width: 1,
                signed: true,
                big,
            }),
            "int16" => Ok(Dtype::Int {
                width: 2,
                signed: true,
                big,
            }),
            "int32" => Ok(Dtype::Int {
                width: 4,
                signed: true,
                big,
            }),
            "int64" => Ok(Dtype::Int {
                width: 8,
                signed: true,
                big,
            }),
            "uint8" => Ok(Dtype::Int {
                width: 1,
                signed: false,
                big,
            }),
            "uint16" => Ok(Dtype::Int {
                width: 2,
                signed: false,
                big,
            }),
            "uint32" => Ok(Dtype::Int {
                width: 4,
                signed: false,
                big,
            }),
            "uint64" => Ok(Dtype::Int {
                width: 8,
                signed: false,
                big,
            }),
            "float32" => Ok(Dtype::Float { width: 4, big }),
            "float64" => Ok(Dtype::Float { width: 8, big }),
            other => bail!("zarr: the {other:?} data type is not one this adapter decodes"),
        }
    }

    fn itemsize(&self) -> usize {
        match self {
            Dtype::Int { width, .. } => *width as usize,
            Dtype::Float { width, .. } => *width as usize,
            Dtype::Bool => 1,
            Dtype::Bytes(n) => *n,
        }
    }

    fn is_integer(&self) -> bool {
        matches!(self, Dtype::Int { .. })
    }

    /// The text one element of this dtype takes.
    fn value(&self, bytes: &[u8], at: usize) -> Result<String> {
        match self {
            Dtype::Int { width, signed, big } => {
                let Some(v) = int_at(bytes, at, *width, *signed, *big) else {
                    bail!("zarr: the chunk ended inside an element");
                };
                Ok(v.to_string())
            }
            Dtype::Float { width, big } => {
                let raw = bytes.get(at..at + *width as usize).ok_or_else(|| {
                    rgx_core::Error::msg("zarr: the chunk ended inside an element")
                })?;
                let mut buf = [0u8; 8];
                let n = *width as usize;
                if *big {
                    buf[8 - n..].copy_from_slice(raw);
                    let bits = u64::from_be_bytes(buf);
                    if n == 4 {
                        Ok(format!("{:?}", f64::from(f32::from_bits(bits as u32))))
                    } else {
                        Ok(format!("{:?}", f64::from_bits(bits)))
                    }
                } else {
                    buf[..n].copy_from_slice(raw);
                    let bits = u64::from_le_bytes(buf);
                    if n == 4 {
                        Ok(format!("{:?}", f64::from(f32::from_bits(bits as u32))))
                    } else {
                        Ok(format!("{:?}", f64::from_bits(bits)))
                    }
                }
            }
            Dtype::Bool => {
                let raw = bytes.get(at..at + 1).ok_or_else(|| {
                    rgx_core::Error::msg("zarr: the chunk ended inside an element")
                })?;
                Ok(if raw[0] != 0 { "true" } else { "false" }.to_string())
            }
            Dtype::Bytes(n) => {
                let raw = bytes.get(at..at + n).ok_or_else(|| {
                    rgx_core::Error::msg("zarr: the chunk ended inside an element")
                })?;
                Ok(String::from_utf8_lossy(raw).into_owned())
            }
        }
    }

    /// The sum of two elements of this dtype, in this dtype. The delta
    /// filter's decoder is a running sum, and the running sum is in the
    /// filter's own dtype, wrapping where that dtype wraps.
    fn add(&self, a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
        let Dtype::Int { width, signed, big } = *self else {
            bail!("zarr: the delta filter accumulates in a type that is not an integer");
        };
        let av = int_at(a, 0, width, signed, big).unwrap_or(0);
        let bv = int_at(b, 0, width, signed, big).unwrap_or(0);
        Ok(int_bytes(wrap(av + bv, width, signed), width, big))
    }
}

impl core::fmt::Display for Dtype {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Dtype::Int { width, signed, big } => write!(
                f,
                "{}{}{}",
                if *big { '>' } else { '<' },
                if *signed { 'i' } else { 'u' },
                width
            ),
            Dtype::Float { width, big } => {
                write!(f, "{}f{}", if *big { '>' } else { '<' }, width)
            }
            Dtype::Bool => write!(f, "|b1"),
            Dtype::Bytes(n) => write!(f, "|S{n}"),
        }
    }
}

/// The integer at an offset, in the dtype's own width and byte order. The
/// value is an `i128` so that an unsigned 64-bit element is exact.
fn int_at(bytes: &[u8], at: usize, width: u8, signed: bool, big: bool) -> Option<i128> {
    let raw = bytes.get(at..at + width as usize)?;
    let mut acc: u64 = 0;
    if big {
        for b in raw {
            acc = (acc << 8) | u64::from(*b);
        }
    } else {
        for b in raw.iter().rev() {
            acc = (acc << 8) | u64::from(*b);
        }
    }
    let bits = width as u32 * 8;
    if signed && bits < 64 && acc & (1u64 << (bits - 1)) != 0 {
        Some(acc as i64 as i128 - (1i128 << bits))
    } else if signed {
        Some(acc as i64 as i128)
    } else {
        Some(acc as i128)
    }
}

/// The bytes of an integer, in the dtype's own width and byte order.
fn int_bytes(value: i128, width: u8, big: bool) -> Vec<u8> {
    let n = width as usize;
    let mut out = vec![0u8; n];
    let mut v = value;
    for slot in out.iter_mut() {
        *slot = (v & 0xff) as u8;
        v >>= 8;
    }
    if big {
        out.reverse();
    }
    out
}

/// The value an integer type wraps to when it runs out of room.
fn wrap(value: i128, width: u8, signed: bool) -> i128 {
    let bits = width as u32 * 8;
    if bits >= 128 {
        return value;
    }
    let masked = value & ((1i128 << bits) - 1);
    if signed && masked & (1i128 << (bits - 1)) != 0 {
        masked - (1i128 << bits)
    } else {
        masked
    }
}

/// The codec the chunks are compressed with.
#[derive(Clone)]
enum Codec {
    None,
    Zlib,
    Gzip,
    Zstd,
    Bzip2,
    Blosc,
}

impl Codec {
    fn parse(arena: &Arena, root: &Value) -> Result<Codec> {
        let Some(v) = root.get(arena, "compressor") else {
            return Ok(Codec::None);
        };
        if v.is_null() {
            return Ok(Codec::None);
        }
        let id = v
            .get(arena, "id")
            .and_then(|id| id.as_str(arena))
            .unwrap_or("");
        match id {
            "zlib" => Ok(Codec::Zlib),
            "gzip" => Ok(Codec::Gzip),
            "zstd" => Ok(Codec::Zstd),
            "bz2" => Ok(Codec::Bzip2),
            "blosc" => Ok(Codec::Blosc),
            other => bail!("zarr: the {other:?} codec is not decoded here"),
        }
    }

    fn decode(&self, raw: &[u8]) -> Result<Vec<u8>> {
        let out = match self {
            Codec::None => raw.to_vec(),
            Codec::Zlib => {
                rgx_core::compress::zlib::ZlibDecoder::new()
                    .decode_bounded(raw, MAX_CHUNK_BYTES)
                    .map_err(|e| {
                        rgx_core::Error::msg(format!("zarr: the chunk does not inflate: {e}"))
                    })?
                    .bytes
            }
            Codec::Gzip => {
                rgx_core::compress::gzip::GzipReader::decode_bounded(raw, MAX_CHUNK_BYTES)
                    .map_err(|e| {
                        rgx_core::Error::msg(format!("zarr: the chunk does not inflate: {e}"))
                    })?
                    .bytes
            }
            Codec::Zstd => {
                rgx_core::compress::zstd::ZstdDecoder::new()
                    .decode_bounded(raw, MAX_CHUNK_BYTES)
                    .map_err(|e| {
                        rgx_core::Error::msg(format!("zarr: the chunk does not decode: {e}"))
                    })?
                    .bytes
            }
            Codec::Bzip2 => {
                rgx_core::compress::bzip2::Bzip2Decoder::new()
                    .decode_bounded(raw, MAX_CHUNK_BYTES)
                    .map_err(|e| {
                        rgx_core::Error::msg(format!("zarr: the chunk does not decode: {e}"))
                    })?
                    .bytes
            }
            Codec::Blosc => {
                rgx_core::compress::blosc::BloscDecoder::new()
                    .decode_bounded(raw, MAX_CHUNK_BYTES)
                    .map_err(|e| {
                        rgx_core::Error::msg(format!("zarr: the chunk does not decode: {e}"))
                    })?
                    .bytes
            }
        };
        Ok(out)
    }
}

impl core::fmt::Display for Codec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Codec::None => "none",
            Codec::Zlib => "zlib",
            Codec::Gzip => "gzip",
            Codec::Zstd => "zstd",
            Codec::Bzip2 => "bz2",
            Codec::Blosc => "blosc",
        })
    }
}

/// The manifest's numbers.
fn numbers(arena: &Arena, root: &Value, key: &str) -> Result<Vec<u64>> {
    let v = root
        .get(arena, key)
        .ok_or_else(|| rgx_core::Error::msg(format!("zarr: the manifest has no {key}")))?;
    let list = v
        .as_array(arena)
        .ok_or_else(|| rgx_core::Error::msg(format!("zarr: the {key} is not a list")))?;
    let mut out = Vec::with_capacity(list.len());
    for n in list {
        let n = n.as_u64().ok_or_else(|| {
            rgx_core::Error::msg(format!(
                "zarr: the {key} holds something that is not a number"
            ))
        })?;
        out.push(n);
    }
    Ok(out)
}

/// The manifest's dtype, as it is written.
fn dtype_text<'a>(arena: &'a Arena, root: &Value) -> Result<&'a str> {
    root.get(arena, "dtype")
        .and_then(|v| v.as_str(arena))
        .ok_or_else(|| rgx_core::Error::msg("zarr: the manifest has no dtype"))
}

/// The fill value, already formatted for the dtype.
fn fill_text(arena: &Arena, root: &Value, dtype: &Dtype) -> Result<String> {
    let Some(v) = root.get(arena, "fill_value") else {
        return Ok(zero_text(dtype));
    };
    if v.is_null() {
        return Ok(zero_text(dtype));
    }
    if let Some(s) = v.as_str(arena) {
        return Ok(s.to_string());
    }
    let Some(n) = v.as_f64() else {
        return Ok(zero_text(dtype));
    };
    Ok(match dtype {
        Dtype::Int { .. } => {
            if n.is_finite() {
                (n as i64).to_string()
            } else {
                n.to_string()
            }
        }
        Dtype::Float { .. } => format!("{n:?}"),
        Dtype::Bool => (n != 0.0).to_string(),
        Dtype::Bytes(_) => zero_text(dtype),
    })
}

/// The zero of a dtype, as text.
fn zero_text(dtype: &Dtype) -> String {
    match dtype {
        Dtype::Int { .. } => "0".to_string(),
        Dtype::Float { .. } => "0.0".to_string(),
        Dtype::Bool => "false".to_string(),
        Dtype::Bytes(_) => String::new(),
    }
}

/// A list of numbers, the way the manifest writes them.
fn bracket(n: &[u64]) -> String {
    let mut out = String::from("[");
    for (i, v) in n.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{v}");
    }
    out.push(']');
    out
}

/// The whole answer: the manifest's own bytes, then the values.
fn render(data: &[u8], path: &str) -> Result<Vec<u8>> {
    let text = core::str::from_utf8(data)
        .map_err(|_| rgx_core::Error::msg("zarr: the manifest is not UTF-8"))?;
    let arena = parse_json(text)
        .map_err(|e| rgx_core::Error::msg(format!("zarr: the manifest is not JSON: {e}")))?;
    let root = arena.root();

    if path.contains('!') {
        decline!(
            "zarr: the array is inside a container, so its chunks are not beside the manifest"
        );
    }
    let dir = match Path::new(path).parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => Path::new(".").to_path_buf(),
    };

    // The consolidated metadata of a group: the manifests of every array of
    // the group are in one file, and the chunks of an array are in the
    // array's own directory.
    if root.get(&arena, "zarr_consolidated_format").is_some() {
        return render_group(&arena, &root, text, &dir);
    }

    let m = Manifest::from_json(&arena, &root)?;

    let mut out = String::new();
    out.push_str(text.trim_end());
    out.push('\n');
    let _ = writeln!(
        out,
        "zarr: shape={} chunks={} dtype={} compressor={} order={}",
        m.shape_text(),
        m.chunks_text(),
        m.dtype_text(),
        m.codec_text(),
        m.order
    );
    m.write_chunks(&dir, "", &mut out)?;

    Ok(out.into_bytes())
}

/// The consolidated metadata of a group.
///
/// The file holds the manifest of every array of the group, and the paths
/// in it are the paths of the group's files, relative to the directory
/// that holds the `.zmetadata`: the manifest of an array is at
/// `<the array's path>/.zarray`, and the chunks of that array are in the
/// array's own directory.
fn render_group(arena: &Arena, root: &Value, text: &str, dir: &Path) -> Result<Vec<u8>> {
    let meta = root
        .get(arena, "metadata")
        .and_then(|v| v.as_object(arena))
        .ok_or_else(|| rgx_core::Error::msg("zarr: the consolidated metadata has no metadata"))?;

    // The arrays the metadata names, in the order it names them.
    let mut arrays: Vec<(String, Manifest)> = Vec::new();
    for (key, value) in meta.iter() {
        let key = arena.get_string(*key);
        let Some(array) = array_path(key) else {
            continue;
        };
        if !array.is_empty() && !stays_inside(array) {
            bail!(
                "zarr: the consolidated metadata names the array {array:?}, whose path leaves the group"
            );
        }
        let m = Manifest::from_json(arena, value).map_err(|e| {
            rgx_core::Error::msg(format!(
                "zarr: the array {array:?} has a manifest this adapter does not read: {e}"
            ))
        })?;
        arrays.push((array.to_string(), m));
    }
    if arrays.is_empty() {
        bail!("zarr: the consolidated metadata names no array");
    }

    let mut out = String::new();
    out.push_str(text.trim_end());
    out.push('\n');
    let _ = writeln!(out, "zarr: consolidated metadata, {} arrays", arrays.len());
    for (array, m) in &arrays {
        let name = if array.is_empty() {
            "."
        } else {
            array.as_str()
        };
        let _ = writeln!(out, "array {name}");
        let _ = writeln!(
            out,
            "zarr: shape={} chunks={} dtype={} compressor={} order={}",
            m.shape_text(),
            m.chunks_text(),
            m.dtype_text(),
            m.codec_text(),
            m.order
        );
        // The chunks of an array are in the array's own directory, and the
        // name of the chunk carries the array's path, so that the chunks
        // of two arrays do not look alike.
        let label = if array.is_empty() {
            String::new()
        } else {
            format!("{array}/")
        };
        m.write_chunks(&dir.join(array), &label, &mut out)?;
    }

    Ok(out.into_bytes())
}

/// The path of an array in the consolidated metadata: the key of its
/// manifest, without the `.zarray` at the end.
///
/// The manifest of an array is at `<the array's path>/.zarray`; the
/// manifest of the store's own root array is at `.zarray`.
fn array_path(key: &str) -> Option<&str> {
    if key == ".zarray" {
        return Some("");
    }
    key.strip_suffix("/.zarray")
}

/// Whether a path in the consolidated metadata stays inside the group.
///
/// The paths are relative to the directory that holds the `.zmetadata`,
/// and one that climbs out of it is not a path the format has.
fn stays_inside(path: &str) -> bool {
    !path.starts_with('/') && !path.contains('\\') && !path.split('/').any(|part| part == "..")
}

/// The facts of a group: the name of every array the consolidated metadata
/// names, and the manifest of each.
fn group_facts(arena: &Arena, root: &Value) -> Vec<Field> {
    let mut facts = Vec::new();
    let Some(meta) = root.get(arena, "metadata").and_then(|v| v.as_object(arena)) else {
        return facts;
    };
    for (key, value) in meta.iter() {
        let key = arena.get_string(*key);
        let Some(array) = array_path(key) else {
            continue;
        };
        let Ok(m) = Manifest::from_json(arena, value) else {
            continue;
        };
        facts.push(Field::new("zarr.array", array));
        facts.push(Field::new("zarr.shape", &m.shape_text()));
        facts.push(Field::new("zarr.chunks", &m.chunks_text()));
        facts.push(Field::new("zarr.dtype", &m.dtype_text()));
        facts.push(Field::new("zarr.compressor", &m.codec_text()));
        facts.push(Field::new("zarr.order", &m.order.to_string()));
    }
    facts
}

/// The transpose codec's order: the permutation of the array's axes.
///
/// The order must be a permutation of the dimensions -- as many entries as
/// the array has dimensions, no duplicates, and every entry in range.
/// Anything else is a pipeline `zarr-python` refuses, so it is refused
/// here too, and by name.
fn transpose_order(arena: &Arena, step: &Value, ndim: usize) -> Result<Vec<usize>> {
    let list = step
        .get(arena, "configuration")
        .and_then(|c| c.get(arena, "order"))
        .and_then(|v| v.as_array(arena))
        .ok_or_else(|| rgx_core::Error::msg("zarr: the transpose codec has no order"))?;
    let mut order = Vec::with_capacity(list.len());
    for v in list {
        let n = v.as_u64().ok_or_else(|| {
            rgx_core::Error::msg(
                "zarr: the transpose codec's order holds something that is not a number",
            )
        })?;
        order.push(n as usize);
    }
    if order.len() != ndim {
        bail!(
            "zarr: the transpose codec's order has {} entries and the array has {ndim} dimensions",
            order.len()
        );
    }
    let mut seen = vec![false; ndim];
    for n in &order {
        if *n >= ndim {
            bail!(
                "zarr: the transpose codec's order holds {n}, which is not one of the array's {ndim} dimensions"
            );
        }
        if seen[*n] {
            bail!("zarr: the transpose codec's order holds {n} twice, so it is not a permutation");
        }
        seen[*n] = true;
    }
    Ok(order)
}

/// Two permutations of the same axes, one after the other.
///
/// The first codec permutes the chunk's axes, and the second permutes the
/// axes the first one left, so the two make one permutation of the chunk's
/// own axes.
fn compose_order(first: &[usize], second: &[usize]) -> Vec<usize> {
    (0..first.len()).map(|i| first[second[i]]).collect()
}

/// The rectilinear chunk grid: the edges of the chunks along each axis.
///
/// The grid is named `rectilinear` by the specification that defines it,
/// which lives in `zarr-extensions`: the core specification has no chunk
/// grid but the regular one. Each axis of the grid is either a number,
/// which is a regular step repeated until the steps cover the axis, or a
/// list of edges: a number in the list is an edge of that length, and a
/// pair is that many edges of that length.
fn rectilinear_grid(arena: &Arena, config: &Value, shape: &[u64]) -> Result<Grid> {
    let kind = config
        .get(arena, "kind")
        .and_then(|v| v.as_str(arena))
        .unwrap_or("");
    if kind != "inline" {
        bail!("zarr: the rectilinear chunk grid's kind {kind:?} is not read here");
    }
    let list = config
        .get(arena, "chunk_shapes")
        .and_then(|v| v.as_array(arena))
        .ok_or_else(|| {
            rgx_core::Error::msg("zarr: the rectilinear chunk grid has no chunk shapes")
        })?;
    if list.len() != shape.len() {
        bail!(
            "zarr: the shape has {} dimensions and the chunk grid has {}",
            shape.len(),
            list.len()
        );
    }
    let mut edges = Vec::with_capacity(list.len());
    let mut starts = Vec::with_capacity(list.len());
    let mut counts = Vec::with_capacity(list.len());
    for (k, spec) in list.iter().enumerate() {
        let axis = rectilinear_axis(arena, spec, shape[k])?;
        // The coordinate every edge starts at.
        let mut at = 0u64;
        let mut axis_starts = Vec::with_capacity(axis.len());
        for e in &axis {
            axis_starts.push(at);
            at += e;
        }
        // The edges that reach into the array. The last one may hang over
        // the end of it, and the edges after that hold nothing.
        let count = axis_starts.iter().filter(|s| **s < shape[k]).count() as u64;
        edges.push(axis);
        starts.push(axis_starts);
        counts.push(count);
    }
    Ok(Grid::Rectilinear {
        edges,
        starts,
        counts,
    })
}

/// The edges of one axis of the rectilinear chunk grid.
///
/// A number is a regular step: the same edge repeated until the edges
/// cover the axis. A list is the edges themselves: a number in it is an
/// edge of that length, and a pair is that many edges of that length.
fn rectilinear_axis(arena: &Arena, spec: &Value, extent: u64) -> Result<Vec<u64>> {
    if let Some(step) = spec.as_u64() {
        if step == 0 {
            bail!("zarr: a chunk dimension of zero would make the grid empty");
        }
        return Ok(vec![step; extent.div_ceil(step) as usize]);
    }
    let Some(list) = spec.as_array(arena) else {
        bail!("zarr: the rectilinear chunk grid holds something that is neither a step nor a list of edges");
    };
    let mut edges: Vec<u64> = Vec::new();
    for item in list {
        if let Some(v) = item.as_u64() {
            if v == 0 {
                bail!("zarr: a chunk dimension of zero would make the grid empty");
            }
            edges.push(v);
            continue;
        }
        // A run: the length of the edge and how many of them there are.
        let Some(pair) = item.as_array(arena) else {
            bail!(
                "zarr: the rectilinear chunk grid holds an edge that is neither a length nor a run"
            );
        };
        if pair.len() != 2 {
            bail!(
                "zarr: the rectilinear chunk grid holds a run of {} entries, not a length and a count",
                pair.len()
            );
        }
        let length = pair[0].as_u64().ok_or_else(|| {
            rgx_core::Error::msg("zarr: the rectilinear chunk grid holds a run with no length")
        })?;
        let count = pair[1].as_u64().ok_or_else(|| {
            rgx_core::Error::msg("zarr: the rectilinear chunk grid holds a run with no count")
        })?;
        if length == 0 {
            bail!("zarr: a chunk dimension of zero would make the grid empty");
        }
        if count == 0 {
            bail!("zarr: the rectilinear chunk grid holds a run of no edges at all");
        }
        for _ in 0..count {
            edges.push(length);
        }
    }
    if edges.is_empty() {
        bail!("zarr: the rectilinear chunk grid has an axis with no edges");
    }
    let sum: u64 = edges.iter().sum();
    if sum < extent {
        bail!(
            "zarr: the rectilinear chunk grid's edges along one axis sum to {sum}, short of the {extent} the axis is"
        );
    }
    Ok(edges)
}

/// The sharding codec: the shape of an inner chunk, the pipeline an inner
/// chunk's bytes go through, and where the index is.
///
/// The byte order comes back with it: the codec is the array-to-bytes step
/// of the pipeline, so the pipeline that says the byte order is the one
/// inside it.
fn parse_sharding(arena: &Arena, step: &Value) -> Result<(Sharding, bool)> {
    let config = step
        .get(arena, "configuration")
        .ok_or_else(|| rgx_core::Error::msg("zarr: the sharding codec has no configuration"))?;
    let chunk_shape = numbers(arena, &config, "chunk_shape")?;
    if chunk_shape.is_empty() {
        bail!("zarr: the sharding codec's chunk shape has no dimensions");
    }
    if chunk_shape.contains(&0) {
        bail!("zarr: a chunk dimension of zero would make the grid empty");
    }

    // The inner pipeline: the codecs an inner chunk's bytes go through.
    let list = config
        .get(arena, "codecs")
        .and_then(|v| v.as_array(arena))
        .ok_or_else(|| rgx_core::Error::msg("zarr: the sharding codec has no inner codecs"))?;
    let (steps, big) = parse_inner_pipeline(arena, list)?;

    // The index: the codecs the index's bytes go through. The reader finds
    // the index by its size, so the index's own pipeline has to be a fixed
    // size: the bytes and the checksum, and nothing else.
    let index_list = config
        .get(arena, "index_codecs")
        .and_then(|v| v.as_array(arena))
        .ok_or_else(|| rgx_core::Error::msg("zarr: the sharding codec has no index codecs"))?;
    let mut crc32c = false;
    let mut seen_bytes = false;
    for codec in index_list {
        let name = codec
            .get(arena, "name")
            .and_then(|v| v.as_str(arena))
            .unwrap_or("");
        match name {
            "bytes" => {
                if parse_endian(arena, codec)? {
                    bail!("zarr: the sharding codec's index is big-endian, which is not read here");
                }
                seen_bytes = true;
            }
            "crc32c" => crc32c = true,
            other => bail!("zarr: the {other:?} index codec is not read here"),
        }
    }
    if !seen_bytes {
        bail!("zarr: the sharding codec's index has no bytes codec, so the byte order is not established");
    }

    // Where the index is: at the start of the shard or at the end of it.
    let index_at_start = match config
        .get(arena, "index_location")
        .and_then(|v| v.as_str(arena))
    {
        None | Some("end") => false,
        Some("start") => true,
        Some(other) => bail!("zarr: the index location {other:?} is neither start nor end"),
    };

    Ok((
        Sharding {
            chunk_shape,
            steps,
            index_at_start,
            crc32c,
        },
        big,
    ))
}

/// The pipeline of a shard's inner chunks: the codecs their bytes go
/// through.
///
/// It is a pipeline of its own: the bytes codec says the byte order the
/// elements are in, and the compressions follow it.
fn parse_inner_pipeline(arena: &Arena, list: &[Value]) -> Result<(Vec<Step>, bool)> {
    let mut steps = Vec::new();
    let mut big = false;
    let mut seen_bytes = false;
    for step in list {
        let name = step
            .get(arena, "name")
            .and_then(|v| v.as_str(arena))
            .unwrap_or("");
        match name {
            "bytes" => {
                big = parse_endian(arena, step)?;
                seen_bytes = true;
                steps.push(Step::Bytes);
            }
            "zstd" => steps.push(Step::Zstd),
            "gzip" => steps.push(Step::Gzip),
            "blosc" => steps.push(Step::Blosc),
            "transpose" => {
                bail!("zarr: the transpose codec inside the sharding codec is not read here")
            }
            "sharding_indexed" | "sharding" => {
                bail!("zarr: the sharding codec inside the sharding codec is not read here")
            }
            other => bail!("zarr: the {other:?} codec is not decoded here"),
        }
    }
    if !seen_bytes {
        bail!("zarr: the sharding codec's inner pipeline has no bytes codec, so the byte order is not established");
    }
    Ok((steps, big))
}

/// The byte order a `bytes` codec says the elements are in.
fn parse_endian(arena: &Arena, step: &Value) -> Result<bool> {
    let endian = step
        .get(arena, "configuration")
        .and_then(|c| c.get(arena, "endian"))
        .and_then(|v| v.as_str(arena))
        .unwrap_or("little");
    match endian {
        "little" => Ok(false),
        "big" => Ok(true),
        other => bail!("zarr: the {other:?} byte order is not read here"),
    }
}

/// The crc32c of these bytes: the Castagnoli polynomial, the one the
/// zarr index codec calls `crc32c`.
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in bytes {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use rgx_core::{Adapter, Outcome, Result};
    use std::path::PathBuf;

    /// The fixtures, in the crate's own testdata.
    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join("zarr")
            .join(name)
    }

    /// Read one fixture the way the pipeline does: the manifest's bytes and
    /// the path it sits at.
    fn read(name: &str) -> Result<String> {
        // The v2 layout's manifest, the v2 layout's consolidated metadata,
        // or the v3 layout's node metadata.
        let dir = fixture(name);
        let path = [".zarray", ".zmetadata", "zarr.json"]
            .iter()
            .map(|f| dir.join(f))
            .find(|p| p.exists())
            .expect("the manifest");
        let data = std::fs::read(&path).expect("the manifest");
        let out = Zarr.extract(&data, &path.to_string_lossy())?;
        let Outcome::Text(t) = out else {
            panic!("the answer is text");
        };
        Ok(String::from_utf8(t).expect("the answer is utf-8"))
    }

    #[test]
    fn the_doubles_come_out_in_their_chunks() {
        let s = read("f64-zlib").expect("the array");
        assert!(
            s.contains("zarr: shape=[4, 6] chunks=[2, 3] dtype=<f8"),
            "{s}"
        );
        assert!(s.contains("chunk 0.0: 1.0 2.0 3.0 7.0 8.0 9.0"), "{s}");
        assert!(s.contains("chunk 0.1: 4.0 5.0 6.0 10.0 11.0 12.0"), "{s}");
        assert!(
            s.contains("chunk 1.0: 13.0 14.0 15.0 19.0 20.0 21.0"),
            "{s}"
        );
        assert!(
            s.contains("chunk 1.1: 16.0 17.0 18.0 22.0 23.0 24.0"),
            "{s}"
        );
    }

    #[test]
    fn the_manifest_is_kept_in_the_answer() {
        // rgx is a superset of ripgrep: the JSON in the manifest is still
        // there to be searched, under the values.
        let s = read("f64-zlib").expect("the array");
        assert!(s.contains("\"zarr_format\": 2"), "{s}");
        assert!(s.contains("\"dtype\": \"<f8\""), "{s}");
    }

    #[test]
    fn a_short_last_chunk_is_the_fill_value() {
        let s = read("i16-raw").expect("the array");
        assert!(s.contains("chunk 0: 10 20"), "{s}");
        assert!(s.contains("chunk 1: 30 40"), "{s}");
        // The shape is five and the chunk holds two, so the last one is
        // half a chunk and the other half is the fill.
        assert!(s.contains("chunk 2: 50 0"), "{s}");
    }

    #[test]
    fn the_gzip_chunks_come_out_as_bytes() {
        let s = read("u1-gzip").expect("the array");
        assert!(s.contains("chunk 0: 1 2 3 4"), "{s}");
        assert!(s.contains("chunk 1: 5 250 251 252"), "{s}");
    }

    #[test]
    fn the_delta_filter_is_a_running_sum() {
        let s = read("i4-delta").expect("the array");
        assert!(s.contains("chunk 0: 4 7 11 16"), "{s}");
    }

    #[test]
    fn the_bzip2_chunks_come_out_as_floats() {
        let s = read("f32-bz2").expect("the array");
        assert!(s.contains("chunk 0: 1.5 2.25 -3.75"), "{s}");
    }

    #[test]
    fn the_chunks_can_live_in_sub_directories() {
        let s = read("u8-slash").expect("the array");
        assert!(s.contains("chunk 0/0: 1"), "{s}");
        assert!(s.contains("chunk 1/1: 4"), "{s}");
    }

    #[test]
    fn the_v3_layout_comes_out_as_floats() {
        // The layout zarr-python writes by default: the metadata in one
        // file, the chunks named by a key encoding, and a pipeline of
        // codecs that says how the bytes of a chunk become the elements.
        //
        // The fixture was written by `scripts/gen_zarr_fixtures.py` and
        // read back by zarr-python itself before it was committed, so it is
        // an array the world agrees on.
        let s = read("f64-zstd-v3").expect("the array");
        assert!(s.contains("compressor=zstd"), "{s}");
        assert!(s.contains("chunk c/0/0: 1.0 2.0 5.0 6.0"), "{s}");
        assert!(s.contains("chunk c/0/1: 3.0 4.0 7.0 8.0"), "{s}");
        assert!(s.contains("chunk c/1/0: 9.0 10.0 13.0 14.0"), "{s}");
        assert!(s.contains("chunk c/1/1: 11.0 12.0 15.0 16.0"), "{s}");
    }

    #[test]
    fn the_blosc_chunks_come_out_as_floats() {
        // The codec zarr-python asks for by default. The frame is a header,
        // a table of block offsets and the blocks, and the blocks are LZ4
        // with the byte shuffle applied to them.
        //
        // The fixture was written by `scripts/gen_zarr_fixtures.py` and
        // read back, before it was committed, by c-blosc itself and by
        // numcodecs -- the two implementations that write these frames -- so
        // the values here are not this reader's own opinion of its own
        // output.
        let s = read("f64-blosc").expect("the array");
        assert!(s.contains("compressor=blosc"), "{s}");
        assert!(s.contains("chunk 0.0: 1.0 2.0 5.0 6.0"), "{s}");
        assert!(s.contains("chunk 0.1: 3.0 4.0 7.0 8.0"), "{s}");
        assert!(s.contains("chunk 1.0: 9.0 10.0 13.0 14.0"), "{s}");
        assert!(s.contains("chunk 1.1: 11.0 12.0 15.0 16.0"), "{s}");
    }

    #[test]
    fn the_consolidated_metadata_names_every_array() {
        // The manifests of every array of a group are in one file, and the
        // chunks of an array are in the array's own directory.
        //
        // The fixture was written by `scripts/gen_zarr_fixtures.py` and
        // read back by zarr-python itself before it was committed, so it
        // is a group the world agrees on.
        let s = read("group-consolidated").expect("the group");
        assert!(s.contains("zarr: consolidated metadata, 2 arrays"), "{s}");
        assert!(s.contains("array first"), "{s}");
        assert!(
            s.contains("zarr: shape=[2, 3] chunks=[1, 3] dtype=<f8"),
            "{s}"
        );
        assert!(s.contains("chunk first/0.0: 1.0 2.0 3.0"), "{s}");
        assert!(s.contains("chunk first/1.0: 4.0 5.0 6.0"), "{s}");
        assert!(s.contains("array nested/second"), "{s}");
        assert!(s.contains("zarr: shape=[4] chunks=[2] dtype=<i4"), "{s}");
        assert!(s.contains("chunk nested/second/0: 10 20"), "{s}");
        assert!(s.contains("chunk nested/second/1: 30 40"), "{s}");
        // The metadata is in the answer, so a search for a key in the JSON
        // still finds it.
        assert!(s.contains("\"zarr_consolidated_format\": 1"), "{s}");
    }

    #[test]
    fn the_transposed_chunks_come_out_with_the_array_s_own_axes() {
        // The transpose codec stores a chunk's elements with its axes
        // permuted. This is the array the f64-zlib fixture holds, with
        // the axes swapped on the way to the disk, and zarr-python reads
        // the values of it the same way -- so the values here are the
        // array's and not the stored order.
        let s = read("f64-transpose-v3").expect("the array");
        assert!(s.contains("compressor=transpose+zstd"), "{s}");
        assert!(s.contains("chunk c/0/0: 1.0 2.0 3.0 7.0 8.0 9.0"), "{s}");
        assert!(s.contains("chunk c/0/1: 4.0 5.0 6.0 10.0 11.0 12.0"), "{s}");
        assert!(
            s.contains("chunk c/1/0: 13.0 14.0 15.0 19.0 20.0 21.0"),
            "{s}"
        );
        assert!(
            s.contains("chunk c/1/1: 16.0 17.0 18.0 22.0 23.0 24.0"),
            "{s}"
        );
    }

    #[test]
    fn the_sharded_chunks_come_out_as_floats() {
        // The sharding codec: the chunk is a shard that holds several inner
        // chunks and the index that says where each of them is. The order of
        // the chunks inside a shard is not fixed by the specification --
        // this one is written in the order a Morton walk gives -- so the
        // reader has to go through the index, and the values here are the
        // array's.
        //
        // The fixture was written by `scripts/gen_zarr_fixtures.py` with
        // zarr-python 3.4.1:
        //
        //     zarr.create_array(shape=(4, 6), chunks=(2, 3),
        //                         shards={"shape": (4, 6), "index_location": "end"},
        //                         dtype="float64", zarr_format=3, compressors=None)
        //
        // and read back by zarr-python itself before it was committed, so
        // it is an array the world agrees on.
        let s = read("f64-sharding-v3").expect("the array");
        assert!(s.contains("compressor=sharding_indexed"), "{s}");
        assert!(
            s.contains(
                "chunk c/0/0: 1.0 2.0 3.0 4.0 5.0 6.0 7.0 8.0 9.0 \
                        10.0 11.0 12.0 13.0 14.0 15.0 16.0 17.0 18.0 \
                        19.0 20.0 21.0 22.0 23.0 24.0"
            ),
            "{s}"
        );
    }

    #[test]
    fn the_rectilinear_chunks_come_out_as_ints() {
        // The rectilinear chunk grid: each axis of the grid is a list of
        // edges, and the chunks are the blocks those edges make. The first
        // axis is cut into edges of 2, 1 and 3 and the second into edges of
        // 2 and 3, so the chunks are not all the same shape and the reader
        // has to know where each one starts.
        //
        // The fixture was written by `scripts/gen_zarr_fixtures.py` with
        // zarr-python 3.4.1:
        //
        //     with zarr.config.set({"array.rectilinear_chunks": True}):
        //         zarr.create_array(shape=(6, 5), chunks=[[2, 1, 3], [2, 3]],
        //                             dtype="int32", zarr_format=3)
        //
        // and read back by zarr-python itself before it was committed, so
        // it is an array the world agrees on.
        let s = read("i4-rectilinear-v3").expect("the array");
        assert!(
            s.contains("zarr: shape=[6, 5] chunks=[[2, 1, 3], [2, 3]] dtype=<i4"),
            "{s}"
        );
        assert!(s.contains("chunk c/0/0: 0 1 5 6"), "{s}");
        assert!(s.contains("chunk c/0/1: 2 3 4 7 8 9"), "{s}");
        assert!(s.contains("chunk c/1/0: 10 11"), "{s}");
        assert!(s.contains("chunk c/1/1: 12 13 14"), "{s}");
        assert!(s.contains("chunk c/2/0: 15 16 20 21 25 26"), "{s}");
        assert!(s.contains("chunk c/2/1: 17 18 19 22 23 24 27 28 29"), "{s}");
    }

    #[test]
    fn the_sharding_codec_is_read_under_both_of_its_names() {
        // The codec was called `sharding` before zarr-python 3.4, and the
        // specification kept the old name too. Both are read: a shard is a
        // shard under either of them.
        for name in ["sharding_indexed", "sharding"] {
            match Zarr.extract(&v3_sharding(name, "end"), "/tmp/x/zarr.json") {
                Ok(_) => {}
                Err(e) => panic!("{name}: the codec is refused: {e}"),
            }
        }
    }

    #[test]
    fn a_shard_can_hold_its_index_at_the_start() {
        // The index of a shard is at the end of it by default, and at the
        // start of it when the codec says so. The offsets in the index are
        // the offsets in the shard either way.
        let dir = std::env::temp_dir().join(format!("rgx-zarr-index-start-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("c").join("0")).expect("the directory");

        // The four inner chunks of the shard, each of them 2x3: the rows
        // two by two and the columns three by three.
        let chunks: [[f64; 6]; 4] = [
            [1.0, 2.0, 3.0, 7.0, 8.0, 9.0],
            [4.0, 5.0, 6.0, 10.0, 11.0, 12.0],
            [13.0, 14.0, 15.0, 19.0, 20.0, 21.0],
            [16.0, 17.0, 18.0, 22.0, 23.0, 24.0],
        ];
        // The index: the offset and the length of every inner chunk, and
        // then the checksum of the index.
        let mut index = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            index.extend_from_slice(&((68 + i * 48) as u64).to_le_bytes());
            index.extend_from_slice(&(chunk.len() as u64 * 8).to_le_bytes());
        }
        let mut shard = index.clone();
        shard.extend_from_slice(&crc32c(&index).to_le_bytes());
        for chunk in chunks.iter() {
            for v in chunk {
                shard.extend_from_slice(&v.to_le_bytes());
            }
        }
        std::fs::write(dir.join("c").join("0").join("0"), &shard).expect("the shard");
        std::fs::write(
            dir.join("zarr.json"),
            v3_sharding("sharding_indexed", "start"),
        )
        .expect("the manifest");

        let path = dir.join("zarr.json");
        let data = std::fs::read(&path).expect("the manifest");
        let out = Zarr
            .extract(&data, &path.to_string_lossy())
            .expect("the array");
        let Outcome::Text(t) = out else {
            panic!("the answer is text");
        };
        let s = String::from_utf8(t).expect("the answer is utf-8");
        assert!(
            s.contains(
                "chunk c/0/0: 1.0 2.0 3.0 4.0 5.0 6.0 7.0 8.0 9.0 \
                        10.0 11.0 12.0 13.0 14.0 15.0 16.0 17.0 18.0 \
                        19.0 20.0 21.0 22.0 23.0 24.0"
            ),
            "{s}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_chunk_grid_that_is_neither_regular_nor_rectilinear_is_refused() {
        // The core specification has no chunk grid but the regular one, and
        // the extensions have the rectilinear one. A grid that is neither
        // is refused by name.
        let msg = refusal(&v3_with(
            r#"{"name": "irregular", "configuration": {"chunk_shape": [2, 3]}}"#,
            r#"{"name": "bytes", "configuration": {"endian": "little"}}"#,
        ));
        assert!(msg.contains("irregular"), "{msg}");
        assert!(msg.contains("chunk grid"), "{msg}");
    }

    #[test]
    fn the_crc32c_is_the_one_the_index_codec_calls_crc32c() {
        // The check value of CRC-32C, the Castagnoli polynomial.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn the_shard_s_index_carries_its_checksum() {
        // The index of the shard in the fixture is the last 68 bytes of it:
        // 64 bytes of offsets and lengths, and the 4 bytes of the crc32c
        // that says the index is whole. The checksum is the one the
        // `google_crc32c` package -- the one zarr-python's own crc32c codec
        // is built on -- gives for those 64 bytes.
        let shard = std::fs::read(fixture("f64-sharding-v3").join("c").join("0").join("0"))
            .expect("the shard");
        let index = &shard[shard.len() - 68..];
        let stored = u32::from_le_bytes(index[64..68].try_into().expect("four bytes"));
        assert_eq!(stored, 0x364C_9F3D);
        assert_eq!(crc32c(&index[..64]), stored);
    }

    #[test]
    fn a_shard_whose_index_does_not_match_its_checksum_is_refused() {
        // The index says where the inner chunks are, and the checksum says
        // the index is whole. A shard whose index does not match is
        // refused, not guessed at.
        let dir = std::env::temp_dir().join(format!("rgx-zarr-checksum-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("c").join("0")).expect("the directory");
        let src = fixture("f64-sharding-v3");
        std::fs::copy(src.join("zarr.json"), dir.join("zarr.json")).expect("the manifest");
        let mut shard = std::fs::read(src.join("c").join("0").join("0")).expect("the shard");
        let last = shard.len() - 1;
        shard[last] ^= 0xFF;
        std::fs::write(dir.join("c").join("0").join("0"), &shard).expect("the shard");

        let path = dir.join("zarr.json");
        let data = std::fs::read(&path).expect("the manifest");
        let msg = match Zarr.extract(&data, &path.to_string_lossy()) {
            Ok(_) => panic!("a shard whose index is broken is not decoded"),
            Err(e) => format!("{e}"),
        };
        assert!(msg.contains("checksum"), "{msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rectilinear_axis_can_be_a_step_or_a_run() {
        // An axis of the rectilinear grid is either a number -- a step
        // repeated until the steps cover the axis -- or a list of edges, in
        // which a pair is that many edges of that length. The first axis
        // here is a run of two edges of two, the second a step of three:
        // the grid is two by two, and the chunks are 2x3.
        let s = answer(&v3_with(
            r#"{"name": "rectilinear", "configuration": {"kind": "inline", "chunk_shapes": [[[2, 2]], 3]}}"#,
            r#"{"name": "bytes", "configuration": {"endian": "little"}}"#,
        ));
        assert!(s.contains("chunks=[[2, 2], [3, 3]]"), "{s}");
        assert!(s.contains("chunk c/0/0: 0.0 0.0 0.0 0.0 0.0 0.0"), "{s}");
        assert!(s.contains("chunk c/1/1: 0.0 0.0 0.0 0.0 0.0 0.0"), "{s}");
        // And there are four chunks and no more.
        assert_eq!(s.matches("chunk c/").count(), 4, "{s}");
    }

    #[test]
    fn a_rectilinear_edge_past_the_end_of_the_axis_holds_nothing() {
        // The edges of an axis may reach past the end of the array, the
        // way the last chunk of a regular grid does. The edges that do are
        // not chunks: the array does not reach them.
        let s = answer(&v3_with(
            r#"{"name": "rectilinear", "configuration": {"kind": "inline", "chunk_shapes": [[[2, 3]], 3]}}"#,
            r#"{"name": "bytes", "configuration": {"endian": "little"}}"#,
        ));
        assert!(s.contains("chunks=[[2, 2, 2], [3, 3]]"), "{s}");
        // The first axis is four long and its edges are two, two and two:
        // the third one starts where the axis ends, so there are two
        // chunks along it and not three.
        assert_eq!(s.matches("chunk c/").count(), 4, "{s}");
        assert!(s.contains("chunk c/1/1: 0.0 0.0 0.0 0.0 0.0 0.0"), "{s}");
    }

    /// A v3 manifest with the given codecs.
    fn v3(codecs: &str) -> Vec<u8> {
        v3_with(
            r#"{"name": "regular", "configuration": {"chunk_shape": [2, 3]}}"#,
            codecs,
        )
    }

    /// A v3 manifest with the given chunk grid and codecs.
    fn v3_with(grid: &str, codecs: &str) -> Vec<u8> {
        format!(
            "{{\"shape\": [4, 6], \"data_type\": \"float64\",
\"chunk_grid\": {grid},
\"chunk_key_encoding\": {{\"name\": \"default\", \"configuration\": {{\"separator\": \"/\"}}}},
\"fill_value\": 0.0, \"codecs\": [{codecs}], \"attributes\": {{}},
\"zarr_format\": 3, \"node_type\": \"array\", \"storage_transformers\": []}}"
        )
        .into_bytes()
    }

    /// A v3 manifest whose pipeline is the sharding codec, under the given
    /// name, with the index where the codec says.
    fn v3_sharding(name: &str, index_location: &str) -> Vec<u8> {
        v3_with(
            r#"{"name": "regular", "configuration": {"chunk_shape": [4, 6]}}"#,
            &format!(
                r#"{{"name": "{name}", "configuration": {{
"chunk_shape": [2, 3],
"codecs": [{{"name": "bytes", "configuration": {{"endian": "little"}}}}],
"index_codecs": [{{"name": "bytes", "configuration": {{"endian": "little"}}}}, {{"name": "crc32c"}}],
"index_location": "{index_location}"}}}}"#
            ),
        )
    }

    /// The error the reader gives for a manifest, or a panic.
    fn refusal(manifest: &[u8]) -> String {
        match Zarr.extract(manifest, "/tmp/x/zarr.json") {
            Ok(_) => panic!("the manifest is refused"),
            Err(e) => format!("{e}"),
        }
    }

    /// The answer the reader gives for a manifest, or a panic.
    fn answer(manifest: &[u8]) -> String {
        match Zarr.extract(manifest, "/tmp/x/zarr.json") {
            Ok(Outcome::Text(t)) => String::from_utf8(t).expect("the answer is utf-8"),
            Ok(_) => panic!("the answer is text"),
            Err(e) => panic!("the array is refused: {e}"),
        }
    }

    #[test]
    fn a_transpose_that_is_not_a_permutation_is_refused() {
        // The order of the transpose codec has to be a permutation of the
        // array's axes. One that is not is refused by name, the way
        // zarr-python refuses it.
        let twice = refusal(&v3(
            r#"{"name": "transpose", "configuration": {"order": [0, 0]}},
{"name": "bytes", "configuration": {"endian": "little"}}"#,
        ));
        assert!(twice.contains("transpose"), "{twice}");
        assert!(twice.contains("twice"), "{twice}");

        let too_many = refusal(&v3(
            r#"{"name": "transpose", "configuration": {"order": [1, 0, 2]}},
{"name": "bytes", "configuration": {"endian": "little"}}"#,
        ));
        assert!(too_many.contains("transpose"), "{too_many}");
        assert!(too_many.contains("3 entries"), "{too_many}");

        let too_big = refusal(&v3(
            r#"{"name": "transpose", "configuration": {"order": [1, 2]}},
{"name": "bytes", "configuration": {"endian": "little"}}"#,
        ));
        assert!(too_big.contains("transpose"), "{too_big}");
        assert!(too_big.contains("not one of the array's"), "{too_big}");
    }

    #[test]
    fn a_transpose_after_the_bytes_codec_is_refused() {
        // The transpose codec rearranges the elements and not the bytes,
        // so it sits before the bytes codec in the pipeline. One that
        // comes after it is a pipeline zarr-python refuses.
        let msg = refusal(&v3(
            r#"{"name": "bytes", "configuration": {"endian": "little"}},
{"name": "transpose", "configuration": {"order": [1, 0]}}"#,
        ));
        assert!(msg.contains("transpose"), "{msg}");
        assert!(msg.contains("after the bytes codec"), "{msg}");
    }

    #[test]
    fn the_facts_of_a_group_are_the_manifests_of_its_arrays() {
        let path = fixture("group-consolidated").join(".zmetadata");
        let data = std::fs::read(&path).expect("the metadata");
        let facts = Zarr.facts(&data, &path.to_string_lossy());
        let arrays: Vec<&str> = facts
            .iter()
            .filter(|f| f.name == "zarr.array")
            .map(|f| f.value.as_str())
            .collect();
        assert_eq!(arrays, vec!["first", "nested/second"]);
        let shapes: Vec<&str> = facts
            .iter()
            .filter(|f| f.name == "zarr.shape")
            .map(|f| f.value.as_str())
            .collect();
        assert_eq!(shapes, vec!["[2, 3]", "[4]"]);
    }

    #[test]
    fn a_manifest_that_is_not_a_zarr_is_declined() {
        // A manifest that is not JSON is not this adapter's.
        let err = match Zarr.extract(b"not json at all", "/tmp/x/.zarray") {
            Ok(_) => panic!("text that is not JSON is not an array"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("JSON"), "{err}");
        // And a manifest for another version of the format is refused.
        let other = br#"{"zarr_format": 4, "shape": [1], "chunks": [1], "dtype": "<f8"}"#;
        let err = match Zarr.extract(other, "/tmp/x/.zarray") {
            Ok(_) => panic!("a layout this adapter does not read is not decoded"),
            Err(e) => e,
        };
        assert!(format!("{err}").contains("zarr_format"), "{err}");
    }

    #[test]
    fn the_facts_are_the_manifest() {
        let path = fixture("f64-zlib").join(".zarray");
        let data = std::fs::read(&path).expect("the manifest");
        let facts = Zarr.facts(&data, &path.to_string_lossy());
        let get = |name: &str| {
            facts
                .iter()
                .find(|f| f.name == name)
                .map(|f| f.value.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("zarr.shape"), "[4, 6]");
        assert_eq!(get("zarr.chunks"), "[2, 3]");
        assert_eq!(get("zarr.dtype"), "<f8");
        assert_eq!(get("zarr.compressor"), "zlib");
        assert_eq!(get("zarr.order"), "C");
    }
}
