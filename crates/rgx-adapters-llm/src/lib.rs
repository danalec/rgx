// SPDX-License-Identifier: Apache-2.0

//! Machine-learning model file adapters.
//!
//! These never extract weights (multi-GB payloads of floats are useless for
//! text search) — they extract *metadata*: tensors, shapes, hyperparameters,
//! architecture strings. That is exactly what an LLM agent wants when grepping
//! a model zoo.

#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::boxed::Box;
use alloc::vec::Vec;
use rgx_core::Adapter;

// The safetensors, npy, protobuf and tiktoken adapters name `String` in
// their own code; the gguf adapter only builds one through `format!`.
#[cfg(any(
    feature = "safetensors",
    feature = "npy",
    feature = "protobuf",
    feature = "tiktoken"
))]
use alloc::string::String;

// The gguf, npy and tiktoken adapters turn a number into a `String`.
#[cfg(any(feature = "gguf", feature = "npy", feature = "tiktoken"))]
use alloc::string::ToString;

// Only the safetensors adapter reads its header as text.
#[cfg(feature = "safetensors")]
use core::str;

// The safetensors, protobuf and tiktoken adapters write into their
// report.
#[cfg(any(feature = "safetensors", feature = "protobuf", feature = "tiktoken"))]
use core::fmt::Write as _;

// The gguf and npy adapters report a broken file.
#[cfg(any(feature = "gguf", feature = "npy"))]
use rgx_core::bail;

// Every adapter declines a file it does not recognise.
#[cfg(any(
    feature = "gguf",
    feature = "safetensors",
    feature = "npy",
    feature = "protobuf",
    feature = "tiktoken"
))]
use rgx_core::decline;

// Only the safetensors adapter attaches a context to a failure.
#[cfg(feature = "safetensors")]
use rgx_core::Context;

// Every adapter answers with a `Result`.
#[cfg(any(
    feature = "gguf",
    feature = "safetensors",
    feature = "npy",
    feature = "protobuf",
    feature = "tiktoken"
))]
use rgx_core::Result;

// The gguf and safetensors adapters report facts.
#[cfg(any(feature = "gguf", feature = "safetensors"))]
use rgx_core::Field;

// Every adapter answers with an `Outcome`.
#[cfg(any(
    feature = "gguf",
    feature = "safetensors",
    feature = "npy",
    feature = "protobuf",
    feature = "tiktoken"
))]
use rgx_core::Outcome;

// The gguf and npy adapters read little-endian integers out of the file.
#[cfg(any(feature = "gguf", feature = "npy"))]
fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
#[cfg(any(feature = "gguf", feature = "npy"))]
fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
// The gguf and safetensors adapters read a little-endian `u64`.
#[cfg(any(feature = "gguf", feature = "safetensors"))]
fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
// Only the gguf adapter reads a float out of the file.
#[cfg(feature = "gguf")]
fn rd_f32(b: &[u8], o: usize) -> f32 {
    f32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[cfg(feature = "gguf")]
fn rd_f64(b: &[u8], o: usize) -> f64 {
    f64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

// The keras, torch and pickle adapters live in `extra.rs`.
#[cfg(any(feature = "keras", feature = "torch", feature = "pickle"))]
mod extra;

pub fn adapters() -> Vec<Box<dyn Adapter>> {
    vec![
        #[cfg(feature = "gguf")]
        Box::new(Gguf),
        #[cfg(feature = "safetensors")]
        Box::new(Safetensors),
        #[cfg(feature = "npy")]
        Box::new(Npy),
        #[cfg(feature = "protobuf")]
        Box::new(Protobuf),
        #[cfg(feature = "tiktoken")]
        Box::new(Tiktoken),
        #[cfg(feature = "keras")]
        Box::new(extra::KerasZip),
        #[cfg(feature = "torch")]
        Box::new(extra::Torch),
        #[cfg(feature = "pickle")]
        Box::new(extra::PickleStrings),
    ]
}

/// GGUF (llama.cpp model containers): header + key/value metadata.
///
/// Layout: magic "GGUF", u32 version, u64 n_tensors, u64 n_kv, then n_kv
/// entries of: string key, u32 value-type, value. Strings are u64-len
/// prefixed; array values are u32-type + u64-len + elements.
#[cfg(feature = "gguf")]
pub struct Gguf;
#[cfg(feature = "gguf")]
impl Adapter for Gguf {
    fn name(&self) -> &'static str {
        "gguf"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["gguf"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 24 || &data[0..4] != b"GGUF" {
            decline!("not a GGUF file (bad magic)");
        }
        let version = rd_u32(data, 4);
        if version > 3 {
            bail!("unsupported GGUF version {version}");
        }
        let n_kv = rd_u64(data, 16) as usize;
        let mut p = 24usize;
        let mut out = format!("gguf version: {version}\n");
        for _ in 0..n_kv.min(4096) {
            if p + 8 > data.len() {
                break;
            }
            let klen = rd_u64(data, p) as usize;
            p += 8;
            // checked_add: klen comes from the file and may be usize::MAX —
            // `p + klen + 4` would overflow before the bound check ran, and
            // the one value the first check let through (`kend ==
            // usize::MAX`) wrapped the second add to a pass and panicked
            // the key slice below.
            let Some(kend) = p.checked_add(klen) else {
                break;
            };
            let Some(after_key) = kend.checked_add(4) else {
                break;
            };
            if after_key > data.len() {
                break;
            }
            // Borrow the key as `&str`; the previous shape allocated
            // an owned String for every header key. The `writeln!`
            // below is happy to take a borrowed slice, and the
            // vtype/match arms below push the value directly into
            // `out` so the only String allocation in this loop
            // is gone.
            let key = core::str::from_utf8(&data[p..kend]).unwrap_or("");
            p = kend;
            let vtype = rd_u32(data, p);
            p += 4;
            // fixed-size values: ensure the payload fits before reading —
            // the +4 guard above only covered the type tag itself
            let vsz = match vtype {
                0 | 1 | 7 => 1,
                2 | 3 => 2,
                4..=6 => 4,
                8..=10 => 8,
                _ => 0,
            };
            if vsz > 0 && p + vsz > data.len() {
                break;
            }
            use core::fmt::Write as _;
            let _ = write!(out, "{key}: ");
            match vtype {
                0 | 1 => {
                    let v = data[p];
                    p += 1;
                    let _ = write!(out, "{v}");
                }
                2 => {
                    let v = rd_u16(data, p);
                    p += 2;
                    let _ = write!(out, "{v}");
                }
                3 => {
                    let v = rd_u16(data, p) as i16;
                    p += 2;
                    let _ = write!(out, "{v}");
                }
                4 => {
                    let v = rd_u32(data, p);
                    p += 4;
                    let _ = write!(out, "{v}");
                }
                5 => {
                    let v = rd_u32(data, p) as i32;
                    p += 4;
                    let _ = write!(out, "{v}");
                }
                6 => {
                    let v = rd_f32(data, p);
                    p += 4;
                    let _ = write!(out, "{v}");
                }
                7 => {
                    bail!("bool GGUF value unsupported")
                }
                8 => {
                    let v = rd_u64(data, p);
                    p += 8;
                    let _ = write!(out, "{v}");
                }
                9 => {
                    let v = rd_u64(data, p) as i64;
                    p += 8;
                    let _ = write!(out, "{v}");
                }
                10 => {
                    let v = rd_f64(data, p);
                    p += 8;
                    let _ = write!(out, "{v}");
                }
                11 => {
                    // string
                    if p + 8 > data.len() {
                        break;
                    }
                    let vlen = rd_u64(data, p) as usize;
                    p += 8;
                    if vlen > data.len().saturating_sub(p) {
                        break;
                    }
                    // Borrow the string slice; do not allocate.
                    let s = core::str::from_utf8(&data[p..p + vlen]).unwrap_or("");
                    let _ = write!(out, "{s}");
                    p += vlen;
                }
                12..=15 => {
                    // array of u8/i8/u16/i16/u32/i32/f32/u64/i64/f64/bool/str
                    if p + 4 + 8 > data.len() {
                        break;
                    }
                    let etype = rd_u32(data, p);
                    p += 4;
                    let elen = rd_u64(data, p) as usize;
                    p += 8;
                    let sz = match etype {
                        0 | 1 => 1,
                        2 | 3 => 2,
                        4 | 5 | 6 | 10 => 4,
                        7 => 1,
                        8 | 9 | 11 => 8,
                        _ => break,
                    };
                    p = p.saturating_add(elen.saturating_mul(sz));
                    let _ = writeln!(out, "<array len={elen}>");
                    // The value was already terminated by the array
                    // length line; skip the per-key writeln below.
                    continue;
                }
                _ => break,
            };
            // Terminate the key:value line.
            let _ = writeln!(out);
        }
        // tensor names: u64 n * (string name, u32 n_dims, u64 dims..., u32 type, u64 offset)
        // already reported counts in header; tensor names are nice-to-have, skip safely
        Ok(Outcome::Text(out.into_bytes()))
    }

    /// The facts the `--filter` asks about: how many tensors the header
    /// declares.
    ///
    /// The summary reads the key/value metadata and stops there -- the
    /// tensor directory is not walked -- so the names and the shapes of
    /// the tensors are not facts this adapter can honestly report. The
    /// count is, and it is the count the header carries.
    fn facts(&self, data: &[u8], _path: &str) -> Vec<Field> {
        if data.len() < 24 || &data[0..4] != b"GGUF" {
            return Vec::new();
        }
        vec![Field::new("tensor.count", &rd_u64(data, 8).to_string())]
    }
}

/// One tensor as the safetensors header describes it.
#[cfg(feature = "safetensors")]
struct TensorInfo {
    name: String,
    dtype: String,
    shape: Vec<Option<u64>>,
}

/// What a safetensors header holds: its metadata and its tensors.
#[cfg(feature = "safetensors")]
struct StHeader {
    /// The `__metadata__` entries, in the order the summary prints them.
    meta: Vec<(String, String)>,
    /// The tensors, in the order the summary prints them.
    tensors: Vec<TensorInfo>,
}

/// The shape as the summary renders it: `[2x3]`, with a `?` for a
/// dimension the header did not give.
///
/// The summary and the fact share this one function, so the value a
/// filter sees is the value the text shows.
#[cfg(feature = "safetensors")]
fn shape_text(shape: &[Option<u64>]) -> String {
    let mut out = String::from("[");
    for (i, s) in shape.iter().enumerate() {
        if i > 0 {
            out.push('x');
        }
        match s {
            Some(u) => {
                let _ = write!(out, "{u}");
            }
            None => out.push('?'),
        }
    }
    out.push(']');
    out
}

/// Read a safetensors header: its metadata and its tensors.
///
/// `Ok(None)` means the file is not a safetensors file -- too small, or
/// with a header length that does not fit. A header that is there and
/// broken is an error, with the context the summary gives it.
#[cfg(feature = "safetensors")]
fn st_read(data: &[u8]) -> Result<Option<StHeader>> {
    if data.len() < 8 {
        return Ok(None);
    }
    let hlen = rd_u64(data, 0) as usize;
    // saturating_sub: an absurd hlen must fail the bound, not the
    // addition (8 + hlen overflowed with hlen = usize::MAX)
    if hlen == 0 || hlen > (1 << 26) || hlen > data.len().saturating_sub(8) {
        return Ok(None);
    }
    let text = str::from_utf8(&data[8..8 + hlen]).context("safetensors header is not UTF-8")?;
    // The lazy walk, not the Arena parser: the summary reads two
    // fields per tensor and the metadata strings -- `data_offsets`
    // and any extra fields are validated and never materialised.
    // Every walk error takes the same context the Arena parser's
    // errors took. The output keeps the Arena parser's key order
    // (first-appearance rank) and its last-wins duplicate
    // semantics, pinned byte for byte by the golden tests.
    let mut doc = rgx_core::djson::ondemand::Ondemand::new(text)
        .map_err(rgx_core::Error::msg)
        .context("safetensors header is not JSON")?;
    let jerr = |e: rgx_core::djson::parser::JsonParseError| {
        rgx_core::Error::msg(e).context("safetensors header is not JSON")
    };

    // Collected in source order, deduped last-wins by key name -- the
    // `BTreeMap` lookup semantics of the parser being replaced. The
    // duplicate test is a map lookup on both groups: a linear scan per
    // entry made a header of hundreds of thousands of keys quadratic,
    // and the header cap is 64 MB of them.
    let mut meta: Vec<(String, String)> = Vec::new();
    let mut meta_idx: alloc::collections::BTreeMap<String, usize> =
        alloc::collections::BTreeMap::new();
    let mut tensors: Vec<TensorInfo> = Vec::new();
    let mut tensor_idx: alloc::collections::BTreeMap<String, usize> =
        alloc::collections::BTreeMap::new();

    let mut root = doc.root().map_err(jerr)?;
    if root.is_object().map_err(jerr)? {
        root.object_entries(|k, mut v| {
            if k.as_ref() == "__metadata__" {
                // The LAST `__metadata__` entry wins outright.
                meta.clear();
                meta_idx.clear();
                if v.is_object()? {
                    v.object_entries(|mk, mv| {
                        let key = mk.into_owned();
                        let val = mv
                            .as_str()?
                            .map(|s| s.into_owned())
                            .unwrap_or_else(|| String::from("?"));
                        match meta_idx.get(&key) {
                            Some(&i) => meta[i].1 = val,
                            None => {
                                meta_idx.insert(key.clone(), meta.len());
                                meta.push((key, val));
                            }
                        }
                        Ok(true)
                    })?;
                } else {
                    v.skip()?;
                }
                return Ok(true);
            }
            let name = k.into_owned();
            let mut dtype = String::from("?");
            let mut shape: Vec<Option<u64>> = Vec::new();
            if v.is_object()? {
                v.object_entries(|tk, mut tv| {
                    match tk.as_ref() {
                        "dtype" => {
                            dtype = tv
                                .as_str()?
                                .map(|s| s.into_owned())
                                .unwrap_or_else(|| String::from("?"));
                        }
                        "shape" => {
                            // Last `shape` key wins, and a
                            // non-array one prints as empty.
                            shape.clear();
                            if tv.is_array()? {
                                tv.array_items(|_, item| {
                                    shape.push(item.as_u64()?);
                                    Ok(true)
                                })?;
                            }
                        }
                        _ => {}
                    }
                    Ok(true)
                })?;
            } else {
                v.skip()?;
            }
            match tensor_idx.get(&name) {
                Some(&i) => tensors[i] = TensorInfo { name, dtype, shape },
                None => {
                    tensor_idx.insert(name.clone(), tensors.len());
                    tensors.push(TensorInfo { name, dtype, shape });
                }
            }
            Ok(true)
        })
        .map_err(jerr)?;
    } else {
        root.skip().map_err(jerr)?;
    }
    doc.finish().map_err(jerr)?;

    // Sort both groups into the Arena parser's iteration order:
    // ascending first-appearance rank of the key string anywhere in
    // the document. One rank pass answers every name at once.
    let mut rank_names: Vec<&str> = meta.iter().map(|(k, _)| k.as_str()).collect();
    rank_names.extend(tensors.iter().map(|t| t.name.as_str()));
    let ranks = doc.first_string_positions(&rank_names);
    let mut rank_of: alloc::collections::BTreeMap<&str, usize> =
        alloc::collections::BTreeMap::new();
    for (n, r) in rank_names.iter().zip(ranks) {
        rank_of.entry(*n).or_insert(r);
    }
    let meta_ranks: Vec<usize> = meta.iter().map(|(k, _)| rank_of[k.as_str()]).collect();
    let tensor_ranks: Vec<usize> = tensors.iter().map(|t| rank_of[t.name.as_str()]).collect();
    drop(rank_of);
    let mut tagged: Vec<(usize, (String, String))> = meta.into_iter().enumerate().collect();
    tagged.sort_by_key(|(i, _)| meta_ranks[*i]);
    let meta: Vec<(String, String)> = tagged.into_iter().map(|(_, e)| e).collect();
    let mut tagged: Vec<(usize, TensorInfo)> = tensors.into_iter().enumerate().collect();
    tagged.sort_by_key(|(i, _)| tensor_ranks[*i]);
    let tensors: Vec<TensorInfo> = tagged.into_iter().map(|(_, t)| t).collect();

    Ok(Some(StHeader { meta, tensors }))
}

/// Hugging Face safetensors: 8-byte LE header length + JSON header.
#[cfg(feature = "safetensors")]
pub struct Safetensors;
#[cfg(feature = "safetensors")]
impl Adapter for Safetensors {
    fn name(&self) -> &'static str {
        "safetensors"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["safetensors", "sft", "st"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 8 {
            decline!("too small for safetensors");
        }
        let Some(header) = st_read(data)? else {
            decline!("bad safetensors header length");
        };
        use core::fmt::Write as _;
        let mut out = String::new();
        for (k, v) in &header.meta {
            let _ = writeln!(out, "{k}: {v}");
        }
        for t in &header.tensors {
            let _ = writeln!(
                out,
                "tensor {}: dtype={} shape={}",
                t.name,
                t.dtype,
                shape_text(&t.shape)
            );
        }
        Ok(Outcome::Text(out.into_bytes()))
    }

    /// The facts the `--filter` asks about: one per tensor.
    ///
    /// The names are `tensor.name`, `tensor.shape` and `tensor.dtype`,
    /// so `tensor:name:transformer` asks for a tensor whose name says
    /// so, `tensor:shape` asks whether the model has a tensor at all,
    /// and `tensor:shape:768` asks for one whose shape says 768.
    fn facts(&self, data: &[u8], _path: &str) -> Vec<Field> {
        let Ok(Some(header)) = st_read(data) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for t in &header.tensors {
            out.push(Field::new("tensor.name", &t.name));
            out.push(Field::new("tensor.shape", &shape_text(&t.shape)));
            // The dtype is a fact only when the header gave one: the
            // summary prints "?" for a tensor whose dtype it could not
            // read, and "?" is not a dtype.
            if !t.dtype.is_empty() && t.dtype != "?" {
                out.push(Field::new("tensor.dtype", &t.dtype));
            }
        }
        out
    }
}

/// NumPy .npy v1/v2: magic \x93NUMPY, version, header-length, header dict.
#[cfg(feature = "npy")]
pub struct Npy;
#[cfg(feature = "npy")]
impl Adapter for Npy {
    fn name(&self) -> &'static str {
        "npy"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["npy"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 10 || &data[0..6] != b"\x93NUMPY" {
            decline!("not an npy file (bad magic)");
        }
        let major = data[6];
        let (hlen, hoff) = match major {
            1 => (rd_u16(data, 8) as usize, 10usize),
            2 | 3 => (rd_u32(data, 8) as usize, 12usize),
            _ => bail!("unsupported npy version {major}"),
        };
        if hoff + hlen > data.len() {
            bail!("npy header overruns file");
        }
        // The header is a Python literal dict; parse the three keys we need
        // without evaluating anything.
        let header = String::from_utf8_lossy(&data[hoff..hoff + hlen]);
        let get = |key: &str| -> String {
            let pat = format!("'{key}':").to_lowercase();
            let h = header.to_lowercase();
            let Some(mut i) = h.find(&pat) else {
                return "?".into();
            };
            i += pat.len();
            let rest = header[i..].trim_start();
            // scan the value: tuples like (2, 3) run to their ')', scalars
            // and strings stop at ',' or '}'
            let bytes = rest.as_bytes();
            let mut depth = 0usize;
            let mut end = bytes.len();
            for (j, &c) in bytes.iter().enumerate() {
                match c {
                    b'(' | b'[' => depth += 1,
                    b')' | b']' => {
                        if depth == 0 {
                            end = j + 1;
                            break;
                        }
                        depth -= 1;
                        if depth == 0 {
                            end = j + 1;
                            break;
                        }
                    }
                    b',' | b'}' if depth == 0 => {
                        end = j;
                        break;
                    }
                    _ => {}
                }
            }
            rest[..end].trim().trim_matches('\'').to_string()
        };
        let descr = get("descr");
        let fortran = get("fortran_order");
        let shape = get("shape").replace(['(', ')'], "");
        let itemsize: usize = descr
            .chars()
            .skip(1)
            .collect::<String>()
            .parse()
            .unwrap_or(0);
        // saturating: the shape is the file's own arithmetic, and a plain
        // product panics under overflow checks and wraps without them.
        let count: usize = shape
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .fold(1usize, usize::saturating_mul);
        let payload = data.len() - (hoff + hlen);
        let text = format!(
            "npy: descr={descr} fortran_order={fortran} shape=({shape}) elements={count} payload_bytes={payload} itemsize={itemsize}\n"
        );
        Ok(Outcome::Text(text.into_bytes()))
    }
}

/// Protobuf wire format: walk fields, print printable length-delimited
/// payloads (architecture strings, vocab entries, names). Covers
/// .onnx/.pb/.model without pulling a full protobuf stack.
#[cfg(feature = "protobuf")]
pub struct Protobuf;
#[cfg(feature = "protobuf")]
impl Adapter for Protobuf {
    fn name(&self) -> &'static str {
        "protobuf"
    }
    fn extensions(&self) -> &'static [&'static str] {
        // `tflite` and `pt2` were listed here and are deliberately NOT. A
        // TFLite model is FlatBuffers and a `.pt2` is a zipped torch archive,
        // so the plausibility check below either refused them (LOUD, a wrong
        // adapter claiming an extension it cannot read) or, worse, accepted a
        // FlatBuffers buffer whose first 16 bytes hold no NUL and rendered it
        // as protobuf field names that do not exist. Claiming the extension an
        // adapter cannot read is how a wrong answer gets printed with
        // confidence; leaving it unclaimed is not a gap, because an unclaimed
        // extension falls through to the raw search and keeps `rg`'s answer.
        // `pt2` belongs to extra::Torch, and `tflite` has no reader here yet.
        &["pb", "onnx", "model", "mlmodel"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // cheap plausibility check: a protobuf usually starts with a
        // field tag (varint key != 0) and has no NULs in the first 16 bytes
        if data.len() < 8 || data[0] == 0 {
            decline!("not plausibly protobuf");
        }
        if data[..16.min(data.len())].contains(&0) {
            decline!("NUL in protobuf header region");
        }
        let mut out = String::new();
        let mut p = 0usize;
        let mut depth = 0usize;
        while p < data.len() && out.len() < 1 << 20 {
            // read varint key
            let mut key: u64 = 0;
            let mut shift = 0;
            let key_start = p;
            while p < data.len() && shift < 64 {
                let b = data[p];
                p += 1;
                key |= ((b & 0x7f) as u64) << shift;
                if b & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            if p == key_start || p - key_start > 10 {
                break;
            }
            let field = key >> 3;
            let wire = key & 7;
            match wire {
                0 => {
                    // varint
                    let mut v: u64 = 0;
                    let mut shift = 0;
                    while p < data.len() && shift < 64 {
                        let b = data[p];
                        p += 1;
                        v |= ((b & 0x7f) as u64) << shift;
                        if b & 0x80 == 0 {
                            break;
                        }
                        shift += 7;
                    }
                    if field <= 100_000 && out.len() < 1 << 18 {
                        let _ = writeln!(out, "field {field}: {v}");
                    }
                }
                1 => p = p.saturating_add(8), // 64-bit
                2 => {
                    // length-delimited
                    if p >= data.len() {
                        break;
                    }
                    let mut len: u64 = 0;
                    let mut shift = 0;
                    while p < data.len() && shift < 64 {
                        let b = data[p];
                        p += 1;
                        len |= ((b & 0x7f) as u64) << shift;
                        if b & 0x80 == 0 {
                            break;
                        }
                        shift += 7;
                    }
                    if len > (1 << 24) {
                        break;
                    }
                    let len = len as usize;
                    if p + len > data.len() {
                        break;
                    }
                    let payload = &data[p..p + len];
                    // printable text? emit it; else recurse one level
                    let printable = !payload.is_empty()
                        && payload.len() >= 3
                        && payload
                            .iter()
                            .filter(|&&b| (0x20..0x7f).contains(&b) || b == b'\n')
                            .count()
                            * 10
                            >= payload.len() * 9;
                    if printable {
                        let s = String::from_utf8_lossy(payload);
                        for line in s.lines().take(50) {
                            if !line.trim().is_empty() {
                                out.push_str(line);
                                out.push('\n');
                            }
                        }
                    } else if depth < 3 && len >= 2 {
                        depth += 1;
                        // nested message: walk it inline
                        let mut q = 0usize;
                        let mut local = String::new();
                        while q + 2 < payload.len() && local.len() < 1 << 16 {
                            let nested = &payload[q..];
                            if nested[0] == 0 {
                                break;
                            }
                            let mut nk: u64 = 0;
                            let mut sh = 0;
                            let ns = q;
                            while q < payload.len() && sh < 64 {
                                let b = payload[q];
                                q += 1;
                                nk |= ((b & 0x7f) as u64) << sh;
                                if b & 0x80 == 0 {
                                    break;
                                }
                                sh += 7;
                            }
                            if q == ns || q - ns > 10 {
                                break;
                            }
                            let w = nk & 7;
                            if w == 2 {
                                if q >= payload.len() {
                                    break;
                                }
                                let mut nl: u64 = 0;
                                let mut sh = 0;
                                while q < payload.len() && sh < 64 {
                                    let b = payload[q];
                                    q += 1;
                                    nl |= ((b & 0x7f) as u64) << sh;
                                    if b & 0x80 == 0 {
                                        break;
                                    }
                                    sh += 7;
                                }
                                if nl > (1 << 20) || q + nl as usize > payload.len() {
                                    break;
                                }
                                let sub = &payload[q..q + nl as usize];
                                if !sub.is_empty()
                                    && sub.iter().filter(|&&b| (0x20..=0x7e).contains(&b)).count()
                                        * 10
                                        >= sub.len() * 9
                                {
                                    let s = String::from_utf8_lossy(sub);
                                    for line in s.lines().take(20) {
                                        if !line.trim().is_empty() {
                                            local.push_str(line);
                                            local.push('\n');
                                        }
                                    }
                                }
                                q += nl as usize;
                            } else if w == 0 {
                                while q < payload.len() && payload[q] & 0x80 != 0 {
                                    q += 1;
                                }
                                q = (q + 1).min(payload.len());
                            } else {
                                break;
                            }
                        }
                        out.push_str(&local);
                        depth -= 1;
                    }
                    p += len;
                }
                5 => p = p.saturating_add(4), // 32-bit
                _ => break,                   // groups (3/4) deprecated — stop
            }
            // give up early on files that don't look like protobuf at all
            if out.is_empty() && p > 4096 {
                break;
            }
        }
        if out.trim().is_empty() {
            decline!("no printable protobuf content found");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// OpenAI tiktoken `.tiktoken` vocabularies: lines of `base64 rank`.
/// Decoding each token makes the vocabulary greppable as plain text.
#[cfg(feature = "tiktoken")]
pub struct Tiktoken;
#[cfg(feature = "tiktoken")]
impl Adapter for Tiktoken {
    fn name(&self) -> &'static str {
        "tiktoken"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["tiktoken"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // fast shape check: first line must be "<base64> <digits>"
        let first_nl = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
        let first = String::from_utf8_lossy(&data[..first_nl]);
        let mut parts = first.split_whitespace();
        let (Some(tok), Some(rank), None) = (parts.next(), parts.next(), parts.next()) else {
            decline!("not a tiktoken file (expected '<base64> <rank>')");
        };
        if rank.parse::<u64>().is_err() || rgx_core::base64::base64_decode_strict(tok).is_err() {
            decline!("not a tiktoken file (bad line shape)");
        }
        let mut out = String::new();
        for line in String::from_utf8_lossy(data).lines().take(1_000_000) {
            let mut it = line.split_whitespace();
            let (Some(tok), Some(rank)) = (it.next(), it.next()) else {
                continue;
            };
            if let Ok(bytes) = rgx_core::base64::base64_decode_strict(tok) {
                let text = String::from_utf8_lossy(&bytes);
                let text = text.escape_default().to_string();
                let _ = writeln!(out, "token {rank}: {text}");
            }
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(all(
    test,
    any(
        feature = "gguf",
        feature = "safetensors",
        feature = "npy",
        feature = "protobuf",
        feature = "tiktoken"
    )
))]
mod tests {
    use super::*;

    /// libFuzzer-found: hlen = u64::MAX as usize made `8 + hlen` overflow
    /// in the bound check itself. Must bail, never panic.
    #[cfg(feature = "safetensors")]
    #[test]
    fn safetensors_absurd_header_length() {
        let mut data = u64::MAX.to_le_bytes().to_vec();
        data.extend_from_slice(&[0xff; 27]);
        assert!(Safetensors.extract(&data, "m.safetensors").is_err());
    }

    /// libFuzzer-found: klen/vlen of usize::MAX in the GGUF kv walk
    /// overflowed `p + len + 4`, and u64 values could dangle past EOF.
    #[cfg(feature = "gguf")]
    #[test]
    fn gguf_absurd_lengths_and_tail_values() {
        let mut data = b"GGUF".to_vec();
        data.extend_from_slice(&3u32.to_le_bytes()); // version
        data.extend_from_slice(&[0u8; 8]); // tensor count
        data.extend_from_slice(&1u64.to_le_bytes()); // n_kv
        data.extend_from_slice(&u64::MAX.to_le_bytes()); // klen
        data.extend_from_slice(&[0u8; 64]);
        assert!(Gguf.extract(&data, "m.gguf").is_ok());
        // u64 value as the very last 4+8 bytes: tag fits, value doesn't
        let mut data = b"GGUF".to_vec();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 8]);
        data.extend_from_slice(&1u64.to_le_bytes()); // n_kv
        data.extend_from_slice(&0u64.to_le_bytes()); // klen
        data.extend_from_slice(&8u32.to_le_bytes()); // vtype = u64
        data.extend_from_slice(&[0u8; 4]); // only 4 bytes of the value
        assert!(Gguf.extract(&data, "m.gguf").is_ok());
    }

    #[cfg(feature = "safetensors")]
    #[test]
    fn safetensors_header() {
        let mut header = br#"{"__metadata__":{"format":"pt"},"w":{"dtype":"F32","shape":[2,3],"data_offsets":[0,24]}}"#.to_vec();
        let mut data = (header.len() as u64).to_le_bytes().to_vec();
        data.append(&mut header);
        let st = Safetensors;
        match st.extract(&data, "m.safetensors").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("format: pt"), "{s}");
                assert!(s.contains("tensor w: dtype=F32 shape=[2x3]"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    /// Wrap a JSON header in the 8-byte-length prefix safetensors uses.
    #[cfg(feature = "safetensors")]
    fn st_wrap(header: &[u8]) -> Vec<u8> {
        let mut data = (header.len() as u64).to_le_bytes().to_vec();
        data.extend_from_slice(header);
        data
    }

    /// Golden: the full summary, byte for byte -- including the Arena
    /// parser's key order. `"alpha"` is interned as a shape value of
    /// `zeta` before it appears as a root key, so its tensor line
    /// leads `mid` even though `mid` comes first in the source. The
    /// lazy walk must reproduce this intern-rank order exactly.
    #[cfg(feature = "safetensors")]
    #[test]
    fn safetensors_output_is_pinned_byte_for_byte() {
        let header = br#"{"zeta":{"shape":["alpha"]},"mid":{"dtype":"F16","shape":[1]},"alpha":{"dtype":"BF16","shape":[8]},"__metadata__":{"z":"1"}}"#;
        let out = Safetensors
            .extract(&st_wrap(header), "m.safetensors")
            .unwrap();
        let Outcome::Text(t) = out else {
            panic!("expected text");
        };
        let s = String::from_utf8(t).unwrap();
        assert_eq!(
            s,
            "z: 1\n\
tensor zeta: dtype=? shape=[?]\n\
tensor alpha: dtype=BF16 shape=[8]\n\
tensor mid: dtype=F16 shape=[1]\n"
        );
    }

    /// Golden: `__metadata__` keys come out in intern-rank order too,
    /// duplicate keys keep the last value, and a non-string value
    /// prints `?` -- the `as_str().unwrap_or("?")` contract.
    #[cfg(feature = "safetensors")]
    #[test]
    fn safetensors_metadata_order_dedupe_and_types() {
        let header = br#"{"w":{"dtype":"U8","shape":["meta"]},"__metadata__":{"z":"1","meta":"2","dup":"old","dup":"new","n":7}}"#;
        let out = Safetensors
            .extract(&st_wrap(header), "m.safetensors")
            .unwrap();
        let Outcome::Text(t) = out else {
            panic!("expected text");
        };
        let s = String::from_utf8(t).unwrap();
        assert_eq!(
            s,
            "meta: 2\n\
z: 1\n\
dup: new\n\
n: ?\n\
tensor w: dtype=U8 shape=[?]\n"
        );
    }

    /// Duplicate tensor names collapse to the last entry, matching the
    /// Arena parser's `BTreeMap` lookup.
    #[cfg(feature = "safetensors")]
    #[test]
    fn safetensors_duplicate_tensor_names_take_the_last_value() {
        let header = br#"{"a":{"dtype":"F32","shape":[1]},"a":{"dtype":"BF16","shape":[2,3]}}"#;
        let out = Safetensors
            .extract(&st_wrap(header), "m.safetensors")
            .unwrap();
        let Outcome::Text(t) = out else {
            panic!("expected text");
        };
        let s = String::from_utf8(t).unwrap();
        assert_eq!(s, "tensor a: dtype=BF16 shape=[2x3]\n");
    }

    /// An invalid header is an adapter failure with its context
    /// message, not a silent empty summary.
    #[cfg(feature = "safetensors")]
    #[test]
    fn safetensors_invalid_json_reports_the_context_error() {
        let err = match Safetensors.extract(&st_wrap(br#"{"a": 01}"#), "m.safetensors") {
            Ok(_) => panic!("bad number must fail"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(msg.contains("safetensors header is not JSON"), "{msg}");
    }

    /// The facts a `--filter` asks about: one per tensor, with the
    /// names the header gives them.
    #[cfg(feature = "safetensors")]
    #[test]
    fn safetensors_facts_report_every_tensor_name_and_shape() {
        let header = br#"{"w":{"dtype":"F32","shape":[2,3]},"b":{"dtype":"BF16","shape":[768]}}"#;
        let facts = Safetensors.facts(&st_wrap(header), "m.safetensors");
        let names: Vec<&str> = facts
            .iter()
            .filter(|f| f.name == "tensor.name")
            .map(|f| f.value.as_str())
            .collect();
        assert_eq!(names, vec!["w", "b"]);
        let shapes: Vec<&str> = facts
            .iter()
            .filter(|f| f.name == "tensor.shape")
            .map(|f| f.value.as_str())
            .collect();
        assert_eq!(shapes, vec!["[2x3]", "[768]"]);
        let dtypes: Vec<&str> = facts
            .iter()
            .filter(|f| f.name == "tensor.dtype")
            .map(|f| f.value.as_str())
            .collect();
        assert_eq!(dtypes, vec!["F32", "BF16"]);
    }

    /// A model with no tensor must not report one: `tensor:name` has to
    /// be false for a header that holds only metadata.
    #[cfg(feature = "safetensors")]
    #[test]
    fn safetensors_facts_report_no_tensor_name_without_a_tensor() {
        let facts = Safetensors.facts(
            &st_wrap(br#"{"__metadata__":{"format":"pt"}}"#),
            "m.safetensors",
        );
        assert!(
            facts.iter().all(|f| f.name != "tensor.name"),
            "a model with no tensor must not report one: {facts:?}"
        );
        let e = rgx_core::filter::parse("tensor:name").expect("parses");
        assert!(
            !rgx_core::filter::matches(&e, &facts),
            "the filter must not match a model with no tensor: {facts:?}"
        );
    }

    /// The dtype is a fact when the header gave one, and not when it
    /// did not: "?" is the summary's way of saying "I could not read
    /// it", and "?" is not a dtype.
    #[cfg(feature = "safetensors")]
    #[test]
    fn safetensors_facts_report_the_dtype_only_when_the_header_gives_one() {
        let facts = Safetensors.facts(&st_wrap(br#"{"w":{"shape":[1]}}"#), "m.safetensors");
        assert!(facts.iter().all(|f| f.name != "tensor.dtype"), "{facts:?}");
    }

    /// A filter asks about the facts by name: `tensor:name:transformer`
    /// is the question "is there a tensor whose name says transformer?".
    #[cfg(feature = "safetensors")]
    #[test]
    fn a_filter_asks_a_safetensors_model_about_its_tensors() {
        let header = br#"{"model.transformer.w":{"dtype":"F32","shape":[2,3]}}"#;
        let facts = Safetensors.facts(&st_wrap(header), "m.safetensors");
        let e = rgx_core::filter::parse("tensor:name:transformer").expect("parses");
        assert!(
            rgx_core::filter::matches(&e, &facts),
            "the tensor name must be findable: {facts:?}"
        );
        let e = rgx_core::filter::parse("tensor:shape").expect("parses");
        assert!(
            rgx_core::filter::matches(&e, &facts),
            "a model with tensors must answer the shape question: {facts:?}"
        );
    }

    /// The GGUF summary reads the key/value metadata and not the tensor
    /// directory, so the count is the fact it can honestly report.
    #[cfg(feature = "gguf")]
    #[test]
    fn gguf_facts_report_the_tensor_count() {
        let mut data = b"GGUF".to_vec();
        data.extend_from_slice(&3u32.to_le_bytes()); // version
        data.extend_from_slice(&7u64.to_le_bytes()); // tensor count
        data.extend_from_slice(&0u64.to_le_bytes()); // kv count
        let facts = Gguf.facts(&data, "m.gguf");
        assert_eq!(facts.len(), 1, "{facts:?}");
        assert_eq!(facts[0].name, "tensor.count");
        assert_eq!(facts[0].value, "7");
    }

    #[cfg(feature = "npy")]
    #[test]
    fn npy_v1_header() {
        let mut data = b"\x93NUMPY\x01\x00".to_vec();
        let hdr = b"{'descr': '<f4', 'fortran_order': False, 'shape': (2, 3), }";
        let pad = 64 - ((10 + hdr.len() + 1) % 64);
        data.extend_from_slice(&(hdr.len() as u16).to_le_bytes());
        data.extend_from_slice(hdr);
        data.extend(std::iter::repeat_n(b' ', pad));
        data.push(b'\n');
        data.extend(std::iter::repeat_n(0u8, 24));
        let npy = Npy;
        match npy.extract(&data, "a.npy").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("descr=<f4"), "{s}");
                assert!(s.contains("shape=(2, 3)"), "{s}");
                assert!(s.contains("elements=6"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[cfg(feature = "tiktoken")]
    #[test]
    fn tiktoken_decodes() {
        // base64 of "hello"
        let data = b"aGVsbG8= 42\n";
        let tt = Tiktoken;
        match tt.extract(data, "v.tiktoken").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("token 42: hello"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[cfg(all(
        test,
        any(
            feature = "gguf",
            feature = "safetensors",
            feature = "npy",
            feature = "protobuf"
        )
    ))]
    mod fuzz {
        use super::*;

        #[cfg(feature = "safetensors")]
        fn safetensors_fixture() -> Vec<u8> {
            let header = br#"{"__metadata__":{"format":"pt"},"w":{"dtype":"F32","shape":[2,3],"data_offsets":[0,24]}}"#.to_vec();
            let mut data = (header.len() as u64).to_le_bytes().to_vec();
            data.extend_from_slice(&header);
            data.extend_from_slice(&[0u8; 24]);
            data
        }

        #[cfg(feature = "npy")]
        fn npy_fixture() -> Vec<u8> {
            let mut data = b"\x93NUMPY\x01\x00".to_vec();
            let hdr = b"{'descr': '<f4', 'fortran_order': False, 'shape': (2, 3), }";
            let pad = 64 - ((10 + hdr.len() + 1) % 64);
            data.extend_from_slice(&(hdr.len() as u16).to_le_bytes());
            data.extend_from_slice(hdr);
            data.extend(std::iter::repeat_n(b' ', pad));
            data.push(b'\n');
            data.extend(std::iter::repeat_n(0u8, 24));
            data
        }

        #[cfg(feature = "safetensors")]
        #[test]
        fn safetensors_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![("st", safetensors_fixture()), ("empty", vec![])],
                1200,
                "safetensors",
                |data| {
                    let _ = Safetensors.extract(data, "fuzz.safetensors");
                },
            );
        }

        #[cfg(feature = "safetensors")]
        #[test]
        fn safetensors_facts_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![("st", safetensors_fixture()), ("empty", vec![])],
                1200,
                "safetensors-facts",
                |data| {
                    let _ = Safetensors.facts(data, "fuzz.safetensors");
                },
            );
        }

        #[cfg(feature = "npy")]
        #[test]
        fn npy_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("npy", npy_fixture()),
                    ("magic-only", b"\x93NUMPY\x01\x00".to_vec()),
                    ("empty", vec![]),
                ],
                1200,
                "npy",
                |data| {
                    let _ = Npy.extract(data, "fuzz.npy");
                },
            );
        }

        #[cfg(feature = "gguf")]
        #[test]
        fn gguf_never_panics_on_mutation() {
            // minimal GGUF v3 header: magic, version, tensor_count, metadata_kv_count
            let mut d = b"GGUF".to_vec();
            d.extend_from_slice(&3u32.to_le_bytes());
            d.extend_from_slice(&0u64.to_le_bytes());
            d.extend_from_slice(&0u64.to_le_bytes());
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("gguf", d),
                    ("magic-only", b"GGUF".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "gguf",
                |data| {
                    let _ = Gguf.extract(data, "fuzz.gguf");
                },
            );
        }

        #[cfg(feature = "protobuf")]
        #[test]
        fn protobuf_never_panics_on_mutation() {
            // a couple of protobuf key/value varints
            let mut d = vec![0x08, 0x96, 0x01]; // field 1 varint 150
            d.extend_from_slice(&[0x12, 0x07]); // field 2 len 7
            d.extend_from_slice(b"ZIRCALO");
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("proto", d),
                    ("varint-only", vec![0x08, 0x96, 0x01]),
                    ("empty", vec![]),
                ],
                1500,
                "protobuf",
                |data| {
                    let _ = Protobuf.extract(data, "fuzz.pb");
                },
            );
        }
    }
}
