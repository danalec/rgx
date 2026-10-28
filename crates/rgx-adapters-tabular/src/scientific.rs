// SPDX-License-Identifier: Apache-2.0

//! Scientific data adapters: MATLAB v5, netCDF-3 (classic/64-bit-offset),
//! NASA CDF-3, Arrow IPC / Feather schema strings. All five are common in
//! data-science and engineering harnesses and all five have small
//! enough on-disk anchors to work with by hand. HDF5 gets the superblock
//! fields, the real link names -- read out of the fractal heap and the
//! B-tree that indexes it, or out of the object header itself -- and the
//! attributes of the file and of every member (see `Hdf5` and `hdf5`).

#[cfg(feature = "netcdf3")]
use alloc::collections::BTreeMap;
#[cfg(any(
    feature = "arrow",
    feature = "hdf5",
    feature = "matv5",
    feature = "netcdf3"
))]
use alloc::string::String;
#[cfg(any(feature = "hdf5", feature = "matv5", feature = "netcdf3"))]
use alloc::string::ToString;
#[cfg(any(feature = "matv5", feature = "netcdf3"))]
use alloc::vec::Vec;
#[cfg(any(feature = "hdf5", feature = "netcdf3"))]
use core::fmt::Write as _;

#[cfg(any(feature = "hdf5", feature = "netcdf3"))]
use rgx_core::bail;
#[cfg(any(
    feature = "arrow",
    feature = "hdf5",
    feature = "matv5",
    feature = "netcdf3"
))]
use rgx_core::decline;
#[cfg(any(
    feature = "arrow",
    feature = "hdf5",
    feature = "matv5",
    feature = "netcdf3"
))]
use rgx_core::Adapter;
#[cfg(any(
    feature = "arrow",
    feature = "hdf5",
    feature = "matv5",
    feature = "netcdf3"
))]
use rgx_core::Outcome;
#[cfg(any(
    feature = "arrow",
    feature = "hdf5",
    feature = "matv5",
    feature = "netcdf3"
))]
use rgx_core::Result;

// ---------- MATLAB v5 ----------

#[cfg(feature = "matv5")]
const MI_COMPRESSED: u32 = 15;
#[cfg(feature = "matv5")]
const MI_MATRIX: u32 = 14;
#[cfg(feature = "matv5")]
const MI_UINT32: u32 = 6;
#[cfg(feature = "matv5")]
const MI_INT32: u32 = 5;
#[cfg(feature = "matv5")]
const MI_UTF8: u32 = 16;
#[cfg(feature = "matv5")]
const MI_UTF16: u32 = 17;
#[cfg(feature = "matv5")]
const MI_UTF32: u32 = 18;

#[cfg(feature = "matv5")]
const MX_CELL: u32 = 1;
#[cfg(feature = "matv5")]
const MX_STRUCT: u32 = 2;
#[cfg(feature = "matv5")]
const MX_CHAR: u32 = 4;

// indexed by mxClassID as stored in files (1-based)
#[cfg(feature = "matv5")]
const MX_NAMES: &[&str] = &[
    "?", "cell", "struct", "object", "char", "sparse", "double", "single", "int8", "uint8",
    "int16", "uint16", "int32", "uint32", "int64", "uint64", "function", "opaque",
];

#[cfg(feature = "matv5")]
struct MatReader<'a> {
    d: &'a [u8],
    /// Output buffer shared with the parent so a single `String`
    /// grows through the whole document: hundreds of MATLAB v5 files
    /// have hundreds of compressed elements, and per-element
    /// `String` allocations plus `push_str` were a reallocation +
    /// memcpy per element.
    out: &'a mut String,
    budget: usize,
}

#[cfg(feature = "matv5")]
impl<'a> MatReader<'a> {
    /// read one element: returns (mi_type, payload range, next offset)
    fn element(&self, p: usize) -> Option<(u32, usize, usize, usize)> {
        let d = self.d;
        if p + 8 > d.len() {
            return None;
        }
        let w0 = u32::from_le_bytes([d[p], d[p + 1], d[p + 2], d[p + 3]]);
        if w0 & 0xFFFF_0000 != 0 {
            // small data element: [type u16][nbytes u16] then 4 inline data
            // bytes — the whole element is exactly 8 bytes.
            let ty = w0 & 0xFFFF;
            let n = (w0 >> 16) as usize;
            if p + 8 > d.len() || n > 4 {
                return None;
            }
            Some((ty, p + 4, n, p + 8))
        } else {
            let n = u32::from_le_bytes([d[p + 4], d[p + 5], d[p + 6], d[p + 7]]) as usize;
            let start = p + 8;
            let end = start.checked_add(n)?;
            if end > d.len() {
                return None;
            }
            let next = end + !n.is_multiple_of(8) as usize * (8 - n % 8); // 8-byte padding
            Some((w0, start, n, next.min(d.len())))
        }
    }

    fn push(&mut self, line: &str) {
        if self.budget == 0 {
            return;
        }
        self.out.push_str(line);
        self.out.push('\n');
        self.budget = self.budget.saturating_sub(line.len() + 1);
    }

    fn elements(&mut self, mut p: usize, depth: usize, prefix: &str) {
        while p < self.d.len() && self.budget > 0 {
            let Some((ty, start, n, next)) = self.element(p) else {
                break;
            };
            match ty {
                MI_COMPRESSED => {
                    let inflated = match rgx_core::compress::zlib::ZlibDecoder::new()
                        .decode(&self.d[start..start + n])
                    {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    if inflated.len() <= (64 << 20) {
                        let sub = MatReader {
                            d: &inflated,
                            out: &mut *self.out,
                            budget: self.budget,
                        };
                        let mut sub = sub;
                        sub.elements(0, depth + 1, prefix);
                        self.budget = sub.budget;
                    }
                }
                MI_MATRIX => {
                    self.matrix(start, start + n, depth, prefix);
                }
                _ => {}
            }
            p = next;
        }
    }

    /// parse one miMATRIX payload
    fn matrix(&mut self, s: usize, e: usize, depth: usize, prefix: &str) {
        if depth > 6 {
            return;
        }
        let mut p = s;
        // array flags: miUINT32 x2 → class in low byte of first word
        let Some((t1, fs, _fn_, np)) = self.element(p) else {
            return;
        };
        if t1 != MI_UINT32 || fs + 8 > e {
            return;
        }
        let flags =
            u32::from_le_bytes([self.d[fs], self.d[fs + 1], self.d[fs + 2], self.d[fs + 3]]);
        let class = flags & 0xFF;
        let class_name = MX_NAMES.get(class as usize).copied().unwrap_or("unknown");
        p = np;
        // dims: miINT32 array
        let Some((t2, ds, dn, np)) = self.element(p) else {
            return;
        };
        if t2 != MI_INT32 {
            return;
        }
        let dims: Vec<usize> = (0..dn / 4)
            .map(|i| {
                let o = ds + i * 4;
                u32::from_le_bytes([self.d[o], self.d[o + 1], self.d[o + 2], self.d[o + 3]])
                    as usize
            })
            .collect();
        p = np;
        // name: usually a small miINT8 element
        let (name, np) = match self.element(p) {
            Some((_, ns, nn, np)) => (
                String::from_utf8_lossy(&self.d[ns..ns + nn])
                    .trim_end_matches('\x00')
                    .to_string(),
                np,
            ),
            None => (String::new(), p),
        };
        p = np;
        let full = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}.{name}")
        };

        match class {
            MX_CHAR => {
                // data element: miUTF8 (raw bytes) or miUTF16 (u16 code units)
                if let Some((ct, cs, cn, _)) = self.element(p) {
                    let text = match ct {
                        MI_UTF8 => String::from_utf8_lossy(&self.d[cs..cs + cn]).into_owned(),
                        MI_UTF16 => {
                            let units: Vec<u16> = self.d[cs..cs + cn]
                                .as_chunks::<2>()
                                .0
                                .iter()
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            String::from_utf16_lossy(&units)
                        }
                        MI_UTF32 => self.d[cs..cs + cn]
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .filter_map(|c| {
                                char::from_u32(u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                            })
                            .collect(),
                        _ => String::new(),
                    };
                    self.push(&format!("{full}: char = {text:?}"));
                } else {
                    self.push(&format!("{full}: char dims={dims:?}"));
                }
            }
            MX_CELL => {
                self.push(&format!("{full}: cell dims={dims:?}"));
                let mut i = 0usize;
                let mut q = p;
                while q < e {
                    let Some((ty, cs, cn, np)) = self.element(q) else {
                        break;
                    };
                    if ty == MI_MATRIX {
                        self.matrix(cs, cs + cn, depth + 1, &format!("{full}{{{i}}}"));
                        i += 1;
                    }
                    q = np;
                }
            }
            MX_STRUCT => {
                self.push(&format!("{full}: struct dims={dims:?}"));
                // field-name length (miINT32 scalar), then field names (miINT8)
                let Some((_fl_t, fl_s, _fl_n, np)) = self.element(p) else {
                    return;
                };
                let flen = u32::from_le_bytes([
                    self.d[fl_s],
                    self.d[fl_s + 1],
                    self.d[fl_s + 2],
                    self.d[fl_s + 3],
                ]) as usize;
                let Some((_fn_t, fns, fnn, np)) = self.element(np) else {
                    return;
                };
                let fbytes = &self.d[fns..fns + fnn];
                let nfields = fnn.checked_div(flen).unwrap_or(0);
                let fields: Vec<String> = (0..nfields)
                    .map(|i| {
                        let start = i * flen;
                        let end = (start + flen).min(fbytes.len());
                        String::from_utf8_lossy(&fbytes[start..end])
                            .trim_end_matches('\0')
                            .to_string()
                    })
                    .collect();
                // then one matrix per field per struct element
                let mut q = np;
                let mut idx = 0usize;
                while q < e && idx < 512 {
                    let Some((ty, cs, cn, nq)) = self.element(q) else {
                        break;
                    };
                    if ty == MI_MATRIX {
                        let fname = fields
                            .get(idx % fields.len().max(1))
                            .cloned()
                            .unwrap_or_else(|| format!("f{idx}"));
                        let elem = if dims.iter().product::<usize>() > 1 {
                            format!("{idx} / {}", fields.len().max(1))
                        } else {
                            String::new()
                        };
                        let pre = if elem.is_empty() {
                            format!("{full}.{fname}")
                        } else {
                            format!("{full}({elem}).{fname}")
                        };
                        self.matrix(cs, cs + cn, depth + 1, &pre);
                        idx += 1;
                    }
                    q = nq;
                }
            }
            _ => {
                self.push(&format!("{full}: {class_name} dims={dims:?}"));
            }
        }
    }
}

/// MATLAB `.mat` v5 (and the v7.x subset that still uses v5 files).
/// Compressed (miCOMPRESSED) variables are inflated; cell/struct trees are
/// walked to their char leaves so string data is greppable.
#[cfg(feature = "matv5")]
pub struct MatV5;
#[cfg(feature = "matv5")]
impl Adapter for MatV5 {
    fn name(&self) -> &'static str {
        "mat"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["mat"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if hdf5_start(data).is_some() {
            // A v7.3 file is an HDF5 file behind a 512-byte user block, and
            // the v5 tag layout is not in it to be read: the endian marker
            // at 126 says "IM" and the bytes after it are HDF5, so reading it
            // as v5 walks nonsense and prints nonsense.
            decline!("a MATLAB v7.3 file is an HDF5 file, not a v5 one");
        }
        if data.len() < 128 || &data[126..128] != b"IM" {
            decline!("not a MATLAB v5 file (bad endian marker)");
        }
        let mut out = String::new();
        let mut r = MatReader {
            d: data,
            out: &mut out,
            budget: 4 << 20,
        };
        r.elements(128, 0, "");
        if out.trim().is_empty() {
            decline!("no readable variables");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

// ---------- netCDF-3 ----------

#[cfg(feature = "netcdf3")]
fn be32(d: &[u8], o: usize) -> u32 {
    // truncated files read as 0 — callers advance by fixed strides and the
    // name readers bail out, so a zero-fill here is safe and panic-free.
    // The offset comes out of the file, so it can be past the end of
    // everything: the addition is checked, not wrapped.
    let Some(end) = o.checked_add(4) else {
        return 0;
    };
    match d.get(o..end) {
        Some(b) => u32::from_be_bytes(b.try_into().unwrap()),
        None => 0,
    }
}

#[cfg(feature = "netcdf3")]
fn be64(d: &[u8], o: usize) -> u64 {
    // the same zero-fill as `be32`, for the 64-bit offset layout
    let Some(end) = o.checked_add(8) else {
        return 0;
    };
    match d.get(o..end) {
        Some(b) => u64::from_be_bytes(b.try_into().unwrap()),
        None => 0,
    }
}

/// The `nc_type` of a netCDF classic variable, by number. The list is
/// indexed by the number itself, so the entry at zero is the "no type"
/// one and the first real type is at one.
#[cfg(feature = "netcdf3")]
const NC_TYPES: &[&str] = &[
    "?", "byte", "char", "short", "int", "float", "double", "ubyte", "ushort", "uint", "int64",
    "uint64",
];

/// The width of one element of each `nc_type`, in bytes. The types
/// without a sign came with netCDF-3, which is the same file layout,
/// and the table stops at the double: a type past it is not a number
/// this reader knows.
#[cfg(feature = "netcdf3")]
const NC_TYPE_SIZES: &[usize] = &[0, 1, 1, 2, 4, 4, 8, 1, 2, 4, 8, 8];

/// Write one element of an `nc_type`, read big-endian the way the file
/// writes it, as the number it holds.
///
/// The type decides the width *and* the sign: `NC_BYTE` is a signed
/// eight-bit integer and `NC_UBYTE` the unsigned one, and a type the
/// table does not know is written as `?` — a number that is not a
/// number is a lie.
#[cfg(feature = "netcdf3")]
fn nc_write_element(out: &mut String, d: &[u8], o: usize, ty: usize) {
    let Some(&width) = NC_TYPE_SIZES.get(ty) else {
        let _ = write!(out, "?");
        return;
    };
    let Some(b) = d.get(o..o + width) else {
        let _ = write!(out, "?");
        return;
    };
    match ty {
        1 => {
            let _ = write!(out, "{}", b[0] as i8);
        }
        2 => {
            let _ = write!(out, "{:?}", b[0] as char);
        }
        3 => {
            let _ = write!(out, "{}", i16::from_be_bytes([b[0], b[1]]));
        }
        4 => {
            let _ = write!(out, "{}", i32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        }
        5 => {
            let _ = write!(out, "{}", f32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        }
        6 => {
            write_float(
                out,
                f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            );
        }
        7 => {
            let _ = write!(out, "{}", b[0]);
        }
        8 => {
            let _ = write!(out, "{}", u16::from_be_bytes([b[0], b[1]]));
        }
        9 => {
            let _ = write!(out, "{}", u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        }
        10 => {
            let _ = write!(
                out,
                "{}",
                i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            );
        }
        11 => {
            let _ = write!(
                out,
                "{}",
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            );
        }
        _ => {
            let _ = write!(out, "?");
        }
    }
}

/// The bytes of a char value: the text they are when they are text,
/// and the bytes they are when they are not.
///
/// A byte that is not valid UTF-8 is not a character, and replacing it
/// with U+FFFD would throw away what the file holds: a number that is
/// not a number is a lie.
#[cfg(feature = "netcdf3")]
fn nc_char_text(raw: &[u8]) -> String {
    match core::str::from_utf8(raw) {
        Ok(text) => {
            let mut out = String::new();
            let _ = write!(out, "{text:?}");
            out
        }
        Err(_) => {
            let mut out = String::with_capacity(raw.len() * 2);
            for &b in raw {
                let _ = write!(out, "{b:02x}");
            }
            out
        }
    }
}

/// The width of a `NON_NEG` field: 32 bits in CDF-1 and CDF-2, 64 bits in
/// CDF-5, where every count and every length in the header is a 64-bit
/// number.
#[cfg(feature = "netcdf3")]
fn nc_nonneg(d: &[u8], o: usize, wide: bool) -> u64 {
    if wide {
        be64(d, o)
    } else {
        be32(d, o) as u64
    }
}

/// The width of the `nelems` of a list: the `NON_NEG` width, which is the
/// width of the field the list's count lives in.
#[cfg(feature = "netcdf3")]
fn nc_count(wide: bool) -> usize {
    if wide {
        8
    } else {
        4
    }
}

/// Parse an attribute list starting at `p`; returns (attrs, next offset).
#[cfg(feature = "netcdf3")]
fn nc_attrs(d: &[u8], p: usize, out: &mut String, owner: &str, wide: bool) -> Option<usize> {
    let tag = be32(d, p);
    if tag == 0 {
        // ABSENT: two zero words in CDF-1 and CDF-2, a 32-bit zero and a
        // 64-bit one in CDF-5.
        return Some(p + if wide { 12 } else { 8 });
    }
    if tag != 0x0C {
        return Some(p);
    }
    let n = usize::try_from(nc_nonneg(d, p + 4, wide)).unwrap_or(usize::MAX);
    let mut q = p + 4 + nc_count(wide);
    for _ in 0..n.min(10_000) {
        let (name, nq) = nc_name(d, q, wide)?;
        q = nq;
        let ty = be32(d, q) as usize;
        let count = usize::try_from(nc_nonneg(d, q + 4, wide)).unwrap_or(usize::MAX);
        q += 4 + nc_count(wide);
        let sz = NC_TYPE_SIZES.get(ty).copied().unwrap_or(1);
        let nbytes = count.saturating_mul(sz);
        if ty == 2 {
            // clamp to available bytes — a fuzzed count points past EOF
            let start = q.min(d.len());
            let end = (q.saturating_add(count.min(4096))).min(d.len());
            let _ = writeln!(out, "{owner}@{name} = {}", nc_char_text(&d[start..end]));
        } else if count <= 8 && q.checked_add(nbytes).is_some_and(|e| e <= d.len()) {
            let _ = write!(out, "{owner}@{name} = [");
            for i in 0..count {
                if i > 0 {
                    let _ = write!(out, ", ");
                }
                nc_write_element(out, d, q + i * sz, ty);
            }
            let _ = writeln!(out, "]");
        }
        // The values are padded to a four-byte boundary.
        q = q.saturating_add(nbytes.div_ceil(4).saturating_mul(4));
    }
    Some(q)
}

#[cfg(feature = "netcdf3")]
fn nc_name(d: &[u8], p: usize, wide: bool) -> Option<(String, usize)> {
    // A CDF-5 length is a 64-bit number, so it does not fit in a `usize`
    // everywhere: the ones that do not are refused here rather than
    // wrapping into a slice that is not there.
    let n = usize::try_from(nc_nonneg(d, p, wide)).unwrap_or(usize::MAX);
    let at = p.checked_add(nc_count(wide))?;
    let end = at.checked_add(n)?;
    if end > d.len() {
        return None;
    }
    let name = String::from_utf8_lossy(&d[at..end]).into_owned();
    Some((name, end.div_ceil(4) * 4))
}

/// netCDF classic (CDF-1) and 64-bit-offset (CDF-2) files: dimensions,
/// variables with their types/shapes, their attributes, and their values.
/// A netCDF-4 file is an HDF5 file and is declined here -- the HDF5
/// reader claims `.nc` as well and answers it, with the file's own
/// superblock and names.
///
/// `.cdf` is claimed here because **CDF-1 is netCDF classic** -- the two
/// share the four-byte `CDF\x01` header and the same descriptor layout, the
/// CDF library having been the origin of netCDF. NASA's own CDF-1 and
/// CDF-2 have a different magic (`00 00 FF FF` and `CD F2 60 02`) and a
/// descriptor of their own, and are read by `cdf12_extract` below; NASA's
/// CDF-3 has a third magic (`CD F3 00 01`) and is read by `cdf3_extract`.
///
/// The classic model has two on-disk shapes: the file that says how many
/// records it holds, and the **streaming** one, whose header is the same
/// but says the count of the records is indeterminate -- the records
/// follow one after the other at the end of the file, and the length of
/// the file says how many of them it holds. The streaming marker is four
/// bytes of 0xFF in CDF-1 and CDF-2; the CDF-5 one is eight bytes and is
/// not read here.
#[cfg(feature = "netcdf3")]
pub struct NetCdf3;
#[cfg(feature = "netcdf3")]
impl Adapter for NetCdf3 {
    fn name(&self) -> &'static str {
        "netcdf"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["nc", "cdf", "netcdf"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // NASA CDF-3 has its own magic, `CD F3 00 01`, and its own
        // descriptor: a chain of internal records at 64-bit offsets, not
        // netCDF's dimension and variable lists. It is read by
        // `cdf3_extract`, and only there.
        if data.len() >= 8 && data[0..4] == CDF3_MAGIC {
            return cdf3_extract(data);
        }
        // NASA's CDF-1 (the pre-V2.6 magic) and CDF-2 have a descriptor of
        // their own as well: the same chain of internal records, but with
        // 32-bit offsets where a CDF-3 has 64-bit ones. They are read by
        // `cdf12_extract`, and only there.
        if data.len() >= 8 && (data[0..4] == CDF1_MAGIC || data[0..4] == CDF2_MAGIC) {
            return cdf12_extract(data);
        }
        if data.len() < 16 || &data[0..3] != b"CDF" {
            decline!("not a netCDF-3 file (bad magic)");
        }
        let version = data[3];
        // CDF-1 is the classic layout, CDF-2 the 64-bit-offset one, and
        // CDF-5 the same classic model with 64-bit fields in the header.
        // The netCDF library writes no other version under this magic:
        // `CDF\x03` and `CDF\x04` are reserved.
        if version != 1 && version != 2 && version != 5 {
            bail!("CDF version {version} is not the classic, the 64-bit-offset or the CDF-5 netCDF layout; unsupported");
        }
        // The `OFFSET` field -- the offset of a variable's data -- is
        // 64-bit in CDF-2 and CDF-5, and 32-bit in CDF-1.
        let big = version != 1;
        // The `NON_NEG` fields -- the counts, the lengths, the dimension
        // ids -- are 64-bit in CDF-5 alone.
        let wide = version == 5;
        // The number of records the file holds. The streaming marker is
        // the shape the classic model has for a file whose records are
        // written as they come: the header is walked the same way, but
        // the count of the records is not in it -- the records follow one
        // after the other at the end of the file, and the length of the
        // file says how many of them it holds. The marker is four bytes
        // of 0xFF in CDF-1 and CDF-2, and eight in CDF-5.
        let numrecs = nc_nonneg(data, 4, wide);
        let streaming = if wide { u64::MAX } else { 0xFFFF_FFFF };
        let is_streaming = numrecs == streaming;
        if is_streaming && wide {
            bail!("a streaming CDF-5 file is not read; unsupported");
        }
        let mut out = String::new();
        let _ = writeln!(
            out,
            "CDF version {version} ({} layout{}), file size {}",
            match version {
                1 => "netCDF classic",
                2 => "netCDF 64-bit offset",
                _ => "netCDF CDF-5",
            },
            if is_streaming { ", streaming" } else { "" },
            data.len()
        );
        let mut p = 4 + nc_count(wide); // skip magic + numrecs
                                        // dim list
                                        // The length of each dimension, in the order the file lists them.
                                        // The record dimension is stored as zero: its real length is the
                                        // number of records.
        let mut dimlen: Vec<u64> = Vec::new();
        if be32(data, p) == 0x0A {
            let n = nc_nonneg(data, p + 4, wide) as usize;
            p += 4 + nc_count(wide);
            for _ in 0..n.min(10_000) {
                let Some((name, q)) = nc_name(data, p, wide) else {
                    break;
                };
                p = q;
                let len = nc_nonneg(data, p, wide);
                p += nc_count(wide);
                dimlen.push(len);
                let _ = writeln!(out, "dim {name} = {len}");
            }
        } else {
            p += if wide { 12 } else { 8 }; // ABSENT
        }
        // global attrs
        let Some(q) = nc_attrs(data, p, &mut out, "global", wide) else {
            bail!("truncated attribute list");
        };
        p = q;
        // var list
        if be32(data, p) != 0x0B {
            decline!("no variable list");
        }
        let nvars = nc_nonneg(data, p + 4, wide) as usize;
        p += 4 + nc_count(wide);
        // The variables are collected while they are read and their
        // values are read afterwards: the records of a record variable
        // are spread through the records of every other record variable,
        // so the distance between two of them is only known once the
        // whole list has been read.
        let mut vars: Vec<NcVar> = Vec::new();
        for _ in 0..nvars.min(100_000) {
            let Some((name, q)) = nc_name(data, p, wide) else {
                break;
            };
            p = q;
            // A header with more dimensions than this is not a file the
            // netCDF library wrote: the bound keeps the loop below from
            // walking off the end of the file.
            let ndims = nc_nonneg(data, p, wide).min(1024) as usize;
            p += nc_count(wide);
            // The dimension ids sit between the name and the attribute
            // list; keeping where they start is what lets the shape be
            // reported without copying them into a Vec first.
            let dimids = p;
            // Stream the dimension IDs directly into `out` instead
            // of building a `Vec<usize>` per variable. The previous
            // shape allocated one Vec per variable (an n-dim header
            // had up to 32 elements per Vec) and then fed it to
            // `format!` for the Debug formatter; the new path is
            // write-direct with the same end-state output.
            p += ndims * nc_count(wide);
            let Some(q) = nc_attrs(data, p, &mut out, &name, wide) else {
                break;
            };
            p = q;
            let ty = be32(data, p) as usize;
            // The type tag is 32 bits in every layout; the size of the
            // data is a count, so it is 64 bits in CDF-5, and the offset
            // of the data is 64 bits in CDF-2 and CDF-5. Stepping 12
            // bytes here instead of 8 walked four bytes past every
            // variable, so the second variable of a file was read from
            // the wrong place and the list stopped there.
            let vsize = nc_nonneg(data, p + 4, wide);
            p += 4 + nc_count(wide); // type + vsize
            let begin = if big {
                be64(data, p)
            } else {
                be32(data, p) as u64
            };
            p += if big { 8 } else { 4 }; // begin offset
            let tyname = NC_TYPES.get(ty).copied().unwrap_or("?");
            use core::fmt::Write as _;
            let _ = write!(out, "var {name}: {tyname} dims=[");
            for i in 0..ndims {
                if i > 0 {
                    let _ = write!(out, ", ");
                }
                let _ = write!(
                    out,
                    "{}",
                    nc_nonneg(data, dimids + i * nc_count(wide), wide)
                );
            }
            let _ = writeln!(out, "]");
            vars.push(NcVar {
                dims: (0..ndims)
                    .map(|i| nc_nonneg(data, dimids + i * nc_count(wide), wide) as usize)
                    .collect(),
                name,
                ty,
                vsize,
                begin,
            });
        }
        if out.trim().is_empty() {
            bail!("empty netcdf header");
        }
        // The values, one line per element, after the header -- the
        // order the `ncdump` reference puts them in.
        let unlimited = dimlen.iter().position(|&l| l == 0);
        // A record holds one element of every record variable, in the
        // order the file lists them, so the size of a record is the sum
        // of their sizes and that sum is the distance between two
        // records.
        let stride = vars
            .iter()
            .filter(|v| nc_is_record(v, unlimited))
            .fold(0u64, |a, v| a.saturating_add(v.vsize));
        // A streaming file does not say how many records it holds: the
        // records follow one after the other at the end of the file, and
        // the count is what the length of the file holds of them.
        let numrecs = if is_streaming {
            let count = nc_streaming_records(data, &vars, unlimited, stride)?;
            let _ = writeln!(
                out,
                "streaming: {count} records, counted from the length of the file"
            );
            count
        } else {
            numrecs
        };
        for var in &vars {
            nc_write_values(&mut out, data, var, &dimlen, unlimited, numrecs, stride)?;
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// One variable of a netCDF classic file: what its header says about
/// it, kept until the data section is walked.
#[cfg(feature = "netcdf3")]
struct NcVar {
    /// The name the file gives the variable.
    name: String,
    /// The dimensions of the variable, by the id the header gives them.
    dims: Vec<usize>,
    /// The `nc_type` of the variable.
    ty: usize,
    /// The size of one record of the variable, as the file gives it.
    vsize: u64,
    /// The offset of the variable's data in the file.
    begin: u64,
}

/// Is the variable a record variable -- one whose first dimension is
/// the record dimension, the one the header stores as length zero?
#[cfg(feature = "netcdf3")]
fn nc_is_record(var: &NcVar, unlimited: Option<usize>) -> bool {
    !var.dims.is_empty() && Some(var.dims[0]) == unlimited
}

/// How many records a streaming file holds.
///
/// A streaming file does not say how many records it has: the records
/// follow one after the other at the end of the file, and the count is
/// what the length of the file holds of them.
///
/// The records start where the first record variable starts -- the
/// record section is the last thing in the file -- and one record is
/// the sum of the `vsize`s of the record variables.
#[cfg(feature = "netcdf3")]
fn nc_streaming_records(
    data: &[u8],
    vars: &[NcVar],
    unlimited: Option<usize>,
    stride: u64,
) -> Result<u64> {
    let mut start = u64::MAX;
    let mut records = 0usize;
    let mut ty = 0usize;
    for var in vars {
        if nc_is_record(var, unlimited) {
            start = start.min(var.begin);
            records += 1;
            ty = var.ty;
        }
    }
    if records == 0 {
        // A file with no record variable holds no records to count.
        return Ok(0);
    }
    // The specification's exception: a file with a single record
    // variable of type byte, char or short keeps its records unpadded,
    // and a reader is to ignore the `vsize` there and assume no
    // padding. This reader walks the record size as the sum of the
    // `vsize`s, so the count it would make is not the count the file
    // has: the file is refused by name instead of read wrong.
    if records == 1 && matches!(ty, 1..=3) {
        bail!("a streaming file whose only record variable is a byte, a char or a short keeps its records unpadded, which this reader does not walk; refused");
    }
    if stride == 0 {
        bail!("a streaming file whose records take no space at all; refused");
    }
    let len = data.len() as u64;
    if start > len {
        bail!("a streaming file whose records start past the end of the file; refused");
    }
    Ok((len - start) / stride)
}

/// Ceiling on the rendered output. The values of a netCDF file are
/// counted by the file, so a file with many elements renders many
/// lines; this is where the reader says no instead of answering with a
/// part of the file.
#[cfg(feature = "netcdf3")]
const MAX_OUT: usize = 64 << 20;

/// The most dimensions one variable may have. HDF5 stops at 32 and
/// the netCDF files in the wild stay far below it; a header that claims
/// more is read for its shape, but its values are not rendered.
#[cfg(feature = "netcdf3")]
const MAX_DIMS: usize = 32;

/// Write the values of one variable: one line per element, with the
/// index that says where the element sits inside the variable.
///
/// A fixed variable is one contiguous block at its own offset. A record
/// variable is spread through the records: a record holds one element
/// of every record variable, in the order the file lists them, so the
/// distance between two of its own elements is the size of a whole
/// record.
///
/// A char variable is text: the last dimension is the length of one
/// string and the dimensions before it index the strings.
#[cfg(feature = "netcdf3")]
fn nc_write_values(
    out: &mut String,
    data: &[u8],
    var: &NcVar,
    dimlen: &[u64],
    unlimited: Option<usize>,
    numrecs: u64,
    stride: u64,
) -> Result<()> {
    let Some(&width) = NC_TYPE_SIZES.get(var.ty) else {
        return Ok(());
    };
    if width == 0 {
        return Ok(());
    }
    let nd = var.dims.len();
    if nd > MAX_DIMS {
        return Ok(());
    }
    // The shape of the variable: the length of each of its dimensions,
    // the record dimension counting the records the file holds.
    let mut shape = [0usize; MAX_DIMS];
    for (i, &d) in var.dims.iter().enumerate() {
        shape[i] = if i == 0 && Some(d) == unlimited {
            usize::try_from(numrecs).unwrap_or(usize::MAX)
        } else {
            usize::try_from(dimlen.get(d).copied().unwrap_or(0)).unwrap_or(0)
        };
    }
    let text = var.ty == 2;
    let unit_dims = if text { nd.saturating_sub(1) } else { nd };
    let unit_bytes = if text && nd > 0 { shape[nd - 1] } else { width };
    let mut unit_shape = [0usize; MAX_DIMS];
    unit_shape[..unit_dims].copy_from_slice(&shape[..unit_dims]);
    let mut units = 1usize;
    for &n in &unit_shape[..unit_dims] {
        units = units.saturating_mul(n);
    }
    // A record variable holds one unit of each of its units in every
    // record, so the units inside one record are the ones after the
    // first dimension.
    let mut per_record = 1usize;
    if unit_dims > 1 {
        for &n in &unit_shape[1..unit_dims] {
            per_record = per_record.saturating_mul(n);
        }
    }
    let is_record = nc_is_record(var, unlimited);
    let mut written = 0usize;
    for u in 0..units {
        let offset = if is_record {
            let r = u / per_record;
            let within = u % per_record;
            var.begin
                .saturating_add((r as u64).saturating_mul(stride))
                .saturating_add((within as u64).saturating_mul(unit_bytes as u64))
        } else {
            var.begin
                .saturating_add((u as u64).saturating_mul(unit_bytes as u64))
        };
        let Ok(offset) = usize::try_from(offset) else {
            break;
        };
        let Some(raw) = data.get(offset..offset.saturating_add(unit_bytes)) else {
            break;
        };
        // The index of the unit: its place in each of the dimensions it
        // is indexed by, the last one counting fastest.
        let mut idx = [0usize; MAX_DIMS];
        let mut rem = u;
        for i in (0..unit_dims).rev() {
            let n = unit_shape[i];
            if n == 0 {
                idx[i] = 0;
                continue;
            }
            idx[i] = rem % n;
            rem /= n;
        }
        let _ = write!(out, "value {}", var.name);
        for &i in &idx[..unit_dims] {
            let _ = write!(out, "[{i}]");
        }
        let _ = write!(out, " = ");
        if text {
            let _ = write!(out, "{}", nc_char_text(raw));
        } else {
            nc_write_element(out, data, offset, var.ty);
        }
        let _ = writeln!(out);
        written += 1;
        if out.len() > MAX_OUT {
            bail!("netcdf: the rendered values are over the {MAX_OUT} byte ceiling");
        }
    }
    if written < units {
        // The header says the variable holds more than the file has
        // bytes for: the file is short, and saying how much of it was
        // read is the honest way to answer.
        let _ = writeln!(out, "truncated: {} holds {written} of {units}", var.name);
    }
    Ok(())
}

// ---------- NASA CDF-3 ----------

/// NASA's CDF-3 magic: `CD F3 00 01`. NASA CDF also has a CDF-1
/// (`00 00 FF FF`) and a CDF-2 (`CD F2 60 02`); neither is the netCDF
/// `CDF\x01`/`CDF\x02` the reader above handles, and all three carry
/// their own descriptor layout, so a file with one of them is never read
/// with netCDF's offsets.
#[cfg(feature = "netcdf3")]
const CDF3_MAGIC: [u8; 4] = [0xCD, 0xF3, 0x00, 0x01];

/// The second magic word of a CDF-3 whose internal records are stored as
/// they are.
#[cfg(feature = "netcdf3")]
const CDF3_PLAIN: u32 = 0x0000_FFFF;

/// The second magic word of a CDF-3 whose internal records are compressed
/// behind a whole-file CCR record.
#[cfg(feature = "netcdf3")]
const CDF3_PACKED: u32 = 0xCCCC_0001;

// The internal record types, as the CDF library numbers them.
#[cfg(feature = "netcdf3")]
const CDF_CDR: i32 = 1;
#[cfg(feature = "netcdf3")]
const CDF_GDR: i32 = 2;
#[cfg(feature = "netcdf3")]
const CDF_RVDR: i32 = 3;
#[cfg(feature = "netcdf3")]
const CDF_ADR: i32 = 4;
#[cfg(feature = "netcdf3")]
const CDF_AGR_EDR: i32 = 5;
#[cfg(feature = "netcdf3")]
const CDF_ZVDR: i32 = 8;
#[cfg(feature = "netcdf3")]
const CDF_AZ_EDR: i32 = 9;
#[cfg(feature = "netcdf3")]
const CDF_CCR: i32 = 10;
#[cfg(feature = "netcdf3")]
const CDF_CPR: i32 = 11;

/// A value record: a block of a variable's data.
#[cfg(feature = "netcdf3")]
const CDF_VVR: i32 = 7;
/// Compressed index record: an index record whose blocks are
/// compressed.
#[cfg(feature = "netcdf3")]
const CDF_CVXR: i32 = 6;

// The ADR scopes: the attribute belongs to the file, or to a variable.
// The "assumed" scopes are the same two, with a weaker promise about the
// value they hold.
#[cfg(feature = "netcdf3")]
const CDF_SCOPE_GLOBAL: i32 = 1;
#[cfg(feature = "netcdf3")]
const CDF_SCOPE_VARIABLE: i32 = 2;
#[cfg(feature = "netcdf3")]
const CDF_SCOPE_GLOBAL_ASSUMED: i32 = 3;
#[cfg(feature = "netcdf3")]
const CDF_SCOPE_VARIABLE_ASSUMED: i32 = 4;

// The compression types a CPR record can name.
#[cfg(feature = "netcdf3")]
const CDF_COMPRESSION_NONE: i32 = 0;
#[cfg(feature = "netcdf3")]
const CDF_COMPRESSION_RLE: i32 = 1;
#[cfg(feature = "netcdf3")]
const CDF_COMPRESSION_GZIP: i32 = 5;

// The ceilings a walk over a linked list of records may have. The chains
// come out of the file, so they can loop: the caps are what keeps a
// fuzzed file from walking forever or allocating without end.
#[cfg(feature = "netcdf3")]
const CDF_MAX_VARS: u32 = 10_000;
#[cfg(feature = "netcdf3")]
const CDF_MAX_ENTRIES: u32 = 10_000;
#[cfg(feature = "netcdf3")]
const CDF_MAX_ATTRS: u32 = 10_000;
#[cfg(feature = "netcdf3")]
const CDF_MAX_DIMS: i32 = 256;
#[cfg(feature = "netcdf3")]
const CDF_MAX_ATTR_LINES: usize = 100_000;

/// The internal records of a CDF-3 file: either the file itself (an
/// uncompressed CDF) or the decompressed descriptor of a compressed one.
///
/// `base` is the file offset that `ir[0]` stands for. It is 0 when the
/// records are in the file, and 8 when they are the decompressed tail of
/// a CCR: a CDF always opens with two magic words, and a compressed CDF's
/// descriptor is the file without them. Every offset stored inside a
/// record is a file offset, so every read goes through `base`.
#[cfg(feature = "netcdf3")]
struct CdfRecords<'a> {
    ir: &'a [u8],
    base: usize,
}

#[cfg(feature = "netcdf3")]
impl<'a> CdfRecords<'a> {
    /// The buffer offset of the record at a file offset, checked to be
    /// inside the descriptor. A file offset that does not fit, or points
    /// past the end, is refused here rather than overflowing an addition
    /// further down: the offsets come out of the file, so they are as
    /// hostile as any other number in it.
    fn at(&self, off: u64) -> Result<usize> {
        let Some(rel) = off.checked_sub(self.base as u64) else {
            bail!("CDF record offset {off} is before the start of the descriptor");
        };
        let Ok(o) = usize::try_from(rel) else {
            bail!("CDF record offset {off} is past the end of the descriptor");
        };
        if o > self.ir.len() {
            bail!("CDF record offset {off} is past the end of the descriptor");
        }
        Ok(o)
    }

    /// The `n` bytes of a field.
    fn field(&self, o: usize, n: usize) -> Option<&'a [u8]> {
        let end = o.checked_add(n)?;
        self.ir.get(o..end)
    }

    fn u32(&self, o: usize) -> Result<u32> {
        let Some(b) = self.field(o, 4) else {
            bail!("CDF record field at {o} is past the end of the descriptor");
        };
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32(&self, o: usize) -> Result<i32> {
        Ok(self.u32(o)? as i32)
    }

    fn u64(&self, o: usize) -> Result<u64> {
        let Some(b) = self.field(o, 8) else {
            bail!("CDF record field at {o} is past the end of the descriptor");
        };
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

/// One variable of a CDF-3 file.
#[cfg(feature = "netcdf3")]
struct CdfVar {
    /// The variable's number: what an attribute entry names it by.
    num: i32,
    name: String,
    ty: i32,
    /// The dimension sizes, in the file's own order: the shape of one
    /// record of the variable.
    dims: Vec<i32>,
    /// The number of elements in one record.
    num_elements: i32,
    /// The number of records the variable holds, less one.
    max_rec: i32,
    /// Whether the variable's records vary.
    record_vary: bool,
    /// The first index record of the chain that points at the blocks
    /// of the data.
    head_vxr: u64,
    /// Whether the records are sparse: a sparse record that was never
    /// written is a pad value, not a hole in the file.
    sparse: i32,
    /// Whether the data of the variable is compressed.
    compressed: bool,
}

/// The name of a CDF data type, by the number a VDR or AEDR holds.
#[cfg(feature = "netcdf3")]
fn cdf_type_name(ty: i32) -> &'static str {
    match ty {
        1 => "int8",
        2 => "int16",
        4 => "int32",
        8 => "int64",
        11 => "uint8",
        12 => "uint16",
        14 => "uint32",
        21 => "float32",
        22 => "float64",
        31 => "epoch",
        32 => "epoch16",
        33 => "tt2000",
        41 => "int8",
        44 => "float32",
        45 => "float64",
        51 => "char",
        52 => "char",
        _ => "?",
    }
}

/// The width in bytes of a CDF data type. Zero for the types this reader
/// does not decode: the epoch types carry an encoding of their own, and a
/// number outside the table is not something to guess at.
#[cfg(feature = "netcdf3")]
fn cdf_type_width(ty: i32) -> usize {
    match ty {
        1 | 11 | 41 | 51 | 52 => 1,
        2 | 12 => 2,
        4 | 14 | 21 | 44 => 4,
        8 | 22 | 45 => 8,
        _ => 0,
    }
}

/// The byte order of a CDF data encoding, from the CDF library's own
/// table. `None` means the encoding is one this reader does not know, so
/// a value that depends on byte order stays undecoded instead of being
/// read in the wrong order.
#[cfg(feature = "netcdf3")]
fn cdf_big_endian(encoding: i32) -> Option<bool> {
    match encoding {
        // network, sun, sgi, ibmrs, hp, next, ppc, arm (big)
        1 | 2 | 5 | 7 | 9 | 11 | 12 | 18 => Some(true),
        // decstation, alphaosf1, alphavms d/g/i, ibmpc, vax, arm (little),
        // ia64vms i/d/g
        3 | 4 | 6 | 13 | 14 | 15 | 16 | 17 | 19 | 20 | 21 => Some(false),
        _ => None,
    }
}

/// Whether a float in this encoding is IEEE 754. The VAX and VMS float
/// formats are not, so a float under them stays undecoded.
#[cfg(feature = "netcdf3")]
fn cdf_float_is_ieee(encoding: i32) -> bool {
    !matches!(encoding, 3 | 14 | 15 | 20 | 21)
}

/// An integer of `b.len()` bytes, in the file's byte order, sign extended.
#[cfg(feature = "netcdf3")]
fn cdf_int(b: &[u8], big: bool) -> i64 {
    // The sign lives in the most significant byte, which is the first one
    // in big endian and the last one in little endian -- reading the
    // wrong end of the buffer is what made a positive value come out
    // negative.
    let msb = if big { b[0] } else { b[b.len() - 1] };
    let fill = if msb & 0x80 != 0 { 0xFF } else { 0x00 };
    let mut buf = [0u8; 8];
    if big {
        // Big endian reads the most significant byte first, so the value
        // sits at the end of the buffer and the sign extension at its
        // front.
        buf[..8 - b.len()].fill(fill);
        buf[8 - b.len()..].copy_from_slice(b);
        i64::from_be_bytes(buf)
    } else {
        buf[b.len()..].fill(fill);
        buf[..b.len()].copy_from_slice(b);
        i64::from_le_bytes(buf)
    }
}

/// An unsigned integer of `b.len()` bytes, in the file's byte order.
#[cfg(feature = "netcdf3")]
fn cdf_uint(b: &[u8], big: bool) -> u64 {
    let mut buf = [0u8; 8];
    if big {
        buf[8 - b.len()..].copy_from_slice(b);
        u64::from_be_bytes(buf)
    } else {
        buf[..b.len()].copy_from_slice(b);
        u64::from_le_bytes(buf)
    }
}

/// A float of `b.len()` bytes, in the file's byte order.
#[cfg(feature = "netcdf3")]
fn cdf_float(b: &[u8], big: bool) -> f64 {
    if b.len() == 4 {
        let raw = [b[0], b[1], b[2], b[3]];
        return if big {
            f32::from_be_bytes(raw) as f64
        } else {
            f32::from_le_bytes(raw) as f64
        };
    }
    let raw = [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
    if big {
        f64::from_be_bytes(raw)
    } else {
        f64::from_le_bytes(raw)
    }
}

/// A float, written the way a reader wants it: the plain form for the
/// magnitudes people write by hand, scientific for the ones that would
/// otherwise run to thirty digits. A fill value of 1e30 is not a
/// thirty-digit number.
/// A float, written the way a reader wants it: the plain form for the
/// magnitudes people write by hand, scientific for the ones that would
/// otherwise run to thirty digits. A fill value of 1e30 is not a
/// thirty-digit number.
#[cfg(feature = "netcdf3")]
fn float_text(v: f64) -> String {
    let mut out = String::new();
    write_float(&mut out, v);
    out
}

/// The same float, written into a buffer that is already there.
#[cfg(feature = "netcdf3")]
fn write_float(out: &mut String, v: f64) {
    if v == 0.0 || (v.abs() >= 1e-4 && v.abs() < 1e16) {
        let _ = write!(out, "{v}");
    } else {
        let _ = write!(out, "{v:e}");
    }
}

/// A CDF name: a fixed 256-byte field, NUL padded.
#[cfg(feature = "netcdf3")]
fn cdf_name(rec: &CdfRecords<'_>, off: usize) -> Result<String> {
    let Some(raw) = rec.field(off, 256) else {
        bail!("CDF record name at {off} is past the end of the descriptor");
    };
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(&raw[..end]).into_owned())
}

/// Read a NASA CDF-3 file: the variables with their types and shapes, and
/// the attributes.
///
/// The descriptor is a chain of internal records -- CDR, GDR, VDRs, ADRs,
/// AEDRs -- each addressed by a 64-bit offset, and not netCDF's dimension
/// and variable lists. A CDF-3 may also hold that whole chain compressed
/// behind a CCR record; the compressed form is unpacked first.
///
/// Variable *values* are not read: the netCDF reader in this file reports
/// the header only, and a CDF variable's data may live in a separate file,
/// be compressed with the CDF library's own scheme, or be sparse -- none
/// of which the header says.
#[cfg(feature = "netcdf3")]
fn cdf3_extract(data: &[u8]) -> Result<Outcome> {
    let Some(head) = data.get(4..8) else {
        bail!("CDF-3 file is shorter than its two magic words");
    };
    let desc = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    // The internal records are either in the file or behind a compressed
    // whole-file CCR record.
    let packed: Option<Vec<u8>> = match desc {
        CDF3_PLAIN => None,
        CDF3_PACKED => Some(cdf3_unpack(data)?),
        other => bail!(
            "CDF-3 descriptor magic 0x{other:08X} is neither a plain nor a compressed descriptor"
        ),
    };
    let rec = CdfRecords {
        ir: match &packed {
            Some(v) => v.as_slice(),
            None => data,
        },
        base: if packed.is_some() { 8 } else { 0 },
    };
    // The CDR is always the first record of a CDF.
    let cdr = rec.at(8)?;
    if rec.i32(cdr + 8)? != CDF_CDR {
        bail!("CDF-3 descriptor does not start with a CDR record");
    }
    let gdr = rec.at(rec.u64(cdr + 12)?)?;
    let version = rec.i32(cdr + 20)?;
    let release = rec.i32(cdr + 24)?;
    let encoding = rec.i32(cdr + 28)?;

    if rec.i32(gdr + 8)? != CDF_GDR {
        bail!("CDF-3 descriptor does not point at a GDR record");
    }
    let rvdr_head = rec.u64(gdr + 12)?;
    let zvdr_head = rec.u64(gdr + 20)?;
    let adr_head = rec.u64(gdr + 28)?;
    let r_num_dims = rec.i32(gdr + 56)?;
    // The record variables share one list of dimension sizes, which the
    // GDR holds. CDF has no dimension names, so this list is all a
    // variable's shape is made of.
    let mut r_dims: Vec<i32> = Vec::new();
    for i in 0..r_num_dims.clamp(0, CDF_MAX_DIMS) {
        r_dims.push(rec.i32(gdr + 84 + 4 * i as usize)?);
    }

    let mut rvars: Vec<CdfVar> = Vec::new();
    let mut zvars: Vec<CdfVar> = Vec::new();
    cdf3_vdrs(&rec, rvdr_head, false, &r_dims, &mut rvars)?;
    cdf3_vdrs(&rec, zvdr_head, true, &[], &mut zvars)?;
    // An attribute entry names its variable by number, and a file may
    // hold thousands of them: the lookup is a map, so the walk does not
    // turn quadratic on a chain that loops.
    let rindex: BTreeMap<i32, usize> = rvars.iter().enumerate().map(|(i, v)| (v.num, i)).collect();
    let zindex: BTreeMap<i32, usize> = zvars.iter().enumerate().map(|(i, v)| (v.num, i)).collect();

    let mut out = String::new();
    let _ = writeln!(
        out,
        "CDF version {version}.{release} (NASA CDF-3 layout{}), file size {}",
        if packed.is_some() {
            ", compressed descriptor"
        } else {
            ""
        },
        data.len()
    );
    cdf3_attributes(
        &rec,
        adr_head,
        (&rvars, &rindex),
        (&zvars, &zindex),
        &mut CdfAttrCtx {
            encoding,
            budget: CDF_MAX_ATTR_LINES,
            out: &mut out,
        },
    )?;
    for v in rvars.iter().chain(zvars.iter()) {
        let _ = write!(out, "var {}: {} dims=[", v.name, cdf_type_name(v.ty));
        for (i, d) in v.dims.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, ", ");
            }
            let _ = write!(out, "{d}");
        }
        let _ = writeln!(out, "]");
        // The values, when the file stores them where this reader can
        // read them.
        let values = match cdf3_values(&rec, data, v, encoding) {
            Ok(values) => values,
            Err(why) => {
                let _ = writeln!(out, "truncated: {}: {why}", v.name);
                continue;
            }
        };
        // The records of a variable come first: the shape of one record
        // is the variable's shape, and the records are the dimension
        // before it.
        let per_record: usize = v.dims.iter().map(|d| *d as usize).product::<usize>().max(1);
        for (i, value) in values.iter().enumerate() {
            let _ = write!(out, "value {}[{}]", v.name, i / per_record);
            // The last dimension counts fastest, the way the file stores
            // the elements.
            let mut rest = i % per_record;
            let mut index = Vec::with_capacity(v.dims.len());
            for d in v.dims.iter().rev() {
                let n = (*d as usize).max(1);
                index.push(rest % n);
                rest /= n;
            }
            index.reverse();
            for i in index {
                let _ = write!(out, "[{i}]");
            }
            let _ = writeln!(out, " = {value}");
        }
    }
    if out.trim().is_empty() {
        bail!("empty CDF-3 header");
    }
    Ok(Outcome::Text(out.into_bytes()))
}

/// The values of a CDF-3 variable: the records it holds, each of them
/// the elements of the variable's shape.
///
/// The data of a variable lives in blocks that a chain of index records
/// points at: the index record names the blocks, the range of records
/// each one holds, and where it is in the file. A block the file
/// compressed, or a variable whose records are sparse, is refused: undo
/// a compression is not something this reader does, and a sparse record
/// that was never written is a pad value the file does not always carry.
#[cfg(feature = "netcdf3")]
fn cdf3_values(
    rec: &CdfRecords<'_>,
    data: &[u8],
    var: &CdfVar,
    encoding: i32,
) -> Result<Vec<String>, &'static str> {
    if var.compressed {
        return Err("the data is compressed, and this reader does not decompress it");
    }
    if var.sparse != 0 {
        return Err("the records are sparse, and this reader does not fill the gaps");
    }
    let Some(big_endian) = cdf_big_endian(encoding) else {
        return Err("the encoding of the values is one this reader does not know");
    };
    let width = cdf_type_width(var.ty);
    if width == 0 {
        return Err("the type carries an encoding of its own, and this reader does not decode it");
    }
    // The elements of one record, and the bytes each of them takes.
    let per_record: usize = var
        .dims
        .iter()
        .map(|d| *d as usize)
        .product::<usize>()
        .max(1);
    let bytes_per_value = (var.num_elements.max(0) as usize).saturating_mul(width);
    if bytes_per_value == 0 {
        return Err("the variable holds no elements");
    }
    // The records of the variable: one, when the records do not vary,
    // and as many as the descriptor says when they do. The block that
    // holds them says how many it has, and that number is not the one
    // that counts: the descriptor is.

    let records = if var.record_vary {
        (var.max_rec + 1).max(0) as usize
    } else {
        1
    };
    let count = records.saturating_mul(per_record);
    let mut blocks = Vec::new();
    cdf3_vxrs(rec, data, var.head_vxr, &mut blocks, 0)
        .ok_or("the blocks of the data are indexed by a tree this reader does not read")?;
    let mut raw: Vec<u8> = Vec::new();
    for (addr, _start, _end) in &blocks {
        let Some(block) = cdf3_block(data, *addr) else {
            return Err(
                "a block of the data is compressed, and this reader does not decompress it",
            );
        };
        raw.extend_from_slice(block);
    }
    let mut out = Vec::with_capacity(count.min(raw.len() / bytes_per_value));
    for i in 0..count {
        let at = i * bytes_per_value;
        let Some(b) = raw.get(at..at + bytes_per_value) else {
            break;
        };
        let text = cdf_element_text(var.ty, big_endian, b)
            .ok_or("the value is of a type this reader does not decode")?;
        out.push(text);
    }
    Ok(out)
}

/// The blocks of a variable's data, and the range of records each one
/// holds.
#[cfg(feature = "netcdf3")]
fn cdf3_vxrs(
    rec: &CdfRecords<'_>,
    data: &[u8],
    head: u64,
    out: &mut Vec<(u64, i32, i32)>,
    depth: u32,
) -> Option<()> {
    if depth > 64 {
        return None;
    }
    let o = rec.at(head).ok()?;
    let next = rec.u64(o + 12).ok()?;
    let num_ent = rec.i32(o + 20).ok()?;
    let used = rec.i32(o + 24).ok()?;

    if num_ent < 0 || used < 0 || used > num_ent {
        return None;
    }
    for ix in 0..used as usize {
        let start = rec.i32(o + 28 + 4 * ix).ok()?;
        let end = rec.i32(o + 28 + 4 * num_ent as usize + 4 * ix).ok()?;
        let offset = rec.u64(o + 28 + 8 * num_ent as usize + 8 * ix).ok()?;
        // The block may be a compressed index record, which points at
        // more of them.
        let kind = cdf3_kind(data, offset)?;
        if kind == CDF_CVXR {
            cdf3_vxrs(rec, data, offset, out, depth + 1)?;
        } else {
            out.push((offset, start, end));
        }
    }
    if next != 0 {
        cdf3_vxrs(rec, data, next, out, depth + 1)?;
    }
    Some(())
}

/// The bytes of a block of a variable's data.
#[cfg(feature = "netcdf3")]
fn cdf3_block(data: &[u8], addr: u64) -> Option<&[u8]> {
    let at = usize::try_from(addr).ok()?;
    let size = u64::from_be_bytes(data.get(at..at + 8)?.try_into().ok()?) as usize;
    // The size is the size of the whole record, the eight bytes of the
    // size included.
    let body = data.get(at + 8..at + size)?;
    match cdf3_kind(data, addr)? {
        CDF_VVR => Some(body.get(4..)?),
        // A compressed block: this reader does not decompress it.
        _ => None,
    }
}

/// The kind of the record at `addr`: the blocks of the data are in the
/// file, not in the descriptor.
#[cfg(feature = "netcdf3")]
fn cdf3_kind(data: &[u8], addr: u64) -> Option<i32> {
    let at = usize::try_from(addr).ok()?;
    let body = data.get(at + 8..at + 12)?;
    Some(i32::from_be_bytes(body.try_into().ok()?))
}

/// The text of one element of a CDF-3 type, as the type gives it.
///
/// `bytes` holds the element: for a number, the bytes of the number;
/// for a character, the bytes of the string it holds.
#[cfg(feature = "netcdf3")]
fn cdf_element_text(ty: i32, big_endian: bool, bytes: &[u8]) -> Option<String> {
    let int = |n: usize| -> Option<u64> {
        let b = bytes.get(..n)?;
        let mut v = 0u64;
        if big_endian {
            for &x in b {
                v = (v << 8) | x as u64;
            }
        } else {
            for (i, &x) in b.iter().enumerate() {
                v |= (x as u64) << (8 * i);
            }
        }
        Some(v)
    };
    match ty {
        // The signed types.
        1 | 41 => Some(format!("{}", int(1)? as u8 as i8)),
        2 => Some(format!("{}", int(2)? as u16 as i16)),
        4 => Some(format!("{}", int(4)? as u32 as i32)),
        8 => Some(format!("{}", int(8)? as i64)),
        // The unsigned ones.
        11 => Some(format!("{}", int(1)? as u8)),
        12 => Some(format!("{}", int(2)? as u16)),
        14 => Some(format!("{}", int(4)? as u32)),
        // The floats.
        21 | 44 => Some(format!("{}", f32::from_bits(int(4)? as u32))),
        22 | 45 => Some(format!("{}", f64::from_bits(int(8)?))),
        // The characters: a string, with the padding dropped.
        51 | 52 => {
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
        }
        _ => None,
    }
}

/// Walk a chain of variable records: an rVDR chain for the record
/// variables, a zVDR chain for the others.
#[cfg(feature = "netcdf3")]
fn cdf3_vdrs(
    rec: &CdfRecords<'_>,
    head: u64,
    zvars: bool,
    r_dims: &[i32],
    out: &mut Vec<CdfVar>,
) -> Result<()> {
    let want = if zvars { CDF_ZVDR } else { CDF_RVDR };
    let mut off = head;
    let mut guard = 0u32;
    while off != 0 && guard < CDF_MAX_VARS {
        guard += 1;
        let o = rec.at(off)?;
        if rec.i32(o + 8)? != want {
            bail!("CDF-3 variable list holds the wrong record type");
        }
        let next = rec.u64(o + 12)?;
        let ty = rec.i32(o + 20)?;
        let num = rec.i32(o + 68)?;
        // The data of the variable lives where the descriptor says: the
        // number of elements in a record, the number of records, the
        // chain of index records that points at the blocks, and whether
        // the records are sparse.
        let max_rec = rec.i32(o + 24)?;
        let head_vxr = rec.u64(o + 28)?;
        let flags = rec.u32(o + 44)?;

        let sparse = rec.i32(o + 48)?;
        let num_elements = rec.i32(o + 64)?;

        let name = cdf_name(rec, o + 84)?;
        // A zVariable carries its own dimension sizes; the record
        // variables share the list the GDR holds.
        let dims = if zvars {
            let n = rec.i32(o + 340)?.clamp(0, CDF_MAX_DIMS);
            let mut v = Vec::with_capacity(n as usize);
            for i in 0..n {
                v.push(rec.i32(o + 344 + 4 * i as usize)?);
            }
            v
        } else {
            r_dims.to_vec()
        };
        out.push(CdfVar {
            num,
            name,
            ty,
            dims,
            num_elements,
            max_rec,
            // The flags of the descriptor: the first bit says whether
            // the records vary, the second whether the data is padded,
            // and the third whether it is compressed.
            record_vary: flags & 0x1 != 0,
            head_vxr,
            sparse,
            compressed: flags & 0x4 != 0,
        });
        off = next;
    }
    Ok(())
}

/// What an attribute walk needs besides the records: the encoding the
/// values are in, how many lines it may still write, and where they go.
#[cfg(feature = "netcdf3")]
struct CdfAttrCtx<'a> {
    encoding: i32,
    budget: usize,
    out: &'a mut String,
}

/// Write the attribute records: one line per attribute entry. A global
/// attribute's entries belong to the file; a variable attribute's entries
/// name the variable they apply to.
#[cfg(feature = "netcdf3")]
fn cdf3_attributes(
    rec: &CdfRecords<'_>,
    head: u64,
    rvars: (&[CdfVar], &BTreeMap<i32, usize>),
    zvars: (&[CdfVar], &BTreeMap<i32, usize>),
    ctx: &mut CdfAttrCtx<'_>,
) -> Result<()> {
    let mut off = head;
    let mut guard = 0u32;
    // The lines the attributes may write in all, over every chain. A
    // file that loops its attribute chain would otherwise write forever.
    ctx.budget = CDF_MAX_ATTR_LINES;
    while off != 0 && guard < CDF_MAX_ATTRS && ctx.budget > 0 {
        guard += 1;
        let o = rec.at(off)?;
        if rec.i32(o + 8)? != CDF_ADR {
            bail!("CDF-3 attribute list holds the wrong record type");
        }
        let next = rec.u64(o + 12)?;
        let scope = rec.i32(o + 28)?;
        let name = cdf_name(rec, o + 68)?;
        match scope {
            CDF_SCOPE_GLOBAL | CDF_SCOPE_GLOBAL_ASSUMED => {
                cdf3_entries(rec, rec.u64(o + 20)?, CDF_AGR_EDR, None, &name, ctx)?;
            }
            CDF_SCOPE_VARIABLE | CDF_SCOPE_VARIABLE_ASSUMED => {
                // The rEntries of a variable attribute name a record
                // variable, the zEntries name one of the others.
                cdf3_entries(rec, rec.u64(o + 20)?, CDF_AGR_EDR, Some(rvars), &name, ctx)?;
                cdf3_entries(rec, rec.u64(o + 48)?, CDF_AZ_EDR, Some(zvars), &name, ctx)?;
            }
            other => bail!("CDF-3 attribute has the unknown scope {other}"),
        }
        off = next;
    }
    Ok(())
}

/// Write the entries of one attribute: a chain of AEDR records, each
/// holding one value.
#[cfg(feature = "netcdf3")]
fn cdf3_entries(
    rec: &CdfRecords<'_>,
    head: u64,
    want: i32,
    vars: Option<(&[CdfVar], &BTreeMap<i32, usize>)>,
    attr: &str,
    ctx: &mut CdfAttrCtx<'_>,
) -> Result<()> {
    let mut e = head;
    let mut guard = 0u32;
    while e != 0 && guard < CDF_MAX_ENTRIES && ctx.budget > 0 {
        guard += 1;
        let o = rec.at(e)?;
        if rec.i32(o + 8)? != want {
            bail!("CDF-3 attribute entry holds the wrong record type");
        }
        let next = rec.u64(o + 12)?;
        let num = rec.i32(o + 28)?;
        let ty = rec.i32(o + 24)?;
        let nelems = rec.i32(o + 32)?;
        let nstrings = rec.i32(o + 36)?;
        let owner = match vars {
            None => "global".to_string(),
            Some((list, index)) => match index.get(&num) {
                Some(&i) => list[i].name.clone(),
                // The entry names a variable the file does not define.
                // Keeping the number is better than dropping the value.
                None => format!("#{num}"),
            },
        };
        let value = cdf3_value(rec, o + 56, ty, nelems, nstrings, ctx.encoding);
        let _ = writeln!(ctx.out, "{owner}@{attr} = {value}");
        ctx.budget = ctx.budget.saturating_sub(1);
        e = next;
    }
    Ok(())
}

/// The value of one attribute entry, as it is written out. A type this
/// reader does not decode -- the epoch types, or a number outside the
/// table -- is written as `?` rather than as a number nobody decoded.
#[cfg(feature = "netcdf3")]
fn cdf3_value(
    rec: &CdfRecords<'_>,
    off: usize,
    ty: i32,
    nelems: i32,
    nstrings: i32,
    encoding: i32,
) -> String {
    let width = cdf_type_width(ty);
    if width == 0 || nelems < 0 {
        return "?".to_string();
    }
    let n = nelems as usize;
    if n > 4096 {
        return "?".to_string();
    }
    let Some(raw) = rec.field(off, n * width) else {
        return "?".to_string();
    };
    // A character value is text.
    if ty == 51 || ty == 52 {
        let text = String::from_utf8_lossy(raw);
        let text = text.trim_end_matches('\0');
        if nstrings > 1 {
            let parts: Vec<String> = text.split('\0').map(|p| format!("{p:?}")).collect();
            return format!("[{}]", parts.join(", "));
        }
        return format!("{text:?}");
    }
    // Everything else is a number in the file's own byte order.
    let Some(big) = cdf_big_endian(encoding) else {
        return "?".to_string();
    };
    if !cdf_float_is_ieee(encoding) && matches!(ty, 21 | 44 | 22 | 45) {
        return "?".to_string();
    }
    let mut vals: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        let b = &raw[i * width..(i + 1) * width];
        let v = match ty {
            1 | 41 => cdf_int(b, big).to_string(),
            11 => cdf_uint(b, big).to_string(),
            2 => cdf_int(b, big).to_string(),
            12 => cdf_uint(b, big).to_string(),
            4 => cdf_int(b, big).to_string(),
            14 => cdf_uint(b, big).to_string(),
            8 => cdf_int(b, big).to_string(),
            21 | 44 => float_text(cdf_float(b, big)),
            22 | 45 => float_text(cdf_float(b, big)),
            _ => "?".to_string(),
        };
        vals.push(v);
    }
    format!("[{}]", vals.join(", "))
}

/// Decode the descriptor of a packed CDF-3.
///
/// The CPR record says which scheme the whole file was packed with: the
/// CDF library's own run-length encoding, or gzip. Huffman and adaptive
/// Huffman are refused -- they are not decoded here, and a descriptor read
/// with the wrong scheme is worse than no descriptor at all.
#[cfg(feature = "netcdf3")]
fn cdf3_unpack(data: &[u8]) -> Result<Vec<u8>> {
    // The CCR sits where the CDR would, at offset 8.
    let rec = CdfRecords { ir: data, base: 0 };
    let ccr = rec.at(8)?;
    if rec.i32(ccr + 8)? != CDF_CCR {
        bail!("packed CDF-3 does not start with a CCR record");
    }
    let record_size = rec.u64(ccr)? as usize;
    let cpr = rec.at(rec.u64(ccr + 12)?)?;
    let declared = rec.u64(ccr + 20)? as usize;
    if rec.i32(cpr + 8)? != CDF_CPR {
        bail!("packed CDF-3 does not point at a CPR record");
    }
    let ctype = rec.i32(cpr + 12)?;
    // The compressed bytes follow the CCR's fixed part.
    let Some(end) = ccr.checked_add(record_size) else {
        bail!("packed CDF-3 declares a descriptor size past the end of the file");
    };
    let Some(src) = data.get(ccr + 32..end) else {
        bail!("packed CDF-3 descriptor runs past the end of the file");
    };
    // The declared size bounds the decode: it is what the descriptor is
    // supposed to weigh once unpacked.
    let limit = declared.min(64 * 1024 * 1024);
    let out = match ctype {
        CDF_COMPRESSION_NONE => src.to_vec(),
        CDF_COMPRESSION_RLE => cdf3_rle(src, limit)?,
        CDF_COMPRESSION_GZIP => {
            match rgx_core::compress::gzip::GzipReader::decode_bounded(src, limit as u64) {
                Ok(b) if b.capped => {
                    bail!("packed CDF-3 gzip descriptor is larger than its CCR declares")
                }
                Ok(b) => b.bytes,
                Err(e) => bail!("packed CDF-3 gzip descriptor did not decode: {e}"),
            }
        }
        other => bail!("packed CDF-3 uses compression type {other}, which is not decoded here"),
    };
    if out.len() != declared {
        bail!(
            "packed CDF-3 descriptor unpacked to {} bytes, not the {declared} its CCR declares",
            out.len()
        );
    }
    Ok(out)
}

/// The CDF library's run-length encoding: a zero byte introduces a run of
/// zeros, and the byte after it counts the zeros that follow -- one more
/// than the byte says, so a count runs from 1 to 256.
#[cfg(feature = "netcdf3")]
fn cdf3_rle(src: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(src.len().min(limit));
    let mut i = 0;
    while i < src.len() {
        let b = src[i];
        i += 1;
        if b == 0 {
            let Some(&count) = src.get(i) else {
                bail!("packed CDF-3 run-length descriptor ends inside a run");
            };
            i += 1;
            out.resize(out.len() + count as usize + 1, 0);
        } else {
            out.push(b);
        }
        if out.len() > limit {
            bail!("packed CDF-3 run-length descriptor expands past the size its CCR declares");
        }
    }
    Ok(out)
}

// ---------- NASA CDF-1 / CDF-2 ----------

/// NASA's pre-V2.6 magic: `00 00 FF FF`. A file that starts with it is an
/// old CDF: the same chain of internal records a CDF-3 is, but with the
/// record sizes and the offsets inside them in 32 bits, where a CDF-3
/// keeps them in 64.
#[cfg(feature = "netcdf3")]
const CDF1_MAGIC: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];

/// NASA's V2.6/V2.7 magic: `CD F2 60 02`.
#[cfg(feature = "netcdf3")]
const CDF2_MAGIC: [u8; 4] = [0xCD, 0xF2, 0x60, 0x02];

/// The internal records of a NASA CDF-1 or CDF-2 file: the file itself,
/// with every record addressed by a 32-bit offset.
///
/// The chain of records is the one a CDF-3 has -- CDR, GDR, VDRs, ADRs,
/// AEDRs -- and the two layouts differ in the width of the fields: an
/// offset is four bytes here and eight there, so every field that
/// follows one moves with it.
#[cfg(feature = "netcdf3")]
struct Cdf12Records<'a> {
    ir: &'a [u8],
}

#[cfg(feature = "netcdf3")]
impl<'a> Cdf12Records<'a> {
    /// The buffer offset of the record at a file offset, checked to be
    /// inside the descriptor. An offset that does not fit, or points past
    /// the end, is refused here rather than overflowing an addition
    /// further down: the offsets come out of the file, so they are as
    /// hostile as any other number in it.
    fn at(&self, off: u32) -> Result<usize> {
        let o = off as usize;
        if o > self.ir.len() {
            bail!("CDF record offset {off} is past the end of the descriptor");
        }
        Ok(o)
    }

    /// The `n` bytes of a field.
    fn field(&self, o: usize, n: usize) -> Option<&'a [u8]> {
        let end = o.checked_add(n)?;
        self.ir.get(o..end)
    }

    fn u32(&self, o: usize) -> Result<u32> {
        let Some(b) = self.field(o, 4) else {
            bail!("CDF record field at {o} is past the end of the descriptor");
        };
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32(&self, o: usize) -> Result<i32> {
        Ok(self.u32(o)? as i32)
    }
}

/// A CDF name: a fixed 64-byte field, NUL padded. A CDF-3 keeps the name
/// in 256 bytes, and this is the only place the two layouts differ in
/// more than the width of a number.
#[cfg(feature = "netcdf3")]
fn cdf12_name(rec: &Cdf12Records<'_>, off: usize) -> Result<String> {
    let Some(raw) = rec.field(off, 64) else {
        bail!("CDF record name at {off} is past the end of the descriptor");
    };
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(&raw[..end]).into_owned())
}

/// Read a NASA CDF-1 or CDF-2 file: the variables with their types and
/// shapes, their attributes, and their values.
///
/// The descriptor is a chain of internal records -- CDR, GDR, VDRs, ADRs,
/// AEDRs -- addressed by 32-bit offsets, where a CDF-3 addresses them by
/// 64-bit ones. The two layouts are the same chain with different field
/// widths, so the walk is the same walk.
///
/// A dimension whose variance is FALSE is virtual: the file does not
/// store it, so the shape reported is the one the file stores, and the
/// values are the stored ones.
#[cfg(feature = "netcdf3")]
fn cdf12_extract(data: &[u8]) -> Result<Outcome> {
    let cdf1 = data[0..4] == CDF1_MAGIC;
    // The second magic word says whether the descriptor is packed: a
    // CDF-2 whose descriptor is behind a CCR record is not unpacked here.
    let second = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if second == CDF3_PACKED {
        bail!("a compressed NASA CDF descriptor is not unpacked by this reader; unsupported");
    }
    let rec = Cdf12Records { ir: data };
    // The CDR is always the first record of a CDF.
    let cdr = rec.at(8)?;
    if rec.i32(cdr + 4)? != CDF_CDR {
        bail!("CDF descriptor does not start with a CDR record");
    }
    let gdr = rec.at(rec.u32(cdr + 8)?)?;
    let version = rec.i32(cdr + 12)?;
    let release = rec.i32(cdr + 16)?;
    let encoding = rec.i32(cdr + 20)?;
    if rec.i32(gdr + 4)? != CDF_GDR {
        bail!("CDF descriptor does not point at a GDR record");
    }
    let rvdr_head = rec.u32(gdr + 8)?;
    let zvdr_head = rec.u32(gdr + 12)?;
    let adr_head = rec.u32(gdr + 16)?;
    let r_num_dims = rec.i32(gdr + 36)?;
    // The record variables share one list of dimension sizes, which the
    // GDR holds. CDF has no dimension names, so this list is all a
    // variable's shape is made of.
    let mut r_dims: Vec<i32> = Vec::new();
    for i in 0..r_num_dims.clamp(0, CDF_MAX_DIMS) {
        r_dims.push(rec.i32(gdr + 60 + 4 * i as usize)?);
    }
    // A CDF older than V2.5 keeps 128 bytes in its variable records that
    // the newer ones do not, and every field after them moves with them.
    let toadd = if version == 2 && release >= 5 { 0 } else { 128 };

    let mut rvars: Vec<CdfVar> = Vec::new();
    let mut zvars: Vec<CdfVar> = Vec::new();
    cdf12_vdrs(&rec, rvdr_head, false, &r_dims, toadd, &mut rvars)?;
    cdf12_vdrs(&rec, zvdr_head, true, &[], toadd, &mut zvars)?;
    // An attribute entry names its variable by number, and a file may
    // hold thousands of them: the lookup is a map, so the walk does not
    // turn quadratic on a chain that loops.
    let rindex: BTreeMap<i32, usize> = rvars.iter().enumerate().map(|(i, v)| (v.num, i)).collect();
    let zindex: BTreeMap<i32, usize> = zvars.iter().enumerate().map(|(i, v)| (v.num, i)).collect();

    let mut out = String::new();
    let _ = writeln!(
        out,
        "CDF version {version}.{release} (NASA CDF-{} layout), file size {}",
        if cdf1 { 1 } else { 2 },
        data.len()
    );
    cdf12_attributes(
        &rec,
        adr_head,
        (&rvars, &rindex),
        (&zvars, &zindex),
        &mut CdfAttrCtx {
            encoding,
            budget: CDF_MAX_ATTR_LINES,
            out: &mut out,
        },
    )?;
    for v in rvars.iter().chain(zvars.iter()) {
        let _ = write!(out, "var {}: {} dims=[", v.name, cdf_type_name(v.ty));
        for (i, d) in v.dims.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, ", ");
            }
            let _ = write!(out, "{d}");
        }
        let _ = writeln!(out, "]");
        // The values, when the file stores them where this reader can
        // read them.
        let values = match cdf12_values(&rec, data, v, encoding) {
            Ok(values) => values,
            Err(why) => {
                let _ = writeln!(out, "truncated: {}: {why}", v.name);
                continue;
            }
        };
        // The records of a variable come first: the shape of one record
        // is the variable's shape, and the records are the dimension
        // before it.
        let per_record: usize = v.dims.iter().map(|d| *d as usize).product::<usize>().max(1);
        for (i, value) in values.iter().enumerate() {
            let _ = write!(out, "value {}[{}]", v.name, i / per_record);
            // The last dimension counts fastest, the way the file stores
            // the elements.
            let mut rest = i % per_record;
            let mut index = Vec::with_capacity(v.dims.len());
            for d in v.dims.iter().rev() {
                let n = (*d as usize).max(1);
                index.push(rest % n);
                rest /= n;
            }
            index.reverse();
            for i in index {
                let _ = write!(out, "[{i}]");
            }
            let _ = writeln!(out, " = {value}");
        }
    }
    if out.trim().is_empty() {
        bail!("empty CDF header");
    }
    Ok(Outcome::Text(out.into_bytes()))
}

/// Walk a chain of variable records: an rVDR chain for the record
/// variables, a zVDR chain for the others.
#[cfg(feature = "netcdf3")]
fn cdf12_vdrs(
    rec: &Cdf12Records<'_>,
    head: u32,
    zvars: bool,
    r_dims: &[i32],
    toadd: usize,
    out: &mut Vec<CdfVar>,
) -> Result<()> {
    let want = if zvars { CDF_ZVDR } else { CDF_RVDR };
    let mut off = head;
    let mut guard = 0u32;
    while off != 0 && guard < CDF_MAX_VARS {
        guard += 1;
        let o = rec.at(off)?;
        if rec.i32(o + 4)? != want {
            bail!("CDF variable list holds the wrong record type");
        }
        let next = rec.u32(o + 8)?;
        let ty = rec.i32(o + 12)?;
        // The data of the variable lives where the descriptor says: the
        // number of elements in a record, the number of records, the
        // chain of index records that points at the blocks, and whether
        // the records are sparse.
        let max_rec = rec.i32(o + 16)?;
        let head_vxr = rec.u32(o + 20)?;
        let flags = rec.u32(o + 28)?;
        let sparse = rec.i32(o + 32)?;
        let num_elements = rec.i32(o + 48 + toadd)?;
        let num = rec.i32(o + 52 + toadd)?;
        let name = cdf12_name(rec, o + 64 + toadd)?;
        // The dimension variances say which of the dimensions the file
        // stores: a dimension with a FALSE variance is virtual, and the
        // values of the variable do not have it.
        let dims = if zvars {
            // A zVariable carries its own dimension sizes; the record
            // variables share the list the GDR holds.
            let n = rec.i32(o + 128 + toadd)?.clamp(0, CDF_MAX_DIMS);
            let mut sizes = Vec::with_capacity(n as usize);
            for i in 0..n as usize {
                sizes.push(rec.i32(o + 132 + toadd + 4 * i)?);
            }
            let mut stored = Vec::with_capacity(n as usize);
            for (i, size) in sizes.iter().enumerate() {
                if rec.i32(o + 132 + toadd + 4 * n as usize + 4 * i)? != 0 {
                    stored.push(*size);
                }
            }
            stored
        } else {
            let mut stored = Vec::with_capacity(r_dims.len());
            for (i, size) in r_dims.iter().enumerate().take(CDF_MAX_DIMS as usize) {
                if rec.i32(o + 128 + toadd + 4 * i)? != 0 {
                    stored.push(*size);
                }
            }
            stored
        };
        out.push(CdfVar {
            num,
            name,
            ty,
            dims,
            num_elements,
            max_rec,
            // The flags of the descriptor: the first bit says whether
            // the records vary, the second whether the data is padded,
            // and the third whether it is compressed.
            record_vary: flags & 0x1 != 0,
            head_vxr: head_vxr as u64,
            sparse,
            compressed: flags & 0x4 != 0,
        });
        off = next;
    }
    Ok(())
}

/// Write the attribute records: one line per attribute entry. A global
/// attribute's entries belong to the file; a variable attribute's entries
/// name the variable they apply to.
#[cfg(feature = "netcdf3")]
fn cdf12_attributes(
    rec: &Cdf12Records<'_>,
    head: u32,
    rvars: (&[CdfVar], &BTreeMap<i32, usize>),
    zvars: (&[CdfVar], &BTreeMap<i32, usize>),
    ctx: &mut CdfAttrCtx<'_>,
) -> Result<()> {
    let mut off = head;
    let mut guard = 0u32;
    // The lines the attributes may write in all, over every chain. A
    // file that loops its attribute chain would otherwise write forever.
    ctx.budget = CDF_MAX_ATTR_LINES;
    while off != 0 && guard < CDF_MAX_ATTRS && ctx.budget > 0 {
        guard += 1;
        let o = rec.at(off)?;
        if rec.i32(o + 4)? != CDF_ADR {
            bail!("CDF attribute list holds the wrong record type");
        }
        let next = rec.u32(o + 8)?;
        let scope = rec.i32(o + 16)?;
        let name = cdf12_name(rec, o + 52)?;
        match scope {
            CDF_SCOPE_GLOBAL | CDF_SCOPE_GLOBAL_ASSUMED => {
                cdf12_entries(rec, rec.u32(o + 12)?, CDF_AGR_EDR, None, &name, ctx)?;
            }
            CDF_SCOPE_VARIABLE | CDF_SCOPE_VARIABLE_ASSUMED => {
                // The rEntries of a variable attribute name a record
                // variable, the zEntries name one of the others.
                cdf12_entries(rec, rec.u32(o + 12)?, CDF_AGR_EDR, Some(rvars), &name, ctx)?;
                cdf12_entries(rec, rec.u32(o + 36)?, CDF_AZ_EDR, Some(zvars), &name, ctx)?;
            }
            other => bail!("CDF attribute has the unknown scope {other}"),
        }
        off = next;
    }
    Ok(())
}

/// Write the entries of one attribute: a chain of AEDR records, each
/// holding one value.
#[cfg(feature = "netcdf3")]
fn cdf12_entries(
    rec: &Cdf12Records<'_>,
    head: u32,
    want: i32,
    vars: Option<(&[CdfVar], &BTreeMap<i32, usize>)>,
    attr: &str,
    ctx: &mut CdfAttrCtx<'_>,
) -> Result<()> {
    let mut e = head;
    let mut guard = 0u32;
    while e != 0 && guard < CDF_MAX_ENTRIES && ctx.budget > 0 {
        guard += 1;
        let o = rec.at(e)?;
        if rec.i32(o + 4)? != want {
            bail!("CDF attribute entry holds the wrong record type");
        }
        let next = rec.u32(o + 8)?;
        let ty = rec.i32(o + 16)?;
        let num = rec.i32(o + 20)?;
        let nelems = rec.i32(o + 24)?;
        let owner = match vars {
            None => "global".to_string(),
            Some((list, index)) => match index.get(&num) {
                Some(&i) => list[i].name.clone(),
                // The entry names a variable the file does not define.
                // Keeping the number is better than dropping the value.
                None => format!("#{num}"),
            },
        };
        let value = cdf12_value(rec, o + 48, ty, nelems, ctx.encoding);
        let _ = writeln!(ctx.out, "{owner}@{attr} = {value}");
        ctx.budget = ctx.budget.saturating_sub(1);
        e = next;
    }
    Ok(())
}

/// The value of one attribute entry, as it is written out. A type this
/// reader does not decode -- the epoch types, or a number outside the
/// table -- is written as `?` rather than as a number nobody decoded.
#[cfg(feature = "netcdf3")]
fn cdf12_value(rec: &Cdf12Records<'_>, off: usize, ty: i32, nelems: i32, encoding: i32) -> String {
    let width = cdf_type_width(ty);
    if width == 0 || nelems < 0 {
        return "?".to_string();
    }
    let n = nelems as usize;
    if n > 4096 {
        return "?".to_string();
    }
    let Some(raw) = rec.field(off, n * width) else {
        return "?".to_string();
    };
    // A character value is text.
    if ty == 51 || ty == 52 {
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let text = String::from_utf8_lossy(&raw[..end]);
        return format!("{text:?}");
    }
    // Everything else is a number in the file's own byte order.
    let Some(big) = cdf_big_endian(encoding) else {
        return "?".to_string();
    };
    if !cdf_float_is_ieee(encoding) && matches!(ty, 21 | 44 | 22 | 45) {
        return "?".to_string();
    }
    let mut vals: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        let b = &raw[i * width..(i + 1) * width];
        let v = match ty {
            1 | 41 => cdf_int(b, big).to_string(),
            11 => cdf_uint(b, big).to_string(),
            2 => cdf_int(b, big).to_string(),
            12 => cdf_uint(b, big).to_string(),
            4 => cdf_int(b, big).to_string(),
            14 => cdf_uint(b, big).to_string(),
            8 => cdf_int(b, big).to_string(),
            21 | 44 => float_text(cdf_float(b, big)),
            22 | 45 => float_text(cdf_float(b, big)),
            _ => "?".to_string(),
        };
        vals.push(v);
    }
    format!("[{}]", vals.join(", "))
}

/// The values of a CDF-1 or CDF-2 variable: the records it holds, each of
/// them the elements of the variable's shape.
///
/// The data of a variable lives in blocks that a chain of index records
/// points at: the index record names the blocks, the range of records
/// each one holds, and where it is in the file. A block the file
/// compressed, or a variable whose records are sparse, is refused: undo
/// a compression is not something this reader does, and a sparse record
/// that was never written is a pad value the file does not always carry.
#[cfg(feature = "netcdf3")]
fn cdf12_values(
    rec: &Cdf12Records<'_>,
    data: &[u8],
    var: &CdfVar,
    encoding: i32,
) -> Result<Vec<String>, &'static str> {
    if var.compressed {
        return Err("the data is compressed, and this reader does not decompress it");
    }
    if var.sparse != 0 {
        return Err("the records are sparse, and this reader does not fill the gaps");
    }
    let Some(big_endian) = cdf_big_endian(encoding) else {
        return Err("the encoding of the values is one this reader does not know");
    };
    let width = cdf_type_width(var.ty);
    if width == 0 {
        return Err("the type carries an encoding of its own, and this reader does not decode it");
    }
    // The elements of one record, and the bytes each of them takes.
    let per_record: usize = var
        .dims
        .iter()
        .map(|d| *d as usize)
        .product::<usize>()
        .max(1);
    let bytes_per_value = (var.num_elements.max(0) as usize).saturating_mul(width);
    if bytes_per_value == 0 {
        return Err("the variable holds no elements");
    }
    // The records of the variable: one, when the records do not vary,
    // and as many as the descriptor says when they do.
    let records = if var.record_vary {
        (var.max_rec + 1).max(0) as usize
    } else {
        1
    };
    let count = records.saturating_mul(per_record);
    let mut blocks = Vec::new();
    cdf12_vxrs(rec, data, var.head_vxr as u32, &mut blocks, 0)
        .ok_or("the blocks of the data are indexed by a tree this reader does not read")?;
    let mut raw: Vec<u8> = Vec::new();
    for (addr, _start, _end) in &blocks {
        let Some(block) = cdf12_block(data, *addr) else {
            return Err(
                "a block of the data is compressed, and this reader does not decompress it",
            );
        };
        raw.extend_from_slice(block);
    }
    let mut out = Vec::with_capacity(count.min(raw.len() / bytes_per_value));
    for i in 0..count {
        let at = i * bytes_per_value;
        let Some(b) = raw.get(at..at + bytes_per_value) else {
            break;
        };
        let text = cdf_element_text(var.ty, big_endian, b)
            .ok_or("the value is of a type this reader does not decode")?;
        out.push(text);
    }
    Ok(out)
}

/// The blocks of a variable's data, and the range of records each one
/// holds.
#[cfg(feature = "netcdf3")]
fn cdf12_vxrs(
    rec: &Cdf12Records<'_>,
    data: &[u8],
    head: u32,
    out: &mut Vec<(u32, i32, i32)>,
    depth: u32,
) -> Option<()> {
    if depth > 64 {
        return None;
    }
    let o = rec.at(head).ok()?;
    let next = rec.u32(o + 8).ok()?;
    let num_ent = rec.i32(o + 12).ok()?;
    let used = rec.i32(o + 16).ok()?;
    if num_ent < 0 || used < 0 || used > num_ent {
        return None;
    }
    for ix in 0..used as usize {
        let start = rec.i32(o + 20 + 4 * ix).ok()?;
        let end = rec.i32(o + 20 + 4 * num_ent as usize + 4 * ix).ok()?;
        let offset = rec.u32(o + 20 + 8 * num_ent as usize + 4 * ix).ok()?;
        // The block may be a compressed index record, which points at
        // more of them.
        let kind = cdf12_kind(data, offset)?;
        if kind == CDF_CVXR {
            cdf12_vxrs(rec, data, offset, out, depth + 1)?;
        } else {
            out.push((offset, start, end));
        }
    }
    if next != 0 {
        cdf12_vxrs(rec, data, next, out, depth + 1)?;
    }
    Some(())
}

/// The bytes of a block of a variable's data.
#[cfg(feature = "netcdf3")]
fn cdf12_block(data: &[u8], addr: u32) -> Option<&[u8]> {
    let at = usize::try_from(addr).ok()?;
    let size = u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?) as usize;
    // The size is the size of the whole record, the four bytes of the
    // size included.
    let body = data.get(at + 4..at + size)?;
    match cdf12_kind(data, addr)? {
        CDF_VVR => Some(body.get(4..)?),
        // A compressed block: this reader does not decompress it.
        _ => None,
    }
}

/// The kind of the record at `addr`: the blocks of the data are in the
/// file, not in the descriptor.
#[cfg(feature = "netcdf3")]
fn cdf12_kind(data: &[u8], addr: u32) -> Option<i32> {
    let at = usize::try_from(addr).ok()?;
    let body = data.get(at + 4..at + 8)?;
    Some(i32::from_be_bytes(body.try_into().ok()?))
}

// ---------- Arrow IPC / Feather ----------

/// Arrow IPC files (.arrow) and Feather (.feather v1 "FEA1" / v2 "ARROW1"):
/// validate the magic, then harvest printable strings from the schema
/// region (field names, type names, metadata). The flatbuffer itself stays
/// unparsed — a schema-name index is what grep needs, and pulling the
/// arrow/flatbuffers stacks for it would violate the lightweight rule.
#[cfg(feature = "arrow")]
pub struct ArrowIpc;

/// Walk `region` for printable runs of at least `min_len` bytes and
/// write each unique run to `out` as `prefix<run>\n`. Runs are
/// deduplicated by a `BTreeSet<&[u8]>` of borrowed slices -- no
/// `String` allocation per match, no per-byte `run.push` on a
/// `Vec<u8>`.
#[cfg(any(feature = "arrow", feature = "hdf5"))]
fn harvest_printable(out: &mut String, region: &[u8], prefix: &str, min_len: usize) {
    use core::fmt::Write as _;
    let mut seen = alloc::collections::BTreeSet::<&[u8]>::new();
    let mut start: Option<usize> = None;
    for (i, &b) in region.iter().enumerate() {
        let printable = (0x20..=0x7e).contains(&b);
        match (printable, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min_len {
                    let key = &region[s..i];
                    if seen.insert(key) {
                        let s = core::str::from_utf8(key).unwrap_or("");
                        let _ = writeln!(out, "{prefix}{s}");
                    }
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        if region.len() - s >= min_len {
            let key = &region[s..];
            if seen.insert(key) {
                let s = core::str::from_utf8(key).unwrap_or("");
                let _ = writeln!(out, "{prefix}{s}");
            }
        }
    }
}
#[cfg(feature = "arrow")]
impl Adapter for ArrowIpc {
    fn name(&self) -> &'static str {
        "arrow"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["arrow", "feather"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let tail = data.len() >= 12
            && data[data.len() - 12..]
                .windows(6)
                .any(|w| w == b"ARROW1" || w == b"FEA1\0\0" || w == b"FEA1");
        if !tail {
            decline!("not an Arrow IPC file (bad trailing magic)");
        }
        let start = if data.starts_with(b"ARROW1") || data.starts_with(b"FEA1") {
            8
        } else {
            0
        };
        let region = &data[start..(64 << 10).min(data.len())];
        let mut out = String::new();
        harvest_printable(&mut out, region, "schema: ", 3);
        if out.trim().is_empty() {
            decline!("no schema strings found");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

// ---------- HDF5 (heuristic) ----------

/// The eight bytes every HDF5 file starts with.
#[cfg(any(feature = "hdf5", feature = "matv5"))]
const HDF5_MAGIC: [u8; 8] = [0x89, b'H', b'D', b'F', 0x0d, 0x0a, 0x1a, 0x0a];

/// Where the HDF5 file starts inside `data`.
///
/// A file may open with a **user block**: HDF5 lets the writer keep the first
/// bytes for itself, and the library finds the superblock by looking for the
/// signature at the powers of two from 512 up. MATLAB's v7.3 `.mat` is
/// exactly that -- 512 bytes of `MATLAB 7.3 MAT-file, Platform: ...` and
/// then the HDF5 file -- so a reader that only looks at offset 0 refuses
/// every real v7.3 file and the `.mat` falls through to its raw bytes.
#[cfg(any(feature = "hdf5", feature = "matv5"))]
fn hdf5_start(data: &[u8]) -> Option<usize> {
    let mut at = 0usize;
    loop {
        if data.len() >= at + 8 && data[at..at + 8] == HDF5_MAGIC {
            return Some(at);
        }
        at = if at == 0 { 512 } else { at * 2 };
        if at > 65536 {
            return None;
        }
    }
}

/// HDF5 superblock + name scan. Used by Keras/PyTorch weights (.h5), MATLAB
/// v7.3, netCDF-4 and most scientific stacks. The superblock is fixed-offset
/// fields, so it is always read:
///
/// 1. find the superblock, which may sit after a user block, and parse it
///    (v0/v1 or v2/v3) for version, address/length widths, end-of-file and
///    root addresses -- all fixed-offset fields, no heap walks;
/// 2. if the root group keeps its links in a **fractal heap** -- which is
///    what the current netCDF-4 layout does -- read the real link names out
///    of it: the v2 object header, the Link Info message, the v2 B-tree
///    that indexes the heap, and the heap's own blocks, one Link message
///    each. Those names come out of the file, so they are the names;
/// 3. if the group has too few members for a heap, HDF5 keeps its names
///    in the group's own object header, as link messages, and those are
///    read too -- it is what a small file has, and the printable strings
///    the fallback would find are fragments of the header, not names;
/// 4. otherwise the group keeps its links in a symbol table inside a v1
///    object header, and the only names on hand are the printable strings
///    in the header window. They are a guess, and they are labelled as one.
///
/// What each member *is* comes from the same object headers: a group, a
/// dataset with its type and shape, a dimension scale, a committed type,
/// or a soft link. A small object header puts the rest of its messages
/// in continuation chunks, and those are followed, so a dataset whose
/// layout message is over there is still a dataset; and a type the file
/// shares with other objects is followed to the object header that holds
/// it, so a variable on a committed type says so.
///
/// The **attributes** of the file and of every member are read from the
/// same headers, and each value is decoded with the attribute's own
/// datatype: a number as a number, a string as a string, and the bytes
/// of a value that is neither as hex, because a number that is not a
/// number is a lie.
///
/// The **members** of a type are read from the same headers too: the
/// names of the members of an enumeration with the values the file
/// gives them, and the names of the members of a compound with the
/// types they hold. A file that stores the same type twice -- once as a
/// committed type, once inside the variable that uses it -- lists the
/// members of that type once.
///
/// The `.nc` and `.mat` extensions are claimed here because both families
/// are HDF5 underneath: a netCDF-4 file is an HDF5 file with the netCDF
/// conventions on top, and a MATLAB v7.3 file is an HDF5 file behind a
/// 512-byte user block. The format-specific readers come first in the
/// registry and decline what is not theirs, so a netCDF-3 `.nc` and a
/// MATLAB v5 `.mat` still go to them.
#[cfg(feature = "hdf5")]
pub struct Hdf5;
#[cfg(feature = "hdf5")]
impl Adapter for Hdf5 {
    fn name(&self) -> &'static str {
        "hdf5"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["h5", "hdf5", "he5", "h5ad", "nc", "mat"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let Some(base) = hdf5_start(data) else {
            decline!("not an HDF5 file (bad magic)");
        };
        // Everything past the user block is the HDF5 file, and its addresses
        // are relative to that start, not to the start of the file on disk.
        let hdf5 = &data[base..];
        if hdf5.len() < 16 {
            decline!("truncated HDF5 file");
        }
        let superblock = match crate::hdf5::superblock(hdf5) {
            Ok(s) => s,
            Err(why) => bail!("hdf5: {why}"),
        };
        let version = superblock.version;
        let size_of_offsets = superblock.so;
        let size_of_lengths = superblock.sl;
        let eof = superblock.eof;
        let root_addr = superblock.root_addr;
        let mut out = format!(
            "hdf5 superblock v{version} offsets={size_of_offsets}B lengths={size_of_lengths}B eof={eof} root=0x{root_addr:x}\n"
        );
        if base > 0 {
            // the writer's own header, before the HDF5 file proper: MATLAB
            // puts its platform and creation date there
            harvest_printable(&mut out, &data[..base], "user block: ", 8);
        }
        // The names of a group that keeps them in a fractal heap are read
        // out of the heap. When they are, the printable strings are noise:
        // the real names are in the output, and they are the names.
        match crate::hdf5::report(hdf5, root_addr, size_of_offsets, size_of_lengths) {
            Ok(Some(report)) => {
                for link in &report.links {
                    let _ = writeln!(out, "{}", hdf5_link_line(link));
                }
                for attribute in &report.attributes {
                    let _ = writeln!(out, "{}", hdf5_attribute_line(attribute));
                }
                for member in &report.members {
                    let _ = writeln!(out, "{}", hdf5_member_line(member));
                }
                for value in &report.values {
                    let _ = writeln!(out, "{}", hdf5_value_line(value));
                }
                for truncated in &report.truncated {
                    let _ = writeln!(out, "{}", hdf5_truncated_line(truncated));
                }
            }
            Ok(None) => {
                // heuristic name index: object headers live at the front of
                // typical files; scan a bounded window for printable runs.
                let window = (256 << 10).min(hdf5.len());
                let region = &hdf5[..window];
                harvest_printable(&mut out, region, "name: ", 4);
            }
            Err(why) => bail!("hdf5: {why}"),
        }
        if out.lines().count() <= 1 {
            decline!("no names found in HDF5 header window");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// One line of the report: the link's path, what it points at and, for a
/// dataset, the datatype and the extent the file gives it.
#[cfg(feature = "hdf5")]
fn hdf5_link_line(link: &crate::hdf5::Link) -> String {
    use crate::hdf5::Kind;
    let what = match &link.kind {
        Kind::Group => "group".to_string(),
        Kind::Dataset {
            dtype,
            dims,
            dimension_scale,
        } => {
            let mut s = if *dimension_scale {
                "dimension scale".to_string()
            } else {
                "dataset".to_string()
            };
            if let Some(dtype) = dtype {
                let _ = write!(s, ": {dtype}");
            }
            if let Some(dims) = dims {
                let _ = write!(s, " dims=[");
                for (i, d) in dims.iter().enumerate() {
                    if i > 0 {
                        let _ = write!(s, ", ");
                    }
                    let _ = write!(s, "{d}");
                }
                let _ = write!(s, "]");
            }
            s
        }
        Kind::Soft { target } => format!("soft link -> {target}"),
        Kind::Datatype { dtype } => match dtype {
            Some(dtype) => format!("committed datatype: {dtype}"),
            None => "committed datatype".to_string(),
        },
        Kind::Unreadable { reason } => format!("object: {reason}"),
    };
    format!("link: {}: {what}", link.path)
}

/// One line of the report: the attribute, the object that holds it, and
/// the value the file gives it.
#[cfg(feature = "hdf5")]
fn hdf5_attribute_line(attribute: &crate::hdf5::Attribute) -> String {
    // The root group holds the file's own attributes, and it has no
    // path of its own.
    let path = if attribute.path.is_empty() {
        "<root>"
    } else {
        &attribute.path
    };
    format!(
        "attribute: {path}: {} = {}",
        attribute.name,
        hdf5_one_line(&attribute.value)
    )
}

/// One line of the report: the member of a type, the type that holds
/// it, and what the member holds.
///
/// The content of a member depends on the kind of type: the value of a
/// member of an enumeration, and the type of a member of a compound.
#[cfg(feature = "hdf5")]
fn hdf5_member_line(member: &crate::hdf5::Member) -> String {
    // The root group holds no type, so a member always has a path.
    let path = if member.path.is_empty() {
        "<root>"
    } else {
        &member.path
    };
    format!(
        "member: {path}: {} = {}",
        member.name,
        hdf5_one_line(&member.holds)
    )
}

/// One line of the report: the value, the dataset that holds it, and
/// the index that locates it inside the dataset.
#[cfg(feature = "hdf5")]
fn hdf5_value_line(value: &crate::hdf5::Value) -> String {
    let mut index = String::new();
    for i in &value.index {
        let _ = write!(index, "[{i}]");
    }
    format!(
        "value: {}{index} = {}",
        value.path,
        hdf5_one_line(&value.value)
    )
}

/// One line of the report: the dataset whose values the reader did not
/// read all of, how many of them it read, and why.
#[cfg(feature = "hdf5")]
fn hdf5_truncated_line(truncated: &crate::hdf5::Truncated) -> String {
    let mut line = format!(
        "truncated: {}: {} of {} values",
        truncated.path, truncated.read, truncated.total
    );
    if !truncated.reason.is_empty() {
        let _ = write!(line, ", {}", truncated.reason);
    }
    line
}

/// A value with the line breaks taken out of it: a record is a line,
/// and a value that carries a line break would split it in two.
#[cfg(feature = "hdf5")]
fn hdf5_one_line(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[cfg(any(
    feature = "arrow",
    feature = "hdf5",
    feature = "matv5",
    feature = "netcdf3"
))]
mod tests {
    use super::*;
    use alloc::string::String;
    #[cfg(any(feature = "hdf5", feature = "matv5", feature = "netcdf3"))]
    use alloc::vec::Vec;

    #[cfg(feature = "matv5")]
    fn mat_header() -> Vec<u8> {
        let mut h = vec![b' '; 116];
        h.extend_from_slice(&0u64.to_le_bytes()); // subsystem offset
        h.extend_from_slice(&0x0100u16.to_le_bytes()); // version 1.0
        h.extend_from_slice(b"IM"); // little-endian
        h
    }

    #[test]
    #[cfg(feature = "matv5")]
    fn mat_double_and_char() {
        let mut d = mat_header();
        // miMATRIX: flags(u32x2), dims(miINT32 1x3), name(small 'grid'),
        // data skipped (numeric summary only)
        d.extend_from_slice(&MI_MATRIX.to_le_bytes());
        let body_start = d.len();
        d.extend_from_slice(&0u32.to_le_bytes()); // placeholder size
        d.extend_from_slice(&MI_UINT32.to_le_bytes());
        d.extend_from_slice(&8u32.to_le_bytes());
        d.extend_from_slice(&6u32.to_le_bytes()); // mxDOUBLE_CLASS
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&MI_INT32.to_le_bytes());
        d.extend_from_slice(&4u32.to_le_bytes());
        d.extend_from_slice(&3u32.to_le_bytes());
        d.extend_from_slice(&[0u8; 4]); // 8-byte element alignment padding
                                        // small element: type u16 lo, nbytes u16 hi, 4 bytes data
        let small = (MI_INT32 & 0xFFFF) | (4 << 16);
        d.extend_from_slice(&small.to_le_bytes());
        d.extend_from_slice(b"grid");
        let size = d.len() - body_start - 4;
        d[body_start..body_start + 4].copy_from_slice(&(size as u32).to_le_bytes());
        let out = MatV5.extract(&d, "v.mat").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("grid: double dims=[3]"), "{s}");
    }

    #[test]
    #[cfg(feature = "matv5")]
    fn mat_compressed_char() {
        // contents of a miMATRIX: a char array "ZIRCALOY"
        let mut body = Vec::new();
        body.extend_from_slice(&MI_UINT32.to_le_bytes());
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(&4u32.to_le_bytes()); // mxCHAR
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&MI_INT32.to_le_bytes());
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&8u32.to_le_bytes());
        // name: full element 'label' (5 bytes, data padded to 8)
        body.extend_from_slice(&1u32.to_le_bytes()); // miINT8
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(b"label\0\0\0");
        // data: miUTF8 with the text
        body.extend_from_slice(&MI_UTF8.to_le_bytes());
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(b"ZIRCALOY");

        // wrap as a complete miMATRIX element, then compress
        let mut inner = Vec::new();
        inner.extend_from_slice(&MI_MATRIX.to_le_bytes());
        inner.extend_from_slice(&(body.len() as u32).to_le_bytes());
        inner.extend_from_slice(&body);

        let compressed = rgx_core::compress::zlib::ZlibEncoder::new().encode(&inner);

        let mut d = mat_header();
        d.extend_from_slice(&MI_COMPRESSED.to_le_bytes());
        d.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        d.extend_from_slice(&compressed);
        let out = MatV5.extract(&d, "c.mat").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("label: char"), "{s}");
        assert!(s.contains("ZIRCALOY"), "{s}");
    }

    #[test]
    #[cfg(feature = "matv5")]
    fn mat_rejects_hdf5_based_v7_3() {
        let d = vec![0x89u8; 200];
        assert!(MatV5.extract(&d, "h.mat").is_err());
    }

    #[cfg(feature = "netcdf3")]
    fn be(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_be_bytes());
    }

    #[test]
    #[cfg(feature = "netcdf3")]
    fn netcdf_classic_dims_vars_attrs() {
        let mut d = b"CDF\x01".to_vec();
        be(&mut d, 0); // numrecs
        be(&mut d, 0x0A); // dim list
        be(&mut d, 1); // 1 dim
        be(&mut d, 4);
        d.extend_from_slice(b"time");
        be(&mut d, 365);
        // global attrs
        be(&mut d, 0x0C);
        be(&mut d, 1);
        be(&mut d, 6);
        d.extend_from_slice(b"source");
        d.extend_from_slice(b"\x00\x00"); // pad name to 4-byte boundary
        be(&mut d, 4); // nc_int
        be(&mut d, 1);
        be(&mut d, 42);
        // vars
        be(&mut d, 0x0B);
        be(&mut d, 1);
        be(&mut d, 4); // name length ("temp")
        d.extend_from_slice(b"temp");
        be(&mut d, 1); // ndims
        be(&mut d, 0); // dimid
        be(&mut d, 0);
        be(&mut d, 0); // no var attrs
        be(&mut d, 6); // double
        be(&mut d, 8); // vsize
        be(&mut d, 128); // begin
        let out = NetCdf3.extract(&d, "c.nc").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("dim time = 365"), "{s}");
        assert!(s.contains("var temp: double dims=[0]"), "{s}");
        assert!(s.contains("source"), "{s}");
    }

    #[test]
    #[cfg(feature = "arrow")]
    fn arrow_harvests_schema_strings() {
        let mut d = b"ARROW1\0\0".to_vec();
        d.extend_from_slice(b"\xFF\xFF\xFF\xFF"); // continuation
        d.extend_from_slice(&64u32.to_le_bytes());
        d.extend_from_slice(b"temperature_id_ZIRCALOY_probe\0\0\0\0");
        d.extend_from_slice(&[0u8; 32]);
        d.extend_from_slice(b"\xFF\xFF\xFF\xFFARROW1\0\0");
        let out = ArrowIpc.extract(&d, "m.arrow").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("ZIRCALOY"), "{s}");
    }

    #[test]
    #[cfg(feature = "arrow")]
    fn arrow_rejects_non_arrow() {
        assert!(ArrowIpc
            .extract(b"random junk bytes here", "x.arrow")
            .is_err());
    }

    #[cfg(any(
        feature = "arrow",
        feature = "hdf5",
        feature = "matv5",
        feature = "netcdf3"
    ))]
    mod fuzz {
        use super::*;

        #[cfg(feature = "matv5")]
        fn mat_matrix() -> Vec<u8> {
            let mut d = mat_header();
            d.extend_from_slice(&MI_MATRIX.to_le_bytes());
            let body_start = d.len();
            d.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
            d.extend_from_slice(&MI_UINT32.to_le_bytes());
            d.extend_from_slice(&8u32.to_le_bytes());
            d.extend_from_slice(&6u32.to_le_bytes()); // mxDOUBLE_CLASS
            d.extend_from_slice(&0u32.to_le_bytes());
            d.extend_from_slice(&MI_INT32.to_le_bytes());
            d.extend_from_slice(&4u32.to_le_bytes());
            d.extend_from_slice(&3u32.to_le_bytes());
            d.extend_from_slice(&[0u8; 4]);
            let small = (MI_INT32 & 0xFFFF) | (4 << 16);
            d.extend_from_slice(&small.to_le_bytes());
            d.extend_from_slice(b"grid");
            let size = d.len() - body_start - 4;
            d[body_start..body_start + 4].copy_from_slice(&(size as u32).to_le_bytes());
            d
        }

        #[cfg(feature = "netcdf3")]
        fn netcdf() -> Vec<u8> {
            let mut d = b"CDF\x01".to_vec();
            be(&mut d, 0);
            be(&mut d, 0x0A);
            be(&mut d, 1);
            be(&mut d, 4);
            d.extend_from_slice(b"time");
            be(&mut d, 365);
            be(&mut d, 0x0C);
            be(&mut d, 0);
            be(&mut d, 0x0B);
            be(&mut d, 0);
            d
        }

        #[test]
        #[cfg(feature = "matv5")]
        fn matv5_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("matrix", mat_matrix()),
                    ("header-only", mat_header()),
                    ("empty", vec![]),
                ],
                1200,
                "matv5",
                |data| {
                    let _ = MatV5.extract(data, "fuzz.mat");
                },
            );
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn netcdf3_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("classic", netcdf()),
                    ("magic-only", b"CDF\x01".to_vec()),
                    ("empty", vec![]),
                ],
                1200,
                "netcdf3",
                |data| {
                    let _ = NetCdf3.extract(data, "fuzz.nc");
                },
            );
        }

        #[test]
        #[cfg(feature = "arrow")]
        fn arrow_ipc_never_panics_on_mutation() {
            let mut d = b"ARROW1\0\0".to_vec();
            d.extend_from_slice(b"\xFF\xFF\xFF\xFF");
            d.extend_from_slice(&64u32.to_le_bytes());
            d.extend_from_slice(b"temperature_id_ZIRCALOY_probe\0\0\0\0");
            d.extend_from_slice(&[0u8; 32]);
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("ipc", d),
                    ("magic-only", b"ARROW1\0\0".to_vec()),
                    ("empty", vec![]),
                ],
                1200,
                "arrow-ipc",
                |data| {
                    let _ = ArrowIpc.extract(data, "fuzz.arrow");
                },
            );
        }

        /// minimal superblock v0 (so=8, sl=8) with a plausible body
        #[cfg(any(feature = "hdf5", feature = "matv5"))]
        fn hdf5_v0() -> Vec<u8> {
            let mut d = b"\x89HDF\r\n\x1a\n".to_vec();
            d.push(0); // superblock version
            d.extend_from_slice(&[0, 0, 0, 0, 8, 8, 0]); // fs/root/shared ver, so, sl, rsvd
            d.extend_from_slice(&4u16.to_le_bytes()); // group leaf K
            d.extend_from_slice(&16u16.to_le_bytes()); // group internal K
            d.extend_from_slice(&[0u8; 4]); // reserved
            d.extend_from_slice(&96u64.to_le_bytes()); // base address
            d.extend_from_slice(&0u64.to_le_bytes()); // extension address
            d.extend_from_slice(&4096u64.to_le_bytes()); // eof address
            d.extend_from_slice(&0u64.to_le_bytes()); // driver info
                                                      // root group symbol table entry: name offset, obj header addr
            d.extend_from_slice(&0u64.to_le_bytes());
            d.extend_from_slice(&2048u64.to_le_bytes());
            // fake object header region with dataset/group names
            while d.len() < 2048 {
                d.push(0);
            }
            d.extend_from_slice(b"\x0b\x00\x01\x00measurements_ZIRCALOY_probe\x00");
            d.extend_from_slice(b"\x0b\x00\x01\x00grid_temperature\x00");
            d
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn hdf5_superblock_and_names() {
            let out = Hdf5.extract(&hdf5_v0(), "m.h5").unwrap();
            let Outcome::Text(t) = out else {
                panic!("text")
            };
            let s = String::from_utf8(t).unwrap();
            assert!(s.contains("superblock v0"), "{s}");
            assert!(s.contains("eof=4096"), "{s}");
            assert!(s.contains("root=0x800"), "{s}");
            assert!(s.contains("measurements_ZIRCALOY_probe"), "{s}");
            assert!(s.contains("grid_temperature"), "{s}");
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn an_attribute_is_one_line_with_the_object_that_holds_it() {
            let attribute = crate::hdf5::Attribute {
                path: String::new(),
                name: "_NCProperties".to_string(),
                value: "version=1".to_string(),
            };
            assert_eq!(
                hdf5_attribute_line(&attribute),
                "attribute: <root>: _NCProperties = version=1"
            );
            let attribute = crate::hdf5::Attribute {
                path: "sub/var".to_string(),
                name: "CLASS".to_string(),
                value: "DIMENSION_SCALE".to_string(),
            };
            assert_eq!(
                hdf5_attribute_line(&attribute),
                "attribute: sub/var: CLASS = DIMENSION_SCALE"
            );
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn a_member_is_one_line_with_the_type_that_holds_it() {
            let member = crate::hdf5::Member {
                path: "cargo".to_string(),
                name: "dogs".to_string(),
                holds: "5000000".to_string(),
            };
            assert_eq!(hdf5_member_line(&member), "member: cargo: dogs = 5000000");
            let member = crate::hdf5::Member {
                path: "cmp_t".to_string(),
                name: "y".to_string(),
                holds: "float64".to_string(),
            };
            assert_eq!(hdf5_member_line(&member), "member: cmp_t: y = float64");
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn a_value_is_one_line_with_the_dataset_that_holds_it() {
            let value = crate::hdf5::Value {
                path: "sub/var".to_string(),
                index: vec![1, 2],
                value: "42".to_string(),
            };
            assert_eq!(hdf5_value_line(&value), "value: sub/var[1][2] = 42");
            // A scalar has no index.
            let value = crate::hdf5::Value {
                path: "var".to_string(),
                index: Vec::new(),
                value: "42".to_string(),
            };
            assert_eq!(hdf5_value_line(&value), "value: var = 42");
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn a_dataset_the_reader_could_not_read_all_of_says_so() {
            let truncated = crate::hdf5::Truncated {
                path: "cr".to_string(),
                read: 0,
                total: 2,
                reason: "the data is in chunks, and this reader does not read them yet".to_string(),
            };
            assert_eq!(
                hdf5_truncated_line(&truncated),
                "truncated: cr: 0 of 2 values, the data is in chunks, and this reader does not read them yet"
            );
            let truncated = crate::hdf5::Truncated {
                path: "big".to_string(),
                read: 10,
                total: 20,
                reason: String::new(),
            };
            assert_eq!(
                hdf5_truncated_line(&truncated),
                "truncated: big: 10 of 20 values"
            );
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn the_values_of_a_netcdf4_dataset_are_read() {
            // The compound of the compact-links file holds a float and
            // a double, and the oracle says what they are:
            // `var = {1, -2}`.
            let s = hdf5_text("netcdf4-compact-links.nc");
            assert!(s.contains("value: var[0] = {x: 1, y: -2}"), "{s}");
            // The enumeration of the irish-rover file: the upstream
            // test wrote the first element, and the value is the name
            // the file gives it.
            let s = hdf5_text("netcdf4-irish-rover.nc");
            assert!(
                s.contains("value: in_the_hold_of_the_Irish_Rover[0] = bags of the best Sligo rags (1000000)"),
                "{s}"
            );
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn a_value_with_a_line_break_in_it_stays_on_one_line() {
            // A record is a line: a value that carries a line break
            // would split it in two, and the second half would look
            // like another record.
            assert_eq!(hdf5_one_line("a\nb"), "a\\nb");
            assert_eq!(hdf5_one_line("a\rb"), "a\\rb");
            assert_eq!(hdf5_one_line("a\tb"), "a\\tb");
            assert_eq!(hdf5_one_line("a\u{1}b"), "a\\x01b");
            assert_eq!(hdf5_one_line("plain"), "plain");
        }

        /// The same file behind a 512-byte user block, which is the shape
        /// MATLAB's v7.3 `.mat` has: the descriptive header, then the HDF5
        /// file.
        #[cfg(any(feature = "hdf5", feature = "matv5"))]
        fn hdf5_v0_behind_a_user_block() -> Vec<u8> {
            let mut d = b"MATLAB 7.3 MAT-file, Platform: GLNXA64".to_vec();
            while d.len() < 512 {
                d.push(0);
            }
            d.extend_from_slice(&hdf5_v0());
            d
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn a_matlab_v73_file_is_an_hdf5_file_behind_a_user_block() {
            let out = Hdf5
                .extract(&hdf5_v0_behind_a_user_block(), "m.mat")
                .unwrap();
            let Outcome::Text(t) = out else {
                panic!("text")
            };
            let s = String::from_utf8(t).unwrap();
            assert!(s.contains("superblock v0"), "{s}");
            assert!(s.contains("measurements_ZIRCALOY_probe"), "{s}");
            assert!(
                s.contains("user block: MATLAB 7.3 MAT-file"),
                "the writer's own header is worth saying: {s}"
            );
        }

        #[test]
        #[cfg(feature = "matv5")]
        fn the_mat_v5_reader_refuses_an_hdf5_file() {
            // The endian marker at 126 says "IM" in a v7.3 file too, so the
            // v5 reader would walk HDF5 bytes as tags and print nonsense.
            let Err(err) = MatV5.extract(&hdf5_v0_behind_a_user_block(), "m.mat") else {
                panic!("the v5 reader answered an HDF5 file");
            };
            assert!(err.is_decline(), "the v5 reader must decline, not guess");
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn a_user_block_is_only_a_user_block_up_to_64k() {
            // The library looks for the signature at the powers of two from
            // 512 up; a signature past that is not an HDF5 file.
            let mut d = vec![b'x'; 70 * 1024];
            d.extend_from_slice(b"\x89HDF\r\n\x1a\n");
            let Err(err) = Hdf5.extract(&d, "m.h5") else {
                panic!("a signature past 64k is not an HDF5 file");
            };
            assert!(err.is_decline(), "{err}");
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn hdf5_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("v0", hdf5_v0()),
                    ("magic-only", b"\x89HDF\r\n\x1a\n\x02".to_vec()),
                    ("v2", b"\x89HDF\r\n\x1a\n\x02\x08\x08\x00".to_vec()),
                    ("empty", vec![]),
                ],
                1200,
                "hdf5",
                |data| {
                    let _ = Hdf5.extract(data, "fuzz.h5");
                },
            );
        }

        /// The HDF5 fixtures, in the crate's own testdata.
        #[cfg(feature = "hdf5")]
        fn hdf5_fixture(name: &str) -> std::path::PathBuf {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("testdata")
                .join(name)
        }

        #[cfg(feature = "hdf5")]
        fn hdf5_text(name: &str) -> String {
            let path = hdf5_fixture(name);
            let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
            let out = Hdf5
                .extract(&data, name)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let Outcome::Text(t) = out else {
                panic!("{name}: not text")
            };
            String::from_utf8(t).unwrap_or_else(|e| panic!("{name}: {e}"))
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn hdf5_reads_the_names_out_of_the_fractal_heap() {
            // The newest netCDF-4 layout keeps the group and dataset
            // names in a fractal heap, so the reader has to walk the
            // heap and the B-tree that indexes it. It used to report
            // the superblock and the printable strings it could see.
            let s = hdf5_text("netcdf4-fractal-heap.nc");
            assert!(s.starts_with("hdf5 superblock v2"), "{s}");
            for line in [
                "link: Dr: dimension scale: float32 dims=[0]",
                "link: D1: dimension scale: float32 dims=[1]",
                "link: D4: dimension scale: float32 dims=[4]",
                "link: c: dataset: char dims=[]",
                "link: b: dataset: int8 dims=[]",
                "link: i: dataset: int32 dims=[]",
                "link: d: dataset: float64 dims=[]",
                "link: cr: dataset: char dims=[2]",
                "link: d434: dataset: float64 dims=[4, 3, 4]",
                "link: i444: dataset: int32 dims=[4, 4, 4]",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
            // Every name the `ncdump` oracle lists, and no others.
            let names: Vec<&str> = s
                .lines()
                .filter_map(|l| l.strip_prefix("link: "))
                .filter_map(|l| l.split(':').next())
                .collect();
            assert_eq!(names.len(), 146, "{s}");
            let cdl = std::fs::read(hdf5_fixture("netcdf4-fractal-heap.cdl"))
                .unwrap_or_else(|e| panic!("the oracle: {e}"));
            let cdl = String::from_utf8_lossy(&cdl);
            let mut oracle: Vec<String> = Vec::new();
            let mut section = 0u8;
            for line in cdl.lines() {
                if line.starts_with("dimensions:") {
                    section = 1;
                } else if line.starts_with("variables:") {
                    section = 2;
                } else if line.starts_with("data:") {
                    section = 0;
                } else if section == 1 {
                    oracle.push(line.split('=').next().unwrap_or("").trim().to_string());
                } else if section == 2 && !line.starts_with("\t\t") && !line.starts_with("//") {
                    // A declaration is indented once; an attribute of
                    // the variable above it is indented twice, and the
                    // global attributes are under a comment.
                    let decl = line.trim().split(';').next().unwrap_or("").trim();
                    let head = decl.split('(').next().unwrap_or("").trim();
                    if let Some(name) = head.split_whitespace().last() {
                        oracle.push(name.to_string());
                    }
                }
            }
            assert_eq!(names.len(), oracle.len(), "{s}");
            for name in &oracle {
                assert!(
                    names.contains(&name.as_str()),
                    "the reader does not report {name}"
                );
            }
            // The harvested strings are gone: the real names are in.
            assert!(!s.contains("name: OHDR"), "{s}");
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn the_hdf5_files_that_keep_their_names_in_a_continuation_chunk_are_read() {
            // These two keep their names as link messages that live in a
            // continuation chunk of the object header, which the reader
            // used to skip. It reported the printable strings it could
            // see instead, and those were guesses.
            let rover = hdf5_text("netcdf4-irish-rover.nc");
            assert!(rover.starts_with("hdf5 superblock"), "{rover}");
            for line in [
                "link: cargo: committed datatype: enum",
                "link: dim: dimension scale: float32 dims=[4]",
                "link: in_the_hold_of_the_Irish_Rover: dataset: enum dims=[4]",
            ] {
                assert!(rover.contains(line), "{line}\n{rover}");
            }
            // The harvested strings are gone: the real names are in.
            assert!(!rover.contains("name: OHDR"), "{rover}");

            let prov = hdf5_text("netcdf4-provenance.nc");
            assert!(prov.starts_with("hdf5 superblock"), "{prov}");
            for line in [
                "link: subgroup: group",
                "link: int_var: dataset: int32 dims=[]",
                "link: time: dimension scale: int32 dims=[4]",
            ] {
                assert!(prov.contains(line), "{line}\n{prov}");
            }
            assert!(!prov.contains("name: OHDR"), "{prov}");
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn a_truncated_fractal_heap_file_is_refused_with_a_reason() {
            let path = hdf5_fixture("netcdf4-fractal-heap.nc");
            let data = std::fs::read(&path).unwrap_or_else(|e| panic!("{e}"));
            // The file keeps its heap past this point, so cutting here
            // leaves a superblock with nothing behind it.
            let cut = &data[..0x1000];
            let Err(err) = Hdf5.extract(cut, "cut.nc") else {
                panic!("a truncated file was accepted");
            };
            assert!(
                !err.is_decline(),
                "a truncated file is a failure, not a decline"
            );
            assert!(
                err.to_string().contains("hdf5:"),
                "the refusal says why: {err}"
            );
        }

        #[test]
        #[cfg(feature = "hdf5")]
        fn hdf5_fixtures_never_panic_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    (
                        "fractal-heap",
                        std::fs::read(hdf5_fixture("netcdf4-fractal-heap.nc")).unwrap(),
                    ),
                    (
                        "irish-rover",
                        std::fs::read(hdf5_fixture("netcdf4-irish-rover.nc")).unwrap(),
                    ),
                ],
                200,
                "hdf5-fixtures",
                |data| {
                    let _ = Hdf5.extract(data, "fuzz.nc");
                },
            );
        }

        /// The netCDF and CDF fixtures, in the crate's own testdata.
        #[cfg(feature = "netcdf3")]
        fn nc_fixture(name: &str) -> std::path::PathBuf {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("testdata")
                .join("nc")
                .join(name)
        }

        #[cfg(feature = "netcdf3")]
        fn nc_read(name: &str) -> Vec<u8> {
            std::fs::read(nc_fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
        }

        /// What the adapter makes of a fixture.
        #[cfg(feature = "netcdf3")]
        fn nc_text(name: &str) -> String {
            let data = nc_read(name);
            let out = NetCdf3
                .extract(&data, name)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let Outcome::Text(t) = out else {
                panic!("{name}: not text")
            };
            String::from_utf8(t).unwrap_or_else(|e| panic!("{name}: {e}"))
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn netcdf_reads_every_variable_in_both_layouts() {
            // The two files hold the same test CDF in the two netCDF
            // layouts, so the variable list has to read the same in both.
            // It used to stop at the first variable: the reader stepped
            // four bytes past the end of every variable record, and the
            // next name was read from the wrong place.
            let classic = nc_text("nctest-classic.nc");
            let wide = nc_text("nctest-64bit-offset.nc");
            assert!(
                classic.starts_with("CDF version 1 (netCDF classic layout), file size 43584"),
                "{classic}"
            );
            assert!(
                wide.starts_with("CDF version 2 (netCDF 64-bit offset layout), file size 43696"),
                "{wide}"
            );
            for line in [
                "dim ii = 4",
                "global@title = ",
                "global@att5 = [4.5, 5.5, 6.5, 7.5]",
                "aa@units = ",
                "var aa: int dims=[0]",
                "var bb: int dims=[2, 1]",
                "var bytev: byte dims=[12, 13, 14, 15, 16, 17]",
                "var doublevar: double dims=[18, 19, 20, 21]",
                "var scalarv: double dims=[]",
                "yet_another_variable@yet_another_attribute = [-1, -2, -3]",
            ] {
                assert!(classic.contains(line), "classic: {line}\n{classic}");
                assert!(wide.contains(line), "64-bit offset: {line}\n{wide}");
            }
            // Same file, same variables: the two layouts must describe
            // them the same way.
            let vars = |s: &str| -> String {
                s.lines()
                    .filter(|l| l.starts_with("var "))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            assert_eq!(vars(&classic), vars(&wide));
        }

        /// The netCDF classic fixture that carries the oracle, in the
        /// crate's own testdata.
        #[cfg(feature = "netcdf3")]
        fn classic_fixture(name: &str) -> std::path::PathBuf {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("testdata")
                .join(name)
        }

        #[cfg(feature = "netcdf3")]
        fn classic_read(name: &str) -> Vec<u8> {
            std::fs::read(classic_fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
        }

        /// What the reader makes of a netCDF classic fixture.
        #[cfg(feature = "netcdf3")]
        fn classic_text(name: &str) -> String {
            let data = classic_read(name);
            let out = NetCdf3
                .extract(&data, name)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let Outcome::Text(t) = out else {
                panic!("{name}: not text")
            };
            String::from_utf8(t).unwrap_or_else(|e| panic!("{name}: {e}"))
        }

        /// The values the reader gives, as the path that locates them
        /// and the value itself.
        #[cfg(feature = "netcdf3")]
        fn values_by_path(text: &str) -> BTreeMap<String, String> {
            text.lines()
                .filter_map(|l| l.strip_prefix("value "))
                .filter_map(|l| l.split_once(" = "))
                .map(|(path, value)| (path.to_string(), value.to_string()))
                .collect()
        }

        /// The date a day number names, in the 360-day calendar the file
        /// declares: twelve months of thirty days, so a year is 360 days
        /// and not 365.
        #[cfg(feature = "netcdf3")]
        fn day_in_the_360_day_calendar(day: u32) -> String {
            let year = 1900 + day / 360;
            let rest = day % 360;
            format!("{year:04}-{:02}-{:02}", rest / 30 + 1, rest % 30 + 1)
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn the_values_of_a_netcdf_file_are_the_ones_the_oracle_gives() {
            // The oracle is the `ncdump` output the netCDF library ships
            // for exactly this file, `ncdump/ref_test_360_day_1900.cdl`.
            // It renders the `time` variable with the units and the
            // calendar the file itself declares, so the value at index
            // i is the date i days after 1900-01-01.
            let cdl = std::fs::read_to_string(classic_fixture("netcdf3-360-day.cdl"))
                .unwrap_or_else(|e| panic!("the oracle: {e}"));
            let mut dates = Vec::new();
            for line in cdl.lines().skip_while(|l| !l.contains("data:")) {
                for part in line.split('"').skip(1).step_by(2) {
                    if part.len() == 10 && part.as_bytes()[4] == b'-' {
                        dates.push(part.to_string());
                    }
                }
            }
            assert_eq!(dates.len(), 2300, "the oracle lists every date");
            let text = classic_text("netcdf3-360-day.nc");
            let values = values_by_path(&text);
            assert_eq!(values.len(), 2300, "the reader gives every value");
            for (index, date) in dates.iter().enumerate() {
                let path = format!("time[{index}]");
                let value = values.get(&path).unwrap_or_else(|| panic!("{path}"));
                let day: u32 = value.parse().unwrap_or_else(|_| panic!("{value}"));
                assert_eq!(
                    &day_in_the_360_day_calendar(day),
                    date,
                    "the value at {path}"
                );
            }
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn the_values_of_a_record_variable_come_from_its_own_records() {
            // A record variable is spread through the records: a record
            // holds one element of every record variable, in the order
            // the file lists them, so the distance between two records
            // is the size of a whole record. The oracle is the file's
            // own header, which says where each record variable starts
            // and how big one record of it is -- and the last record of
            // the file ends at its last byte.
            let classic = nc_text("nctest-classic.nc");
            let wide = nc_text("nctest-64bit-offset.nc");
            for text in [&classic, &wide] {
                // `cc` is an int with one element per record, `cd` a
                // short with three, `ce` a float with twenty-one.
                for line in [
                    "value cc[0] = -1",
                    "value cc[1] = 0",
                    "value cc[2] = 0",
                    "value cc[3] = 1",
                    "value cc[4] = 0",
                    "value cd[0][0] = -4",
                    "value cd[0][1] = -3",
                    "value cd[0][2] = -2",
                    "value cd[1][0] = -1",
                    "value cd[1][1] = 0",
                    "value cd[1][2] = 1",
                    "value cd[3][0] = 2",
                    "value cd[3][1] = 3",
                    "value cd[3][2] = 4",
                    "value ce[0][0][0] = 1",
                    "value ce[0][2][6] = 21",
                    "value ce[2][0][0] = 43",
                    "value ce[4][0][0] = 85",
                ] {
                    assert!(text.contains(line), "{line}\n{text}");
                }
            }
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn the_two_netcdf_layouts_read_the_same_values() {
            // The two files are the same test CDF in the two layouts the
            // netCDF library writes, so every value has to come out the
            // same in both: the header of the 64-bit offset one is
            // wider, and its data starts further into the file.
            let classic = nc_text("nctest-classic.nc");
            let wide = nc_text("nctest-64bit-offset.nc");
            let values = |s: &str| -> Vec<String> {
                s.lines()
                    .filter(|l| l.starts_with("value "))
                    .map(str::to_string)
                    .collect()
            };
            let a = values(&classic);
            assert_eq!(a.len(), 27_346);
            assert_eq!(a, values(&wide));
        }

        /// Push one variable into a netCDF classic header, and keep
        /// where its `begin` word is, so the offset can be patched once
        /// the size of the header is known.
        #[cfg(feature = "netcdf3")]
        fn nc_push_var(
            d: &mut Vec<u8>,
            begins: &mut Vec<usize>,
            data: &mut Vec<Vec<u8>>,
            name: &[u8],
            ty: u32,
            values: &[u8],
        ) {
            be(d, name.len() as u32);
            d.extend_from_slice(name);
            // the name is padded to a four-byte boundary
            let pad = (4 - name.len() % 4) % 4;
            d.resize(d.len() + pad, 0);
            be(d, 1); // one dimension
            be(d, 0); // the dimension
            be(d, 0); // no attributes: the list is absent, two zero words
            be(d, 0);
            be(d, ty);
            be(d, values.len() as u32); // the size of the data
            begins.push(d.len());
            be(d, 0); // the offset of the data, patched below
            data.push(values.to_vec());
        }

        /// A netCDF classic file with one variable of each type the
        /// header can name.
        #[cfg(feature = "netcdf3")]
        fn netcdf_types() -> Vec<u8> {
            let mut d = b"CDF\x01".to_vec();
            be(&mut d, 0); // numrecs
            be(&mut d, 0x0A); // the dim list
            be(&mut d, 1); // one dimension
            be(&mut d, 4);
            d.extend_from_slice(b"slot");
            be(&mut d, 3); // three elements
            be(&mut d, 0x0C); // the global attributes
            be(&mut d, 0);
            be(&mut d, 0x0B); // the var list
            be(&mut d, 6); // six variables
            let mut begins = Vec::new();
            let mut data: Vec<Vec<u8>> = Vec::new();
            nc_push_var(&mut d, &mut begins, &mut data, b"b", 1, &[0xFF, 0x01, 0x80]);
            nc_push_var(
                &mut d,
                &mut begins,
                &mut data,
                b"ub",
                7,
                &[0xFF, 0x01, 0x80],
            );
            nc_push_var(
                &mut d,
                &mut begins,
                &mut data,
                b"us",
                8,
                &[0xFF, 0xFF, 0x00, 0x01, 0x80, 0x00],
            );
            nc_push_var(
                &mut d,
                &mut begins,
                &mut data,
                b"ui",
                9,
                &[
                    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00,
                ],
            );
            nc_push_var(
                &mut d,
                &mut begins,
                &mut data,
                b"i64",
                10,
                &[
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            );
            nc_push_var(&mut d, &mut begins, &mut data, b"u64", 11, &[0xFFu8; 24]);
            // The data of every variable follows the header, in the
            // order the file lists the variables.
            let mut at = d.len() as u32;
            for (i, values) in data.iter().enumerate() {
                d[begins[i]..begins[i] + 4].copy_from_slice(&at.to_be_bytes());
                at += values.len() as u32;
            }
            for values in &data {
                d.extend_from_slice(values);
            }
            d
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn every_type_the_header_can_name_is_read_with_its_own_width_and_sign() {
            // The types without a sign came with netCDF-3, which is the
            // same file layout, and the reader used to read them with
            // the width of the byte -- and a byte with a sign was read
            // without one.
            let d = netcdf_types();
            let out = NetCdf3.extract(&d, "types.nc").unwrap();
            let Outcome::Text(t) = out else {
                panic!("text")
            };
            let s = String::from_utf8(t).unwrap();
            for line in [
                "var b: byte dims=[0]",
                "var ub: ubyte dims=[0]",
                "var us: ushort dims=[0]",
                "var ui: uint dims=[0]",
                "var i64: int64 dims=[0]",
                "var u64: uint64 dims=[0]",
                "value b[0] = -1",
                "value b[1] = 1",
                "value b[2] = -128",
                "value ub[0] = 255",
                "value ub[1] = 1",
                "value ub[2] = 128",
                "value us[0] = 65535",
                "value us[1] = 1",
                "value us[2] = 32768",
                "value ui[0] = 4294967295",
                "value ui[1] = 1",
                "value ui[2] = 2147483648",
                "value i64[0] = -1",
                "value i64[1] = 1",
                "value i64[2] = -9223372036854775808",
                "value u64[0] = 18446744073709551615",
                "value u64[1] = 18446744073709551615",
                "value u64[2] = 18446744073709551615",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn a_variable_shorter_than_its_shape_says_is_reported_as_such() {
            // The header says the variable holds ten elements and the
            // file has two of them: the reader gives the two it has and
            // says how many the shape promised.
            let mut d = b"CDF\x01".to_vec();
            be(&mut d, 0); // numrecs
            be(&mut d, 0x0A); // the dim list
            be(&mut d, 1); // one dimension
            be(&mut d, 4);
            d.extend_from_slice(b"slot");
            be(&mut d, 10); // ten elements
            be(&mut d, 0x0C); // the global attributes
            be(&mut d, 0);
            be(&mut d, 0x0B); // the var list
            be(&mut d, 1); // one variable
            be(&mut d, 1); // the name
            d.extend_from_slice(b"v");
            d.resize(d.len() + 3, 0); // the name is padded to a four-byte boundary
            be(&mut d, 1); // one dimension
            be(&mut d, 0); // the dimension
            be(&mut d, 0); // no attributes: the list is absent, two zero words
            be(&mut d, 0);
            be(&mut d, 4); // an int
            be(&mut d, 8); // two elements of data
            let begin = d.len() as u32 + 4; // the data follows the offset word
            be(&mut d, begin); // the offset of the data
            d.extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 8]); // two ints
            let out = NetCdf3.extract(&d, "short.nc").unwrap();
            let Outcome::Text(t) = out else {
                panic!("text")
            };
            let s = String::from_utf8(t).unwrap();
            assert!(s.contains("value v[0] = 7"), "{s}");
            assert!(s.contains("value v[1] = 8"), "{s}");
            assert!(s.contains("truncated: v holds 2 of 10"), "{s}");
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn a_streaming_netcdf_file_is_read_with_the_records_it_holds() {
            // A streaming file says the count of its records is
            // indeterminate: the header is the one the reader walks all
            // the same, and the records are counted from the length of
            // the file. This one holds no record variable, so it holds
            // no records.
            let mut d = b"CDF\x01".to_vec();
            be(&mut d, 0xFFFF_FFFF); // numrecs: the streaming marker
            be(&mut d, 0x0A); // the dim list
            be(&mut d, 0);
            be(&mut d, 0x0C); // the global attributes
            be(&mut d, 0);
            be(&mut d, 0x0B); // the var list
            be(&mut d, 0);
            let out = NetCdf3.extract(&d, "stream.nc").unwrap();
            let Outcome::Text(t) = out else {
                panic!("text")
            };
            let s = String::from_utf8(t).unwrap();
            assert!(
                s.starts_with("CDF version 1 (netCDF classic layout, streaming), file size 32"),
                "{s}"
            );
            assert!(
                s.contains("streaming: 0 records, counted from the length of the file"),
                "{s}"
            );
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn a_streaming_netcdf_file_holds_the_records_the_file_it_comes_from_holds() {
            // The fixture is the netCDF library's own `nctest-classic.nc`
            // with the count of the records set to the streaming marker.
            // The specification says of the marker that the count in the
            // header is not updated as the records are added, so these
            // are the bytes a streaming writer leaves behind: every
            // value has to come out the way the file the marker was put
            // into gives it.
            let streaming = nc_text("nctest-classic-streaming.nc");
            let classic = nc_text("nctest-classic.nc");
            assert!(
                streaming.starts_with(
                    "CDF version 1 (netCDF classic layout, streaming), file size 43584"
                ),
                "{streaming}"
            );
            assert!(
                streaming.contains("streaming: 5 records, counted from the length of the file"),
                "{streaming}"
            );
            for line in [
                "value cc[0] = -1",
                "value cc[4] = 0",
                "value cd[3][2] = 4",
                "value ce[4][0][0] = 85",
            ] {
                assert!(streaming.contains(line), "{line}\n{streaming}");
            }
            let values = |s: &str| -> Vec<String> {
                s.lines()
                    .filter(|l| l.starts_with("value "))
                    .map(str::to_string)
                    .collect()
            };
            let a = values(&streaming);
            assert_eq!(a.len(), 27_346);
            assert_eq!(a, values(&classic));
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn a_streaming_file_with_one_byte_record_variable_is_refused() {
            // The specification's exception: a file with a single record
            // variable of type byte, char or short keeps its records
            // unpadded, and a reader is to ignore the `vsize` there. This
            // reader walks the record size as the sum of the `vsize`s,
            // so the count it would make is not the count the file has:
            // the file is refused by name.
            let mut d = b"CDF\x01".to_vec();
            be(&mut d, 0xFFFF_FFFF); // numrecs: the streaming marker
            be(&mut d, 0x0A); // the dim list
            be(&mut d, 1); // one dimension
            be(&mut d, 3); // the name has three characters
            d.extend_from_slice(b"rec");
            d.resize(d.len() + 1, 0); // the name is padded to a four-byte boundary
            be(&mut d, 0); // the record dimension is stored as zero
            be(&mut d, 0x0C); // the global attributes
            be(&mut d, 0);
            be(&mut d, 0x0B); // the var list
            be(&mut d, 1); // one variable
            be(&mut d, 1); // the name
            d.extend_from_slice(b"v");
            d.resize(d.len() + 3, 0); // the name is padded to a four-byte boundary
            be(&mut d, 1); // one dimension
            be(&mut d, 0); // the dimension
            be(&mut d, 0); // no attributes: the list is absent, two zero words
            be(&mut d, 0);
            be(&mut d, 1); // a byte
            be(&mut d, 4); // the size of a record, padded as a writer stores it
            let begin = d.len() as u32 + 4;
            be(&mut d, begin); // the offset of the data
            d.extend_from_slice(&[1, 2, 3, 4, 5, 6]); // two records of three bytes
            let Err(err) = NetCdf3.extract(&d, "unpadded.nc") else {
                panic!("a streaming file with unpadded records is refused");
            };
            assert!(!err.is_decline(), "{err}");
            assert!(err.to_string().contains("unpadded"), "{err}");
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn cdf3_reads_the_descriptor_of_a_nasa_cdf3() {
            let s = nc_text("test_alltypes.cdf");
            assert!(
                s.starts_with("CDF version 3.8 (NASA CDF-3 layout), file size 117066"),
                "{s}"
            );
            for line in [
                "global@Project = \"Using the CDFJava API\"",
                "global@PI = \"Ernie Els\"",
                "global@Test = [5.3432]",
                "Longitude@validmin = [-10]",
                "Latitude@VALIDMAX = [90]",
                "newI8@validmin = [-12345678900]",
                "var Latitude: int8 dims=[3]",
                "var Longitude: int16 dims=[3]",
                "var Delta: int32 dims=[3, 2]",
                "var Temperature: float32 dims=[]",
                "var newI8: int64 dims=[2]",
                "var ep: epoch dims=[]",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn cdf3_reads_the_values_of_its_variables() {
            // The values the CDF library's own reader gives for the
            // file: `Latitude` holds 1, 2 and 3, and `Delta` a ramp of
            // numbers.
            let s = nc_text("test_alltypes.cdf");
            for line in [
                "value Latitude[0][0] = 1",
                "value Latitude[0][1] = 2",
                "value Latitude[0][2] = 3",
                "value Delta[0][0][0] = 110",
                "value Delta[0][0][1] = 210",
                "value Delta[0][2][1] = 610",
                "value Temperature[0] = 55.55",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn cdf3_says_which_values_it_could_not_read() {
            // The data of some variables is compressed, some records
            // are sparse, and the epoch types carry an encoding of their
            // own: the reader says which is which instead of reading
            // the wrong bytes.
            let s = nc_text("test_alltypes.cdf");
            for line in [
                "truncated: Longitude: the data is compressed",
                "truncated: ep: the type carries an encoding of its own",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn cdf3_reads_a_compressed_descriptor() {
            // This file's whole descriptor is behind a CCR record, packed
            // with the CDF library's run-length encoding.
            let s = nc_text("fa_esa_l2_eeb_00000000_v01.cdf");
            assert!(
                s.starts_with(
                    "CDF version 3.8 (NASA CDF-3 layout, compressed descriptor), file size 67164"
                ),
                "{s}"
            );
            assert!(s.contains("var epoch: epoch dims=[]"), "{s}");
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn cdf3_reads_a_big_endian_descriptor() {
            // The PSP file is written with the network encoding, so its
            // numbers are big endian; the CDFJava one is little endian.
            // Both have to come out the same way.
            let s = nc_text("psp_fld_l2_mag_rtn_1min_20200104_v02.cdf");
            assert!(
                s.starts_with("CDF version 3.7 (NASA CDF-3 layout), file size 70003"),
                "{s}"
            );
            assert!(s.contains("global@Project = \"PSP\""), "{s}");
            assert!(s.contains("var epoch_mag_RTN_1min: tt2000 dims=[]"), "{s}");
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn the_nasa_cdf2_descriptor_is_read() {
            // `CD F2 60 02` is NASA's CDF-2: the same CDF library, its own
            // descriptor, and not a netCDF file. The oracle is the
            // `cdflib` reader in the corpus: `CDF(path).cdf_info()` gives
            // the version 2.7.2 and the twenty zVariables, and
            // `varget(name)` gives the values.
            let s = nc_text("de2_ion2s_rpa_19830213_v01.cdf");
            assert!(
                s.starts_with("CDF version 2.7 (NASA CDF-2 layout), file size 125566"),
                "{s}"
            );
            for line in [
                "global@TITLE = \"DE-2 RPA 2-sec Plasma Densities and Temperatures in ASCII\"",
                "global@Logical_source = \"de2_ion2s_rpa\"",
                "global@Logical_file_id = \"de2_ion2s_rpa_00000000_v01\"",
                "var Epoch: epoch dims=[]",
                "var dataQuality: int32 dims=[]",
                "var ionTemperature: float32 dims=[]",
                "var alt: float32 dims=[]",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn the_nasa_cdf2_values_are_the_ones_the_oracle_gives() {
            // The values `cdflib` gives for the file: `varget("Status__CL_SP_EDI")`
            // starts with 255 and then six zeros, `varget("L_gse_xyz")` holds
            // the three axis names, and the half interval is 30000 seconds.
            let s = nc_text("cl_sp_edi_00000000_v01.cdf");
            assert!(
                s.starts_with("CDF version 2.7 (NASA CDF-2 layout), file size 19099"),
                "{s}"
            );
            for line in [
                "global@TITLE = \"Electron Drift Velocity>1-min averages\"",
                "global@Project = \"STSP Cluster>Solar Terrestrial Science Programme, Cluster\"",
                "var L_gse_xyz: char dims=[3]",
                "var Half_interval__CL_SP_EDI: float64 dims=[]",
                "var Status__CL_SP_EDI: uint8 dims=[7]",
                "value Half_interval__CL_SP_EDI[0] = 30000",
                "value Status__CL_SP_EDI[0][0] = 255",
                "value Status__CL_SP_EDI[0][1] = 0",
                "value L_gse_xyz[0][0] = x (GSE)",
                "value L_gse_xyz[0][2] = z (GSE)",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
            // The whole of what the oracle reports for this file: 21
            // values, the three of them in `L_gse_xyz` included.
            let reported = s.lines().filter(|l| l.starts_with("value ")).count();
            assert_eq!(reported, 21, "{s}");
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn a_cdf2_file_whose_data_is_compressed_says_so() {
            // The DE-2 file holds its data in compressed blocks, and a
            // compressed block is not decompressed here -- the CDF-3
            // reader says the same of its own compressed variables.
            let s = nc_text("de2_ion2s_rpa_19830213_v01.cdf");
            assert!(
                s.contains("truncated: dataQuality: the data is compressed, and this reader does not decompress it"),
                "{s}"
            );
            // The epoch type carries an encoding of its own, and the
            // reader says so instead of reading the wrong bytes.
            assert!(
                s.contains("truncated: Epoch: the type carries an encoding of its own"),
                "{s}"
            );
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn the_nasa_cdf1_descriptor_is_read() {
            // `00 00 FF FF` is the magic of a pre-V2.6 CDF: the same
            // chain of internal records as a CDF-3, with the record
            // sizes and the offsets inside them in 32 bits. The oracle
            // is the `cdflib` reader in the corpus: `cdf_info()` gives
            // the version 2.4.6 and the twenty-five record variables.
            let s = nc_text("ge_k0_cpi_19921231_v02.cdf");
            assert!(
                s.starts_with("CDF version 2.4 (NASA CDF-1 layout), file size 148480"),
                "{s}"
            );
            for line in [
                "global@TITLE = \"Geotail CPI\"",
                "global@ADID_ref = \"NSSD0091\"",
                "global@Logical_file_id = \"GE_K0_CPI_19921231_V02\"",
                "var Epoch: epoch dims=[]",
                "var SW_P_Den: float32 dims=[]",
                // A dimension whose variance is FALSE is virtual: the file
                // stores three values of the record, not six.
                "var Time_PB5: int32 dims=[3]",
                "var SW_V: float32 dims=[3]",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn the_nasa_cdf1_values_are_the_ones_the_oracle_gives() {
            // The values `cdflib` gives for the file: `varget("SW_P_Den")`
            // starts with 11.244948, and `varget("Time_PB5")` with the
            // year, the day of the year and the millisecond of the day.
            let s = nc_text("ge_k0_cpi_19921231_v02.cdf");
            for line in [
                "value SW_P_Den[0] = 11.244948",
                "value SW_P_AVGE[0] = 864.8506",
                "value Quality_SW[0] = 0",
                "value Time_PB5[0][0] = 1992",
                "value Time_PB5[0][1] = 366",
                "value Time_PB5[0][2] = 5326872",
                "value SW_V[0][0] = -399.11932",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
            // Every value of the file, and not a sample of them: the
            // oracle reports 23 999 values for these variables -- the
            // `Epoch` one, whose 1 090 values the reader declines, is the
            // rest of what the oracle has -- and the reader has to report
            // the same number, or it has dropped or invented one.
            let reported = s.lines().filter(|l| l.starts_with("value ")).count();
            assert_eq!(reported, 23_999, "{s}");
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn the_netcdf_cdf5_layout_is_read() {
            // `CDF\x05` is the netCDF library's own CDF-5: the classic
            // model with a 64-bit data section and 64-bit counts in the
            // header. The fixture is the `od -c` dump the CDF-5
            // specification prints of its own `tiny.nc`, transcribed
            // byte for byte, and the values are the ones the dump shows:
            // the `tiny.cdl` beside it says `vx = 3, 1, 4, 1, 5`.
            let s = nc_text("tiny-cdf5.nc");
            assert!(
                s.starts_with("CDF version 5 (netCDF CDF-5 layout), file size 140"),
                "{s}"
            );
            for line in [
                "dim dim = 5",
                "var vx: short dims=[0]",
                "value vx[0] = 3",
                "value vx[1] = 1",
                "value vx[2] = 4",
                "value vx[3] = 1",
                "value vx[4] = 5",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
        }

        /// A 64-bit word, big endian: the width of every count and every
        /// length in a CDF-5 header.
        #[cfg(feature = "netcdf3")]
        fn be64v(v: &mut Vec<u8>, x: u64) {
            v.extend_from_slice(&x.to_be_bytes());
        }

        /// Push one variable into a CDF-5 header, and keep where its
        /// `begin` word is, so the offset can be patched once the size of
        /// the header is known.
        #[cfg(feature = "netcdf3")]
        fn nc5_push_var(
            d: &mut Vec<u8>,
            begins: &mut Vec<usize>,
            data: &mut Vec<Vec<u8>>,
            name: &[u8],
            ty: u32,
            values: &[u8],
        ) {
            be64v(d, name.len() as u64);
            d.extend_from_slice(name);
            // the name is padded to a four-byte boundary
            let pad = (4 - name.len() % 4) % 4;
            d.resize(d.len() + pad, 0);
            be64v(d, 1); // one dimension
            be64v(d, 0); // the dimension
                         // no attributes: the list is absent, a zero word and a zero
                         // 64-bit word
            be(d, 0);
            be64v(d, 0);
            be(d, ty);
            be64v(d, values.len() as u64); // the size of the data
            begins.push(d.len());
            be64v(d, 0); // the offset of the data, patched below
            data.push(values.to_vec());
        }

        /// A CDF-5 file with one variable of each of the five types the
        /// layout added.
        #[cfg(feature = "netcdf3")]
        fn netcdf5_types() -> Vec<u8> {
            let mut d = b"CDF\x05".to_vec();
            be64v(&mut d, 0); // numrecs
            be(&mut d, 0x0A); // the dim list
            be64v(&mut d, 1); // one dimension
            be64v(&mut d, 4);
            d.extend_from_slice(b"slot");
            be64v(&mut d, 3); // three elements
            be(&mut d, 0x0C); // the global attributes
            be64v(&mut d, 0); // none of them
            be(&mut d, 0x0B); // the var list
            be64v(&mut d, 5); // five variables
            let mut begins = Vec::new();
            let mut data: Vec<Vec<u8>> = Vec::new();
            nc5_push_var(
                &mut d,
                &mut begins,
                &mut data,
                b"ub",
                7,
                &[0xFF, 0x01, 0x80],
            );
            nc5_push_var(
                &mut d,
                &mut begins,
                &mut data,
                b"us",
                8,
                &[0xFF, 0xFF, 0x00, 0x01, 0x80, 0x00],
            );
            nc5_push_var(
                &mut d,
                &mut begins,
                &mut data,
                b"ui",
                9,
                &[
                    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00,
                ],
            );
            nc5_push_var(
                &mut d,
                &mut begins,
                &mut data,
                b"i64",
                10,
                &[
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            );
            nc5_push_var(&mut d, &mut begins, &mut data, b"u64", 11, &[0xFFu8; 24]);
            // The data of every variable follows the header, in the
            // order the file lists the variables.
            let mut at = d.len() as u64;
            for (i, values) in data.iter().enumerate() {
                d[begins[i]..begins[i] + 8].copy_from_slice(&at.to_be_bytes());
                at += values.len() as u64;
            }
            for values in &data {
                d.extend_from_slice(values);
            }
            d
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn the_five_types_cdf5_added_are_read_with_their_own_width_and_sign() {
            // The types CDF-5 added: an unsigned byte, an unsigned short,
            // an unsigned int, a signed 64-bit int and an unsigned 64-bit
            // one. The `NC_INT64` tag is ten, which in CDF-1 named the
            // dimension list -- a tag means what the place it sits in
            // says it means.
            let d = netcdf5_types();
            let out = NetCdf3.extract(&d, "types5.nc").unwrap();
            let Outcome::Text(t) = out else {
                panic!("text")
            };
            let s = String::from_utf8(t).unwrap();
            for line in [
                "var ub: ubyte dims=[0]",
                "var us: ushort dims=[0]",
                "var ui: uint dims=[0]",
                "var i64: int64 dims=[0]",
                "var u64: uint64 dims=[0]",
                "value ub[0] = 255",
                "value us[0] = 65535",
                "value ui[0] = 4294967295",
                "value i64[0] = -1",
                "value u64[0] = 18446744073709551615",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn a_streaming_cdf5_file_is_refused() {
            // The streaming marker of CDF-5 is eight bytes of 0xFF, where
            // CDF-1 and CDF-2 use four. The CDF-5 layout keeps the
            // reading it has: a file that claims the marker is refused
            // by name.
            let mut d = b"CDF\x05".to_vec();
            be64v(&mut d, u64::MAX); // numrecs
            be(&mut d, 0x0A); // the dim list
            be64v(&mut d, 0);
            let Err(err) = NetCdf3.extract(&d, "stream5.nc") else {
                panic!("a streaming file is not the CDF-5 layout");
            };
            assert!(!err.is_decline(), "{err}");
            assert!(err.to_string().contains("streaming"), "{err}");
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn the_netcdf_librarys_own_cdf5_file_has_its_header_read() {
            // The netCDF library writes this file to be rejected: its
            // `begin` offsets point past the end of the file, and its
            // first dimension claims 2^32-1 elements. The header is
            // still a header -- the dimensions and the variables are read
            // -- and the values are not there.
            let s = nc_text("bad_cdf5_begin.nc");
            assert!(
                s.starts_with("CDF version 5 (netCDF CDF-5 layout), file size 220"),
                "{s}"
            );
            for line in [
                "dim dim0 = 4294967295",
                "dim dim1 = 10",
                "var var_big: short dims=[0]",
                "var var_small: short dims=[1]",
                "truncated: var_big holds 0 of 4294967295",
                "truncated: var_small holds 0 of 10",
            ] {
                assert!(s.contains(line), "{line}\n{s}");
            }
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn netcdf_fixtures_never_panic_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("classic", nc_read("nctest-classic.nc")),
                    ("64-bit-offset", nc_read("nctest-64bit-offset.nc")),
                    ("cdf5", nc_read("tiny-cdf5.nc")),
                    // The netCDF library's own broken CDF-5 file: its
                    // `begin` offsets point into the header.
                    ("cdf5-broken", nc_read("bad_cdf5_begin.nc")),
                ],
                200,
                "netcdf-fixtures",
                |data| {
                    let _ = NetCdf3.extract(data, "fuzz.nc");
                },
            );
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn cdf12_fixtures_never_panic_on_mutation() {
            // The CDF-1 file holds 46,000 values, so every read of it is
            // expensive: it gets fewer rounds than the others.
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("cdf1", nc_read("ge_k0_cpi_19921231_v02.cdf")),
                    ("cdf2", nc_read("cl_sp_edi_00000000_v01.cdf")),
                    ("cdf2-compressed", nc_read("de2_ion2s_rpa_19830213_v01.cdf")),
                ],
                30,
                "cdf12-fixtures",
                |data| {
                    let _ = NetCdf3.extract(data, "fuzz.cdf");
                },
            );
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn cdf3_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("magic-only", CDF3_MAGIC.to_vec()),
                    ("packed-magic", {
                        let mut v = CDF3_MAGIC.to_vec();
                        v.extend_from_slice(&CDF3_PACKED.to_be_bytes());
                        v
                    }),
                    ("empty", vec![]),
                ],
                1200,
                "cdf3",
                |data| {
                    let _ = NetCdf3.extract(data, "fuzz.cdf");
                },
            );
        }

        #[test]
        #[cfg(feature = "netcdf3")]
        fn cdf3_fixtures_never_panic_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("alltypes", nc_read("test_alltypes.cdf")),
                    ("packed", nc_read("fa_esa_l2_eeb_00000000_v01.cdf")),
                ],
                200,
                "cdf3-fixtures",
                |data| {
                    let _ = NetCdf3.extract(data, "fuzz.cdf");
                },
            );
        }
    }
}
