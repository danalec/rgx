// SPDX-License-Identifier: Apache-2.0

//! Binary property lists (`bplist00`): the `.icloud` placeholder, macOS
//! preferences, `.mobileconfig` profiles and `.strings` caches.
//!
//! An `.icloud` file is a plist with almost nothing readable in it as bytes —
//! the whole payload is a string, an integer and a data blob. Rendering it
//! as key/value lines is what turns "a 4 KB file rgx skips" into "the name
//! of the file this placeholder stands for".
//!
//! The layout is Apple CoreFoundation's: an 8-byte header, an offset table
//! sized by a field in the *trailer*, and objects addressed by index into
//! that table. The trailer is read first and on purpose — every size in the
//! header is relative to it, so a reader that starts at offset 0 has no idea
//! how large anything is.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use rgx_core::{bail, decline, Adapter, Outcome, Result};

const MAGIC: &[u8; 8] = b"bplist00";
const TRAILER: usize = 32;

/// The top-level object is a dict, a set or an array. Anything else at the
/// root is legal but is not what a placeholder file is, so it is reported
/// rather than rejected.
pub struct BinaryPlist;
impl Adapter for BinaryPlist {
    fn name(&self) -> &'static str {
        "bplist"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["icloud", "bplist", "pref", "plist", "mobileconfig"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let Some(p) = BPlist::parse(data) else {
            decline!("not a binary plist (bad magic)");
        };
        if p.count == 0 {
            bail!("binary plist holds no objects");
        }
        let mut out = String::new();
        let _ = writeln!(
            out,
            "binary plist: {count} objects, {ref_size}-byte refs, {int_size}-byte offsets",
            count = p.count,
            ref_size = p.ref_size,
            int_size = p.offset_size
        );
        p.render(p.top, 0, &mut out);
        Ok(Outcome::Text(out.into_bytes()))
    }
}

struct BPlist<'a> {
    d: &'a [u8],
    offsets: Vec<usize>,
    offset_size: usize,
    ref_size: usize,
    count: usize,
    top: usize,
    depth: usize,
}

/// Objects cannot nest forever; a plist that does is a bomb, not a document.
const MAX_DEPTH: usize = 24;
/// Values printed per container.
const MAX_ITEMS: usize = 512;

impl<'a> BPlist<'a> {
    fn parse(d: &'a [u8]) -> Option<Self> {
        if d.len() < MAGIC.len() + TRAILER || &d[..8] != MAGIC {
            return None;
        }
        // The trailer lives in the LAST 32 bytes, not the first: everything
        // in it is an offset measured from the start of the file, and its
        // own position is only known once the file's length is.
        let t = d.len() - TRAILER;
        let offset_size = *d.get(t + 6)? as usize;
        let ref_size = *d.get(t + 7)? as usize;
        let count = be64(d.get(t + 8..t + 16)?)? as usize;
        let top = be64(d.get(t + 16..t + 24)?)? as usize;
        let table_at = be64(d.get(t + 24..t + 32)?)? as usize;

        // The offset table is `count` entries of `offset_size` bytes. A count
        // that does not fit is corruption, and honouring it would allocate
        // whatever the file asked for.
        if !(1..=8).contains(&offset_size) || !(1..=8).contains(&ref_size) {
            return None;
        }
        let table_end = table_at.checked_add(count.checked_mul(offset_size)?)?;
        if table_end > d.len() {
            return None;
        }
        let mut offsets = Vec::with_capacity(count.min(1 << 20));
        for i in 0..count {
            offsets.push(read_uint(d, table_at + i * offset_size, offset_size)? as usize);
        }
        Some(BPlist {
            d,
            offsets,
            offset_size,
            ref_size,
            count,
            top,
            depth: 0,
        })
    }

    fn obj(&self, index: usize) -> Option<&'a [u8]> {
        let at = *self.offsets.get(index)?;
        self.d.get(at..)
    }

    /// Render object `index` at `depth`. Returning `Option` rather than `()`
    /// is what lets a truncated object stop the walk instead of indexing
    /// past the buffer: a plist is attacker-controlled in every field.
    fn render(&self, index: usize, depth: usize, out: &mut String) -> Option<()> {
        if depth > MAX_DEPTH || self.depth > MAX_ITEMS {
            return Some(());
        }
        let obj = self.obj(index)?;
        // `get(at..)` yields `Some(&[])` when `at == d.len()` -- an offset
        // table entry pointing exactly at the end of the file is a *valid*
        // range that happens to be empty, so `get` cannot reject it and `obj[0]`
        // panicked. `first()` asks the question the range never did: is there
        // a marker here at all.
        let marker = *obj.first()?;
        let kind = marker >> 4;
        let nib = (marker & 0x0F) as usize;
        let inline = 0xF == nib;
        // Everything past the marker. A length nibble of 0xF means "the real
        // length is an int object index", which is how a plist holds anything
        // over 14 bytes.
        let mut rest = obj.get(1..)?;

        // With a 0xF nibble the length is not in the marker: an *integer marker*
        // and its payload follow inline. That is what Apple's parser reads,
        // and it is why the payload is written twice in a real file — once as
        // its own object, once here. Reading it as a reference-table index
        // instead resolves to an unrelated object and prints its bytes as
        // leading garbage on every long string.
        let mut len = nib;
        if inline && kind != 0x0 {
            let (n, after) = inline_int(rest)?;
            len = n;
            rest = after;
        }

        match kind {
            0x0 => {
                let name = match nib {
                    0x0 => "null",
                    0x8 => "false",
                    0x9 => "true",
                    _ => "fill",
                };
                let _ = writeln!(out, "{name}");
            }
            0x1 => {
                let (v, _) = int_from_bytes(rest, len.min(16))?;
                let _ = writeln!(out, "int {v}");
            }
            0x2 => match len {
                4 => {
                    let b = rest.get(..4)?;
                    let _ = writeln!(out, "real {}", f32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                }
                8 => {
                    let b = rest.get(..8)?;
                    let _ = writeln!(
                        out,
                        "real {}",
                        f64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                    );
                }
                _ => {
                    let _ = writeln!(out, "real ({} bytes)", rest.len());
                }
            },
            0x3 => {
                // Seconds since 2001-01-01, as a little-endian double.
                let b = rest.get(..8)?;
                let secs = f64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                let _ = writeln!(out, "date {secs} (2001 epoch seconds)");
            }
            0x4 => {
                let body = rest.get(..len.min(rest.len()))?;
                let _ = writeln!(out, "data {} bytes{}", body.len(), text_prefix(body));
            }
            0x5 => {
                let body = rest.get(..len.min(rest.len()))?;
                let _ = writeln!(out, "{}", String::from_utf8_lossy(body));
            }
            0x6 => {
                // UTF-16BE: the high byte first, which is the byte order that
                // makes a `bplist` look like mojibake to a reader that
                // assumes little-endian.
                let body = rest.get(..len.min(rest.len()))?;
                let units: Vec<u16> = body
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                let _ = writeln!(out, "{}", String::from_utf16_lossy(&units));
            }
            0x8 => {
                let (v, _) = int_from_bytes(rest, len.min(16))?;
                let _ = writeln!(out, "uid {v}");
            }
            0xA | 0xC => {
                let label = if kind == 0xC { "set" } else { "array" };
                let _ = writeln!(out, "{label} ({len} items)");
                self.children(rest, len, depth, out)?;
            }
            0xD => {
                let _ = writeln!(out, "dict ({len} entries)");
                self.children(rest, len, depth, out)?;
            }
            _ => {
                let _ = writeln!(out, "unknown marker {marker:#04x}");
            }
        }
        Some(())
    }

    /// A dict's body is `len` key refs then `len` value refs; every other
    /// container is just `len` refs. Confusing the two is why a naive reader
    /// pairs a key with another key.
    fn children(&self, rest: &'a [u8], len: usize, depth: usize, out: &mut String) -> Option<()> {
        if self.ref_size == 0 || len > self.count || len > 1 << 20 {
            return Some(());
        }
        let keys_end = len.checked_mul(self.ref_size)?;
        let keys = rest.get(..keys_end)?;
        let values = rest.get(keys_end..keys_end.checked_add(keys_end)?)?;
        let pad = "  ".repeat(depth + 1);
        for i in 0..len {
            let kid = read_uint(keys, i * self.ref_size, self.ref_size)? as usize;
            let mut key_line = String::new();
            self.render(kid, depth + 1, &mut key_line);
            let key = key_line.trim_end().to_string();
            let vid = read_uint(values, i * self.ref_size, self.ref_size)? as usize;
            let mut val = String::new();
            self.render(vid, depth + 1, &mut val);
            for line in val.lines() {
                let _ = writeln!(out, "{pad}{key}: {line}");
            }
        }
        Some(())
    }
}

/// The integer that follows an `0x?n` marker with a `0xF` nibble, together
/// with the bytes after it. The first byte is the integer marker, and its
/// width is `1 << (marker & 0x0F)` bytes.
fn inline_int(b: &[u8]) -> Option<(usize, &[u8])> {
    let marker = *b.first()?;
    if marker >> 4 != 0x1 {
        return None;
    }
    let width = 1usize << (marker & 0x0F);
    let (v, _) = int_from_bytes(b.get(1..)?, width)?;
    let n = usize::try_from(v).ok()?;
    Some((n, b.get(1 + width..)?))
}

fn be64(b: &[u8]) -> Option<u64> {
    let s = b.get(..8)?;
    Some(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// A big-endian unsigned integer of `width` bytes, as every plist offset and
/// object reference is.
fn read_uint(d: &[u8], at: usize, width: usize) -> Option<u64> {
    let b = d.get(at..at.checked_add(width)?)?;
    let mut v = 0u64;
    for byte in b {
        v = (v << 8) | *byte as u64;
    }
    Some(v)
}

/// Integers inside objects are little-endian, unlike every offset in the
/// file. Mixing the two is a silent, catastrophic mistake.
fn int_from_bytes(b: &[u8], width: usize) -> Option<(i64, ())> {
    let s = b.get(..width)?;
    let mut v: i64 = if s.first()? & 0x80 != 0 { -1 } else { 0 };
    for byte in s {
        v = (v << 8) | *byte as i64;
    }
    Some((v, ()))
}

/// A data blob is usually a payload, but a short one that is printable is
/// worth a peek — that is where a plist keeps a filename or a MIME type.
fn text_prefix(b: &[u8]) -> String {
    let printable = b
        .iter()
        .filter(|x| (**x as i32) >= 0x20 && (**x as i32) < 0x7f)
        .count();
    if printable * 2 < b.len() {
        return String::new();
    }
    let head = &b[..b.len().min(96)];
    let s = String::from_utf8_lossy(head);
    if s.contains('\n') {
        return String::new();
    }
    alloc::format!(": {s}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Build a bplist with one dict of string values, which is the shape an
    /// `.icloud` placeholder has.
    struct W {
        objects: Vec<Vec<u8>>,
    }

    impl W {
        fn new() -> Self {
            W {
                objects: Vec::new(),
            }
        }
        fn push(&mut self, o: Vec<u8>) -> usize {
            self.objects.push(o);
            self.objects.len() - 1
        }
        fn ascii(&mut self, s: &str) -> usize {
            let mut o = vec![0x50 | (s.len().min(0xF) as u8)];
            o.extend_from_slice(s.as_bytes());
            self.push(o)
        }
        fn long_ascii(&mut self, s: &str) -> usize {
            // 0x5F: the length is not in the marker. Apple's parser reads an
            // *integer marker* plus its payload inline right after it, and
            // the same integer also exists as its own object so other
            // objects can reference it. Both copies are written here, which
            // is what a real file does.
            self.push(vec![0x10u8, s.len() as u8]);
            let mut o = vec![0x5F, 0x10u8];
            o.push(s.len() as u8);
            o.extend_from_slice(s.as_bytes());
            self.push(o)
        }
        fn finish(&self, top: usize) -> Vec<u8> {
            let count = self.objects.len();
            let mut body: Vec<u8> = MAGIC.to_vec();
            let mut table = Vec::new();
            for o in self.objects.iter() {
                // The offset table is written *after* every object, so an
                // object's offset is simply where the body currently ends.
                // Adding the table's own length here would land every entry
                // past its object, which is a plist that parses and prints
                // nonsense.
                let at = body.len();
                table.push(at as u8);
                body.extend_from_slice(o);
            }
            let table_at = body.len();
            body.extend_from_slice(&table);
            // trailer: 5 unused, sortVersion, offsetSize, refSize, then the
            // three big-endian counts. That is 8 + 24 = the 32 bytes the
            // parser slices off the end. Writing six unused bytes instead
            // makes a 33-byte trailer, and the parser would then read every
            // field one byte early -- from the right length but the wrong
            // place, which is how a fixture can pass a test and still
            // describe a file no writer produces.
            let mut t = vec![0u8; 5];
            t.push(0); // sortVersion
            t.push(1); // offsetSize
            t.push(1); // refSize
            t.extend_from_slice(&(count as u64).to_be_bytes());
            t.extend_from_slice(&(top as u64).to_be_bytes());
            t.extend_from_slice(&(table_at as u64).to_be_bytes());
            body.extend_from_slice(&t);
            body
        }
    }

    #[test]
    fn an_icloud_placeholder_renders_as_key_value_lines() {
        let mut w = W::new();
        let k1 = w.ascii("BRWS-Size");
        let v1 = w.ascii("48213");
        let k2 = w.ascii("BRWS-Signature");
        let v2 = w.ascii("9a1f");
        let mut dict = vec![0xD2u8, k1 as u8, k2 as u8, v1 as u8, v2 as u8];
        dict[0] = 0xD2;
        let d = w.push(dict);
        let data = w.finish(d);
        let out = String::from_utf8_lossy(&match BinaryPlist
            .extract(&data, "x.icloud")
            .expect("plist")
        {
            Outcome::Text(t) => t,
            _ => panic!("expected Text"),
        })
        .into_owned();
        assert!(out.contains("BRWS-Size: 48213"), "{out}");
        assert!(out.contains("BRWS-Signature: 9a1f"), "{out}");
    }

    #[test]
    fn a_string_longer_than_fourteen_bytes_follows_its_integer_length() {
        let mut w = W::new();
        let long = "a-very-long-key-that-overflows-the-nibble";
        let k = w.long_ascii(long);
        let v = w.ascii("v");
        let d = w.push(vec![0xD1, k as u8, v as u8]);
        let data = w.finish(d);
        let out = String::from_utf8_lossy(&match BinaryPlist
            .extract(&data, "x.icloud")
            .expect("plist")
        {
            Outcome::Text(t) => t,
            _ => panic!("expected Text"),
        })
        .into_owned();
        assert!(out.contains(long), "{out}");
    }

    #[test]
    fn a_file_that_is_not_a_plist_is_declined() {
        assert!(BinaryPlist
            .extract(b"<?xml version=\"1.0\"?><plist/>", "x.icloud")
            .is_err());
        assert!(BinaryPlist.extract(b"bplist00", "x.icloud").is_err());
    }

    #[test]
    fn an_object_count_that_does_not_fit_the_table_is_refused() {
        let mut w = W::new();
        let k = w.ascii("a");
        let v = w.ascii("b");
        let d = w.push(vec![0xD1, k as u8, v as u8]);
        let mut data = w.finish(d);
        // Claim a billion objects in the trailer: honouring it would allocate
        // a billion offsets before the first read.
        let t = data.len() - TRAILER;
        data[t + 8..t + 16].copy_from_slice(&1_000_000_000u64.to_be_bytes());
        assert!(BinaryPlist.extract(&data, "x.icloud").is_err());
    }
}
