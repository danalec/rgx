// SPDX-License-Identifier: Apache-2.0

//! TAR archives (POSIX.1-2001 ustar, with the pax and GNU extensions
//! that real archives carry).
//!
//! Independent reimplementation of the archive walk the POSIX.1-2001
//! ustar format defines: a sequence of 512-byte header blocks, each
//! followed by its file data padded to a 512-byte boundary, terminated
//! by a zero block. The reader also resolves the two long-path
//! extensions in common use — pax extended headers (`x`/`g` typeflags,
//! records of the form `"<decimal length> <key>=<value>\n"`) and GNU
//! long name/link entries (`L`/`K` typeflags) — because archives that
//! need them are the archives whose paths matter most.
//!
//! # Contract
//!
//! A header's checksum is the unsigned sum of all 512 bytes with the
//! checksum field itself taken as eight spaces. Numeric fields are
//! NUL/space-terminated octal. The ustar path is the `prefix` field
//! (155 bytes at offset 345) joined with `name` (100 bytes at offset 0)
//! by a single `/` whenever the prefix is non-empty — per POSIX the
//! prefix applies regardless of how full `name` is, so a NUL-padded
//! short name with a prefix is a split path, not a short one. Name
//! precedence for the following entry is: pax `path` over GNU `L` over
//! the ustar name/prefix pair; the same ordering applies to `linkpath`
//! and `size`.
//!
//! The zero-block terminator stops the walk; anything after the first
//! zero block is not an entry. Only regular entries carry data.

// The write half and the header fields no rgx consumer reads (mode,
// uid, gid, uname, gname, dev*) are kept so the on-disk struct layout
// and a reader/writer round trip stay complete; they are unused in the
// shipped adapter path.
#![allow(dead_code)]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::budget::Stopped;

pub const TMAGIC: &[u8; 5] = b"ustar";
pub const GNUTMAGIC: &[u8; 7] = b"ustar  ";

const BLOCK_SIZE: usize = 512;

/// ustar field offsets (POSIX.1-2001, Table "ustar Header Block").
const NAME: (usize, usize) = (0, 100);
const MODE: (usize, usize) = (100, 8);
const UID: (usize, usize) = (108, 8);
const GID: (usize, usize) = (116, 8);
const SIZE: (usize, usize) = (124, 12);
const MTIME: (usize, usize) = (136, 12);
const CHECKSUM: (usize, usize) = (148, 8);
const TYPEFLAG: usize = 156;
const LINKNAME: (usize, usize) = (157, 100);
const DEVMAJOR: (usize, usize) = (329, 8);
const DEVMINOR: (usize, usize) = (337, 8);
const PREFIX: (usize, usize) = (345, 155);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarEntryType {
    Regular,
    Link,
    SymbolicLink,
    CharacterDevice,
    BlockDevice,
    Directory,
    Fifo,
    Contiguous,
    GnuLongName,
    GnuLongLink,
    PaxHeader,
    Unknown(u8),
}

impl From<u8> for TarEntryType {
    fn from(value: u8) -> Self {
        match value {
            b'0' | 0 => Self::Regular,
            b'1' => Self::Link,
            b'2' => Self::SymbolicLink,
            b'3' => Self::CharacterDevice,
            b'4' => Self::BlockDevice,
            b'5' => Self::Directory,
            b'6' => Self::Fifo,
            b'7' => Self::Contiguous,
            b'L' => Self::GnuLongName,
            b'K' => Self::GnuLongLink,
            b'x' | b'g' => Self::PaxHeader,
            v => Self::Unknown(v),
        }
    }
}

impl TarEntryType {
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Regular => b'0',
            Self::Link => b'1',
            Self::SymbolicLink => b'2',
            Self::CharacterDevice => b'3',
            Self::BlockDevice => b'4',
            Self::Directory => b'5',
            Self::Fifo => b'6',
            Self::Contiguous => b'7',
            Self::GnuLongName => b'L',
            Self::GnuLongLink => b'K',
            Self::PaxHeader => b'x',
            Self::Unknown(v) => v,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TarHeader {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime: u64,
    pub checksum: u32,
    pub entry_type: TarEntryType,
    pub linkname: String,
    pub uname: String,
    pub gname: String,
    pub devmajor: u32,
    pub devminor: u32,
    pub prefix: String,
}

#[derive(Debug, Clone)]
pub struct TarEntry {
    pub header: TarHeader,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum TarError {
    Truncated,
    InvalidHeader,
    InvalidChecksum,
    InvalidOctal,
    Utf8Error,
    IoError,
}

impl core::fmt::Display for TarError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "Truncated TAR archive"),
            Self::InvalidHeader => write!(f, "Invalid TAR header"),
            Self::InvalidChecksum => write!(f, "Invalid checksum"),
            Self::InvalidOctal => write!(f, "Invalid octal number"),
            Self::Utf8Error => write!(f, "UTF-8 decoding error"),
            Self::IoError => write!(f, "I/O error"),
        }
    }
}

pub type TarResult<T> = Result<T, TarError>;

impl std::error::Error for TarError {}

/// Name/link/size overrides carried by the pax and GNU extension
/// entries seen so far; they apply to the next real entry only.
#[derive(Default)]
struct Pending {
    gnu_name: Option<String>,
    gnu_link: Option<String>,
    pax_path: Option<String>,
    pax_link: Option<String>,
    pax_size: Option<u64>,
}

impl Pending {
    /// pax `path` over GNU `L` over the ustar name/prefix pair.
    fn take_name(&mut self, ustar_name: String) -> String {
        self.pax_path
            .take()
            .or_else(|| self.gnu_name.take())
            .unwrap_or(ustar_name)
    }

    fn take_link(&mut self, ustar_link: String) -> String {
        self.pax_link
            .take()
            .or_else(|| self.gnu_link.take())
            .unwrap_or(ustar_link)
    }
}

pub struct TarReader;

impl TarReader {
    pub fn read_all(data: &[u8]) -> TarResult<Vec<TarEntry>> {
        Ok(Self::read_all_limited(data, usize::MAX, u64::MAX)?.0)
    }

    /// [`Self::read_all`] that stops once `max_members` regular entries or
    /// `max_bytes` of member data have been read, and reports whether it
    /// stopped with entries still unread.
    ///
    /// Only regular members count against the budget: a directory entry
    /// costs a header block and no data, so a tarball of mostly directories
    /// must not be truncated for holding many of them.
    pub fn read_all_limited(
        data: &[u8],
        max_members: usize,
        max_bytes: u64,
    ) -> TarResult<(Vec<TarEntry>, Option<Stopped>)> {
        let mut entries = Vec::new();
        let mut members = 0usize;
        let mut member_bytes = 0u64;
        let mut stopped = None;
        let mut offset = 0usize;
        let mut pending = Pending::default();

        while offset + BLOCK_SIZE <= data.len() {
            let header_block = &data[offset..offset + BLOCK_SIZE];

            // The end-of-archive marker is a zero block; nothing after
            // the first one is an entry.
            if Self::is_zero_block(header_block) {
                break;
            }

            let checksum = Self::parse_octal(field(header_block, CHECKSUM))? as u32;
            let computed = Self::compute_checksum(header_block);
            if checksum != computed {
                return Err(TarError::InvalidChecksum);
            }

            let entry_type = TarEntryType::from(header_block[TYPEFLAG]);
            let size = Self::parse_octal(field(header_block, SIZE))?;
            let body_start = offset + BLOCK_SIZE;
            let data_blocks = (size as usize).div_ceil(BLOCK_SIZE);
            let body_end = body_start + data_blocks * BLOCK_SIZE;

            // Extension entries consume their body and set up an
            // override for the entry that follows; they are never
            // themselves returned.
            match entry_type {
                TarEntryType::GnuLongName => {
                    let name = Self::read_c_string(data, body_start, size)?;
                    pending.gnu_name = Some(name);
                    offset = body_end;
                    continue;
                }
                TarEntryType::GnuLongLink => {
                    let link = Self::read_c_string(data, body_start, size)?;
                    pending.gnu_link = Some(link);
                    offset = body_end;
                    continue;
                }
                TarEntryType::PaxHeader => {
                    let body = Self::read_body(data, body_start, size)?;
                    for (key, value) in Self::parse_pax_records(body) {
                        match key.as_str() {
                            "path" => pending.pax_path = Some(value),
                            "linkpath" => pending.pax_link = Some(value),
                            "size" => pending.pax_size = value.parse::<u64>().ok(),
                            _ => {}
                        }
                    }
                    offset = body_end;
                    continue;
                }
                _ => {}
            }

            // ustar splits a long path across `prefix` and `name`,
            // joined with '/'; the prefix applies whenever it is
            // non-empty, so a NUL-padded short name still joins.
            let ustar_name = Self::join_ustar_name(header_block);
            let name = pending.take_name(ustar_name);
            let linkname = pending.take_link(Self::read_field_string(header_block, LINKNAME));
            let size = pending.pax_size.take().unwrap_or(size);

            let header = TarHeader {
                name,
                mode: Self::parse_octal(field(header_block, MODE))? as u32,
                uid: Self::parse_octal(field(header_block, UID))? as u32,
                gid: Self::parse_octal(field(header_block, GID))? as u32,
                size,
                mtime: Self::parse_octal(field(header_block, MTIME))?,
                checksum,
                entry_type,
                linkname,
                uname: String::new(),
                gname: String::new(),
                devmajor: Self::parse_octal(field(header_block, DEVMAJOR))? as u32,
                devminor: Self::parse_octal(field(header_block, DEVMINOR))? as u32,
                prefix: String::new(),
            };

            // Only regular entries carry member data; the rest advance
            // over their (usually empty) body without copying it.
            let entry_data = if entry_type == TarEntryType::Regular {
                let take = (size as usize).min(data.len().saturating_sub(body_start));
                data[body_start..body_start + take].to_vec()
            } else {
                Vec::new()
            };

            if entry_type == TarEntryType::Regular {
                if members >= max_members || member_bytes + entry_data.len() as u64 > max_bytes {
                    stopped = Some(if members >= max_members {
                        Stopped::MemberCount
                    } else {
                        Stopped::Bytes
                    });
                    break;
                }
                members += 1;
                member_bytes += entry_data.len() as u64;
            }

            entries.push(TarEntry {
                header,
                data: entry_data,
            });
            offset = body_end;
        }

        Ok((entries, stopped))
    }

    /// The ustar path: `prefix`/`name` joined by '/' when the prefix is
    /// non-empty, `name` alone otherwise.
    fn join_ustar_name(header: &[u8]) -> String {
        let name = Self::nul_terminated(field(header, NAME));
        let prefix = Self::nul_terminated(field(header, PREFIX));
        if prefix.is_empty() {
            return name;
        }
        let mut buf = String::with_capacity(prefix.len() + 1 + name.len());
        buf.push_str(&prefix);
        buf.push('/');
        buf.push_str(&name);
        buf
    }

    /// A NUL-terminated string field: bytes up to the first NUL.
    fn nul_terminated(raw: &[u8]) -> String {
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    }

    fn read_field_string(header: &[u8], loc: (usize, usize)) -> String {
        Self::nul_terminated(field(header, loc))
    }

    /// The body of an extension entry as a byte slice, bounds-checked.
    fn read_body(data: &[u8], start: usize, size: u64) -> TarResult<&[u8]> {
        let end = start
            .checked_add(size as usize)
            .filter(|&e| e <= data.len())
            .ok_or(TarError::Truncated)?;
        Ok(&data[start..end])
    }

    /// A GNU `L`/`K` body: the name as a NUL-terminated string.
    fn read_c_string(data: &[u8], start: usize, size: u64) -> TarResult<String> {
        let body = Self::read_body(data, start, size)?;
        Ok(Self::nul_terminated(body))
    }

    /// Parse a PAX extended-header body into `(key, value)` pairs.
    ///
    /// Each record is `"<decimal length> <key>=<value>\n"`, where the
    /// length counts the whole record including its own digits and the
    /// trailing newline. Records are walked by that declared length
    /// rather than split on newlines, so a value containing a newline
    /// is not truncated. Unparseable records are skipped rather than
    /// failing the archive: one malformed key must not cost the caller
    /// every entry.
    fn parse_pax_records(body: &[u8]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < body.len() {
            let Some(sp) = body[pos..].iter().position(|&b| b == b' ') else {
                break;
            };
            let len_str = core::str::from_utf8(&body[pos..pos + sp]).unwrap_or_default();
            let Ok(len) = len_str.trim().parse::<usize>() else {
                break;
            };
            // A declared length can lie in both directions: a huge one
            // wraps `pos + len` past `usize::MAX` and a tiny one leaves
            // the record shorter than its own `<digits> ` prefix. Both
            // end the walk rather than slicing what is not there.
            let Some(end) = pos.checked_add(len) else {
                break;
            };
            if len == 0 || end > body.len() {
                break;
            }
            // Skip "<len> " then take everything up to the final newline.
            let start = pos + sp + 1;
            if start > end {
                break;
            }
            let record = &body[start..end];
            if let Some(nl) = record.iter().rposition(|&b| b == b'\n') {
                let record = &record[..nl];
                if let Some(eq) = record.iter().position(|&b| b == b'=') {
                    let key = core::str::from_utf8(&record[..eq]).unwrap_or_default();
                    let value = core::str::from_utf8(&record[eq + 1..]).unwrap_or_default();
                    out.push((key.to_string(), value.to_string()));
                }
            }
            pos += len;
        }
        out
    }

    /// A NUL/space-terminated octal field. An empty field is zero.
    fn parse_octal(data: &[u8]) -> TarResult<u64> {
        let s = core::str::from_utf8(data)
            .map_err(|_| TarError::Utf8Error)?
            .trim_end_matches(['\0', ' ']);

        if s.is_empty() {
            return Ok(0);
        }

        let mut result = 0u64;
        for c in s.bytes() {
            if (b'0'..=b'7').contains(&c) {
                result = result * 8 + (c - b'0') as u64;
            } else if c != b' ' && c != 0 {
                return Err(TarError::InvalidOctal);
            }
        }

        Ok(result)
    }

    /// The unsigned byte sum of the block with the checksum field
    /// taken as eight spaces (POSIX checksum definition).
    fn compute_checksum(header: &[u8]) -> u32 {
        // Two linear scans instead of a per-byte branch keeps the
        // auto-vectorizer on a plain horizontal sum.
        let (lo, rest) = header.split_at(CHECKSUM.0);
        let mut sum: u32 = lo.iter().map(|&b| b as u32).sum::<u32>();
        sum += 8 * 0x20;
        sum += rest[CHECKSUM.1..].iter().map(|&b| b as u32).sum::<u32>();
        sum
    }

    /// True if the 512-byte block is the tar end-of-archive marker
    /// (all zeros). Walks the block as `u64` words so any non-zero
    /// word short-circuits.
    fn is_zero_block(block: &[u8]) -> bool {
        let (chunks, remainder) = block.as_chunks::<8>();
        for &w in chunks {
            if u64::from_ne_bytes(w) != 0 {
                return false;
            }
        }
        remainder.iter().all(|&b| b == 0)
    }
}

/// `buf[offset..offset+width]` as one ustar field.
fn field(buf: &[u8], loc: (usize, usize)) -> &[u8] {
    &buf[loc.0..loc.0 + loc.1]
}

pub struct TarWriter {
    entries: Vec<TarEntry>,
}

impl TarWriter {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add_entry(&mut self, name: String, data: Vec<u8>, mode: u32) {
        self.entries.push(TarEntry {
            header: TarHeader {
                name,
                mode,
                uid: 0,
                gid: 0,
                size: data.len() as u64,
                mtime: 0,
                checksum: 0,
                entry_type: TarEntryType::Regular,
                linkname: String::new(),
                uname: String::new(),
                gname: String::new(),
                devmajor: 0,
                devminor: 0,
                prefix: String::new(),
            },
            data,
        });
    }

    pub fn add_directory(&mut self, name: String, mode: u32) {
        self.entries.push(TarEntry {
            header: TarHeader {
                name,
                mode,
                uid: 0,
                gid: 0,
                size: 0,
                mtime: 0,
                checksum: 0,
                entry_type: TarEntryType::Directory,
                linkname: String::new(),
                uname: String::new(),
                gname: String::new(),
                devmajor: 0,
                devminor: 0,
                prefix: String::new(),
            },
            data: Vec::new(),
        });
    }

    /// Serialize as ustar: header, body padded to 512 bytes, and the
    /// two zero blocks the terminator is conventionally written with.
    pub fn finish(self) -> Vec<u8> {
        let mut output = Vec::new();

        for entry in &self.entries {
            let mut header = [0u8; BLOCK_SIZE];

            let name_bytes = entry.header.name.as_bytes();
            let name_len = name_bytes.len().min(100);
            header[0..name_len].copy_from_slice(&name_bytes[..name_len]);

            Self::write_octal(&mut header[100..108], entry.header.mode as u64, 7);
            Self::write_octal(&mut header[108..116], entry.header.uid as u64, 7);
            Self::write_octal(&mut header[116..124], entry.header.gid as u64, 7);
            Self::write_octal(&mut header[124..136], entry.header.size, 11);
            Self::write_octal(&mut header[136..148], entry.header.mtime, 11);

            header[156] = entry.header.entry_type.to_byte();

            let link_bytes = entry.header.linkname.as_bytes();
            let link_len = link_bytes.len().min(100);
            header[157..157 + link_len].copy_from_slice(&link_bytes[..link_len]);

            header[257..262].copy_from_slice(b"ustar");
            header[263] = b'0';

            // The checksum field is 6 octal digits, NUL, space; it is
            // computed with the field itself standing as eight spaces.
            let checksum = Self::compute_checksum(&header);
            Self::write_octal(&mut header[148..155], checksum as u64, 6);
            header[155] = b' ';

            output.extend_from_slice(&header);

            if !entry.data.is_empty() {
                output.extend_from_slice(&entry.data);
                let padding = (BLOCK_SIZE - (entry.data.len() % BLOCK_SIZE)) % BLOCK_SIZE;
                output.resize(output.len() + padding, 0);
            }
        }

        output.resize(output.len() + BLOCK_SIZE * 2, 0);

        output
    }

    /// Write `value` as `width` octal digits filling the rightmost
    /// `width` bytes of `buf`; the byte before them is left for the
    /// field's terminator.
    fn write_octal(buf: &mut [u8], mut value: u64, width: usize) {
        let start = buf.len() - width - 1;
        for i in (start..buf.len() - 1).rev() {
            buf[i] = b'0' + (value % 8) as u8;
            value /= 8;
        }
    }

    fn compute_checksum(header: &[u8]) -> u32 {
        TarReader::compute_checksum(header)
    }
}

impl Default for TarWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 512-byte ustar header with a valid checksum.
    fn header(name: &[u8], prefix: &[u8], size: u64, typeflag: u8) -> Vec<u8> {
        let mut h = vec![0u8; BLOCK_SIZE];
        let n = name.len().min(100);
        h[..n].copy_from_slice(&name[..n]);
        h[100..107].copy_from_slice(b"0000644");
        h[108..115].copy_from_slice(b"0000000");
        h[116..123].copy_from_slice(b"0000000");
        let sz = format!("{size:011o}\0");
        h[124..136].copy_from_slice(sz.as_bytes());
        h[136..147].copy_from_slice(b"00000000000");
        h[148..156].copy_from_slice(b"        "); // checksum placeholder
        h[156] = typeflag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let p = prefix.len().min(155);
        if p > 0 {
            h[345..345 + p].copy_from_slice(&prefix[..p]);
        }
        let sum = TarReader::compute_checksum(&h);
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    /// Append `body` padded to a 512-byte boundary.
    fn pad_body(blocks: &mut Vec<u8>, data: &[u8]) {
        blocks.extend_from_slice(data);
        let pad = (BLOCK_SIZE - data.len() % BLOCK_SIZE) % BLOCK_SIZE;
        blocks.resize(blocks.len() + pad, 0);
    }

    fn end_of_archive(blocks: &mut Vec<u8>) {
        blocks.extend_from_slice(&[0u8; BLOCK_SIZE * 2]);
    }

    /// ustar splits a long path across `prefix` and a *full* 100-byte
    /// `name`. Reading `name` alone truncated it silently.
    #[test]
    fn test_ustar_prefix_is_joined() {
        let dir = b"a-very-long-directory-name-that-keeps-going-and-going";
        let mut name = vec![b'x'; 100]; // completely full: no NUL terminator
        name[..5].copy_from_slice(b"file.");
        let data = {
            let mut d = header(&name, dir, 0, b'0');
            end_of_archive(&mut d);
            d
        };

        let entries = TarReader::read_all(&data).expect("should parse");
        assert_eq!(entries.len(), 1);
        let expected = format!(
            "{}/{}",
            core::str::from_utf8(dir).unwrap(),
            core::str::from_utf8(&name).unwrap()
        );
        assert_eq!(entries[0].header.name, expected, "prefix was not joined");
    }

    /// Per POSIX ustar the `prefix` field applies whenever it is
    /// non-empty, independently of how full `name` is. A producer writing
    /// a short name with a prefix is producing a split path, and dropping
    /// the prefix truncates it. (This test asserted the opposite before
    /// the GNU tar fixtures forced the question: `tar --format=ustar`
    /// splits a deep path into a NUL-padded short `name` plus a
    /// non-empty `prefix`.)
    #[test]
    fn test_short_name_joins_prefix() {
        let data = {
            let mut d = header(b"short.txt", b"real/dir", 0, b'0');
            end_of_archive(&mut d);
            d
        };
        let entries = TarReader::read_all(&data).expect("should parse");
        assert_eq!(entries[0].header.name, "real/dir/short.txt");
    }

    /// Build one PAX record, `"<len> <key>=<value>\n"`.
    ///
    /// The declared length counts the whole record *including* its own
    /// digits, which is circular: writing the length can change how many
    /// digits it needs. Iterate to a fixed point rather than guessing.
    fn pax_record(key: &str, value: &str) -> Vec<u8> {
        let body = format!("{key}={value}\n");
        let mut len = body.len() + 1;
        loop {
            let candidate = format!("{len} {body}");
            if candidate.len() == len {
                return candidate.into_bytes();
            }
            len = candidate.len();
        }
    }

    /// A PAX extended header carries the authoritative path for the entry
    /// that follows. They were previously skipped wholesale.
    #[test]
    fn test_pax_path_overrides_the_ustar_name() {
        let long_path =
            "a/very/long/path/that/only/pax/can/express/because/it/is/longer/than/100/bytes.txt";
        let body = pax_record("path", long_path);

        let mut data = header(b"PaxHeaders/entry", b"", body.len() as u64, b'x');
        pad_body(&mut data, &body);
        // the real entry follows, with a placeholder name
        data.extend_from_slice(&header(b"placeholder", b"", 0, b'0'));
        end_of_archive(&mut data);

        let entries = TarReader::read_all(&data).expect("should parse");
        assert_eq!(
            entries.len(),
            1,
            "the PAX header must not appear as an entry"
        );
        assert_eq!(entries[0].header.name, long_path);
    }

    #[test]
    fn test_pax_record_parsing() {
        let mut body = pax_record("path", "a/b.txt");
        body.extend_from_slice(&pax_record("size", "42"));
        let got = TarReader::parse_pax_records(&body);
        assert_eq!(got.len(), 2, "got {got:?}");
        assert_eq!(got[0], ("path".to_string(), "a/b.txt".to_string()));
        assert_eq!(got[1], ("size".to_string(), "42".to_string()));
    }

    /// A record's declared length can lie in both directions, and neither
    /// one may panic: a length near `usize::MAX` used to wrap the bounds
    /// check past itself, and a length shorter than its own `<digits> `
    /// prefix used to invert the record slice.
    #[test]
    fn a_pax_record_length_that_lies_ends_the_walk_rather_than_panicking() {
        // One honest record, then one whose length wraps `pos + len`.
        let mut body = pax_record("path", "a/b.txt");
        body.extend_from_slice(b"18446744073709551615 y=z\n");
        let got = TarReader::parse_pax_records(&body);
        assert_eq!(got.len(), 1, "the lying record ends the walk: {got:?}");
        assert_eq!(got[0].0, "path");

        // A length too small to hold even the space after its own digits.
        let got = TarReader::parse_pax_records(b"1 x=y\n");
        assert!(
            got.is_empty(),
            "a record shorter than its prefix is not a record"
        );
    }

    #[test]
    fn test_tar_entry_type() {
        assert_eq!(TarEntryType::from(b'0'), TarEntryType::Regular);
        assert_eq!(TarEntryType::from(b'5'), TarEntryType::Directory);
        assert_eq!(TarEntryType::from(b'2'), TarEntryType::SymbolicLink);
    }

    #[test]
    fn test_empty_tar() {
        let data = [0u8; 1024];
        let entries = TarReader::read_all(&data).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_roundtrip() {
        let mut writer = TarWriter::new();
        writer.add_entry("test.txt".to_string(), b"Hello, World!".to_vec(), 0o644);
        let tar_data = writer.finish();

        let entries = TarReader::read_all(&tar_data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "test.txt");
        assert_eq!(&entries[0].data, b"Hello, World!");
    }

    /// Third-party vectors: archives produced by GNU tar in ustar, pax and
    /// gnu formats — covering ustar prefix splitting, PAX `path=` records
    /// and GNU 'L' long names (140-char filename). The expected file is a
    /// canonical form: "name\tsize\n" per entry (sorted), "==\n", then the
    /// concatenated contents in that order.
    #[test]
    fn test_tar_third_party_vectors() {
        macro_rules! case {
            ($name:literal) => {{
                let tar = include_bytes!(concat!("../testdata/tar_", $name, ".tar"));
                let expected = include_bytes!(concat!("../testdata/tar_", $name, ".expected"));
                let mut entries = TarReader::read_all(tar)
                    .expect(concat!("tar_", $name))
                    .into_iter()
                    .filter(|e| e.header.entry_type == TarEntryType::Regular)
                    .collect::<Vec<_>>();
                entries.sort_by(|a, b| a.header.name.cmp(&b.header.name));
                let mut canon = String::new();
                for e in &entries {
                    canon.push_str(&e.header.name);
                    canon.push('\t');
                    canon.push_str(&e.data.len().to_string());
                    canon.push('\n');
                }
                canon.push_str("==\n");
                let mut built = canon.into_bytes();
                for e in &entries {
                    built.extend_from_slice(&e.data);
                }
                assert_eq!(built, &expected[..], concat!("tar_", $name));
            }};
        }
        case!("ustar");
        case!("pax");
        case!("gnu");
    }

    /// A GNU 'L' entry carries the next entry's name in its body
    /// (NUL-terminated), overriding the ustar name field.
    #[test]
    fn gnu_longname_supplies_the_next_name() {
        let long_name = "dir/".repeat(30) + "deep.txt";
        let mut data = {
            let mut d = header(b"././@LongLink", b"", long_name.len() as u64 + 1, b'L');
            let mut name_body = long_name.clone().into_bytes();
            name_body.push(0);
            pad_body(&mut d, &name_body);
            d
        };
        data.extend_from_slice(&header(b"placeholder", b"", 3, b'0'));
        pad_body(&mut data, b"abc");
        end_of_archive(&mut data);

        let entries = TarReader::read_all(&data).expect("should parse");
        assert_eq!(entries.len(), 1, "the 'L' record is not an entry");
        assert_eq!(entries[0].header.name, long_name);
        assert_eq!(entries[0].data, b"abc");
    }

    /// A GNU 'K' entry carries the next entry's link target the same way.
    #[test]
    fn gnu_longlink_supplies_the_next_linkname() {
        let target = "target/".repeat(20) + "file";
        let mut data = {
            let mut d = header(b"././@LongLink", b"", target.len() as u64 + 1, b'K');
            let mut link_body = target.clone().into_bytes();
            link_body.push(0);
            pad_body(&mut d, &link_body);
            d
        };
        data.extend_from_slice(&header(b"link", b"", 0, b'2'));
        end_of_archive(&mut data);

        let entries = TarReader::read_all(&data).expect("should parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.entry_type, TarEntryType::SymbolicLink);
        assert_eq!(entries[0].header.linkname, target);
    }

    /// The first zero block is the end of the archive; entries after it
    /// are not walked.
    #[test]
    fn zero_block_terminates_the_archive() {
        let mut data = header(b"first.txt", b"", 1, b'0');
        pad_body(&mut data, b"x");
        end_of_archive(&mut data);
        // a second archive's entry sitting after the terminator
        data.extend_from_slice(&header(b"second.txt", b"", 1, b'0'));
        pad_body(&mut data, b"y");
        end_of_archive(&mut data);

        let entries = TarReader::read_all(&data).expect("should parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "first.txt");
    }

    /// A pax `size` record overrides the size in the ustar header of
    /// the entry that follows, so the body length is read from the
    /// record and not from the (stale) numeric field.
    #[test]
    fn pax_size_overrides_the_header_size() {
        let rec = pax_record("size", "5");
        let mut data = header(b"PaxHeaders/entry", b"", rec.len() as u64, b'x');
        pad_body(&mut data, &rec);
        // the header claims size 1, the record says 5
        data.extend_from_slice(&header(b"file.txt", b"", 1, b'0'));
        pad_body(&mut data, b"hello");
        end_of_archive(&mut data);

        let entries = TarReader::read_all(&data).expect("should parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.size, 5);
        assert_eq!(&entries[0].data, b"hello");
    }

    /// An extension entry whose declared body runs past the end of the
    /// buffer is Truncated, not a panic: the length comes from the
    /// archive and a short buffer must not index past itself.
    #[test]
    fn truncated_extension_body_is_an_error_not_a_panic() {
        let long_name = "n".repeat(200);
        let d = header(b"././@LongLink", b"", long_name.len() as u64 + 1, b'L');
        // no body at all: the declared size cannot be read
        assert!(matches!(TarReader::read_all(&d), Err(TarError::Truncated)));

        let mut d = header(b"PaxHeaders/entry", b"", 100, b'x');
        d.extend_from_slice(&[0u8; 10]); // body far shorter than declared
        assert!(matches!(TarReader::read_all(&d), Err(TarError::Truncated)));
    }

    #[test]
    fn read_all_limited_stops_on_the_member_budget() {
        let mut data = Vec::new();
        for i in 0..3 {
            data.extend_from_slice(&header(format!("f{i}.txt").as_bytes(), b"", 1, b'0'));
            pad_body(&mut data, b"z");
        }
        end_of_archive(&mut data);

        let (entries, stopped) =
            TarReader::read_all_limited(&data, 2, u64::MAX).expect("should parse");
        assert_eq!(entries.len(), 2);
        assert_eq!(stopped, Some(Stopped::MemberCount));
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: Vec<(&'static str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("zeros", vec![0u8; 1024]),
            ("block", vec![0xff; 512]),
            ("valid", header(b"a.txt", b"", 0, b'0')),
        ];
        rgx_core::fuzzkit::assert_never_panics(corpus, 200, "tar", |data| {
            let _ = TarReader::read_all(data);
        });
    }
}
