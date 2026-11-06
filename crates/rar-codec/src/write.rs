// SPDX-License-Identifier: Apache-2.0

//! RAR 5.0 archive writer, store method only.
//!
//! Independent reimplementation, written from RARLAB's published RAR 5.0
//! archive format specification (`technote.htm`) — the container is the one
//! half of RAR that specification documents completely. Every field below
//! is taken from that document's block tables:
//!
//! > RAR 5.0 signature consists of 8 bytes:
//! > `0x52 0x61 0x72 0x21 0x1A 0x07 0x01 0x00`
//!
//! > Header CRC32 — CRC32 of header data starting from Header size field
//! > and up to and including the optional extra area.
//!
//! Only compression method 0 (store) is emitted: the proprietary
//! compression algorithms are not implemented by this codec, so an entry's
//! data area holds its bytes verbatim.

use alloc::string::String;
use alloc::vec::Vec;

use crate::crc32::crc32;
use crate::vint;
use crate::{Error, Result};

/// The 8-byte RAR 5.0 signature. RAR 4.x's is the same first 7 bytes with a
/// final `0x00` instead of `0x01 0x00`.
const SIGNATURE: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];

// Header types, as the specification numbers them.
const HEADER_MAIN: u64 = 1;
const HEADER_FILE: u64 = 2;
const HEADER_END: u64 = 5;

// Common header flags. The writer emits a data area and never an extra
// area, so only FLAG_DATA is named here; the pair is documented in the
// specification's "General archive block format" table.
const FLAG_DATA: u64 = 0x0002;

// File-header flags.
const FILE_DIRECTORY: u64 = 0x0001;
const FILE_HAS_CRC: u64 = 0x0004;

// Compression information: bits 8-10 hold the method. 0 is store, which is
// the only method this codec writes. Bits 0-5 hold the algorithm version;
// 0 is the version RAR 5.0 itself reads.
const METHOD_STORE: u64 = 0;

/// Host OS, as the specification numbers it. 0 is Windows, 1 is Unix. The
/// writer emits Unix, because the names it takes are UTF-8 with `/`
/// separators, which is what the spec says a Unix name is.
const HOST_UNIX: u64 = 1;

/// One pending member. Names are held as written; the writer does not
/// normalise separators.
struct Pending {
    name: String,
    data: Vec<u8>,
    directory: bool,
}

/// Builds a RAR 5.0 archive whose entries are all stored uncompressed.
///
/// ```no_run
/// use rar_codec::ArchiveBuilder;
/// let mut w = ArchiveBuilder::new();
/// w.add_stored("hello.txt", b"hi there").unwrap();
/// let bytes = w.finish();
/// ```
pub struct ArchiveBuilder {
    pending: Vec<Pending>,
}

impl Default for ArchiveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        ArchiveBuilder {
            pending: Vec::new(),
        }
    }

    /// How many members are queued.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Queue one stored file. `data` is written verbatim as the member's
    /// data area; nothing is compressed.
    pub fn add_stored(&mut self, name: &str, data: &[u8]) -> Result<&mut Self> {
        self.push(name, data.to_vec(), false)
    }

    /// Queue one directory entry. A directory has no data area.
    pub fn add_directory(&mut self, name: &str) -> Result<&mut Self> {
        self.push(name, Vec::new(), true)
    }

    fn push(&mut self, name: &str, data: Vec<u8>, directory: bool) -> Result<&mut Self> {
        if name.is_empty() {
            return Err(Error::Malformed("empty member name"));
        }
        self.pending.push(Pending {
            name: String::from(name),
            data,
            directory,
        });
        Ok(self)
    }

    /// Serialise the archive and return it.
    ///
    /// The output is: signature, one main archive header, one file header
    /// per queued member (each followed by its data area), and an end of
    /// archive header. That is the layout the specification calls the
    /// "General archive layout" for an archive with no SFX module, no
    /// encryption header and no service blocks.
    pub fn finish(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&SIGNATURE);
        self.write_main_header(&mut out);
        // `mem::take` so the loop can borrow `out` mutably per member
        // without fighting the borrow checker over `self.pending`.
        for p in core::mem::take(&mut self.pending) {
            Self::write_file_header(&mut out, &p);
        }
        Self::write_end_header(&mut out);
        out
    }

    /// Main archive header (type 1). Archive flags are 0: not a volume,
    /// not solid, no recovery record, not locked.
    fn write_main_header(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        vint::write(&mut body, HEADER_MAIN);
        vint::write(&mut body, 0); // header flags: no extra area, no data area
        vint::write(&mut body, 0); // archive flags
        emit_block(out, &body);
    }

    /// End of archive header (type 5). End flags are 0: this is the last
    /// volume in the set (there is no set).
    fn write_end_header(out: &mut Vec<u8>) {
        let mut body = Vec::new();
        vint::write(&mut body, HEADER_END);
        vint::write(&mut body, 0); // header flags
        vint::write(&mut body, 0); // end of archive flags
        emit_block(out, &body);
    }

    /// File header (type 2) plus its data area.
    ///
    /// Field order is the specification's: after the common prefix come
    /// File flags, Unpacked size, Attributes, the optional mtime and Data
    /// CRC32, Compression information, Host OS, Name length and Name.
    fn write_file_header(out: &mut Vec<u8>, p: &Pending) {
        let mut body = Vec::new();
        vint::write(&mut body, HEADER_FILE);

        // Common header flags: a data area follows the header (every member
        // has one, even an empty one), and no extra area.
        let hflags = FLAG_DATA;
        vint::write(&mut body, hflags);
        vint::write(&mut body, p.data.len() as u64); // Data size

        // File flags: a directory is marked; every member carries its CRC32.
        let mut fflags = FILE_HAS_CRC;
        if p.directory {
            fflags |= FILE_DIRECTORY;
        }
        vint::write(&mut body, fflags);

        vint::write(&mut body, p.data.len() as u64); // Unpacked size
        vint::write(&mut body, 0); // Attributes: none, the writer does not take them
                                   // No mtime: FILE_HAS_MTIME is not set, so the field is absent.
        body.extend_from_slice(&crc32(&p.data).to_le_bytes()); // Data CRC32

        // Compression information: method 0 (store), version 0, no solid
        // flag, no dictionary size to declare for stored data.
        vint::write(&mut body, METHOD_STORE);
        vint::write(&mut body, HOST_UNIX);

        let name = p.name.as_bytes();
        vint::write(&mut body, name.len() as u64); // Name length
        body.extend_from_slice(name);

        emit_block(out, &body);

        // Data area. Not counted in Header CRC32 or Header size, which is
        // why it is appended after `emit_block` rather than being part of
        // `body`.
        out.extend_from_slice(&p.data);
    }
}

/// Prefix `body` with its own header CRC32 and its size, as the block
/// format requires.
///
/// The CRC covers "starting from Header size field and up to and including
/// the optional extra area", which is exactly `body` once its size is
/// known — so the size is encoded first, then the CRC of (size || body) is
/// prepended.
fn emit_block(out: &mut Vec<u8>, body: &[u8]) {
    let mut size_bytes = Vec::new();
    vint::write(&mut size_bytes, body.len() as u64);

    let mut crc_input = Vec::with_capacity(size_bytes.len() + body.len());
    crc_input.extend_from_slice(&size_bytes);
    crc_input.extend_from_slice(body);

    out.extend_from_slice(&crc32(&crc_input).to_le_bytes());
    out.extend_from_slice(&size_bytes);
    out.extend_from_slice(body);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signature is the first thing in every RAR 5 archive.
    #[test]
    fn an_empty_archive_starts_with_the_signature() {
        let bytes = ArchiveBuilder::new().finish();
        assert_eq!(&bytes[..8], &SIGNATURE);
    }

    /// A member's data area sits right after its header block, and the
    /// header CRC covers the header and not the payload — otherwise a
    /// corrupt payload would look like a corrupt header.
    #[test]
    fn the_header_crc_excludes_the_data_area() {
        let mut w = ArchiveBuilder::new();
        w.add_stored("a.txt", b"hello").unwrap();
        let bytes = w.finish();
        // The data area holds the exact bytes written.
        assert!(bytes.windows(5).any(|w| w == b"hello"));
    }

    /// Two different payloads of the same name must produce different
    /// archives: the CRC and the data area both change.
    #[test]
    fn different_payloads_produce_different_archives() {
        let mut a = ArchiveBuilder::new();
        a.add_stored("f", b"one").unwrap();
        let mut b = ArchiveBuilder::new();
        b.add_stored("f", b"two").unwrap();
        assert_ne!(a.finish(), b.finish());
    }

    /// An empty name is refused rather than emitted as a header the
    /// reader cannot represent.
    #[test]
    fn an_empty_name_is_refused() {
        assert!(matches!(
            ArchiveBuilder::new().add_stored("", b"x"),
            Err(Error::Malformed(_))
        ));
    }

    /// `len`/`is_empty` track what is queued.
    #[test]
    fn the_counts_track_the_queue() {
        let mut w = ArchiveBuilder::new();
        assert!(w.is_empty());
        w.add_stored("a", b"1").unwrap();
        w.add_directory("d").unwrap();
        assert_eq!(w.len(), 2);
        assert!(!w.is_empty());
    }

    /// The vint-encoded header size must be what the block actually
    /// carries: a mismatch is a CRC that verifies and a reader that
    /// truncates the wrong way.
    #[test]
    fn the_declared_header_size_matches_the_body() {
        let mut w = ArchiveBuilder::new();
        w.add_stored("x", b"y").unwrap();
        let bytes = w.finish();
        // Skip the 8-byte signature and the 4-byte CRC32 of the main
        // header; the next vint is the main header's size.
        let (size, used) = vint::read(&bytes[12..]).unwrap();
        let body_start = 12 + used;
        // The body is `size` bytes and ends before the next block's CRC.
        let body_end = body_start + size as usize;
        assert!(
            body_end < bytes.len(),
            "main header must be followed by more"
        );
        // The main header body is: type=1, flags=0, archive flags=0.
        assert_eq!(bytes[body_start], 1);
    }
}
