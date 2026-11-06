// SPDX-License-Identifier: Apache-2.0

//! The HDF5 structures that carry the **names**.
//!
//! A netCDF-4 file written with the current default layout does not keep
//! its group and dataset names in the object header: it keeps them in a
//! **fractal heap**, indexed by a **v2 B-tree**, and the object header
//! carries only a **Link Info message** pointing at both. Reading the
//! names therefore means walking four structures, in this order:
//!
//! 1. the **v2 object header** of the group (`OHDR`), to find the Link
//!    Info message;
//! 2. the **Link Info message**, which names the fractal heap and the
//!    B-tree that indexes it;
//! 3. the **v2 B-tree**, whose leaves hold the heap IDs of the managed
//!    objects -- and whose *internal* nodes hold the records that a
//!    split moved up out of a leaf, which is why the tree holds more
//!    records than the leaves alone;
//! 4. the **fractal heap**, whose direct blocks hold the objects
//!    themselves: one **Link message** each.
//!
//! A group with few enough members does not get a heap: HDF5 keeps its
//! names in the group's own object header, as **Link messages**, and
//! leaves the heap's address undefined in the Link Info message. That
//! is the common case in a small file, and reading only the heap would
//! miss every name in it.
//!
//! Every field is read with the layout the HDF5 implementation uses
//! (`src/H5Olayout.c`, `src/H5Olinfo.c`, `src/H5Olink.c`, `src/H5B2*.c`,
//! `src/H5HF*.c`), not from guesswork, and every read is bounds-checked:
//! these are untrusted files, and a truncated one has to be refused with
//! a reason rather than read past the end.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use rgx_core::compress::ZlibDecoder;

/// The v2 object header signature.
const OHDR: &[u8; 4] = b"OHDR";
/// The fractal heap header signature.
const FRHP: &[u8; 4] = b"FRHP";
/// The fractal heap indirect block signature.
const FHIB: &[u8; 4] = b"FHIB";
/// The v2 B-tree header signature.
const BTHD: &[u8; 4] = b"BTHD";
/// The v2 B-tree internal node signature.
const BTIN: &[u8; 4] = b"BTIN";
/// The v2 B-tree leaf node signature.
const BTLF: &[u8; 4] = b"BTLF";
/// The v1 B-tree node signature: the tree that indexes the chunks of
/// a chunked dataset, and the links of an old-style group.
const TREE: &[u8; 4] = b"TREE";
/// The local heap signature: the heap that holds the names of an
/// old-style group.
const HEAP: &[u8; 4] = b"HEAP";
/// The symbol table node signature: a node of the table that holds
/// the links of an old-style group.
const SNOD: &[u8; 4] = b"SNOD";
/// The fixed array header signature: the index of a dataset whose chunks
/// are the elements of an array.
const FAHD: &[u8; 4] = b"FAHD";
/// The fixed array data block signature.
const FADB: &[u8; 4] = b"FADB";
/// The extensible array header signature: the index of a dataset whose
/// chunks are the elements of an array that grows with the dataset.
const EAHD: &[u8; 4] = b"EAHD";
/// The extensible array index block signature.
const EAIB: &[u8; 4] = b"EAIB";

/// The chunk index types the fourth version of the layout message names.
/// The third version of the message, and every file that does not use the
/// latest format, have a v1 B-tree and say nothing.
const CHUNK_INDEX_SINGLE: u8 = 1;
const CHUNK_INDEX_IMPLICIT: u8 = 2;
const CHUNK_INDEX_FIXED_ARRAY: u8 = 3;
const CHUNK_INDEX_EXTENSIBLE_ARRAY: u8 = 4;
const CHUNK_INDEX_BTREE2: u8 = 5;

/// The layout message flag: the single chunk of a single chunk index was
/// put through a filter, and the message says how big it is.
const LAYOUT_SINGLE_WITH_FILTER: u8 = 0x02;

/// Dataspace message.
const MSG_SDSPACE: u16 = 0x0001;
/// Link Info message: the fractal heap and the B-tree that index it.
const MSG_LINFO: u16 = 0x0002;
/// Datatype message.
const MSG_DTYPE: u16 = 0x0003;
/// Data layout message: the thing that makes an object a dataset.
const MSG_LAYOUT: u16 = 0x0008;
/// Group Info message: the thing that makes an object a group.
const MSG_GINFO: u16 = 0x000a;
/// Attribute message.
const MSG_ATTR: u16 = 0x000c;
/// Filter Pipeline message: the filters a dataset's data is put
/// through.
const MSG_PLINE: u16 = 0x000b;
/// Link message: a link the group keeps in its own object header.
const MSG_LINK: u16 = 0x0006;
/// Symbol Table message: the group keeps its names the old way, in a
/// tree that indexes the nodes of a table and in a local heap.
const MSG_STAB: u16 = 0x0011;
/// Object header continuation message: it says where the rest of the
/// messages of an object header are.
const MSG_CONT: u16 = 0x0010;

/// The signature of an object header continuation chunk.
const OCHK: &[u8; 4] = b"OCHK";

/// The message flag: the body of the message is a reference to a
/// message the file shares, not the message itself.
const MSG_FLAG_SHARED: u8 = 0x02;

/// The shared-message kind: the message is in another object header.
const SHARE_TYPE_COMMITTED: u8 = 2;

/// The link type byte of a link message: a hard link.
const LINK_TYPE_HARD: u8 = 0;
/// The link type byte of a link message: a soft link.
const LINK_TYPE_SOFT: u8 = 1;

/// The object header flags: the low two bits give the width of the
/// chunk-0 size field, which is `1 << bits` bytes.
const OHD_CHUNK0_SIZE: u8 = 0x03;
/// The object header flags: attribute creation order is tracked, so every
/// message header carries a creation-order index.
const OHD_CRT_ORDER_TRACKED: u8 = 0x04;
/// The object header flags: the object stores its timestamps.
const OHD_STORE_TIMES: u8 = 0x20;
/// The object header flags: the object stores its attribute phase change.
const OHD_ATTR_STORE_PHASE_CHANGE: u8 = 0x10;

/// The link message flags: the low two bits give the width of the name
/// length field (1, 2, 4 or 8 bytes).
const LINK_NAME_SIZE: u8 = 0x03;
/// The link message flags: the creation-order index is stored.
const LINK_STORE_CORDER: u8 = 0x04;
/// The link message flags: the link type is stored.
const LINK_STORE_LINK_TYPE: u8 = 0x08;
/// The link message flags: the name's character set is stored.
const LINK_STORE_NAME_CSET: u8 = 0x10;

/// The heap ID flags: the type of the object the ID points at.
const HEAP_ID_TYPE_MASK: u8 = 0x30;
/// The heap ID flags: a "managed" object, stored in the heap's blocks.
const HEAP_ID_TYPE_MANAGED: u8 = 0x00;

/// The heap header flags: the heap's direct blocks carry a checksum.
const HEAP_FLAGS_CHECKSUM_DBLOCKS: u8 = 0x02;

/// The netCDF marker: a dataset with this attribute is a dimension.
const DIMENSION_SCALE_CLASS: &[u8] = b"DIMENSION_SCALE";

/// The type of a dataspace with no elements at all: `H5S_NULL`. A
/// value held by it has no bytes.
const DS_NULL: u8 = 2;

/// The biggest number of groups the walk descends into. A file that wants
/// more than this is not a file, it is a loop.
const MAX_DEPTH: usize = 32;

/// The biggest number of continuation chunks one object header may
/// chain. A file that wants more than this is not a file, it is a loop.
const MAX_CONTINUATIONS: usize = 64;

/// The deepest a type may nest: a type inside a type inside a type. A
/// file that wants more than this is not a file, it is a loop.
const MAX_TYPE_DEPTH: usize = 16;

/// The class of a datatype message: a fixed-point number.
const DT_INTEGER: u8 = 0;
/// The class of a datatype message: a floating-point number.
const DT_FLOAT: u8 = 1;
/// The class of a datatype message: a time.
const DT_TIME: u8 = 2;
/// The class of a datatype message: a string.
const DT_STRING: u8 = 3;
/// The class of a datatype message: a bit field.
const DT_BITFIELD: u8 = 4;
/// The class of a datatype message: an opaque type.
const DT_OPAQUE: u8 = 5;
/// The class of a datatype message: a compound type.
const DT_COMPOUND: u8 = 6;
/// The class of a datatype message: a reference.
const DT_REFERENCE: u8 = 7;
/// The class of a datatype message: an enumeration.
const DT_ENUM: u8 = 8;
/// The class of a datatype message: a variable-length type.
const DT_VLEN: u8 = 9;
/// The class of a datatype message: an array.
const DT_ARRAY: u8 = 10;

/// The biggest size the tag of an opaque type may have.
const OPAQUE_TAG_MAX: u32 = 256;

/// A link read out of a group.
#[derive(Debug)]
pub(crate) struct Link {
    /// The link's path from the root group: `c` for a link in the root
    /// group, `sub/c` for one in a group below it.
    pub path: String,
    /// What the link points at, as the file itself says.
    pub kind: Kind,
}

/// An attribute, as the file says it: where it is, its name, and its
/// value.
#[derive(Debug)]
pub(crate) struct Attribute {
    /// The path of the object that holds the attribute: `sub/var` for a
    /// variable inside a group. The root group holds its attributes
    /// under an empty path, and those are the file's own attributes.
    pub path: String,
    /// The attribute's name.
    pub name: String,
    /// The value, decoded by the attribute's own datatype: a number, a
    /// string, or the bytes as they are.
    pub value: String,
}

/// A member of a type: the name it has, and what it holds.
#[derive(Debug)]
pub(crate) struct Member {
    /// The path of the object that holds the type: `cargo` for a
    /// committed enumeration, `cmp_t` for a committed compound.
    pub path: String,
    /// The member's name.
    pub name: String,
    /// What the member holds: the value of a member of an
    /// enumeration, or the type of a member of a compound.
    pub holds: String,
}

/// A value of a dataset: where it sits inside the dataset, and what it
/// holds.
#[derive(Debug)]
pub(crate) struct Value {
    /// The path of the dataset that holds the value: `sub/var` for a
    /// variable inside a group.
    pub path: String,
    /// The index of the element inside the dataset: one number per
    /// dimension, the last one counting fastest.
    pub index: Vec<u64>,
    /// The value, decoded by the dataset's own datatype.
    pub value: String,
}

/// A dataset whose values the reader did not read all of.
#[derive(Debug)]
pub(crate) struct Truncated {
    /// The path of the dataset.
    pub path: String,
    /// The number of values the reader reported.
    pub read: u64,
    /// The number of values the dataset holds.
    pub total: u64,
    /// Why the reader did not report them all.
    pub reason: String,
}

/// What the reader found in the file: the names, and the metadata
/// attached to them.
#[derive(Debug, Default)]
pub(crate) struct Report {
    /// The links of the root group, and of every group below it.
    pub links: Vec<Link>,
    /// The attributes of every object the reader visited.
    pub attributes: Vec<Attribute>,
    /// The members of the types the file stores.
    pub members: Vec<Member>,
    /// The values of the datasets the file stores where this reader can
    /// read them.
    pub values: Vec<Value>,
    /// The datasets whose values the reader did not read all of.
    pub truncated: Vec<Truncated>,
}

/// What a link points at.
#[derive(Debug, Clone)]
pub(crate) enum Kind {
    /// A hard link to a group.
    Group,
    /// A hard link to a dataset.
    Dataset {
        /// The datatype, as the file's datatype message says it: `int32`,
        /// `float64`, `char`, ...
        dtype: Option<String>,
        /// The extent, as the file's dataspace message says it.
        dims: Option<Vec<u64>>,
        /// netCDF marks a dimension by giving the dataset the attribute
        /// `CLASS = DIMENSION_SCALE`. That attribute is the only place
        /// the file says "dimension"; without it this is `false`.
        dimension_scale: bool,
    },
    /// A soft link: a path, not an object.
    Soft {
        /// The path the link points at.
        target: String,
    },
    /// A hard link to a committed datatype: a type the file stores as
    /// an object of its own, so that several variables can share it.
    Datatype {
        /// The datatype, as the file's datatype message says it:
        /// `compound`, `int32`, ...
        ///
        /// `None` when the file shares the type with other objects and
        /// this reader cannot follow the share to the object that
        /// holds it.
        dtype: Option<String>,
    },
    /// A hard link to an object whose header could not be read, and the
    /// reason it could not be.
    Unreadable {
        /// Why the object's header would not read.
        reason: String,
    },
}

/// What the reader found in one object: what it is, the attributes it
/// holds, and the members of the type it holds.
struct Object {
    /// What the object is.
    kind: Kind,
    /// The attributes the object holds.
    attributes: Vec<(String, String)>,
    /// The members of the type the object holds, if it holds a type.
    members: Vec<(String, String)>,
    /// The values of the dataset, if the object is one and the file
    /// stores them where this reader can read them: the index of each
    /// element inside the dataset, and what it holds.
    values: Vec<(Vec<u64>, String)>,
    /// The number of elements the dataset holds.
    values_total: u64,
    /// Why the reader did not read them all, if it did not.
    values_reason: String,
}

/// The file, with the address and length widths the superblock declares.
struct File<'a> {
    data: &'a [u8],
    /// Size of an address, in bytes.
    so: usize,
    /// Size of a length, in bytes.
    sl: usize,
}

/// One message of an object header.
struct Message<'a> {
    /// The message type.
    kind: u16,
    /// The message flags.
    flags: u8,
    /// The message body.
    body: &'a [u8],
}

/// The messages of one object header.
struct Header<'a> {
    /// Every message of the header: those of the first chunk, and
    /// those of the continuation chunks.
    messages: Vec<Message<'a>>,
    /// Whether every continuation chunk was read. A header that was
    /// cut short may be missing the message that says what the object
    /// is.
    complete: bool,
}

/// A fractal heap, as its header describes it.
struct Heap {
    /// The width of a heap ID, in bytes.
    id_len: usize,
    /// The number of blocks in a row of the doubling table.
    width: usize,
    /// The size of the first row's blocks.
    start_block_size: u64,
    /// The number of rows the table has now.
    curr_root_rows: usize,
    /// The address of the table's root block.
    table_addr: u64,
    /// The number of rows of the table that hold direct blocks.
    max_direct_rows: usize,
    /// The size of each row's blocks.
    row_block_size: Vec<u64>,
    /// The heap offset each row starts at.
    row_block_off: Vec<u64>,
    /// The width of a heap offset, in bytes.
    heap_off_size: usize,
    /// The width of a heap object length, in bytes.
    heap_len_size: usize,
    /// Whether the heap's direct blocks carry a checksum.
    checksum_dblocks: bool,
}

/// A direct block of the heap's managed space.
struct DirectBlock {
    /// The heap offset the block starts at.
    off: u64,
    /// The block's size, in bytes, prefix included.
    size: u64,
    /// Where the block lives in the file.
    addr: u64,
}

/// A link message, before its target has been looked at.
struct RawLink {
    /// The link's name.
    name: String,
    /// The creation-order index, or `u64::MAX` when the message did not
    /// carry one.
    corder: u64,
    /// Where the link points.
    target: Target,
}

/// Where a link points.
enum Target {
    /// A hard link: the address of an object header.
    Hard(u64),
    /// A soft link: a path.
    Soft(String),
}

/// The superblock: the widths the file uses, and where its root group
/// is.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Superblock {
    /// The version of the superblock.
    pub version: u8,
    /// The size of an address, in bytes.
    pub so: usize,
    /// The size of a length, in bytes.
    pub sl: usize,
    /// Where the file says it ends.
    pub eof: u64,
    /// The address of the root group's object header.
    pub root_addr: u64,
}

/// The superblock of an HDF5 file: the widths every address in the
/// file is written with, and the root group they are relative to.
pub(crate) fn superblock(data: &[u8]) -> Result<Superblock, String> {
    if data.len() < 16 {
        return Err("truncated superblock".to_string());
    }
    let version = data[8];
    if version > 3 {
        return Err(format!("unknown superblock version {version}"));
    }
    if version <= 1 {
        let so = data[13] as usize;
        let sl = data[14] as usize;
        if !(1..=16).contains(&so) || !(1..=16).contains(&sl) {
            return Err(format!("absurd address/length width {so}/{sl}"));
        }
        // The fixed header is 24 bytes, then the base address and the
        // extension's, then the address of the end of the file, then
        // the driver's, and then the root group's symbol table entry:
        // the name's offset, and the address of the object header.
        let p = 24 + so + so;
        if p + sl + so + sl + so > data.len() {
            return Err("truncated superblock".to_string());
        }
        let eof = le_uint(data, p, sl)?;
        let root = p + sl + so;
        let root_addr = le_uint(data, root + sl, so)?;
        Ok(Superblock {
            version,
            so,
            sl,
            eof,
            root_addr,
        })
    } else {
        let so = data[9] as usize;
        let sl = data[10] as usize;
        if !(1..=16).contains(&so) || !(1..=16).contains(&sl) {
            return Err(format!("absurd address/length width {so}/{sl}"));
        }
        // The header is 12 bytes, then the base address, then the
        // extension's, then the address of the end of the file.
        let p = 12 + so;
        if p + so + sl > data.len() {
            return Err("truncated superblock".to_string());
        }
        let eof = le_uint(data, p + so, sl)?;
        let root_addr = le_uint(data, p + so + sl, so)?;
        Ok(Superblock {
            version,
            so,
            sl,
            eof,
            root_addr,
        })
    }
}

/// What the reader found in the file: the links of every group, and the
/// attributes of every object.
///
/// `Ok(None)` means the root group keeps its links the old way -- in a
/// symbol table inside a v1 object header -- so there is no heap to
/// walk and no link message to read.
pub(crate) fn report(
    data: &[u8],
    root_addr: u64,
    so: usize,
    sl: usize,
) -> Result<Option<Report>, String> {
    let file = File { data, so, sl };
    let mut out = Report::default();
    let mut seen = Vec::new();
    // The types the file stores, so that a type it stores twice is
    // reported once.
    let mut types: Vec<Vec<u8>> = Vec::new();
    if !file.walk_group(root_addr, "", 0, &mut seen, &mut types, &mut out)? {
        return Ok(None);
    }
    Ok(Some(out))
}

impl<'a> File<'a> {
    /// `n` bytes at `addr`, or the reason there are not `n` bytes there.
    fn bytes(&self, addr: u64, n: usize) -> Result<&'a [u8], String> {
        let off = usize::try_from(addr).map_err(|_| {
            format!("address 0x{addr:x} does not fit in this platform's address space")
        })?;
        let end = off
            .checked_add(n)
            .ok_or_else(|| format!("address 0x{addr:x} plus {n} bytes overflows"))?;
        if end > self.data.len() {
            return Err(format!(
                "0x{addr:x}..0x{end:x} runs past the end of the file ({} bytes)",
                self.data.len()
            ));
        }
        Ok(&self.data[off..end])
    }

    /// The object header at `addr`, and every message in it.
    ///
    /// `Ok(None)` means the address does not hold an object header.
    fn object_header(&self, addr: u64) -> Result<Option<Header<'a>>, String> {
        let head = self.bytes(addr, 6)?;
        if &head[0..4] == OHDR {
            return self.object_header_v2(addr, head[5]);
        }
        // A version 1 object header has no signature: it starts with
        // its version. It keeps the names of its members in a symbol
        // table, so there are no links to read in it, but it says what
        // it is.
        if head[0] == 1 {
            return self.object_header_v1(addr);
        }
        Ok(None)
    }

    /// The messages of a version 1 object header.
    ///
    /// The number of messages the header gives counts the messages of
    /// the whole object, and the size counts the ones that are in the
    /// header itself: the rest are in the blocks that a header
    /// continuation message names.
    fn object_header_v1(&self, addr: u64) -> Result<Option<Header<'a>>, String> {
        // The version, a reserved byte, the number of messages, the
        // reference count, the size of the messages, and four bytes of
        // padding.
        let head = self.bytes(addr, 16)?;
        let count = u16::from_le_bytes([head[2], head[3]]) as usize;
        let size = u32::from_le_bytes([head[8], head[9], head[10], head[11]]) as usize;
        let body = self.bytes(addr + 16, size)?;

        let mut messages = Vec::with_capacity(count);
        let mut pending = self.messages_v1(body, &mut messages, addr)?;
        let mut rounds = 0usize;
        while let Some((off, len)) = pending.pop() {
            rounds += 1;
            if rounds > MAX_CONTINUATIONS {
                return Err(format!(
                    "the object header at 0x{addr:x} chains more than {MAX_CONTINUATIONS} continuations"
                ));
            }
            let chunk = match self.bytes(off, len as usize) {
                Ok(c) => c,
                Err(e) => {
                    return Err(format!(
                    "the object header at 0x{addr:x} names a continuation that does not read: {e}"
                ))
                }
            };
            pending.extend(self.messages_v1(chunk, &mut messages, addr)?);
        }

        Ok(Some(Header {
            complete: messages.len() >= count,
            messages,
        }))
    }

    /// The messages of one block of a version 1 object header, and the
    /// blocks that its continuations name.
    fn messages_v1(
        &self,
        body: &'a [u8],
        messages: &mut Vec<Message<'a>>,
        addr: u64,
    ) -> Result<Vec<(u64, u64)>, String> {
        let mut out = Vec::new();
        let mut q = 0usize;
        while q + 8 <= body.len() {
            let kind = u16::from_le_bytes([body[q], body[q + 1]]);
            let msize = u16::from_le_bytes([body[q + 2], body[q + 3]]) as usize;
            let flags = body[q + 4];
            let mbody = q + 8;
            if mbody + msize > body.len() {
                return Err(format!(
                    "the object header at 0x{addr:x} has a message of {msize} bytes that does not fit in it"
                ));
            }
            if kind == MSG_CONT {
                if let Some(target) =
                    continuation_target(&body[mbody..mbody + msize], self.so, self.sl)
                {
                    out.push(target);
                }
            }
            messages.push(Message {
                kind,
                flags,
                body: &body[mbody..mbody + msize],
            });
            q = mbody + msize;
        }
        Ok(out)
    }

    /// The object header at `addr`, and every message in it.
    fn object_header_v2(&self, addr: u64, flags: u8) -> Result<Option<Header<'a>>, String> {
        let mut p = addr + 6;
        if flags & OHD_STORE_TIMES != 0 {
            p += 16;
        }
        if flags & OHD_ATTR_STORE_PHASE_CHANGE != 0 {
            p += 4;
        }
        let chunk0_len = 1usize << (flags & OHD_CHUNK0_SIZE);
        let chunk0_size = le_uint(self.bytes(p, chunk0_len)?, 0, chunk0_len)? as usize;
        p += chunk0_len as u64;
        // The chunk holds the messages; the checksum that closes the
        // chunk comes after them.
        let chunk0 = self.bytes(p, chunk0_size)?;
        let head_len = if flags & OHD_CRT_ORDER_TRACKED != 0 {
            6
        } else {
            4
        };
        let mut messages = Vec::new();
        let mut pending = self.chunk_messages(chunk0, head_len, &mut messages, addr)?;

        // The header of a small object is full, and the file puts the
        // rest of the messages in continuation chunks. A dataset whose
        // layout message is over there cannot be told apart from a
        // committed datatype without reading them.
        let mut complete = true;
        let mut rounds = 0usize;
        while let Some((off, len)) = pending.pop() {
            rounds += 1;
            if rounds > MAX_CONTINUATIONS {
                complete = false;
                break;
            }
            let len = match usize::try_from(len) {
                Ok(n) => n,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            let chunk = match self.bytes(off, len) {
                Ok(c) => c,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            if chunk.len() < 8 || &chunk[0..4] != OCHK {
                complete = false;
                continue;
            }
            // The signature opens the chunk and a checksum closes it;
            // the messages are what is between.
            let body = &chunk[4..chunk.len() - 4];
            match self.chunk_messages(body, head_len, &mut messages, addr) {
                Ok(next) => pending.extend(next),
                Err(_) => complete = false,
            }
        }
        Ok(Some(Header { messages, complete }))
    }

    /// The messages of one chunk of an object header, and the
    /// continuation chunks that the chunk names.
    fn chunk_messages(
        &self,
        chunk: &'a [u8],
        head_len: usize,
        messages: &mut Vec<Message<'a>>,
        addr: u64,
    ) -> Result<Vec<(u64, u64)>, String> {
        let mut out = Vec::new();
        let mut q = 0usize;
        while q + head_len <= chunk.len() {
            let kind = u16::from(chunk[q]);
            let size = u16::from_le_bytes([chunk[q + 1], chunk[q + 2]]) as usize;
            let flags = chunk[q + 3];
            let body = q + head_len;
            if body + size > chunk.len() {
                return Err(format!(
                    "the object header at 0x{addr:x} has a message of {size} bytes that does not fit in its chunk"
                ));
            }
            let message = Message {
                kind,
                flags,
                body: &chunk[body..body + size],
            };
            if kind == MSG_CONT {
                if let Some(target) = continuation_target(message.body, self.so, self.sl) {
                    out.push(target);
                }
            }
            messages.push(message);
            q = body + size;
        }
        Ok(out)
    }

    /// The links of the group whose object header is at `addr`, and of
    /// the groups below it, and the attributes of every object the walk
    /// reaches.
    ///
    /// `false` means the group keeps its links in a symbol table, so
    /// there is nothing here to read.
    fn walk_group(
        &self,
        addr: u64,
        prefix: &str,
        depth: usize,
        seen: &mut Vec<u64>,
        types: &mut Vec<Vec<u8>>,
        out: &mut Report,
    ) -> Result<bool, String> {
        if depth > MAX_DEPTH {
            return Err(format!(
                "the groups are nested more than {MAX_DEPTH} deep at 0x{addr:x}"
            ));
        }
        let Some(header) = self.object_header(addr)? else {
            return Ok(false);
        };
        // A group in the new format says so with a Link Info message.
        // Without one it keeps its names the old way, in a symbol table,
        // and the names are read from there.
        let linfo = header.messages.iter().find(|m| m.kind == MSG_LINFO);
        if linfo.is_none() && !header.messages.iter().any(|m| m.kind == MSG_STAB) {
            return Ok(false);
        }
        if seen.contains(&addr) {
            return Err(format!("the group at 0x{addr:x} contains itself"));
        }
        seen.push(addr);

        // The root group holds the file's own attributes. The groups
        // below it are reached through a link, and their attributes are
        // read where the link is.
        if prefix.is_empty() {
            for (name, value) in self.object_attributes(&header) {
                out.attributes.push(Attribute {
                    path: String::new(),
                    name,
                    value,
                });
            }
        }

        let raw = match linfo {
            Some(linfo) => match link_info(linfo.body, self.so)? {
                // The names live in a fractal heap, indexed by a B-tree.
                Storage::Heap { heap, btree } => self.heap_links(heap, btree)?,
                // The group keeps the names in its own object header, as
                // link messages. HDF5 does that for a group with few
                // enough members that a heap would be wasteful, and it is
                // what a small file has.
                Storage::Compact => {
                    let mut raw = Vec::new();
                    for m in header.messages.iter().filter(|m| m.kind == MSG_LINK) {
                        raw.push(self.link_message(m.body, self.so)?);
                    }
                    raw
                }
            },
            // The group keeps its names in a symbol table: a tree that
            // indexes the nodes of the table, and a local heap that
            // holds the names.
            None => self.symbol_table_links(&header)?,
        };
        // The creation order is the order the links were made in, and the
        // file keeps it; the B-tree itself is a hash index, so it comes
        // out in no particular order.
        let mut raw = raw;
        raw.sort_by_key(|l| l.corder);

        let mut groups = Vec::new();
        for link in raw {
            let path = if prefix.is_empty() {
                link.name.clone()
            } else {
                let mut p = String::from(prefix);
                p.push('/');
                p.push_str(&link.name);
                p
            };
            match link.target {
                Target::Soft(target) => out.links.push(Link {
                    path,
                    kind: Kind::Soft { target },
                }),
                Target::Hard(obj) => {
                    let object = self.object_info(obj, types);
                    let is_group = matches!(object.kind, Kind::Group);
                    out.links.push(Link {
                        path: path.clone(),
                        kind: object.kind,
                    });
                    for (name, value) in object.attributes {
                        out.attributes.push(Attribute {
                            path: path.clone(),
                            name,
                            value,
                        });
                    }
                    for (name, holds) in object.members {
                        out.members.push(Member {
                            path: path.clone(),
                            name,
                            holds,
                        });
                    }
                    let mut read = 0u64;
                    for (index, value) in object.values {
                        if out.values.len() >= MAX_VALUES {
                            break;
                        }
                        out.values.push(Value {
                            path: path.clone(),
                            index,
                            value,
                        });
                        read += 1;
                    }
                    if read < object.values_total {
                        out.truncated.push(Truncated {
                            path: path.clone(),
                            read,
                            total: object.values_total,
                            reason: object.values_reason,
                        });
                    }
                    if is_group {
                        groups.push((obj, path));
                    }
                }
            }
        }
        for (obj, path) in groups {
            self.walk_group(obj, &path, depth + 1, seen, types, out)?;
        }
        // The group is no longer an ancestor of what comes next: a group
        // may be linked twice, and that is not a loop.
        seen.pop();
        Ok(true)
    }

    /// The link messages of the group whose names live in a fractal
    /// heap, and of the heap the B-tree indexes.
    fn heap_links(&self, heap_addr: u64, btree_addr: u64) -> Result<Vec<RawLink>, String> {
        let heap = self.heap(heap_addr)?;
        let blocks = heap.direct_blocks(self)?;
        let ids = self.btree_ids(btree_addr, heap.id_len)?;

        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let (off, len) = heap.managed_object(&id)?;
            let raw = heap.object(self, &blocks, off, len)?;
            out.push(self.link_message(raw, self.so)?);
        }
        Ok(out)
    }

    /// The attributes of the object whose header is `header`, as a name
    /// and a value each.
    fn object_attributes(&self, header: &Header<'a>) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for m in header.messages.iter().filter(|m| m.kind == MSG_ATTR) {
            if m.flags & MSG_FLAG_SHARED != 0 {
                // The message is a reference to one the file shares, and
                // this reader does not follow it here.
                continue;
            }
            let Some(raw) = attribute(m.body, self.sl) else {
                continue;
            };
            out.push((
                String::from_utf8_lossy(raw.name).into_owned(),
                attribute_value(&raw),
            ));
        }
        out
    }

    /// The members of the type the object holds: the names of the
    /// members of an enumeration with the values the file gives them,
    /// and the names of the members of a compound with the types they
    /// hold.
    ///
    /// A file may store the same type twice -- once as a committed
    /// type, once inside the variable that uses it -- and the reader
    /// lists the members of a type once, at the first place the type
    /// appears.
    fn object_members(
        &self,
        header: &Header<'a>,
        types: &mut Vec<Vec<u8>>,
    ) -> Vec<(String, String)> {
        let Some(msg) = header.messages.iter().find(|m| m.kind == MSG_DTYPE) else {
            return Vec::new();
        };
        let Some(body) = self.shared_body(msg, MSG_DTYPE) else {
            return Vec::new();
        };
        let Some(ty) = read_type(body, 0, 0) else {
            return Vec::new();
        };
        if ty.members.is_empty() {
            return Vec::new();
        }
        // The bytes of the type, without the padding that may follow
        // the message: two copies of the same type have the same bytes.
        let content = body.get(..ty.len).unwrap_or(body).to_vec();
        if types.contains(&content) {
            return Vec::new();
        }
        types.push(content);
        ty.members
    }

    /// What the object whose header is at `addr` is, the attributes it
    /// holds, and the members of the type it holds.
    fn object_info(&self, addr: u64, types: &mut Vec<Vec<u8>>) -> Object {
        let header = match self.object_header(addr) {
            Ok(Some(h)) => h,
            Ok(None) => {
                return Object {
                    kind: Kind::Unreadable {
                        reason: format!("0x{addr:x} does not hold an object header"),
                    },
                    attributes: Vec::new(),
                    members: Vec::new(),
                    values: Vec::new(),
                    values_total: 0,
                    values_reason: String::new(),
                }
            }
            Err(e) => {
                return Object {
                    kind: Kind::Unreadable { reason: e },
                    attributes: Vec::new(),
                    members: Vec::new(),
                    values: Vec::new(),
                    values_total: 0,
                    values_reason: String::new(),
                }
            }
        };
        let attributes = self.object_attributes(&header);
        let members = self.object_members(&header, types);
        let messages = &header.messages;
        // A group in the new format says so with a Group Info message.
        // A group in the old one says so with a Symbol Table message:
        // it keeps its names in a table instead of in a heap.
        if messages.iter().any(|m| m.kind == MSG_GINFO)
            || messages.iter().any(|m| m.kind == MSG_STAB)
        {
            return Object {
                kind: Kind::Group,
                attributes,
                members,
                values: Vec::new(),
                values_total: 0,
                values_reason: String::new(),
            };
        }
        if !messages.iter().any(|m| m.kind == MSG_LAYOUT) {
            // A committed datatype is an object of its own: it carries
            // a datatype message and no layout, because it holds no
            // data. A header that could not be read to the end may be
            // a dataset whose layout message is over there, so only a
            // header that was read whole may be called a datatype.
            if header.complete {
                if let Some(dtype) = messages.iter().find(|m| m.kind == MSG_DTYPE) {
                    return Object {
                        kind: Kind::Datatype {
                            dtype: self.datatype_of(dtype),
                        },
                        attributes,
                        members,
                        values: Vec::new(),
                        values_total: 0,
                        values_reason: String::new(),
                    };
                }
            }
            return Object {
                kind: Kind::Unreadable {
                    reason: if header.complete {
                        format!(
                            "the object header at 0x{addr:x} is neither a group, a dataset nor a datatype"
                        )
                    } else {
                        format!(
                            "the object header at 0x{addr:x} could not be read to the end, and it is not a group"
                        )
                    },
                },
                attributes,
                members,
                values: Vec::new(),
                values_total: 0,
                values_reason: String::new(),
            };
        }
        let dtype = messages
            .iter()
            .find(|m| m.kind == MSG_DTYPE)
            .and_then(|m| self.datatype_of(m));
        let dims = messages
            .iter()
            .find(|m| m.kind == MSG_SDSPACE)
            .and_then(|m| self.dataspace_of(m, self.sl));
        let dimension_scale = messages.iter().filter(|m| m.kind == MSG_ATTR).any(|m| {
            m.flags & MSG_FLAG_SHARED == 0
                && attribute_is(m.body, self.sl, b"CLASS", DIMENSION_SCALE_CLASS)
        });
        // The data of the dataset, when the file stores it where this
        // reader can read it.
        let (values, values_total, values_reason) = self.dataset_values(messages);
        Object {
            kind: Kind::Dataset {
                dtype,
                dims,
                dimension_scale,
            },
            attributes,
            members,
            values,
            values_total,
            values_reason,
        }
    }
    /// When the file shares the message with another object, the shared
    /// message points at the object header that holds it, and the type
    /// is there.
    fn datatype_of(&self, msg: &Message<'a>) -> Option<String> {
        datatype_name(self.shared_body(msg, MSG_DTYPE)?)
    }

    /// The extent a dataspace message says.
    fn dataspace_of(&self, msg: &Message<'a>, sl: usize) -> Option<Vec<u64>> {
        dataspace_dims(self.shared_body(msg, MSG_SDSPACE)?, sl)
    }

    /// The maximum extent of a dataset, when the file says it.
    ///
    /// The second version of the dataspace message may carry the maximum
    /// dimensions of the dataset, which are the dimensions the chunk
    /// index is built for.
    fn dataspace_max_of(&self, msg: &Message<'a>, sl: usize) -> Option<Vec<u64>> {
        dataspace_max_dims(self.shared_body(msg, MSG_SDSPACE)?, sl)
    }

    /// The values of a dataset, and the number of elements the file
    /// holds that the reader did not read.
    ///
    /// The file stores the data either in the layout message itself or
    /// in one block at an address, or in chunks that an index holds: a
    /// v1 B-tree, a single chunk, an implicit array, a fixed array, an
    /// extensible array, or a v2 B-tree. The index the layout message
    /// names is the one the reader walks.
    fn dataset_values(&self, messages: &[Message<'a>]) -> (Vec<(Vec<u64>, String)>, u64, String) {
        let Some(dtype_msg) = messages.iter().find(|m| m.kind == MSG_DTYPE) else {
            return (Vec::new(), 0, String::new());
        };
        let Some(dtype) = self.shared_body(dtype_msg, MSG_DTYPE) else {
            return (Vec::new(), 0, String::new());
        };
        let Some(ty) = read_type(dtype, 0, 0) else {
            return (Vec::new(), 0, String::new());
        };
        if ty.size == 0 {
            return (Vec::new(), 0, String::new());
        }
        let Some(layout_msg) = messages.iter().find(|m| m.kind == MSG_LAYOUT) else {
            return (Vec::new(), 0, String::new());
        };
        let Some(layout) = layout_of(layout_msg.body, self.so, self.sl) else {
            return (Vec::new(), 0, String::new());
        };
        // The extent of the dataset: the dataspace says how many
        // elements it holds.
        let shape: Vec<u64> = messages
            .iter()
            .find(|m| m.kind == MSG_SDSPACE)
            .and_then(|m| self.dataspace_of(m, self.sl))
            .unwrap_or_default();
        let count: u64 = if shape.is_empty() {
            1
        } else {
            shape.iter().product()
        };
        let raw: &'a [u8] = match layout {
            Layout::Compact { size, at } => match layout_msg.body.get(at..at + size) {
                Some(b) => b,
                None => return (Vec::new(), 0, String::new()),
            },
            Layout::Contiguous { addr, size } => {
                // The undefined address is the one a dataset with no
                // data has.
                if addr == u64::MAX {
                    return (Vec::new(), 0, String::new());
                }
                let want = if size > 0 {
                    size as usize
                } else {
                    // The first two versions of the message do not
                    // carry the size: the dataspace says how big the
                    // dataset is.
                    (count as usize).saturating_mul(ty.size)
                };
                match self.bytes(addr, want) {
                    Ok(b) => b,
                    Err(_) => return (Vec::new(), 0, String::new()),
                }
            }
            // The data is in chunks, and the index that holds them says
            // where each one is.
            Layout::Chunked { index, dims } => {
                if index.addr().is_none() || dims.is_empty() {
                    return (Vec::new(), count, "the dataset holds no data".to_string());
                }
                // The pipeline of the dataset says which filters its
                // data is put through, and the key of a chunk says
                // which of them were applied to it.
                let pipeline: Vec<Filter> = messages
                    .iter()
                    .find(|m| m.kind == MSG_PLINE)
                    .and_then(|m| self.shared_body(m, MSG_PLINE))
                    .and_then(filters)
                    .unwrap_or_default();
                // The chunk's shape in elements. A layout message of the
                // first two versions counts the size of an element as a
                // dimension of its own -- the chunk is stored as an array
                // of bytes -- so its last dimension is the size of an
                // element and not a coordinate. The file says so: the
                // chunk of `deflate.h5` is fifty by fifty elements of
                // four bytes, and the dataset is a hundred by two hundred
                // of the same.
                let chunk_shape: Vec<u64> = match dims.len() {
                    n if n == shape.len() + 1 && dims[n - 1] == ty.size as u64 => {
                        dims[..n - 1].to_vec()
                    }
                    n if n == shape.len() => dims.to_vec(),
                    _ => {
                        return (
                            Vec::new(),
                            count,
                            "the chunk's shape does not match the dataset's".to_string(),
                        );
                    }
                };
                let chunk_count: u64 = chunk_shape.iter().product();
                // The maximum extent of the dataset: the chunk index is
                // built for it, and a dataset that may grow has an index
                // that holds the chunks it may have.
                let max_shape = messages
                    .iter()
                    .find(|m| m.kind == MSG_SDSPACE)
                    .and_then(|m| self.dataspace_max_of(m, self.sl))
                    .filter(|m| m.len() == shape.len())
                    .unwrap_or_else(|| shape.clone());
                let grid = ChunkGrid::new(
                    chunk_shape.clone(),
                    &shape,
                    &max_shape,
                    chunk_count.saturating_mul(ty.size as u64),
                );
                let chunks = match self.chunks(&index, &dims, &grid) {
                    Ok(chunks) => chunks,
                    Err(why) => return (Vec::new(), count, why),
                };
                let mut values = Vec::new();
                let mut reason = String::new();
                for chunk in &chunks {
                    let Ok(raw) = self.bytes(chunk.addr, chunk.nbytes) else {
                        continue;
                    };
                    // The mask of a chunk says the filters that were
                    // **excluded** from it: a bit that is clear is a
                    // filter that was applied to the chunk.
                    let applied: Vec<&Filter> = pipeline
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| chunk.filter_mask & (1 << i) == 0)
                        .map(|(_, f)| f)
                        .collect();
                    let raw = if applied.is_empty() {
                        raw.to_vec()
                    } else {
                        // What the chunk holds once the filters are undone:
                        // the elements of the chunk's shape, plus the four
                        // bytes a Fletcher-32 filter ahead of the deflate
                        // in the pipeline would have added.
                        let want = chunk_count.saturating_mul(ty.size as u64).saturating_add(4);
                        match undo_filters(&applied, raw, ty.size, want) {
                            Ok(data) => data,
                            Err(why) => {
                                if reason.is_empty() {
                                    reason = why;
                                }
                                continue;
                            }
                        }
                    };
                    for flat in 0..chunk_count {
                        if values.len() >= MAX_VALUES {
                            break;
                        }
                        let at = (flat as usize).saturating_mul(ty.size);
                        let Some(b) = raw.get(at..at + ty.size) else {
                            break;
                        };
                        let Some(text) = element_text(&ty, b) else {
                            break;
                        };
                        // The chunk holds the elements of its own
                        // shape, and the dataset holds them at the
                        // chunk's offset.
                        let mut index = element_index(&chunk_shape, flat);
                        for (i, start) in index.iter_mut().zip(chunk.start.iter()) {
                            *i += *start;
                        }
                        // A chunk may be bigger than the dataset: the
                        // elements outside it are not part of it.
                        if index.iter().zip(shape.iter()).any(|(i, s)| *i >= *s) {
                            continue;
                        }
                        values.push((index, text));
                    }
                }
                // The chunks come in the order the tree holds them, and
                // the elements of the dataset are in the order the
                // file stores them.
                values.sort_by(|a, b| a.0.cmp(&b.0));
                let reason = if !reason.is_empty() {
                    reason
                } else if values.len() as u64 == count {
                    String::new()
                } else {
                    "the reader reads the most values it may".to_string()
                };
                return (values, count, reason);
            }
        };
        let mut values = Vec::new();
        for i in 0..count {
            if values.len() >= MAX_VALUES {
                break;
            }
            let at = (i as usize).saturating_mul(ty.size);
            let Some(b) = raw.get(at..at + ty.size) else {
                break;
            };
            let Some(text) = element_text(&ty, b) else {
                break;
            };
            values.push((element_index(&shape, i), text));
        }
        let reason = if values.len() as u64 == count {
            String::new()
        } else {
            "the reader reads the most values it may".to_string()
        };
        (values, count, reason)
    }

    /// The children of the leaves of a v1 B-tree: the key of each and
    /// the address it points at.
    ///
    /// The node of the tree holds its children in the order of their
    /// keys, and the key of a leaf says what the child is: the chunk
    /// index's key says where the chunk is, and the group's key says
    /// where the name is in the local heap.
    fn btree_leaves(
        &self,
        addr: u64,
        node_type: u8,
        key_size: usize,
    ) -> Result<Vec<(Vec<u8>, u64)>, String> {
        let mut out = Vec::new();
        let mut queue = vec![addr];
        let mut seen = 0usize;
        while let Some(node_addr) = queue.pop() {
            seen += 1;
            if seen > 4096 {
                return Err("the tree has more nodes than a file can hold".to_string());
            }
            let head = self.bytes(node_addr, 8 + 2 * self.so)?;
            if &head[0..4] != TREE {
                return Err(format!("0x{node_addr:x} is not a v1 B-tree node"));
            }
            if head[4] != node_type {
                return Err(format!(
                    "the tree at 0x{node_addr:x} has node type {}, and this reader does not read it",
                    head[4]
                ));
            }
            // A node that is not a leaf holds other nodes.
            let leaf = head[5] == 0;
            let nchildren = le_uint(&head[6..8], 0, 2)? as usize;
            let mut p = 8 + 2 * self.so;
            for _ in 0..nchildren {
                let key = self.bytes(node_addr + p as u64, key_size)?.to_vec();
                p += key_size;
                let child = le_uint(self.bytes(node_addr + p as u64, self.so)?, 0, self.so)?;
                p += self.so;
                if leaf {
                    out.push((key, child));
                } else {
                    queue.push(child);
                }
            }
        }
        Ok(out)
    }

    /// The chunks the index holds: where each one is, how big it is on
    /// the disk, and where it starts in the dataset.
    ///
    /// The index is the one the layout message names: a v1 B-tree, a
    /// single chunk, an implicit array, a fixed array, an extensible
    /// array, or a v2 B-tree.
    fn chunks(
        &self,
        index: &ChunkIndex,
        dims: &[u64],
        grid: &ChunkGrid,
    ) -> Result<Vec<Chunk>, String> {
        match index {
            ChunkIndex::Btree1 { addr } => self.chunks_btree1(*addr, dims),
            ChunkIndex::Single {
                addr,
                nbytes,
                filter_mask,
            } => Ok(vec![Chunk {
                addr: *addr,
                nbytes: nbytes.unwrap_or(grid.bytes) as usize,
                filter_mask: *filter_mask,
                start: vec![0; grid.shape.len()],
            }]),
            ChunkIndex::Implicit { addr } => self.chunks_implicit(*addr, grid),
            ChunkIndex::FixedArray { addr } => self.chunks_fixed_array(*addr, grid),
            ChunkIndex::ExtensibleArray { addr } => self.chunks_extensible_array(*addr, grid),
            ChunkIndex::Btree2 { addr } => self.chunks_btree2(*addr, grid),
        }
    }

    /// The chunks the v1 B-tree at `addr` indexes: where each one is,
    /// how big it is on the disk, and where it starts in the dataset.
    ///
    /// The key of a chunk says the size of its data on the disk, the
    /// filters that were applied to it, and the offset of the chunk in
    /// each of the dataset's dimensions.
    fn chunks_btree1(&self, addr: u64, dims: &[u64]) -> Result<Vec<Chunk>, String> {
        let ndims = dims.len();
        // The key of a chunk: the size of its data, the mask of the
        // filters, and the offset in each dimension.
        let key_size = 8 + ndims * 8;
        let leaves = self.btree_leaves(addr, 1, key_size)?;
        let mut out = Vec::with_capacity(leaves.len());
        for (key, child) in leaves {
            let nbytes = le_uint(&key[0..4], 0, 4)? as usize;
            let filter_mask = le_uint(&key[4..8], 0, 4)? as u32;
            let mut start = Vec::with_capacity(ndims);
            for u in 0..ndims {
                let offset = le_uint(&key[8 + u * 8..], 0, 8)?;
                let dim = dims[u];
                if dim == 0 || offset % dim != 0 {
                    return Err(
                        "the chunk index has a chunk that does not start on a chunk boundary"
                            .to_string(),
                    );
                }
                start.push(offset);
            }
            out.push(Chunk {
                addr: child,
                nbytes,
                filter_mask,
                start,
            });
        }
        Ok(out)
    }

    /// The chunks the implicit index at `addr` holds.
    ///
    /// The chunks are an array: the chunk in the place `scaled` is at
    /// the address of the array plus its place in the array times the size
    /// of a chunk. The array holds every chunk of the dataset, even the
    /// ones that were never written: those hold the fill value, which the
    /// file does not write out.
    fn chunks_implicit(&self, addr: u64, grid: &ChunkGrid) -> Result<Vec<Chunk>, String> {
        // An implicit list holds every chunk back to back, unfiltered, so
        // a file of this length holds at most this many of them: a count
        // past the ceiling is a layout the file cannot back, and walking
        // it anyway is a loop a crafted max-shape can push past 2^60. The
        // ceiling is the loop's bound, because every chunk in `out` is a
        // `Vec` of its own.
        if grid.bytes == 0 {
            return Err(
                "the chunk layout declares chunks of zero bytes, and this reader \
                 does not read it"
                    .to_string(),
            );
        }
        let count = grid.count().min(self.data.len() as u64 / grid.bytes + 1);
        let mut out = Vec::new();
        for index in 0..count {
            let at = addr.saturating_add(index.saturating_mul(grid.bytes));
            out.push(Chunk {
                addr: at,
                nbytes: grid.bytes as usize,
                filter_mask: 0,
                start: grid.start(&grid.place(index)),
            });
        }
        Ok(out)
    }

    /// The chunks the fixed array at `addr` holds.
    ///
    /// The array is a header and a data block: the header says how big an
    /// element is and how many elements there are, and the data block
    /// holds the elements. An element is the address of a chunk, and the
    /// place of the chunk in the dataset is its place in the array.
    fn chunks_fixed_array(&self, addr: u64, grid: &ChunkGrid) -> Result<Vec<Chunk>, String> {
        let head = self.bytes(addr, 8 + self.sl + self.so)?;
        if &head[0..4] != FAHD {
            return Err(format!("0x{addr:x} is not a fixed array header"));
        }
        if head[4] != 0 {
            return Err(format!(
                "the fixed array at 0x{addr:x} has version {}, and only version 0 is understood",
                head[4]
            ));
        }
        // The class of the elements: 0 for the chunks that were not put
        // through a filter, 1 for the ones that were.
        let class = head[5];
        if class > 1 {
            return Err(format!(
                "the fixed array at 0x{addr:x} has class {class}, and this reader does not read it"
            ));
        }
        let elmt_size = head[6] as usize;
        if elmt_size < self.so {
            return Err(format!(
                "the fixed array at 0x{addr:x} has {elmt_size}-byte elements, too small for an address"
            ));
        }
        // The number of elements in a page of the array, and whether the
        // array is paged at all. The shift is a count the file supplies:
        // 64 or more is not a page size but an arithmetic trap, and the
        // element spans below are checked because `nelmts * elmt_size + 4`
        // used to wrap and hand the element loop a slice too short for its
        // first element.
        if head[7] >= 64 {
            return Err(format!(
                "the fixed array at 0x{addr:x} puts 2^{} elements in a page",
                head[7]
            ));
        }
        let page_nelmts = 1u64 << head[7];
        let nelmts = le_uint(&head[8..8 + self.sl], 0, self.sl)?;
        let dblk_addr = le_uint(&head[8 + self.sl..], 0, self.so)?;
        if dblk_addr == u64::MAX {
            return Ok(Vec::new());
        }
        let npages = if nelmts > page_nelmts {
            nelmts.div_ceil(page_nelmts)
        } else {
            0
        };
        // The data block: its prefix, the bitmap of the pages that are
        // there, and then the elements.
        let bitmap = if npages > 0 {
            (npages as usize).div_ceil(8)
        } else {
            0
        };
        let prefix = 6 + self.so + bitmap;
        let dblk = self.bytes(dblk_addr, prefix)?;
        if &dblk[0..4] != FADB {
            return Err(format!("0x{dblk_addr:x} is not a fixed array data block"));
        }
        if dblk[4] != 0 {
            return Err(format!(
                "the fixed array data block at 0x{dblk_addr:x} has version {}, and only version 0 is understood",
                dblk[4]
            ));
        }
        // The elements of the array, and the index of each one of them.
        // The byte span of `count` elements plus the checksum is checked
        // arithmetic: a count the file invented used to wrap the product
        // and buy a short slice for a long element loop.
        let span = |count: u64| -> Result<usize, String> {
            count
                .checked_mul(elmt_size as u64)
                .and_then(|span| span.checked_add(4))
                .and_then(|span| usize::try_from(span).ok())
                .ok_or_else(|| {
                    format!(
                        "the fixed array at 0x{addr:x} declares {count} elements of \
                         {elmt_size} bytes, a span this platform cannot address"
                    )
                })
        };
        let page_stride = page_nelmts
            .checked_mul(elmt_size as u64)
            .and_then(|stride| stride.checked_add(4))
            .ok_or_else(|| {
                format!(
                    "the fixed array at 0x{addr:x} puts {} elements of \
                     {elmt_size} bytes in a page",
                    page_nelmts
                )
            })?;
        let mut raw: Vec<(u64, Vec<u8>)> = Vec::new();
        if npages > 0 {
            for page in 0..npages {
                // The bitmap says which pages were written.
                if !bit_is_set(&dblk[6 + self.so..], page as usize) {
                    continue;
                }
                let first = page * page_nelmts;
                let count = (nelmts - first).min(page_nelmts);
                let page_addr = dblk_addr
                    .checked_add(prefix as u64)
                    .and_then(|at| at.checked_add(page.checked_mul(page_stride)?))
                    .ok_or_else(|| {
                        format!("the fixed array at 0x{addr:x} page {page} runs past the end of the address space")
                    })?;
                let data = self.bytes(page_addr, span(count)?)?;
                for i in 0..count {
                    let at = i as usize * elmt_size;
                    raw.push((first + i, data[at..at + elmt_size].to_vec()));
                }
            }
        } else {
            let data = self.bytes(dblk_addr + prefix as u64, span(nelmts)?)?;
            for i in 0..nelmts {
                let at = i as usize * elmt_size;
                raw.push((i, data[at..at + elmt_size].to_vec()));
            }
        }
        // Every element is a chunk: the address of its data, and where
        // the chunk sits in the dataset.
        let mut out = Vec::with_capacity(raw.len());
        for (index, elmt) in raw {
            let chunk_addr = le_uint(&elmt[0..self.so], 0, self.so)?;
            if chunk_addr == u64::MAX {
                // The chunk was never written: the array holds the fill
                // value there, and the file does not write it out.
                continue;
            }
            let (nbytes, filter_mask) = if class == 1 {
                // The size of the chunk, and the filters that were left
                // out of it.
                let len = elmt_size - self.so - 4;
                let nbytes = le_uint(&elmt[self.so..self.so + len], 0, len)?;
                let mask = le_uint(&elmt[self.so + len..], 0, 4)? as u32;
                (nbytes, mask)
            } else {
                (grid.bytes, 0)
            };
            out.push(Chunk {
                addr: chunk_addr,
                nbytes: nbytes as usize,
                filter_mask,
                start: grid.start(&grid.place(index)),
            });
        }
        Ok(out)
    }

    /// The chunks the extensible array at `addr` holds.
    ///
    /// The array is a header and an index block: the header says how big
    /// an element is and how many elements there are, and the index block
    /// holds the elements. An element is the address of a chunk, and the
    /// place of the chunk in the dataset is its place in the array.
    ///
    /// The array of a dataset with a dimension of unlimited extent puts
    /// that dimension first, so that the array grows by appending; the
    /// library calls that a swizzle.
    fn chunks_extensible_array(&self, addr: u64, grid: &ChunkGrid) -> Result<Vec<Chunk>, String> {
        // The header of the array.
        let head = self.bytes(addr, 12 + 6 * self.sl + self.so)?;
        if &head[0..4] != EAHD {
            return Err(format!("0x{addr:x} is not an extensible array header"));
        }
        if head[4] != 0 {
            return Err(format!(
                "the extensible array at 0x{addr:x} has version {}, and only version 0 is understood",
                head[4]
            ));
        }
        // The class of the elements: 0 for the chunks that were not put
        // through a filter, 1 for the ones that were.
        let class = head[5];
        if class > 1 {
            return Err(format!(
                "the extensible array at 0x{addr:x} has class {class}, and this reader does not read it"
            ));
        }
        let elmt_size = head[6] as usize;
        if elmt_size < self.so {
            return Err(format!(
                "the extensible array at 0x{addr:x} has {elmt_size}-byte elements, too small for an address"
            ));
        }
        // The number of elements the index block holds, and the statistics
        // of the array.
        let idx_blk_elmts = head[8] as u64;
        let nsuper_blks = le_uint(&head[12..12 + self.sl], 0, self.sl).unwrap_or(0);
        let ndata_blks =
            le_uint(&head[12 + 2 * self.sl..12 + 3 * self.sl], 0, self.sl).unwrap_or(0);
        let nelmts = le_uint(&head[12 + 5 * self.sl..12 + 6 * self.sl], 0, self.sl).unwrap_or(0);
        let idx_blk_addr = le_uint(&head[12 + 6 * self.sl..], 0, self.so).unwrap_or(u64::MAX);
        if ndata_blks > 0 || nsuper_blks > 0 || nelmts > idx_blk_elmts {
            // The array is big enough that its elements live in data
            // blocks, and the reader does not read those.
            return Err(
                "the chunks of the extensible array are in data blocks, which this reader does not read"
                    .to_string(),
            );
        }
        // The index block, and the elements in it.
        let iblock = self.bytes(
            idx_blk_addr,
            6 + self.so + idx_blk_elmts as usize * elmt_size,
        )?;
        if &iblock[0..4] != EAIB {
            return Err(format!(
                "0x{idx_blk_addr:x} is not an extensible array index block"
            ));
        }
        if iblock[4] != 0 {
            return Err(format!(
                "the extensible array index block at 0x{idx_blk_addr:x} has version {}, and only version 0 is understood",
                iblock[4]
            ));
        }
        // The dimensions of the array, in the order they are in: the
        // dimension of unlimited extent first.
        let order = grid.swizzled_order();
        let counts: Vec<u64> = order.iter().map(|&u| grid.curr[u]).collect();
        let mut down = vec![1u64; counts.len()];
        let mut acc = 1u64;
        for u in (0..counts.len()).rev() {
            down[u] = acc;
            acc = acc.saturating_mul(counts[u]);
        }
        // Every element is a chunk: the address of its data, and where the
        // chunk sits in the dataset.
        let mut out = Vec::with_capacity(nelmts as usize);
        for index in 0..nelmts {
            let at = 6 + self.so + index as usize * elmt_size;
            let elmt = &iblock[at..at + elmt_size];
            let chunk_addr = le_uint(&elmt[0..self.so], 0, self.so)?;
            if chunk_addr == u64::MAX {
                // The chunk was never written: the array holds the fill
                // value there, and the file does not write it out.
                continue;
            }
            let (nbytes, filter_mask) = if class == 1 {
                // The size of the chunk, and the filters that were left
                // out of it.
                let len = elmt_size - self.so - 4;
                let nbytes = le_uint(&elmt[self.so..self.so + len], 0, len)?;
                let mask = le_uint(&elmt[self.so + len..], 0, 4)? as u32;
                (nbytes, mask)
            } else {
                (grid.bytes, 0)
            };
            // The place of the chunk in the dataset: the element's index
            // in the array, unravelled over the dimensions.
            let mut scaled = vec![0u64; grid.shape.len()];
            for (u, &v) in order.iter().enumerate() {
                scaled[v] = if counts[u] == 0 {
                    0
                } else {
                    (index / down[u]) % counts[u]
                };
            }
            out.push(Chunk {
                addr: chunk_addr,
                nbytes: nbytes as usize,
                filter_mask,
                start: grid.start(&scaled),
            });
        }
        Ok(out)
    }

    /// The chunks the v2 B-tree at `addr` holds.
    ///
    /// The tree indexes the chunks of a dataset with more than one
    /// dimension of unlimited extent. A record holds the address of a
    /// chunk and the place of the chunk in the dataset; a record of a
    /// chunk that was put through a filter holds its size and the mask of
    /// its filters too.
    fn chunks_btree2(&self, addr: u64, grid: &ChunkGrid) -> Result<Vec<Chunk>, String> {
        let header = self.btree_header(addr)?;
        // The type of the tree: 10 for the chunks that were not put
        // through a filter, 11 for the ones that were.
        if header.kind != 10 && header.kind != 11 {
            return Err(format!(
                "the v2 B-tree at 0x{addr:x} has type {}, and this reader does not read it",
                header.kind
            ));
        }
        // The width of the size of a chunk, which the record of a filtered
        // chunk carries.
        let len = if header.kind == 11 {
            let len = header
                .rrec_size
                .checked_sub(self.so + 4 + 8 * grid.shape.len())
                .ok_or_else(|| {
                    format!(
                        "the v2 B-tree at 0x{addr:x} has {}-byte records, too small for a chunk",
                        header.rrec_size
                    )
                })?;
            if len == 0 || len > 8 {
                return Err(format!(
                    "the v2 B-tree at 0x{addr:x} has {}-byte records, which this reader does not read",
                    header.rrec_size
                ));
            }
            len
        } else {
            0
        };
        // The place of the chunk in the dataset follows the address of
        // the chunk, and the size of the chunk and the mask of its
        // filters when it was put through one.
        let at = self.so + if header.kind == 11 { len + 4 } else { 0 };
        let records = self.btree_records(&header)?;
        let mut out = Vec::with_capacity(records.len());
        for raw in records {
            let chunk_addr = le_uint(&raw[0..self.so], 0, self.so)?;
            let (nbytes, filter_mask) = if header.kind == 11 {
                let nbytes = le_uint(&raw[self.so..self.so + len], 0, len)?;
                let mask = le_uint(&raw[self.so + len..self.so + len + 4], 0, 4)? as u32;
                (nbytes, mask)
            } else {
                (grid.bytes, 0)
            };
            let mut scaled = Vec::with_capacity(grid.shape.len());
            for u in 0..grid.shape.len() {
                scaled.push(le_uint(&raw[at + 8 * u..], 0, 8)?);
            }
            out.push(Chunk {
                addr: chunk_addr,
                nbytes: nbytes as usize,
                filter_mask,
                start: grid.start(&scaled),
            });
        }
        Ok(out)
    }

    /// The local heap at `addr`: the segment that holds the names of an
    /// old-style group, and how big it is.
    fn local_heap(&self, addr: u64) -> Result<(u64, usize), String> {
        let head = self.bytes(addr, 8 + 2 * self.sl + self.so)?;
        if &head[0..4] != HEAP {
            return Err(format!("0x{addr:x} is not a local heap"));
        }
        if head[4] != 0 {
            return Err(format!(
                "the local heap at 0x{addr:x} has version {}, and only version 0 is understood",
                head[4]
            ));
        }
        // The size of the data segment, the head of the free list, and
        // the address of the data.
        let size = le_uint(&head[8..8 + self.sl], 0, self.sl)? as usize;
        let data = le_uint(
            &head[8 + 2 * self.sl..8 + 2 * self.sl + self.so],
            0,
            self.so,
        )?;
        Ok((data, size))
    }

    /// The links of a group that keeps its names in a symbol table: a
    /// tree that indexes the nodes of the table, and a local heap that
    /// holds the names.
    fn symbol_table_links(&self, header: &Header<'a>) -> Result<Vec<RawLink>, String> {
        let Some(stab) = header.messages.iter().find(|m| m.kind == MSG_STAB) else {
            return Err("the group has no symbol table message".to_string());
        };
        if stab.body.len() < 2 * self.so {
            return Err("the symbol table message is too short".to_string());
        }
        let btree_addr = le_uint(&stab.body[0..self.so], 0, self.so)?;
        let heap_addr = le_uint(&stab.body[self.so..2 * self.so], 0, self.so)?;
        let (data_addr, data_size) = self.local_heap(heap_addr)?;
        let segment = self.bytes(data_addr, data_size)?;
        // The tree indexes the nodes of the table, and the key of each
        // of them says where its name is in the heap.
        let nodes = self.btree_leaves(btree_addr, 0, 8)?;
        let mut out = Vec::new();
        for (_, node_addr) in nodes {
            let head = self.bytes(node_addr, 8)?;
            if &head[0..4] != SNOD {
                return Err(format!("0x{node_addr:x} is not a symbol table node"));
            }
            let count = u16::from_le_bytes([head[6], head[7]]) as usize;
            for i in 0..count {
                let entry = self.bytes(node_addr + 8 + (i * 40) as u64, 40)?;
                // The offset of the name in the heap, and the address
                // of the object it names.
                let name_off = le_uint(&entry[0..8], 0, 8)? as usize;
                let object = le_uint(&entry[8..16], 0, 8)?;
                let Some(rest) = segment.get(name_off..) else {
                    return Err(format!(
                        "the symbol table node at 0x{node_addr:x} names something the heap does not hold"
                    ));
                };
                let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                let name = String::from_utf8_lossy(&rest[..end]).into_owned();
                // The old format keeps no order of creation: the tree
                // holds the names in the order of the names themselves.
                out.push(RawLink {
                    corder: out.len() as u64,
                    name,
                    target: Target::Hard(object),
                });
            }
        }
        Ok(out)
    }

    /// The body of a message, or of the message a shared message stands
    /// for.
    fn shared_body(&self, msg: &Message<'a>, kind: u16) -> Option<&'a [u8]> {
        if msg.flags & MSG_FLAG_SHARED == 0 {
            return Some(msg.body);
        }
        let addr = shared_target(msg.body, self.so)?;
        let header = self.object_header(addr).ok()??;
        let found = header.messages.iter().find(|m| m.kind == kind)?;
        if found.flags & MSG_FLAG_SHARED != 0 {
            // The message it points at is shared as well, and this
            // reader does not follow a chain of them.
            return None;
        }
        Some(found.body)
    }

    /// The fractal heap header at `addr`.
    fn heap(&self, addr: u64) -> Result<Heap, String> {
        let head = self.bytes(addr, 10)?;
        if &head[0..4] != FRHP {
            return Err(format!(
                "the link info message points at 0x{addr:x}, which is not a fractal heap header"
            ));
        }
        if head[4] != 0 {
            return Err(format!(
                "the fractal heap at 0x{addr:x} has version {}, and only version 0 is understood",
                head[4]
            ));
        }
        let id_len = u16::from_le_bytes([head[5], head[6]]) as usize;
        let filter_len = u16::from_le_bytes([head[7], head[8]]) as usize;
        let flags = head[9];

        let mut p = addr + 10;
        let max_man_size = le_uint(self.bytes(p, 4)?, 0, 4)?;
        p += 4;
        p += self.sl as u64; // next huge object id
        p += self.so as u64; // address of the huge object's B-tree
        p += self.sl as u64; // total free space
        p += self.so as u64; // address of the free space manager
        p += self.sl as u64; // size of the managed space
        p += self.sl as u64; // size of the allocated managed space
        p += self.sl as u64; // iterator offset
        p += self.sl as u64; // number of managed objects
        p += self.sl as u64; // size of the huge space
        p += self.sl as u64; // number of huge objects
        p += self.sl as u64; // size of the tiny space
        p += self.sl as u64; // number of tiny objects

        let width = le_uint(self.bytes(p, 2)?, 0, 2)? as usize;
        p += 2;
        let start_block_size = le_uint(self.bytes(p, self.sl)?, 0, self.sl)?;
        p += self.sl as u64;
        let max_direct_size = le_uint(self.bytes(p, self.sl)?, 0, self.sl)?;
        p += self.sl as u64;
        let max_index = le_uint(self.bytes(p, 2)?, 0, 2)? as usize;
        p += 2;
        p += 2; // the number of rows the table started with
        let table_addr = le_uint(self.bytes(p, self.so)?, 0, self.so)?;
        p += self.so as u64;
        let curr_root_rows = le_uint(self.bytes(p, 2)?, 0, 2)? as usize;
        if filter_len > 0 {
            // The heap's I/O filter pipeline follows the table: the root
            // direct block's size, the filter mask and the encoded filter
            // list. It is not read here, but it has to be there.
            self.bytes(p + 2, self.sl + 4 + filter_len)?;
        }

        if width == 0 || !width.is_power_of_two() {
            return Err(format!(
                "the fractal heap at 0x{addr:x} has a table width of {width}, which is not a power of two"
            ));
        }
        if start_block_size == 0 || !start_block_size.is_power_of_two() {
            return Err(format!(
                "the fractal heap at 0x{addr:x} starts with blocks of {start_block_size} bytes, which is not a power of two"
            ));
        }
        if max_direct_size == 0 || !max_direct_size.is_power_of_two() {
            return Err(format!(
                "the fractal heap at 0x{addr:x} has a maximum block size of {max_direct_size} bytes, which is not a power of two"
            ));
        }
        if max_direct_size < start_block_size {
            return Err(format!(
                "the fractal heap at 0x{addr:x} has blocks smaller ({start_block_size}) than its maximum ({max_direct_size})"
            ));
        }

        let start_bits = start_block_size.trailing_zeros() as usize;
        let first_row_bits = start_bits + width.trailing_zeros() as usize;
        if max_index < first_row_bits {
            return Err(format!(
                "the fractal heap at 0x{addr:x} has a maximum index of {max_index}, too small for its own table"
            ));
        }
        let max_root_rows = (max_index - first_row_bits) + 1;
        let max_direct_bits = max_direct_size.trailing_zeros() as usize;
        let max_direct_rows = (max_direct_bits - start_bits) + 2;

        let mut row_block_size = Vec::with_capacity(max_root_rows);
        let mut row_block_off = Vec::with_capacity(max_root_rows);
        row_block_size.push(start_block_size);
        row_block_off.push(0);
        for u in 1..max_root_rows {
            row_block_size.push(start_block_size << (u - 1));
            row_block_off.push(start_block_size * width as u64 * (1u64 << (u - 1)));
        }

        // The width of a heap offset, and of a heap object length: the
        // implementation derives them from the table, not from the file.
        let heap_off_size = max_index.div_ceil(8);
        let max_dir_blk_off_size = max_direct_bits.div_ceil(8);
        let man_bits = 64 - max_man_size.leading_zeros() as usize;
        let heap_len_size = core::cmp::min(max_dir_blk_off_size, man_bits.div_ceil(8)).max(1);

        if id_len != 1 + heap_off_size + heap_len_size {
            return Err(format!(
                "the fractal heap at 0x{addr:x} says its object ids are {id_len} bytes, but its own numbers make them {} bytes",
                1 + heap_off_size + heap_len_size
            ));
        }

        Ok(Heap {
            id_len,
            width,
            start_block_size,
            curr_root_rows,
            table_addr,
            max_direct_rows,
            row_block_size,
            row_block_off,
            heap_off_size,
            heap_len_size,
            checksum_dblocks: flags & HEAP_FLAGS_CHECKSUM_DBLOCKS != 0,
        })
    }

    /// The header of the v2 B-tree at `addr`.
    fn btree_header(&self, addr: u64) -> Result<BtreeHeader, String> {
        let head = self.bytes(addr, 10)?;
        if &head[0..4] != BTHD {
            return Err(format!("0x{addr:x} is not a v2 B-tree header"));
        }
        if head[4] != 0 {
            return Err(format!(
                "the v2 B-tree at 0x{addr:x} has version {}, and only version 0 is understood",
                head[4]
            ));
        }
        // The type of the tree: the type of the records it holds.
        let kind = head[5];
        let node_size = le_uint(&head[6..10], 0, 4)? as usize;
        let mut p = addr + 10;
        let rrec_size = le_uint(self.bytes(p, 2)?, 0, 2)? as usize;
        p += 2;
        let depth = le_uint(self.bytes(p, 2)?, 0, 2)? as usize;
        p += 2;
        p += 2; // split percent, merge percent
        let root_addr = le_uint(self.bytes(p, self.so)?, 0, self.so)?;
        p += self.so as u64;
        let root_nrec = le_uint(self.bytes(p, 2)?, 0, 2)? as usize;
        p += 2;
        let _all_nrec = le_uint(self.bytes(p, self.sl)?, 0, self.sl)?;

        if node_size < 16 {
            return Err(format!(
                "the v2 B-tree at 0x{addr:x} has {node_size}-byte nodes"
            ));
        }
        let max_nrec = (node_size - 10) / rrec_size;
        if max_nrec == 0 {
            return Err(format!(
                "the v2 B-tree at 0x{addr:x} has {node_size}-byte nodes, too small for a {rrec_size}-byte record"
            ));
        }
        let max_nrec_size = limit_enc_size(max_nrec as u64);
        // The width of the "total records below this node" field, which
        // only a tree deeper than one level carries.
        let mut cum_max_nrec = vec![max_nrec as u64];
        let mut cum_max_nrec_size = vec![0usize];
        for d in 1..=depth {
            let ptr = self.so + max_nrec_size + cum_max_nrec_size[d - 1];
            if node_size <= 10 + ptr {
                return Err(format!(
                    "the v2 B-tree at 0x{addr:x} has {node_size}-byte nodes, too small for its own pointers"
                ));
            }
            let mx = ((node_size - (10 + ptr)) / (rrec_size + ptr)) as u64;
            cum_max_nrec.push(((mx + 1) * cum_max_nrec[d - 1]) + mx);
            cum_max_nrec_size.push(limit_enc_size(cum_max_nrec[d]));
        }
        Ok(BtreeHeader {
            kind,
            rrec_size,
            root_addr,
            root_nrec,
            depth,
            max_nrec_size,
            cum_max_nrec_size,
        })
    }

    /// The records the v2 B-tree holds: every record of every node of
    /// the tree, in the order the tree holds them.
    fn btree_records(&self, header: &BtreeHeader) -> Result<Vec<Vec<u8>>, String> {
        let mut records = Vec::new();
        // A node costs six bytes of the file at the least, so this many
        // nodes is more than any tree the file can hold — and a walk that
        // asks for one more has come around to a node it already read.
        let mut nodes = self.data.len() / 6 + 1;
        self.btree_walk(
            header.root_addr,
            header.root_nrec,
            header.depth,
            header.rrec_size,
            header.max_nrec_size,
            &header.cum_max_nrec_size,
            &mut records,
            &mut nodes,
        )?;
        Ok(records)
    }

    /// The heap IDs the v2 B-tree at `addr` holds.
    ///
    /// The tree is a hash index: a record holds a hash of the name and
    /// the heap ID of the object that holds the name. The names
    /// themselves are in the heap, not in the tree.
    fn btree_ids(&self, addr: u64, id_len: usize) -> Result<Vec<Vec<u8>>, String> {
        let header = self.btree_header(addr)?;
        if header.rrec_size < 4 + id_len {
            return Err(format!(
                "the v2 B-tree at 0x{addr:x} has {}-byte records, too small for a {id_len}-byte object id",
                header.rrec_size
            ));
        }
        let records = self.btree_records(&header)?;
        Ok(records
            .into_iter()
            .map(|r| r[4..4 + id_len].to_vec())
            .collect())
    }

    /// The records of the B-tree node at `addr`, and of the nodes below.
    ///
    /// The level is not a bound on the walk: it saturates at zero, so a
    /// child that points back at a node already read would walk forever.
    /// The node budget is — every node costs its six-byte signature, so a
    /// budget of the file's own length over six ends any cycle the file
    /// was built to carry.
    #[allow(clippy::too_many_arguments)]
    fn btree_walk(
        &self,
        addr: u64,
        nrec: usize,
        level: usize,
        rrec_size: usize,
        max_nrec_size: usize,
        cum_max_nrec_size: &[usize],
        records: &mut Vec<Vec<u8>>,
        nodes: &mut usize,
    ) -> Result<(), String> {
        if *nodes == 0 {
            return Err(format!(
                "the v2 B-tree node at 0x{addr:x} was reached again: the walk \
                 has visited more nodes than the file holds"
            ));
        }
        *nodes -= 1;
        let head = self.bytes(addr, 6)?;
        if &head[0..4] == BTLF {
            let mut p = addr + 6;
            for _ in 0..nrec {
                records.push(self.bytes(p, rrec_size)?.to_vec());
                p += rrec_size as u64;
            }
            return Ok(());
        }
        if &head[0..4] != BTIN {
            return Err(format!(
                "the v2 B-tree node at 0x{addr:x} has the signature {:?}, which is neither a leaf nor an internal node",
                String::from_utf8_lossy(&head[0..4])
            ));
        }
        let mut p = addr + 6;
        // The records of an internal node are the ones a split moved up
        // out of a leaf; they are real records, not separators.
        for _ in 0..nrec {
            records.push(self.bytes(p, rrec_size)?.to_vec());
            p += rrec_size as u64;
        }
        let extra = if level > 1 {
            cum_max_nrec_size[level - 1]
        } else {
            0
        };
        let mut children = Vec::with_capacity(nrec + 1);
        for _ in 0..=nrec {
            let child = le_uint(self.bytes(p, self.so)?, 0, self.so)?;
            p += self.so as u64;
            let child_nrec = le_uint(self.bytes(p, max_nrec_size)?, 0, max_nrec_size)? as usize;
            p += max_nrec_size as u64;
            if extra > 0 {
                p += extra as u64;
            }
            children.push((child, child_nrec));
        }
        for (child, child_nrec) in children {
            if child == u64::MAX {
                continue;
            }
            self.btree_walk(
                child,
                child_nrec,
                level.saturating_sub(1),
                rrec_size,
                max_nrec_size,
                cum_max_nrec_size,
                records,
                nodes,
            )?;
        }
        Ok(())
    }

    /// The link message in `raw`.
    fn link_message(&self, raw: &[u8], so: usize) -> Result<RawLink, String> {
        if raw.is_empty() {
            return Err("an empty object in the heap is not a link".to_string());
        }
        if raw[0] != 1 {
            return Err(format!(
                "a link message has version {}, and only version 1 is understood",
                raw[0]
            ));
        }
        let flags = raw[1];
        let mut p = 2usize;
        let mut link_type = LINK_TYPE_HARD;
        if flags & LINK_STORE_LINK_TYPE != 0 {
            link_type = *raw.get(p).ok_or("a link message is truncated")?;
            p += 1;
        }
        let mut corder = u64::MAX;
        if flags & LINK_STORE_CORDER != 0 {
            corder = le_uint(
                raw.get(p..p + 8).ok_or("a link message is truncated")?,
                0,
                8,
            )?;
            p += 8;
        }
        if flags & LINK_STORE_NAME_CSET != 0 {
            p += 1;
        }
        let name_len_bytes = 1usize << (flags & LINK_NAME_SIZE);
        let name_len = le_uint(
            raw.get(p..p + name_len_bytes)
                .ok_or("a link message is truncated")?,
            0,
            name_len_bytes,
        )? as usize;
        p += name_len_bytes;
        if name_len == 0 {
            return Err("a link message has an empty name".to_string());
        }
        let name_bytes = raw
            .get(p..p + name_len)
            .ok_or("a link message's name runs past the end of the object")?;
        p += name_len;
        let name = String::from_utf8_lossy(name_bytes).into_owned();

        let target = match link_type {
            LINK_TYPE_HARD => {
                let addr = le_uint(
                    raw.get(p..p + so).ok_or("a link message is truncated")?,
                    0,
                    so,
                )?;
                Target::Hard(addr)
            }
            LINK_TYPE_SOFT => {
                let len = le_uint(
                    raw.get(p..p + 2).ok_or("a link message is truncated")?,
                    0,
                    2,
                )? as usize;
                p += 2;
                let target = raw
                    .get(p..p + len)
                    .ok_or("a soft link's target runs past the end of the object")?;
                Target::Soft(String::from_utf8_lossy(target).into_owned())
            }
            other => {
                return Err(format!(
                "a link message has the link type {other}, which is neither a hard nor a soft link"
            ))
            }
        };
        Ok(RawLink {
            name,
            corder,
            target,
        })
    }
}

impl Heap {
    /// The heap's direct blocks, and where each one starts in the heap's
    /// own address space.
    fn direct_blocks(&self, file: &File<'_>) -> Result<Vec<DirectBlock>, String> {
        let mut out = Vec::new();
        if self.curr_root_rows == 0 {
            // The table's root has not been made yet, so the heap holds
            // nothing.
            return Ok(out);
        }
        self.walk_blocks(file, self.table_addr, 0, self.curr_root_rows, &mut out)?;
        Ok(out)
    }

    /// The direct blocks under the indirect block at `addr`.
    fn walk_blocks(
        &self,
        file: &File<'_>,
        addr: u64,
        block_off: u64,
        nrows: usize,
        out: &mut Vec<DirectBlock>,
    ) -> Result<(), String> {
        let head = file.bytes(addr, 5)?;
        if &head[0..4] != FHIB {
            return Err(format!(
                "the fractal heap's block at 0x{addr:x} has the signature {:?}, which is not an indirect block",
                String::from_utf8_lossy(&head[0..4])
            ));
        }
        if head[4] != 0 {
            return Err(format!(
                "the fractal heap's indirect block at 0x{addr:x} has version {}, and only version 0 is understood",
                head[4]
            ));
        }
        let mut p = addr + 5;
        p += file.so as u64; // the heap's own address
        p += self.heap_off_size as u64; // the block's offset in the heap

        let count = nrows
            .checked_mul(self.width)
            .ok_or("the fractal heap's table is impossibly wide")?;
        let entries = file.bytes(p, count * file.so)?;

        for u in 0..count {
            let child = le_uint(&entries[u * file.so..(u + 1) * file.so], 0, file.so)?;
            if child == u64::MAX {
                continue;
            }
            let row = u / self.width;
            let col = u % self.width;
            if row >= self.row_block_size.len() {
                return Err(format!(
                    "the fractal heap's table has a row {row} that its own numbers do not allow"
                ));
            }
            let child_off =
                block_off + self.row_block_off[row] + self.row_block_size[row] * col as u64;
            if u < self.max_direct_rows * self.width {
                out.push(DirectBlock {
                    off: child_off,
                    size: self.row_block_size[row],
                    addr: child,
                });
            } else {
                // A row of indirect blocks: the child holds as many rows
                // as its own size allows.
                let child_nrows = self.size_to_rows(self.row_block_size[row]);
                self.walk_blocks(file, child, child_off, child_nrows, out)?;
            }
        }
        Ok(())
    }

    /// The number of rows of an indirect block that holds blocks of
    /// `size` bytes.
    fn size_to_rows(&self, size: u64) -> usize {
        let start_bits = self.start_block_size.trailing_zeros() as usize;
        let first_row_bits = start_bits + self.width.trailing_zeros() as usize;
        let bits = 64 - size.leading_zeros() as usize;
        (bits - first_row_bits) + 1
    }

    /// The overhead of a direct block: its signature, its version, the
    /// heap's address, its own offset and, when the heap checksums its
    /// blocks, the checksum.
    fn direct_overhead(&self, file: &File<'_>) -> usize {
        4 + 1 + file.so + self.heap_off_size + if self.checksum_dblocks { 4 } else { 0 }
    }

    /// The heap offset and length of the object the heap ID points at.
    fn managed_object(&self, id: &[u8]) -> Result<(u64, u64), String> {
        if id.len() != self.id_len {
            return Err(format!(
                "a heap id of {} bytes does not fit this heap's {}-byte ids",
                id.len(),
                self.id_len
            ));
        }
        let kind = id[0] & HEAP_ID_TYPE_MASK;
        if kind != HEAP_ID_TYPE_MANAGED {
            return Err(format!(
                "a heap id points at a {} object, and only managed objects are read",
                match kind {
                    0x10 => "huge",
                    0x20 => "tiny",
                    _ => "reserved",
                }
            ));
        }
        let off = le_uint(&id[1..1 + self.heap_off_size], 0, self.heap_off_size)?;
        let len = le_uint(
            &id[1 + self.heap_off_size..1 + self.heap_off_size + self.heap_len_size],
            0,
            self.heap_len_size,
        )?;
        Ok((off, len))
    }

    /// The bytes of the managed object at `off`, `len` bytes long.
    fn object<'a>(
        &self,
        file: &File<'a>,
        blocks: &[DirectBlock],
        off: u64,
        len: u64,
    ) -> Result<&'a [u8], String> {
        if len == 0 {
            return Err("a managed object of zero length".to_string());
        }
        let block = blocks
            .iter()
            .find(|b| off >= b.off && off < b.off + b.size)
            .ok_or_else(|| {
                format!(
                    "the heap offset {off} is not in any of the heap's {} direct blocks",
                    blocks.len()
                )
            })?;
        let blk_off = off - block.off;
        let overhead = self.direct_overhead(file) as u64;
        if blk_off < overhead {
            return Err(format!(
                "the heap offset {off} lands in the header of the direct block at 0x{:x}",
                block.addr
            ));
        }
        if blk_off + len > block.size {
            return Err(format!(
                "the object at heap offset {off} runs past the end of the direct block at 0x{:x}",
                block.addr
            ));
        }
        let len =
            usize::try_from(len).map_err(|_| "a heap object is too long to read".to_string())?;
        file.bytes(block.addr + blk_off, len)
    }
}

/// Where a group keeps the names of its members.
enum Storage {
    /// A fractal heap of link messages, indexed by a v2 B-tree.
    Heap {
        /// The fractal heap's address.
        heap: u64,
        /// The v2 B-tree that indexes it.
        btree: u64,
    },
    /// The group's own object header, as link messages. HDF5 does this
    /// for a group with few enough members that a heap would be
    /// wasteful, and it is what a small file has.
    Compact,
}

/// Where a group keeps the names of its members, from a Link Info
/// message.
///
/// The message is written either way: when the group keeps its names
/// in a fractal heap, the message names the heap and the B-tree that
/// indexes it. When the group keeps them in its own object header, the
/// heap's address is undefined.
fn link_info(body: &[u8], so: usize) -> Result<Storage, String> {
    if body.len() < 2 {
        return Err("the link info message is truncated".to_string());
    }
    if body[0] != 0 {
        return Err(format!(
            "the link info message has version {}, and only version 0 is understood",
            body[0]
        ));
    }
    let flags = body[1];
    let mut p = 2usize;
    if flags & 0x01 != 0 {
        p += 8; // the largest creation-order index
    }
    let heap = le_uint(
        body.get(p..p + so)
            .ok_or("the link info message is truncated")?,
        0,
        so,
    )?;
    p += so;
    let bt2 = le_uint(
        body.get(p..p + so)
            .ok_or("the link info message is truncated")?,
        0,
        so,
    )?;
    let undefined = u64::MAX >> ((8 - so) * 8);
    if heap == undefined {
        // There is no heap: the names are link messages in the group's
        // own object header.
        return Ok(Storage::Compact);
    }
    if bt2 == undefined {
        return Err(
            "the link info message names a fractal heap but no B-tree to index it".to_string(),
        );
    }
    Ok(Storage::Heap { heap, btree: bt2 })
}

/// The address and the length of the chunk an object header
/// continuation message names.
fn continuation_target(body: &[u8], so: usize, sl: usize) -> Option<(u64, u64)> {
    if body.len() < so + sl {
        return None;
    }
    let off = le_uint(&body[..so], 0, so).ok()?;
    let len = le_uint(&body[so..so + sl], 0, sl).ok()?;
    Some((off, len))
}

/// The address of the object header that holds the message a shared
/// message stands for.
///
/// `None` when the message is shared in the file's shared message table,
/// or when it uses an encoding this reader does not follow.
fn shared_target(body: &[u8], so: usize) -> Option<u64> {
    if body.len() < 2 + so {
        return None;
    }
    match body[0] {
        // Version 2 always means a committed type: it points at the
        // object header that holds the type.
        2 => {}
        // Version 3 says where the message is: in another object
        // header, or in the file's shared message table, which this
        // reader does not follow.
        3 => {
            if body[1] != SHARE_TYPE_COMMITTED {
                return None;
            }
        }
        // Version 1 carries a symbol table entry, and a version above
        // 3 is not understood.
        _ => return None,
    }
    le_uint(&body[2..2 + so], 0, so).ok()
}
/// The header of a datatype message: the class of the type it
/// declares, the version of the message, the class bit field, and the
/// size of one element of the type.
struct DatatypeHeader {
    /// The class of the type.
    class: u8,
    /// The version of the datatype message.
    version: u8,
    /// The class bit field. Its low sixteen bits are the number of
    /// members of a compound or an enumeration; bit 0 is the byte
    /// order of a number; bit 3 says whether an integer is signed.
    flags: u32,
    /// The size of one element of the type, in bytes.
    size: usize,
}

/// The header of a datatype message.
fn datatype_header(msg: &[u8]) -> Option<DatatypeHeader> {
    if msg.len() < 8 {
        return None;
    }
    Some(DatatypeHeader {
        class: msg[0] & 0x0f,
        version: msg[0] >> 4,
        flags: u32::from(msg[1]) | (u32::from(msg[2]) << 8) | (u32::from(msg[3]) << 16),
        size: u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]) as usize,
    })
}

/// The name of the datatype in a datatype message.
fn datatype_name(msg: &[u8]) -> Option<String> {
    let head = datatype_header(msg)?;
    Some(match head.class {
        // fixed-point: bit 3 of the class bit field is the sign
        DT_INTEGER => {
            let signed = head.flags & 0x08 != 0;
            let precision = if msg.len() >= 10 {
                u16::from_le_bytes([msg[8], msg[9]]) as u32
            } else {
                0
            };
            let bits = if precision == 0 {
                head.size * 8
            } else {
                precision as usize
            };
            if signed {
                format!("int{bits}")
            } else {
                format!("uint{bits}")
            }
        }
        // floating-point
        DT_FLOAT => format!("float{}", head.size * 8),
        // time
        DT_TIME => "time".to_string(),
        // string
        DT_STRING => {
            if head.size == u32::MAX as usize {
                "string(vlen)".to_string()
            } else if head.size == 1 {
                "char".to_string()
            } else {
                format!("string({})", head.size)
            }
        }
        DT_BITFIELD => "bitfield".to_string(),
        DT_OPAQUE => "opaque".to_string(),
        DT_COMPOUND => "compound".to_string(),
        DT_REFERENCE => "reference".to_string(),
        DT_ENUM => "enum".to_string(),
        DT_VLEN => "vlen".to_string(),
        DT_ARRAY => "array".to_string(),
        other => format!("datatype(class {other})"),
    })
}

/// A type, read out of a datatype message.
struct Type {
    /// The length of the message the type came from, in bytes: the
    /// header, the properties of the class, and whatever the type
    /// declares.
    len: usize,
    /// The name of the type, as the file's datatype message says it.
    name: String,
    /// The class of the type.
    class: u8,
    /// The size of one element of the type, in bytes.
    size: usize,
    /// Whether a number of this type is signed.
    signed: bool,
    /// Whether the bytes of a number of this type are big-endian.
    big_endian: bool,
    /// The members of a compound or an enumeration: the name of each
    /// member, and what it holds.
    members: Vec<(String, String)>,
    /// The members of a compound: where each one sits inside the
    /// record, and the type it holds.
    fields: Vec<Field>,
}

/// One member of a compound: where it sits inside the record, and the
/// type it holds.
struct Field {
    /// The member's name.
    name: String,
    /// The offset of the member inside the record, in bytes.
    offset: usize,
    /// The class of the member's type.
    class: u8,
    /// The size of the member, in bytes.
    size: usize,
    /// Whether a number of the member's type is signed.
    signed: bool,
    /// Whether the bytes of a number of the member's type are
    /// big-endian.
    big_endian: bool,
}

/// The type a datatype message at `at` declares.
///
/// `None` when the message is cut short, or when it declares a class
/// whose layout this reader does not know.
fn read_type(msg: &[u8], at: usize, depth: usize) -> Option<Type> {
    if depth > MAX_TYPE_DEPTH {
        return None;
    }
    let head = datatype_header(msg.get(at..)?)?;
    let mut p = at + 8;
    match head.class {
        DT_COMPOUND => {
            let count = member_count(head.flags);
            // The offset of a member inside the record is written in
            // the fewest bytes that hold the size of the record.
            let offset_nbytes = limit_enc_size(head.size as u64);
            let mut members = Vec::with_capacity(count);
            let mut fields = Vec::with_capacity(count);
            for _ in 0..count {
                let (name, after) = cstring(msg, p)?;
                p = if head.version >= 3 {
                    after
                } else {
                    // The name is padded to a multiple of eight bytes.
                    p + span8(name.len())
                };
                // The offset of the member inside the record.
                let offset_at = p;
                let offset_n = if head.version >= 3 { offset_nbytes } else { 4 };
                p += offset_n;
                let offset = le_uint(msg.get(offset_at..)?, 0, offset_n).ok()? as usize;
                if head.version == 1 {
                    // The first version carried the size of an array
                    // member: four dimensions, and their permutation.
                    p += 28;
                }
                let member = read_type(msg, p, depth + 1)?;
                fields.push(Field {
                    name: name.clone(),
                    offset,
                    class: member.class,
                    size: member.size,
                    signed: member.signed,
                    big_endian: member.big_endian,
                });
                members.push((name, member.name));
                p += member.len;
            }
            Some(Type {
                len: p - at,
                name: "compound".to_string(),
                class: head.class,
                size: head.size,
                signed: false,
                big_endian: false,
                members,
                fields,
            })
        }
        DT_ENUM => {
            // The base type: a whole datatype message of its own.
            let base = read_type(msg, p, depth + 1)?;
            p += base.len;
            let count = member_count(head.flags);
            let mut names = Vec::with_capacity(count);
            for _ in 0..count {
                let (name, after) = cstring(msg, p)?;
                p = if head.version >= 3 {
                    after
                } else {
                    p + span8(name.len())
                };
                names.push(name);
            }
            // The values: one per member, each the size of the base.
            let size = base.size;
            if size == 0 {
                return None;
            }
            let bytes = msg.get(p..p + count.checked_mul(size)?)?;
            let mut members = Vec::with_capacity(count);
            for (i, name) in names.into_iter().enumerate() {
                let value = &bytes[i * size..(i + 1) * size];
                let holds = if base.class == DT_INTEGER {
                    integer_text(value, base.signed, base.big_endian)
                } else {
                    // A base that is not an integer: the bytes are what
                    // they are.
                    hex_bytes(value)
                };
                members.push((name, holds));
            }
            p += count * size;
            Some(Type {
                len: p - at,
                name: "enum".to_string(),
                class: head.class,
                size: head.size,
                signed: base.signed,
                big_endian: base.big_endian,
                members,
                fields: Vec::new(),
            })
        }
        DT_VLEN => {
            // The base type: a whole datatype message of its own.
            let base = read_type(msg, p, depth + 1)?;
            p += base.len;
            Some(Type {
                len: p - at,
                name: "vlen".to_string(),
                class: head.class,
                size: head.size,
                signed: base.signed,
                big_endian: base.big_endian,
                members: Vec::new(),
                fields: Vec::new(),
            })
        }
        DT_ARRAY => {
            // The number of dimensions, then the dimensions, then the
            // base type.
            let ndims = *msg.get(p)? as usize;
            p += 1;
            if head.version < 3 {
                p += 3; // reserved
            }
            p += 4 * ndims;
            if head.version < 3 {
                p += 4 * ndims; // the permutation of the dimensions
            }
            let base = read_type(msg, p, depth + 1)?;
            p += base.len;
            Some(Type {
                len: p - at,
                name: "array".to_string(),
                class: head.class,
                size: head.size,
                signed: base.signed,
                big_endian: base.big_endian,
                members: Vec::new(),
                fields: Vec::new(),
            })
        }
        class => {
            // A type that declares no members of its own: the header,
            // and the properties of its class.
            let props = properties_len(class, &head)?;
            let len = 8 + props;
            let body = msg.get(at..at + len)?;
            Some(Type {
                len,
                name: datatype_name(body)?,
                class,
                size: head.size,
                signed: head.flags & 0x08 != 0,
                big_endian: head.flags & 0x01 != 0,
                members: Vec::new(),
                fields: Vec::new(),
            })
        }
    }
}

/// The number of members a compound or an enumeration declares: the low
/// sixteen bits of the class bit field.
fn member_count(flags: u32) -> usize {
    (flags & 0xffff) as usize
}

/// The number of bytes the properties of a datatype message of this
/// class take, after the eight-byte header.
///
/// `None` for a class whose properties this reader does not know.
fn properties_len(class: u8, head: &DatatypeHeader) -> Option<usize> {
    Some(match class {
        DT_INTEGER | DT_BITFIELD => 4,
        DT_FLOAT => 12,
        DT_TIME => 2,
        DT_STRING | DT_REFERENCE => 0,
        // The tag of an opaque type: its length is in the class bit
        // field, and the tag itself is not null-terminated.
        DT_OPAQUE => (head.flags & (OPAQUE_TAG_MAX - 1)) as usize,
        _ => return None,
    })
}

/// The null-terminated string at `at`, and the byte after it.
fn cstring(msg: &[u8], at: usize) -> Option<(String, usize)> {
    let rest = msg.get(at..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    Some((
        String::from_utf8_lossy(&rest[..end]).into_owned(),
        at + end + 1,
    ))
}

/// The span a name takes when the file pads it to a multiple of eight
/// bytes.
fn span8(len: usize) -> usize {
    ((len + 8) / 8) * 8
}

/// The extent of a dataspace message.
fn dataspace_dims(msg: &[u8], sl: usize) -> Option<Vec<u64>> {
    if msg.len() < 4 {
        return None;
    }
    let version = msg[0];
    if version != 1 && version != 2 {
        return None;
    }
    if version == 2 && msg[3] == DS_NULL {
        // A dataspace with no elements at all has no extent to report.
        return None;
    }
    let rank = msg[1] as usize;
    // Version 1 has a reserved byte and four more after the flags;
    // version 2 has the extent's type there instead.
    let head = if version == 2 { 4 } else { 8 };
    let need = head + rank * sl;
    if msg.len() < need {
        return None;
    }
    let mut dims = Vec::with_capacity(rank);
    for i in 0..rank {
        dims.push(le_uint(&msg[head + i * sl..head + (i + 1) * sl], 0, sl).ok()?);
    }
    Some(dims)
}

/// The maximum dimensions of a dataset, when the file says them.
///
/// The second version of the dataspace message carries the maximum
/// extent of the dataset after its current extent, and the flag of the
/// message says whether it does.
fn dataspace_max_dims(msg: &[u8], sl: usize) -> Option<Vec<u64>> {
    if msg.len() < 4 {
        return None;
    }
    if msg[0] != 2 {
        // The first version of the message has no maximum extent: the
        // dataset is as big as it says it is.
        return None;
    }
    // The flag that says the maximum dimensions are stored.
    if msg[2] & 0x01 == 0 {
        return None;
    }
    let rank = msg[1] as usize;
    let head = 4;
    if msg.len() < head + 2 * rank * sl {
        return None;
    }
    let mut dims = Vec::with_capacity(rank);
    for i in 0..rank {
        dims.push(le_uint(&msg[head + (rank + i) * sl..], 0, sl).ok()?);
    }
    Some(dims)
}

/// Whether the bit at `index` is set in a bitmap.
fn bit_is_set(bitmap: &[u8], index: usize) -> bool {
    match bitmap.get(index / 8) {
        Some(b) => (b >> (index % 8)) & 1 == 1,
        None => false,
    }
}

/// The most values the reader reports. A file may hold more, and then
/// the reader says how many of them it did not read.
const MAX_VALUES: usize = 1 << 20;

/// Where a dataset keeps its data.
#[derive(Debug)]
enum Layout {
    /// The data is in the layout message itself, right after its size.
    Compact {
        /// The size of the data, in bytes.
        size: usize,
        /// The offset of the data inside the message.
        at: usize,
    },
    /// The data is one block at an address in the file.
    Contiguous {
        /// The address of the data.
        addr: u64,
        /// The size of the data, in bytes. Zero when the message does
        /// not say: the first two versions of the message do not carry
        /// it, and the dataspace says how big the dataset is.
        size: u64,
    },
    /// The data is in chunks, and the index that holds them.
    Chunked {
        /// The index that holds the chunks.
        index: ChunkIndex,
        /// The size of a chunk, in each of the dataset's dimensions.
        dims: Vec<u64>,
    },
}

/// The index that holds the chunks of a chunked dataset.
///
/// The fourth version of the layout message names the index; the third
/// version, and every file that does not use the latest format, have a v1
/// B-tree and say nothing.
#[derive(Debug)]
enum ChunkIndex {
    /// A v1 B-tree: the index of every file that does not use the latest
    /// format.
    Btree1 {
        /// The address of the tree.
        addr: u64,
    },
    /// A single chunk: the dataset holds one chunk, and the layout
    /// message gives its address.
    Single {
        /// The address of the chunk.
        addr: u64,
        /// The size of the chunk on the disk, when the file says it: a
        /// chunk that was put through a filter says so in the message.
        nbytes: Option<u64>,
        /// The filters that were left out of the chunk: bit *i* is the
        /// filter *i*.
        filter_mask: u32,
    },
    /// An implicit index: the chunks are an array, and the address of
    /// each one is computed from its place in the array.
    Implicit {
        /// The address of the array.
        addr: u64,
    },
    /// A fixed array: the chunks are the elements of an array, and the
    /// dataset's maximum dimensions fix how many elements it has.
    FixedArray {
        /// The address of the array's header.
        addr: u64,
    },
    /// An extensible array: the chunks are the elements of an array that
    /// grows as the dataset does.
    ExtensibleArray {
        /// The address of the array's header.
        addr: u64,
    },
    /// A v2 B-tree: the index of a dataset with more than one dimension
    /// of unlimited extent.
    Btree2 {
        /// The address of the tree.
        addr: u64,
    },
}

impl ChunkIndex {
    /// The address of the index that holds the chunks, or `None` when the
    /// file says the dataset holds no data.
    fn addr(&self) -> Option<u64> {
        let addr = match *self {
            ChunkIndex::Btree1 { addr }
            | ChunkIndex::Single { addr, .. }
            | ChunkIndex::Implicit { addr }
            | ChunkIndex::FixedArray { addr }
            | ChunkIndex::ExtensibleArray { addr }
            | ChunkIndex::Btree2 { addr } => addr,
        };
        if addr == u64::MAX {
            None
        } else {
            Some(addr)
        }
    }
}

/// One filter of a dataset's pipeline.
struct Filter {
    /// The filter's ID: 1 is deflate, 2 shuffle, 3 fletcher32.
    id: u16,
    /// The filter's name, when the file gives one. The first version
    /// of the pipeline message names every filter; the second names
    /// only the ones that are not built into the library.
    name: String,
    /// The filter's own data: the shuffle keeps the size of an element
    /// and the number of elements there are.
    cd: Vec<u32>,
}

/// The filters of a dataset's pipeline, as the file's message says.
///
/// The message is the version, the number of filters, and then each
/// filter: its ID, its name, its flags, and its own data. The first
/// version of the message keeps the name padded to eight bytes and
/// names every filter; the second names only the filters that are not
/// built into the library, and the ones it does not name are the
/// deflate, the shuffle and the Fletcher-32.
fn filters(msg: &[u8]) -> Option<Vec<Filter>> {
    let version = *msg.first()?;
    let nused = *msg.get(1)? as usize;
    let mut p = 2usize;
    if version == 1 {
        p += 6; // the reserved bytes
    }
    let mut out = Vec::with_capacity(nused);
    for _ in 0..nused {
        let id = u16::from_le_bytes([*msg.get(p)?, *msg.get(p + 1)?]);
        p += 2;
        let name_len = u16::from_le_bytes([*msg.get(p)?, *msg.get(p + 1)?]) as usize;
        p += 2;
        p += 2; // the flags
        let cd_nelmts = u16::from_le_bytes([*msg.get(p)?, *msg.get(p + 1)?]) as usize;
        p += 2;
        let mut name = String::new();
        if name_len > 0 {
            let bytes = msg.get(p..p + name_len)?;
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            name = String::from_utf8_lossy(&bytes[..end]).into_owned();
            p += name_len;
        }
        let mut cd = Vec::with_capacity(cd_nelmts);
        for _ in 0..cd_nelmts {
            cd.push(le_uint(msg.get(p..)?, 0, 4).ok()? as u32);
            p += 4;
        }
        out.push(Filter { id, name, cd });
    }
    Some(out)
}

/// Undo the filters a chunk was put through.
///
/// The pipeline is applied in order, so undoing it is in reverse. The
/// reader undoes the three it knows: the shuffle, which interlaces the
/// bytes of the elements, the Fletcher-32, which appends a checksum of the
/// data, and the deflate, which compresses the result. A filter it does
/// not know, or cannot undo, is a refusal that says which one.
///
/// `limit` is how many bytes the chunk may hold once the filters are
/// undone, and it is the ceiling the deflate is decoded under: a chunk
/// that inflates to more than that is not a chunk.
fn undo_filters(
    filters: &[&Filter],
    data: &[u8],
    elem_size: usize,
    limit: u64,
) -> Result<Vec<u8>, String> {
    let mut out = data.to_vec();
    for f in filters.iter().rev() {
        match f.id {
            // The shuffle: the bytes of the elements are interlaced, so
            // that all the bytes of the same position of every element
            // are together. The filter says how big an element is.
            2 => {
                let size = f.cd.first().copied().unwrap_or(elem_size as u32) as usize;
                out = unshuffle(&out, size);
            }
            // The Fletcher-32: the data with a checksum of itself
            // appended.
            3 => {
                if out.len() < 4 {
                    return Err("the chunk is too short to hold its checksum".to_string());
                }
                let body = out.len() - 4;
                let stored =
                    u32::from_le_bytes([out[body], out[body + 1], out[body + 2], out[body + 3]]);
                let computed = fletcher32(&out[..body]);
                if stored != computed && stored != computed.swap_bytes() {
                    return Err("the chunk's checksum does not match its data".to_string());
                }
                out.truncate(body);
            }
            // The deflate: the data is compressed, and this reader
            // inflates it.
            1 => {
                // The HDF5 library's deflate filter holds a **zlib**
                // stream, not a raw DEFLATE one: the filter calls zlib's
                // `inflateInit` (`src/H5Zdeflate.c`), which is the RFC
                // 1950 framing -- the two-byte header and the Adler-32
                // trailer around the DEFLATE data. The file says so too:
                // every chunk of `deflate.h5` starts with `78 da`, the
                // header of a zlib stream at the best-compression preset,
                // and the reader's own decoder is the one that checks the
                // Adler-32 at the end.
                //
                // What the stream holds is the chunk's own bytes. The
                // ceiling is the size the chunk has, so a chunk that
                // expands past it is refused rather than expanded.
                let decoder = ZlibDecoder::new();
                match decoder.decode_bounded(&out, limit) {
                    Ok(bounded) => {
                        if bounded.capped {
                            return Err(format!(
                                "the chunk compressed with {} expands to more than the chunk holds",
                                filter_name(f)
                            ));
                        }
                        out = bounded.bytes;
                    }
                    Err(e) => {
                        return Err(format!(
                            "the chunk compressed with {} does not inflate: {e}",
                            filter_name(f)
                        ))
                    }
                }
            }
            _ => {
                return Err(format!(
                    "the chunk was put through the filter {}, which this reader does not undo",
                    filter_name(f)
                ))
            }
        }
    }
    Ok(out)
}

/// The name of a filter, or its number when the file does not name it.
///
/// The second version of the pipeline message names only the filters
/// that are not built into the library, and the reader knows the six the
/// library gives a number to: the deflate, the shuffle, the Fletcher-32,
/// the szip, the nbit and the scale-offset. The three it undoes are the
/// deflate, the shuffle and the Fletcher-32; the other three are a
/// refusal that says which one.
fn filter_name(f: &Filter) -> String {
    if !f.name.is_empty() {
        return f.name.clone();
    }
    match f.id {
        1 => "deflate".to_string(),
        2 => "shuffle".to_string(),
        3 => "fletcher32".to_string(),
        4 => "szip".to_string(),
        5 => "nbit".to_string(),
        6 => "scale-offset".to_string(),
        _ => format!("{}", f.id),
    }
}

/// Undo the shuffle filter: the bytes of the elements were interlaced,
/// so that all the bytes of the same position of every element are
/// together.
fn unshuffle(data: &[u8], elem_size: usize) -> Vec<u8> {
    if elem_size <= 1 {
        return data.to_vec();
    }
    // The bytes that do not fill an element stay at the end.
    let leftover = data.len() % elem_size;
    let count = (data.len() - leftover) / elem_size;
    let mut out = vec![0u8; data.len()];
    let mut src = 0usize;
    for i in 0..elem_size {
        for k in 0..count {
            out[i + k * elem_size] = data[src];
            src += 1;
        }
    }
    if leftover > 0 {
        let at = data.len() - leftover;
        out[at..].copy_from_slice(&data[at..]);
    }
    out
}

/// The Fletcher-32 checksum the HDF5 library uses: the data in
/// sixteen-bit words, most significant byte first, with the two sums
/// folded back to sixteen bits.
fn fletcher32(data: &[u8]) -> u32 {
    let mut sum1: u32 = 0;
    let mut sum2: u32 = 0;
    let mut at = 0usize;
    let mut words = data.len() / 2;
    while words > 0 {
        let tlen = words.min(360);
        words -= tlen;
        for _ in 0..tlen {
            sum1 += ((data[at] as u32) << 8) | data[at + 1] as u32;
            at += 2;
            sum2 += sum1;
        }
        sum1 = (sum1 & 0xffff) + (sum1 >> 16);
        sum2 = (sum2 & 0xffff) + (sum2 >> 16);
    }
    if data.len() % 2 == 1 {
        sum1 += (data[at] as u32) << 8;
        sum2 += sum1;
        sum1 = (sum1 & 0xffff) + (sum1 >> 16);
        sum2 = (sum2 & 0xffff) + (sum2 >> 16);
    }
    sum1 = (sum1 & 0xffff) + (sum1 >> 16);
    sum2 = (sum2 & 0xffff) + (sum2 >> 16);
    (sum2 << 16) | sum1
}

/// The header of a v2 B-tree: what its records are and where they are.
struct BtreeHeader {
    /// The type of the tree: the type of the records it holds.
    kind: u8,
    /// The size of a record, in bytes.
    rrec_size: usize,
    /// The address of the root node.
    root_addr: u64,
    /// The number of records in the root node.
    root_nrec: usize,
    /// The number of levels of the tree below the root.
    depth: usize,
    /// The width of the "number of records below this node" field.
    max_nrec_size: usize,
    /// The width of that field for each level of the tree.
    cum_max_nrec_size: Vec<usize>,
}

/// The grid the chunks of a dataset sit in: how big a chunk is, how many
/// of them there are, and where each one is in the array of them.
struct ChunkGrid {
    /// The size of a chunk, in each of the dataset's dimensions.
    shape: Vec<u64>,
    /// The number of chunks in each of the dataset's dimensions.
    nchunks: Vec<u64>,
    /// The number of chunks in each of the dataset's dimensions, as the
    /// dataset is now: a dataset that may grow has more of them later.
    curr: Vec<u64>,
    /// The dimension of unlimited extent, when the dataset has one.
    unlim: Option<usize>,
    /// The stride of each dimension in the array of chunks: the chunk in
    /// the place `scaled` is at `sum(scaled[u] * down[u])`.
    down: Vec<u64>,
    /// The size of a chunk on the disk, in bytes.
    bytes: u64,
}

impl ChunkGrid {
    /// The grid of the chunks of a dataset: the shape of a chunk, the
    /// number of chunks in each dimension, and the size of a chunk.
    ///
    /// The number of chunks in a dimension is the number of the dataset's
    /// maximum extent in it: a dataset that may grow has an index that
    /// holds the chunks it may have.
    fn new(shape: Vec<u64>, curr_shape: &[u64], max_shape: &[u64], bytes: u64) -> Self {
        let count = |dims: &[u64], u: usize| -> u64 {
            let chunk = shape[u];
            if chunk == 0 {
                0
            } else {
                dims.get(u).copied().unwrap_or(0).div_ceil(chunk)
            }
        };
        let nchunks: Vec<u64> = (0..shape.len()).map(|u| count(max_shape, u)).collect();
        let curr: Vec<u64> = (0..shape.len()).map(|u| count(curr_shape, u)).collect();
        // The dimension of unlimited extent is the one whose maximum is
        // the library's mark for a dimension that may grow.
        let unlim = max_shape
            .iter()
            .position(|d| *d == u64::MAX)
            .filter(|u| *u < shape.len());
        let mut down = vec![1u64; nchunks.len()];
        let mut acc = 1u64;
        for u in (0..nchunks.len()).rev() {
            down[u] = acc;
            acc = acc.saturating_mul(nchunks[u]);
        }
        ChunkGrid {
            shape,
            nchunks,
            curr,
            unlim,
            down,
            bytes,
        }
    }

    /// The order the dimensions of the array of chunks are in.
    ///
    /// The dimension of unlimited extent comes first, so that the array
    /// grows by appending: the library calls that a swizzle.
    fn swizzled_order(&self) -> Vec<usize> {
        match self.unlim {
            Some(u) if u > 0 => {
                let mut order = vec![u];
                order.extend(0..u);
                order.extend(u + 1..self.shape.len());
                order
            }
            _ => (0..self.shape.len()).collect(),
        }
    }

    /// The number of chunks in the grid.
    fn count(&self) -> u64 {
        self.nchunks.iter().product()
    }

    /// The place in the grid of the chunk at the linear index `index`.
    fn place(&self, index: u64) -> Vec<u64> {
        self.nchunks
            .iter()
            .zip(self.down.iter())
            .map(|(n, d)| if *n == 0 { 0 } else { (index / d) % n })
            .collect()
    }

    /// The place in the dataset of the chunk whose scaled offsets are
    /// `scaled`: the scaled offset of a chunk is its place in the grid.
    fn start(&self, scaled: &[u64]) -> Vec<u64> {
        scaled
            .iter()
            .zip(self.shape.iter())
            .map(|(s, c)| s * c)
            .collect()
    }
}

/// One chunk of a chunked dataset: where it is, how big it is, and
/// where it starts in the dataset.
struct Chunk {
    /// The address of the chunk's data.
    addr: u64,
    /// The size of the chunk's data on the disk, in bytes.
    nbytes: usize,
    /// The filters that were applied to the chunk: bit *i* is the
    /// filter *i*.
    filter_mask: u32,
    /// The offset of the chunk in each of the dataset's dimensions.
    start: Vec<u64>,
}

/// Where a dataset keeps its data, according to its layout message.
///
/// The class of the message says it, and the class sits in a different
/// byte depending on the version of the message: the first two
/// versions put it after the dimensionality, the third and the fourth
/// put it right after the version.
fn layout_of(msg: &[u8], so: usize, sl: usize) -> Option<Layout> {
    let version = *msg.first()?;
    if version == 1 || version == 2 {
        // version, dimensionality, class, reserved
        let class = *msg.get(2)?;
        let head = 8;
        let ndims = *msg.get(1)? as usize;
        match class {
            0 => {
                // The dimension sizes, then the size of the data, then
                // the data itself.
                let at = head + ndims * 4;
                let size = le_uint(msg.get(at..)?, 0, 4).ok()? as usize;
                Some(Layout::Compact { size, at: at + 4 })
            }
            1 => {
                // The address, then the dimension sizes. The size of
                // the data is not in the message: the dataspace says
                // how big the dataset is.
                let addr = le_uint(msg.get(head..)?, 0, so).ok()?;
                Some(Layout::Contiguous { addr, size: 0 })
            }
            2 => {
                // The address of the B-tree that indexes the chunks,
                // and the size of a chunk in each of the dimensions.

                let addr = le_uint(msg.get(head..)?, 0, so).ok()?;
                let mut dims = Vec::with_capacity(ndims);
                for i in 0..ndims {
                    dims.push(le_uint(msg.get(head + so + 4 * i..)?, 0, 4).ok()?);
                }
                Some(Layout::Chunked {
                    index: ChunkIndex::Btree1 { addr },
                    dims,
                })
            }
            _ => None,
        }
    } else if version == 3 || version == 4 {
        // version, class
        let class = *msg.get(1)?;
        let head = 2;
        match class {
            0 => {
                let size = le_uint(msg.get(head..)?, 0, 2).ok()? as usize;
                Some(Layout::Compact { size, at: head + 2 })
            }
            1 => {
                let addr = le_uint(msg.get(head..)?, 0, so).ok()?;
                let size = le_uint(msg.get(head + so..)?, 0, sl).ok()?;
                Some(Layout::Contiguous { addr, size })
            }
            2 if version == 3 => {
                // The dimensionality, the address of the B-tree that
                // indexes the chunks, and the size of a chunk in each
                // of the dimensions.
                let ndims = *msg.get(head)? as usize;
                let addr = le_uint(msg.get(head + 1..)?, 0, so).ok()?;
                let mut dims = Vec::with_capacity(ndims);
                for i in 0..ndims {
                    dims.push(le_uint(msg.get(head + 1 + so + 4 * i..)?, 0, 4).ok()?);
                }
                Some(Layout::Chunked {
                    index: ChunkIndex::Btree1 { addr },
                    dims,
                })
            }
            // The fourth version of the message names the index that
            // holds the chunks.
            2 => chunked_layout_of_v4(msg, so, sl),
            _ => None,
        }
    } else {
        None
    }
}

/// The chunked layout of the fourth version of the layout message.
///
/// The message is the flags of the layout, the dimensionality, the width
/// of each dimension, the dimensions themselves, the type of the index
/// that holds the chunks, the parameters of that index, and the address
/// of the index.
///
/// The third version of the message has none of this: it always has a
/// v1 B-tree, and says nothing about it.
fn chunked_layout_of_v4(msg: &[u8], so: usize, sl: usize) -> Option<Layout> {
    let flags = *msg.get(2)?;
    let ndims = *msg.get(3)? as usize;
    // The width of each dimension: one to eight bytes.
    let width = *msg.get(4)? as usize;
    if width == 0 || width > 8 {
        return None;
    }
    let mut p = 5usize;
    let mut dims = Vec::with_capacity(ndims);
    for _ in 0..ndims {
        dims.push(le_uint(msg.get(p..)?, 0, width).ok()?);
        p += width;
    }
    // The type of the index, and then the parameters of that index.
    let kind = *msg.get(p)?;
    p += 1;
    let index = match kind {
        CHUNK_INDEX_SINGLE => {
            // The size of the chunk and the mask of its filters, when the
            // chunk was put through a filter.
            let mut nbytes = None;
            let mut filter_mask = 0u32;
            if flags & LAYOUT_SINGLE_WITH_FILTER != 0 {
                nbytes = Some(le_uint(msg.get(p..)?, 0, sl).ok()?);
                p += sl;
                filter_mask = le_uint(msg.get(p..)?, 0, 4).ok()? as u32;
                p += 4;
            }
            let addr = le_uint(msg.get(p..)?, 0, so).ok()?;
            ChunkIndex::Single {
                addr,
                nbytes,
                filter_mask,
            }
        }
        CHUNK_INDEX_IMPLICIT => {
            let addr = le_uint(msg.get(p..)?, 0, so).ok()?;
            ChunkIndex::Implicit { addr }
        }
        CHUNK_INDEX_FIXED_ARRAY => {
            // The number of bits needed to store the number of elements
            // in a page of the array.
            p += 1;
            let addr = le_uint(msg.get(p..)?, 0, so).ok()?;
            ChunkIndex::FixedArray { addr }
        }
        CHUNK_INDEX_EXTENSIBLE_ARRAY => {
            // The five parameters of the array.
            p += 5;
            let addr = le_uint(msg.get(p..)?, 0, so).ok()?;
            ChunkIndex::ExtensibleArray { addr }
        }
        CHUNK_INDEX_BTREE2 => {
            // The size of a node of the tree, and the percentages at
            // which it splits and merges.
            p += 6;
            let addr = le_uint(msg.get(p..)?, 0, so).ok()?;
            ChunkIndex::Btree2 { addr }
        }
        _ => return None,
    };
    Some(Layout::Chunked { index, dims })
}

/// The text of one element of a type, as the type gives it.
///
/// `None` for a type this reader does not decode: a number that is not
/// a number is a lie.
fn element_text(ty: &Type, bytes: &[u8]) -> Option<String> {
    match ty.class {
        DT_INTEGER | DT_FLOAT | DT_STRING => {
            atomic_text(ty.class, ty.size, ty.signed, ty.big_endian, bytes)
        }
        DT_ENUM => {
            // The value of an enumeration is the number its base type
            // holds; the name of the member is what the file calls it.
            let value = atomic_text(DT_INTEGER, ty.size, ty.signed, ty.big_endian, bytes)?;
            for (name, holds) in &ty.members {
                if *holds == value {
                    return Some(format!("{name} ({value})"));
                }
            }
            Some(value)
        }
        DT_COMPOUND => {
            // A compound is a record: each of its members sits at its
            // own offset inside it.
            let mut parts = Vec::with_capacity(ty.fields.len());
            for f in &ty.fields {
                let b = bytes.get(f.offset..f.offset + f.size)?;
                let text = atomic_text(f.class, f.size, f.signed, f.big_endian, b)?;
                parts.push(format!("{}: {text}", f.name));
            }
            Some(format!("{{{}}}", parts.join(", ")))
        }
        _ => None,
    }
}

/// The text of one element of an atomic type: an integer, a float or a
/// string.
fn atomic_text(
    class: u8,
    size: usize,
    signed: bool,
    big_endian: bool,
    bytes: &[u8],
) -> Option<String> {
    match class {
        DT_INTEGER => Some(integer_text(bytes, signed, big_endian)),
        DT_FLOAT => {
            if size == 4 {
                let mut b = [0u8; 4];
                b.copy_from_slice(bytes.get(..4)?);
                let x = if big_endian {
                    f32::from_be_bytes(b) as f64
                } else {
                    f32::from_le_bytes(b) as f64
                };
                Some(float_text(x))
            } else if size == 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(bytes.get(..8)?);
                let x = if big_endian {
                    f64::from_be_bytes(b)
                } else {
                    f64::from_le_bytes(b)
                };
                Some(float_text(x))
            } else {
                None
            }
        }
        DT_STRING => {
            if size == u32::MAX as usize {
                // A string with no fixed length is a handle into a
                // heap, not the text itself.
                return None;
            }
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            match core::str::from_utf8(&bytes[..end]) {
                Ok(text) => Some(text.to_string()),
                // Not text: the bytes are what they are.
                Err(_) => Some(hex_bytes(&bytes[..end])),
            }
        }
        _ => None,
    }
}

/// The index of the element at `flat` in a dataset of this shape: one
/// number per dimension, the last one counting fastest.
fn element_index(shape: &[u64], flat: u64) -> Vec<u64> {
    if shape.is_empty() {
        return Vec::new();
    }
    let mut index = vec![0u64; shape.len()];
    let mut rest = flat;
    for i in (0..shape.len()).rev() {
        let n = shape[i].max(1);
        index[i] = rest % n;
        rest /= n;
    }
    index
}

/// Whether an attribute message holds the attribute `name` with the value
/// `value`.
fn attribute_is(msg: &[u8], sl: usize, name: &[u8], value: &[u8]) -> bool {
    let Some(raw) = attribute(msg, sl) else {
        return false;
    };
    raw.name == name && raw.value.starts_with(value)
}

/// What an attribute message says, before the value is decoded.
struct RawAttribute<'a> {
    /// The attribute's name, without the null that ends it.
    name: &'a [u8],
    /// The datatype's class: 0 is an integer, 1 a float, 3 a string.
    class: u8,
    /// Whether an integer is signed.
    signed: bool,
    /// Whether the bytes of a value are big-endian. The datatype says
    /// so: bit 0 of its class bit field is the byte order.
    big_endian: bool,
    /// The size of one element of the datatype, in bytes. A string
    /// whose size is `u32::MAX` has no fixed length.
    elem_size: usize,
    /// How many elements the attribute holds.
    nelmts: u64,
    /// The value's bytes.
    value: &'a [u8],
}

/// The name and the raw value of an attribute message.
fn attribute(msg: &[u8], sl: usize) -> Option<RawAttribute<'_>> {
    if msg.len() < 8 {
        return None;
    }
    let version = msg[0];
    if !(1..=3).contains(&version) {
        return None;
    }
    let name_len = u16::from_le_bytes([msg[2], msg[3]]) as usize;
    let dt_size = u16::from_le_bytes([msg[4], msg[5]]) as usize;
    let ds_size = u16::from_le_bytes([msg[6], msg[7]]) as usize;
    let mut p = 8usize;
    if version >= 3 {
        p += 1; // the name's character set
    }
    if name_len == 0 {
        return None;
    }
    let name = msg.get(p..p + name_len - 1)?;
    p += name_len;
    if version < 2 {
        p = (p + 7) & !7;
    }
    let dt = msg.get(p..p + dt_size)?;
    p += dt_size;
    if version < 2 {
        p = (p + 7) & !7;
    }
    let ds = msg.get(p..p + ds_size)?;
    p += ds_size;
    if version < 2 {
        p = (p + 7) & !7;
    }
    // The datatype's size, and the dataspace's number of elements, say
    // how long the value is.
    if dt.len() < 8 || ds.len() < 4 {
        return None;
    }
    let elem_size = u32::from_le_bytes([dt[4], dt[5], dt[6], dt[7]]) as usize;
    let ds_version = ds[0];
    let rank = ds[1] as usize;
    let ds_head = match ds_version {
        1 => 8,
        2 => 4,
        _ => return None,
    };
    if ds.len() < ds_head {
        return None;
    }
    // A dataspace with no elements at all: the value is empty, and
    // the file writes no bytes for it.
    let mut nelmts = 1u64;
    if ds_version == 2 && ds[3] == DS_NULL {
        nelmts = 0;
    } else {
        for i in 0..rank {
            let at = ds_head + i * sl;
            nelmts = nelmts.checked_mul(le_uint(ds.get(at..at + sl)?, 0, sl).ok()?)?;
        }
    }
    let bytes = (nelmts as usize).checked_mul(elem_size)?;
    let value = msg.get(p..p + bytes)?;
    Some(RawAttribute {
        name,
        // The class is the low nibble of the datatype's first byte, and
        // the sign of an integer is bit 3 of the class bit field, and
        // the byte order is bit 0 of it.
        class: dt[0] & 0x0f,
        signed: dt[1] & 0x08 != 0,
        big_endian: dt[1] & 0x01 != 0,
        elem_size,
        nelmts,
        value,
    })
}

/// A float, the way a person reads it: in full when the number is a
/// reasonable size, and in exponent form when the full form would be
/// a line of digits.
fn float_text(x: f64) -> String {
    if x.is_nan() || x.is_infinite() {
        return format!("{x}");
    }
    let a = x.abs();
    if a != 0.0 && (a >= 1e16 || a < 1e-4) {
        format!("{x:e}")
    } else {
        format!("{x}")
    }
}

/// How many elements the attribute holds: the number the dataspace
/// declares, and no more than the bytes it has.
fn element_count(raw: &RawAttribute<'_>, elem: usize) -> usize {
    if elem == 0 {
        return 0;
    }
    let declared = usize::try_from(raw.nelmts).unwrap_or(usize::MAX);
    declared.min(raw.value.len() / elem)
}

/// The value of an attribute, as the text a search can match.
///
/// The attribute's own datatype says what its bytes are. An attribute
/// may hold several elements -- an array of numbers, an array of
/// strings -- and each one is decoded on its own. A value of a type
/// this reader does not decode is reported as the bytes it is, in
/// hex: a number that is not a number is a lie.
fn attribute_value(raw: &RawAttribute<'_>) -> String {
    match raw.class {
        // An integer, in the order the datatype says, signed or not.
        0 => {
            let elem = raw.elem_size;
            if elem == 0 || elem > 8 {
                // An integer wider than 64 bits does not fit here.
                return hex_bytes(raw.value);
            }
            let count = element_count(raw, elem);
            let mut parts = Vec::with_capacity(count);
            for i in 0..count {
                let bytes = &raw.value[i * elem..(i + 1) * elem];
                parts.push(integer_text(bytes, raw.signed, raw.big_endian));
            }
            parts.join(", ")
        }
        // A float.
        1 => {
            let elem = raw.elem_size;
            if elem != 4 && elem != 8 {
                return hex_bytes(raw.value);
            }
            let count = element_count(raw, elem);
            let mut parts = Vec::with_capacity(count);
            for i in 0..count {
                let bytes = &raw.value[i * elem..(i + 1) * elem];
                if elem == 4 {
                    let mut b = [0u8; 4];
                    b.copy_from_slice(bytes);
                    let x = if raw.big_endian {
                        f32::from_be_bytes(b) as f64
                    } else {
                        f32::from_le_bytes(b) as f64
                    };
                    parts.push(float_text(x));
                } else {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(bytes);
                    let x = if raw.big_endian {
                        f64::from_be_bytes(b)
                    } else {
                        f64::from_le_bytes(b)
                    };
                    parts.push(float_text(x));
                }
            }
            parts.join(", ")
        }
        // A string: the text, with the padding nulls dropped.
        3 => {
            if raw.elem_size == u32::MAX as usize {
                // A string with no fixed length: the bytes are a handle
                // into a heap, not the text itself.
                return hex_bytes(raw.value);
            }
            let elem = raw.elem_size.max(1);
            let count = element_count(raw, elem);
            let mut parts = Vec::with_capacity(count);
            for i in 0..count {
                let bytes = &raw.value[i * elem..(i + 1) * elem];
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                match core::str::from_utf8(&bytes[..end]) {
                    Ok(text) => parts.push(text.to_string()),
                    // Not text: the bytes are what they are.
                    Err(_) => parts.push(hex_bytes(bytes)),
                }
            }
            parts.join(", ")
        }
        // Anything else: the bytes, in hex.
        _ => hex_bytes(raw.value),
    }
}

/// An integer of `bytes`, as the number the file holds: the bytes in
/// the order the type says, and the sign the type says.
///
/// An integer wider than 64 bits does not fit here, and is reported as
/// the bytes it is: a number that is not a number is a lie.
fn integer_text(bytes: &[u8], signed: bool, big_endian: bool) -> String {
    if bytes.is_empty() || bytes.len() > 8 {
        return hex_bytes(bytes);
    }
    let mut v = 0u64;
    if big_endian {
        for &b in bytes {
            v = (v << 8) | b as u64;
        }
    } else {
        for (j, &b) in bytes.iter().enumerate() {
            v |= (b as u64) << (8 * j);
        }
    }
    if signed {
        // The sign of the last byte carries into the rest.
        let bits = 8 * bytes.len();
        if bits < 64 && v & (1 << (bits - 1)) != 0 {
            v |= u64::MAX << bits;
        }
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// The bytes, in hex.
fn hex_bytes(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A little-endian unsigned integer of `n` bytes (1..=8).
fn le_uint(data: &[u8], at: usize, n: usize) -> Result<u64, String> {
    if n > 8 {
        return Err(format!("a {n}-byte integer is wider than 64 bits"));
    }
    let bytes = data
        .get(at..at + n)
        .ok_or_else(|| format!("a {n}-byte integer at {at} runs past the end of the data"))?;
    let mut v = 0u64;
    for (i, &b) in bytes.iter().enumerate() {
        v |= (b as u64) << (8 * i);
    }
    Ok(v)
}

/// The number of bytes the implementation uses to encode `limit`.
///
/// The implementation takes the highest bit of the limit and adds a
/// byte for it: the number of bytes is `log2(limit) / 8 + 1`. The
/// reader counted the bits of the limit instead, and the two disagree
/// for a limit of 128 to 255 -- which is where the width of a member
/// offset of a compound type, and the width of the record count of a
/// B-tree node, are read.
fn limit_enc_size(limit: u64) -> usize {
    if limit == 0 {
        return 1;
    }
    ((63 - limit.leading_zeros() as usize) / 8) + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec;

    /// The netCDF-4 file that keeps its names in a fractal heap.
    fn fixture() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/netcdf4-fractal-heap.nc"
        );
        std::fs::read(path).expect("the fractal-heap fixture is in the tree")
    }

    /// The `ncdump` output the netCDF library ships for that file: the
    /// oracle the reader has to agree with.
    fn oracle() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/netcdf4-fractal-heap.cdl"
        );
        std::fs::read(path).expect("the ncdump oracle is in the tree")
    }

    /// The names the oracle lists: the dimensions, then the variables.
    fn oracle_names() -> Vec<String> {
        let cdl = String::from_utf8_lossy(&oracle()).into_owned();
        let mut names = Vec::new();
        let mut section = 0u8;
        for line in cdl.lines() {
            if line.starts_with("dimensions:") {
                section = 1;
                continue;
            }
            if line.starts_with("variables:") {
                section = 2;
                continue;
            }
            if line.starts_with("data:") {
                section = 0;
                continue;
            }
            if section == 0 {
                continue;
            }
            let body = line.trim();
            if body.is_empty() || body.starts_with("//") {
                continue;
            }
            if section == 1 {
                names.push(body.split('=').next().unwrap_or("").trim().to_string());
            } else {
                // A variable declaration is indented once; an attribute
                // of the variable above it is indented twice.
                if line.starts_with("\t\t") {
                    continue;
                }
                let decl = body.split(';').next().unwrap_or("").trim();
                let head = decl.split('(').next().unwrap_or("").trim();
                if let Some(name) = head.split_whitespace().last() {
                    names.push(name.to_string());
                }
            }
        }
        names
    }

    /// The report the reader finds in the fixture.
    fn read_report() -> Report {
        let data = fixture();
        let so = data[9] as usize;
        let sl = data[10] as usize;
        let root = le_uint(&data[12 + so + so + sl..], 0, so).unwrap();
        report(&data, root, so, sl)
            .expect("the fixture reads")
            .expect("the fixture keeps its links in a fractal heap")
    }

    /// The links the reader finds in the fixture.
    fn read_links() -> Vec<Link> {
        read_report().links
    }

    /// The netCDF-4 file whose group keeps its names in its own object
    /// header, as link messages, and not in a fractal heap.
    fn compact_fixture() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/netcdf4-compact-links.nc"
        );
        std::fs::read(path).expect("the compact-links fixture is in the tree")
    }

    /// The `ncdump` output the netCDF library ships for that file: the
    /// oracle the reader has to agree with.
    fn compact_oracle() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/netcdf4-compact-links.cdl"
        );
        std::fs::read(path).expect("the compact-links oracle is in the tree")
    }

    /// The names the oracle lists: the types, then the dimensions, then
    /// the variables.
    fn compact_oracle_names() -> Vec<String> {
        let cdl = String::from_utf8_lossy(&compact_oracle()).into_owned();
        let mut names = Vec::new();
        let mut section = 0u8;
        for line in cdl.lines() {
            if line.starts_with("types:") {
                section = 1;
                continue;
            }
            if line.starts_with("dimensions:") {
                section = 2;
                continue;
            }
            if line.starts_with("variables:") {
                section = 3;
                continue;
            }
            if line.starts_with("data:") {
                section = 0;
                continue;
            }
            if section == 0 {
                continue;
            }
            let body = line.trim();
            if body.is_empty() || body.starts_with("//") {
                continue;
            }
            match section {
                // A type is declared as `compound name { ... };`. The
                // members inside the braces are fields of the type,
                // not names of the file, so only the line that opens
                // the type counts.
                1 => {
                    if body.ends_with('{') {
                        if let Some(name) = body.split_whitespace().nth(1) {
                            names.push(name.to_string());
                        }
                    }
                }
                // A dimension is `name = size ;`.
                2 => names.push(body.split('=').next().unwrap_or("").trim().to_string()),
                // A variable is `type name(dims) ;`. An attribute of
                // the variable above it is indented twice.
                _ => {
                    if line.starts_with("\t\t") {
                        continue;
                    }
                    let decl = body.split(';').next().unwrap_or("").trim();
                    let head = decl.split('(').next().unwrap_or("").trim();
                    if let Some(name) = head.split_whitespace().last() {
                        names.push(name.to_string());
                    }
                }
            }
        }
        names
    }

    /// The report the reader finds in the compact fixture.
    fn read_compact_report() -> Report {
        let data = compact_fixture();
        let so = data[9] as usize;
        let sl = data[10] as usize;
        let root = le_uint(&data[12 + so + so + sl..], 0, so).unwrap();
        report(&data, root, so, sl)
            .expect("the fixture reads")
            .expect("the fixture keeps its links in the object header")
    }

    /// The links the reader finds in the compact fixture.
    fn read_compact_links() -> Vec<Link> {
        read_compact_report().links
    }

    /// One attribute the oracle lists: the object that holds it, its
    /// name, and the value as the oracle writes it.
    struct OracleAttribute {
        /// The path of the object: empty for the root group.
        path: String,
        /// The attribute's name.
        name: String,
        /// The value, as the oracle writes it.
        value: Vec<u8>,
    }

    /// The attributes the oracle lists: the ones of the variables, and
    /// the global ones.
    ///
    /// `ncdump` writes an attribute as `<object>:<name> = <value> ;`,
    /// indented twice, with the object's name empty when the attribute
    /// is global.
    fn oracle_attributes() -> Vec<OracleAttribute> {
        let mut out = Vec::new();
        let mut section = 0u8;
        for line in oracle().split(|&b| b == b'\n') {
            let text = String::from_utf8_lossy(line);
            if text.starts_with("variables:") {
                section = 1;
                continue;
            }
            if text.starts_with("// global attributes:") {
                section = 2;
                continue;
            }
            if text.starts_with("data:") {
                section = 0;
                continue;
            }
            if section == 0 {
                continue;
            }
            // An attribute is indented twice; the data below is
            // indented once.
            if !line.starts_with(b"\t\t") || line.starts_with(b"\t\t\t") {
                continue;
            }
            let body = &line[2..];
            let Some(eq) = body.iter().position(|&b| b == b'=') else {
                continue;
            };
            let head = &body[..eq];
            let Some(colon) = head.iter().position(|&b| b == b':') else {
                continue;
            };
            let path = String::from_utf8_lossy(&head[..colon]).trim().to_string();
            let name = String::from_utf8_lossy(&head[colon + 1..])
                .trim()
                .to_string();
            // The value is kept as bytes: the oracle writes the bytes
            // of a string that is not text as they are.
            let value = trim_ascii(&body[eq + 1..]);
            let value = value.strip_suffix(b";").unwrap_or(value);
            out.push(OracleAttribute {
                path,
                name,
                value: trim_ascii(value).to_vec(),
            });
        }
        out
    }

    /// The bytes of a slice without the spaces around it.
    fn trim_ascii(bytes: &[u8]) -> &[u8] {
        let start = bytes
            .iter()
            .position(|&b| !b.is_ascii_whitespace())
            .unwrap_or(bytes.len());
        let end = bytes
            .iter()
            .rposition(|&b| !b.is_ascii_whitespace())
            .map(|i| i + 1)
            .unwrap_or(start);
        &bytes[start..end]
    }

    /// The bytes of the string the oracle writes: the quotes are off,
    /// and the `\177` escape is the byte it names.
    fn oracle_string(value: &[u8]) -> Vec<u8> {
        let inner = value
            .strip_prefix(b"\"")
            .and_then(|v| v.strip_suffix(b"\""))
            .unwrap_or(value);
        let mut out = Vec::with_capacity(inner.len());
        let mut i = 0;
        while i < inner.len() {
            if inner[i] == b'\\' && i + 3 < inner.len() {
                let escape = String::from_utf8_lossy(&inner[i + 1..i + 4]).into_owned();
                if let Ok(byte) = u8::from_str_radix(&escape, 8) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
            out.push(inner[i]);
            i += 1;
        }
        out
    }

    /// The numbers the oracle writes, with `ncdump`'s type decoration
    /// taken off: the `b` of a byte, the `s` of a short, the `f` of a
    /// float.
    fn oracle_numbers(value: &[u8]) -> Vec<f64> {
        String::from_utf8_lossy(value)
            .split(',')
            .filter_map(|token| {
                let t = token.trim();
                let t = t
                    .strip_suffix('b')
                    .or_else(|| t.strip_suffix('s'))
                    .unwrap_or(t);
                let t = t.strip_suffix('f').unwrap_or(t);
                let t = t.strip_suffix('.').unwrap_or(t);
                match t {
                    "Infinity" => Some(f64::INFINITY),
                    "-Infinity" => Some(f64::NEG_INFINITY),
                    _ => t.parse::<f64>().ok(),
                }
            })
            .collect()
    }

    /// Whether two numbers are the same number: `ncdump` writes a
    /// float with seven digits, and the reader writes all of them.
    fn numbers_agree(want: f64, got: f64) -> bool {
        if want.is_nan() || got.is_nan() {
            return want.is_nan() && got.is_nan();
        }
        if want.is_infinite() || got.is_infinite() {
            return want == got;
        }
        (want - got).abs() <= 1e-6 * want.abs().max(got.abs()).max(1.0)
    }

    /// The value the reader must give for the bytes the oracle writes:
    /// the text, when the bytes are text, and the bytes in hex when
    /// they are not.
    fn value_of(bytes: &[u8]) -> String {
        match core::str::from_utf8(bytes) {
            Ok(text) => text.to_string(),
            Err(_) => hex_bytes(bytes),
        }
    }

    /// The attribute of the report that the oracle names.
    fn reported<'a>(report: &'a Report, path: &str, name: &str) -> Option<&'a Attribute> {
        report
            .attributes
            .iter()
            .find(|a| a.path == path && a.name == name)
    }

    /// The report the reader finds in a MATLAB file, whose HDF5 part
    /// starts after the 512-byte header MATLAB writes in front of it.
    fn read_matlab(name: &str) -> Report {
        let path = format!("{}/testdata/{}", env!("CARGO_MANIFEST_DIR"), name);
        let data = std::fs::read(&path).expect("the fixture is in the tree");
        let at = data
            .windows(8)
            .position(|w| w == b"\x89HDF\r\n\x1a\n")
            .expect("the file holds an HDF5 part");
        let part = &data[at..];
        let superblock = superblock(part).expect("the fixture has a superblock");
        report(part, superblock.root_addr, superblock.so, superblock.sl)
            .expect("the fixture reads")
            .expect("the fixture keeps its names where the reader looks")
    }

    /// The report the reader finds in a fixture of the tree.
    fn read_fixture(name: &str) -> Report {
        let path = format!("{}/testdata/{}", env!("CARGO_MANIFEST_DIR"), name);
        let data = std::fs::read(&path).expect("the fixture is in the tree");
        let superblock = superblock(&data).expect("the fixture has a superblock");
        report(&data, superblock.root_addr, superblock.so, superblock.sl)
            .expect("the fixture reads")
            .expect("the fixture keeps its names where the reader looks")
    }

    /// The value of the attribute that the report holds.
    fn value_of_attribute(report: &Report, path: &str, name: &str) -> Option<String> {
        reported(report, path, name).map(|a| a.value.clone())
    }

    /// The values the report holds for a dataset, as the text of each
    /// of them.
    fn values_of(report: &Report, path: &str) -> Vec<String> {
        report
            .values
            .iter()
            .filter(|v| v.path == path)
            .map(|v| v.value.clone())
            .collect()
    }

    /// The numbers the `ncdump` oracle gives for the variables whose
    /// value is a number: the name of the variable and the numbers it
    /// holds.
    ///
    /// The oracle is the `.cdl` the netCDF library ships for the
    /// fixture. Its `data:` section holds the value of every variable,
    /// rendered with the types the file declares. A value with a string
    /// in it is a char, and its bytes are compared elsewhere.
    fn cdl_numbers(cdl: &str) -> BTreeMap<String, Vec<f64>> {
        let mut out = BTreeMap::new();
        let Some((_, data)) = cdl.split_once("data:") else {
            return out;
        };
        for entry in data.split(';') {
            let Some((name, value)) = entry.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }
            let mut numbers = Vec::new();
            let mut all_numbers = true;
            for part in value.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                match part.parse::<f64>() {
                    Ok(n) => numbers.push(n),
                    Err(_) => {
                        all_numbers = false;
                        break;
                    }
                }
            }
            if all_numbers && !numbers.is_empty() {
                out.insert(name.to_string(), numbers);
            }
        }
        out
    }

    #[test]
    fn the_class_of_a_layout_message_sits_in_a_different_byte_in_the_third_version() {
        // The first two versions put the class after the
        // dimensionality, and the third and the fourth put it right
        // after the version. Reading it in the wrong place gives a
        // class that does not exist, and the data of the dataset is
        // never found.
        let mut old = vec![2u8, 1, 1, 0, 0, 0, 0, 0];
        old.extend_from_slice(&[0x40u8, 0, 0, 0, 0, 0, 0, 0]); // the address
        old.extend_from_slice(&[0u8; 4]); // the dimension sizes
        match layout_of(&old, 8, 8) {
            Some(Layout::Contiguous { addr, size }) => {
                assert_eq!(addr, 0x40);
                assert_eq!(size, 0);
            }
            other => panic!("a contiguous layout: {other:?}"),
        }
        let mut new = vec![3u8, 1];
        new.extend_from_slice(&[0x40u8, 0, 0, 0, 0, 0, 0, 0]); // the address
        new.extend_from_slice(&[0x20u8, 0, 0, 0, 0, 0, 0, 0]); // the size
        match layout_of(&new, 8, 8) {
            Some(Layout::Contiguous { addr, size }) => {
                assert_eq!(addr, 0x40);
                assert_eq!(size, 0x20);
            }
            other => panic!("a contiguous layout: {other:?}"),
        }
        // A chunked dataset says where the tree that indexes its
        // chunks is, and how big a chunk is.
        let mut chunked = vec![3u8, 2, 2];
        chunked.extend_from_slice(&[0x40u8, 0, 0, 0, 0, 0, 0, 0]); // the address
        chunked.extend_from_slice(&[2u8, 0, 0, 0]); // the size of a chunk
        chunked.extend_from_slice(&[3u8, 0, 0, 0]); // and of the other
        match layout_of(&chunked, 8, 8) {
            Some(Layout::Chunked { index, dims }) => {
                assert_eq!(index.addr(), Some(0x40));
                assert_eq!(dims, vec![2, 3]);
            }
            other => panic!("a chunked layout: {other:?}"),
        }
    }

    #[test]
    fn the_index_of_an_element_says_where_it_sits() {
        // The last dimension counts fastest, the way the file stores
        // the elements.
        assert_eq!(element_index(&[4], 2), vec![2]);
        assert_eq!(element_index(&[3, 3], 0), vec![0, 0]);
        assert_eq!(element_index(&[3, 3], 1), vec![0, 1]);
        assert_eq!(element_index(&[3, 3], 3), vec![1, 0]);
        assert_eq!(element_index(&[3, 3], 8), vec![2, 2]);
        assert_eq!(element_index(&[2, 3, 4], 19), vec![1, 1, 3]);
        // A scalar has no index.
        assert!(element_index(&[], 0).is_empty());
    }

    #[test]
    fn the_values_of_a_dataset_are_read_from_where_the_file_stores_them() {
        // The compound of the compact-links file holds a float and a
        // double, and the oracle says what they are: `var = {1, -2}`.
        let report = read_fixture("netcdf4-compact-links.nc");
        assert_eq!(values_of(&report, "var"), vec!["{x: 1, y: -2}"]);
    }

    #[test]
    fn the_values_of_a_netcdf4_file_are_the_ones_the_oracle_gives() {
        // The oracle is the `ncdump` output the netCDF library ships
        // for exactly this file: its `data:` section holds the value
        // of every variable.
        let cdl = String::from_utf8_lossy(&oracle()).into_owned();
        let oracle = cdl_numbers(&cdl);
        assert!(oracle.len() > 100, "the oracle lists the variables");
        let report = read_report();
        // The reader's values, by dataset.
        let mut by_dataset: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for value in &report.values {
            by_dataset
                .entry(value.path.as_str())
                .or_default()
                .push(value.value.as_str());
        }
        let mut compared = 0usize;
        for (name, want) in &oracle {
            let Some(got) = by_dataset.get(name.as_str()) else {
                continue;
            };
            assert_eq!(got.len(), want.len(), "{name}");
            for (g, w) in got.iter().zip(want) {
                compared += 1;
                let g: f64 = g.parse().unwrap_or_else(|_| panic!("{name}: {g}"));
                // The floats are 32-bit in the file and `ncdump` prints
                // them with seven digits: the tolerance is the
                // precision of a float.
                assert!(
                    (g - w).abs() <= 1e-6 * w.abs().max(1.0),
                    "{name}: the oracle has {w}, the reader has {g}"
                );
            }
        }
        assert!(compared > 1000, "the comparison covered {compared} values");
    }

    #[test]
    fn the_shuffle_filter_is_undone() {
        // The shuffle filter interlaces the bytes of the elements: all
        // the bytes of the same position of every element are together.
        // Four elements of two bytes each shuffle from
        // 01 02 03 04 05 06 07 08 into 01 03 05 07 02 04 06 08.
        let data = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let shuffled = [0x01u8, 0x03, 0x05, 0x07, 0x02, 0x04, 0x06, 0x08];
        assert_eq!(unshuffle(&shuffled, 2), data);
        // A single-byte element has nothing to interlace.
        assert_eq!(unshuffle(&data, 1), data);
    }

    #[test]
    fn the_filters_of_a_chunk_are_undone() {
        // The Fletcher-32 filter appends a checksum of the data to the
        // chunk, and the reader takes the checksum off and checks it:
        // the file's own checksum is the oracle for the bytes.
        let report = read_fixture("test_filters_le.h5");
        assert_eq!(values_of(&report, "dset"), vec!["1", "1"]);
        assert!(report.truncated.is_empty(), "the chunk was read");
    }

    /// The deflate filter compresses the chunk, and the reader inflates it.
    ///
    /// The oracle is the producer's own source: the HDF5 library's
    /// `test/gen_deflate.c` writes a 100x200 dataset of native `int`,
    /// whose value at (i, j) is `j % 5`, in chunks of 50x50. Every value
    /// the reader reports has to be that dataset's value at that index.
    #[test]
    fn a_chunk_that_is_compressed_with_deflate_is_inflated() {
        let report = read_fixture("deflate.h5");
        assert!(
            report.truncated.is_empty(),
            "the chunk was not read: {:?}",
            report.truncated
        );
        let values: Vec<&Value> = report
            .values
            .iter()
            .filter(|v| v.path == "Dataset1")
            .collect();
        assert_eq!(values.len(), 20_000, "not every value was read");
        // The dataset is a hundred by two hundred, and the generator
        // wrote the value `j % 5` at (i, j) -- so the value at the
        // dataset's own k-th place is the one the k-th coordinate holds.
        // The index of a value is the dataset's coordinate and not the
        // chunk's: the chunk is fifty by fifty elements of four bytes.
        for (k, value) in values.iter().enumerate() {
            let i = (k / 200) as u64;
            let j = (k % 200) as u64;
            assert_eq!(
                value.index,
                vec![i, j],
                "the value at {k} is not at the coordinate it belongs to"
            );
            assert_eq!(
                value.value,
                (j % 5).to_string(),
                "the value at ({i}, {j}) is not the one the generator wrote"
            );
        }
    }

    #[test]
    fn the_names_of_an_old_style_group_are_read() {
        // A group in the old format keeps its names in a symbol table:
        // a tree that indexes the nodes of the table, and a local heap
        // that holds the names. The fixture is the HDF5 library's own
        // old-style group file: the only name in it is the one the
        // reader gives, and the group it names is empty.
        let report = read_fixture("group_old.h5");
        let names: Vec<&str> = report.links.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(names, vec!["old"]);
        assert!(matches!(report.links[0].kind, Kind::Group));
    }

    #[test]
    fn the_names_and_the_values_of_a_matlab_v73_file_are_read() {
        // The MATLAB v7.3 file is an HDF5 file whose groups keep their
        // names the old way, and the reader used to report the
        // internals of the file -- the heap, the tree, the symbol table
        // node -- instead of the variables.
        let report = read_matlab("matlab-v73.mat");
        let names: Vec<&str> = report.links.iter().map(|l| l.path.as_str()).collect();
        for name in ["d", "i8", "s", "easy", "sp", "struct_nested"] {
            assert!(names.contains(&name), "{name} in {names:?}");
        }
        // The groups below the root are read too.
        assert!(names.contains(&"#refs#/a"), "{names:?}");
        // The matrix `d` holds fifty numbers.
        let d: Vec<&str> = report
            .values
            .iter()
            .filter(|v| v.path == "d")
            .map(|v| v.value.as_str())
            .collect();
        assert_eq!(d.len(), 50);
        assert_eq!(d[0], "1");
        assert_eq!(d[49], "50");
    }

    #[test]
    fn the_values_of_a_chunked_dataset_are_read() {
        // The record variables of the netCDF-4 file are in chunks, and
        // the chunks are indexed by a v1 B-tree: the tree says where
        // each chunk is, how big it is on the disk, and where it
        // starts in the dataset. The oracle lists the same values:
        // `br = -128, 127`, `sr = -32768, 32767`,
        // `ir = -2147483648, 2147483647`.
        let report = read_report();
        assert_eq!(values_of(&report, "br"), vec!["-128", "127"]);
        assert_eq!(values_of(&report, "sr"), vec!["-32768", "32767"]);
        assert_eq!(values_of(&report, "ir"), vec!["-2147483648", "2147483647"]);
        // The float ones, at the ends of what a float can hold.
        assert_eq!(
            values_of(&report, "fr"),
            vec!["-3.4028230607370965e38", "3.4028230607370965e38"]
        );
        // Nothing was left unread: every dataset of the file was
        // read.
        assert!(
            report.truncated.is_empty(),
            "the reader left something out: {:?}",
            report.truncated
        );
    }

    #[test]
    fn a_small_file_reports_the_attributes_of_its_members() {
        // The provenance file has a group, a variable and a dimension,
        // each with an attribute of its own, and the file's own
        // attributes on the root group.
        let report = read_fixture("netcdf4-provenance.nc");
        assert_eq!(
            value_of_attribute(&report, "", "int_attr").as_deref(),
            Some("17"),
            "the file's own attribute"
        );
        assert_eq!(
            value_of_attribute(&report, "subgroup", "int_attr").as_deref(),
            Some("17"),
            "the group's attribute"
        );
        assert_eq!(
            value_of_attribute(&report, "int_var", "int_attr").as_deref(),
            Some("17"),
            "the variable's attribute"
        );
        assert_eq!(
            value_of_attribute(&report, "time", "CLASS").as_deref(),
            Some("DIMENSION_SCALE"),
            "the attribute that marks a dimension"
        );
        assert_eq!(
            value_of_attribute(&report, "time", "NAME").as_deref(),
            Some("time"),
            "the name of a dimension"
        );
        assert_eq!(
            value_of_attribute(&report, "time", "_Netcdf4Dimid").as_deref(),
            Some("0"),
            "the index of a dimension"
        );
        let properties =
            value_of_attribute(&report, "", "_NCProperties").expect("the file says who wrote it");
        assert!(
            properties.starts_with("version=1|netcdflibversion="),
            "the file's own properties: {properties}"
        );
    }

    #[test]
    fn a_dimension_says_which_dimension_it_is() {
        // The irish rover file: the dimension carries the name netCDF
        // gives it, padded to a fixed width, and the number of the
        // dimension it stands for.
        let report = read_fixture("netcdf4-irish-rover.nc");
        let name = value_of_attribute(&report, "dim", "NAME").expect("the dimension's name");
        assert!(
            name.starts_with("This is a netCDF dimension but not a netCDF variable."),
            "the name of the dimension: {name}"
        );
        assert!(name.ends_with('4'), "the name of the dimension: {name}");
        assert_eq!(
            value_of_attribute(&report, "dim", "CLASS").as_deref(),
            Some("DIMENSION_SCALE"),
            "the attribute that marks a dimension"
        );
        assert!(
            value_of_attribute(&report, "in_the_hold_of_the_Irish_Rover", "DIMENSION_LIST")
                .is_some(),
            "the variable that uses the dimension says so"
        );
    }

    #[test]
    fn every_attribute_the_oracle_lists_is_the_attribute_the_reader_reads() {
        // The oracle is the `ncdump` output the netCDF library ships
        // for exactly this file. It lists thirteen attributes: six
        // global ones and seven on variables.
        let report = read_report();
        let mut checked = 0;
        for attribute in oracle_attributes() {
            let found = reported(&report, &attribute.path, &attribute.name).unwrap_or_else(|| {
                panic!(
                    "the reader did not report the attribute {}:{}",
                    attribute.path, attribute.name
                )
            });
            checked += 1;
            if attribute.value.starts_with(b"\"") {
                // A string: the bytes are the text, when they are text.
                let want = value_of(&oracle_string(&attribute.value));
                assert_eq!(
                    found.value, want,
                    "the value of {}:{} differs",
                    attribute.path, attribute.name
                );
            } else {
                // Numbers: `ncdump` writes the type after each of them.
                let want = oracle_numbers(&attribute.value);
                let got: Vec<f64> = found
                    .value
                    .split(", ")
                    .map(|t| t.parse::<f64>().unwrap_or(f64::NAN))
                    .collect();
                assert_eq!(
                    want.len(),
                    got.len(),
                    "the number of values of {}:{} differs",
                    attribute.path,
                    attribute.name
                );
                for (w, g) in want.iter().zip(got.iter()) {
                    assert!(
                        numbers_agree(*w, *g),
                        "the value of {}:{} differs: the oracle says {w}, the reader says {g}",
                        attribute.path,
                        attribute.name
                    );
                }
            }
        }
        assert_eq!(checked, 13, "the oracle lists thirteen attributes");
    }

    #[test]
    fn the_only_attributes_the_oracle_does_not_list_are_the_ones_netcdf_writes_itself() {
        // `ncdump` does not print the attributes netCDF writes for its
        // own bookkeeping: the class and the name of a dimension
        // scale, the dimensions a variable uses, and the variables that
        // use a dimension. They are in the file, so the reader reads
        // them.
        const BOOKKEEPING: [&str; 5] = [
            "CLASS",
            "NAME",
            "DIMENSION_LIST",
            "REFERENCE_LIST",
            "_Netcdf4Dimid",
        ];
        let report = read_report();
        for attribute in &report.attributes {
            let listed = oracle_attributes()
                .iter()
                .any(|a| a.path == attribute.path && a.name == attribute.name);
            if listed {
                continue;
            }
            assert!(
                BOOKKEEPING.contains(&attribute.name.as_str()),
                "the reader reported {}:{}, which the oracle does not list and which netCDF does not write",
                attribute.path,
                attribute.name
            );
        }
    }

    #[test]
    fn a_global_attribute_belongs_to_the_file_and_not_to_a_member() {
        // The root group holds the file's own attributes, and the
        // reader gives them the empty path: they belong to no member.
        let report = read_report();
        let global: Vec<&str> = report
            .attributes
            .iter()
            .filter(|a| a.path.is_empty())
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(
            global,
            ["Gc", "Gb", "Gs", "Gi", "Gf", "Gd"],
            "the file carries six global attributes"
        );
    }

    #[test]
    fn a_group_with_compact_link_storage_gives_every_name_the_oracle_lists() {
        // A group with few enough members does not get a fractal heap:
        // HDF5 keeps its names in the group's own object header, as
        // link messages, and leaves the heap's address undefined. The
        // reader used to look for a heap, find none, and fall back to
        // the printable strings it could see.
        let names: Vec<String> = read_compact_links().into_iter().map(|l| l.path).collect();
        let want = compact_oracle_names();
        assert_eq!(
            names, want,
            "the reader and the oracle disagree on the names"
        );
    }

    #[test]
    fn a_compact_group_says_what_its_members_are() {
        let links = read_compact_links();
        let kind = |name: &str| {
            links
                .iter()
                .find(|l| l.path == name)
                .map(|l| l.kind.clone())
                .unwrap_or(Kind::Unreadable {
                    reason: "<missing>".to_string(),
                })
        };
        assert!(
            matches!(
                kind("cmp_t"),
                Kind::Datatype {
                    dtype: Some(ref d)
                } if d == "compound"
            ),
            "a committed type is a type, not a dataset: {:?}",
            kind("cmp_t")
        );
        assert!(
            matches!(
                kind("n"),
                Kind::Dataset {
                    dtype: Some(ref d),
                    dims: Some(ref dims),
                    dimension_scale: true,
                } if d == "float32" && dims == &[1]
            ),
            "netCDF marks a dimension with an attribute: {:?}",
            kind("n")
        );
        assert!(
            matches!(
                kind("var"),
                Kind::Dataset {
                    dtype: Some(ref d),
                    dims: Some(ref dims),
                    dimension_scale: false,
                } if d == "compound" && dims == &[1]
            ),
            "a variable on a committed type says so: {:?}",
            kind("var")
        );
    }

    #[test]
    fn the_reader_never_panics_on_a_mutated_compact_fixture() {
        let data = compact_fixture();
        rgx_core::fuzzkit::assert_never_panics(
            vec![("compact-links", data.clone())],
            200,
            "hdf5-compact-links",
            |d| {
                let _ = report(d, 0x30, 8, 8);
            },
        );
    }

    #[test]
    fn the_fractal_heap_gives_every_name_the_oracle_lists() {
        // The claim this closes: the newest netCDF-4 layout keeps the
        // group and variable names in a fractal heap, and the reader
        // used to report the superblock and nothing else.
        let names: Vec<String> = read_links().into_iter().map(|l| l.path).collect();
        let want = oracle_names();
        assert_eq!(
            names.len(),
            want.len(),
            "the reader and the oracle disagree on the count"
        );
        assert_eq!(
            names, want,
            "the reader and the oracle disagree on the names"
        );
    }

    #[test]
    fn the_dimensions_are_the_ones_the_oracle_calls_dimensions() {
        // netCDF marks a dimension by giving its dataset the attribute
        // `CLASS = DIMENSION_SCALE`; the oracle lists five of them.
        let links = read_links();
        let dims: Vec<&str> = links
            .iter()
            .filter(|l| {
                matches!(
                    l.kind,
                    Kind::Dataset {
                        dimension_scale: true,
                        ..
                    }
                )
            })
            .map(|l| l.path.as_str())
            .collect();
        assert_eq!(dims, ["Dr", "D1", "D2", "D3", "D4"]);
    }

    #[test]
    fn a_dataset_reports_the_type_the_file_gives_it() {
        let links = read_links();
        let kind = |name: &str| {
            links
                .iter()
                .find(|l| l.path == name)
                .map(|l| l.kind.clone())
                .unwrap_or(Kind::Unreadable {
                    reason: "<missing>".to_string(),
                })
        };
        let dtype_of = |name: &str| match kind(name) {
            Kind::Dataset { dtype, .. } => dtype,
            _ => None,
        };
        let dims_of = |name: &str| match kind(name) {
            Kind::Dataset { dims, .. } => dims,
            _ => None,
        };
        assert_eq!(
            dtype_of("d").as_deref(),
            Some("float64"),
            "a netCDF double is an HDF5 float64"
        );
        assert_eq!(
            dtype_of("i").as_deref(),
            Some("int32"),
            "a netCDF int is an HDF5 int32"
        );
        assert_eq!(
            dtype_of("c").as_deref(),
            Some("char"),
            "a netCDF char is an HDF5 one-byte string"
        );
        assert_eq!(
            dims_of("cr"),
            Some(vec![2]),
            "a variable on the unlimited dimension has two elements"
        );
        assert_eq!(
            dims_of("c"),
            Some(vec![]),
            "a scalar variable has no dimensions"
        );
    }

    #[test]
    fn a_truncated_file_is_refused_with_a_reason() {
        // A file cut before the fractal heap has a superblock and an
        // object header, but no heap to walk.
        let data = fixture();
        let cut = &data[..0x1000];
        let so = cut[9] as usize;
        let sl = cut[10] as usize;
        let root = le_uint(&cut[12 + so + so + sl..], 0, so).unwrap();
        let err = report(cut, root, so, sl).expect_err("a truncated file does not read");
        assert!(!err.is_empty(), "the refusal says why");
    }

    #[test]
    fn a_hostile_file_is_refused_with_a_reason() {
        // Every byte of the heap header replaced by 0xff: the table's
        // width is no longer a power of two, and the reader has to say
        // so rather than walk off the end of the file.
        let mut data = fixture();
        for b in data[0x101a..0x101a + 64].iter_mut() {
            *b = 0xff;
        }
        let so = data[9] as usize;
        let sl = data[10] as usize;
        let root = le_uint(&data[12 + so + so + sl..], 0, so).unwrap();
        let err = report(&data, root, so, sl).expect_err("a hostile file does not read");
        assert!(!err.is_empty(), "the refusal says why");
    }

    #[test]
    fn the_reader_never_panics_on_a_mutated_fixture() {
        let data = fixture();
        rgx_core::fuzzkit::assert_never_panics(
            vec![("fractal-heap", data.clone())],
            200,
            "hdf5-fractal-heap",
            |d| {
                let _ = report(d, 0x30, 8, 8);
            },
        );
    }

    #[test]
    fn the_reader_never_panics_on_a_mutated_latest_format_fixture() {
        // The file of the latest format: the reader walks the chunk
        // indexes of that format, and a mutated one has to make it say
        // why it does not read, not panic.
        let data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/hdf5/h5fc_ext1_f.h5"
        ))
        .expect("the latest-format fixture is in the tree");
        rgx_core::fuzzkit::assert_never_panics(
            vec![("latest-format", data.clone())],
            200,
            "hdf5-latest-format",
            |d| {
                let _ = report(d, 0x89, 8, 8);
            },
        );
    }

    #[test]
    fn an_integer_is_read_in_the_order_the_datatype_says() {
        // The datatype says which order its bytes are in: bit 0 of the
        // class bit field. The reader used to read every value in the
        // little-endian order, whatever the file said.
        assert_eq!(integer_text(&[0x01, 0x02], false, false), "513");
        assert_eq!(integer_text(&[0x01, 0x02], false, true), "258");
        assert_eq!(integer_text(&[0xff], true, false), "-1");
        assert_eq!(integer_text(&[0xff], true, true), "-1");
        assert_eq!(integer_text(&[0xff, 0x00], true, false), "255");
        assert_eq!(integer_text(&[0xff, 0x00], true, true), "-256");
        // An integer wider than 64 bits is reported as the bytes it is.
        assert_eq!(
            integer_text(&[1, 2, 3, 4, 5, 6, 7, 8, 9], false, false),
            "010203040506070809"
        );
    }

    #[test]
    fn a_float_is_read_in_the_order_the_datatype_says() {
        let big = 1.0f64.to_be_bytes();
        let little = 1.0f64.to_le_bytes();
        fn raw<'a>(big_endian: bool, value: &'a [u8]) -> RawAttribute<'a> {
            RawAttribute {
                name: b"f",
                class: 1,
                signed: false,
                big_endian,
                elem_size: 8,
                nelmts: 1,
                value,
            }
        }
        assert_eq!(attribute_value(&raw(true, &big)), "1");
        assert_eq!(attribute_value(&raw(false, &little)), "1");
    }

    /// The members the oracle lists for the type: the name of each
    /// member, and the type it holds, as `ncdump` writes it.
    fn compact_oracle_members() -> Vec<(String, String)> {
        let cdl = String::from_utf8_lossy(&compact_oracle()).into_owned();
        let mut out = Vec::new();
        let mut inside = false;
        for line in cdl.lines() {
            let body = line.trim();
            if body.starts_with("compound ") {
                inside = true;
                continue;
            }
            if !inside {
                continue;
            }
            if body.starts_with('}') {
                inside = false;
                continue;
            }
            // A member is `type name ;`.
            let decl = body.trim_end_matches(';').trim();
            let mut parts = decl.split_whitespace();
            let ty = parts.next().unwrap_or("").to_string();
            let name = parts.next().unwrap_or("").to_string();
            out.push((name, ty));
        }
        out
    }

    #[test]
    fn every_member_the_oracle_names_is_the_member_the_reader_reads() {
        // The oracle is the `ncdump` output the netCDF library ships
        // for exactly this file: it declares the type `cmp_t` and its
        // members inside the braces.
        let want = compact_oracle_members();
        assert_eq!(
            want,
            [
                ("x".to_string(), "float".to_string()),
                ("y".to_string(), "double".to_string()),
            ],
            "the oracle lists two members"
        );
        let report = read_fixture("netcdf4-compact-links.nc");
        let got: Vec<(String, String)> = report
            .members
            .iter()
            .filter(|m| m.path == "cmp_t")
            .map(|m| (m.name.clone(), m.holds.clone()))
            .collect();
        // `ncdump` writes the type of a member the way the language
        // writes it; the reader writes the type the file's own
        // datatype message says.
        let same: Vec<(String, String)> = want
            .iter()
            .map(|(name, ty)| {
                let holds = match ty.as_str() {
                    "float" => "float32",
                    "double" => "float64",
                    other => other,
                };
                (name.clone(), holds.to_string())
            })
            .collect();
        assert_eq!(
            got, same,
            "the reader and the oracle disagree on the members of the type"
        );
    }

    #[test]
    fn the_members_of_an_enumeration_are_the_names_and_the_values_the_source_gives() {
        // The oracle is the source that wrote the file: the netCDF
        // library's own test, `nc_test4/tst_enums.c`, defines the type
        // "cargo" with eight members, and the values it gives them.
        let report = read_fixture("netcdf4-irish-rover.nc");
        let got: Vec<(&str, &str)> = report
            .members
            .iter()
            .filter(|m| m.path == "cargo")
            .map(|m| (m.name.as_str(), m.holds.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("bags of the best Sligo rags", "1000000"),
                ("barrels of bones", "2000000"),
                ("bails of old nanny goats' tails", "3000000"),
                ("barrels of stones", "4000000"),
                ("dogs", "5000000"),
                ("hogs", "6000000"),
                ("barrels of porter", "7000000"),
                ("sides of old blind horses hides", "8000000"),
            ],
            "the reader and the source disagree on the members of the enumeration"
        );
    }

    /// The HDF5 file the library wrote with the latest format: its
    /// datasets are indexed by the chunk indexes of the latest format.
    ///
    /// The file is the one the HDF5 library's own `h5format_convert`
    /// tests ship, `tools/h5format_convert/testfiles/h5fc_ext1_f.h5`,
    /// written by `tools/h5format_convert/h5fc_gentest.c` with the latest
    /// format bounds. The generator is the oracle: it writes a four by
    /// six dataset of native `int`, in chunks of two by three, whose
    /// value at (i, j) is `i * 6 + j`.
    fn read_latest_fixture() -> Report {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/hdf5/h5fc_ext1_f.h5");
        let data = std::fs::read(path).expect("the latest-format fixture is in the tree");
        let superblock = superblock(&data).expect("the fixture has a superblock");
        report(&data, superblock.root_addr, superblock.so, superblock.sl)
            .expect("the fixture reads")
            .expect("the fixture keeps its names where the reader looks")
    }

    #[test]
    fn the_chunks_of_the_latest_format_are_read() {
        // The file holds one dataset for each of the chunk indexes of the
        // latest format that carries data: the implicit index, the fixed
        // array and the v2 B-tree. The generator wrote the same twenty
        // four values in each of them, so the reader has to give the same
        // twenty four values at the same coordinates in each.
        let report = read_latest_fixture();
        for path in ["DSET_NONE", "DSET_FA", "DSET_EA", "GROUP/DSET_BT2"] {
            let values: Vec<&Value> = report.values.iter().filter(|v| v.path == path).collect();
            assert_eq!(values.len(), 24, "{path}: not every value was read");
            for (k, value) in values.iter().enumerate() {
                let i = (k / 6) as u64;
                let j = (k % 6) as u64;
                assert_eq!(
                    value.index,
                    vec![i, j],
                    "{path}: the value at {k} is not at the coordinate it belongs to"
                );
                assert_eq!(
                    value.value,
                    (i * 6 + j).to_string(),
                    "{path}: the value at ({i}, {j}) is not the one the generator wrote"
                );
            }
        }
    }

    #[test]
    fn the_extensible_array_is_read() {
        // The extensible array is the index of a dataset with a dimension
        // of unlimited extent. Its array puts that dimension first, so
        // that the array grows by appending, and the reader has to place
        // the chunks the same way the library did.
        let report = read_latest_fixture();
        let values: Vec<&Value> = report
            .values
            .iter()
            .filter(|v| v.path == "DSET_EA")
            .collect();
        assert_eq!(values.len(), 24, "not every value was read");
        for (k, value) in values.iter().enumerate() {
            let i = (k / 6) as u64;
            let j = (k % 6) as u64;
            assert_eq!(
                value.index,
                vec![i, j],
                "the value at {k} is not at the coordinate it belongs to"
            );
            assert_eq!(
                value.value,
                (i * 6 + j).to_string(),
                "the value at ({i}, {j}) is not the one the generator wrote"
            );
        }
    }

    #[test]
    fn the_fourth_version_of_the_layout_message_names_the_index() {
        // The fourth version of the layout message says which index holds
        // the chunks: the flags, the dimensionality, the width of each
        // dimension, the dimensions themselves, the type of the index,
        // the parameters of that index, and the address of the index.
        //
        // No file in the tree uses the single chunk index -- the library
        // picks it for a dataset that is one chunk, and none of the
        // fixtures is -- so the messages are built here, the way the file
        // format specification says they are.
        let message = |kind: u8, params: &[u8]| -> Vec<u8> {
            let mut msg = vec![4u8, 2, 0, 2, 4];
            msg.extend_from_slice(&[2u8, 0, 0, 0]); // the first dimension
            msg.extend_from_slice(&[3u8, 0, 0, 0]); // the second
            msg.push(kind); // the type of the index
            msg.extend_from_slice(params); // the parameters of the index
            msg.extend_from_slice(&[0x40u8, 0, 0, 0, 0, 0, 0, 0]); // the address of the index
            msg
        };
        // The single chunk index: the dataset has one chunk, and the
        // message gives its address.
        match layout_of(&message(CHUNK_INDEX_SINGLE, &[]), 8, 8) {
            Some(Layout::Chunked { index, dims }) => {
                assert_eq!(dims, vec![2, 3]);
                match index {
                    ChunkIndex::Single {
                        addr,
                        nbytes,
                        filter_mask,
                    } => {
                        assert_eq!(addr, 0x40);
                        assert_eq!(nbytes, None);
                        assert_eq!(filter_mask, 0);
                    }
                    other => panic!("a single chunk index: {other:?}"),
                }
            }
            other => panic!("a chunked layout: {other:?}"),
        }
        // The same message with the flag that says the chunk was put
        // through a filter carries the size of the chunk and the mask of
        // its filters before the address.
        let mut filtered = message(CHUNK_INDEX_SINGLE, &[]);
        filtered[2] = LAYOUT_SINGLE_WITH_FILTER;
        let at = filtered.len() - 8;
        filtered.splice(at..at, [24u8, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0]);
        match layout_of(&filtered, 8, 8) {
            Some(Layout::Chunked { index, .. }) => match index {
                ChunkIndex::Single {
                    addr,
                    nbytes,
                    filter_mask,
                } => {
                    assert_eq!(addr, 0x40);
                    assert_eq!(nbytes, Some(24));
                    assert_eq!(filter_mask, 2);
                }
                other => panic!("a single chunk index: {other:?}"),
            },
            other => panic!("a chunked layout: {other:?}"),
        }
        // The implicit index: the chunks are an array, and the message
        // gives the address of the array.
        match layout_of(&message(CHUNK_INDEX_IMPLICIT, &[]), 8, 8) {
            Some(Layout::Chunked { index, .. }) => match index {
                ChunkIndex::Implicit { addr } => assert_eq!(addr, 0x40),
                other => panic!("an implicit index: {other:?}"),
            },
            other => panic!("a chunked layout: {other:?}"),
        }
        // The fixed array: the parameter is the number of bits needed to
        // store the number of elements in a page of the array.
        match layout_of(&message(CHUNK_INDEX_FIXED_ARRAY, &[10]), 8, 8) {
            Some(Layout::Chunked { index, .. }) => match index {
                ChunkIndex::FixedArray { addr } => assert_eq!(addr, 0x40),
                other => panic!("a fixed array: {other:?}"),
            },
            other => panic!("a chunked layout: {other:?}"),
        }
        // The extensible array: five parameters.
        match layout_of(
            &message(CHUNK_INDEX_EXTENSIBLE_ARRAY, &[32, 4, 16, 4, 10]),
            8,
            8,
        ) {
            Some(Layout::Chunked { index, .. }) => match index {
                ChunkIndex::ExtensibleArray { addr } => assert_eq!(addr, 0x40),
                other => panic!("an extensible array: {other:?}"),
            },
            other => panic!("a chunked layout: {other:?}"),
        }
        // The v2 B-tree: the size of a node of the tree, and the
        // percentages at which it splits and merges.
        match layout_of(&message(CHUNK_INDEX_BTREE2, &[0, 0, 32, 0, 100, 40]), 8, 8) {
            Some(Layout::Chunked { index, .. }) => match index {
                ChunkIndex::Btree2 { addr } => assert_eq!(addr, 0x40),
                other => panic!("a v2 B-tree: {other:?}"),
            },
            other => panic!("a chunked layout: {other:?}"),
        }
    }

    #[test]
    fn the_filters_the_reader_does_not_undo_are_named() {
        // The second version of the pipeline message names only the
        // filters that are not built into the library, so the reader
        // knows the three it does not undo by their number alone: the
        // szip, the nbit and the scale-offset. A refusal has to say which
        // filter it is, and a number is not a name.
        let filter = |id: u16| Filter {
            id,
            name: String::new(),
            cd: Vec::new(),
        };
        assert_eq!(filter_name(&filter(4)), "szip");
        assert_eq!(filter_name(&filter(5)), "nbit");
        assert_eq!(filter_name(&filter(6)), "scale-offset");
        // A filter the file names keeps the name the file gives it.
        let named = Filter {
            id: 32004,
            name: "lz4".to_string(),
            cd: Vec::new(),
        };
        assert_eq!(filter_name(&named), "lz4");
    }

    #[test]
    fn a_type_the_file_stores_twice_is_listed_once() {
        // The irish rover file stores the enumeration twice: once as
        // the committed type "cargo", and once inside the variable
        // that uses it. The reader lists the eight members once.
        let report = read_fixture("netcdf4-irish-rover.nc");
        assert_eq!(
            report.members.len(),
            8,
            "the file has eight members of the enumeration, and the reader lists them once"
        );
        assert!(
            report.members.iter().all(|m| m.path == "cargo"),
            "the members belong to the committed type: {:?}",
            report.members
        );
    }
}
