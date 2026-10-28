// SPDX-License-Identifier: Apache-2.0

//! SquashFS 4.0 reader.
//!
//! A SquashFS image is three metadata tables and a pile of data blocks:
//! inodes, a directory listing, and a fragment table, each stored as a chain
//! of metadata blocks whose payloads may be compressed with the image's own
//! codec. A metadata offset is a 64-bit `(block << 16 | offset-in-block)`
//! pair, which is why the format reads as opaque numbers until you know
//! that.
//!
//! The part worth spelling out is where a file's bytes physically live.
//! Data blocks are laid out from offset 0 **in inode-table order**, and each
//! inode stores only the block *sizes*. So the running position is recovered
//! by walking the inode table front to back and accumulating, which is why
//! this walks every inode before it reads a single directory entry — a
//! per-file search for "where does this extent start" has no answer, and an
//! implementation that guessed one would produce plausible wrong bytes.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::budget::MemberSink;
use rgx_core::compress;
use rgx_core::{bail, decline, Adapter, Outcome, Result};

const MAGIC: u32 = 0x7371_7368; // "hsqs"

const INODE_DIR: u16 = 1;
const INODE_FILE: u16 = 2;
const INODE_SYMLINK: u16 = 3;
const INODE_LDIR: u16 = 8;
const INODE_LREG: u16 = 9;
const INODE_LSYMLINK: u16 = 10;

const FLAG_UNCOMPRESSED_INODES: u16 = 0x0001;
const FLAG_UNCOMPRESSED_DATA: u16 = 0x0002;
const FLAG_UNCOMPRESSED_FRAGMENTS: u16 = 0x0008;
const FLAG_NO_FRAGMENTS: u16 = 0x0010;

/// The sparse flag and the size share a word; the size is the low 24 bits.
const BLOCK_SPARSE: u32 = 0x0100_0000;
const BLOCK_SIZE_MASK: u32 = 0x00FF_FFFF;

const NO_FRAGMENT: u32 = 0xFFFF_FFFF;

fn le16(d: &[u8], p: usize) -> Option<u16> {
    let b = d.get(p..p + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn le32(d: &[u8], p: usize) -> Option<u32> {
    let b = d.get(p..p + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le64(d: &[u8], p: usize) -> Option<u64> {
    let b = d.get(p..p + 8)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

struct Super {
    inode_count: u32,
    block_size: u32,
    compression: u16,
    flags: u16,
    root_inode: u64,
    bytes_used: u64,
    fragments: u32,
    id_count: u16,
    fragment_table: u64,
    inode_table: u64,
    directory_table: u64,
    id_table: u64,
    lookup_table: u64,
}

/// Where the data blocks begin: immediately after the last metadata table.
///
/// A file's inode stores only the *sizes* of its data blocks, so the reader
/// has to know where the first one is, and the superblock says so only
/// indirectly — the tables are contiguous and the data follows them. The
/// last table is the export table when the image has one (its entries are
/// 16 bytes each) and the id index otherwise (4 bytes each), and both
/// carry one more entry than they have ids, because the trailing one is the
/// terminator. Assuming offset zero instead lands in the superblock and
/// hands every file the image's own header bytes.
fn blocks_start(sup: &Super) -> u64 {
    let ids = sup.id_count as u64 + 1;
    let frag_end = sup
        .fragment_table
        .saturating_add((sup.fragments as u64 + 1) * 8);
    let id_end = sup.id_table.saturating_add(ids * 4);
    let export_end = sup.lookup_table.saturating_add(ids * 16);
    frag_end
        .max(id_end)
        .max(export_end)
        .max(sup.inode_table)
        .max(sup.directory_table)
}

fn parse_super(d: &[u8]) -> Option<Super> {
    if le32(d, 0) != Some(MAGIC) {
        return None;
    }
    let major = le16(d, 28)?;
    if major != 4 {
        return None;
    }
    Some(Super {
        inode_count: le32(d, 4)?,
        fragments: le32(d, 16)?,
        id_count: le16(d, 26)?,
        block_size: le32(d, 12)?,
        compression: le16(d, 20)?,
        flags: le16(d, 24)?,
        root_inode: le64(d, 32)?,
        bytes_used: le64(d, 40)?,
        fragment_table: le64(d, 80)?,
        inode_table: le64(d, 64)?,
        directory_table: le64(d, 72)?,
        id_table: le64(d, 48)?,
        lookup_table: le64(d, 88)?,
    })
}

fn codec_name(c: u16) -> &'static str {
    match c {
        1 => "gzip",
        2 => "lzma",
        3 => "lzo",
        4 => "xz",
        5 => "lz4",
        6 => "zstd",
        _ => "unknown",
    }
}

/// Decode one compressed block. `limit` is the byte budget a single block
/// may expand to: without it a 128 KiB block claiming a gigabyte is the
/// cheapest denial of service in the whole format, and the budget is what
/// stops it *as it is emitted* rather than after the damage.
fn decompress(comp: u16, raw: &[u8], limit: u64) -> Option<Vec<u8>> {
    match comp {
        1 => compress::DeflateDecoder::new()
            .decode_bounded(raw, limit)
            .ok()
            .map(|b| b.bytes),
        2 => compress::lzma::LzmaDecoder::new()
            .decode_bounded(raw, limit)
            .ok()
            .map(|b| b.bytes),
        4 => compress::XzReader::decompress_bounded(raw, limit)
            .ok()
            .map(|b| b.bytes),
        5 => crate::lz4::Lz4Decoder::new().decode_legacy(raw).ok(),
        6 => compress::ZstdDecoder::new()
            .decode_bounded(raw, limit)
            .ok()
            .map(|b| b.bytes),
        _ => None,
    }
}

struct Meta<'a> {
    data: &'a [u8],
    super_: &'a Super,
}

impl<'a> Meta<'a> {
    /// Read the metadata block holding `meta_off` and report where the next
    /// one starts. A metadata offset is `(block << 16) | offset`, and the
    /// block's own 2-byte header says whether the payload that follows is
    /// stored or compressed.
    fn block_at(&self, table: u64, meta_off: u64, stored_flag: bool) -> Option<(Vec<u8>, u64)> {
        let block = meta_off >> 16;
        let pos = (table + block) as usize;
        let mut header = le16(self.data, pos)? as u32;
        let mut pos = pos + 2;
        // 0xFFFF is the legacy "the next header carries an uncompressed
        // size" marker. 4.0 does not write it; images from older tools do.
        if header == 0xFFFF {
            header = le16(self.data, pos)? as u32;
            pos += 2;
        }
        let uncompressed_bit = header & 0x8000 != 0;
        let size = (header & 0x7FFF) as usize;
        if size == 0 || pos + size > self.data.len() {
            return None;
        }
        let payload = &self.data[pos..pos + size];
        let next = pos as u64 + size as u64;
        if uncompressed_bit || stored_flag {
            return Some((payload.to_vec(), next));
        }
        let out = decompress(
            self.super_.compression,
            payload,
            self.super_.block_size as u64 + 1,
        )?;
        Some((out, next))
    }

    /// Every byte from `meta_off` until `want` bytes have been read, as one
    /// buffer. A block list (or a name table) may straddle metadata blocks,
    /// so the offset *inside* the current block has to be honoured and the
    /// remainder carried into the next one.
    fn read_span(
        &self,
        table: u64,
        meta_off: u64,
        want: usize,
        stored_flag: bool,
    ) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(want.min(1 << 20));
        let mut block_index = meta_off >> 16;
        let mut in_block = (meta_off & 0xFFFF) as usize;
        let mut guard = 0usize;
        while out.len() < want {
            guard += 1;
            if guard > 4096 {
                return None;
            }
            let (block, next) = self.block_at(table, block_index << 16, stored_flag)?;
            let start = in_block.min(block.len());
            let take = (block.len() - start).min(want - out.len());
            out.extend_from_slice(&block[start..start + take]);
            // `next` is a file offset; convert back to the block number the
            // next metadata offset would carry.
            block_index = next.saturating_sub(table) >> 16;
            in_block = 0;
        }
        out.truncate(want);
        Some(out)
    }
}

#[derive(Clone)]
struct Inode {
    ty: u16,
    perms: u16,
    uid: u16,
    gid: u16,
    mtime: u32,
    number: u32,
    /// Directory: metadata offset of the listing. Regular file: metadata
    /// offset of the block-size list.
    start_block: u32,
    nlink: u32,
    fragment: u32,
    frag_offset: u32,
    file_size: u32,
    symlink: Vec<u8>,
}

fn parse_inode(buf: &[u8], off: usize) -> Option<(Inode, usize)> {
    let ty = le16(buf, off)?;
    let perms = le16(buf, off + 2)?;
    let uid = le16(buf, off + 4)?;
    let gid = le16(buf, off + 6)?;
    let mtime = le32(buf, off + 8)?;
    let number = le32(buf, off + 12)?;
    let base = 16;
    let mut inode = Inode {
        ty,
        perms,
        uid,
        gid,
        mtime,
        number,
        start_block: 0,
        nlink: 0,
        fragment: NO_FRAGMENT,
        frag_offset: 0,
        file_size: 0,
        symlink: Vec::new(),
    };
    let size = match ty {
        INODE_DIR => {
            inode.start_block = le32(buf, off + base)?;
            inode.nlink = le32(buf, off + base + 4)?;
            inode.file_size = le32(buf, off + base + 8)?;
            base + 16
        }
        INODE_FILE => {
            inode.start_block = le32(buf, off + base)?;
            inode.fragment = le32(buf, off + base + 4)?;
            inode.frag_offset = le32(buf, off + base + 8)?;
            inode.file_size = le32(buf, off + base + 12)?;
            base + 16
        }
        INODE_LREG => {
            inode.nlink = le32(buf, off + base)?;
            inode.start_block = le32(buf, off + base + 4)?;
            inode.fragment = le32(buf, off + base + 8)?;
            inode.frag_offset = le32(buf, off + base + 12)?;
            inode.file_size = le32(buf, off + base + 16)?;
            base + 28
        }
        INODE_SYMLINK | INODE_LSYMLINK => {
            inode.nlink = le32(buf, off + base)?;
            let target_len = le32(buf, off + base + 4)? as usize;
            if target_len > 4096 {
                return None;
            }
            inode.symlink = buf
                .get(off + base + 8..off + base + 8 + target_len)?
                .to_vec();
            let mut end = base + 8 + target_len;
            if ty == INODE_LSYMLINK {
                end += 4; // parent inode number
            }
            end.div_ceil(4) * 4
        }
        4..=7 => base + 8,
        11..=14 => base + 12,
        _ => return None,
    };
    if off + size > buf.len() {
        return None;
    }
    Some((inode, off + size))
}

/// One fragment entry: where its compressed block lives and how big the
/// decompressed tail is. A fragment is the *tail* of the last block of every
/// file that has one, packed back to back.
fn fragment_size(meta: &Meta, index: u32) -> Option<(u64, u32)> {
    let entry_off = (meta.super_.fragment_table + 8 * index as u64) as usize;
    let meta_off = le64(meta.data, entry_off)?;
    let (buf, _) = meta.block_at(
        meta.super_.fragment_table,
        meta_off,
        meta.stored_fragments(),
    )?;
    let start = le64(&buf, 0)?;
    let size = le32(&buf, 8)?;
    Some((start, size))
}

impl<'a> Meta<'a> {
    fn stored_inodes(&self) -> bool {
        self.super_.flags & FLAG_UNCOMPRESSED_INODES != 0
    }
    fn stored_fragments(&self) -> bool {
        self.super_.flags & FLAG_UNCOMPRESSED_FRAGMENTS != 0
    }
    fn stored_data(&self) -> bool {
        self.super_.flags & FLAG_UNCOMPRESSED_DATA != 0
    }
}

/// POSIX mode as `drwxr-xr-x` — the permission bits and the type letter.
///
/// The inode stores both in one word, and the type half is what separates a
/// directory from a file, so a listing that printed only the low nine bits
/// would show every directory in the image as an ordinary file.
fn mode_string(perms: u16, ty: u16) -> String {
    const TYPE_BITS: u16 = 0o170000;
    const DIRECTORY: u16 = 0o040000;
    const SYMLINK: u16 = 0o120000;
    let file_type = if ty == INODE_DIR || ty == INODE_LDIR {
        DIRECTORY
    } else if ty == INODE_SYMLINK || ty == INODE_LSYMLINK {
        SYMLINK
    } else {
        perms & TYPE_BITS
    };
    let letter = match file_type {
        0o040000u16 => 'd',
        0o120000u16 => 'l',
        0o060000u16 => 'b',
        0o020000u16 => 'c',
        0o010000u16 => 'p',
        0o140000u16 => 's',
        _ => '-',
    };
    format!("{letter}{:03o}", perms & 0o777)
}

pub struct Squashfs;
impl Adapter for Squashfs {
    fn name(&self) -> &'static str {
        "squashfs"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["squashfs", "sqsh", "snap"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let Some(sup) = parse_super(data) else {
            decline!("not a SquashFS 4.0 image (bad magic or major version)");
        };
        let meta = Meta { data, super_: &sup };

        // Walk the inode table front to back. Each regular file's data
        // blocks start where the previous one's ended, and the first one
        // starts at offset 0 of the image.
        let mut positions: BTreeMap<u64, u64> = BTreeMap::new();
        let mut sizes: BTreeMap<u64, (u32, u32, u32, u32)> = BTreeMap::new();
        let mut next_data: u64 = blocks_start(&sup);
        let mut pos = sup.inode_table;
        let mut read = 0u32;
        let mut guard = 0u32;
        'walk: while (pos as usize) < data.len() && read < sup.inode_count {
            guard += 1;
            if guard > 4096 {
                break;
            }
            let Some((block, next)) = meta.block_at(
                sup.inode_table,
                (pos - sup.inode_table) >> 16 << 16,
                meta.stored_inodes(),
            ) else {
                break;
            };
            let mut off = 0usize;
            while off + 16 <= block.len() {
                let Some((inode, next_off)) = parse_inode(&block, off) else {
                    break;
                };
                let meta_off = ((pos - sup.inode_table) << 16) | off as u64;
                if inode.ty == INODE_FILE || inode.ty == INODE_LREG {
                    let frag_bytes =
                        if inode.fragment == NO_FRAGMENT || sup.flags & FLAG_NO_FRAGMENTS != 0 {
                            0
                        } else {
                            fragment_size(&meta, inode.fragment)
                                .map(|(_, sz)| sz.saturating_sub(inode.frag_offset))
                                .unwrap_or(0)
                        };
                    let i_size = inode.file_size.saturating_sub(frag_bytes);
                    let count = if sup.block_size == 0 {
                        0
                    } else {
                        i_size.div_ceil(sup.block_size) as usize
                    };
                    sizes.insert(
                        meta_off,
                        (count as u32, i_size, inode.fragment, inode.frag_offset),
                    );
                    if count > 0 {
                        positions.insert(meta_off, next_data);
                        let raw = meta
                            .read_span(
                                sup.inode_table,
                                inode.start_block as u64,
                                count * 4,
                                meta.stored_inodes(),
                            )
                            .unwrap_or_default();
                        for i in 0..count {
                            let entry = le32(&raw, i * 4).unwrap_or(0);
                            let len = (entry & BLOCK_SIZE_MASK) as u64;
                            if entry & BLOCK_SPARSE == 0 {
                                next_data += len;
                            }
                        }
                    } else {
                        positions.insert(meta_off, next_data);
                    }
                }
                off = next_off;
                read += 1;
                if read >= sup.inode_count {
                    break 'walk;
                }
            }
            pos = next;
        }

        let root_meta_off = sup.root_inode;
        let Some((root, _)) = read_inode_at(&meta, root_meta_off) else {
            bail!("root inode unreadable");
        };

        let mut sink = MemberSink::new();
        let mut listing = String::new();
        let _ = writeln!(
            listing,
            "# squashfs: {} inodes, {} codec, {} bytes used",
            sup.inode_count,
            codec_name(sup.compression),
            sup.bytes_used
        );
        let mut stack: Vec<(String, u64, u32)> = vec![(String::new(), root_meta_off, 0)];
        let mut guard = 0u32;
        while let Some((prefix, dir_off, depth)) = stack.pop() {
            guard += 1;
            if guard > 100_000 {
                break;
            }
            if depth > 32 {
                continue;
            }
            let Some((dir, _)) = read_inode_at(&meta, dir_off) else {
                continue;
            };
            let Some(entries) = dir_entries(&meta, &dir) else {
                continue;
            };
            for (name, child_off, ty) in entries {
                let full = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                let child = read_inode_at(&meta, child_off).map(|(i, _)| i);
                let kind = match child.as_ref().map(|c| c.ty).unwrap_or(ty) {
                    INODE_DIR | INODE_LDIR => "dir",
                    INODE_SYMLINK | INODE_LSYMLINK => "link",
                    INODE_FILE | INODE_LREG => "file",
                    t if (4..=7).contains(&t) => "dev",
                    _ => "other",
                };
                let size = child.as_ref().map(|c| c.file_size).unwrap_or(0);
                let perms = child.as_ref().map(|c| c.perms).unwrap_or(0);
                let inode_ty = child.as_ref().map(|c| c.ty).unwrap_or(ty);
                let _ = writeln!(
                    listing,
                    "{} {size:>12} {full}",
                    mode_string(perms, inode_ty)
                );
                let mtime = child.as_ref().map(|c| c.mtime).unwrap_or(0);
                let uid = child.as_ref().map(|c| c.uid).unwrap_or(0);
                let gid = child.as_ref().map(|c| c.gid).unwrap_or(0);
                let inode_no = child.as_ref().map(|c| c.number).unwrap_or(0);
                let _ = writeln!(
                    listing,
                    "      inode {inode_no} uid {uid} gid {gid} mtime {mtime}"
                );
                match kind {
                    "dir" => stack.push((full, child_off, depth + 1)),
                    "link" => {
                        if let Some(c) = &child {
                            let _ = writeln!(
                                listing,
                                "      -> {}",
                                String::from_utf8_lossy(&c.symlink)
                            );
                        }
                    }
                    "file" => {
                        if let Some(c) = &child {
                            // The declared size is reserved before the file
                            // is read: a sparse-block file extends to its
                            // full size with no input bytes at all, so the
                            // sink's refusal has to come before the
                            // allocation rather than after it.
                            let declared = c.file_size as u64;
                            if declared > 0 && sink.reserve(declared) {
                                let bytes = read_file(&meta, child_off, c, &positions, &sizes);
                                if !bytes.is_empty() {
                                    sink.push(full, bytes);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        let _ = root;
        if !listing.is_empty() {
            sink.push("squashfs-listing.txt".to_string(), listing.into_bytes());
        }
        let members = sink.finish();
        if members.is_empty() {
            bail!("SquashFS image holds no readable file data");
        }
        Ok(Outcome::Members(members))
    }
}

/// Read an inode straight from its metadata offset. The directory walk only
/// needs the fields a listing shows; the block list is read separately,
/// once, in the table walk above.
fn read_inode_at(meta: &Meta, meta_off: u64) -> Option<(Inode, usize)> {
    let (block, _) = meta.block_at(meta.super_.inode_table, meta_off, meta.stored_inodes())?;
    let off = (meta_off & 0xFFFF) as usize;
    parse_inode(&block, off)
}

/// Every entry of one directory inode, in listing order. A directory inode
/// declares `nlink` subdirectories and its listing occupies that many
/// header-delimited runs in the directory table.
fn dir_entries(meta: &Meta, dir: &Inode) -> Option<Vec<(String, u64, u16)>> {
    let table = meta.super_.directory_table;
    let stored = meta.stored_inodes();
    let mut out = Vec::new();
    let mut meta_off = dir.start_block as u64;
    let mut remaining_dirs = dir.nlink.max(1);
    let mut guard = 0u32;
    while remaining_dirs > 0 {
        guard += 1;
        if guard > 4096 {
            break;
        }
        let (block, next) = meta.block_at(table, meta_off, stored)?;
        let mut off = (meta_off & 0xFFFF) as usize;
        let count = le32(&block, off)? as usize + 1;
        let name_table = le32(&block, off + 4)? as u64;
        off += 12;
        for i in 0..count {
            if off + 16 > block.len() {
                break;
            }
            // offset u64, then the inode's metadata offset — the entry's 16-byte
            // fixed part is those plus the type and size halfwords.
            let child_off = le32(&block, off + 8)? as u64;
            let ty = le16(&block, off + 12)?;
            let size = le16(&block, off + 14)? as usize;
            off += 16;
            let table_off = size >> 8;
            let name_len = size & 0xFF;
            let name = if table_off != 0 {
                // Long name: the bytes live in the directory's name table,
                // one byte of length followed by the characters.
                let Some(nt) = meta.block_at(table, name_table + table_off as u64, stored) else {
                    continue;
                };
                let Some(&n) = nt.0.first() else {
                    continue;
                };
                let n = (n as usize).min(name_len);
                let Some(slice) = nt.0.get(1..1 + n) else {
                    continue;
                };
                String::from_utf8_lossy(slice).into_owned()
            } else if name_len > 1 && off + name_len <= block.len() {
                let slice = &block[off + 1..off + name_len];
                off += name_len;
                String::from_utf8_lossy(slice).into_owned()
            } else {
                continue;
            };
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            let _ = i;
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            out.push((name, child_off, ty));
            let _ = i;
        }
        meta_off = next;
        remaining_dirs -= 1;
    }
    Some(out)
}

/// Assemble one file's bytes: data blocks first, then the fragment tail.
fn read_file(
    meta: &Meta,
    meta_off: u64,
    inode: &Inode,
    positions: &BTreeMap<u64, u64>,
    sizes: &BTreeMap<u64, (u32, u32, u32, u32)>,
) -> Vec<u8> {
    let sup = meta.super_;
    let Some(&(count, i_size, fragment, frag_offset)) = sizes.get(&meta_off) else {
        return Vec::new();
    };
    let start = positions.get(&meta_off).copied().unwrap_or(0);
    let mut out = Vec::new();
    if count > 0 {
        let Some(raw) = meta.read_span(
            sup.inode_table,
            inode.start_block as u64,
            count as usize * 4,
            meta.stored_inodes(),
        ) else {
            return Vec::new();
        };
        let mut pos = start;
        for i in 0..count as usize {
            let entry = le32(&raw, i * 4).unwrap_or(0);
            let len = (entry & BLOCK_SIZE_MASK) as usize;
            if entry & BLOCK_SPARSE != 0 {
                // A hole: the file carries zero bytes there.
                let zeros = (len as u64).min(sup.block_size as u64) as usize;
                out.extend(core::iter::repeat_n(0u8, zeros));
                continue;
            }
            let Some(slice) = meta.data.get(pos as usize..pos as usize + len) else {
                break;
            };
            let chunk = if meta.stored_data() {
                Some(slice.to_vec())
            } else {
                decompress(sup.compression, slice, sup.block_size as u64 + 1)
            };
            let Some(chunk) = chunk else {
                break;
            };
            out.extend_from_slice(&chunk);
            pos += len as u64;
        }
        out.truncate(i_size as usize);
    }
    if fragment != NO_FRAGMENT && sup.flags & FLAG_NO_FRAGMENTS == 0 {
        if let Some((frag_start, frag_size)) = fragment_size(meta, fragment) {
            let want = (frag_size.saturating_sub(frag_offset)) as usize;
            if want > 0 && want <= sup.block_size as usize {
                let raw_len = want;
                if let Some(slice) = meta
                    .data
                    .get(frag_start as usize..frag_start as usize + raw_len)
                {
                    let chunk = if meta.stored_fragments() {
                        Some(slice.to_vec())
                    } else {
                        decompress(sup.compression, slice, sup.block_size as u64 + 1)
                    };
                    if let Some(chunk) = chunk {
                        let start = (frag_offset as usize).min(chunk.len());
                        let end = (chunk.len())
                            .min(start + (inode.file_size as usize).saturating_sub(out.len()));
                        if start < end {
                            out.extend_from_slice(&chunk[start..end]);
                        }
                    }
                }
            }
        }
    }
    out.truncate(inode.file_size as usize);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Builds a real SquashFS 4.0 image: one stored inode-table block, one
    /// stored directory-table block, no fragments, two files whose data
    /// blocks sit at offsets 0 and 131072 in image order.
    struct Builder {
        inode_block: Vec<u8>,
        dir_block: Vec<u8>,
        data: Vec<u8>,
        blocks: Vec<u32>,
        inode_count: u32,
        compress: bool,
    }

    const BS: u32 = 131_072;

    impl Builder {
        /// `compress` chooses between stored metadata blocks and real
        /// raw-DEFLATE payloads, so both halves of the reader are covered by
        /// the same image shape.
        fn with_compression(compress: bool) -> Self {
            Self {
                inode_block: Vec::new(),
                dir_block: Vec::new(),
                data: Vec::new(),
                blocks: Vec::new(),
                inode_count: 0,
                compress,
            }
        }

        fn push_inode(&mut self, bytes: &[u8]) -> usize {
            let off = self.inode_block.len();
            self.inode_block.extend_from_slice(bytes);
            self.inode_count += 1;
            off
        }

        fn dir_header(&mut self, count: usize, name_table: u32, inode_number: u32) -> usize {
            let off = self.dir_block.len();
            self.dir_block
                .extend_from_slice(&((count.saturating_sub(1)) as u32).to_le_bytes());
            self.dir_block.extend_from_slice(&name_table.to_le_bytes());
            self.dir_block
                .extend_from_slice(&inode_number.to_le_bytes());
            off
        }

        fn dir_entry(&mut self, child_off: u32, ty: u16, name: &str) {
            self.dir_block.extend_from_slice(&0u64.to_le_bytes());
            self.dir_block.extend_from_slice(&child_off.to_le_bytes());
            self.dir_block.extend_from_slice(&ty.to_le_bytes());
            self.dir_block
                .extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
            self.dir_block.push(name.len() as u8);
            self.dir_block.extend_from_slice(name.as_bytes());
        }

        /// Data blocks are laid out back to back from the end of the directory
        /// table, each exactly as long as its block-list entry says. That is what
        /// makes the running position in the inode walk land on the right byte:
        /// a builder that padded every block to BS would produce an image whose
        /// offsets only the builder knew.
        fn file_data(&mut self, payload: &[u8]) {
            if self.compress {
                let enc = stored_deflate(payload);
                self.blocks.push(enc.len() as u32);
                self.data.extend_from_slice(&enc);
            } else {
                self.blocks.push(payload.len() as u32);
                self.data.extend_from_slice(payload);
            }
        }

        fn block_list(&mut self, inodes: &mut Vec<u8>) -> usize {
            let off = inodes.len();
            for b in &self.blocks {
                inodes.extend_from_slice(&b.to_le_bytes());
            }
            off
        }

        /// Assemble the image. `root_off` is the byte offset of the root
        /// inode inside the inode metadata block.
        fn build(mut self, root_off: u64) -> Vec<u8> {
            let stored = !self.compress;
            let inode_table_start = 96u64;
            let mut inode_block = core::mem::take(&mut self.inode_block);
            // The block list lives in the same metadata block here, appended
            // after the inodes, which is what a real image does too.
            let list_off = self.block_list(&mut inode_block);
            let pad = (BS as usize).saturating_sub(inode_block.len()).min(64);
            inode_block.extend(core::iter::repeat_n(0u8, pad));
            // patch the two file inodes' start_block to the list offset
            patch_list_offset(&mut inode_block, list_off);

            let dir_table_start = inode_table_start + BS as u64;
            let dir_block = core::mem::take(&mut self.dir_block);
            // Empty fragment index (one terminator u64) and empty id index
            // (one terminator u32), then the data blocks — the order a real
            // image writes them in, and the order `blocks_start` assumes.
            let frag_table_start = dir_table_start + BS as u64;
            let id_table_start = frag_table_start + 8;
            let data_start = id_table_start + 4;

            let mut img = vec![0u8; 96];
            img[0..4].copy_from_slice(&MAGIC.to_le_bytes());
            img[4..8].copy_from_slice(&self.inode_count.to_le_bytes());
            img[8..12].copy_from_slice(&0u32.to_le_bytes());
            img[12..16].copy_from_slice(&BS.to_le_bytes());
            img[16..20].copy_from_slice(&0u32.to_le_bytes()); // fragments
            img[20..22].copy_from_slice(&1u16.to_le_bytes()); // gzip
            img[22..24].copy_from_slice(&17u16.to_le_bytes()); // block log
            let flags = if stored {
                FLAG_UNCOMPRESSED_INODES | FLAG_UNCOMPRESSED_DATA
            } else {
                0
            } | FLAG_NO_FRAGMENTS;
            img[24..26].copy_from_slice(&flags.to_le_bytes());
            img[26..28].copy_from_slice(&0u16.to_le_bytes()); // id count
            img[28..30].copy_from_slice(&4u16.to_le_bytes());
            img[30..32].copy_from_slice(&0u16.to_le_bytes());
            img[32..40].copy_from_slice(&root_off.to_le_bytes());
            img[40..48].copy_from_slice(&(data_start + self.data.len() as u64).to_le_bytes());
            img[48..56].copy_from_slice(&id_table_start.to_le_bytes());
            img[56..64].copy_from_slice(&0u64.to_le_bytes()); // no xattr ids
            img[64..72].copy_from_slice(&inode_table_start.to_le_bytes());
            img[72..80].copy_from_slice(&dir_table_start.to_le_bytes());
            img[80..88].copy_from_slice(&frag_table_start.to_le_bytes());
            img[88..96].copy_from_slice(&0u64.to_le_bytes()); // no export table

            push_meta_block(&mut img, inode_table_start, &inode_block, stored);
            push_meta_block(&mut img, dir_table_start, &dir_block, stored);
            while (img.len() as u64) < frag_table_start {
                img.push(0);
            }
            img.extend_from_slice(&0u64.to_le_bytes()); // fragment index terminator
            debug_assert_eq!(img.len() as u64, id_table_start);
            img.extend_from_slice(&0u32.to_le_bytes()); // id index terminator
            debug_assert_eq!(img.len() as u64, data_start);
            img.extend_from_slice(&self.data);
            img
        }
    }

    fn patch_list_offset(block: &mut [u8], off: usize) {
        // Walk the inodes in storage order: each starts with its type word,
        // and a file's inode carries the metadata offset of *its own* first
        // block-list entry. Two files sharing one list is a builder trick,
        // so each one gets the next slot — pointing both at the same offset
        // makes every file after the first read the first file's length.
        let mut p = 0usize;
        let mut slot = off as u32;
        while p + 16 <= block.len() {
            match le16(block, p).unwrap_or(0) {
                INODE_DIR | INODE_LDIR => p += 32,
                INODE_FILE | INODE_LREG => {
                    block[p + 16..p + 20].copy_from_slice(&slot.to_le_bytes());
                    slot += 4;
                    p += 32;
                }
                _ => break,
            }
        }
    }

    fn push_meta_block(img: &mut Vec<u8>, at: u64, payload: &[u8], stored: bool) {
        while (img.len() as u64) < at {
            img.push(0);
        }
        if stored {
            img.extend_from_slice(&(0x8000 | payload.len() as u16).to_le_bytes());
            img.extend_from_slice(payload);
        } else {
            push_compressed_block(img, at, payload);
        }
    }

    fn read_inode_image() -> (Vec<u8>, Vec<Vec<u8>>) {
        read_inode_image_with(false)
    }

    fn read_inode_image_with(compress: bool) -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut b = Builder::with_compression(compress);
        let payload1 = b"invoice total is 42\n".to_vec();
        let payload2 = b"second member says nothing useful\n".to_vec();
        // File inodes first, because a file's data blocks are laid out in
        // inode-table order and the block list follows them.
        let f1 = b.push_inode(&file_inode(NO_FRAGMENT, 0, payload1.len() as u32));
        b.file_data(&payload1);
        let f2 = b.push_inode(&file_inode(NO_FRAGMENT, 0, payload2.len() as u32));
        b.file_data(&payload2);
        let root = b.push_inode(&dir_inode(1));
        let _h = b.dir_header(2, 0, 1);
        b.dir_entry(f1 as u32, INODE_FILE, "one.txt");
        b.dir_entry(f2 as u32, INODE_FILE, "two.txt");
        let img = b.build(root as u64);
        (img, vec![payload1, payload2])
    }

    fn file_inode(fragment: u32, frag_offset: u32, size: u32) -> [u8; 32] {
        let mut i = [0u8; 32];
        i[0..2].copy_from_slice(&INODE_FILE.to_le_bytes());
        i[2..4].copy_from_slice(&0o644u16.to_le_bytes());
        i[8..12].copy_from_slice(&1_700_000_000u32.to_le_bytes());
        i[12..16].copy_from_slice(&1u32.to_le_bytes());
        i[16..20].copy_from_slice(&0u32.to_le_bytes()); // start_block, patched
        i[20..24].copy_from_slice(&fragment.to_le_bytes());
        i[24..28].copy_from_slice(&frag_offset.to_le_bytes());
        i[28..32].copy_from_slice(&size.to_le_bytes());
        i
    }

    fn dir_inode(nlink: u32) -> [u8; 32] {
        let mut i = [0u8; 32];
        i[0..2].copy_from_slice(&INODE_DIR.to_le_bytes());
        i[2..4].copy_from_slice(&0o755u16.to_le_bytes());
        i[12..16].copy_from_slice(&1u32.to_le_bytes());
        i[20..24].copy_from_slice(&nlink.to_le_bytes());
        i
    }

    fn members(out: Outcome) -> Vec<(String, Vec<u8>)> {
        match out {
            Outcome::Members(m) => m,
            _ => panic!("expected Members"),
        }
    }

    #[test]
    fn squashfs_reads_a_file_and_its_listing() {
        let (img, payloads) = read_inode_image();
        let m = members(Squashfs.extract(&img, "root.squashfs").expect("squashfs"));
        let one = m.iter().find(|(n, _)| n == "one.txt").expect("one.txt");
        assert_eq!(one.1, payloads[0]);
        let two = m.iter().find(|(n, _)| n == "two.txt").expect("two.txt");
        assert_eq!(two.1, payloads[1]);
        let listing = m
            .iter()
            .find(|(n, _)| n == "squashfs-listing.txt")
            .expect("listing");
        let text = String::from_utf8_lossy(&listing.1);
        assert!(text.contains("one.txt"), "{text}");
        assert!(text.contains("two.txt"), "{text}");
        assert!(text.contains("-644"), "{text}");
        assert!(text.contains("inode 1 uid"), "{text}");
    }

    #[test]
    fn squashfs_declines_a_non_image() {
        assert!(Squashfs.extract(b"hsqs", "x.squashfs").is_err());
        assert!(Squashfs.extract(&[0u8; 200], "x.squashfs").is_err());
    }

    #[test]
    fn every_metadata_and_data_block_is_inflated_when_the_image_is_compressed() {
        // Same shape as the stored image, but the inode, directory and data
        // blocks carry raw-DEFLATE payloads and the "stored" flags are
        // clear — so the whole path runs through the codec, including the
        // position arithmetic that depends on the compressed lengths.
        let (img, payloads) = read_inode_image_with(true);
        let sup = parse_super(&img).expect("super");
        assert_eq!(sup.flags & FLAG_UNCOMPRESSED_INODES, 0);
        let m = members(Squashfs.extract(&img, "root.squashfs").expect("squashfs"));
        let one = m.iter().find(|(n, _)| n == "one.txt").expect("one.txt");
        assert_eq!(one.1, payloads[0]);
        let two = m.iter().find(|(n, _)| n == "two.txt").expect("two.txt");
        assert_eq!(two.1, payloads[1]);
    }

    fn push_compressed_block(img: &mut Vec<u8>, at: u64, payload: &[u8]) {
        while (img.len() as u64) < at {
            img.push(0);
        }
        // A DEFLATE stream of stored blocks: header bits BFINAL=1, BTYPE=00
        // in the first byte, then LEN/NLEN and the bytes, which is the
        // uncompressed encoding RFC 1951 defines. Real codec output is not
        // needed to prove the decode path — a wrong framing would fail here.
        let raw = stored_deflate(payload);
        img.extend_from_slice(&(raw.len() as u16).to_le_bytes());
        img.extend_from_slice(&raw);
    }

    fn stored_deflate(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x01u8];
        let n = payload.len() as u16;
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&(!n).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }
}
