// SPDX-License-Identifier: Apache-2.0

//! Archive & decompression adapters, all in-process.

#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

use alloc::boxed::Box;
#[cfg(any(feature = "cpio", feature = "decompress"))]
use alloc::string::String;
#[cfg(any(feature = "cpio", feature = "decompress", feature = "tar"))]
use alloc::string::ToString;
use alloc::vec::Vec;
#[cfg(feature = "cpio")]
use core::str;
#[cfg(feature = "decompress")]
use rgx_core::decline;
use rgx_core::Adapter;
#[cfg(any(feature = "cpio", feature = "sevenz", feature = "zip"))]
use rgx_core::Context;
#[cfg(any(
    feature = "cpio",
    feature = "decompress",
    feature = "sevenz",
    feature = "tar",
    feature = "zip"
))]
use rgx_core::Outcome;
#[cfg(any(
    feature = "cpio",
    feature = "decompress",
    feature = "sevenz",
    feature = "tar",
    feature = "zip"
))]
use rgx_core::Result;

#[cfg(feature = "std")]
pub mod budget;
// `pub` so `examples/decomp_bench.rs` can reach the codecs directly --
// the adapter surface is the registry, and a bench that went through it
// would measure the pipeline instead of the decoder.
#[cfg(feature = "borg")]
mod borg;
#[cfg(any(
    feature = "borg",
    feature = "decompress",
    feature = "pgdump",
    feature = "squashfs"
))]
pub mod lz4;
#[cfg(feature = "borg")]
mod msgpack;
#[cfg(feature = "pgdump")]
mod pgdump;
#[cfg(feature = "rar")]
mod rar;
#[cfg(feature = "tar")]
mod tar;
// Vendored from the 7-Zip project and kept byte-identical for easy
// re-sync, so it carries the full encoder side (7z write path) that rgx
// never calls, plus the borrow/mutability idioms that go with it.
// Silence the lint noise here rather than per-item, which a re-vendor
// would have to replay. `unreachable_patterns` is deliberately NOT
// allowed: a duplicate or shadowed match arm in a parser is a real
// defect, not vendoring noise.
#[allow(
    dead_code,
    unused_imports,
    unused_mut,
    unused_variables,
    unused_assignments
)]
#[cfg(feature = "sevenz")]
pub mod sevenz;
// In-house RFC 7932 decoder: stream header, meta-block headers, block
// switching, context maps, the command alphabet, backward references, and
// the static dictionary with its 121 word transformations. Verified
// against reference-CLI vectors in `crate::tests::oracle`; coverage of
// the corpus is in `crate::brotli::coverage`.
#[cfg(feature = "ar")]
pub mod ar;
#[cfg(any(feature = "git-bundle", feature = "svn-dump"))]
pub mod backups;
#[cfg(feature = "decompress")]
pub mod brotli;
#[cfg(feature = "git-pack")]
pub mod git_pack;
#[cfg(any(
    feature = "applefs",
    feature = "erofs",
    feature = "iso9660",
    feature = "qcow2",
    feature = "raw-image",
    feature = "vdi",
    feature = "vhd",
    feature = "vhdx",
    feature = "vmdk",
    feature = "wim"
))]
pub mod images;
#[cfg(feature = "squashfs")]
pub mod squashfs;

pub fn adapters() -> Vec<Box<dyn Adapter>> {
    vec![
        #[cfg(feature = "zip")]
        Box::new(Zip),
        #[cfg(feature = "sevenz")]
        Box::new(SevenZ),
        #[cfg(feature = "tar")]
        Box::new(Tar),
        #[cfg(feature = "cpio")]
        Box::new(Cpio),
        #[cfg(feature = "ar")]
        Box::new(ar::Ar),
        #[cfg(feature = "git-pack")]
        Box::new(git_pack::GitPack),
        #[cfg(feature = "git-bundle")]
        Box::new(backups::GitBundle),
        #[cfg(feature = "decompress")]
        Box::new(Decompress),
        #[cfg(feature = "rar")]
        Box::new(rar::Rar),
        #[cfg(feature = "svn-dump")]
        Box::new(backups::SvnDump),
        // `.dump` is claimed by the Subversion dump too. The two magic
        // numbers are disjoint -- a Subversion dump starts with
        // "SVN-fs-dump-format-version:" and a PostgreSQL custom archive
        // with "PGDMP" -- so whichever runs first declines the other's
        // file.
        #[cfg(feature = "pgdump")]
        Box::new(pgdump::PgDump),
        // A borg segment names nothing: it is `data/0/2`, with no extension
        // and no dot in its name. It is the one adapter that claims a file
        // by its first bytes instead of by what it is called, so it goes
        // last: the name is the stronger claim, and the magic only speaks
        // when the name is silent.
        #[cfg(feature = "borg")]
        Box::new(borg::Borg),
        // Images last among the containers: each one declines with `bail!`
        // on a magic it does not own, so `.img` reaches the raw-dump
        // dispatch only after the real archives have declined it.
        #[cfg(feature = "iso9660")]
        Box::new(images::Iso9660),
        #[cfg(feature = "squashfs")]
        Box::new(squashfs::Squashfs),
        #[cfg(feature = "wim")]
        Box::new(images::Wim),
        #[cfg(feature = "vhd")]
        Box::new(images::Vhd),
        #[cfg(feature = "vhdx")]
        Box::new(images::Vhdx),
        #[cfg(feature = "qcow2")]
        Box::new(images::Qcow2),
        #[cfg(feature = "vmdk")]
        Box::new(images::Vmdk),
        #[cfg(feature = "vdi")]
        Box::new(images::Vdi),
        #[cfg(feature = "erofs")]
        Box::new(images::Erofs),
        #[cfg(feature = "applefs")]
        Box::new(images::AppleFs),
        #[cfg(feature = "raw-image")]
        Box::new(images::RawImage),
    ]
}

/// `outer.tar.gz` -> inner path hint `outer.tar` (used to re-match adapters).
/// Member names are always relative to the archive: only the final path
/// segment is kept, so nested carving shows `bundle/carved-0x2a1` instead
/// of re-embedding the full parent path.
#[cfg(feature = "decompress")]
fn strip_suffix(path: &str, suffix: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    let stem = file.strip_suffix(suffix).unwrap_or(file);
    if stem == file {
        format!("{stem}.out")
    } else {
        stem.to_string()
    }
}

#[cfg(feature = "zip")]
pub struct Zip;
#[cfg(feature = "zip")]
impl Adapter for Zip {
    fn name(&self) -> &'static str {
        "zip"
    }
    /// Package formats that are ZIP archives under a different extension.
    /// None of them carries a second container: a `.gem`, a `.nupkg` and a
    /// `.crate` are all a plain central directory with their own manifest
    /// inside, so claiming them here is what makes the manifest — the one
    /// file anyone greps a package for — searchable.
    ///
    /// `e57` is on this list for the same reason and not for the same
    /// reason: an ASME E57 point cloud is a ZIP whose `header.xml` carries
    /// the scan description and whose members carry the coordinates. Reading
    /// it as a ZIP is strictly more searchable than any header parser, since
    /// the XML *is* the document.
    fn extensions(&self) -> &'static [&'static str] {
        &[
            "zip", "zipx", "jar", "xpi", "kra", "snagx", "3mf", "usdz", "cbz", "apk", "aar", "war",
            "ear", "ipa", "whl", "egg", "kmz", "sketch", "pages", "numbers", "key", "pk3", "pk4",
            "crx", "msix", "appx", "snb", "wsb", "gem", "nupkg", "crate", "e57",
            // UOF (GB/T 20916) is XML in a compressed container, "similar to
            // OpenDocument and Office Open XML" -- a ZIP package, so unzipping
            // is strictly more searchable than reading any header. `.uot` is
            // the text template, `.uos` the spreadsheet, `.uop` the
            // presentation; `.uof` is the generic package.
            "uof", "uot", "uos", "uop",
        ]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // In-house container (vendored from the ZIP specification, APKPNOTE.TXT):
        // store/deflate/bzip2/lzma entries, zip64, CRC verified per entry.
        // Methods we do not implement (deflate64, zstd, ppmd, xz) surface as
        // a skipped member rather than raw compressed bytes. The decode cap
        // is the process budget, so `-M 20G` lifts it along with the member
        // budget; `ZipReader::new` would pin it to the default and silently
        // ignore both.
        let archive = rgx_core::zip::ZipReader::with_limit(data, budget::budget().bytes)
            .map_err(rgx_core::Error::msg)
            .decline_context("not a zip archive")?;
        let mut sink = budget::MemberSink::new();
        sink.declare(archive.list().len());
        for (i, entry) in archive.list().iter().enumerate() {
            if entry.name.ends_with('/') {
                continue;
            }
            if !sink.reserve(entry.size as u64) {
                break;
            }
            match archive.extract_index(i) {
                Ok(bytes) => {
                    if !sink.push(entry.name.clone(), bytes) {
                        break;
                    }
                }
                // An entry we cannot decode must not sink the archive: the
                // rest is still searchable. A capped entry is different from
                // a broken one -- it was readable up to a limit, and saying
                // nothing would read as "that file had no match".
                Err(_) => {
                    let (limit, spent) = archive.budget();
                    if spent >= limit {
                        sink.stop(budget::Stopped::Bytes);
                    }
                    continue;
                }
            }
        }
        Ok(Outcome::Members(sink.finish()))
    }
}

#[cfg(feature = "sevenz")]
pub struct SevenZ;
#[cfg(feature = "sevenz")]
impl Adapter for SevenZ {
    fn name(&self) -> &'static str {
        "7z"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["7z", "cb7"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let archive = sevenz::SevenzArchive::parse(data).decline_context("not a 7z archive")?;
        let mut sink = budget::MemberSink::new();
        sink.declare(archive.files().len());
        // **One folder decoded at most once.** Entries are contiguous by
        // folder in a 7z, so a single slot that is replaced whenever the
        // folder index moves turns "decode the whole folder for every file"
        // into "decode it once per folder". The old per-file re-decode was
        // quadratic in files-per-folder, and the fix is worth 8% of the
        // adapter's time on the corpus that has it -- most of that time is
        // the expansion itself, not the redundancy.
        //
        // A cache of every folder would fix the time and break the memory
        // bound -- it would hold the entire unpacked archive at once, which
        // is precisely what the member budget and `OutputCap` exist to
        // prevent. One slot keeps the peak at a single folder, the same as
        // the per-file decode it replaces.
        let mut decoded: Option<(usize, Vec<u8>)> = None;
        for (i, entry) in archive.files().iter().enumerate() {
            if entry.is_directory {
                continue;
            }
            if !sink.reserve(entry.size) {
                break;
            }
            let Some((folder_idx, sub_idx)) = archive.stream_of(i) else {
                continue;
            };
            if decoded.as_ref().map(|(f, _)| *f) != Some(folder_idx) {
                // A folder is decoded whole, so its *declared* output is
                // materialized before any entry of it can be refused by
                // the sink — the substream sizes are the file's own, and a
                // folder of `[1 byte, budget-sized]` substreams passed the
                // per-entry reserve and then paid for the whole folder.
                // The declaration is checked first, and the truncation
                // note says what was not extracted.
                if archive.folder_unpack_size(folder_idx)? > sink.remaining_bytes() {
                    sink.stop(budget::Stopped::Bytes);
                    break;
                }
                decoded = Some((folder_idx, archive.folder_output(folder_idx)?));
            }
            let (_, folder_out) = decoded.as_ref().expect("just populated");
            let bytes = archive.substream_bytes(folder_idx, sub_idx, folder_out)?;
            if !sink.push(entry.name.clone(), bytes) {
                break;
            }
        }
        Ok(Outcome::Members(sink.finish()))
    }
}

#[cfg(feature = "tar")]
pub struct Tar;
#[cfg(feature = "tar")]
impl Adapter for Tar {
    fn name(&self) -> &'static str {
        "tar"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["tar", "pax"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        // In-house reader (vendored from the GNU tar spec, verified against
        // GNU tar ustar/pax/gnu fixtures): reads regular members, resolves
        // ustar `prefix` joins, GNU 'L'/'K' long names and PAX path/size
        // records on the way through.
        let budget = budget::budget();
        let (entries, stopped) =
            tar::TarReader::read_all_limited(data, budget.members, budget.bytes)?;
        let mut sink = budget::MemberSink::with_budget(budget);
        for e in entries {
            if e.header.entry_type != tar::TarEntryType::Regular {
                continue;
            }
            let name = e
                .header
                .name
                .strip_prefix("./")
                .map(str::to_string)
                .unwrap_or(e.header.name);
            if !sink.push(name, e.data) {
                break;
            }
        }
        if let Some(reason) = stopped {
            sink.stop(reason);
        }
        Ok(Outcome::Members(sink.finish()))
    }
}

/// cpio "newc" (SVR4) format: 6-byte magic "070701"/"070702".
#[cfg(feature = "cpio")]
pub struct Cpio;
#[cfg(feature = "cpio")]
impl Adapter for Cpio {
    fn name(&self) -> &'static str {
        "cpio"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["cpio"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 6 || !(data.starts_with(b"070701") || data.starts_with(b"070702")) {
            rgx_core::decline!("not a newc cpio archive");
        }
        let hex = |b: &[u8]| -> Result<u64> {
            let s = str::from_utf8(b).context("cpio header not ascii")?;
            Ok(u64::from_str_radix(s, 16)?)
        };
        let mut pos = 0usize;
        let mut sink = budget::MemberSink::new();
        loop {
            if pos + 110 > data.len() {
                break;
            }
            let hdr = &data[pos..pos + 110];
            let namesize = hex(&hdr[94..102])? as usize;
            let filesize = hex(&hdr[54..62])? | (hex(&hdr[62..70])? << 32);
            let name_start = pos + 110;
            let name_end = name_start + namesize;
            if name_end > data.len() {
                break;
            }
            let name_raw = &data[name_start..name_end.saturating_sub(1)];
            let name = String::from_utf8_lossy(name_raw).to_string();
            let data_start = (name_end + 3) & !3;
            let data_end = data_start + filesize as usize;
            if name == "TRAILER!!!" || data_end > data.len() {
                break;
            }
            if !sink.reserve(filesize) {
                break;
            }
            if !sink.push(name, data[data_start..data_end].to_vec()) {
                break;
            }
            pos = (data_end + 3) & !3;
        }
        Ok(Outcome::Members(sink.finish()))
    }
}

/// Single-file decompressors; the decompressed stream is re-matched by
/// extension (`.tar.gz` keeps unpacking into `.tar`).
#[cfg(feature = "decompress")]
pub struct Decompress;
#[cfg(feature = "decompress")]
impl Adapter for Decompress {
    fn name(&self) -> &'static str {
        "decompress"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &[
            "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "zstd", "tzst", "lz4", "br", "z",
            "taz", "tbz", "tpz", "tz2", "tb2", "als", "bz", "bzip2", "lzma",
        ]
    }
    /// `Budget::bytes` is the ceiling on how far a stream may expand. The
    /// walker checks `Ctx::max_file_size` against the *compressed* length on
    /// disk, so a one-member bomb is the case nothing else reaches; reusing
    /// the budget's byte field keeps it to one number and one env var.
    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        let limit = budget::budget().bytes;
        let ext = rgx_core::extension_of(path);
        // "Not the format its name promises" is a `bail!`, not an empty
        // decode. Every branch below reaches its decoder through a
        // `?`, and a decoder handed bytes it does not recognise has two
        // honest answers: an error, or -- for the streaming ones -- *nothing
        // at all*. `GzipReader::decode_bounded` walks
        // `while pos < len && is_gzip(rest)`, so a text file named `.gz`
        // leaves the loop unentered and returns `Ok` carrying zero bytes.
        // `Ok(Outcome::Members([(inner, [])]))` then hands the pipeline a
        // member with an empty payload, the recursion into it finds no
        // extension and emits nothing, and the file the walk found becomes
        // unsearchable: rgx reports no match and no reason, which is the
        // exact shape the rga #151 lesson is about, reached through the
        // decoder instead of the pipeline.
        //
        // The magic is checked here, at the adapter boundary, rather than
        // inside the codecs: `decode_bounded` is also called by the forensic
        // carver on an *embedded* stream it has already located, where the
        // magic is what found it and re-checking would be noise. Brotli is
        // absent from this table because RFC 7932 defines no magic — a
        // `.br` file cannot be recognised before it is decoded, so that one
        // is decided by the decoder's own error instead.
        let recognised = match &*ext {
            "gz" | "tgz" | "taz" => rgx_core::compress::gzip::GzipReader::is_gzip(data),
            "bz2" | "tbz2" | "tbz" | "tb2" | "bz" | "bzip2" => data.starts_with(b"BZh"),
            "xz" | "txz" | "lzma" | "tlz" => xz_or_lzma(data),
            "zst" | "zstd" | "tzst" => zstd_framed(data),
            "lz4" => {
                // `decode_auto` accepts two containers: the frame magic and
                // the deprecated `lz4 -l` one, and the decoder already
                // publishes the latter's predicate.
                data.starts_with(&[0x04, 0x22, 0x4D, 0x18]) || lz4::Lz4Decoder::is_legacy(data)
            }
            // "z": 0x1f 0x9d is Unix `compress` LZW, which the branch below
            // names explicitly; everything else is zlib framing, whose first
            // byte carries the compression method and CMF/FLG validity.
            "z" | "tz2" | "tpz" | "als" => data.starts_with(&[0x1f, 0x9d]) || zlib_framed(data),
            // brotli (RFC 7932) defines no magic, so there is nothing to
            // check before decoding and the decoder's own error decides.
            "br" => true,
            _ => true,
        };
        if !recognised {
            decline!("not a {ext} stream: the bytes do not carry that format's magic");
        }
        let (inner, bytes, declared, capped) = match &*ext {
            "gz" | "tgz" | "taz" => {
                let b = rgx_core::compress::gzip::GzipReader::decode_bounded(data, limit)?;
                (
                    strip_suffix(path, &format!(".{ext}")),
                    b.bytes,
                    b.declared,
                    b.capped,
                )
            }
            "bz2" | "tbz2" | "tbz" | "tb2" | "bz" | "bzip2" => {
                let b =
                    rgx_core::compress::bzip2::Bzip2Decoder::new().decode_bounded(data, limit)?;
                (
                    strip_suffix(
                        path,
                        match &*ext {
                            "bz2" | "bz" | "bzip2" => ".bz2",
                            "tbz2" => ".tbz2",
                            "tbz" => ".tbz",
                            _ => ".tb2",
                        },
                    ),
                    b.bytes,
                    b.declared,
                    b.capped,
                )
            }
            "xz" | "txz" => {
                // In-house XZ container (verified against XZ Utils vectors).
                let b = rgx_core::compress::xz::XzReader::decompress_bounded(data, limit)
                    .map_err(rgx_core::Error::msg)?;
                (
                    strip_suffix(path, if ext == "txz" { ".txz" } else { ".xz" }),
                    b.bytes,
                    b.declared,
                    b.capped,
                )
            }
            "lzma" | "tlz" => {
                // Legacy .lzma is the FORMAT_ALONE stream (props byte +
                // dict size + size), not an XZ container — the xz2 crate
                // was handed these and could not read them.
                let b = rgx_core::compress::lzma::LzmaDecoder::new()
                    .decode_bounded(data, limit)
                    .map_err(rgx_core::Error::msg)?;
                (
                    strip_suffix(path, if ext == "lzma" { ".lzma" } else { ".tlz" }),
                    b.bytes,
                    b.declared,
                    b.capped,
                )
            }
            "zst" | "zstd" | "tzst" => {
                // The in-house decoder refuses a bomb from the frame header
                // before it expands one and enforces the cap while it runs.
                // It declines exactly one shape -- a frame carrying a
                // Dictionary_ID, which cannot be read without the dictionary
                // -- and libzstd gets those, so a file shape this build has
                // not seen degrades to a slower answer rather than no answer.
                // It does not fall back on a decode *error*: a broken frame
                // is broken, and handing it to a second implementation only
                // risks one of the two being wrong.
                let stem = strip_suffix(path, if ext == "tzst" { ".tzst" } else { ".zst" });
                let in_house =
                    rgx_core::compress::zstd::ZstdDecoder::new().decode_bounded(data, limit);
                let (bytes, declared, capped) = match in_house {
                    Ok(b) => (b.bytes, b.declared, b.capped),
                    Err(rgx_core::compress::error::CompressError::UnsupportedFormat(why)) => {
                        let mut bytes = Vec::new();
                        let capped = stream_bounded(
                            || zstd::stream::read::Decoder::new(data),
                            limit,
                            &mut bytes,
                        )
                        .map_err(|e| rgx_core::Error::msg(format!("zstd: {why}; {e}")))?;
                        let declared = zstd::zstd_safe::get_frame_content_size(data)
                            .ok()
                            .flatten()
                            .filter(|n| *n != zstd::zstd_safe::CONTENTSIZE_UNKNOWN);
                        (bytes, declared, capped)
                    }
                    Err(e) => return Err(rgx_core::Error::msg(e).context("zstd frame")),
                };
                (stem, bytes, declared, capped)
            }
            "lz4" => {
                // In-house decoder covering both the modern frame and the
                // deprecated legacy container that `lz4 -l` emits, verified
                // against reference `lz4`-CLI output in
                // `lz4::lz4::tests`. `decode_auto` picks the container from
                // its magic; the `lz4_flex` crate this replaced read both.
                let b = lz4::Lz4Decoder::new().decode_auto_bounded(data, limit)?;
                (strip_suffix(path, ".lz4"), b.bytes, b.declared, b.capped)
            }
            "br" => {
                // In-house RFC 7932 decoder, verified against reference
                // `brotli` 1.2.0 output in `crate::tests::brotli_oracle`; see
                // `testdata/brotli_README.md` for the vectors. It caps
                // itself as it emits, so a bomb costs the budget and no
                // more, and brotli declares no content size anywhere, so
                // there is nothing to report about what it left out.
                let b = brotli::BrotliDecoder::new()
                    .decode_bounded(data, limit)
                    .map_err(rgx_core::Error::msg)?;
                (strip_suffix(path, ".br"), b.bytes, b.declared, b.capped)
            }
            "z" | "tz2" | "tpz" | "als" => {
                // Unix `compress` writes the LZW magic 1f 9d; zlib framing
                // starts 78 xx. An LZW stream is a genuine `.Z` -- the
                // extension this branch claims -- and no LZW decoder is
                // bundled, so name that. Letting the zlib attempt run and
                // fail produced a file with nothing searchable and nothing
                // on stderr, indistinguishable from "no match": the user
                // who named `.z` got no answer and no reason.
                if data.starts_with(&[0x1f, 0x9d]) {
                    return Err(rgx_core::Error::msg(
                        "LZW-compressed .Z: the registry claims .z but only zlib \
                         framing is decoded, and no LZW decoder is bundled",
                    ));
                }
                // Otherwise treat it as zlib framing, which is what the
                // gzip-compatible producers of these suffixes emit.
                let b = rgx_core::compress::zlib::ZlibDecoder::new().decode_bounded(data, limit)?;
                (
                    strip_suffix(path, &format!(".{ext}")),
                    b.bytes,
                    b.declared,
                    b.capped,
                )
            }
            _ => rgx_core::bail!("unsupported compression suffix .{ext}"),
        };
        if capped {
            return Ok(truncated(inner, bytes, declared, limit));
        }
        // recurse through the pipeline with the inner name (a tar.gz becomes
        // a tar member expansion, transparently)
        Ok(Outcome::Members(vec![(inner, bytes)]))
    }
}

/// zstd (RFC 8878): a frame magic, or a skippable frame, which is a valid
/// stream start in its own right and which the decoder skips rather than
/// decodes. Checking only the frame magic would decline a skippable-frame
/// file the branch above exists to read.
#[cfg(feature = "decompress")]
fn zstd_framed(data: &[u8]) -> bool {
    let Some(head) = data.get(0..4) else {
        return false;
    };
    let magic = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    magic == rgx_core::compress::zstd::MAGIC || (magic & 0xFFFF_FFF0) == 0x184D_2A50
}

/// XZ and legacy `.lzma` share the extension list above but not the magic:
/// an XZ container is the 6-byte stream header `FD 37 7A 58 5A 00`, while
/// `.lzma` is the FORMAT_ALONE stream, whose first byte is the properties
/// byte and which has no signature at all. Checking only the XZ magic would
/// decline every `.lzma` file the `.lzma` branch exists to read.
#[cfg(feature = "decompress")]
fn xz_or_lzma(data: &[u8]) -> bool {
    if data.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return true;
    }
    // FORMAT_ALONE: props <= 224, dict size a power of two in the low 3
    // bytes, then a little-endian u64 dictionary size. The props bound plus
    // the dictionary-shape test is what separates it from arbitrary bytes,
    // and it is the same shape the LzmaDecoder itself accepts.
    match data {
        [props, d0, d1, d2, rest @ ..] if *props <= 225 && rest.len() >= 8 => {
            let dict = u32::from_le_bytes([*d0, *d1, *d2, 0]);
            dict != 0 && dict.is_power_of_two()
        }
        _ => false,
    }
}

/// zlib framing (RFC 1950): CMF's low nibble is the compression method (8
/// for deflate) and `(CMF << 8 | FLG) % 31 == 0` is the header check. The
/// divisibility test is what makes this a format check rather than a guess
/// at the first byte.
#[cfg(feature = "decompress")]
fn zlib_framed(data: &[u8]) -> bool {
    match data {
        [cmf, flg, ..] if cmf & 0x0F == 8 => (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0,
        _ => false,
    }
}

/// A decode the byte budget stopped, as the note plus what it did produce.
/// The decoded prefix is kept: the first `limit` bytes of a bomb are
/// ordinary content, and a search that found nothing in them is a different
/// answer from a search that was never run.
#[cfg(feature = "decompress")]
fn truncated(inner: String, bytes: Vec<u8>, declared: Option<u64>, limit: u64) -> Outcome {
    let emitted = bytes.len() as u64;
    let note = budget::decompression_note(emitted, limit, declared);
    Outcome::Members(vec![note, (inner, bytes)])
}

/// Read a streaming decoder into `out`, stopping at `limit` bytes.
///
/// `.take(limit + 1)` rather than `limit`: the extra byte is what tells a
/// stream that filled the budget exactly from one that went past it, which
/// is the difference between "decoded whole" and "stopped here" when the
/// real size is not declared anywhere.
#[cfg(feature = "decompress")]
fn stream_bounded<R: std::io::Read>(
    make: impl FnOnce() -> std::io::Result<R>,
    limit: u64,
    out: &mut Vec<u8>,
) -> Result<bool> {
    use std::io::Read as _;
    let mut reader = make()?.take(limit.saturating_add(1));
    reader.read_to_end(out)?;
    if (out.len() as u64) <= limit {
        return Ok(false);
    }
    out.truncate(limit as usize);
    Ok(true)
}

#[cfg(all(
    test,
    any(
        feature = "cpio",
        feature = "decompress",
        feature = "tar",
        feature = "sevenz",
        feature = "zip"
    )
))]
mod tests {
    use super::*;
    #[cfg(any(feature = "decompress", feature = "sevenz", feature = "zip"))]
    use alloc::string::String;
    #[cfg(any(feature = "decompress", feature = "sevenz", feature = "zip"))]
    use rgx_core::Outcome;
    #[cfg(feature = "decompress")]
    use std::eprintln;

    /// The in-house XZ container and the legacy FORMAT_ALONE `.lzma`
    /// stream, both produced by liblzma via python.
    #[cfg(feature = "decompress")]
    #[test]
    fn xz_and_lzma_decompress() {
        use crate::budget::testing::locked;
        let expected = include_bytes!("../testdata/xz_sample.plain");
        let xz = include_bytes!("../testdata/xz_sample.xz");
        let lzma = include_bytes!("../testdata/xz_sample.lzma");
        locked(|| {
            let out = Decompress.extract(xz, "sample.xz").expect("xz");
            let Outcome::Members(m) = out else {
                panic!("xz: members")
            };
            assert_eq!(m.len(), 1);
            assert_eq!(m[0].1, &expected[..]);

            let out = Decompress.extract(lzma, "sample.lzma").expect("lzma");
            let Outcome::Members(m) = out else {
                panic!("lzma: members")
            };
            assert_eq!(m.len(), 1);
            assert_eq!(m[0].1, &expected[..]);
        });
    }

    /// Every `.zst` fixture, decoded through the adapter, against the
    /// plaintext the tool that made the frame says it holds.
    ///
    /// The frames come from two implementations that are neither this one
    /// nor each other: the reference `zstd` CLI v1.5.7 at levels 1, 3, 9,
    /// 19 and 22 (including `--long`), and `klauspost/compress`, a Go
    /// implementation that is not a binding to libzstd. rgx-core has no
    /// encoder, so every frame here is output this project did not produce.
    #[cfg(feature = "decompress")]
    #[test]
    fn every_reference_zstd_frame_decodes() {
        use crate::budget::testing::locked;
        /// (frame, plaintext, what produced it)
        const CASES: &[(&[u8], &[u8], &str)] = &[
            (
                include_bytes!("../testdata/zstd_text_l1.zst"),
                include_bytes!("../testdata/zstd_text.plain"),
                "zstd -1",
            ),
            (
                include_bytes!("../testdata/zstd_text_l3.zst"),
                include_bytes!("../testdata/zstd_text.plain"),
                "zstd -3",
            ),
            (
                include_bytes!("../testdata/zstd_text_l9.zst"),
                include_bytes!("../testdata/zstd_text.plain"),
                "zstd -9",
            ),
            (
                include_bytes!("../testdata/zstd_text_l19.zst"),
                include_bytes!("../testdata/zstd_text.plain"),
                "zstd -19 --ultra",
            ),
            (
                include_bytes!("../testdata/zstd_text_u22.zst"),
                include_bytes!("../testdata/zstd_text.plain"),
                "zstd -22 --ultra --long",
            ),
            (
                include_bytes!("../testdata/zstd_text_l3_nosum.zst"),
                include_bytes!("../testdata/zstd_text.plain"),
                "zstd -3 --no-check",
            ),
            (
                include_bytes!("../testdata/zstd_text_l3_nofcs.zst"),
                include_bytes!("../testdata/zstd_text.plain"),
                "zstd -3, streamed",
            ),
            (
                include_bytes!("../testdata/zstd_records_l3.zst"),
                include_bytes!("../testdata/zstd_records.plain"),
                "zstd -3",
            ),
            (
                include_bytes!("../testdata/zstd_rand_l3.zst"),
                include_bytes!("../testdata/zstd_rand.bin"),
                "zstd -3, incompressible",
            ),
            (
                include_bytes!("../testdata/zstd_noise_l3.zst"),
                include_bytes!("../testdata/zstd_noise.bin"),
                "zstd -3, no sequences",
            ),
            (
                include_bytes!("../testdata/zstd_runs_l3.zst"),
                include_bytes!("../testdata/zstd_runs.bin"),
                "zstd -3, RLE block",
            ),
            (
                include_bytes!("../testdata/zstd_longrange_l3.zst"),
                include_bytes!("../testdata/zstd_longrange.plain"),
                "zstd -3, long-distance",
            ),
            (
                include_bytes!("../testdata/zstd_longrange_u22.zst"),
                include_bytes!("../testdata/zstd_longrange.plain"),
                "zstd -22 --ultra --long",
            ),
            (
                include_bytes!("../testdata/zstd_tiny.zst"),
                include_bytes!("../testdata/zstd_tiny.plain"),
                "zstd -3, 3 bytes",
            ),
            (
                include_bytes!("../testdata/zstd_empty.zst"),
                b"",
                "zstd -3, empty",
            ),
            (
                include_bytes!("../testdata/zstd_seqheavy_l1.zst"),
                include_bytes!("../testdata/zstd_seqheavy.bin"),
                "zstd -1, sequence-heavy",
            ),
            (
                include_bytes!("../testdata/zstd_wc12_l3.zst"),
                include_bytes!("../testdata/zstd_wc12.bin"),
                "zstd -3, four-stream literals",
            ),
            (
                include_bytes!("../testdata/zstd_wc40_l3.zst"),
                include_bytes!("../testdata/zstd_wc40.bin"),
                "zstd -3, four-stream literals",
            ),
            (
                include_bytes!("../testdata/zstd_wc40_l3_win.zst"),
                include_bytes!("../testdata/zstd_wc40.bin"),
                "zstd -3 via a pipe, window descriptor",
            ),
            (
                include_bytes!("../testdata/zstd_blocks_l3.zst"),
                include_bytes!("../testdata/zstd_blocks.plain"),
                "zstd -3, many blocks",
            ),
            (
                include_bytes!("../testdata/zstd_blocks_u19.zst"),
                include_bytes!("../testdata/zstd_blocks.plain"),
                "zstd -19 --ultra, treeless literals",
            ),
            (
                include_bytes!("../testdata/zstd_go_fastest.zst"),
                include_bytes!("../testdata/zstd_text.plain"),
                "klauspost/compress, fastest",
            ),
            (
                include_bytes!("../testdata/zstd_go_default.zst"),
                include_bytes!("../testdata/zstd_text.plain"),
                "klauspost/compress, default",
            ),
            (
                include_bytes!("../testdata/zstd_go_better.zst"),
                include_bytes!("../testdata/zstd_blocks.plain"),
                "klauspost/compress, better",
            ),
            (
                include_bytes!("../testdata/zstd_go_best.zst"),
                include_bytes!("../testdata/zstd_longrange.plain"),
                "klauspost/compress, best",
            ),
            (
                include_bytes!("../testdata/zstd_go_nosum.zst"),
                include_bytes!("../testdata/zstd_records.plain"),
                "klauspost/compress, no checksum",
            ),
        ];
        locked(|| {
            for (frame, want, label) in CASES {
                let b = rgx_core::compress::zstd::ZstdDecoder::new()
                    .decode_bounded(frame, u64::MAX)
                    .unwrap_or_else(|e| panic!("{label}: {e:?}"));
                assert!(!b.capped, "{label}");
                assert_eq!(b.bytes, *want, "{label}");
                assert_eq!(
                    b.bytes,
                    zstd::stream::decode_all(*frame).expect(label),
                    "{label}"
                );
            }
        });
    }

    /// The in-house decoder and the `zstd` crate must agree byte for byte on
    /// frames neither of them produced: a corpus of inputs encoded at every
    /// level the `zstd` crate offers, plus mutations of a real frame that
    /// either decode to the same bytes or are refused by both.
    #[cfg(feature = "decompress")]
    #[test]
    fn the_in_house_decoder_agrees_with_the_zstd_crate() {
        use crate::budget::testing::locked;
        /// Deterministic, no `rand` in the dependency set.
        fn corpus() -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            let mut x: u64 = 0x243F_6A88_85A3_08D3;
            let mut next = move || {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x
            };
            // empty, tiny, and each awkward size around a block boundary
            out.push(Vec::new());
            for n in [
                1usize, 2, 3, 7, 31, 32, 33, 255, 256, 1023, 1024, 4095, 4096, 65_535, 65_536,
                131_071, 131_072, 131_073,
            ] {
                out.push((0..n).map(|i| (i % 251) as u8).collect());
                out.push(vec![b'x'; n]);
            }
            // incompressible
            for n in [1000usize, 40_000, 150_000] {
                out.push((0..n).map(|_| (next() >> 33) as u8).collect());
            }
            // one byte value only, and two alternating
            out.push(vec![b'A'; 200_000]);
            out.push(
                (0..200_000)
                    .map(|i| if i % 2 == 0 { b'A' } else { b'B' })
                    .collect(),
            );
            // highly repetitive, and text-shaped
            let lorem = b"the quick brown fox jumps over the lazy dog. ";
            out.push(lorem.iter().cycle().take(200_000).copied().collect());
            let mut rec = Vec::new();
            for i in 0..8_000u32 {
                rec.extend_from_slice(
                    format!("id={i},name=w{},price={}.50,tag=a,b,c\n", i % 97, i % 13).as_bytes(),
                );
            }
            out.push(rec);
            // long-distance matches: the same block again, far apart
            let base: Vec<u8> = (0..65_536).map(|_| (next() >> 33) as u8).collect();
            let mut far = base.clone();
            far.extend(std::iter::repeat_n(0u8, 150_000));
            far.extend_from_slice(&base);
            far.extend(std::iter::repeat_n(0xFFu8, 100_000));
            far.extend_from_slice(&base);
            out.push(far);
            // sequences by the thousand: 4-byte runs of one letter each
            let mut many = Vec::new();
            for _ in 0..40_000 {
                many.extend(std::iter::repeat_n((next() >> 33) as u8, 4));
            }
            out.push(many);
            out
        }

        // Every level on the small inputs, which is where a block-boundary
        // bug shows; a representative spread on the large ones, which cost
        // the same to encode and dominate the runtime.
        locked(|| {
            for (i, plain) in corpus().iter().enumerate() {
                let levels: &[i32] = match plain.len() {
                    0..=4096 => &[1, 2, 3, 5, 9, 12, 15, 19, 22],
                    4097..=65_536 => &[1, 3, 9, 19, 22],
                    _ => &[1, 3, 19],
                };
                for &level in levels {
                    let frame = zstd::stream::encode_all(&plain[..], level)
                        .unwrap_or_else(|e| panic!("corpus {i} level {level}: {e}"));
                    let ours = rgx_core::compress::zstd::ZstdDecoder::new()
                        .decode_bounded(&frame, u64::MAX)
                        .unwrap_or_else(|e| panic!("corpus {i} level {level}: {e:?}"));
                    assert!(!ours.capped);
                    assert_eq!(ours.bytes, *plain, "corpus {i} level {level}");
                }
            }
        });
    }

    /// Concatenated frames decode to the concatenation, and a skippable
    /// frame between them is skipped rather than read as data (§3.1.2).
    #[cfg(feature = "decompress")]
    #[test]
    fn concatenated_and_skippable_zstd_frames() {
        use crate::budget::testing::locked;
        let a = include_bytes!("../testdata/zstd_text_l1.zst");
        let b = include_bytes!("../testdata/zstd_text_l3.zst");
        let plain = include_bytes!("../testdata/zstd_text.plain");
        locked(|| {
            let mut both = a.to_vec();
            both.extend_from_slice(b);
            let mut want = plain.to_vec();
            want.extend_from_slice(plain);
            let got = rgx_core::compress::zstd::ZstdDecoder::new()
                .decode(&both)
                .expect("two frames");
            assert_eq!(got, want);
            assert_eq!(got, zstd::stream::decode_all(&both[..]).expect("libzstd"));

            // Skippable frame: magic 0x184D2A5x, then a 4-byte length.
            let mut skipped = vec![0x5f, 0x2a, 0x4d, 0x18, 0x04, 0x00, 0x00, 0x00, 1, 2, 3, 4];
            skipped.extend_from_slice(a);
            skipped.extend_from_slice(b);
            let got = rgx_core::compress::zstd::ZstdDecoder::new()
                .decode(&skipped)
                .expect("skippable");
            assert_eq!(got, want);
        });
    }

    /// A frame carrying a Dictionary_ID is the one shape the in-house
    /// decoder declines; the adapter must hand it to the `zstd` crate
    /// rather than decode it without the dictionary it was written against.
    ///
    /// libzstd refuses it too -- rgx ships no dictionary -- so the answer is
    /// an error, never a short read that looks like text. The message the
    /// fallback builds is the one that carries both the reason the in-house
    /// decoder gave up and libzstd's own refusal, so asserting on that is
    /// what makes this a test of the fallback rather than of the refusal:
    /// the in-house path alone renders as `zstd frame: ...` and would fail
    /// the prefix check.
    #[cfg(feature = "decompress")]
    #[test]
    fn a_dictionary_frame_falls_back_and_is_still_not_decoded() {
        use crate::budget::testing::locked;
        let frame = [
            0x28u8, 0xb5, 0x2f, 0xfd, 0xa3, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00,
        ];
        assert!(matches!(
            rgx_core::compress::zstd::ZstdDecoder::new().decode_bounded(&frame, u64::MAX),
            Err(rgx_core::compress::error::CompressError::UnsupportedFormat(
                _
            ))
        ));
        locked(|| match Decompress.extract(&frame, "d.zst") {
            Err(e) => {
                let text = format!("{e}");
                assert!(
                    text.starts_with("zstd: "),
                    "the fallback did not run: {text}"
                );
                assert!(text.contains("dictionary"), "{text}");
                // libzstd's own refusal, so the crate really was called
                assert!(text.contains("incomplete frame"), "{text}");
            }
            Ok(_) => panic!("decoded a frame that needs a dictionary rgx does not have"),
        });
    }

    /// The RLE_Literals_Block shape (RFC 8878 §3.1.1.3.1.3) that no encoder
    /// in the reference corpus produces, hand-built and checked against
    /// libzstd, so "libzstd accepts it" is the evidence that it is real.
    #[cfg(feature = "decompress")]
    #[test]
    fn libzstd_agrees_on_the_hand_built_rle_literals_frame() {
        use crate::budget::testing::locked;
        const N: usize = 31;
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xa0];
        frame.extend_from_slice(&(N as u32).to_le_bytes());
        // Literals header: type 1 (RLE), Size_Format 00, a 5-bit size.
        // Bit 3 is the low bit of that size, not a format bit.
        let block: [u8; 3] = [((N as u8) << 3) | 1, b'Z', 0x00];
        let header = ((block.len() as u32) << 3) | (2 << 1) | 1;
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.extend_from_slice(&block);
        locked(|| {
            let libzstd = zstd::stream::decode_all(&frame[..]).expect("libzstd accepts the frame");
            assert_eq!(libzstd, vec![b'Z'; N]);
            let ours = rgx_core::compress::zstd::ZstdDecoder::new()
                .decode(&frame)
                .expect("ours");
            assert_eq!(ours, libzstd);
        });
    }

    /// A `.zst` that the byte budget has to stop, which is the one the
    /// frame header can answer before a single byte expands.
    #[cfg(feature = "decompress")]
    #[test]
    fn a_declared_bomb_stops_at_the_byte_budget() {
        const LIMIT: u64 = 1 << 20;
        let bomb = bzst_of_runs(8 << 20);
        assert!(
            zstd::stream::decode_all(&bomb[..]).is_ok(),
            "libzstd calls it a real frame"
        );
        crate::budget::testing::under_budget(64, LIMIT, || {
            let Outcome::Members(m) = Decompress.extract(&bomb, "bomb.zst").expect("bomb") else {
                panic!("members")
            };
            assert_eq!(
                m.len(),
                2,
                "notice plus payload: {:?}",
                m.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>()
            );
            assert_eq!(m[0].0, crate::budget::DECOMPRESSION_NOTE);
            assert!(m[1].1.is_empty(), "expanded {} bytes", m[1].1.len());
            let text = String::from_utf8(m[0].1.clone()).expect("the notice is text");
            assert!(text.contains("decompression truncated"), "{text}");
        });
    }

    /// Eight megabytes of one byte in about twenty bytes of RLE blocks.
    /// Valid per RFC 8878, so `zstd -t` calls it good: a bomb, not a
    /// malformed file. Hand-built because no reference encoder will make one
    /// at this ratio, and it is not evidence about any real `.zst` -- the
    /// fixtures above are.
    #[cfg(feature = "decompress")]
    fn bzst_of_runs(total: u32) -> Vec<u8> {
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0xa0];
        frame.extend_from_slice(&total.to_le_bytes());
        // A block may not regenerate more than `Block_Maximum_Size`.
        const CHUNK: u32 = 128 * 1024;
        let mut left = total;
        loop {
            let last = left <= CHUNK;
            let size = left.min(CHUNK);
            left -= size;
            let h = (size << 3) | (1 << 1) | u32::from(last);
            frame.extend_from_slice(&h.to_le_bytes()[..3]);
            frame.push(b'Q');
            if last {
                break;
            }
        }
        frame
    }

    /// What the decoder claims to cover, checked against the frames rather
    /// than asserted. A coverage claim that is only a comment is a guess:
    /// this walks each fixture's block, literals and sequence headers and
    /// requires the corpus really to exercise every shape listed below, so a
    /// fixture set that stops covering one cannot leave the claim standing.
    #[cfg(feature = "decompress")]
    #[test]
    fn the_zstd_corpus_exercises_every_shape_claimed() {
        #[derive(Default)]
        struct Seen {
            raw_block: bool,
            rle_block: bool,
            compressed_block: bool,
            raw_literals: bool,
            rle_literals: bool,
            huf_literals: bool,
            treeless_literals: bool,
            huffman_one_stream: bool,
            huffman_four_streams: bool,
            ll_predef: bool,
            ll_rle: bool,
            ll_fse: bool,
            ll_repeat: bool,
            ml_predef: bool,
            ml_rle: bool,
            ml_fse: bool,
            ml_repeat: bool,
            of_predef: bool,
            of_rle: bool,
            of_fse: bool,
            of_repeat: bool,
            checksum: bool,
            no_checksum: bool,
            single_segment: bool,
            window_descriptor: bool,
            content_size: bool,
            no_content_size: bool,
            multi_frame: bool,
            zero_sequences: bool,
        }
        const FRAMES: &[&[u8]] = &[
            include_bytes!("../testdata/zstd_text_l1.zst"),
            include_bytes!("../testdata/zstd_text_l3.zst"),
            include_bytes!("../testdata/zstd_text_l9.zst"),
            include_bytes!("../testdata/zstd_text_l19.zst"),
            include_bytes!("../testdata/zstd_text_u22.zst"),
            include_bytes!("../testdata/zstd_text_l3_nosum.zst"),
            include_bytes!("../testdata/zstd_text_l3_nofcs.zst"),
            include_bytes!("../testdata/zstd_records_l3.zst"),
            include_bytes!("../testdata/zstd_rand_l3.zst"),
            include_bytes!("../testdata/zstd_noise_l3.zst"),
            include_bytes!("../testdata/zstd_runs_l3.zst"),
            include_bytes!("../testdata/zstd_longrange_l3.zst"),
            include_bytes!("../testdata/zstd_longrange_u22.zst"),
            include_bytes!("../testdata/zstd_tiny.zst"),
            include_bytes!("../testdata/zstd_empty.zst"),
            include_bytes!("../testdata/zstd_seqheavy_l1.zst"),
            include_bytes!("../testdata/zstd_wc12_l3.zst"),
            include_bytes!("../testdata/zstd_wc40_l3.zst"),
            include_bytes!("../testdata/zstd_wc40_l3_win.zst"),
            include_bytes!("../testdata/zstd_blocks_l3.zst"),
            include_bytes!("../testdata/zstd_blocks_u19.zst"),
            include_bytes!("../testdata/zstd_go_fastest.zst"),
            include_bytes!("../testdata/zstd_go_default.zst"),
            include_bytes!("../testdata/zstd_go_better.zst"),
            include_bytes!("../testdata/zstd_go_best.zst"),
            include_bytes!("../testdata/zstd_go_nosum.zst"),
            include_bytes!("../testdata/zstd_multiframe.zst"),
        ];
        fn mark(v: u8, pre: &mut bool, rle: &mut bool, fse: &mut bool, rep: &mut bool) {
            match v {
                0 => *pre = true,
                1 => *rle = true,
                2 => *fse = true,
                _ => *rep = true,
            }
        }
        let mut seen = Seen::default();
        let mut frames = 0usize;
        for frame in FRAMES {
            let mut p = 0usize;
            while p + 4 <= frame.len() {
                let magic =
                    u32::from_le_bytes([frame[p], frame[p + 1], frame[p + 2], frame[p + 3]]);
                if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
                    let n = u32::from_le_bytes([
                        frame[p + 4],
                        frame[p + 5],
                        frame[p + 6],
                        frame[p + 7],
                    ]);
                    p += 8 + n as usize;
                    continue;
                }
                assert_eq!(magic, 0xFD2F_B528, "not a zstd frame at {p}");
                frames += 1;
                let fhd = frame[p + 4];
                let has_checksum = fhd & 4 != 0;
                let single = fhd & 0x20 != 0;
                seen.checksum |= has_checksum;
                seen.no_checksum |= !has_checksum;
                seen.single_segment |= single;
                seen.window_descriptor |= !single;
                let fcs = fhd >> 6;
                seen.content_size |= fcs != 0 || single;
                seen.no_content_size |= fcs == 0 && !single;
                let mut q = p + 5;
                if !single {
                    q += 1;
                }
                q += [0usize, 1, 2, 4][(fhd & 3) as usize];
                q += match (fcs, single) {
                    (0, false) => 0,
                    (0, true) => 1,
                    (1, _) => 2,
                    (2, _) => 4,
                    _ => 8,
                };
                loop {
                    let bh = u32::from_le_bytes([frame[q], frame[q + 1], frame[q + 2], 0]);
                    q += 3;
                    let last = bh & 1 != 0;
                    let size = (bh >> 3) as usize;
                    match (bh >> 1) & 3 {
                        0 => {
                            seen.raw_block = true;
                            q += size;
                        }
                        1 => {
                            seen.rle_block = true;
                            q += 1;
                        }
                        2 => {
                            seen.compressed_block = true;
                            let end = q + size;
                            let head = frame[q];
                            let kind = head & 3;
                            let sf = (head >> 2) & 3;
                            seen.raw_literals |= kind == 0;
                            seen.rle_literals |= kind == 1;
                            seen.huf_literals |= kind == 2;
                            seen.treeless_literals |= kind == 3;
                            if kind < 2 {
                                let hsize = match sf {
                                    0 | 2 => 1,
                                    1 => 2,
                                    _ => 3,
                                };
                                let regen = match sf {
                                    0 | 2 => head as usize >> 3,
                                    1 => u16::from_le_bytes([frame[q], frame[q + 1]]) as usize >> 4,
                                    _ => {
                                        let v = frame[q] as u32
                                            | (frame[q + 1] as u32) << 8
                                            | (frame[q + 2] as u32) << 16;
                                        v as usize >> 4
                                    }
                                };
                                q += hsize + if kind == 0 { regen } else { 1 };
                            } else {
                                let lhc = u32::from_le_bytes([
                                    frame[q],
                                    frame[q + 1],
                                    frame[q + 2],
                                    frame[q + 3],
                                ]);
                                let (hsize, regen, csize) = match sf {
                                    0 | 1 => (
                                        3usize,
                                        ((lhc >> 4) & 0x3FF) as usize,
                                        ((lhc >> 14) & 0x3FF) as usize,
                                    ),
                                    2 => (
                                        4,
                                        ((lhc >> 4) & 0x3FFF) as usize,
                                        ((lhc >> 18) & 0x3FFF) as usize,
                                    ),
                                    _ => (
                                        5,
                                        ((lhc >> 4) & 0x3FFFF) as usize,
                                        ((lhc >> 22) as usize) | ((frame[q + 4] as usize) << 10),
                                    ),
                                };
                                seen.huffman_one_stream |= sf == 0;
                                seen.huffman_four_streams |= sf != 0;
                                assert!(
                                    sf == 0 || regen >= 6,
                                    "four Huffman streams need six literals"
                                );
                                q += hsize + csize;
                            }
                            let b0 = frame[q];
                            q += 1;
                            let nb = if b0 == 0 {
                                0
                            } else if b0 < 128 {
                                b0 as usize
                            } else if b0 == 255 {
                                u16::from_le_bytes([frame[q], frame[q + 1]]) as usize + 0x7F00
                            } else {
                                ((b0 as usize - 128) << 8) + frame[q] as usize
                            };
                            q += if b0 == 255 {
                                2
                            } else if b0 >= 128 {
                                1
                            } else {
                                0
                            };
                            seen.zero_sequences |= nb == 0;
                            if nb > 0 {
                                let modes = frame[q];
                                mark(
                                    modes >> 6,
                                    &mut seen.ll_predef,
                                    &mut seen.ll_rle,
                                    &mut seen.ll_fse,
                                    &mut seen.ll_repeat,
                                );
                                mark(
                                    (modes >> 4) & 3,
                                    &mut seen.of_predef,
                                    &mut seen.of_rle,
                                    &mut seen.of_fse,
                                    &mut seen.of_repeat,
                                );
                                mark(
                                    (modes >> 2) & 3,
                                    &mut seen.ml_predef,
                                    &mut seen.ml_rle,
                                    &mut seen.ml_fse,
                                    &mut seen.ml_repeat,
                                );
                            }
                            q = end;
                        }
                        _ => panic!("reserved block type"),
                    }
                    if last {
                        break;
                    }
                }
                p = q;
                if has_checksum {
                    p += 4;
                }
                if p < frame.len() {
                    seen.multi_frame = true;
                }
            }
        }
        assert!(frames > 1, "the corpus has to hold more than one frame");
        assert!(seen.multi_frame, "no frame is followed by another");
        for (what, got) in [
            ("Raw_Block", seen.raw_block),
            ("RLE_Block", seen.rle_block),
            ("Compressed_Block", seen.compressed_block),
            ("Raw_Literals_Block", seen.raw_literals),
            ("Compressed_Literals_Block", seen.huf_literals),
            ("Treeless_Literals_Block", seen.treeless_literals),
            (
                "a one-stream Huffman literals block",
                seen.huffman_one_stream,
            ),
            (
                "a four-stream Huffman literals block",
                seen.huffman_four_streams,
            ),
            ("literals length Predefined_Mode", seen.ll_predef),
            ("literals length RLE_Mode", seen.ll_rle),
            ("literals length FSE_Compressed_Mode", seen.ll_fse),
            ("literals length Repeat_Mode", seen.ll_repeat),
            ("match length Predefined_Mode", seen.ml_predef),
            ("match length RLE_Mode", seen.ml_rle),
            ("match length FSE_Compressed_Mode", seen.ml_fse),
            ("offset Predefined_Mode", seen.of_predef),
            ("offset RLE_Mode", seen.of_rle),
            ("offset FSE_Compressed_Mode", seen.of_fse),
            ("offset Repeat_Mode", seen.of_repeat),
            ("a content checksum", seen.checksum),
            ("a frame with no content checksum", seen.no_checksum),
            ("a single-segment frame header", seen.single_segment),
            ("a window descriptor", seen.window_descriptor),
            ("a declared content size", seen.content_size),
            (
                "a frame with no declared content size",
                seen.no_content_size,
            ),
            ("a block with no sequences", seen.zero_sequences),
        ] {
            assert!(got, "the corpus does not exercise {what}");
        }
        // RLE_Literals_Block is the one shape no encoder in reach produces;
        // it is covered by a hand-built frame checked against libzstd above.
        assert!(
            !seen.rle_literals,
            "an encoder did produce RLE literals: add them here"
        );
    }

    #[cfg(feature = "decompress")]
    #[test]
    fn gz_becomes_inner_name() {
        let gz = rgx_core::compress::gzip::GzipWriter::new().encode(b"payload");
        let out = Decompress.extract(&gz, "logs.tar.gz").unwrap();
        match out {
            Outcome::Members(m) => {
                assert_eq!(m[0].0, "logs.tar");
                assert_eq!(m[0].1, b"payload");
            }
            _ => panic!("expected members"),
        }
    }

    /// Third-party vector, end to end: a `.lz4` written by the reference
    /// `lz4` CLI (v1.10.0) has to come back out of the adapter, not just out
    /// of the decoder in isolation, or a change to the call site could swap
    /// in something these fixtures never tested. Provenance and the full
    /// vector list are in `testdata/lz4_README.md`.
    #[cfg(feature = "decompress")]
    #[test]
    fn lz4_reference_frame_through_the_adapter() {
        let cases: [(&[u8], &[u8], &str); 4] = [
            (
                include_bytes!("../testdata/lz4_text_plain.lz4"),
                include_bytes!("../testdata/lz4_text.expected"),
                "plain",
            ),
            (
                include_bytes!("../testdata/lz4_text_bx_csize.lz4"),
                include_bytes!("../testdata/lz4_text.expected"),
                "block + content checksum + content size",
            ),
            (
                include_bytes!("../testdata/lz4_binary_b4.lz4"),
                include_bytes!("../testdata/lz4_binary.expected"),
                "stored (uncompressed) block",
            ),
            (
                include_bytes!("../testdata/lz4_big_bd.lz4"),
                include_bytes!("../testdata/lz4_big.expected"),
                "dependent blocks, 4 in one frame",
            ),
        ];
        for (frame, expected, label) in cases {
            let out = crate::budget::testing::locked(|| Decompress.extract(frame, "payload.lz4"));
            match out.unwrap() {
                Outcome::Members(m) => {
                    assert_eq!(m[0].0, "payload", "{label}");
                    assert_eq!(m[0].1, expected, "{label}");
                }
                _ => panic!("{label}: expected members"),
            }
        }
    }

    /// Third-party vectors. Every `.bz2` file here was emitted by the
    /// reference `bzip2` CLI, 1.0.8 of 13-Jul-2019 (the original Julian
    /// Seward release), not by anything in this repository. A round trip
    /// through our own encoder would prove nothing: it passes just as
    /// happily against a broken implementation.
    #[cfg(feature = "decompress")]
    mod oracle {
        use super::*;

        /// Same for a `.bz2` emitted by the reference bzip2 CLI, decoded by
        /// `rgx_core::compress::bzip2` — the in-house decoder.
        macro_rules! bz2_decodes {
            ($test:ident, $stem:literal) => {
                #[test]
                fn $test() {
                    let compressed = include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/testdata/",
                        $stem,
                        ".bz2"
                    ));
                    let expected = include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/testdata/",
                        $stem,
                        ".bz2.expected"
                    ));
                    match crate::budget::testing::locked(|| {
                        Decompress.extract(compressed, "fixture.bz2")
                    })
                    .expect("decode .bz2")
                    {
                        Outcome::Members(m) => {
                            assert_eq!(m[0].0, "fixture", "inner name for {}", $stem);
                            assert_eq!(m[0].1.len(), expected.len(), "length for {}", $stem);
                            assert!(m[0].1 == expected, "bytes for {}", $stem);
                        }
                        _ => panic!("expected members"),
                    }
                }
            };
        }

        bz2_decodes!(bzip2_cli_l1_lorem_decodes, "bzip2_cli_l1_lorem");
        bz2_decodes!(bzip2_cli_l9_repetitive_decodes, "bzip2_cli_l9_rep");
        bz2_decodes!(bzip2_cli_l1_random_decodes, "bzip2_cli_l1_rand");
        bz2_decodes!(bzip2_cli_l9_empty_decodes, "bzip2_cli_l9_empty");
        bz2_decodes!(bzip2_cli_l9_tiny_decodes, "bzip2_cli_l9_tiny");
    }

    /// The in-house RFC 7932 decoder, measured against files the reference
    /// `brotli` CLI wrote. A round trip through our own encoder would
    /// prove nothing here -- it passes just as happily against a broken
    /// implementation -- so every vector is a third party's output, and the
    /// bar is byte-identity against the plaintext, not "it decoded
    /// something".
    ///
    /// Provenance, the full vector list and the exact commands are in
    /// `testdata/brotli_README.md`.
    #[cfg(feature = "decompress")]
    mod brotli_oracle {
        use super::*;
        use crate::brotli::coverage as cov;

        /// A file under `testdata/`, by name.
        macro_rules! t {
            ($name:literal) => {
                include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/", $name))
                    as &'static [u8]
            };
        }

        /// (vector, plaintext, what it pins down)
        const VECTORS: &[(&[u8], &[u8], &str)] = &[
            // Every quality the reference CLI exposes, on English text.
            // q0 writes stored meta-blocks, q1..q9 build Huffman trees and
            // block splits, and q10 and q11 are the two that reach for the
            // static dictionary.
            (
                t!("brotli_text_q0.br"),
                t!("brotli_text.plain"),
                "q0, stored meta-blocks",
            ),
            (t!("brotli_text_q1.br"), t!("brotli_text.plain"), "q1"),
            (t!("brotli_text_q2.br"), t!("brotli_text.plain"), "q2"),
            (t!("brotli_text_q3.br"), t!("brotli_text.plain"), "q3"),
            (t!("brotli_text_q4.br"), t!("brotli_text.plain"), "q4"),
            (t!("brotli_text_q5.br"), t!("brotli_text.plain"), "q5"),
            (t!("brotli_text_q6.br"), t!("brotli_text.plain"), "q6"),
            (t!("brotli_text_q7.br"), t!("brotli_text.plain"), "q7"),
            (t!("brotli_text_q8.br"), t!("brotli_text.plain"), "q8"),
            (t!("brotli_text_q9.br"), t!("brotli_text.plain"), "q9"),
            (
                t!("brotli_text_q10.br"),
                t!("brotli_text.plain"),
                "q10, static dictionary",
            ),
            (
                t!("brotli_text_q11.br"),
                t!("brotli_text.plain"),
                "q11, static dictionary",
            ),
            // The stream header, one field at a time: 10 is the smallest
            // window RFC 7932 has and 24 the largest, and 0 lets the
            // encoder choose.
            (
                t!("brotli_text_q11_w10.br"),
                t!("brotli_text.plain"),
                "WBITS 10",
            ),
            (
                t!("brotli_text_q11_w24.br"),
                t!("brotli_text.plain"),
                "WBITS 24",
            ),
            (
                t!("brotli_text_q5_w0.br"),
                t!("brotli_text.plain"),
                "WBITS chosen by the encoder",
            ),
            // A metadata meta-block, which carries bytes that are neither
            // output nor window. The CLI emits one for `-C`.
            (
                t!("brotli_text_q5_comment.br"),
                t!("brotli_text.plain"),
                "metadata meta-block",
            ),
            // Highly repetitive: at q5 and above this is a short stream of
            // a single-symbol literal code and long backward references.
            (
                t!("brotli_rep_q0.br"),
                t!("brotli_rep.plain"),
                "repetitive, q0",
            ),
            (
                t!("brotli_rep_q5.br"),
                t!("brotli_rep.plain"),
                "repetitive, q5",
            ),
            (
                t!("brotli_rep_q9.br"),
                t!("brotli_rep.plain"),
                "repetitive, q9",
            ),
            (
                t!("brotli_rep_q11.br"),
                t!("brotli_rep.plain"),
                "repetitive, q11",
            ),
            // Incompressible: the encoder cannot do better than stored, so
            // this is the ISUNCOMPRESSED meta-block path end to end.
            (t!("brotli_rand_q0.br"), t!("brotli_rand.bin"), "random, q0"),
            (t!("brotli_rand_q1.br"), t!("brotli_rand.bin"), "random, q1"),
            (t!("brotli_rand_q5.br"), t!("brotli_rand.bin"), "random, q5"),
            (t!("brotli_rand_q9.br"), t!("brotli_rand.bin"), "random, q9"),
            (
                t!("brotli_rand_q11.br"),
                t!("brotli_rand.bin"),
                "random, q11",
            ),
            // Runs of one byte and short runs, which the encoder turns
            // into long copies at small distance.
            (t!("brotli_runs_q0.br"), t!("brotli_runs.bin"), "runs, q0"),
            (t!("brotli_runs_q5.br"), t!("brotli_runs.bin"), "runs, q5"),
            (t!("brotli_runs_q9.br"), t!("brotli_runs.bin"), "runs, q9"),
            (t!("brotli_runs_q11.br"), t!("brotli_runs.bin"), "runs, q11"),
            // Text in nineteen scripts plus emoji, CJK and RTL, so the
            // UTF8 and Signed literal context modes have something to
            // discriminate on.
            (t!("brotli_utf8_q0.br"), t!("brotli_utf8.plain"), "utf8, q0"),
            (t!("brotli_utf8_q1.br"), t!("brotli_utf8.plain"), "utf8, q1"),
            (t!("brotli_utf8_q5.br"), t!("brotli_utf8.plain"), "utf8, q5"),
            (t!("brotli_utf8_q9.br"), t!("brotli_utf8.plain"), "utf8, q9"),
            (
                t!("brotli_utf8_q10.br"),
                t!("brotli_utf8.plain"),
                "utf8, q10",
            ),
            (
                t!("brotli_utf8_q11.br"),
                t!("brotli_utf8.plain"),
                "utf8, q11",
            ),
            // A large payload with a repeat 16 KB back and another 90 KB
            // back, so distances past the immediate neighbourhood and
            // several meta-blocks in one stream are both covered.
            (t!("brotli_big_q0.br"), t!("brotli_big.plain"), "large, q0"),
            (t!("brotli_big_q1.br"), t!("brotli_big.plain"), "large, q1"),
            (t!("brotli_big_q5.br"), t!("brotli_big.plain"), "large, q5"),
            (t!("brotli_big_q9.br"), t!("brotli_big.plain"), "large, q9"),
            (
                t!("brotli_big_q11.br"),
                t!("brotli_big.plain"),
                "large, q11",
            ),
            // The two ends of the size range.
            (t!("brotli_one_q11.br"), t!("brotli_one.plain"), "one byte"),
            (
                t!("brotli_tiny_q5.br"),
                t!("brotli_tiny.plain"),
                "two bytes",
            ),
            (t!("brotli_empty_q9.br"), t!("brotli_empty.plain"), "empty"),
        ];

        /// The decoder itself, on every vector, byte for byte.
        #[test]
        fn every_reference_brotli_stream_decodes_byte_for_byte() {
            for &(stream, want, label) in VECTORS {
                let got = crate::brotli::BrotliDecoder::new()
                    .decode_bounded(stream, u64::MAX)
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
                assert!(!got.capped, "{label}");
                assert_eq!(got.declared, None, "{label}: brotli declares no size");
                assert_eq!(got.bytes.len(), want.len(), "{label}: length");
                assert!(got.bytes == want, "{label}: bytes");
            }
        }

        /// And end to end, through the shipped `.br` path, so a change to
        /// the call site cannot swap in something these vectors never
        /// tested. This is the one that says rgx decodes a `.br`; it is NOT
        /// the one that says rgx can *search* one — see
        /// `the_corpus_holds_a_payload_with_a_nul_in_it` for why that
        /// distinction is the whole reason a real defect shipped green.
        #[test]
        fn every_reference_brotli_stream_through_the_adapter() {
            for &(stream, want, label) in VECTORS {
                let out =
                    crate::budget::testing::locked(|| Decompress.extract(stream, "fixture.br"))
                        .unwrap_or_else(|e| panic!("{label}: {e}"));
                let Outcome::Members(m) = out else {
                    panic!("{label}: expected members")
                };
                let names: Vec<&str> = m.iter().map(|(n, _)| n.as_str()).collect();
                assert_eq!(names, ["fixture"], "{label}");
                assert!(m[0].1 == want, "{label}: bytes through the adapter");
            }
        }

        /// **The corpus has to hold a payload with a NUL in it, and this is
        /// the assertion that says so.**
        ///
        /// The decode-only tests above would stay green if every fixture
        /// payload became binary: a single-file decompressor's member comes
        /// back labelled `"raw"`, the searcher's on-disk NUL heuristic runs
        /// on the *decoded* bytes, and `BinaryDetection::Quit` then reports
        /// nothing once a NUL sits in the first 64 KiB. The fixture set has
        /// to carry a NUL inside that window — and more than one of them —
        /// so it stays honest instead of silently testing nothing.
        #[test]
        fn the_corpus_holds_a_payload_with_a_nul_in_it() {
            let mut with_nul: Vec<&str> = Vec::new();
            let mut earliest = usize::MAX;
            for &(stream, want, label) in VECTORS {
                if let Some(at) = want.iter().position(|&b| b == 0) {
                    with_nul.push(label);
                    earliest = earliest.min(at);
                    // and the adapter hands those bytes on unchanged
                    let out =
                        crate::budget::testing::locked(|| Decompress.extract(stream, "fixture.br"))
                            .unwrap_or_else(|e| panic!("{label}: {e}"));
                    let Outcome::Members(m) = out else {
                        panic!("{label}: expected members")
                    };
                    assert!(m[0].1 == want, "{label}: bytes through the adapter");
                }
            }
            assert!(
                !with_nul.is_empty(),
                "no fixture payload holds a NUL, so a decoded payload that is \
                 binary by the on-disk rule is no longer in the corpus"
            );
            assert!(
                earliest < 64 * 1024,
                "the NULs are all past the 64 KiB window: {:?} at {earliest} is \
                 not the shape that hid the defect",
                with_nul
            );
            // named, so a fixture swap that keeps one NUL-bearing payload but
            // drops the rest still shows what is left
            assert!(with_nul.len() >= 3, "only {with_nul:?} carry a NUL");
        }

        /// What the decoder claims to cover, checked against the corpus
        /// rather than asserted: `crate::brotli::coverage` counts what the
        /// decode actually reached, so a fixture set that stops exercising
        /// a path cannot leave the claim standing. The counters are
        /// process-wide, so this decodes the whole corpus itself rather
        /// than trusting whatever ran first.
        #[test]
        fn the_brotli_corpus_exercises_every_shape_claimed() {
            crate::brotli::coverage::reset();
            for &(stream, _, label) in VECTORS {
                crate::brotli::BrotliDecoder::new()
                    .decode_bounded(stream, u64::MAX)
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
            }
            let n = cov::get;
            assert!(
                n(&cov::METABLOCKS) > 1,
                "the corpus has to hold more than one meta-block"
            );
            assert!(n(&cov::STORED) > 0, "no stored (ISUNCOMPRESSED) meta-block");
            assert!(n(&cov::METADATA) > 0, "no metadata meta-block");
            assert!(n(&cov::BLOCK_SWITCHES) > 0, "no block switch");
            assert!(n(&cov::SIMPLE) > 0, "no simple prefix code");
            assert!(n(&cov::COMPLEX) > 0, "no complex prefix code");
            assert!(n(&cov::SINGLETON) > 0, "no single-symbol prefix code");
            assert!(n(&cov::CONTEXT_MAPS) > 0, "no context map");
            assert!(n(&cov::IMULTIPLE) > 0, "no inverse move-to-front transform");
            assert!(n(&cov::RLE_ZERO) > 0, "no run of zeros in a context map");
            assert!(n(&cov::DIRECT_DIST) > 0, "no NDIRECT distance code");
            assert!(n(&cov::COMPUTED_DIST) > 0, "no computed distance code");
            for (code, seen) in cov::SHORT_DIST.iter().enumerate() {
                assert!(n(seen) > 0, "distance short code {code} is never used");
            }
            // The static dictionary and its transformations are the whole
            // reason this was hard, so they are asserted rather than
            // assumed.
            assert!(
                n(&cov::DICT_WORDS) > 0,
                "the corpus never reaches the static dictionary"
            );
            let transforms = (0..121).filter(|&i| n(&cov::TRANSFORMS[i]) > 0).count();
            assert!(
                transforms > 1,
                "only {transforms} word transformations reached"
            );
            // Every window size the fixtures claim to vary has to actually
            // show up, or the WBITS vectors stopped meaning anything.
            let mut windows: Vec<usize> = (0..25).filter(|&i| n(&cov::WINDOWS[i]) > 0).collect();
            windows.sort_unstable();
            assert!(
                windows.contains(&10) && windows.contains(&24),
                "{windows:?}"
            );
            assert!(windows.len() >= 5, "only {windows:?} window sizes reached");
        }

        /// The context ID formulas, all four. The corpus above reaches
        /// LSB6, UTF8 and Signed; the reference encoder never chose MSB6 on
        /// any vector in it, so that one line is pinned here rather than
        /// left quietly untested.
        #[test]
        fn every_literal_context_mode_is_pinned() {
            use crate::brotli::context_for_test as ctx;
            for p1 in 0..=255u8 {
                for p2 in [0u8, 1, 0x41, 0x7f, 0x80, 0xc3, 0xe4, 0xff] {
                    assert_eq!(ctx(0, p1, p2), p1 & 0x3f, "LSB6 p1={p1:#x}");
                    assert_eq!(ctx(1, p1, p2), p1 >> 2, "MSB6 p1={p1:#x}");
                    assert!(ctx(2, p1, p2) < 64, "UTF8 p1={p1:#x} p2={p2:#x}");
                    assert!(ctx(3, p1, p2) < 64, "Signed p1={p1:#x} p2={p2:#x}");
                }
            }
            // A context ID is 0..63 by construction, and the two
            // multi-table modes reach the top of that range.
            assert_eq!(ctx(0, 0xff, 0xff), 0x3f);
            assert_eq!(ctx(1, 0xff, 0xff), 0x3f);
        }
    }

    /// The member budget: every producer stops on it, a truncated archive
    /// says so, and a legitimate archive under the cap is untouched.
    /// The decompression budget: a stream that expands past the byte
    /// budget stops where the cap is, says so in a member the pipeline
    /// searches, and a stream under the cap is not touched.
    #[cfg(feature = "decompress")]
    mod bounded_output {
        use super::*;
        use crate::budget::testing::{locked, under_budget};
        use crate::budget::DECOMPRESSION_NOTE;

        /// Deflate's bit packing: values go in least-significant bit
        /// first, Huffman codes most-significant bit first (RFC 1951
        /// 3.1.1).
        struct Bits {
            out: Vec<u8>,
            acc: u32,
            n: u32,
        }

        impl Bits {
            fn new() -> Self {
                Self {
                    out: Vec::new(),
                    acc: 0,
                    n: 0,
                }
            }
            fn raw(&mut self, v: u32, n: u32) {
                self.acc |= (v & ((1u32 << n) - 1)) << self.n;
                self.n += n;
                while self.n >= 8 {
                    self.out.push(self.acc as u8);
                    self.acc >>= 8;
                    self.n -= 8;
                }
            }
            fn code(&mut self, v: u32, n: u32) {
                for i in (0..n).rev() {
                    self.raw((v >> i) & 1, 1);
                }
            }
            /// Fixed literal/length code (RFC 1951 3.2.6).
            fn symbol(&mut self, s: u32) {
                match s {
                    0..=143 => self.code(0x30 + s, 8),
                    144..=255 => self.code(0x190 + s - 144, 9),
                    256..=279 => self.code(s - 256, 7),
                    _ => self.code(0xC0 + s - 280, 8),
                }
            }
            fn finish(mut self) -> Vec<u8> {
                if self.n > 0 {
                    self.out.push(self.acc as u8);
                }
                self.out
            }
        }

        fn crc32_of(n: u64) -> u32 {
            let chunk = vec![b'A'; 1 << 16];
            let mut crc = 0xFFFF_FFFFu32;
            let mut left = n;
            while left > 0 {
                let take = left.min(chunk.len() as u64) as usize;
                crc = rgx_core::compress::crc32::crc32_update(crc, &chunk[..take]);
                left -= take as u64;
            }
            !crc
        }

        /// A valid single-member `.gz` holding `total` copies of `A`,
        /// written as one fixed-Huffman block of 258-byte matches at
        /// distance 1. The compressed file is about `total / 86` bytes and
        /// the CRC-32 and ISIZE trailer is the real one, so `gzip -t` calls
        /// it good: this is a bomb, not a malformed file.
        ///
        /// Hand-built because the in-house encoder cannot make 64 MB in
        /// test time and no 64 MB fixture belongs in the tree. It is not
        /// used to prove the decoder right -- that is the reference-CLI
        /// vectors' job, and they still have it.
        fn gz_bomb(total: u64) -> Vec<u8> {
            let mut w = Bits::new();
            w.raw(1, 1); // BFINAL
            w.raw(1, 2); // fixed Huffman
            w.symbol(u32::from(b'A'));
            let mut left = total - 1;
            while left >= 258 {
                w.symbol(285); // length 258, no extra bits
                w.code(0, 5); // distance 1
                left -= 258;
            }
            for _ in 0..left {
                w.symbol(u32::from(b'A'));
            }
            w.symbol(256); // end of block
            let mut gz = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03];
            gz.extend_from_slice(&w.finish());
            gz.extend_from_slice(&crc32_of(total).to_le_bytes());
            gz.extend_from_slice(&(total as u32).to_le_bytes());
            gz
        }

        /// `.z` reaches the adapter through the in-house zlib decoder, and
        /// this crate has no zlib writer, so the fixture is the in-house
        /// encoder's. It is not evidence about libzlib's output; the
        /// rgx-core `zlib_*` vectors are, and they carry their own cap test.
        fn zlib_of(data: &[u8]) -> Vec<u8> {
            rgx_core::compress::zlib::ZlibEncoder::new().encode(data)
        }

        /// libzstd, through this crate's `zstd` dependency.
        fn zst_of(data: &[u8]) -> Vec<u8> {
            zstd::stream::encode_all(data, 3).expect("zstd")
        }

        fn members(out: Outcome) -> Vec<(String, Vec<u8>)> {
            let Outcome::Members(m) = out else {
                panic!("expected members")
            };
            m
        }

        fn names(m: &[(String, Vec<u8>)]) -> Vec<&str> {
            m.iter().map(|(n, _)| n.as_str()).collect()
        }

        fn note(m: &[(String, Vec<u8>)]) -> String {
            String::from_utf8(m[0].1.clone()).expect("the notice is text")
        }

        fn payload(m: &[(String, Vec<u8>)]) -> &[u8] {
            &m[1].1
        }

        /// The builder is only worth anything if the file it makes is a
        /// real one, so check it against the decoder that reads every other
        /// gzip in this tree.
        #[test]
        fn the_bomb_builder_makes_a_real_gzip() {
            let gz = gz_bomb(100_000);
            let out = rgx_core::compress::gzip::GzipReader::decode(&gz).expect("decode");
            assert_eq!(out, vec![b'A'; 100_000]);
            assert!(gz.len() < 4_000, "{} bytes for 100000", gz.len());
        }

        /// The bomb this whole thing exists for. One member, so the member
        /// budget never applies, and small on disk, so the walker's
        /// `Ctx::max_file_size` check against the *compressed* length never
        /// applies either: the decoder's byte budget is the only thing
        /// that can stop it, and the test asserts it does.
        #[test]
        fn a_single_member_bomb_stops_at_the_byte_budget() {
            const LIMIT: u64 = 1 << 20;
            let gz = gz_bomb(64 << 20);
            assert!(gz.len() < 1 << 20, "the bomb is {} bytes on disk", gz.len());

            let (out, elapsed) = under_budget(64, LIMIT, || {
                let t = std::time::Instant::now();
                let m = members(Decompress.extract(&gz, "bomb.gz").expect("extract"));
                (m, t.elapsed())
            });
            assert_eq!(out.len(), 2, "notice plus payload: {:?}", names(&out));
            assert_eq!(out[0].0, DECOMPRESSION_NOTE);
            assert_eq!(out[1].0, "bomb");
            let n = payload(&out).len();
            assert!(
                n as u64 <= LIMIT,
                "emitted {n} bytes under a {LIMIT} byte cap"
            );
            assert!(n as u64 + 258 >= LIMIT, "emitted only {n} of {LIMIT} bytes");
            eprintln!("64 MB bomb stopped at {LIMIT} bytes in {elapsed:?}");
            assert!(elapsed.as_millis() < 500, "took {elapsed:?}");

            let text = note(&out);
            assert!(text.contains("decompression truncated"), "{text}");
            assert!(text.contains(&format!("{n} bytes decoded")), "{text}");
            assert!(
                text.contains(&format!("byte budget: {LIMIT} bytes")),
                "{text}"
            );
        }

        /// Every format the `Decompress` adapter reaches stops on the same
        /// budget, with the notice first every time. The fixtures are
        /// reference-CLI output; only the budget is small, which is the
        /// point -- an entirely legitimate file has to be able to trip it.
        #[test]
        fn every_decompressed_format_stops_at_the_byte_budget() {
            const LIMIT: u64 = 1000;
            let zlib = zlib_of(&b"needle ".repeat(500));
            let zst = zst_of(&b"needle ".repeat(500));
            let cases: [(&[u8], &str, &str); 9] = [
                (
                    include_bytes!("../testdata/bzip2_cli_l9_rep.bz2"),
                    "fixture.bz2",
                    "bzip2, bzip2 1.0.8",
                ),
                (
                    include_bytes!("../testdata/xz_sample.xz"),
                    "fixture.xz",
                    "xz, XZ Utils",
                ),
                (
                    include_bytes!("../testdata/xz_sample.lzma"),
                    "fixture.lzma",
                    "lzma FORMAT_ALONE, liblzma",
                ),
                (
                    include_bytes!("../testdata/lz4_text_plain.lz4"),
                    "fixture.lz4",
                    "lz4 frame without content size, lz4 CLI",
                ),
                (
                    include_bytes!("../testdata/lz4_text_csize.lz4"),
                    "fixture2.lz4",
                    "lz4 frame with content size, lz4 CLI",
                ),
                (
                    include_bytes!("../testdata/lz4legacy_text.lz4"),
                    "fixture3.lz4",
                    "lz4 legacy container, lz4 -l",
                ),
                (
                    include_bytes!("../testdata/brotli_text_q5.br"),
                    "fixture.br",
                    "brotli, brotli 1.2.0",
                ),
                (&zlib, "fixture.z", "zlib framing, in-house encoder"),
                (&zst, "fixture.zst", "zstd, libzstd"),
            ];
            for (data, path, label) in cases {
                let out = under_budget(64, LIMIT, || {
                    members(Decompress.extract(data, path).unwrap())
                });
                assert_eq!(out.len(), 2, "{label}: {:?}", names(&out));
                assert_eq!(out[0].0, DECOMPRESSION_NOTE, "{label}");
                let n = payload(&out).len();
                assert!(
                    n as u64 <= LIMIT,
                    "{label}: emitted {n} under a {LIMIT} cap"
                );
                assert!(
                    note(&out).contains("decompression truncated"),
                    "{label}: {}",
                    note(&out)
                );
            }
        }

        /// The other half of the bargain: a file that fits the budget comes
        /// back whole, with no notice, on every format. Same reference-CLI
        /// files as above.
        #[test]
        fn legitimate_streams_are_not_truncated() {
            let payload = b"needle ".repeat(500);
            let zlib = zlib_of(&payload);
            let zst = zst_of(&payload);
            let cases: [(&[u8], &[u8], &str, &str); 8] = [
                (
                    include_bytes!("../testdata/bzip2_cli_l9_rep.bz2"),
                    include_bytes!("../testdata/bzip2_cli_l9_rep.bz2.expected"),
                    "fixture.bz2",
                    "fixture",
                ),
                (
                    include_bytes!("../testdata/xz_sample.xz"),
                    include_bytes!("../testdata/xz_sample.plain"),
                    "fixture.xz",
                    "fixture",
                ),
                (
                    include_bytes!("../testdata/xz_sample.lzma"),
                    include_bytes!("../testdata/xz_sample.plain"),
                    "fixture.lzma",
                    "fixture",
                ),
                (
                    include_bytes!("../testdata/lz4_text_plain.lz4"),
                    include_bytes!("../testdata/lz4_text.expected"),
                    "fixture.lz4",
                    "fixture",
                ),
                (
                    include_bytes!("../testdata/lz4legacy_text.lz4"),
                    include_bytes!("../testdata/lz4legacy_text.expected"),
                    "fixture3.lz4",
                    "fixture3",
                ),
                (
                    include_bytes!("../testdata/brotli_text_q5.br"),
                    include_bytes!("../testdata/brotli_text.plain"),
                    "fixture.br",
                    "fixture",
                ),
                (&zlib, &payload, "fixture.z", "fixture"),
                (&zst, &payload, "fixture.zst", "fixture"),
            ];
            for (data, expected, path, inner) in cases {
                let out = locked(|| members(Decompress.extract(data, path).unwrap()));
                assert_eq!(out.len(), 1, "{path}: a notice on a file that fits");
                assert_eq!(out[0].0, inner, "{path}");
                assert_eq!(out[0].1, expected, "{path}");
            }
        }

        /// The number the whole thing turns on: a 500 MB `.gz` is under the
        /// default 1 GiB budget and has to come out whole. Ignored by
        /// default because it is ~3 s of decode and 500 MB of allocation;
        /// `cargo test --release -- --ignored` runs it.
        #[test]
        #[ignore = "500 MB of allocation; run with --release --ignored"]
        fn a_five_hundred_megabyte_gzip_still_decompresses() {
            let gz = gz_bomb(500 << 20);
            eprintln!("a 500 MB gzip is {} bytes on disk", gz.len());
            let out = locked(|| members(Decompress.extract(&gz, "big.gz").unwrap()));
            assert_eq!(
                out.len(),
                1,
                "a notice on a file that fits: {:?}",
                names(&out)
            );
            assert_eq!(out[0].1.len(), 500 << 20);
        }
    }

    #[cfg(any(feature = "zip", feature = "sevenz"))]
    mod budgeted_members {
        use super::*;
        #[cfg(feature = "zip")]
        use crate::budget::testing::locked;
        #[cfg(any(feature = "sevenz", feature = "zip"))]
        use crate::budget::testing::under_budget;
        #[cfg(feature = "zip")]
        use crate::budget::TRUNCATION_MEMBER;

        /// A zip with `count` stored members named `f00000.txt`...; the last
        /// one carries `needle`, so a test can prove the members themselves
        /// still come back. Hand-written because there is no zip writer
        /// in-tree; past 65535 entries the 32-bit EOCD saturates and the
        /// zip64 records are where `rgx_core::zip` reads the real count.
        #[cfg(feature = "zip")]
        fn stored_zip(count: usize) -> Vec<u8> {
            let entries: Vec<(String, &[u8])> = (0..count)
                .map(|i| {
                    let payload: &[u8] = if i + 1 == count { b"needle" } else { b"x" };
                    (format!("f{i:05}.txt"), payload)
                })
                .collect();
            zip_of(
                &entries
                    .iter()
                    .map(|(n, d)| (n.as_str(), *d, false))
                    .collect::<Vec<_>>(),
            )
        }

        /// The same, with `count` directory entries ahead of `files` real
        /// ones — a container announcing far more entries than it holds.
        #[cfg(feature = "zip")]
        fn zip_of_dirs_then_files(dirs: usize, files: usize) -> Vec<u8> {
            let mut entries: Vec<(&str, &[u8], bool)> = (0..dirs)
                .map(|i| {
                    let name = format!("d{i:05}/");
                    (
                        Box::leak(name.into_boxed_str()) as &str,
                        b"".as_slice(),
                        true,
                    )
                })
                .collect();
            entries.extend((0..files).map(|i| {
                (
                    Box::leak(format!("f{i:05}.txt").into_boxed_str()) as &str,
                    b"needle".as_slice(),
                    false,
                )
            }));
            zip_of(&entries)
        }

        #[cfg(feature = "zip")]
        fn zip_of(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
            let mut out = Vec::with_capacity(entries.len() * 100);
            let mut central = Vec::with_capacity(entries.len() * 80);
            for (name, data, _) in entries {
                let crc = fuzz::crc32(data);
                let offset = out.len() as u32;
                out.extend_from_slice(b"PK\x03\x04");
                out.extend_from_slice(&20u16.to_le_bytes()); // version needed
                out.extend_from_slice(&[0u8; 4]); // flags, method
                out.extend_from_slice(&[0u8; 4]); // time, date
                out.extend_from_slice(&crc.to_le_bytes());
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                out.extend_from_slice(&(data.len() as u32).to_le_bytes());
                out.extend_from_slice(&(name.len() as u16).to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes()); // extra length
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(data);

                central.extend_from_slice(b"PK\x01\x02");
                central.extend_from_slice(&20u16.to_le_bytes()); // version made by
                central.extend_from_slice(&20u16.to_le_bytes()); // version needed
                central.extend_from_slice(&[0u8; 4]);
                central.extend_from_slice(&[0u8; 4]);
                central.extend_from_slice(&crc.to_le_bytes());
                central.extend_from_slice(&(data.len() as u32).to_le_bytes());
                central.extend_from_slice(&(data.len() as u32).to_le_bytes());
                central.extend_from_slice(&(name.len() as u16).to_le_bytes());
                central.extend_from_slice(&[0u8; 12]); // extra, comment, disk, attrs
                central.extend_from_slice(&offset.to_le_bytes());
                central.extend_from_slice(name.as_bytes());
            }
            let cd_offset = out.len() as u64;
            out.extend_from_slice(&central);
            let cd_size = central.len() as u64;
            let sat = entries.len() > 0xFFFE;
            if sat {
                let eocd64 = out.len() as u64;
                out.extend_from_slice(b"PK\x06\x06");
                out.extend_from_slice(&44u64.to_le_bytes()); // size of this record - 12
                out.extend_from_slice(&45u16.to_le_bytes()); // version made by
                out.extend_from_slice(&45u16.to_le_bytes()); // version needed
                out.extend_from_slice(&0u32.to_le_bytes()); // this disk
                out.extend_from_slice(&0u32.to_le_bytes()); // disk with the directory
                out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
                out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
                out.extend_from_slice(&cd_size.to_le_bytes());
                out.extend_from_slice(&cd_offset.to_le_bytes());
                out.extend_from_slice(b"PK\x06\x07"); // locator
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&eocd64.to_le_bytes());
                out.extend_from_slice(&1u32.to_le_bytes());
            }
            let n = if sat { 0xFFFFu16 } else { entries.len() as u16 };
            out.extend_from_slice(b"PK\x05\x06");
            out.extend_from_slice(&[0u8; 4]); // this disk, disk with the directory
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(&(if sat { 0xFFFF_FFFF } else { cd_size as u32 }).to_le_bytes());
            out.extend_from_slice(
                &(if sat { 0xFFFF_FFFF } else { cd_offset as u32 }).to_le_bytes(),
            );
            out.extend_from_slice(&0u16.to_le_bytes()); // comment length
            out
        }

        #[cfg(all(feature = "zip", feature = "tar"))]
        fn tar_of(count: usize) -> Vec<u8> {
            let mut w = tar::TarWriter::new();
            for i in 0..count {
                let payload = if i + 1 == count {
                    b"needle".to_vec()
                } else {
                    b"x".to_vec()
                };
                w.add_entry(format!("f{i:05}.txt"), payload, 0o644);
            }
            w.finish()
        }

        /// newc archive, as `Cpio` reads it.
        #[cfg(all(
            feature = "zip",
            feature = "tar",
            feature = "cpio",
            feature = "rar",
            feature = "sevenz"
        ))]
        fn cpio_of(count: usize) -> Vec<u8> {
            let mut out = Vec::new();
            for i in 0..count {
                let data: &[u8] = if i + 1 == count { b"needle" } else { b"x" };
                let name = format!("f{i:05}.txt");
                let mut h = b"070701".to_vec();
                let fields: [u64; 13] = [
                    1,
                    0o100644,
                    0,
                    0,
                    1,
                    0,
                    data.len() as u64,
                    0,
                    0,
                    0,
                    0,
                    name.len() as u64 + 1,
                    0,
                ];
                for f in fields {
                    h.extend_from_slice(format!("{f:08x}").as_bytes());
                }
                h.extend_from_slice(name.as_bytes());
                h.push(0);
                while !h.len().is_multiple_of(4) {
                    h.push(0);
                }
                h.extend_from_slice(data);
                while !h.len().is_multiple_of(4) {
                    h.push(0);
                }
                out.extend_from_slice(&h);
            }
            let mut t = b"070701".to_vec();
            for _ in 0..11 {
                t.extend_from_slice(b"00000000");
            }
            t.extend_from_slice(b"TRAILER!!!\0");
            while !t.len().is_multiple_of(4) {
                t.push(0);
            }
            out.extend_from_slice(&t);
            out
        }

        #[cfg(any(feature = "zip", feature = "sevenz"))]
        fn members(out: Outcome) -> Vec<(String, Vec<u8>)> {
            let Outcome::Members(m) = out else {
                panic!("expected members")
            };
            m
        }

        #[cfg(feature = "zip")]
        fn names(m: &[(String, Vec<u8>)]) -> Vec<&str> {
            m.iter().map(|(n, _)| n.as_str()).collect()
        }

        #[cfg(all(feature = "zip", feature = "tar"))]
        fn truncated(m: &[(String, Vec<u8>)]) -> bool {
            names(m).contains(&TRUNCATION_MEMBER)
        }

        /// The member bomb this whole budget exists for: 65 537 stored
        /// entries of one byte. The producer must stop at the budget
        /// without iterating the whole list -- `ZipReader::extract`
        /// scans the entry list by name on every call, which is
        /// quadratic against the declared count.
        #[cfg(feature = "zip")]
        #[test]
        fn zip_member_bomb_is_capped_in_the_producer() {
            let zip = stored_zip(65_537);
            let out = locked(|| members(Zip.extract(&zip, "bomb.zip").unwrap()));
            let budget = crate::budget::budget();
            assert_eq!(
                out.len(),
                budget.members,
                "the producer returned every entry of a 65537-member bomb"
            );
            assert_eq!(out[0].0, TRUNCATION_MEMBER);
            assert_eq!(out[1].0, "f00000.txt");
            assert_eq!(
                out[out.len() - 1].0,
                format!("f{:05}.txt", budget.members - 2),
                "the last member kept is not the last one the budget allows"
            );
            let note = String::from_utf8(out[0].1.clone()).unwrap();
            assert!(note.contains("65537 entries declared"), "{note}");
            assert!(
                note.contains(&format!("{} extracted", budget.members - 1)),
                "{note}"
            );
        }

        /// The other half of the bargain: an archive the budget was sized
        /// for still comes back whole, with no notice.
        #[cfg(all(feature = "zip", feature = "tar"))]
        #[test]
        fn legit_multi_thousand_member_archives_are_not_truncated() {
            let zip = stored_zip(3_000);
            let out = locked(|| members(Zip.extract(&zip, "src.zip").unwrap()));
            assert_eq!(out.len(), 3_000);
            assert!(!truncated(&out), "a 3000-member zip must not be truncated");
            assert_eq!(out[2_999].0, "f02999.txt");
            assert_eq!(out[2_999].1, b"needle");

            let tar = tar_of(3_000);
            let out = locked(|| members(Tar.extract(&tar, "src.tar").unwrap()));
            assert_eq!(out.len(), 3_000);
            assert!(!truncated(&out), "a 3000-member tar must not be truncated");
            assert_eq!(out[2_999].1, b"needle");
        }

        /// Every producer stops at the same budget, and each says so. There
        /// is no 7z writer in-tree, so the 7z arm runs on a reference
        /// three-file archive instead of a synthesised bomb.
        #[cfg(all(
            feature = "zip",
            feature = "tar",
            feature = "cpio",
            feature = "rar",
            feature = "sevenz"
        ))]
        #[test]
        fn every_producer_stops_at_the_member_budget() {
            under_budget(3, 1 << 20, || {
                let out = members(Zip.extract(&stored_zip(5), "a.zip").unwrap());
                assert_eq!(
                    names(&out),
                    vec![TRUNCATION_MEMBER, "f00000.txt", "f00001.txt"]
                );
                assert_eq!(out[2].1, b"x");
            });

            under_budget(3, 1 << 20, || {
                let out = members(Tar.extract(&tar_of(5), "a.tar").unwrap());
                assert_eq!(
                    names(&out),
                    vec![TRUNCATION_MEMBER, "f00000.txt", "f00001.txt"]
                );
                assert_eq!(out[2].1, b"x");
            });

            under_budget(3, 1 << 20, || {
                let out = members(Cpio.extract(&cpio_of(5), "a.cpio").unwrap());
                assert_eq!(
                    names(&out),
                    vec![TRUNCATION_MEMBER, "f00000.txt", "f00001.txt"]
                );
                assert_eq!(out[2].1, b"x");
            });

            under_budget(3, 1 << 20, || {
                let out = members(rar::Rar.extract(&rar_of(5), "a.rar").unwrap());
                assert_eq!(
                    names(&out),
                    vec![TRUNCATION_MEMBER, "f00000.txt", "f00001.txt"]
                );
                assert_eq!(out[2].1, b"x");
            });

            under_budget(2, 1 << 20, || {
                let seven = include_bytes!("../testdata/multifile.7z");
                let out = members(SevenZ.extract(seven, "a.7z").unwrap());
                assert_eq!(out.len(), 2, "{:?}", names(&out));
                assert_eq!(out[0].0, TRUNCATION_MEMBER);
                assert_eq!(
                    out[1].1,
                    include_bytes!("../testdata/multifile.7z.a.txt.expected")
                );
            });
        }

        // ── 7z: folders after the first ──────────────────────────────

        #[cfg(feature = "sevenz")]
        const MULTIFOLDER: &[u8] = include_bytes!("../testdata/sevenz_multifolder.7z");

        /// The fixture must actually have more than one folder, or every
        /// test below passes for the wrong reason -- the defect they pin is
        /// specific to a folder past the first, and a single-folder fixture
        /// cannot exercise it at all.
        #[cfg(feature = "sevenz")]
        #[test]
        fn the_multifolder_fixture_really_holds_several_folders() {
            let arc = sevenz::SevenzArchive::parse(MULTIFOLDER).expect("parse");
            assert!(
                arc.folder_count() > 1,
                "fixture has {} folder(s); it cannot pin a per-folder bug",
                arc.folder_count()
            );
        }

        /// A file past the first folder used to decode the FIRST folder's
        /// packed bytes through its own coder chain, so every such file came
        /// back as a CRC mismatch and the whole archive failed to open.
        ///
        /// The assertion is that it opens AND that the members are not all
        /// the same bytes: an archive that "opened" by handing folder 0 to
        /// every entry would satisfy a bare `.is_ok()`.
        #[cfg(feature = "sevenz")]
        #[test]
        fn a_multifolder_archive_reads_the_folders_past_the_first() {
            let arc = sevenz::SevenzArchive::parse(MULTIFOLDER).expect("parse");
            let mut payloads: Vec<Vec<u8>> = Vec::new();
            for i in 0..arc.files().len() {
                if arc.files()[i].is_directory {
                    continue;
                }
                payloads.push(arc.extract(i).expect("every member decodes"));
            }
            assert!(payloads.len() > arc.folder_count());
            let distinct: std::collections::BTreeSet<&[u8]> =
                payloads.iter().map(|p| p.as_slice()).collect();
            assert!(
                distinct.len() > 1,
                "all {} members decoded to the same bytes; the folders are not \
                 being told apart",
                payloads.len()
            );
        }

        /// One decode per folder, not one per file.
        ///
        /// The adapter held a decoded folder and re-decoded it for every
        /// file in it, so the cost was files-per-folder times the folder's
        /// decode. Counting decodes is the only assertion that holds on any
        /// machine; a timing assertion would be a flaky proxy for the same
        /// contract.
        #[cfg(feature = "sevenz")]
        #[test]
        fn a_folder_is_decoded_once_however_many_files_it_holds() {
            let arc = sevenz::SevenzArchive::parse(MULTIFOLDER).expect("parse");
            let folders = arc.folder_count();

            sevenz::take_folder_decodes();
            let _ = under_budget(64, 1 << 30, || {
                members(SevenZ.extract(MULTIFOLDER, "m.7z").unwrap())
            });
            let decodes = sevenz::take_folder_decodes();

            // Diagnostics for the failure message: which folder each entry
            // lives in. Contiguity is what a one-slot cache needs, and the
            // sequence is what makes a re-decode explainable.
            let seq: Vec<Option<usize>> = (0..arc.files().len())
                .map(|i| {
                    let f = &arc.files()[i];
                    if f.is_directory {
                        None
                    } else {
                        arc.stream_of(i).map(|(folder, _)| folder)
                    }
                })
                .collect();
            let files = seq.iter().filter(|s| s.is_some()).count();

            // One decode per data folder. The +1 is the encoded header,
            // which `parse` decodes before any of this runs and which has
            // its own folder -- it is not a data folder and does not
            // thrash.
            assert!(
                decodes <= folders + 1,
                "{decodes} folder decodes for {folders} folders: {seq:?}"
            );
            // The contract this whole test exists for: strictly fewer
            // decodes than files. The per-file version decoded once per
            // entry, so it scored files+1 here and failed.
            assert!(
                decodes < files,
                "{decodes} decodes for {files} files: the per-file re-decode is back: {seq:?}"
            );
        }

        #[cfg(all(
            feature = "zip",
            feature = "tar",
            feature = "cpio",
            feature = "rar",
            feature = "sevenz"
        ))]
        fn rar_of(count: usize) -> Vec<u8> {
            use rar_codec::ArchiveBuilder;
            let mut w = ArchiveBuilder::new();
            for i in 0..count {
                let data: &[u8] = if i + 1 == count { b"needle" } else { b"x" };
                w.add_stored(&format!("f{i:05}.txt"), data).unwrap();
            }
            w.finish()
        }

        /// A member that does not fit the byte budget is not decoded, and
        /// the notice names the byte budget rather than the count.
        #[cfg(feature = "zip")]
        #[test]
        fn a_member_that_does_not_fit_the_byte_budget_is_not_decoded() {
            under_budget(4096, 4, || {
                let out = members(Zip.extract(&stored_zip(6), "a.zip").unwrap());
                assert_eq!(
                    names(&out),
                    vec![
                        TRUNCATION_MEMBER,
                        "f00000.txt",
                        "f00001.txt",
                        "f00002.txt",
                        "f00003.txt",
                    ]
                );
                let note = String::from_utf8(out[0].1.clone()).unwrap();
                assert!(note.contains("member byte budget"), "{note}");
                assert!(note.contains("4 extracted"), "{note}");
            });
        }

        /// Entries that *fail* to decode must not consume the member budget
        /// either: an archive declaring 20 000 entries of which none
        /// decode has to stop on its own. The reason is structural --
        /// `ZipReader::extract` re-scans the central directory for every
        /// name, so without a scan ceiling that scales with the
        /// declared count.
        #[cfg(feature = "zip")]
        #[test]
        fn an_archive_whose_entries_all_fail_to_decode_stops_looking() {
            let count = 20_000;
            let mut zip = stored_zip(count);
            // The central directory is intact; every local header is not.
            let mut pos = 0;
            for i in 0..count {
                zip[pos..pos + 4].copy_from_slice(b"XXXX");
                pos += 30 + 10 + if i + 1 == count { 6 } else { 1 };
            }
            let out = locked(|| members(Zip.extract(&zip, "broken.zip").unwrap()));
            assert_eq!(names(&out), vec![TRUNCATION_MEMBER]);
            let note = String::from_utf8(out[0].1.clone()).unwrap();
            assert!(note.contains("entry scan budget"), "{note}");
            assert!(note.contains("20000 entries declared"), "{note}");
            assert!(note.contains("0 extracted"), "{note}");
        }

        /// The guard against a container that announces a huge member count
        /// and holds a handful of real ones: entries rgx does not expand
        /// (directories) must not eat the budget, and the archive is not
        /// reported as truncated.
        #[cfg(feature = "zip")]
        #[test]
        fn directory_entries_do_not_consume_the_member_budget() {
            let z = zip_of_dirs_then_files(3_000, 2);
            let out = locked(|| members(Zip.extract(&z, "d.zip").unwrap()));
            assert_eq!(names(&out), vec!["f00000.txt", "f00001.txt"]);
        }
    }

    #[cfg(any(
        feature = "zip",
        feature = "tar",
        feature = "cpio",
        feature = "decompress"
    ))]
    mod fuzz {
        use super::*;

        #[cfg(feature = "zip")]
        pub(super) fn crc32(b: &[u8]) -> u32 {
            let mut crc = 0xFFFF_FFFFu32;
            for &byte in b {
                crc ^= byte as u32;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xEDB8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }

        /// one stored entry "note.txt" = "hello", local header + CDR + EOCD
        #[cfg(feature = "zip")]
        fn stored_zip() -> Vec<u8> {
            let content = b"hello";
            let name = b"note.txt";
            let crc = crc32(content);
            let mut z = Vec::new();
            z.extend_from_slice(b"PK\x03\x04");
            z.extend_from_slice(&20u16.to_le_bytes());
            z.extend_from_slice(&[0u8; 4]); // flags, method
            z.extend_from_slice(&[0u8; 4]); // time, date
            z.extend_from_slice(&crc.to_le_bytes());
            z.extend_from_slice(&(content.len() as u32).to_le_bytes());
            z.extend_from_slice(&(content.len() as u32).to_le_bytes());
            z.extend_from_slice(&(name.len() as u16).to_le_bytes());
            z.extend_from_slice(&0u16.to_le_bytes());
            z.extend_from_slice(name);
            z.extend_from_slice(content);
            let cdr_off = z.len() as u32;
            z.extend_from_slice(b"PK\x01\x02");
            z.extend_from_slice(&20u16.to_le_bytes());
            z.extend_from_slice(&20u16.to_le_bytes());
            z.extend_from_slice(&[0u8; 8]);
            z.extend_from_slice(&crc.to_le_bytes());
            z.extend_from_slice(&(content.len() as u32).to_le_bytes());
            z.extend_from_slice(&(content.len() as u32).to_le_bytes());
            z.extend_from_slice(&(name.len() as u16).to_le_bytes());
            z.extend_from_slice(&[0u8; 10]); // extra, comment, disk, attrs
            z.extend_from_slice(&0u32.to_le_bytes());
            z.extend_from_slice(&0u32.to_le_bytes());
            z.extend_from_slice(name);
            let cd_size = z.len() as u32 - cdr_off;
            z.extend_from_slice(b"PK\x05\x06");
            z.extend_from_slice(&[0u8; 4]);
            z.extend_from_slice(&1u16.to_le_bytes());
            z.extend_from_slice(&1u16.to_le_bytes());
            z.extend_from_slice(&cd_size.to_le_bytes());
            z.extend_from_slice(&cdr_off.to_le_bytes());
            z.extend_from_slice(&0u16.to_le_bytes());
            z
        }

        /// one-file ustar archive: "hi.txt" (2 bytes) + zero blocks
        #[cfg(feature = "tar")]
        fn mini_tar() -> Vec<u8> {
            let mut h = vec![0u8; 512];
            h[0..6].copy_from_slice(b"hi.txt");
            h[100] = b'0'; // mode
            h[124..136].copy_from_slice(b"00000000002\0"); // size octal
            h[136..148].copy_from_slice(b"00000000000\0"); // mtime
            h[156] = b'0'; // typeflag regular
            h[257..263].copy_from_slice(b"ustar\0");
            let mut t = h;
            t.extend_from_slice(b"hi");
            t.extend_from_slice(&vec![0u8; 512 * 2 - 2]);
            t
        }

        /// newc cpio: one file "a.txt" = "ZIRCALOY" + trailer
        #[cfg(feature = "cpio")]
        fn mini_cpio() -> Vec<u8> {
            let data = b"ZIRCALOY";
            let name = b"a.txt\0";
            let mut h = b"070701".to_vec();
            // newc header: ino, mode, uid, gid, nlink, mtime, filesize,
            // devmaj, devmin, rdevmaj, rdevmin, namesize, check
            let fields: [u64; 13] = [
                1,
                0o100644,
                0,
                0,
                1,
                0,
                data.len() as u64,
                0,
                0,
                0,
                0,
                name.len() as u64,
                0,
            ];
            for f in fields {
                h.extend_from_slice(format!("{f:08x}").as_bytes());
            }
            h.extend_from_slice(name);
            while !h.len().is_multiple_of(4) {
                h.push(0);
            }
            h.extend_from_slice(data);
            while !h.len().is_multiple_of(4) {
                h.push(0);
            }
            // TRAILER!!!
            let mut t = b"070701".to_vec();
            for _ in 0..11 {
                t.extend_from_slice(b"00000000");
            }
            t.extend_from_slice(b"TRAILER!!!\0");
            while !t.len().is_multiple_of(4) {
                t.push(0);
            }
            h.extend_from_slice(&t);
            h
        }

        #[cfg(feature = "decompress")]
        fn gz_payload() -> Vec<u8> {
            rgx_core::compress::gzip::GzipWriter::new().encode(b"payload")
        }

        #[cfg(feature = "zip")]
        #[test]
        fn zip_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("stored", stored_zip()),
                    ("eocd-only", b"PK\x05\x06".to_vec()),
                    ("empty", vec![]),
                ],
                1200,
                "zip",
                |data| {
                    let _ = Zip.extract(data, "fuzz.zip");
                },
            );
        }

        #[cfg(feature = "tar")]
        #[test]
        fn tar_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("ustar", mini_tar()),
                    ("zeros", vec![0u8; 1024]),
                    ("empty", vec![]),
                ],
                1200,
                "tar",
                |data| {
                    let _ = Tar.extract(data, "fuzz.tar");
                },
            );
        }

        #[cfg(feature = "cpio")]
        #[test]
        fn cpio_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("newc", mini_cpio()),
                    ("magic-only", b"070701".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "cpio",
                |data| {
                    let _ = Cpio.extract(data, "fuzz.cpio");
                },
            );
        }

        #[cfg(feature = "decompress")]
        #[test]
        fn decompress_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("gz", gz_payload()),
                    ("gz-magic-only", b"\x1f\x8b\x08".to_vec()),
                    ("empty", vec![]),
                ],
                800,
                "decompress",
                |data| {
                    let _ = Decompress.extract(data, "fuzz.gz");
                },
            );
        }

        /// The `.br` path, on mutated reference-CLI streams. A decoder
        /// that reads untrusted input has to answer with an error rather
        /// than a panic, and RFC 7932 has a lot of ways to be wrong:
        /// prefix codes that are not prefix codes, distances past the
        /// window, block types past their category, lengths that overrun
        /// the meta-block. The seeds are real streams, so the mutations
        /// land on real headers.
        #[cfg(feature = "decompress")]
        #[test]
        fn brotli_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    (
                        "text q11",
                        include_bytes!("../testdata/brotli_text_q11.br").to_vec(),
                    ),
                    (
                        "utf8 q5",
                        include_bytes!("../testdata/brotli_utf8_q5.br").to_vec(),
                    ),
                    (
                        "large q9",
                        include_bytes!("../testdata/brotli_big_q9.br").to_vec(),
                    ),
                    (
                        "empty",
                        include_bytes!("../testdata/brotli_empty_q9.br").to_vec(),
                    ),
                ],
                1500,
                "brotli",
                |data| {
                    let _ = crate::brotli::BrotliDecoder::new().decode_bounded(data, 1 << 20);
                },
            );
        }
    }
}
