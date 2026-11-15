// SPDX-License-Identifier: Apache-2.0

//! rgx-adapters-inspect: forensic-style binary inspection.
//!
//! Always-in-process triage adapter. Never trusts the extension, never
//! spawns a subprocess, never ships a heavyweight parser.
//!
//! 1. **Identification** — magic bytes + minimal header (PE machine/class,
//!    ELF class/type, image dimensions).
//! 2. **Embedded-structure scan** — full blob scanned for known
//!    signatures (ZIP, PNG, PDF, GZIP, ELF, SQLite, …); cheap-to-slice
//!    formats (ZIP via EOCD, GZIP, PDF via `%%EOF`) carve into `Members`
//!    so a ZIP buried in a `.bin` is searched through by the full chain.
//! 3. **Strings** — ASCII and UTF-16LE/BE runs, capped so huge blobs stay
//!    cheap.
//! 4. **Entropy triage** — Shannon entropy per 4 KiB window flags
//!    compressed/encrypted/packed regions.
//!
//! Everything is heuristic and bail-safe: if nothing is found the
//! adapter still returns a structural report; if the input is plain
//! text it bails so the raw path keeps rg binary semantics.
//!
//! Every adapter sits behind a Cargo feature of its own, named after the
//! format it reads, so a binary that names the formats it needs carries
//! only those. The default build keeps all of them.

#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::boxed::Box;
#[cfg(any(feature = "inspect", feature = "lnk", feature = "wasm"))]
use alloc::string::String;
#[cfg(any(feature = "inspect", feature = "lnk"))]
use alloc::string::ToString;
use alloc::vec::Vec;
#[cfg(any(feature = "inspect", feature = "lnk", feature = "wasm"))]
use core::fmt::Write as _;
use rgx_core::Adapter;
#[cfg(any(feature = "inspect", feature = "lnk", feature = "wasm"))]
use rgx_core::Outcome;
#[cfg(any(feature = "inspect", feature = "lnk", feature = "wasm"))]
use rgx_core::Result;
#[cfg(any(feature = "lnk", feature = "wasm"))]
use rgx_core::{bail, decline};

#[cfg(any(feature = "bam", feature = "bcf", feature = "cram", feature = "sam"))]
mod bioinformatics;
#[cfg(any(
    feature = "acis-sab",
    feature = "dgn",
    feature = "dwg",
    feature = "parasolid",
    feature = "rvt"
))]
mod cad;
#[cfg(feature = "c4")]
mod cad_c4;
#[cfg(feature = "cals")]
mod cad_cals;
#[cfg(feature = "cgm")]
mod cad_cgm;
#[cfg(feature = "dxf")]
mod cad_dxf;
#[cfg(feature = "iges")]
mod cad_iges;
#[cfg(feature = "plt")]
mod cad_plt;
#[cfg(feature = "acis-sat")]
mod cad_sat;
#[cfg(feature = "step")]
mod cad_step;
#[cfg(feature = "stl")]
mod cad_stl;
#[cfg(feature = "compound")]
mod compound;
#[cfg(feature = "cram")]
mod cram_arith;
#[cfg(feature = "cram")]
mod cram_fqz;
#[cfg(feature = "cram")]
mod cram_rans;
#[cfg(feature = "cram")]
mod cram_rans16;
#[cfg(feature = "cram")]
mod cram_tokeniser;
#[cfg(any(
    feature = "dex",
    feature = "elf",
    feature = "macho",
    feature = "pe",
    feature = "wasm-meta"
))]
mod executables;
#[cfg(feature = "firebird")]
mod firebird;
#[cfg(any(
    feature = "fasta",
    feature = "fastq",
    feature = "gff",
    feature = "mmcif",
    feature = "pdb",
    feature = "vcf"
))]
mod flatfiles;
#[cfg(feature = "isobmff")]
mod isobmff;
#[cfg(feature = "bplist")]
mod plist;
#[cfg(any(feature = "djvu", feature = "tiff"))]
mod rasters;
#[cfg(any(
    feature = "bufr",
    feature = "grib",
    feature = "n5",
    feature = "root",
    feature = "segy"
))]
mod scientific;
#[cfg(feature = "x509")]
mod x509;

#[cfg(feature = "bam")]
pub use bioinformatics::BamAlign;
#[cfg(feature = "bcf")]
pub use bioinformatics::BcfVariants;
#[cfg(feature = "cram")]
pub use bioinformatics::CramAlign;
#[cfg(feature = "sam")]
pub use bioinformatics::Sam;
#[cfg(feature = "acis-sab")]
pub use cad::AcisSab;
#[cfg(feature = "dgn")]
pub use cad::Dgn;
#[cfg(feature = "dwg")]
pub use cad::Dwg;
#[cfg(feature = "parasolid")]
pub use cad::ParasolidXt;
#[cfg(feature = "rvt")]
pub use cad::Rvt;
#[cfg(feature = "c4")]
pub use cad_c4::C4;
#[cfg(feature = "cals")]
pub use cad_cals::Cals;
#[cfg(feature = "cgm")]
pub use cad_cgm::Cgm;
#[cfg(feature = "dxf")]
pub use cad_dxf::Dxf;
#[cfg(feature = "iges")]
pub use cad_iges::Iges;
#[cfg(feature = "plt")]
pub use cad_plt::Plt;
#[cfg(feature = "acis-sat")]
pub use cad_sat::AcisSat;
#[cfg(feature = "step")]
pub use cad_step::Step;
#[cfg(feature = "stl")]
pub use cad_stl::Stl;
#[cfg(feature = "compound")]
pub use compound::Compound;
#[cfg(feature = "dex")]
pub use executables::DexStrings;
#[cfg(feature = "elf")]
pub use executables::ElfProvenance;
#[cfg(feature = "macho")]
pub use executables::MachOStrings;
#[cfg(feature = "pe")]
pub use executables::PeResources;
#[cfg(feature = "wasm-meta")]
pub use executables::WasmMeta;
#[cfg(feature = "firebird")]
pub use firebird::Firebird;
#[cfg(feature = "fasta")]
pub use flatfiles::Fasta;
#[cfg(feature = "fastq")]
pub use flatfiles::Fastq;
#[cfg(feature = "gff")]
pub use flatfiles::Gff;
#[cfg(feature = "mmcif")]
pub use flatfiles::MmCif;
#[cfg(feature = "pdb")]
pub use flatfiles::Pdb;
#[cfg(feature = "vcf")]
pub use flatfiles::Vcf;
#[cfg(feature = "isobmff")]
pub use isobmff::IsoBmff;
#[cfg(feature = "bplist")]
pub use plist::BinaryPlist;
#[cfg(feature = "djvu")]
pub use rasters::Djvu;
#[cfg(feature = "tiff")]
pub use rasters::Tiff;
#[cfg(feature = "bufr")]
pub use scientific::Bufr;
#[cfg(feature = "grib")]
pub use scientific::Grib;
#[cfg(feature = "root")]
pub use scientific::Root;
#[cfg(feature = "segy")]
pub use scientific::Segy;
#[cfg(feature = "n5")]
pub use scientific::N5;
#[cfg(feature = "x509")]
pub use x509::X509Cert;

/// A known binary signature. `scan` marks formats searched for at any
/// offset (embedded detection); others are only checked at offset 0.
#[cfg(feature = "inspect")]
struct Sig {
    magic: &'static [u8],
    name: &'static str,
    /// suggested extension for carved members ("" = report only)
    ext: &'static str,
    scan: bool,
}

#[cfg(feature = "inspect")]
const SIGS: &[Sig] = &[
    // executables / bytecodes
    Sig {
        magic: b"\x7fELF",
        name: "ELF executable/shared object",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\x00asm",
        name: "WebAssembly module",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\xfe\xed\xfa\xce",
        name: "Mach-O 32-bit (big-endian)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\xce\xfa\xed\xfe",
        name: "Mach-O 32-bit",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\xfe\xed\xfa\xcf",
        name: "Mach-O 64-bit (big-endian)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\xcf\xfa\xed\xfe",
        name: "Mach-O 64-bit",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\xca\xfe\xba\xbe",
        name: "Mach-O universal binary / Java class",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"dex\n",
        name: "Android DEX bytecode",
        ext: "",
        scan: true,
    },
    // documents / databases
    Sig {
        magic: b"%PDF-",
        name: "PDF document",
        ext: "pdf",
        scan: true,
    },
    Sig {
        magic: b"SQLite format 3\x00",
        name: "SQLite database",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        name: "OLE2/CFB compound document",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\x89HDF\r\n\x1a\n",
        name: "HDF5 scientific data",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"BLENDER",
        name: "Blender scene",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"wOF2",
        name: "WOFF2 web font",
        ext: "",
        scan: false,
    },
    // images
    Sig {
        magic: b"\x89PNG\r\n\x1a\n",
        name: "PNG image",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\xff\xd8\xff",
        name: "JPEG image",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"GIF87a",
        name: "GIF image",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"GIF89a",
        name: "GIF image (89a)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"BM",
        name: "BMP image",
        ext: "",
        scan: false,
    },
    Sig {
        magic: b"II*\x00",
        name: "TIFF image (LE)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"MM\x00*",
        name: "TIFF image (BE)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\x00\x00\x01\x00",
        name: "Windows icon/cursor",
        ext: "",
        scan: false,
    },
    Sig {
        magic: b"8BPS",
        name: "Photoshop PSD",
        ext: "",
        scan: true,
    },
    // archives / compression
    Sig {
        magic: b"PK\x03\x04",
        name: "ZIP archive",
        ext: "zip",
        scan: true,
    },
    Sig {
        magic: b"PK\x05\x06",
        name: "ZIP archive (empty)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\x1f\x8b\x08",
        name: "gzip stream",
        ext: "gz",
        scan: true,
    },
    Sig {
        magic: b"BZh",
        name: "bzip2 stream",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\x28\xb5\x2f\xfd",
        name: "zstd stream",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\xfd7zXZ\x00",
        name: "xz stream",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"7z\xbc\xaf'\x1c",
        name: "7z archive",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"Rar!\x1a\x07",
        name: "RAR archive",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\x04\x22\x4d\x18",
        name: "LZ4 frame",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\x1f\x9e",
        name: "compress/LZW stream",
        ext: "",
        scan: false,
    },
    Sig {
        magic: b"!<arch>\n",
        name: "ar archive (deb/static lib)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\xed\xab\xee\xdb",
        name: "RPM package",
        ext: "",
        scan: true,
    },
    // media
    Sig {
        magic: b"OggS",
        name: "Ogg container",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"fLaC",
        name: "FLAC audio",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"ID3",
        name: "MP3 audio (ID3v2)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"RIFF",
        name: "RIFF container (wav/avi/webp)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\x1a\x45\xdf\xa3",
        name: "EBML container (mkv/webm)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"FORM",
        name: "IFF container (aiff/ilbm)",
        ext: "",
        scan: true,
    },
    // misc structured
    Sig {
        magic: b"\x30\x82",
        name: "ASN.1/DER (certificate, PKCS)",
        ext: "",
        scan: false,
    },
    Sig {
        magic: b"-----BEGIN ",
        name: "PEM encoded data",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\xd4\xc3\xb2\xa1",
        name: "pcap capture (LE)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\xa1\xb2\xc3\xd4",
        name: "pcap capture (BE)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\x0a\x0d\x0d\x0a",
        name: "pcapng capture",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"ustar",
        name: "tar archive (ustar)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"070701",
        name: "cpio archive (newc)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"070702",
        name: "cpio archive (newc, crc)",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"hsqs",
        name: "squashfs filesystem",
        ext: "",
        scan: true,
    },
    Sig {
        magic: b"\x55\xaa",
        name: "boot sector / MBR signature",
        ext: "",
        scan: false,
    },
];

#[cfg(feature = "inspect")]
const MAX_FINDINGS: usize = 64;
#[cfg(feature = "inspect")]
const MAX_STRINGS_BYTES: usize = 64 * 1024;
#[cfg(feature = "inspect")]
const STR_MIN_RUN: usize = 5;
/// windows at or above this entropy are flagged compressed/encrypted
#[cfg(feature = "inspect")]
const ENTROPY_HOT: f64 = 7.5;
/// only blobs at least this large get entropy triage
#[cfg(feature = "inspect")]
const ENTROPY_MIN_SIZE: usize = 16 * 1024;

#[cfg(feature = "inspect")]
pub struct Inspect;
/// Adapters provided by this crate.
///
/// **Order is the contract.** The registry resolves by extension and the
/// first matching available adapter wins, so a later entry only ever runs
/// when every earlier one for that extension has `bail!`ed. Two entries are
/// ordered against `Inspect` on purpose:
///
/// - `PeResources` precedes it, because `Inspect` claims `exe`/`dll`/`sys`/
///   `drv`/`efi`/`mui`/`ocx`/`cpl` and its generic report carries no version
///   strings. A carved `.rsrc` cannot yield its leaves at all (the data
///   entries hold image RVAs and a carve has no section table), so
///   `PeResources` declines a bare `.rsrc` blob and keeps the tree.
/// - `WasmMeta` follows `Wasm`, which bails when it finds no readable
///   sections; the `name`/`producers` payloads are what is left.
pub fn adapters() -> Vec<Box<dyn Adapter>> {
    vec![
        #[cfg(feature = "pe")]
        Box::new(PeResources),
        #[cfg(feature = "inspect")]
        Box::new(Inspect),
        #[cfg(feature = "macho")]
        Box::new(MachOStrings),
        #[cfg(feature = "elf")]
        Box::new(ElfProvenance),
        #[cfg(feature = "dex")]
        Box::new(DexStrings),
        #[cfg(feature = "wasm")]
        Box::new(Wasm),
        #[cfg(feature = "wasm-meta")]
        Box::new(WasmMeta),
        #[cfg(feature = "lnk")]
        Box::new(Lnk),
        #[cfg(feature = "x509")]
        Box::new(X509Cert),
        #[cfg(feature = "compound")]
        Box::new(Compound),
        #[cfg(feature = "bplist")]
        Box::new(BinaryPlist),
        #[cfg(feature = "tiff")]
        Box::new(Tiff),
        #[cfg(feature = "djvu")]
        Box::new(Djvu),
        #[cfg(feature = "isobmff")]
        Box::new(IsoBmff),
        #[cfg(feature = "dwg")]
        Box::new(Dwg),
        #[cfg(feature = "parasolid")]
        Box::new(ParasolidXt),
        #[cfg(feature = "acis-sab")]
        Box::new(AcisSab),
        #[cfg(feature = "rvt")]
        Box::new(Rvt),
        #[cfg(feature = "dgn")]
        Box::new(Dgn),
        // The text CAD formats. These are plain text `rg` already reads, so
        // they are rendered and not answered: under the default policy the
        // file's own bytes are the answer and these are not consulted at
        // all, and under `RGX_ADAPTER_VIEW=render` the rendering is what
        // gets searched. What each of them buys is an entity's name beside
        // its values, which is a pattern the file's own bytes cannot hold.
        //
        // `.stl` is claimed twice on purpose: the `threed` crate answers
        // the binary form, which ripgrep cannot read at all, and this one
        // answers the ASCII form, which ripgrep reads perfectly. A `bail!`
        // does not end the chain, so the ASCII file reaches the reader that
        // can render it.
        #[cfg(feature = "dxf")]
        Box::new(Dxf),
        #[cfg(feature = "step")]
        Box::new(Step),
        #[cfg(feature = "iges")]
        Box::new(Iges),
        #[cfg(feature = "acis-sat")]
        Box::new(AcisSat),
        #[cfg(feature = "stl")]
        Box::new(Stl),
        // The graphics metafile and the two bilevel rasters. These are
        // binary: ripgrep reads none of them, so the adapter's answer is
        // the answer, and the reach is `Reveal`. The metafile's elements
        // and the rasters' headers carry numbers that are not in the file
        // as text — a polyline's points, a page's size, a tile count.
        #[cfg(feature = "cgm")]
        Box::new(Cgm),
        #[cfg(feature = "cals")]
        Box::new(Cals),
        #[cfg(feature = "c4")]
        Box::new(C4),
        // The plotter format. Its bytes are text `rg` already reads, so it
        // is rendered and not answered, for the same reason as the CAD
        // formats above. `.plt` is also the extension of a gnuplot script,
        // so this one declines a file whose stream is not a run of plotter
        // commands: the gnuplot script falls through to the raw search and
        // is found there, in its own words.
        #[cfg(feature = "plt")]
        Box::new(Plt),
        #[cfg(feature = "grib")]
        Box::new(Grib),
        #[cfg(feature = "bufr")]
        Box::new(Bufr),
        #[cfg(feature = "segy")]
        Box::new(Segy),
        #[cfg(feature = "root")]
        Box::new(Root),
        #[cfg(feature = "n5")]
        Box::new(N5),
        // `.fdb`/`.gdb` are claimed by nobody else, so placement is free;
        // it sits with the other page-structured readers.
        #[cfg(feature = "firebird")]
        Box::new(Firebird),
        #[cfg(feature = "bam")]
        Box::new(BamAlign),
        #[cfg(feature = "bcf")]
        Box::new(BcfVariants),
        #[cfg(feature = "cram")]
        Box::new(CramAlign),
        // `.sam` is claimed only for the compressed form: a plain-text SAM is
        // declined so the raw path keeps it searchable, and a BGZF one is
        // inflated because `rg` cannot see its records at all.
        #[cfg(feature = "sam")]
        Box::new(Sam),
        // The flat files of the same family. These are text, so they are
        // rendered and not answered: under the default policy the file's own
        // bytes are the answer and these are not consulted, and under
        // `--view render` the records come out unwrapped and with their
        // fields separated by spaces. Their extensions are claimed by nobody
        // else, so the placement is free.
        #[cfg(feature = "fasta")]
        Box::new(Fasta),
        #[cfg(feature = "fastq")]
        Box::new(Fastq),
        #[cfg(feature = "vcf")]
        Box::new(Vcf),
        #[cfg(feature = "gff")]
        Box::new(Gff),
        #[cfg(feature = "pdb")]
        Box::new(Pdb),
        #[cfg(feature = "mmcif")]
        Box::new(MmCif),
    ]
}

#[cfg(feature = "inspect")]
impl Adapter for Inspect {
    fn name(&self) -> &'static str {
        "inspect"
    }

    /// Generic binary extensions, plus executable/container formats that
    /// hide most of their text in UTF-16 or embedded payloads. Renamed
    /// files (`payload.zip` -> `payload.bin`) land here and get identified
    /// by magic instead of extension.
    ///
    /// **`o` is deliberately NOT claimed.** `.o` is an object file, and
    /// object files reach the walker by the thousand from the `ar`
    /// adapter: every `.a` static library yields one member per object,
    /// and `process` recurses into each. With no adapter claiming `o`,
    /// `process` falls through to the raw passthrough and an object
    /// file is grepped as the bytes it is -- the forensic triage
    /// header goes away, which is the right trade at that volume.
    ///
    /// `objbin` is unrelated and stays: that extension is not produced
    /// by any archiver, so it cannot arrive by the thousand.
    fn extensions(&self) -> &'static [&'static str] {
        &[
            "bin", "dat", "raw", "img", "rom", "blob", "payload", "scratch", "fw", "objbin", "exe",
            "dll", "sys", "drv", "efi", "mui", "ocx", "cpl", "apk", "msi",
        ]
    }

    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        Ok(inspect(data, path))
    }
}

#[cfg(feature = "inspect")]
fn inspect(data: &[u8], path: &str) -> Outcome {
    // plain text is the raw path's job — keep rg binary semantics
    if looks_like_text(data) {
        return Outcome::Bail("plain text, raw search is better".into());
    }

    let mut out = String::new();
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            out,
            "[inspect] file={path} size={} classification={}",
            data.len(),
            classify(data)
        );
    }

    // --- identification of the outer container (offset 0) ---
    for sig in SIGS {
        if data.len() >= sig.magic.len() && &data[..sig.magic.len()] == sig.magic {
            use core::fmt::Write as _;
            let _ = writeln!(out, "[format] {}", describe_outer(sig, data));
            break;
        }
    }
    // PE is the one common executable without a fixed-offset magic: MZ +
    // PE\0\0 at e_lfanew
    if data.len() > 0x40 && data[..2] == *b"MZ" {
        let peoff = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        if peoff + 6 <= data.len() && &data[peoff..peoff + 4] == b"PE\0\0" {
            use core::fmt::Write as _;
            let _ = writeln!(out, "[format] {}", describe_pe(data, peoff));
        }
    }

    // --- embedded-structure scan + carving ---
    //
    // **The carve pass is budgeted, and it was not.** `MAX_FINDINGS` caps the
    // COUNT, but each carve is a slice of the input and the slices are copied
    // into `members`, which `process` then recurses into. `Adapter::extract`
    // never receives a `Ctx`, so `MemberSink` -- the producer-side budget the
    // whole archive family reads -- is not reachable from this crate without a
    // dependency that points the wrong way. The result was that Inspect could
    // hold `MAX_FINDINGS` copies of most of the file live at once: 64 slices
    // each approaching the whole size, roughly 64x the input, and each one
    // then re-entering the pipeline with its own fresh budget.
    //
    // The ceiling below is the same 16 MiB the gz carve has always applied to
    // ONE payload, applied to the whole pass. It is a local constant rather
    // than the process budget because the process budget is not visible here;
    // moving `MemberSink` into `rgx-core` so every producer shares one number
    // is the architectural fix and is a larger change than this defect
    // warrants on its own.
    const CARVE_TOTAL_MAX: usize = 16 * 1024 * 1024;
    let mut carve_bytes = 0usize;
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();
    let mut findings = 0usize;
    for sig in SIGS {
        if !sig.scan || findings >= MAX_FINDINGS {
            continue;
        }
        let mut from = 0usize;
        while findings < MAX_FINDINGS {
            let Some(rel) = find_subsequence(&data[from..], sig.magic) else {
                break;
            };
            let off = from + rel;
            from = off + 1;
            if off == 0 {
                continue; // outer format already reported
            }
            findings += 1;
            let extra = describe_embedded(sig, data, off);
            let _ = writeln!(out, "[embedded] 0x{off:08x}: {}{extra}", sig.name);
            // carve the formats we can slice cheaply and usefully
            if !sig.ext.is_empty() {
                let room = CARVE_TOTAL_MAX.saturating_sub(carve_bytes);
                if room == 0 {
                    let _ = writeln!(
                        out,
                        "[carved]   ... and more, over the {CARVE_TOTAL_MAX}-byte carve budget"
                    );
                    break;
                }
                // `carve` is told the room it has, so a payload that cannot
                // fit is declined rather than allocated and then dropped.
                if let Some(bytes) = carve_bounded(sig, data, off, room) {
                    let _ = writeln!(
                        out,
                        "[carved]   0x{off:08x}: {} bytes -> recursion as .{}",
                        bytes.len(),
                        sig.ext
                    );
                    carve_bytes = carve_bytes.saturating_add(bytes.len());
                    members.push((format!("carved-0x{off:08x}.{}", sig.ext), bytes));
                }
            }
        }
    }

    // --- entropy triage ---
    if data.len() >= ENTROPY_MIN_SIZE {
        let win = 4096usize;
        // One memo for the whole sweep, not one per window: the whole point
        // is that a count seen in window 1 is free in window 900.
        let mut memo = EntropyMemo::new();
        let mut flagged = 0usize;
        let mut w_start = 0usize;
        while w_start + win <= data.len() {
            let e = entropy(&data[w_start..w_start + win], &mut memo);
            if e >= ENTROPY_HOT {
                if flagged < 16 {
                    let _ = writeln!(
                        out,
                        "[entropy]  0x{w_start:08x}-0x{:08x}: {e:.2} bits/byte (compressed/encrypted/packed?)",
                        w_start + win
                    );
                }
                flagged += 1;
            }
            w_start += win;
        }
        if flagged > 16 {
            let _ = writeln!(
                out,
                "[entropy]  ... and {} more high-entropy windows",
                flagged - 16
            );
        }
    }

    // --- strings (ASCII + UTF-16), capped ---
    let strings = extract_strings(data, MAX_STRINGS_BYTES);
    if strings.is_empty() {
        out.push_str("[strings]  none (fully packed/encrypted?)\n");
    } else {
        out.push_str("[strings]  extracted strings follow\n--- strings ---\n");
        out.push_str(&strings);
        if !strings.ends_with('\n') {
            out.push('\n');
        }
    }

    // A generic-extension blob with no embedded structure found is just a
    // binary: bail so it keeps rg's exact binary semantics (matches count
    // for the exit code/-c/-l, lines stay suppressed without -a). Named
    // executables (.exe/.dll/…) still get the full report — there the
    // strings *are* the value.
    if findings == 0 && members.is_empty() {
        let ext = rgx_core::extension_of(path);
        if matches!(
            &*ext,
            "bin" | "dat" | "raw" | "img" | "rom" | "blob" | "payload" | "scratch" | "fw"
        ) {
            return Outcome::Bail("no embedded structures, raw binary semantics".into());
        }
    }

    if members.is_empty() {
        Outcome::Text(out.into_bytes())
    } else {
        // text report first (searchable), then the carved members recurse
        let mut all = vec![("report.txt".to_string(), out.into_bytes())];
        all.extend(members);
        Outcome::Members(all)
    }
}

// --- helpers ---

/// Map a magic-byte prefix to the short type label the `-t`/`-T` filter
/// understands. Returns `None` when the prefix is not one of the formats
/// `rgx_adapters_inspect` knows about; the caller is expected to fall back
/// to extension classification or skip the file.
///
/// The returned names line up with the `rgx` `TypeDb` defaults where one
/// entry covers the format (`pdf`, `zip`, `elf`, `sqlite`, `png`, `jpeg`,
/// `gif`, `bmp`, `gzip`, `bzip2`, `xz`, `zstd`, `7z`, `rar`, `wasm`,
/// `class`, `dex`, `blender`, `hdf5`, `webp`, `tiff`, `cfb`, `macho`,
/// `psd`, `ogg`, `mpeg-ts`, `flac`, `mp3`, `midi`, `ico`, `wmf`).
pub fn magic_classify(data: &[u8]) -> Option<&'static str> {
    let s = data;
    if s.len() < 2 {
        return None;
    }
    // Order matters: longer prefixes are tried first, because every shorter
    // prefix is also a valid match for the longer one.
    if s.starts_with(b"%PDF-") {
        return Some("pdf");
    }
    if s.starts_with(b"PK\x03\x04") || s.starts_with(b"PK\x05\x06") {
        return Some("zip");
    }
    if s.starts_with(b"\x7fELF") {
        return Some("elf");
    }
    if s.starts_with(b"SQLite format 3\x00") {
        return Some("sqlite");
    }
    if s.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("png");
    }
    if s.len() >= 3 && &s[..3] == b"\xff\xd8\xff" {
        return Some("jpeg");
    }
    if s.starts_with(b"GIF87a") || s.starts_with(b"GIF89a") {
        return Some("gif");
    }
    if s.starts_with(b"BM") {
        return Some("bmp");
    }
    if s.starts_with(b"\x1f\x8b\x08") {
        return Some("gzip");
    }
    if s.starts_with(b"BZh") {
        return Some("bzip2");
    }
    if s.starts_with(b"\xfd7zXZ\x00") {
        return Some("xz");
    }
    if s.starts_with(b"\x28\xb5\x2f\xfd") {
        return Some("zstd");
    }
    if s.starts_with(b"7z\xbc\xaf'\x1c") {
        return Some("7z");
    }
    if s.starts_with(b"Rar!\x1a\x07") {
        return Some("rar");
    }
    if s.starts_with(b"\x00asm") {
        return Some("wasm");
    }
    if s.starts_with(b"\xca\xfe\xba\xbe") {
        return Some("class");
    }
    if s.starts_with(b"dex\n") {
        return Some("dex");
    }
    if s.starts_with(b"BLENDER") {
        return Some("blender");
    }
    if s.starts_with(b"\x89HDF\r\n\x1a\n") {
        return Some("hdf5");
    }
    if s.len() >= 12 && s.starts_with(b"RIFF") && &s[8..12] == b"WEBP" {
        return Some("webp");
    }
    if s.starts_with(b"II*\x00") || s.starts_with(b"MM\x00*") {
        return Some("tiff");
    }
    if s.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        return Some("cfb");
    }
    if s.starts_with(b"wOF2") {
        return Some("cfb");
    }
    if s.starts_with(b"\xfe\xed\xfa\xce")
        || s.starts_with(b"\xce\xfa\xed\xfe")
        || s.starts_with(b"\xfe\xed\xfa\xcf")
        || s.starts_with(b"\xcf\xfa\xed\xfe")
    {
        return Some("macho");
    }
    if s.starts_with(b"8BPS") {
        return Some("psd");
    }
    if s.starts_with(b"OggS") {
        return Some("ogg");
    }
    if s.len() >= 4
        && s[0] == 0x47
        && s[2] == 0x47
        && (s[3] == 0x07 || s[3] == 0x08 || s[3] == 0x09)
    {
        return Some("mpeg-ts");
    }
    if s.starts_with(b"fLaC") {
        return Some("flac");
    }
    if s.starts_with(b"ID3") || (s.len() >= 2 && s[0] == 0xff && (s[1] & 0xe0) == 0xe0) {
        return Some("mp3");
    }
    if s.starts_with(b"MThd") {
        return Some("midi");
    }
    if s.starts_with(b"\x00\x00\x01\x00") {
        return Some("ico");
    }
    if s.starts_with(b"\xd7\xcd\xc6\x9a") {
        return Some("wmf");
    }
    None
}

#[cfg(feature = "inspect")]
fn looks_like_text(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(4096)];
    if sample.is_empty() {
        return true;
    }
    if sample.contains(&0) {
        return false;
    }
    let printable = sample
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b))
        .count();
    printable as f64 / sample.len() as f64 > 0.95
}

#[cfg(feature = "inspect")]
fn classify(data: &[u8]) -> &'static str {
    let sample = &data[..data.len().min(8192)];
    if sample.is_empty() {
        return "empty";
    }
    let nul_frac = sample.iter().filter(|&&b| b == 0).count() as f64 / sample.len() as f64;
    if nul_frac > 0.30 {
        return "sparse/padded (mostly NULs)";
    }
    if looks_like_text(data) {
        return "plain text";
    }
    let printable = sample
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
        .count() as f64
        / sample.len() as f64;
    if printable > 0.70 {
        return "structured text/binary mix (logs, ini-in-binary, …)";
    }
    let e = entropy(sample, &mut EntropyMemo::new());
    if e > 7.3 {
        "high-entropy blob (compressed or encrypted)"
    } else {
        "structured binary"
    }
}

/// Parse a gzip member header starting at `off`; returns the absolute
/// offset where the raw deflate stream begins.
#[cfg(feature = "inspect")]
fn parse_gzip_header(data: &[u8], off: usize) -> Option<usize> {
    let h = data.get(off..off + 10)?;
    if h[0] != 0x1f || h[1] != 0x8b || h[2] != 8 {
        return None;
    }
    let flg = h[3];
    let mut p = off + 10;
    if flg & 0x04 != 0 {
        // FEXTRA
        let xlen = u16::from_le_bytes([*data.get(p)?, *data.get(p + 1)?]) as usize;
        p += 2 + xlen;
    }
    if flg & 0x08 != 0 {
        // FNAME: zero-terminated
        let end = data.get(p..)?.iter().position(|&b| b == 0)? + 1;
        p += end;
    }
    if flg & 0x10 != 0 {
        // FCOMMENT: zero-terminated
        let end = data.get(p..)?.iter().position(|&b| b == 0)? + 1;
        p += end;
    }
    if flg & 0x02 != 0 {
        // FHCRC
        p += 2;
    }
    if p > data.len() {
        return None;
    }
    Some(p)
}

/// Shannon entropy in bits/byte over a window. Caches `log2(p)`
/// for the bin counts the sweep actually sees.
///
/// **Exact memo, not approximation.** The cached value is the same
/// `p.log2()` the uncached code would compute — the first time a
/// count `c` is seen it is filled with `(c as f64 / n).log2()`, and
/// every later window with the same `n` reads that same `f64` back.
/// The printed `{e:.2}` and the `>= ENTROPY_HOT` comparison are
/// unchanged bit for bit.
///
/// `NAN` marks "not computed". `log2` of `c/n` for `c >= 1` and
/// finite `n` is always finite, so a stored `NAN` can never be
/// mistaken for a real value.
#[cfg(feature = "inspect")]
struct EntropyMemo {
    /// The window length the cached values were computed for. A different `n`
    /// gives different `p`, so the whole table is dropped.
    n: f64,
    vals: alloc::boxed::Box<[f64]>,
}

#[cfg(feature = "inspect")]
impl EntropyMemo {
    fn new() -> Self {
        Self {
            n: f64::NAN,
            // A window cannot exceed the sweep's 4096, but `classify` samples
            // up to the same bound; sized for it so the table is never indexed
            // out of range.
            vals: alloc::vec![f64::NAN; 4097].into_boxed_slice(),
        }
    }

    /// `log2(p)` for a bin of `count` bytes. `p` must be `count / n` for the
    /// `n` the memo was last pointed at; [`Self::set_n`] is what guarantees
    /// that, and `entropy` calls it once per window before this.
    #[inline]
    fn log2_of(&mut self, count: usize, p: f64) -> f64 {
        match self.vals.get(count).copied() {
            Some(v) if !v.is_nan() => v,
            _ => {
                let v = p.log2();
                if count < self.vals.len() {
                    self.vals[count] = v;
                }
                v
            }
        }
    }

    /// Point the memo at a new window length, dropping stale values.
    fn set_n(&mut self, n: f64) {
        if self.n != n {
            self.n = n;
            self.vals.fill(f64::NAN);
        }
    }
}

#[cfg(feature = "inspect")]
fn entropy(window: &[u8], memo: &mut EntropyMemo) -> f64 {
    let mut counts = [0u64; 256];
    for &b in window {
        counts[b as usize] += 1;
    }
    let n = window.len() as f64;
    memo.set_n(n);
    let mut h = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        // The memo is keyed on the COUNT and the count is what `p` comes from,
        // so the cached value is exactly the value this expression would make.
        h -= p * memo.log2_of(c as usize, p);
    }
    h
}

/// memmem is SIMD-backed — this helper runs over the whole blob once per
/// signature in the embedded-structure scan, so the search kernel matters
#[cfg(feature = "inspect")]
fn find_subsequence(hay: &[u8], needle: &[u8]) -> Option<usize> {
    rgx_core::memchr::memmem::find(hay, needle)
}

#[cfg(feature = "inspect")]
fn describe_outer(sig: &Sig, data: &[u8]) -> String {
    let base = sig.name.to_string();
    match sig.magic {
        b"\x7fELF" => {
            if data.len() < 20 {
                return base;
            }
            let class = match data[4] {
                1 => "32-bit",
                2 => "64-bit",
                _ => "unknown-class",
            };
            let typ = match u16::from_le_bytes([data[16], data[17]]) {
                0 => "relocatable",
                1 => "executable",
                2 => "executable",
                3 => "shared object",
                4 => "core dump",
                _ => "type-?",
            };
            format!("{base} ({class} {typ})")
        }
        b"\x89PNG\r\n\x1a\n" => {
            if data.len() >= 24 {
                let w = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
                let h = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
                format!("{base} {w}x{h}")
            } else {
                base
            }
        }
        b"%PDF-" => {
            let ver: String = data[5..]
                .iter()
                .take(8)
                .map(|&b| b as char)
                .take_while(|c| c.is_ascii_graphic())
                .collect();
            format!("{base} version {ver}")
        }
        b"PK\x03\x04" => {
            // local file header: flag(2) method(2) time(2) date(2) crc(4)
            // csize(4) usize(4) namelen(2) extralen(2) name…
            if data.len() >= 30 {
                let nlen = u16::from_le_bytes([data[26], data[27]]) as usize;
                let elen = u16::from_le_bytes([data[28], data[29]]) as usize;
                if 30 + nlen + elen <= data.len() {
                    let name = String::from_utf8_lossy(&data[30..30 + nlen]);
                    return format!("{base} first-entry \"{name}\"");
                }
            }
            base
        }
        _ => base,
    }
}

#[cfg(feature = "inspect")]
fn describe_pe(data: &[u8], peoff: usize) -> String {
    // COFF header at peoff+4: machine(2) nsections(2) timestamp(4)…
    let machine = match data
        .get(peoff + 4..peoff + 6)
        .map(|m| u16::from_le_bytes([m[0], m[1]]))
    {
        Some(0x14c) => "x86",
        Some(0x8664) => "x86-64",
        Some(0xaa64) => "ARM64",
        Some(0x1c0) => "ARM",
        Some(_) => "unknown-cpu",
        None => return "PE executable".into(),
    };
    let nsec = data
        .get(peoff + 6..peoff + 8)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0);
    let ts = data
        .get(peoff + 8..peoff + 12)
        .map(|t| u32::from_le_bytes([t[0], t[1], t[2], t[3]]))
        .unwrap_or(0);
    let ts_str = if ts > 0 {
        // render as raw unix timestamp; converting needs no chrono
        format!(", link ts {ts}")
    } else {
        String::new()
    };
    let opt = data.get(peoff + 22).copied().unwrap_or(0);
    let kind = if opt & 0x02 != 0 {
        "executable"
    } else if opt & 0x20 != 0 {
        "DLL"
    } else {
        "executable image"
    };
    format!("PE {kind} ({machine}), {nsec} sections{ts_str}")
}

#[cfg(feature = "inspect")]
fn describe_embedded(sig: &Sig, data: &[u8], off: usize) -> String {
    match sig.magic {
        b"\x89PNG\r\n\x1a\n" => {
            if off + 24 <= data.len() {
                let w = u32::from_be_bytes([
                    data[off + 16],
                    data[off + 17],
                    data[off + 18],
                    data[off + 19],
                ]);
                let h = u32::from_be_bytes([
                    data[off + 20],
                    data[off + 21],
                    data[off + 22],
                    data[off + 23],
                ]);
                return format!(" {w}x{h}");
            }
            String::new()
        }
        b"PK\x03\x04" => {
            if off + 30 <= data.len() {
                let nlen = u16::from_le_bytes([data[off + 26], data[off + 27]]) as usize;
                if off + 30 + nlen <= data.len() {
                    let name = String::from_utf8_lossy(&data[off + 30..off + 30 + nlen]);
                    return format!(" entry \"{name}\"");
                }
            }
            String::new()
        }
        b"SQLite format 3\x00" => {
            if off + 100 <= data.len() {
                let ps = u16::from_be_bytes([data[off + 16], data[off + 17]]);
                let ps = if ps == 1 { 65536 } else { ps as usize };
                return format!(" page-size {ps}");
            }
            String::new()
        }
        _ => String::new(),
    }
}

/// Slice an embedded structure out of the blob, refusing anything larger
/// than `room` bytes.
///
/// The size is decided BEFORE the copy, not after it — that is the whole
/// point. For a `.zip` the slice runs to the last EOCD, which is to say to
/// the end of the file, so `MAX_FINDINGS` of them means 64 near-whole-file
/// copies allocated and held live at once. Checking the length after
/// `to_vec()` would bound the retention and still pay every allocation.
#[cfg(feature = "inspect")]
fn carve_bounded(sig: &Sig, data: &[u8], off: usize, room: usize) -> Option<Vec<u8>> {
    let (start, end) = carve_span(sig, data, off)?;
    let span = end.checked_sub(start)?;
    if span > room {
        return None;
    }
    Some(data[start..end].to_vec())
}

/// The byte range an embedded structure occupies, without copying it.
/// Only formats with a cheap, reliable end marker are carved; everything else
/// is report-only.
#[cfg(feature = "inspect")]
fn carve_span(sig: &Sig, data: &[u8], off: usize) -> Option<(usize, usize)> {
    match sig.ext {
        // ZIP: find the EOCD record scanning backwards from the end
        // (comment is rare; scan the last 256 KiB)
        "zip" => {
            let tail_start = data.len().saturating_sub(256 * 1024);
            let tail = &data[tail_start..];
            let eocd = find_subsequence(tail, b"PK\x05\x06")?;
            let eocd_abs = tail_start + eocd;
            // both ends: after `off` AND fully inside the file — a PK\x05\x06
            // signature in the last 3 bytes has no 22-byte record after it
            if eocd_abs < off + 22 || eocd_abs + 22 > data.len() {
                return None;
            }
            let comment = u16::from_le_bytes([data[eocd_abs + 20], data[eocd_abs + 21]]) as usize;
            let end = (eocd_abs + 22 + comment).min(data.len());
            Some((off, end))
        }
        // gzip: parse the header manually, then inflate the payload with
        // the in-house decoder, which reports the *exact* byte where the
        // deflate stream ends — so the carved member keeps the original
        // compressed bytes (archive family decompresses for real, nesting
        // keeps working) with zero trailing-junk slop.
        //
        // The inflated bytes are never used — they exist only to find where
        // the deflate stream ends — so the decode is BOUNDED. Inflating a
        // 400 MB embedded payload in full to read `.len()` and return `None`
        // is the shape this replaced.
        "gz" => {
            let h = parse_gzip_header(data, off)?;
            const CARVE_MAX: u64 = 16 * 1024 * 1024;
            let (bounded, deflate_len) = match rgx_core::compress::deflate::DeflateDecoder::new()
                .decode_bounded_with_consumed(&data[h..], CARVE_MAX)
            {
                Ok(v) => v,
                Err(_) => return None,
            };
            if bounded.capped {
                return None; // embedded payload too big for triage
            }
            if deflate_len == 0 {
                return None;
            }
            let end = h + deflate_len + 8; // + CRC32 + ISIZE trailer
            if end > data.len() {
                return None;
            }
            Some((off, end))
        }
        // PDF: slice to the last %%EOF (scan a 1 MiB tail)
        "pdf" => {
            let tail_start = data.len().saturating_sub(1024 * 1024);
            let tail = &data[tail_start..];
            let eof = find_subsequence(tail, b"%%EOF")?;
            let end = (tail_start + eof + 5).min(data.len());
            if end <= off + 8 {
                return None;
            }
            Some((off, end))
        }
        _ => None,
    }
}

/// ASCII + UTF-16LE/BE string runs, concatenated and capped.
#[cfg(feature = "inspect")]
fn extract_strings(data: &[u8], cap: usize) -> String {
    let mut out = String::new();
    let emit = |s: &str, out: &mut String| {
        if out.len() < cap {
            out.push_str(s);
            out.push('\n');
        }
    };

    // ASCII runs.
    //
    // **The run is tracked as a byte RANGE and appended once, not pushed a
    // byte at a time.** This is the whole cost of the function, measured:
    // ablating it takes Inspect from ~927 ms to ~504 ms over the 293 test
    // binaries under `target/release` -- 46% of the adapter, and Inspect is
    // itself 83% of all adapter time on a binary-heavy tree. `String::push`
    // is a bounds check plus a UTF-8 encode plus a capacity check, and doing
    // it once per byte over a whole binary is what the ablation removed.
    //
    // The test is `b.wrapping_sub(0x20) < 0x5f` rather than
    // `(0x20..=0x7e).contains(&b)`: one unsigned compare instead of a pair of
    // bounds checks, and it is the shape the rest of this crate already uses.
    //
    // Returning as soon as the cap is reached is output-equivalent, not a
    // behaviour change: `emit` refuses to append once `out.len() >= cap`, so
    // the old loop walked the rest of the file producing nothing. The early
    // return just stops doing that.
    let mut run_start = 0usize;
    for i in 0..data.len() {
        if data[i].wrapping_sub(0x20) < 0x5f {
            continue;
        }
        // `data[i]` is not printable, so the run is exactly `run_start..i`.
        if i - run_start >= STR_MIN_RUN {
            emit(core::str::from_utf8(&data[run_start..i]).unwrap(), &mut out);
            if out.len() >= cap {
                return out;
            }
        }
        run_start = i + 1;
    }
    if data.len() - run_start >= STR_MIN_RUN {
        emit(core::str::from_utf8(&data[run_start..]).unwrap(), &mut out);
    }
    if out.len() >= cap {
        return out;
    }

    // UTF-16LE/BE runs: <printable><NUL> pairs.
    for be in [false, true] {
        let mut run16 = String::new();
        let mut i = 0usize;
        while i + 1 < data.len() {
            let (a, b) = if be {
                (data[i], data[i + 1])
            } else {
                (data[i + 1], data[i])
            };
            if b == 0 && (0x20..=0x7e).contains(&a) {
                run16.push(a as char);
                i += 2;
            } else {
                // **`run16.len()` is the char count, exactly.** Every byte
                // that reaches `push` passed `0x20..=0x7e`, so every char is
                // one ASCII byte; the old `.chars().count()` walked the run a
                // second time at every break to learn a number `len()` already
                // holds. It was not free: on a binary with many UTF-16 runs
                // that recount is a second pass over the same bytes.
                if run16.len() >= STR_MIN_RUN {
                    emit(&run16, &mut out);
                    if out.len() >= cap {
                        return out;
                    }
                }
                run16.clear();
                i += 2;
            }
        }
        if run16.len() >= STR_MIN_RUN {
            emit(&run16, &mut out);
        }
        if out.len() >= cap {
            break;
        }
    }
    out
}

// ---------- WebAssembly module ----------

/// WebAssembly binary module: validate magic/version, then walk the
/// section sequence with an LEB128 reader and index what a code search
/// wants — import module/name pairs, export names with their kind, custom
/// section names (the "name" section carries function names). No decoding
/// of function bodies: names are the greppable payload.
#[cfg(feature = "wasm")]
pub struct Wasm;
#[cfg(feature = "wasm")]
impl Adapter for Wasm {
    fn name(&self) -> &'static str {
        "wasm"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["wasm"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 8 || &data[0..4] != b"\0asm" {
            decline!("not a wasm module (bad magic)");
        }
        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version != 1 {
            bail!("unsupported wasm version {version}");
        }
        const SECTION_NAMES: &[&str] = &[
            "custom",
            "type",
            "import",
            "function",
            "table",
            "memory",
            "global",
            "export",
            "start",
            "element",
            "code",
            "data",
            "datacount",
        ];
        const KIND_NAMES: &[&str] = &["func", "table", "memory", "global"];
        let mut out = String::from("wasm module v1\n");
        let mut p = 8usize;
        let mut sections = 0usize;
        while p < data.len() && sections < 10_000 && out.len() < (1 << 20) {
            sections += 1;
            let id = data[p];
            p += 1;
            let Some(size) = leb(data, &mut p, 32) else {
                break;
            };
            if size > (1 << 28) {
                break; // absurd section size: malformed
            }
            let size = size as usize;
            if p.checked_add(size).is_none_or(|e| e > data.len()) {
                break; // truncated file: report what we have
            }
            let payload = &data[p..p + size];
            let sname = SECTION_NAMES.get(id as usize).copied().unwrap_or("unknown");
            match id {
                0 => {
                    // custom: first LEB string is the section name
                    let mut q = 0usize;
                    if let Some(n) = leb(payload, &mut q, 32) {
                        let n = n as usize;
                        if q + n <= payload.len() && n <= 1024 {
                            let name = String::from_utf8_lossy(&payload[q..q + n]);
                            let _ = writeln!(out, "custom: {name}");
                        }
                    }
                }
                2 => {
                    // import: count, then (module, name, kind, desc)
                    let mut q = 0usize;
                    let Some(count) = leb(payload, &mut q, 32) else {
                        continue;
                    };
                    for _ in 0..count.min(4096) {
                        let Some(m) = leb_str(payload, &mut q) else {
                            break;
                        };
                        let Some(n) = leb_str(payload, &mut q) else {
                            break;
                        };
                        let Some(kind) = payload.get(q).copied() else {
                            break;
                        };
                        q += 1;
                        // skip the import descriptor (kind-specific widths)
                        let desc_ok = match kind {
                            0 => leb(payload, &mut q, 32).is_some(), // typeidx
                            1 => {
                                // table: reftype + limits
                                let a = payload.get(q).is_some();
                                q = q.saturating_add(1);
                                a && limits(payload, &mut q)
                            }
                            2 => limits(payload, &mut q), // memory
                            3 => {
                                // global: valtype + mut
                                let a = payload.get(q).is_some();
                                q = q.saturating_add(2);
                                a
                            }
                            _ => false,
                        };
                        if !desc_ok {
                            break;
                        }
                        let _ = writeln!(
                            out,
                            "import: {m}.{n} ({})",
                            KIND_NAMES.get(kind as usize).copied().unwrap_or("?")
                        );
                    }
                }
                7 => {
                    // export: count, then (name, kind, index)
                    let mut q = 0usize;
                    let Some(count) = leb(payload, &mut q, 32) else {
                        continue;
                    };
                    for _ in 0..count.min(4096) {
                        let Some(n) = leb_str(payload, &mut q) else {
                            break;
                        };
                        let Some(kind) = payload.get(q).copied() else {
                            break;
                        };
                        q += 1;
                        if leb(payload, &mut q, 32).is_none() {
                            break;
                        }
                        let _ = writeln!(
                            out,
                            "export: {n} ({})",
                            KIND_NAMES.get(kind as usize).copied().unwrap_or("?")
                        );
                    }
                }
                _ => {
                    let _ = writeln!(out, "section: {sname} ({size} bytes)");
                }
            }
            p += size;
        }
        if out.lines().count() <= 1 {
            bail!("wasm module with no readable sections");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// LEB128 unsigned integer, at most `max_bits`; returns None on overflow,
/// truncation or excessive length. `p` advances only on success.
#[cfg(feature = "wasm")]
fn leb(data: &[u8], p: &mut usize, max_bits: u32) -> Option<u64> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    let start = *p;
    while *p < data.len() && shift < max_bits {
        let b = data[*p];
        *p += 1;
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
    }
    *p = start;
    None
}

/// LEB128 length-prefixed string.
#[cfg(feature = "wasm")]
fn leb_str(data: &[u8], p: &mut usize) -> Option<String> {
    let n = leb(data, p, 32)?;
    if n > 4096 {
        return None;
    }
    let n = n as usize;
    if p.checked_add(n).is_none_or(|e| e > data.len()) {
        return None;
    }
    let s = String::from_utf8_lossy(&data[*p..*p + n]).into_owned();
    *p += n;
    Some(s)
}

/// limits: flags byte then min (and optional max) LEB.
#[cfg(feature = "wasm")]
fn limits(data: &[u8], p: &mut usize) -> bool {
    let Some(flags) = data.get(*p).copied() else {
        return false;
    };
    *p += 1;
    if leb(data, p, 32).is_none() {
        return false;
    }
    if flags & 1 != 0 && leb(data, p, 32).is_none() {
        return false;
    }
    true
}

// ---------- Windows Shell Link (.lnk) ----------

#[cfg(feature = "lnk")]
const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
#[cfg(feature = "lnk")]
const LNK_HAS_ID_LIST: u32 = 0x01;
#[cfg(feature = "lnk")]
const LNK_HAS_LINK_INFO: u32 = 0x02;
#[cfg(feature = "lnk")]
const LNK_HAS_NAME: u32 = 0x04;
#[cfg(feature = "lnk")]
const LNK_HAS_RELPATH: u32 = 0x08;
#[cfg(feature = "lnk")]
const LNK_HAS_WORKDIR: u32 = 0x10;
#[cfg(feature = "lnk")]
const LNK_HAS_ARGS: u32 = 0x20;
#[cfg(feature = "lnk")]
const LNK_HAS_ICONLOC: u32 = 0x40;
#[cfg(feature = "lnk")]
const LNK_IS_UNICODE: u32 = 0x80;

#[cfg(feature = "lnk")]
fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
#[cfg(feature = "lnk")]
fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
#[cfg(feature = "lnk")]
fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

#[cfg(feature = "lnk")]
fn filetime_to_unix(ft: u64) -> u64 {
    ft.saturating_sub(11_644_473_600_000_000_000) / 10_000_000
}

#[cfg(feature = "lnk")]
fn lnk_string(data: &[u8], pos: &mut usize, unicode: bool) -> Result<String> {
    if *pos + 2 > data.len() {
        bail!("truncated .lnk string count");
    }
    let count = rd_u16(data, *pos) as usize;
    *pos += 2;
    let width = if unicode { 2 } else { 1 };
    let need = count
        .checked_mul(width)
        .ok_or_else(|| rgx_core::anyhow!(".lnk string overflow"))?;
    if *pos + need > data.len() {
        bail!("truncated .lnk string body");
    }
    let raw = &data[*pos..*pos + need];
    *pos += need;
    if unicode {
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    } else {
        Ok(String::from_utf8_lossy(raw).into_owned())
    }
}

/// Windows Shell Link (shortcut): decode the header, string sections and
/// LinkInfo so jump-list and Recent-Items binaries become greppable —
/// target path, arguments, working directory and timestamps.
#[cfg(feature = "lnk")]
pub struct Lnk;
#[cfg(feature = "lnk")]
impl Adapter for Lnk {
    fn name(&self) -> &'static str {
        "lnk"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["lnk"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 76 {
            decline!("shorter than the .lnk header");
        }
        if rd_u32(data, 0) != 0x4C {
            decline!("not a Shell Link (header size != 0x4C)");
        }
        if data[4..20] != LNK_CLSID {
            decline!("not a Shell Link (bad CLSID)");
        }
        let link_flags = rd_u32(data, 20);
        let unicode = link_flags & LNK_IS_UNICODE != 0;
        let mut out = String::from("windows shell link (.lnk)\n");
        let _ = writeln!(
            out,
            "target size: {} bytes\nwritten: {}",
            rd_u32(data, 52),
            filetime_to_unix(rd_u64(data, 44))
        );
        // IconIndex occupies 56..60; a search tool does not need it.
        let show_raw = rd_u32(data, 60);
        let show = match show_raw {
            1 => "normal".to_string(),
            3 => "maximized".to_string(),
            7 => "minimized".to_string(),
            other => format!("other({other})"),
        };
        let _ = writeln!(out, "show: {show}");

        let mut pos = 76usize;
        if link_flags & LNK_HAS_ID_LIST != 0 {
            // The length field needs its own two bytes before the size
            // guard below runs: a header of exactly 76 ends here, and
            // the read used to go one past it.
            if pos + 2 > data.len() {
                bail!("truncated .lnk IDList");
            }
            let idlist_size = rd_u16(data, pos) as usize;
            pos += 2;
            if pos + idlist_size > data.len() {
                bail!("truncated .lnk IDList");
            }
            pos += idlist_size;
        }
        if link_flags & LNK_HAS_LINK_INFO != 0 {
            if pos + 28 > data.len() {
                bail!("truncated .lnk LinkInfo");
            }
            let size = rd_u32(data, pos) as usize;
            if size < 0x1C || pos + size > data.len() {
                bail!("bad .lnk LinkInfo size");
            }
            let block = &data[pos..pos + size];
            let header_size = rd_u32(block, 4) as usize;
            let li_flags = rd_u32(block, 8);
            let local_off = if header_size >= 0x24 {
                rd_u32(block, 20) as usize
            } else {
                0
            };
            if li_flags & 0x1 != 0 && local_off > 0 && local_off < block.len() {
                let raw = &block[local_off..];
                let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                let _ = writeln!(
                    out,
                    "local target: {}",
                    String::from_utf8_lossy(&raw[..end])
                );
            }
            pos += size;
        }
        for (flag, label) in [
            (LNK_HAS_NAME, "name"),
            (LNK_HAS_RELPATH, "relative path"),
            (LNK_HAS_WORKDIR, "working dir"),
            (LNK_HAS_ARGS, "arguments"),
            (LNK_HAS_ICONLOC, "icon location"),
        ] {
            if link_flags & flag != 0 {
                let s = lnk_string(data, &mut pos, unicode)?;
                let _ = writeln!(out, "{label}: {s}");
            }
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(test)]
#[cfg(any(feature = "inspect", feature = "lnk", feature = "wasm"))]
mod tests {
    use super::*;

    #[cfg(feature = "lnk")]
    fn lnk_header(link_flags: u32) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&0x4Cu32.to_le_bytes());
        d.extend_from_slice(&LNK_CLSID);
        d.extend_from_slice(&link_flags.to_le_bytes());
        d.extend_from_slice(&0x20u32.to_le_bytes()); // file attrs
        d.extend_from_slice(&[0u8; 24]); // three FILETIMEs
        d.extend_from_slice(&77u32.to_le_bytes()); // target size
        d.extend_from_slice(&0u32.to_le_bytes()); // icon index
        d.extend_from_slice(&1u32.to_le_bytes()); // SW_NORMAL
        d.extend_from_slice(&0u16.to_le_bytes()); // hotkey
        d.extend_from_slice(&[0u8; 10]); // reserved
        d
    }

    #[test]
    #[cfg(feature = "lnk")]
    fn lnk_decodes_unicode_sections() {
        let flags = LNK_HAS_NAME | LNK_HAS_ARGS | LNK_IS_UNICODE;
        let mut d = lnk_header(flags);
        d.extend_from_slice(&3u16.to_le_bytes());
        for u in "pay".encode_utf16() {
            d.extend_from_slice(&u.to_le_bytes());
        }
        d.extend_from_slice(&6u16.to_le_bytes());
        for u in "--fast".encode_utf16() {
            d.extend_from_slice(&u.to_le_bytes());
        }
        let Outcome::Text(t) = Lnk.extract(&d, "x.lnk").unwrap() else {
            panic!("expected text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("name: pay"), "{s}");
        assert!(s.contains("arguments: --fast"), "{s}");
        assert!(s.contains("target size: 77"), "{s}");
    }

    #[test]
    #[cfg(feature = "lnk")]
    fn lnk_decodes_local_target() {
        let flags = LNK_HAS_LINK_INFO;
        let mut d = lnk_header(flags);
        let path = b"C:\\bin\\tool.exe\0";
        let size = 0x24 + path.len();
        d.extend_from_slice(&(size as u32).to_le_bytes());
        d.extend_from_slice(&0x24u32.to_le_bytes());
        d.extend_from_slice(&1u32.to_le_bytes()); // VolumeIDAndLocalBasePath
        d.extend_from_slice(&[0u8; 8]); // volume / cnrl offsets unused
        d.extend_from_slice(&0x24u32.to_le_bytes()); // LocalBasePath offset
        d.extend_from_slice(&[0u8; 4]); // CommonPathSuffix offset
        d.extend_from_slice(&[0u8; 8]); // reserved → header is 0x24 bytes
        d.extend_from_slice(path);
        let Outcome::Text(t) = Lnk.extract(&d, "x.lnk").unwrap() else {
            panic!("expected text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("local target: C:\\bin\\tool.exe"), "{s}");
    }

    #[test]
    #[cfg(feature = "lnk")]
    fn lnk_rejects_garbage() {
        assert!(Lnk.extract(&[0u8; 100], "x.lnk").is_err());
        let mut d = lnk_header(0);
        d[4] ^= 0xFF;
        assert!(Lnk.extract(&d, "x.lnk").is_err());
    }

    /// libFuzzer-found: a PK\x05\x06 signature in the last 3 bytes of the
    /// blob made the EOCD read go past EOF. Extract must decline the carve,
    /// never panic.
    #[test]
    #[cfg(feature = "inspect")]
    fn zip_carve_declares_tail_signature() {
        let mut data = b"MZ".to_vec();
        data.extend_from_slice(&[0u8; 60]);
        data.extend_from_slice(b"PK\x05\x06"); // 6 bytes, record needs 22
        let outcome = Inspect.extract(&data, "blob.bin").unwrap();
        match outcome {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("[embedded]"), "{s}");
                assert!(!s.contains("[carved]"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[cfg(feature = "inspect")]
    fn fake_pe() -> Vec<u8> {
        let mut v = vec![0u8; 0x400];
        v[0] = b'M';
        v[1] = b'Z';
        v[0x3c] = 0x80; // e_lfanew = 0x80
        v[0x80..0x84].copy_from_slice(b"PE\0\0");
        v[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // x86-64
        v[0x86..0x88].copy_from_slice(&3u16.to_le_bytes()); // 3 sections
        v[0x88..0x8c].copy_from_slice(&1700000000u32.to_le_bytes());
        v[0xa2] = 0x22; // DLL characteristics-ish flags (optional header magic byte pos)
        v
    }

    #[test]
    #[cfg(feature = "inspect")]
    fn identifies_pe_with_details() {
        let out = inspect(&fake_pe(), "app.exe");
        let Outcome::Text(t) = out else {
            panic!("expected text")
        };
        let s = String::from_utf8_lossy(&t);
        assert!(s.contains("[format] PE"), "{s}");
        assert!(s.contains("x86-64"), "{s}");
        assert!(s.contains("3 sections"), "{s}");
    }

    #[test]
    #[cfg(feature = "inspect")]
    fn text_bails_to_raw() {
        let t = b"just some plain text with no binary at all\n".to_vec();
        let Outcome::Bail(_) = inspect(&t, "notes.bin") else {
            panic!("text must bail")
        };
    }

    #[test]
    #[cfg(feature = "inspect")]
    fn utf16_strings_extracted() {
        // "Hidden" encoded UTF-16LE
        let mut v = vec![0u8; 64];
        let s16: Vec<u8> = "HiddenWide"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        v[10..10 + s16.len()].copy_from_slice(&s16);
        let out = inspect(&v, "res.dll");
        let Outcome::Text(t) = out else {
            panic!("expected text")
        };
        let s = String::from_utf8_lossy(&t);
        assert!(s.contains("HiddenWide"), "{s}");
    }

    #[test]
    #[cfg(feature = "inspect")]
    fn embedded_png_reported_with_dimensions() {
        let mut png = vec![0u8; 64];
        png[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        png[16..20].copy_from_slice(&640u32.to_be_bytes());
        png[20..24].copy_from_slice(&480u32.to_be_bytes());
        let mut blob = vec![0xAAu8; 512];
        blob[300..300 + 64].copy_from_slice(&png);

        let out = inspect(&blob, "blob.bin");
        let Outcome::Text(t) = out else {
            panic!("expected text")
        };
        let s = String::from_utf8_lossy(&t);
        assert!(
            s.contains("[embedded] 0x0000012c: PNG image 640x480"),
            "{s}"
        );
    }

    #[test]
    #[cfg(feature = "inspect")]
    fn embedded_zip_carved_and_recurse_ready() {
        // minimal real zip built by hand: one stored entry "note.txt" = "hello"
        let content = b"hello";
        let name = b"note.txt";
        let mut zip = Vec::new();
        let crc = crc32(content);
        // local header
        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&20u16.to_le_bytes()); // version
        zip.extend_from_slice(&0u16.to_le_bytes()); // flags
        zip.extend_from_slice(&0u16.to_le_bytes()); // method stored
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(content.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(content.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(name);
        zip.extend_from_slice(content);
        let cdr_off = zip.len() as u32;
        zip.extend_from_slice(b"PK\x01\x02");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&crc.to_le_bytes());
        zip.extend_from_slice(&(content.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(content.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(name);
        let cd_size = zip.len() as u32 - cdr_off;
        zip.extend_from_slice(b"PK\x05\x06");
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&cd_size.to_le_bytes());
        zip.extend_from_slice(&cdr_off.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());

        let mut blob = vec![0x55u8; 256];
        blob.extend_from_slice(&zip);
        blob.extend_from_slice(&[0xEEu8; 64]); // trailing junk after the archive

        let out = inspect(&blob, "firmware.bin");
        let Outcome::Members(m) = out else {
            panic!("expected carved members")
        };
        assert_eq!(m.len(), 2, "report + carved zip");
        let carved = &m[1];
        assert!(carved.0.ends_with(".zip"), "{}", carved.0);
        assert!(carved.1.starts_with(b"PK\x03\x04"));
        // carved slice must end exactly at the EOCD (no trailing junk)
        assert!(
            carved.1.ends_with(b"PK\x05\x06") || carved.1.windows(4).any(|w| w == b"PK\x05\x06")
        );
        let report = String::from_utf8_lossy(&m[0].1);
        assert!(report.contains("[carved]"), "{report}");
        assert!(report.contains("note.txt"), "{report}");
    }

    #[test]
    #[cfg(feature = "inspect")]
    fn embedded_gzip_carved_via_inflate() {
        let gz = rgx_core::compress::gzip::GzipWriter::new()
            .encode(b"embedded gzip payload secret-treasure");
        let mut blob = vec![0x11u8; 128];
        blob.extend_from_slice(&gz);
        blob.extend_from_slice(&[0x22u8; 32]);

        let out = inspect(&blob, "pkg.dat");
        let Outcome::Members(m) = out else {
            panic!("expected carved members")
        };
        let carved = m
            .iter()
            .find(|(n, _)| n.ends_with(".gz"))
            .expect("gz member");
        // the carved member keeps the *compressed* stream — the archive
        // family owns decompression, nesting keeps working
        assert!(carved.1.starts_with(b"\x1f\x8b\x08"), "{}", carved.1.len());
        let text = String::from_utf8_lossy(
            &rgx_core::compress::gzip::GzipReader::decode(&carved.1[..]).expect("decode carved gz"),
        )
        .into_owned();
        assert!(text.contains("secret-treasure"), "{text}");
        // trailing junk after the stream must NOT be part of the carve
        assert!(!carved.1.contains(&0x22u8), "trailing junk leaked in");
    }

    #[test]
    #[cfg(feature = "inspect")]
    fn entropy_flags_packed_region() {
        // deterministic xorshift "random" middle, zeros elsewhere
        let mut blob = vec![0u8; 32 * 1024];
        let mut x = 0x12345678u32;
        for b in &mut blob[8 * 1024..24 * 1024] {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x >> 24) as u8;
        }
        let out = inspect(&blob, "packed.sys");
        let Outcome::Text(t) = out else {
            panic!("expected text")
        };
        let s = String::from_utf8_lossy(&t);
        assert!(s.contains("[entropy]"), "{s}");
        assert!(s.contains("compressed/encrypted"), "{s}");
        // sparse classification for the zero regions must also appear
        assert!(s.contains("sparse/padded"), "{s}");
    }

    #[test]
    #[cfg(feature = "inspect")]
    fn classification_high_entropy_blob() {
        let mut x = 0xdeadbeefu32;
        let mut blob = vec![0u8; 8192];
        for b in &mut blob {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x >> 24) as u8;
        }
        assert_eq!(
            classify(&blob),
            "high-entropy blob (compressed or encrypted)"
        );
    }

    /// tiny but complete wasm module: header + a "name" custom section +
    /// an export section with one function. LEB sizes < 128, single byte.
    #[cfg(feature = "wasm")]
    fn wasm_module() -> Vec<u8> {
        let mut m = b"\0asm\x01\0\0\0".to_vec();
        // custom section (id 0): name "name"
        m.push(0);
        m.push(4 + 5); // size: name len byte + 4 chars + empty body
        m.push(4);
        m.extend_from_slice(b"name");
        m.extend_from_slice(b"\0\0\0\0");
        // export section (id 7): 1 entry, name "solve_ZIRCALOY", kind func(0), idx 0
        let name = b"solve_ZIRCALOY";
        m.push(7);
        m.push(name.len() as u8 + 4);
        m.push(1); // count
        m.push(name.len() as u8);
        m.extend_from_slice(name);
        m.push(0); // kind func
        m.push(0); // index
        m
    }

    #[test]
    #[cfg(feature = "wasm")]
    fn wasm_exports_and_custom_sections() {
        let out = Wasm.extract(&wasm_module(), "m.wasm").unwrap();
        let Outcome::Text(t) = out else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("wasm module v1"), "{s}");
        assert!(s.contains("custom: name"), "{s}");
        assert!(s.contains("export: solve_ZIRCALOY (func)"), "{s}");
    }

    #[test]
    #[cfg(feature = "wasm")]
    fn wasm_rejects_bad_version() {
        let bad = b"\0asm\x02\0\0\0";
        assert!(Wasm.extract(bad, "m.wasm").is_err());
    }

    #[cfg(feature = "inspect")]
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= b as u32;
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

    #[cfg(any(feature = "inspect", feature = "wasm"))]
    mod fuzz {
        use super::*;

        #[cfg(feature = "inspect")]
        fn png_blob() -> Vec<u8> {
            let mut png = vec![0u8; 64];
            png[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
            png[16..20].copy_from_slice(&640u32.to_be_bytes());
            png[20..24].copy_from_slice(&480u32.to_be_bytes());
            let mut blob = vec![0xAAu8; 512];
            blob[300..300 + 64].copy_from_slice(&png);
            blob
        }

        #[cfg(feature = "inspect")]
        fn gzip_blob() -> Vec<u8> {
            let gz = rgx_core::compress::gzip::GzipWriter::new()
                .encode(b"embedded gzip payload secret-treasure");
            let mut blob = vec![0x11u8; 128];
            blob.extend_from_slice(&gz);
            blob
        }

        #[test]
        #[cfg(feature = "inspect")]
        fn inspect_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("pe", fake_pe()),
                    ("png-embedded", png_blob()),
                    ("gzip-embedded", gzip_blob()),
                    ("mz-only", b"MZ".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "inspect",
                |data| {
                    let _ = inspect(data, "fuzz.bin");
                },
            );
        }

        #[test]
        #[cfg(feature = "wasm")]
        fn wasm_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("module", wasm_module()),
                    ("magic-only", b"\0asm\x01\0\0\0".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "wasm",
                |data| {
                    let _ = Wasm.extract(data, "fuzz.wasm");
                },
            );
        }
    }
}

#[cfg(test)]
mod classify_tests {
    use super::*;

    #[test]
    fn recognises_common_magic_prefixes() {
        assert_eq!(magic_classify(b"%PDF-1.7\n"), Some("pdf"));
        assert_eq!(magic_classify(b"PK\x03\x04some zip"), Some("zip"));
        assert_eq!(magic_classify(b"PK\x05\x06empty"), Some("zip"));
        assert_eq!(magic_classify(b"\x7fELF\x02\x01\x01"), Some("elf"));
        assert_eq!(magic_classify(b"SQLite format 3\x00\x10"), Some("sqlite"));
        assert_eq!(magic_classify(b"\x89PNG\r\n\x1a\n"), Some("png"));
        assert_eq!(magic_classify(b"\xff\xd8\xff\xe0"), Some("jpeg"));
        assert_eq!(magic_classify(b"GIF89a\x10"), Some("gif"));
        assert_eq!(magic_classify(b"BM\x10"), Some("bmp"));
        assert_eq!(magic_classify(b"\x1f\x8b\x08"), Some("gzip"));
        assert_eq!(magic_classify(b"BZh9"), Some("bzip2"));
        assert_eq!(magic_classify(b"\xfd7zXZ\x00\x01"), Some("xz"));
        assert_eq!(magic_classify(b"\x28\xb5\x2f\xfd"), Some("zstd"));
        assert_eq!(magic_classify(b"7z\xbc\xaf'\x1c"), Some("7z"));
        assert_eq!(magic_classify(b"Rar!\x1a\x07\x00"), Some("rar"));
        assert_eq!(magic_classify(b"\x00asm\x01"), Some("wasm"));
        assert_eq!(magic_classify(b"\xca\xfe\xba\xbe"), Some("class"));
        assert_eq!(magic_classify(b"dex\n035"), Some("dex"));
        assert_eq!(magic_classify(b"BLENDER_v300"), Some("blender"));
        assert_eq!(magic_classify(b"\x89HDF\r\n\x1a\n"), Some("hdf5"));
        assert_eq!(magic_classify(b"RIFF\x00\x00\x00\x00WEBP"), Some("webp"));
        assert_eq!(magic_classify(b"II*\x00\x08"), Some("tiff"));
        assert_eq!(magic_classify(b"MM\x00*\x00"), Some("tiff"));
        assert_eq!(
            magic_classify(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
            Some("cfb")
        );
        assert_eq!(magic_classify(b"\xfe\xed\xfa\xce"), Some("macho"));
        assert_eq!(magic_classify(b"\xcf\xfa\xed\xfe"), Some("macho"));
        assert_eq!(magic_classify(b"OggS\x00"), Some("ogg"));
        assert_eq!(magic_classify(b"fLaC"), Some("flac"));
        assert_eq!(magic_classify(b"ID3\x04"), Some("mp3"));
        assert_eq!(magic_classify(b"\xff\xfb\x90"), Some("mp3"));
        assert_eq!(magic_classify(b"MThd\x00"), Some("midi"));
        assert_eq!(magic_classify(b"8BPS\x00"), Some("psd"));
    }

    #[test]
    fn returns_none_for_unrecognised_prefix() {
        assert_eq!(magic_classify(b"hello world"), None);
        assert_eq!(magic_classify(b""), None);
        assert_eq!(magic_classify(b"\x00\x00"), None);
        assert_eq!(magic_classify(b"plain text content here"), None);
    }
}

/// The carve pass must be bounded, not merely capped in COUNT.
///
/// `MAX_FINDINGS` is 64 and a `.zip` carve runs to the last EOCD, which is to
/// say to the end of the file. So the uncapped pass could hold 64 near-whole-file
/// copies live at once — roughly 64x the input — and each carved member then
/// re-entered the pipeline with its own fresh budget. `Adapter::extract` never
/// sees a `Ctx`, so `MemberSink` was not reachable from this crate and nothing
/// bounded it.
#[test]
#[cfg(feature = "inspect")]
fn carved_members_stay_inside_the_carve_budget() {
    // One file containing many zip signatures, each of which would carve to
    // the SAME final EOCD — so every carve is the whole tail of the file.
    let mut data = Vec::new();
    // A binary head, or `looks_like_text` bails before the carve pass runs.`n    data.extend_from_slice(&[0x7f, 0x45, 0x4c, 0x46]);`n    data.extend_from_slice(&[0u8; 512]);
    // 1 MiB between signatures, so 80 carves would be ~80 MiB retained without
    // a budget -- comfortably past the 16 MiB ceiling, so the ceiling has to
    // bind rather than merely exist.
    for _ in 0..80 {
        data.extend_from_slice(b"PK\x03\x04");
        data.extend_from_slice(&[0u8; 1024 * 1024]);
    }
    // The single EOCD every carve will find: last 22 bytes, zero comment.
    data.extend_from_slice(b"PK\x05\x06");
    data.extend_from_slice(&[0u8; 18]);

    let outcome = inspect(&data, "synthetic.bin");
    // Either shape is correct here: the ceiling refuses the oversized carves
    // and leaves `members` empty (so the adapter reports its text), or a carve
    // fits and is kept. What must never happen is a member set past the
    // ceiling, so both arms are measured the same way.
    let retained: usize = match &outcome {
        Outcome::Members(m) => m.iter().map(|(_, b)| b.len()).sum(),
        Outcome::Text(_) => 0,
        _ => 0,
    };
    let total = data.len();
    assert!(
        retained <= 16 * 1024 * 1024,
        "carve budget exceeded: {retained} bytes retained from a {total}-byte input"
    );
    // The point of the budget: without it this is ~80x the input, because every
    // carve spans from its own signature to the one shared EOCD.
    assert!(
        retained < 16 * 1024 * 1024,
        "carving retained {retained} bytes from a {total}-byte input, past the ceiling"
    );
}
