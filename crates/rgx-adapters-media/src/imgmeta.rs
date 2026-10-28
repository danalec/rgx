// SPDX-License-Identifier: Apache-2.0

//! GIF and BMP metadata, hand-rolled (covering what `io::binary::gif`
//! and `io::binary::bmp` cover). Only headers and comment text are read — pixel
//! data is never decoded.

#[cfg(any(feature = "gif", feature = "bmp"))]
use alloc::string::String;
#[cfg(feature = "gif")]
use alloc::vec::Vec;
#[cfg(any(feature = "gif", feature = "bmp"))]
use rgx_core::{bail, decline, Result};
#[cfg(any(feature = "gif", feature = "bmp"))]
use rgx_core::{Adapter, Outcome};

/// GIF87a/GIF89a: logical-screen descriptor + comment extensions.
#[cfg(feature = "gif")]
pub struct Gif;
#[cfg(feature = "gif")]
impl Adapter for Gif {
    fn name(&self) -> &'static str {
        "gif"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["gif"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let meta = gif_meta(data)?;
        let mut out = String::new();
        use core::fmt::Write as _;
        // Write directly via `writeln!` instead of building a
        // throwaway `String` per field for `push_str`. Each frame
        // allocates 5-6 short Strings it then drops; the macro
        // expands to the same Display calls but writes through
        // `&mut out` directly.
        let _ = writeln!(out, "version: {}", meta.version);
        let _ = writeln!(out, "width: {}", meta.width);
        let _ = writeln!(out, "height: {}", meta.height);
        let _ = writeln!(out, "color_resolution: {}", meta.color_resolution);
        let _ = writeln!(out, "global_colors: {}", meta.global_colors);
        for c in &meta.comments {
            let _ = writeln!(out, "comment: {}", c);
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(feature = "gif")]
struct GifMeta {
    version: &'static str,
    width: u16,
    height: u16,
    color_resolution: u8,
    global_colors: u16,
    comments: Vec<String>,
}

#[cfg(feature = "gif")]
fn gif_meta(data: &[u8]) -> Result<GifMeta> {
    if data.len() < 13 {
        decline!("fewer bytes than a GIF header");
    }
    let version = match &data[..6] {
        b"GIF87a" => "GIF87a",
        b"GIF89a" => "GIF89a",
        _ => decline!("not a GIF (bad signature)"),
    };
    let width = u16::from_le_bytes([data[6], data[7]]);
    let height = u16::from_le_bytes([data[8], data[9]]);
    let packed = data[10];
    let gct_flag = packed & 0x80 != 0;
    let color_resolution = ((packed >> 4) & 0x07) + 1;
    let global_colors = if gct_flag {
        1u16 << ((packed & 0x07) + 1)
    } else {
        0
    };
    let mut meta = GifMeta {
        version,
        width,
        height,
        color_resolution,
        global_colors,
        comments: Vec::new(),
    };
    let gct_bytes = if gct_flag {
        global_colors as usize * 3
    } else {
        0
    };
    let mut pos = 13usize
        .checked_add(gct_bytes)
        .ok_or_else(|| rgx_core::anyhow!("GIF blocks truncated"))?;
    if pos > data.len() {
        bail!("GIF blocks truncated");
    }

    // block walk: trailer 0x3B, image descriptor 0x2C, extension 0x21
    while pos < data.len() {
        let introducer = data[pos];
        pos += 1;
        match introducer {
            0x3B => break, // trailer
            0x2C => {
                // image descriptor: 9 more bytes + optional LCT + data sub-blocks
                pos = pos
                    .checked_add(9)
                    .ok_or_else(|| rgx_core::anyhow!("GIF blocks truncated"))?;
                if pos > data.len() {
                    bail!("GIF blocks truncated");
                }
                if data[pos - 1] & 0x80 != 0 {
                    let lct = 1usize << ((data[pos - 1] & 0x07) + 1);
                    pos = pos
                        .checked_add(lct * 3)
                        .ok_or_else(|| rgx_core::anyhow!("GIF blocks truncated"))?;
                }
                pos = skip_sub_blocks(data, pos)?;
            }
            0x21 => {
                if pos >= data.len() {
                    bail!("GIF blocks truncated");
                }
                let label = data[pos];
                pos += 1;
                if label == 0xFE {
                    // comment extension: plain sub-block text
                    let (text, next) = read_sub_blocks(data, pos)?;
                    if !text.is_empty() {
                        meta.comments.push(text);
                    }
                    pos = next;
                } else {
                    // other extensions carry a fixed-size header first
                    // (graphic control: 4; application: 11; plain text: 12)
                    let header_size = match data.get(pos) {
                        Some(&s) => s as usize,
                        None => bail!("GIF blocks truncated"),
                    };
                    pos = pos
                        .checked_add(1 + header_size)
                        .ok_or_else(|| rgx_core::anyhow!("GIF blocks truncated"))?;
                    pos = skip_sub_blocks(data, pos)?;
                }
            }
            _ => bail!("GIF blocks truncated"),
        }
        if pos > data.len() {
            bail!("GIF blocks truncated");
        }
    }
    Ok(meta)
}

#[cfg(feature = "gif")]
fn read_sub_blocks(data: &[u8], mut pos: usize) -> Result<(String, usize)> {
    let mut out = Vec::new();
    loop {
        let Some(&size) = data.get(pos) else {
            bail!("GIF blocks truncated");
        };
        pos += 1;
        if size == 0 {
            break;
        }
        let end = pos
            .checked_add(size as usize)
            .ok_or_else(|| rgx_core::anyhow!("GIF blocks truncated"))?;
        if end > data.len() {
            bail!("GIF blocks truncated");
        }
        out.extend_from_slice(&data[pos..end]);
        pos = end;
    }
    Ok((String::from_utf8_lossy(&out).into_owned(), pos))
}

#[cfg(feature = "gif")]
fn skip_sub_blocks(data: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        let Some(&size) = data.get(pos) else {
            bail!("GIF blocks truncated");
        };
        pos += 1;
        if size == 0 {
            return Ok(pos);
        }
        pos = pos
            .checked_add(size as usize)
            .ok_or_else(|| rgx_core::anyhow!("GIF blocks truncated"))?;
        if pos > data.len() {
            bail!("GIF blocks truncated");
        }
    }
}

/// BMP: BITMAPFILEHEADER + BITMAPINFOHEADER/CORE/V4/V5 fields.
#[cfg(feature = "bmp")]
pub struct Bmp;
#[cfg(feature = "bmp")]
impl Adapter for Bmp {
    fn name(&self) -> &'static str {
        "bmp"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bmp"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 26 || &data[0..2] != b"BM" {
            decline!("not a BMP (bad signature)");
        }
        let pixel_offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
        let dib_size = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);
        let (width, height, bpp, compression) = match dib_size {
            12 => {
                // BITMAPCOREHEADER: 16-bit width/height, no compression field
                if data.len() < 26 {
                    bail!("truncated BMP core header");
                }
                (
                    u16::from_le_bytes([data[18], data[19]]) as i64,
                    u16::from_le_bytes([data[20], data[21]]) as i64,
                    u16::from_le_bytes([data[24], data[25]]),
                    0u32,
                )
            }
            n if n >= 40 => {
                if data.len() < 38 {
                    bail!("truncated BMP info header");
                }
                (
                    i32::from_le_bytes([data[18], data[19], data[20], data[21]]) as i64,
                    i32::from_le_bytes([data[22], data[23], data[24], data[25]]) as i64,
                    u16::from_le_bytes([data[28], data[29]]),
                    u32::from_le_bytes([data[30], data[31], data[32], data[33]]),
                )
            }
            _ => bail!("unsupported BMP DIB header size {dib_size}"),
        };
        let height_abs = height.unsigned_abs();
        let orientation = if height < 0 { "top-down" } else { "bottom-up" };
        let mut out = String::new();
        use core::fmt::Write as _;
        let _ = writeln!(out, "width: {width}");
        let _ = writeln!(out, "height: {height_abs}");
        let _ = writeln!(out, "orientation: {orientation}");
        let _ = writeln!(out, "bpp: {bpp}");
        let _ = writeln!(out, "compression: {}", bmp_compression_name(compression));
        let _ = writeln!(out, "pixel_offset: {pixel_offset}");
        let _ = writeln!(out, "dib_header: {dib_size}");
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(feature = "bmp")]
fn bmp_compression_name(c: u32) -> &'static str {
    match c {
        0 => "none",
        1 => "rle8",
        2 => "rle4",
        3 => "bitfields",
        4 => "jpeg",
        5 => "png",
        6 => "alpha-bitfields",
        11 => "cmyk-none",
        12 => "cmyk-rle8",
        13 => "cmyk-rle4",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(feature = "gif", feature = "bmp"))]
    use alloc::vec::Vec;

    #[cfg(feature = "gif")]
    fn mini_gif() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"GIF89a");
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&3u16.to_le_bytes());
        v.push(0x00); // packed: no GCT
        v.push(0x00); // bg color
        v.push(0x00); // aspect
        v.push(0x21);
        v.push(0xFE);
        v.push(11);
        v.extend_from_slice(b"ZIRCALOY v1");
        v.push(0);
        v.push(0x3B);
        v
    }

    #[cfg(feature = "bmp")]
    fn mini_bmp() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"BM");
        v.extend_from_slice(&70u32.to_le_bytes()); // file size
        v.extend_from_slice(&0u16.to_le_bytes()); // reserved
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&54u32.to_le_bytes()); // pixel offset
        v.extend_from_slice(&40u32.to_le_bytes()); // BITMAPINFOHEADER
        v.extend_from_slice(&640i32.to_le_bytes());
        v.extend_from_slice(&480i32.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // planes
        v.extend_from_slice(&24u16.to_le_bytes()); // bpp
        v.extend_from_slice(&0u32.to_le_bytes()); // compression
        v.extend_from_slice(&0u32.to_le_bytes()); // image size
        v
    }

    #[test]
    #[cfg(feature = "gif")]
    fn gif_header_and_comment() {
        match Gif.extract(&mini_gif(), "a.gif").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("version: GIF89a"), "{s}");
                assert!(s.contains("width: 2"), "{s}");
                assert!(s.contains("height: 3"), "{s}");
                assert!(s.contains("comment: ZIRCALOY v1"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    #[cfg(feature = "gif")]
    fn gif_rejects_non_gif() {
        assert!(Gif.extract(b"NOTGIF1234567890", "a.gif").is_err());
        assert!(Gif.extract(b"", "a.gif").is_err());
    }

    #[test]
    #[cfg(feature = "bmp")]
    fn bmp_info_header() {
        match Bmp.extract(&mini_bmp(), "a.bmp").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("width: 640"), "{s}");
                assert!(s.contains("height: 480"), "{s}");
                assert!(s.contains("bpp: 24"), "{s}");
                assert!(s.contains("compression: none"), "{s}");
                assert!(s.contains("pixel_offset: 54"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    #[cfg(feature = "bmp")]
    fn bmp_top_down_negative_height() {
        let mut v = mini_bmp();
        v[22..26].copy_from_slice(&(-480i32).to_le_bytes());
        match Bmp.extract(&v, "a.bmp").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("height: 480"), "{s}");
                assert!(s.contains("orientation: top-down"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    #[cfg(feature = "bmp")]
    fn bmp_core_header() {
        let mut v = Vec::new();
        v.extend_from_slice(b"BM");
        v.extend_from_slice(&26u32.to_le_bytes());
        v.extend_from_slice(&[0u8; 4]);
        v.extend_from_slice(&26u32.to_le_bytes());
        v.extend_from_slice(&12u32.to_le_bytes()); // BITMAPCOREHEADER
        v.extend_from_slice(&10u16.to_le_bytes());
        v.extend_from_slice(&20u16.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&8u16.to_le_bytes());
        match Bmp.extract(&v, "a.bmp").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("width: 10"), "{s}");
                assert!(s.contains("height: 20"), "{s}");
                assert!(s.contains("bpp: 8"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    mod fuzz {
        use super::*;

        #[test]
        #[cfg(feature = "gif")]
        fn gif_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("gif", mini_gif()),
                    ("magic-only", b"GIF89a".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "gif",
                |data| {
                    let _ = Gif.extract(data, "fuzz.gif");
                },
            );
        }

        #[test]
        #[cfg(feature = "bmp")]
        fn bmp_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("bmp", mini_bmp()),
                    ("magic-only", b"BM".to_vec()),
                    ("empty", vec![]),
                ],
                1500,
                "bmp",
                |data| {
                    let _ = Bmp.extract(data, "fuzz.bmp");
                },
            );
        }
    }
}
