// SPDX-License-Identifier: Apache-2.0

//! A minimal PNG writer: 8-bit greyscale, one IDAT, no interlacing.
//!
//! Present because a CCITT scan decodes to raw pixels and an OCR engine wants
//! a picture. Everything else about the format is deliberately absent: there
//! is no palette, no truecolour, no alpha and no interlacing, because the
//! only caller wants to hand a monochrome page to a recogniser and a wider
//! surface is a wider surface to get wrong.
//!
//! # Why the IDAT is stored, not deflated
//!
//! A zlib stream of *stored* (uncompressed) deflate blocks is a valid zlib
//! stream, and a PNG with one is a valid PNG — every decoder reads it. The
//! alternative is a real deflate encoder, which is a few hundred lines and a
//! per-byte cost on every scan, to save space in a buffer that is written
//! once, handed to a subprocess, and thrown away. Compressing an image in
//! order to write it to a pipe is the kind of optimisation that shows up as a
//! bug report rather than as a faster benchmark.
//!
//! What it does cost is size: a 1720×400 page is about 700 KB rather than a
//! few KB. That is bounded by the caller, not by this module — see
//! [`encode_gray8`], which refuses a zero-sized image rather than emitting a
//! file nothing can open.

use alloc::vec::Vec;

use crate::compress::crc32;

/// The 8-byte PNG signature. Everything after it is a sequence of chunks.
const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// Encode an 8-bit greyscale image, `width` × `height`, row-major, one byte
/// per pixel with no row padding.
///
/// `pixels.len()` must be exactly `width * height`. A mismatch returns
/// `None` rather than a truncated image: a PNG whose last row is short is
/// rejected by most decoders and silently mis-rendered by the rest.
pub fn encode_gray8(width: u32, height: u32, pixels: &[u8]) -> Option<Vec<u8>> {
    let w = width as usize;
    let h = height as usize;
    if w == 0 || h == 0 || w.checked_mul(h)? != pixels.len() {
        return None;
    }

    // Raw scanlines are each prefixed with filter type 0 ("none"). The filter
    // is not optional in the format; none is the one that costs nothing.
    let mut raw = Vec::with_capacity(h * (w + 1));
    for row in pixels.chunks_exact(w) {
        raw.push(0);
        raw.extend_from_slice(row);
    }

    let mut out = Vec::new();
    out.extend_from_slice(&SIGNATURE);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]); // depth 8, greyscale, no interlace
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &zlib_stored(&raw));
    chunk(&mut out, b"IEND", &[]);

    Some(out)
}

/// Wrap `data` in a zlib stream made of stored deflate blocks.
///
/// A stored block carries up to 65535 bytes and declares its own length in
/// both the byte count and its complement, so a decoder can skip it without
/// interpreting anything — which is the point: nothing here has to be
/// correct about compression for the file to open.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 65535 * 5 + 16);
    // CMF/FLG: deflate, 32 KiB window, no preset dictionary, and the two
    // bytes together must be a multiple of 31 for zlib to accept them.
    out.push(0x78);
    out.push(0x01);
    if data.is_empty() {
        // An empty final stored block, so the stream still has one.
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
    } else {
        let mut rest = data;
        while !rest.is_empty() {
            let take = rest.len().min(0xFFFF);
            let last = take == rest.len();
            out.push(u8::from(last));
            out.extend_from_slice(&(take as u16).to_le_bytes());
            out.extend_from_slice(&(!(take as u16)).to_le_bytes());
            out.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
        }
    }
    // Adler-32 over the uncompressed data, per RFC 1950.
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]) {
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(body);
    // The CRC covers the type and the data, not the length that precedes
    // them — a detail that is easy to get wrong and produces a file whose
    // every chunk is rejected.
    out.extend_from_slice(&crc32::crc32(&out[start..]).to_be_bytes());
}

/// Adler-32 (RFC 1950 §9), the zlib stream's integrity check.
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    // 5552 is the largest number of bytes that cannot overflow u32 before the
    // modulus is applied, so the inner loop needs no per-byte division.
    for chunk in data.chunks(5552) {
        for byte in chunk {
            a += *byte as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    //! The checks that matter here are the ones a consumer would make: that a
    //! decoder opens the file, that the pixels come back, and that the edge
    //! cases do not produce a file that merely looks like a PNG.
    use super::*;
    use alloc::vec;

    /// Walk the chunk structure and pull the IDAT back out, which is what a
    /// minimal decoder does. If this can read the file, a real decoder can.
    fn chunks(png: &[u8]) -> Vec<(alloc::string::String, Vec<u8>)> {
        assert_eq!(&png[..8], &SIGNATURE, "signature");
        let mut out = vec![];
        let mut i = 8;
        while i + 8 <= png.len() {
            let len = u32::from_be_bytes(png[i..i + 4].try_into().unwrap()) as usize;
            let kind = alloc::string::String::from_utf8_lossy(&png[i + 4..i + 8]).into_owned();
            let body = png[i + 8..i + 8 + len].to_vec();
            out.push((kind, body));
            i += 12 + len;
        }
        out
    }

    fn inflate_stored(z: &[u8]) -> Vec<u8> {
        assert_eq!(&z[..2], &[0x78, 0x01], "zlib header");
        let mut out = vec![];
        let mut i = 2;
        while i < z.len() - 4 {
            assert_eq!(z[i] & 0x06, 0, "stored blocks only");
            let n = u16::from_le_bytes([z[i + 1], z[i + 2]]) as usize;
            out.extend_from_slice(&z[i + 5..i + 5 + n]);
            i += 5 + n;
        }
        assert_eq!(
            adler32(&out),
            u32::from_be_bytes(z[z.len() - 4..].try_into().unwrap())
        );
        out
    }

    #[test]
    fn a_one_pixel_image_round_trips_through_the_chunk_structure() {
        let png = encode_gray8(1, 1, &[0x5A]).expect("encoded");
        let cs = chunks(&png);
        assert_eq!(cs.len(), 3, "IHDR, IDAT, IEND");
        assert_eq!(cs[0].0, "IHDR");
        assert_eq!(cs[2].0, "IEND");
        assert_eq!(cs[1].1, zlib_stored(&[0x00, 0x5A]));
    }

    #[test]
    fn the_header_declares_the_size_and_depth_the_pixels_have() {
        let pixels = vec![7u8; 4 * 3];
        let png = encode_gray8(4, 3, &pixels).expect("encoded");
        let cs = chunks(&png);
        let ihdr = &cs[0].1;
        assert_eq!(&ihdr[0..4], &4u32.to_be_bytes(), "width");
        assert_eq!(&ihdr[4..8], &3u32.to_be_bytes(), "height");
        assert_eq!(ihdr[8], 8, "bit depth");
        assert_eq!(ihdr[9], 0, "colour type 0 is greyscale");
        assert_eq!(ihdr[12], 0, "interlace 0 is none");
    }

    #[test]
    fn every_row_is_filtered_and_the_pixels_survive_in_order() {
        // Two rows of three, with values chosen so a transposition or a
        // dropped filter byte would change the answer.
        let pixels = vec![1u8, 2, 3, 200, 201, 202];
        let png = encode_gray8(3, 2, &pixels).expect("encoded");
        let raw = inflate_stored(&chunks(&png)[1].1);
        assert_eq!(raw, vec![0, 1, 2, 3, 0, 200, 201, 202]);
    }

    #[test]
    fn a_payload_larger_than_one_stored_block_comes_back_whole() {
        // 70,000 bytes needs two blocks; a decoder that only reads the first
        // would return half an image and every consumer would render a
        // half-height page without complaining.
        let w = 70_000u32;
        let pixels: Vec<u8> = (0..w).map(|i| (i % 251) as u8).collect();
        let png = encode_gray8(w, 1, &pixels).expect("encoded");
        let raw = inflate_stored(&chunks(&png)[1].1);
        let mut expect = vec![0u8];
        expect.extend_from_slice(&pixels);
        assert_eq!(raw, expect);
    }

    #[test]
    fn a_pixel_count_that_disagrees_with_the_dimensions_is_refused() {
        assert!(encode_gray8(4, 4, &[0u8; 15]).is_none(), "one byte short");
        assert!(encode_gray8(4, 4, &[0u8; 17]).is_none(), "one byte long");
        assert!(encode_gray8(0, 4, &[]).is_none(), "zero width");
        assert!(encode_gray8(4, 0, &[]).is_none(), "zero height");
    }

    #[test]
    fn the_adler_of_the_empty_input_is_its_defined_starting_value() {
        assert_eq!(adler32(b""), 1, "RFC 1950: A(0) = 1, B(0) = 0");
    }
}
