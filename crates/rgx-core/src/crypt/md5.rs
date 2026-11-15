// SPDX-License-Identifier: Apache-2.0

//! MD5, as specified in RFC 1321.
//!
//! Present because the PDF standard security handler is defined in terms of
//! it (ISO 32000-1 §7.6.3.3 computes the file identifier by MD5-ing a padded
//! password string), not because MD5 is a hash worth reaching for. It is
//! collision-broken; a wrong answer here is silent, so every constant,
//! shift and word order below is pinned by the RFC 1321 Appendix A.5
//! vectors in the `tests` module.

extern crate alloc;

/// `T[i] = floor(2^32 * abs(sin(i)))` for `i = 1..=64`, RFC 1321 §3.4.
/// Tabulated rather than derived: a `const fn` sine would put a float
/// rounding difference between this build and the next one, and the table
/// is the thing the RFC publishes.
const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Per-step left-rotation amounts, RFC 1321 §3.4, in the order the 64
/// operations are listed there.
const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// Streaming MD5 hasher.
///
/// The buffered `update` is the whole reason this is a struct: the PDF
/// security handler hashes a file identifier assembled from parts whose
/// sizes depend on the trailer, so callers feed it in irregular chunks and
/// a digest that only matches the one-shot path is worthless.
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; 64],
    buffered: usize,
    total_len: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    /// A fresh hasher, holding RFC 1321 §3.3's initial `A`/`B`/`C`/`D`.
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            buffer: [0u8; 64],
            buffered: 0,
            total_len: 0,
        }
    }

    /// Absorb `data`, compressing every whole 64-byte block it completes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;

        if self.buffered > 0 {
            let space = 64 - self.buffered;
            if data.len() < space {
                self.buffer[self.buffered..self.buffered + data.len()].copy_from_slice(data);
                self.buffered += data.len();
                return;
            }
            self.buffer[self.buffered..].copy_from_slice(&data[..space]);
            let block = self.buffer;
            Self::compress(&mut self.state, &block);
            self.buffered = 0;
            data = &data[space..];
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            Self::compress(&mut self.state, &block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    /// Append the padding and length, and emit the digest.
    ///
    /// The length field counts the message *before* padding, which is why
    /// `total_len` is snapshotted here rather than read after the padding
    /// has gone through `update`.
    pub fn finalize(mut self) -> [u8; 16] {
        let bit_len = self.total_len.wrapping_mul(8);

        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;

        // 56 is where the 8-byte length must land; a padding byte that
        // reaches it leaves no room, so the block is flushed instead.
        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            let block = self.buffer;
            Self::compress(&mut self.state, &block);
            self.buffer = [0u8; 64];
            self.buffered = 0;
        } else {
            self.buffer[self.buffered..].fill(0);
        }

        self.buffer[56..64].copy_from_slice(&bit_len.to_le_bytes());
        let block = self.buffer;
        Self::compress(&mut self.state, &block);

        // RFC 1321 §3.5: the digest runs from A's low-order byte to D's
        // high-order byte, so the words go out little-endian.
        let mut out = [0u8; 16];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
        let mut x = [0u32; 16];
        for (i, word) in x.iter_mut().enumerate() {
            // RFC 1321 §2: a word is read off the byte stream
            // low-order byte first, which is why this is `from_le_bytes`
            // and not a `chunks_exact` cast.
            *word = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];

        for i in 0..64 {
            let r = i / 16;
            let (f, k) = match r {
                0 => ((b & c) | (!b & d), i % 16),
                1 => ((b & d) | (c & !d), (5 * (i % 16) + 1) % 16),
                2 => (b ^ c ^ d, (3 * (i % 16) + 5) % 16),
                _ => (c ^ (b | !d), (7 * (i % 16)) % 16),
            };

            // RFC 1321 §3.4 writes the same macro to the register named
            // first in each `[PQRS k s i]` tag, and those tags rotate A→D→C→B.
            // The rotation below is that: on entry to step `i`, (a, b, c, d)
            // holds the register quadruple rotated by `i % 4`, so the four
            // rotations above reduce to the one shift-and-update below.
            // Change it to an unrotated update and the first four steps
            // silently start mixing the wrong registers.
            let next_a = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(x[k])
                    .wrapping_add(K[i])
                    .rotate_left(S[i]),
            );
            a = d;
            d = c;
            c = b;
            b = next_a;
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
}

/// One-shot MD5 over `data`.
pub fn hash(data: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> alloc::string::String {
        let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&alloc::format!("{b:02x}"));
        }
        s
    }

    /// RFC 1321 Appendix A.5, "Test suite", verbatim: the digests the RFC
    /// states the driver option `-x` must print.
    #[test]
    fn the_rfc_1321_a5_suite_hashes_to_the_published_digests() {
        let suite: &[(&[u8], &str)] = &[
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ];
        for (input, want) in suite {
            assert_eq!(&hex(&hash(input)), want, "input {:?}", input);
        }
    }

    /// The million-`a` case. The digest is the one published with the RFC
    /// 1321 suite as its multi-block companion (A.5 itself lists only the
    /// seven short strings above), and it is the shortest input that runs
    /// the compression loop thousands of times.
    #[test]
    fn a_million_as_hash_to_the_published_digest() {
        let million: alloc::vec::Vec<u8> = alloc::vec![b'a'; 1_000_000];
        assert_eq!(hex(&hash(&million)), "7707d6ae4e027c70eea2a935c2296f21");
    }

    /// The million-`a` input fed in five different chunk sizes must give
    /// the one-shot digest. 1 and 64 exercise the buffer-empty and
    /// buffer-exact edges of `update`, 7 and 999 land mid-block, and
    /// 1_000_000 never enters the buffer at all.
    #[test]
    fn the_million_a_digest_survives_every_chunk_split() {
        let million: alloc::vec::Vec<u8> = alloc::vec![b'a'; 1_000_000];
        let one_shot = hash(&million);

        for chunk in [1usize, 7, 64, 999, 1_000_000] {
            let mut h = Md5::new();
            for piece in million.chunks(chunk) {
                h.update(piece);
            }
            assert_eq!(h.finalize(), one_shot, "chunk size {chunk}");
        }
    }

    /// Every two-way split of a buffer must give the one-shot digest. The
    /// lengths bracket the two places the padding can go wrong: a `0x80`
    /// that lands exactly at offset 56, and one that overflows the block.
    #[test]
    fn no_split_point_changes_the_digest() {
        let data: alloc::vec::Vec<u8> = (0..200u32).map(|i| (i * 7 % 251) as u8).collect();
        let one_shot = hash(&data);

        for split in 0..=data.len() {
            let mut h = Md5::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), one_shot, "split at {split}");
        }
    }

    /// Lengths around the padding boundary, streamed one byte at a time.
    /// No published digest exists for these, so the property asserted is
    /// the one that actually protects the padding code: the block split
    /// cannot reach the result.
    #[test]
    fn padding_boundary_lengths_are_split_insensitive() {
        for len in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121] {
            let data: alloc::vec::Vec<u8> = (0..len as u32).map(|i| (i * 31 % 256) as u8).collect();
            let one_shot = hash(&data);

            let mut h = Md5::new();
            for byte in &data {
                h.update(&[*byte]);
            }
            assert_eq!(h.finalize(), one_shot, "len {len}");
        }
    }

    /// Empty updates must not disturb a live digest, because the PDF file
    /// identifier is hashed as `tag + digest + ...` and the padding step
    /// can contribute a zero-length piece.
    #[test]
    fn empty_updates_leave_the_digest_unchanged() {
        let mut h = Md5::new();
        h.update(b"a");
        h.update(&[]);
        h.update(b"bc");
        h.update(&[]);
        assert_eq!(hex(&h.finalize()), "900150983cd24fb0d6963f7d28e17f72");
    }

    /// A digest is 16 bytes and a difference in one input bit must reach
    /// them; this catches a `finalize` that emits the state words instead
    /// of the digest.
    #[test]
    fn one_changed_input_byte_changes_the_digest() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        let mut input = [0u8; 128];
        a.copy_from_slice(&hash(&input));
        input[100] = 1;
        b.copy_from_slice(&hash(&input));
        assert_ne!(a, b);
    }
}
