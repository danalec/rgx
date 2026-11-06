// SPDX-License-Identifier: Apache-2.0

//! SHA-256 (FIPS 180-4).
//!
//! Independent reimplementation of the FIPS 180-4 SHA-256 hash: the §4.1.2
//! boolean and rotation functions, the §4.2.2 initial hash value H(0), the
//! §4.2.3 round constants K, the §5.1 padding rule, and the §5.2 /
//! §6.2 message schedule and block compression. Trimmed to what rgx
//! needs — an incremental hasher and a 32-byte digest — because nothing
//! in this tree shares the multi-digest trait surface the larger digest
//! libraries carry.
//!
//! The one thing not optional here is the *uncompressed* direction: the
//! xz Check this exists for is the only integrity check in the format
//! that is computed over the plaintext, so a SHA-256 computed over the
//! bytes on disk would validate the wrong thing and pass on any file a
//! third party had tampered with.
//!
//! # Contract
//!
//! [`Sha256`] absorbs bytes in any split and produces the same digest
//! (§5.2 "the message is padded and parsed"), so `update` may be called
//! any number of times. `finalize` implements §5.1 exactly: append the
//! bit `1`, then `0` bits until 56 bytes remain in the final block, then
//! the message length in bits as a 64-bit big-endian integer. A message
//! whose last block has no room for the length runs through a second
//! padded block; the tests pin both branches.

/// K[t] is the first 32 bits of the fractional parts of the cube roots
/// of the first 64 primes (FIPS 180-4 §4.2.3).
pub(crate) const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// H(0): the first 32 bits of the fractional parts of the square roots
/// of the first 8 primes (FIPS 180-4 §4.2.2).
pub(crate) const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z) — §4.1.2.
#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z) — §4.1.2.
#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Σ0(x) — §4.1.2.
#[inline]
fn sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// Σ1(x) — §4.1.2.
#[inline]
fn sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// σ0(x) — §4.1.2.
#[inline]
fn gamma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// σ1(x) — §4.1.2.
#[inline]
fn gamma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Incremental SHA-256 hasher.
#[derive(Clone, Debug)]
pub struct Sha256 {
    h: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            h: H0,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Hash `data` in one call.
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;
        self.total_len += data.len() as u64;

        if self.buffer_len > 0 {
            let space = 64 - self.buffer_len;
            if data.len() < space {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
            self.buffer[self.buffer_len..].copy_from_slice(&data[..space]);
            let block = self.buffer;
            self.process_block(&block);
            self.buffer_len = 0;
            data = &data[space..];
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.process_block(&block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// §5.1 padding: append `1`, then `0` bits until 56 bytes remain in
    /// the block, then the message length in bits as a 64-bit big-endian
    /// integer.
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.process_block(&block);
            self.buffer = [0u8; 64];
        } else {
            self.buffer[self.buffer_len..].fill(0);
        }

        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());

        let block = self.buffer;
        self.process_block(&block);

        let mut output = [0u8; 32];
        for i in 0..8 {
            output[i * 4..i * 4 + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        output
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        // `sha256_hw::compress_block` owns the dispatch: it reaches the
        // SHA-NI kernel when the running CPU has the extension and falls
        // back to `process_block_scalar` when it does not. The
        // `hardware_available()` check is not repeated here -- it used to
        // be, which meant two cached atomic loads per 64-byte block to
        // arrive at the same answer twice.
        #[cfg(feature = "sha256-hw")]
        crate::sha256_hw::compress_block(&mut self.h, block);

        #[cfg(not(feature = "sha256-hw"))]
        process_block_scalar(&mut self.h, block);
    }
}

/// Scalar SHA-256 block compression (FIPS 180-4 §6.2). Kept as a free
/// function so the hardware dispatch in `Sha256::process_block` falls
/// through to it on any CPU that lacks the matching ISA extension, and
/// so the `sha256_hw` module can re-use it as the backend stub when the
/// hardware backends are not yet active on stable Rust.
pub(crate) fn process_block_scalar(h: &mut [u32; 8], block: &[u8; 64]) {
    // W[0..16] is the block as 16 big-endian words; W[16..64] is the
    // schedule expansion σ0/σ1 of §6.2.
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        w[i] = gamma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(gamma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
    let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);

    for i in 0..64 {
        let t1 = hh
            .wrapping_add(sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = sigma0(a).wrapping_add(maj(a, b, c));

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // FIPS 180-4 examples, plus the 56-byte and one-million-'a' cases
    // that pin the two padding branches.
    #[test]
    fn matches_the_fips_examples() {
        assert_eq!(
            hex(&Sha256::hash(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&Sha256::hash(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&Sha256::hash(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&Sha256::hash(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// The §5.1 padding boundary: a 55-byte message still fits its
    /// length in the block, 56 does not and takes a second padded
    /// block. The digests are from an external SHA-256 (python hashlib)
    /// and pin both branches and the two block sizes around them.
    #[test]
    fn padding_length_fits_or_spills_exactly_at_56_bytes() {
        let cases: &[(usize, &str)] = &[
            (
                55,
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            ),
            (
                56,
                "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
            ),
            (
                57,
                "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6",
            ),
            (
                63,
                "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
            ),
            (
                64,
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            ),
            (
                65,
                "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
            ),
        ];
        for (n, expected) in cases {
            assert_eq!(&hex(&Sha256::hash(&vec![b'a'; *n])), expected, "len {n}");
        }
    }

    /// Feeding the same bytes in every possible split must give the same
    /// digest: the block buffering is the only thing that could get this
    /// wrong, and a bug there would still pass the fixed-size tests.
    #[test]
    fn splitting_the_input_does_not_change_the_digest() {
        let data: Vec<u8> = (0..200u32).map(|i| (i * 7 % 251) as u8).collect();
        let once = Sha256::hash(&data);

        for split in 0..=data.len() {
            let mut h = Sha256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), once, "split at {split}");
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: Vec<(&'static str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("abc", b"abc".to_vec()),
            ("block", vec![0u8; 64]),
            ("spill", vec![0xff; 56]),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 100, "sha256", |data| {
            let _ = Sha256::hash(data);
        });
    }
}
