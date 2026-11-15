// SPDX-License-Identifier: Apache-2.0

//! Reference SHA-256.
//!
//! A *known-good* second implementation carried alongside `sha256` to
//! cross-check the in-tree scalar module and any hardware backend. The
//! two are written in the same style (same constants, same `K`, same
//! `H0`, same `ch`/`maj`/`sigma0`/`sigma1`/`gamma0`/`gamma1`) but in
//! different files with no shared code: when both produce identical
//! digests on the FIPS 180-4 vectors and on randomized split inputs, the
//! algorithm is correct twice and the test is what keeps it that way.
//!
//! The public surface is a single `reference_hash(&[u8]) -> [u8; 32]`.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline]
fn sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline]
fn sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline]
fn gamma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline]
fn gamma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

struct Ref {
    h: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Ref {
    fn new() -> Self {
        Self {
            h: H0,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
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
            Self::process_block(&mut self.h, &block);
            self.buffer_len = 0;
            data = &data[space..];
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            Self::process_block(&mut self.h, &block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            Self::process_block(&mut self.h, &block);
            self.buffer = [0u8; 64];
        } else {
            self.buffer[self.buffer_len..].fill(0);
        }

        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        Self::process_block(&mut self.h, &block);

        let mut output = [0u8; 32];
        for i in 0..8 {
            output[i * 4..i * 4 + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        output
    }

    fn process_block(h: &mut [u32; 8], block: &[u8; 64]) {
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

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

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
}

/// Hash `data` to a 32-byte digest using the reference implementation.
/// Verified against the FIPS 180-4 vectors and the split-input property
/// in the `tests` module below, and cross-checked against the in-tree
/// `sha256::Sha256` so a regression in either path trips a test.
pub fn reference_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Ref::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256::Sha256;

    /// The FIPS 180-4 examples plus the 1-million-'a' vector, computed
    /// with the reference path. These same vectors are the ones the
    /// in-tree `sha256` module is verified against; matching here is
    /// what makes the second copy a "known good" rather than a "second
    /// wrong with two of us".
    #[test]
    fn reference_matches_fips_examples() {
        assert_eq!(
            hex(&reference_hash(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&reference_hash(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&reference_hash(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let million = alloc::vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&reference_hash(&million)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// The in-tree `sha256::Sha256` and the reference must agree on
    /// every byte. A disagreement here means one of the two is wrong;
    /// the FIPS vectors above tell you which, but the disagreement is
    /// what tells you something is wrong at all.
    #[test]
    fn reference_matches_sha256() {
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"abc",
            b"hello, world",
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            &alloc::vec![b'x'; 65],
            &alloc::vec![b'x'; 127],
            &alloc::vec![b'x'; 128],
            &alloc::vec![b'x'; 129],
            &alloc::vec![b'a'; 1_000_000],
        ];
        for case in cases {
            let a = reference_hash(case);
            let b = Sha256::hash(case);
            assert_eq!(a, b, "mismatch on len {}", case.len());
        }
    }

    /// Splitting the same data in different ways must give the same
    /// digest. The block buffering is the only thing that could get this
    /// wrong; a bug there would still pass the fixed-size vectors.
    #[test]
    fn splitting_the_input_does_not_change_the_digest() {
        let data: alloc::vec::Vec<u8> = (0..200u32).map(|i| (i * 7 % 251) as u8).collect();
        let once = reference_hash(&data);

        for split in 0..=data.len() {
            let mut h = Ref::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), once, "split at {split}");
        }
    }

    fn hex(bytes: &[u8]) -> alloc::string::String {
        let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&alloc::format!("{b:02x}"));
        }
        s
    }
}
