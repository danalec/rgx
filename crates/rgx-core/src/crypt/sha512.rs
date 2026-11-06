// SPDX-License-Identifier: Apache-2.0

//! SHA-384 and SHA-512 (FIPS 180-4).
//!
//! One implementation of the SHA-512 machinery (§4.1.3 functions, §5.3
//! padding, §6.4 message schedule and block compression) serving both
//! published digests. SHA-384 is not SHA-512 truncated to 48 bytes: §6.6
//! gives it its own initial hash value H(0), and the truncation keeps the
//! *leftmost* 48 bytes of the resulting 64-byte state. Sharing the
//! compression function is therefore exact, not an approximation -- the
//! only differences between the two are H(0), the digest length and the
//! output length, all three of which are visible in [`Sha384::new`] and
//! [`Sha384::finalize`].
//!
//! The padded length field is 128 bits (§5.1.2) and is carried as a
//! `u128`, not as a `u64` bit count of the message. `total_len * 8` in
//! `u64` wraps at 2^61 bytes -- a message length the field can still
//! express -- and the digest would then be one of a different message.
//! No vector in the test suite reaches that size, so this is a stated
//! invariant rather than a measured one.
//!
//! # Contract
//!
//! [`Sha384`] and [`Sha512`] absorb bytes in any split and produce the
//! same digest (§5.3.1 "the message is padded and parsed"), so `update`
//! may be called any number of times, including with empty slices.
//! `finalize` implements §5.1.2 exactly: append the bit `1`, then `0`
//! bits until 112 bytes remain in the final block, then the message
//! length in bits as a 128-bit big-endian integer. A message whose last
//! block has no room for the length runs through a second padded block;
//! the tests pin both branches.

/// K[t] is the first 64 bits of the fractional parts of the cube roots
/// of the first 80 primes (FIPS 180-4 §4.2.3).
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-384 H(0): the first 64 bits of the fractional parts of the square
/// roots of the first 8 primes, generated with the same second-order
/// procedure as SHA-512 but over a different prime list (FIPS 180-4
/// §5.3.3). It is *not* H(0) for SHA-512, which is why SHA-384 cannot be
/// derived from a SHA-512 digest.
const H0_384: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

/// SHA-512 H(0): the first 64 bits of the fractional parts of the square
/// roots of the first 8 primes (FIPS 180-4 §5.3.5).
const H0_512: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// Compression block size in bytes (§4.2.1: SHA-384 and SHA-512 share
/// it). The padded tail is 1 + 16 bytes, so a message whose length mod
/// 128 falls in `112..=127` needs a second block.
const BLOCK: usize = 128;

/// Bytes of the final block reserved for the 128-bit length field.
const LEN_FIELD: usize = 16;

/// Ch(x, y, z) = (x AND y) XOR ((NOT x) AND z) — §4.1.3.
#[inline]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

/// Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z) — §4.1.3.
#[inline]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Σ0(x) — §4.1.3.
#[inline]
fn sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

/// Σ1(x) — §4.1.3.
#[inline]
fn sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

/// σ0(x) — §4.1.3.
#[inline]
fn gamma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

/// σ1(x) — §4.1.3.
#[inline]
fn gamma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// The SHA-512 state, parameterised by H(0). Sharing it between the two
/// public hashers is the whole point of this type: the compression
/// function, the block buffering and the padding are identical, so a
/// second copy of any of them could only ever be a second thing to get
/// wrong. The two differences that matter -- H(0) and the truncated
/// output -- are applied by the callers, not here.
#[derive(Clone, Debug)]
struct Core {
    h: [u64; 8],
    buffer: [u8; BLOCK],
    buffer_len: usize,
    total_len: u64,
}

impl Core {
    fn new(iv: [u64; 8]) -> Self {
        Self {
            h: iv,
            buffer: [0u8; BLOCK],
            buffer_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut data = data;
        self.total_len += data.len() as u64;

        if self.buffer_len > 0 {
            let space = BLOCK - self.buffer_len;
            if data.len() < space {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
            self.buffer[self.buffer_len..].copy_from_slice(&data[..space]);
            let block = self.buffer;
            self.compress(&block);
            self.buffer_len = 0;
            data = &data[space..];
        }

        while data.len() >= BLOCK {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(&data[..BLOCK]);
            self.compress(&block);
            data = &data[BLOCK..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// §5.1.2 padding: append `1`, then `0` bits until 112 bytes remain
    /// in the block, then the message length in bits as a 128-bit
    /// big-endian integer. The cast to `u128` is the contract: a `u64`
    /// would wrap at 2^61 bytes of input instead of reporting a length
    /// the spec can still express.
    fn finalize(mut self) -> [u8; 64] {
        let bit_len = (self.total_len as u128) * 8;

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > BLOCK - LEN_FIELD {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0u8; BLOCK];
        } else {
            self.buffer[self.buffer_len..].fill(0);
        }

        self.buffer[BLOCK - LEN_FIELD..].copy_from_slice(&bit_len.to_be_bytes());

        let block = self.buffer;
        self.compress(&block);

        let mut output = [0u8; 64];
        for i in 0..8 {
            output[i * 8..i * 8 + 8].copy_from_slice(&self.h[i].to_be_bytes());
        }
        output
    }

    fn compress(&mut self, block: &[u8; BLOCK]) {
        compress_block(&mut self.h, block);
    }
}

/// Scalar SHA-512 block compression (FIPS 180-4 §6.4.2).
fn compress_block(h: &mut [u64; 8], block: &[u8; BLOCK]) {
    // W[0..16] is the block as 16 big-endian 64-bit words; W[16..80] is
    // the schedule expansion σ0/σ1 of §6.4.2.
    let mut w = [0u64; 80];
    let (block_words, _) = block.as_chunks::<8>();
    for (word, bytes) in w.iter_mut().zip(block_words.iter()) {
        *word = u64::from_be_bytes(*bytes);
    }
    for i in 16..80 {
        w[i] = gamma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(gamma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
    let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);

    for i in 0..80 {
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

/// SHA-384. Distinct initial value and truncated to 48 bytes; it is NOT
/// SHA-512 truncated to the same length, because the IV differs.
#[derive(Clone, Debug)]
pub struct Sha384 {
    core: Core,
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha384 {
    pub fn new() -> Self {
        Self {
            core: Core::new(H0_384),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    /// The leftmost 48 bytes of the final hash value (§5.3.3), which is
    /// what distinguishes the digest from SHA-512's 64.
    pub fn finalize(self) -> [u8; 48] {
        let mut output = [0u8; 48];
        output.copy_from_slice(&self.core.finalize()[..48]);
        output
    }
}

/// SHA-512, full 64-byte digest.
#[derive(Clone, Debug)]
pub struct Sha512 {
    core: Core,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            core: Core::new(H0_512),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    pub fn finalize(self) -> [u8; 64] {
        self.core.finalize()
    }
}

/// SHA-384 of `data` in one call.
pub fn hash384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize()
}

/// SHA-512 of `data` in one call.
pub fn hash512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    //! Digests for these tests come from two independent sources, kept
    //! apart on purpose: published FIPS 180-4 / NIST vectors, which are
    //! the authority, and `openssl dgst -sha384 -sha512` (OpenSSL 3.5.9)
    //! over the same inputs, which is a second implementation that does
    //! not share a line of code with this one. Every vector below was
    //! produced by one of those two and is labelled with which.

    use super::*;

    const HEX: &[u8; 16] = b"0123456789abcdef";

    /// The one-million-'a' input of the NIST SHA-2 test-vector set, as
    /// a `static` so the 1 MiB never enters a release build and the
    /// chunk-splitting test can hand out slices of it for free.
    static MILLION_A: [u8; 1_000_000] = [b'a'; 1_000_000];

    /// A 1024-byte non-repeating input: a constant byte stream would let
    /// a schedule bug hide behind repetition, so the OpenSSL cross-check
    /// runs over a pattern that repeats only every 256 bytes.
    static MIXED: [u8; 1024] = {
        let mut buf = [0u8; 1024];
        let mut i = 0;
        while i < 1024 {
            buf[i] = ((i * 31 + 7) % 256) as u8;
            i += 1;
        }
        buf
    };

    /// Compares a digest with its published hex form without allocating:
    /// `rgx-core` is `no_std` + `alloc` and every digest here is
    /// fixed-size, so a `String` would buy nothing.
    fn assert_digest(actual: &[u8], expected: &str) {
        assert_eq!(
            actual.len() * 2,
            expected.len(),
            "digest is {} bytes, expected a {}-digit hex string",
            actual.len(),
            expected.len()
        );
        let mut hex = [0u8; 128];
        for (i, byte) in actual.iter().enumerate() {
            hex[i * 2] = HEX[usize::from(byte >> 4)];
            hex[i * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        assert_eq!(&hex[..actual.len() * 2], expected.as_bytes());
    }

    /// The FIPS 180-4 §5.3.5 / §5.3.3 "one-block" example, `abc`, and
    /// the §B.1 empty-string example.
    #[test]
    fn the_fips_180_4_one_block_examples_hash_to_their_published_digests() {
        assert_digest(
            &hash384(b""),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        );
        assert_digest(
            &hash384(b"abc"),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        );
        assert_digest(
            &hash512(b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );
        assert_digest(
            &hash512(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
    }

    /// The FIPS 180-4 §B.1 "two-block" example, 112 bytes long: the
    /// last full block of message plus one padded block holding only the
    /// `1` and the length.
    #[test]
    fn the_fips_180_4_two_block_example_hashes_to_its_published_digests() {
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assert_eq!(msg.len(), 112);
        assert_digest(
            &hash384(msg),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        );
        assert_digest(
            &hash512(msg),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        );
    }

    /// The NIST SHA-2 one-million-`a` vector. It is on its own because
    /// it is the only case here that runs the block loop thousands of
    /// times and pushes the length field through its high bytes.
    #[test]
    fn the_one_million_a_nist_vector_hashes_to_its_published_digests() {
        assert_digest(
            &hash384(&MILLION_A),
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
        );
        assert_digest(
            &hash512(&MILLION_A),
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        );
    }

    /// The streaming contract: feeding the same message in pieces of a
    /// fixed size must give the one-shot digest. The sizes bracket the
    /// ways a caller can split it -- below the block, exactly the block,
    /// and awkwardly inside it -- because a buffering defect that only
    /// shows on a split input is invisible to every fixed-vector test
    /// above.
    #[test]
    fn every_documented_chunk_split_of_the_one_million_a_input_agrees() {
        for chunk in [1usize, 7, 64, 127, 128, 999, 1_000_000] {
            let mut h384 = Sha384::new();
            let mut h512 = Sha512::new();
            for piece in MILLION_A.chunks(chunk) {
                h384.update(piece);
                h512.update(piece);
            }
            assert_eq!(
                h384.finalize(),
                hash384(&MILLION_A),
                "sha-384 in {chunk}-byte chunks"
            );
            assert_eq!(
                h512.finalize(),
                hash512(&MILLION_A),
                "sha-512 in {chunk}-byte chunks"
            );
        }
    }

    /// Every possible single split of a multi-block message, for both
    /// digests: `update` may be called with two pieces at any offset and
    /// must not care where the block boundary falls.
    #[test]
    fn splitting_the_input_at_any_offset_does_not_change_the_digest() {
        let mut data = [0u8; 300];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i * 31 + 7) as u8;
        }
        let once384 = hash384(&data);
        let once512 = hash512(&data);

        for split in 0..=data.len() {
            let mut h384 = Sha384::new();
            let mut h512 = Sha512::new();
            h384.update(&data[..split]);
            h384.update(&data[split..]);
            h512.update(&data[..split]);
            h512.update(&data[split..]);
            assert_eq!(h384.finalize(), once384, "split at {split}");
            assert_eq!(h512.finalize(), once512, "split at {split}");
        }
    }

    /// An empty `update` between two real ones must change nothing; a
    /// caller that filters its input can hand over a zero-length piece.
    #[test]
    fn an_empty_update_is_a_no_op() {
        let mut h = Sha512::new();
        h.update(b"");
        h.update(b"a");
        h.update(&[]);
        h.update(b"bc");
        h.update(&[]);
        assert_eq!(h.finalize(), hash512(b"abc"));
    }

    /// The §5.1.2 padding boundary: 111 bytes still fit their length in
    /// the block, 112 do not and take a second padded block, and the
    /// same pair of branches repeats at the 240-byte (two-block) mark.
    /// The spec publishes no vectors at these lengths, so they are the
    /// OpenSSL 3.5.9 `dgst -sha384` / `dgst -sha512` digests of that
    /// many `a` bytes -- an oracle this crate shares no code with.
    #[test]
    fn padding_fits_or_spills_at_the_block_boundaries() {
        let cases: &[(usize, &str, &str)] = &[
            (
                111,
                "3c37955051cb5c3026f94d551d5b5e2ac38d572ae4e07172085fed81f8466b8f90dc23a8ffcdea0b8d8e58e8fdacc80a",
                "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2",
            ),
            (
                112,
                "187d4e07cb306103c69967bf544d0dfbe9042577599c73c330abc0cb64c61236d5ed565ee19119d8c31779a38f791fcd",
                "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca",
            ),
            (
                113,
                "1d6bed01626682961b50da078a6b1da707c1da0c8a0a3226f159235bd45ed724a0622fa6f39fd70007a6c72a5cda43ae",
                "55ddd8ac210a6e18ba1ee055af84c966e0dbff091c43580ae1be703bdb85da31acf6948cf5bd90c55a20e5450f22fb89bd8d0085e39f85a86cc46abbca75e24d",
            ),
            (
                127,
                "9bd06b1763c2cf7aef40e795dc65bc96d59c41b537f3ad72ebdefd485476b5717c1aeb37c327fe9c1831b12b9efd08ae",
                "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502",
            ),
            (
                128,
                "edb12730a366098b3b2beac75a3bef1b0969b15c48e2163c23d96994f8d1bef760c7e27f3c464d3829f56c0d53808b0b",
                "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321",
            ),
            (
                129,
                "39b6f5a7b0e781dbc419f72e49b30eaac10f2c98c4403bc610da31067fd1b48f324138c8615d2b496d08d73d5e865326",
                "4f681e0bd53cda4b5a2041cc8a06f2eabde44fb16c951fbd5b87702f07aeab611565b19c47fde30587177ebb852e3971bbd8d3fd30da18d71037dfbd98420429",
            ),
            (
                239,
                "e247c35f4bc1aa38026f8880c8c97305545d00d3f859e00c57d1c1f0a176b3c6b749c4eb081f08bd0fba500969cd056a",
                "52c853cb8d907f3d4d6b889beb027985d7c273486d75f8baf26f80d24e90c74c6c3de3e22131582380a7d14d43f2941a31385439cd6ddc469f628015e50bf286",
            ),
            (
                240,
                "4d86957beab348a29180f02d02564ac1d32f5b4c217ece2b038f7c184f0cafc8c8e438eb82aa03796170e0a7ce8c0675",
                "4c296d90c61052a62ffb1dd196f1b7b09373b1f93e71836baebf89690546b7595684dbe9467a8e484fa0d1094272b4344a7c24f5fee8daedeb0bf549c985ab5f",
            ),
        ];
        for (n, expected384, expected512) in cases {
            let mut buf = [b'a'; 240];
            let msg = &mut buf[..*n];
            assert_digest(&hash384(msg), expected384);
            assert_digest(&hash512(msg), expected512);

            // The same bytes, streamed one at a time: the published
            // digest above only covers the one-shot path.
            let mut h384 = Sha384::new();
            let mut h512 = Sha512::new();
            for byte in msg.iter() {
                h384.update(core::slice::from_ref(byte));
                h512.update(core::slice::from_ref(byte));
            }
            assert_digest(&h384.finalize(), expected384);
            assert_digest(&h512.finalize(), expected512);
        }
    }

    /// The independent-oracle check proper: a 1024-byte non-repeating
    /// input hashed through the streaming API, against the
    /// OpenSSL 3.5.9 `dgst -sha384` / `dgst -sha512` digests of that
    /// same file (`buf[i] = (i * 31 + 7) % 256`, 1024 bytes).
    #[test]
    fn openssl_agrees_with_both_hashers_on_a_fixed_non_repeating_input() {
        assert_digest(
            &hash384(&MIXED),
            "842464fc1cdb79019d67aaf4a9dad824f2f44b3ea496a89155867a1f4eb5f4c8861cfa4266b72696a5f9e63bf74b9feb",
        );
        assert_digest(
            &hash512(&MIXED),
            "076291378444ac54f7e7ac5717c498f169218b3ba608d08a3fa63e56063c4a9e0e26ea6fc82654b79aadb9e70ae90d5401de36a0df9b4b2dd046b7bad4e4da32",
        );

        let mut h512 = Sha512::new();
        for piece in MIXED.chunks(37) {
            h512.update(piece);
        }
        assert_eq!(h512.finalize(), hash512(&MIXED));
    }

    /// Every prefix length around the block and length-field boundaries
    /// must be total: no panic, and the streaming path must agree with
    /// the one-shot path for each.
    #[test]
    fn every_length_up_to_two_blocks_plus_one_hashes_without_panicking() {
        let mut buf = [0u8; 300];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i * 17 + 3) as u8;
        }
        for n in 0..=buf.len() {
            let msg = &buf[..n];
            assert_eq!(hash384(msg).len(), 48);
            assert_eq!(hash512(msg).len(), 64);

            let mut h = Sha512::new();
            for byte in msg {
                h.update(core::slice::from_ref(byte));
            }
            assert_eq!(h.finalize(), hash512(msg), "byte-at-a-time len {n}");
        }
    }
}
