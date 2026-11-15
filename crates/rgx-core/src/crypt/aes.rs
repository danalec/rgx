// SPDX-License-Identifier: Apache-2.0

//! AES-128/256 with the CBC modes the PDF standard security handler needs.
//!
//! This file is self-contained on purpose: it references no sibling module and
//! no `crate::` path, so `rustc --edition 2021 --test --crate-type lib` compiles
//! and runs it standalone. That is the only way the FIPS 197 and SP 800-38A
//! vectors below can be checked without registering it in the crate first.
//!
//! `AesError` implements `core::error::Error + Send + Sync + 'static`, so the
//! blanket `From<E> for rgx_core::Error` (gated on the crate's `std` feature)
//! lifts it: a `?` on any of these functions works from a `rgx_core::Result`
//! without a manual `map_err`.
//!
//! ## Correctness oracle
//!
//! An AES that is subtly wrong does not fail loudly here — it produces
//! plausible PDF text that decrypts to nothing useful. So nothing in this file
//! is validated against itself: the block tests are the FIPS 197 Appendix B
//! and C vectors, the CBC tests are the NIST SP 800-38A Appendix F vectors
//! including their IVs, and the padded tests are streams reproduced from
//! OpenSSL 3.5.9 `enc`. Round-trip tests exist too, but they are the weakest
//! evidence here and are labelled as such.
//!
//! ## What this is not
//!
//! The implementation is byte-at-a-time and **not constant-time**: `MixColumns`
//! and the key schedule both branch and table-lookup on secret-dependent
//! values. That is acceptable for the PDF standard security handler, where the
//! key sits in the same file as the ciphertext and the threat is a wrong
//! key producing wrong plaintext, not a local timing attack. Anything that
//! needs a side-channel-resistant AES should not reuse this file.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Cipher block size in bytes. Every length rule below is expressed against
/// it, so a mode change that altered the block size cannot pass the tests
/// while still dividing what the callers hand in.
const BLOCK: usize = 16;

/// Longest key schedule: AES-256 runs 14 rounds, so 15 round keys of 16 bytes.
const MAX_ROUND_KEYS: usize = 15 * BLOCK;

// -- GF(2^8) and the tables derived from it ---------------------------------
//
// The S-box is computed rather than transcribed. A single mistyped byte in a
// copied 256-entry table would not panic and would not fail the round-trip
// tests; it would fail *here*, loudly, against FIPS 197.

/// Multiply in GF(2^8) modulo the AES polynomial `x^8 + x^4 + x^3 + x + 1`.
const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
        i += 1;
    }
    p
}

/// Multiplicative inverse in GF(2^8); zero maps to zero, as the specification
/// requires (FIPS 197 §5.1.1, the inversion is undefined on 0 and S[0] is
/// fixed by the affine transform alone).
const fn ginv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut i = 1u16;
    while i < 256 {
        if gmul(a, i as u8) == 1 {
            return i as u8;
        }
        i += 1;
    }
    // Unreachable for a field: every nonzero element has exactly one inverse.
    // Returning 0 would silently corrupt the table, so the constant is only
    // ever reached if `gmul` above stops being a field multiplication.
    0
}

/// The FIPS 197 §5.1.1 affine transform over the inversion.
const fn affine(b: u8) -> u8 {
    b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63
}

const fn build_sbox() -> [u8; 256] {
    let mut s = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        s[i] = affine(ginv(i as u8));
        i += 1;
    }
    s
}

/// The inverse table is searched out of the forward one rather than computed
/// with a hand-written affine inverse, so the two cannot drift apart.
const fn build_inv_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        let mut y = 0usize;
        while y < 256 {
            if SBOX[x] == y as u8 {
                inv[y] = x as u8;
            }
            y += 1;
        }
        x += 1;
    }
    inv
}

/// `RCON[j] = x^(j-1)` in GF(2^8) (FIPS 197 §5.2), derived by repeated
/// doubling so the `0x1b` reduction lives in exactly one place. `RCON[0]` is
/// unused — the key schedule only ever indexes `1..=10` — and doubling from it
/// would make the whole table zero and every round key wrong from round 1 on,
/// with no failure a round-trip test could see.
const fn build_rcon() -> [u8; 11] {
    let mut r = [0u8; 11];
    r[1] = 1;
    let mut i = 2usize;
    while i < 11 {
        let prev = r[i - 1];
        r[i] = if prev & 0x80 != 0 {
            (prev << 1) ^ 0x1b
        } else {
            prev << 1
        };
        i += 1;
    }
    r
}

const SBOX: [u8; 256] = build_sbox();
const INV_SBOX: [u8; 256] = build_inv_sbox();
const RCON: [u8; 11] = build_rcon();

// -- errors -----------------------------------------------------------------

/// Why an AES entry point refused its input.
///
/// Each variant is a *refusal*, never a truncation: a caller that gets an
/// `Err` knows nothing was returned rather than something shortened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesError {
    /// The key was neither 16 nor 32 bytes.
    KeyLength(usize),
    /// The ciphertext body (after the IV) was empty or not a whole number of
    /// blocks.
    CiphertextLength(usize),
    /// PKCS#7 padding did not describe a whole run of equal bytes whose length
    /// is in `1..=16`.
    Padding,
}

impl fmt::Display for AesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AesError::KeyLength(n) => {
                write!(f, "aes: key must be 16 or 32 bytes, got {n}")
            }
            AesError::CiphertextLength(n) => write!(
                f,
                "aes: ciphertext must be a positive multiple of {BLOCK} bytes, got {n}"
            ),
            AesError::Padding => write!(
                f,
                "aes: pkcs#7 padding run is 0, longer than {BLOCK}, or not uniform"
            ),
        }
    }
}

impl core::error::Error for AesError {}

/// The crate's own error type carries the crate's message chain; a local
/// alias keeps this file compilable without `crate::`.
pub type Result<T> = core::result::Result<T, AesError>;

/// Dispatch a slice key onto the two supported sizes.
///
/// The length check lives here and nowhere else: `new`/`new256` take fixed
/// arrays so they cannot be handed a wrong length, and every free function
/// routes through this.
fn key_schedule(key: &[u8]) -> Result<([u8; MAX_ROUND_KEYS], usize)> {
    let words = match key.len() {
        16 => 4,
        32 => 8,
        other => return Err(AesError::KeyLength(other)),
    };
    let rounds = words + 6;
    let mut rk = [0u8; MAX_ROUND_KEYS];
    rk[..key.len()].copy_from_slice(key);
    let total_words = 4 * (rounds + 1);
    for i in words..total_words {
        let prev = 4 * (i - 1);
        let mut t = [rk[prev], rk[prev + 1], rk[prev + 2], rk[prev + 3]];
        if i % words == 0 {
            // RotWord then SubWord then the round constant.
            t = [t[1], t[2], t[3], t[0]];
            t = sub_word(t);
            t[0] ^= RCON[i / words];
        } else if words > 6 && i % words == 4 {
            // AES-256 alone has this extra SubWord; dropping it changes every
            // round key from 8 onward and only the FIPS 197 C vector catches it.
            t = sub_word(t);
        }
        let base = 4 * (i - words);
        for (j, byte) in t.into_iter().enumerate() {
            rk[4 * i + j] = rk[base + j] ^ byte;
        }
    }
    Ok((rk, rounds))
}

fn sub_word(w: [u8; 4]) -> [u8; 4] {
    [
        SBOX[w[0] as usize],
        SBOX[w[1] as usize],
        SBOX[w[2] as usize],
        SBOX[w[3] as usize],
    ]
}

// -- the cipher -------------------------------------------------------------

/// Key material expanded into the round-key schedule. AES-128 has 10 rounds,
/// AES-192 has 12, AES-256 has 14; only 128 and 256 are accepted here.
pub struct Aes {
    round_keys: [u8; MAX_ROUND_KEYS],
    rounds: usize,
}

impl Aes {
    /// AES-128: `Nk = 4`, `Nr = 10`.
    pub fn new(key: &[u8; 16]) -> Self {
        let (round_keys, rounds) = key_schedule(key).expect("a 16-byte key is a valid AES-128 key");
        Self { round_keys, rounds }
    }

    /// AES-256: `Nk = 8`, `Nr = 14`.
    pub fn new256(key: &[u8; 32]) -> Self {
        let (round_keys, rounds) = key_schedule(key).expect("a 32-byte key is a valid AES-256 key");
        Self { round_keys, rounds }
    }

    /// Encrypt one block in place (FIPS 197 §5.1). The final round omits
    /// `MixColumns`, so the loop below runs `rounds - 1` full rounds and one
    /// half round — collapsing them would break every vector.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        add_round_key(block, &self.round_keys[..BLOCK]);
        for round in 1..self.rounds {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, self.round_key(round));
        }
        sub_bytes(block);
        shift_rows(block);
        add_round_key(block, self.round_key(self.rounds));
    }

    /// Decrypt one block in place (FIPS 197 §5.3, the equivalent inverse
    /// cipher — the plain `InvCipher` is mathematically identical but needs
    /// the inverse key schedule, which this does not build).
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        let last = self.rounds;
        add_round_key(block, self.round_key(last));
        for round in (1..last).rev() {
            inv_shift_rows(block);
            inv_sub_bytes(block);
            add_round_key(block, self.round_key(round));
            inv_mix_columns(block);
        }
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, &self.round_keys[..BLOCK]);
    }

    fn round_key(&self, round: usize) -> &[u8] {
        &self.round_keys[round * BLOCK..round * BLOCK + BLOCK]
    }
}

/// Implemented rather than derived: `rgx`'s failure notes are printed, and a
/// derived `Debug` would print the round-key schedule of a PDF's encryption
/// key into whatever log the caller attached it to.
impl fmt::Debug for Aes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Nk = Nr - 6` (FIPS 197 §5.3), so the key size follows from the
        // round count. Reporting `rounds * 4` would claim a 40-bit key.
        write!(
            f,
            "Aes {{ key_bits: {}, rounds: {} }}",
            (self.rounds - 6) * 32,
            self.rounds
        )
    }
}

fn add_round_key(block: &mut [u8; 16], key: &[u8]) {
    for (b, k) in block.iter_mut().zip(key) {
        *b ^= *k;
    }
}

fn sub_bytes(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn inv_sub_bytes(block: &mut [u8; 16]) {
    for b in block.iter_mut() {
        *b = INV_SBOX[*b as usize];
    }
}

/// The state is column-major: index `i` is row `i % 4`, column `i / 4`.
/// Row `r` rotates left by `r`.
fn shift_rows(block: &mut [u8; 16]) {
    let src = *block;
    for row in 1..4 {
        for col in 0..4 {
            block[row + 4 * col] = src[row + 4 * ((col + row) % 4)];
        }
    }
}

fn inv_shift_rows(block: &mut [u8; 16]) {
    let src = *block;
    for row in 1..4 {
        for col in 0..4 {
            block[row + 4 * col] = src[row + 4 * ((col + 4 - row) % 4)];
        }
    }
}

/// Multiplication by 2, i.e. `x * {02}`.
fn xtime(a: u8) -> u8 {
    if a & 0x80 != 0 {
        (a << 1) ^ 0x1b
    } else {
        a << 1
    }
}

/// Multiplication by 3, i.e. `x * {03}`; the identity column of the
/// `MixColumns` matrix.
fn mul3(a: u8) -> u8 {
    xtime(a) ^ a
}

fn mix_columns(block: &mut [u8; 16]) {
    let src = *block;
    for col in 0..4 {
        let (a0, a1, a2, a3) = (
            src[4 * col],
            src[4 * col + 1],
            src[4 * col + 2],
            src[4 * col + 3],
        );
        block[4 * col] = xtime(a0) ^ mul3(a1) ^ a2 ^ a3;
        block[4 * col + 1] = a0 ^ xtime(a1) ^ mul3(a2) ^ a3;
        block[4 * col + 2] = a0 ^ a1 ^ xtime(a2) ^ mul3(a3);
        block[4 * col + 3] = mul3(a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

fn inv_mix_columns(block: &mut [u8; 16]) {
    let src = *block;
    for col in 0..4 {
        let (a0, a1, a2, a3) = (
            src[4 * col],
            src[4 * col + 1],
            src[4 * col + 2],
            src[4 * col + 3],
        );
        block[4 * col] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        block[4 * col + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        block[4 * col + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
        block[4 * col + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
    }
}

// -- CBC --------------------------------------------------------------------

/// Build the cipher for a slice key, or refuse.
fn cipher(key: &[u8]) -> Result<Aes> {
    match key.len() {
        16 => Ok(Aes::new(
            key.try_into().map_err(|_| AesError::KeyLength(key.len()))?,
        )),
        32 => Ok(Aes::new256(
            key.try_into().map_err(|_| AesError::KeyLength(key.len()))?,
        )),
        other => Err(AesError::KeyLength(other)),
    }
}

/// CBC with PKCS#7 padding. Returns the IV followed by the ciphertext, which
/// is the on-the-wire convention the PDF spec uses: the IV is not stored
/// anywhere else, it is simply the first block of the stream.
///
/// An empty `pt` is legal and yields exactly one block, the full padding
/// block; PKCS#7 never emits an empty result, so `cbc_decrypt_padded` can tell
/// that case apart from an empty stream without a side channel.
pub fn cbc_encrypt_padded(key: &[u8], iv: &[u8; 16], pt: &[u8]) -> Result<Vec<u8>> {
    let aes = cipher(key)?;
    let pad = BLOCK - (pt.len() % BLOCK);
    let mut out = Vec::with_capacity(BLOCK + pt.len() + pad);
    out.extend_from_slice(iv);
    out.extend_from_slice(pt);
    out.resize(out.len() + pad, pad as u8);
    cbc_encrypt_blocks(&aes, iv, &mut out[BLOCK..])?;
    Ok(out)
}

/// CBC without padding. The PDF R6 key derivation encrypts 64-byte inputs
/// with AES-256-CBC-NoPad, and the `encrypt_metadata` distinction in the spec
/// is a padding question, so both variants have to exist.
///
/// `pt` must already be a positive whole number of blocks: an unpadded
/// plaintext that is not a multiple of the block size has no ciphertext that
/// could decrypt back to it, and rounding it up here would invent bytes the
/// caller never supplied.
pub fn cbc_encrypt_nopad(key: &[u8], iv: &[u8; 16], pt: &[u8]) -> Result<Vec<u8>> {
    let aes = cipher(key)?;
    check_block_multiple(pt.len())?;
    let mut out = Vec::with_capacity(BLOCK + pt.len());
    out.extend_from_slice(iv);
    out.extend_from_slice(pt);
    cbc_encrypt_blocks(&aes, iv, &mut out[BLOCK..])?;
    Ok(out)
}

/// CBC decrypt where the first 16 bytes of `data` are the IV.
pub fn cbc_decrypt_padded(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut out = cbc_decrypt_body(key, data)?;
    unpad(&mut out)?;
    Ok(out)
}

/// CBC decrypt, no padding check. An input whose length is not a multiple of
/// the block size is an error here rather than a truncated tail.
pub fn cbc_decrypt_nopad(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    cbc_decrypt_body(key, data)
}

fn check_block_multiple(len: usize) -> Result<()> {
    if len == 0 || !len.is_multiple_of(BLOCK) {
        return Err(AesError::CiphertextLength(len));
    }
    Ok(())
}

/// Strip the IV and decrypt the body. Shared by both decrypt entry points so
/// the length rule cannot be stated once strictly and once loosely.
fn cbc_decrypt_body(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let aes = cipher(key)?;
    if data.len() < BLOCK * 2 {
        return Err(AesError::CiphertextLength(data.len().saturating_sub(BLOCK)));
    }
    let (iv, body) = data.split_at(BLOCK);
    check_block_multiple(body.len())?;
    let mut out = body.to_vec();
    let mut prev = [0u8; BLOCK];
    prev.copy_from_slice(iv);
    for chunk in out.as_chunks_mut::<BLOCK>().0 {
        let cipher_block = *chunk;
        let mut plain = cipher_block;
        aes.decrypt_block(&mut plain);
        // The XOR lands in the *decrypted* block; `prev` is replaced by this
        // block's ciphertext afterwards, never by the chained plaintext. XORing
        // the ciphertext in instead would silently return `ciphertext ^ prev`,
        // which round-trips against nothing.
        for (d, p) in plain.iter_mut().zip(prev.iter()) {
            *d ^= *p;
        }
        *chunk = plain;
        prev = cipher_block;
    }
    Ok(out)
}

/// CBC the whole `body` in place, chaining through `iv`.
fn cbc_encrypt_blocks(aes: &Aes, iv: &[u8; BLOCK], body: &mut [u8]) -> Result<()> {
    check_block_multiple(body.len())?;
    let mut prev = *iv;
    for chunk in body.as_chunks_mut::<BLOCK>().0 {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        let mut block = *chunk;
        aes.encrypt_block(&mut block);
        *chunk = block;
        prev = block;
    }
    Ok(())
}

/// Validate and strip a PKCS#7 run.
///
/// The whole run is checked, not just the last byte. A wrong key decrypts to
/// a final block that is wrong with high probability, and "looks like valid
/// padding" is precisely the case that turns a wrong key into plausible PDF
/// text, so the comparison covers every byte the run claims to occupy.
fn unpad(buf: &mut Vec<u8>) -> Result<()> {
    let Some(last) = buf.last().copied() else {
        return Err(AesError::Padding);
    };
    let run = last as usize;
    if run == 0 || run > BLOCK {
        return Err(AesError::Padding);
    }
    let start = buf.len() - run;
    if !buf[start..].iter().all(|b| *b == last) {
        return Err(AesError::Padding);
    }
    buf.truncate(start);
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The published vectors that say this file is AES, plus the padding and
    //! length rules the PDF security handler depends on. Round-trip tests are
    //! present but are the weakest evidence here — they pass for a cipher that
    //! is wrong in both directions.

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i + 1 < bytes.len() {
            out.push(nibble(bytes[i]) << 4 | nibble(bytes[i + 1]));
            i += 2;
        }
        out
    }

    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            other => panic!("not a hex digit: {:?}", other as char),
        }
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        let v = hex(s);
        assert_eq!(v.len(), N, "hex literal is not {N} bytes");
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        out
    }

    /// Re-encrypt the last ciphertext block from an edited plaintext block, so
    /// a test can name the padding it wants to attack instead of hunting for
    /// a bit flip that produces it.
    fn edit_final_plaintext(aes: &Aes, stream: &mut [u8], edit: impl FnOnce(&mut [u8; BLOCK])) {
        let n = stream.len();
        let mut block = [0u8; BLOCK];
        block.copy_from_slice(&stream[n - BLOCK..]);
        aes.decrypt_block(&mut block);
        edit(&mut block);
        aes.encrypt_block(&mut block);
        stream[n - BLOCK..].copy_from_slice(&block);
    }

    mod fips_197_block_vectors {
        //! Single-block vectors from **FIPS 197, Appendix B (AES-128)** and
        //! **Appendix C (AES-256)**. These are the anchors: if the key
        //! schedule, the S-box, `ShiftRows` or `MixColumns` is wrong, these
        //! fail even though the cipher is self-consistent.

        use super::*;

        const K128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
        const K256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        /// Appendix C's plaintext; Appendix B uses a different one.
        const PT256: &str = "00112233445566778899aabbccddeeff";

        #[test]
        fn aes_128_key_and_plaintext_from_fips_197_appendix_b_give_the_published_ciphertext() {
            let mut block = arr::<16>("3243f6a8885a308d313198a2e0370734");
            Aes::new(&arr::<16>(K128)).encrypt_block(&mut block);
            assert_eq!(block, arr::<16>("3925841d02dc09fbdc118597196a0b32"));
        }

        #[test]
        fn aes_256_key_and_plaintext_from_fips_197_appendix_c_give_the_published_ciphertext() {
            let mut block = arr::<16>(PT256);
            Aes::new256(&arr::<32>(K256)).encrypt_block(&mut block);
            assert_eq!(block, arr::<16>("8ea2b7ca516745bfeafc49904b496089"));
        }

        #[test]
        fn decrypting_the_fips_197_ciphertexts_returns_the_published_plaintext() {
            let mut c128 = arr::<16>("3925841d02dc09fbdc118597196a0b32");
            Aes::new(&arr::<16>(K128)).decrypt_block(&mut c128);
            assert_eq!(c128, arr::<16>("3243f6a8885a308d313198a2e0370734"));

            let mut c256 = arr::<16>("8ea2b7ca516745bfeafc49904b496089");
            Aes::new256(&arr::<32>(K256)).decrypt_block(&mut c256);
            assert_eq!(c256, arr::<16>(PT256));
        }

        #[test]
        fn the_debug_form_names_the_key_size_and_never_prints_the_key() {
            // rgx prints failure notes, and a derived `Debug` would put a
            // PDF's expanded key into whatever log caught the note.
            let a = alloc::format!("{:?}", Aes::new(&[0u8; 16]));
            assert_eq!(a, "Aes { key_bits: 128, rounds: 10 }");
            let b = alloc::format!("{:?}", Aes::new256(&[0u8; 32]));
            assert_eq!(b, "Aes { key_bits: 256, rounds: 14 }");
        }

        #[test]
        fn aes_192_is_refused_because_no_entry_point_accepts_a_24_byte_key() {
            for len in [0usize, 8, 15, 17, 24, 31, 33, 64] {
                assert_eq!(
                    cbc_decrypt_nopad(&vec![0u8; len], &[0u8; 64]),
                    Err(AesError::KeyLength(len)),
                    "a {len}-byte key must be refused"
                );
            }
        }

        #[test]
        fn flipping_any_key_bit_changes_the_ciphertext() {
            // Avalanche, stated as a property: a degenerate S-box entry or a
            // byte dropped from a round key leaves at least one key bit with
            // no effect on the output, and this catches it.
            let pt256 = arr::<16>(PT256);
            let mut base = pt256;
            Aes::new(&arr::<16>(K128)).encrypt_block(&mut base);
            for byte in 0..16usize {
                for bit in 0..8u8 {
                    let mut key = arr::<16>(K128);
                    key[byte] ^= 1 << bit;
                    let mut block = pt256;
                    Aes::new(&key).encrypt_block(&mut block);
                    assert_ne!(block, base, "key byte {byte} bit {bit} had no effect");
                }
            }
        }

        #[test]
        fn encrypt_and_decrypt_are_inverses_over_a_spread_of_keys() {
            // Weakest evidence in this file — both directions come from the
            // same code, so a symmetric defect passes. It is here to catch a
            // state corruption the fixed vectors happen not to reach.
            for seed in 0u8..=255 {
                let key: [u8; 16] =
                    core::array::from_fn(|i| seed.wrapping_mul(i as u8).wrapping_add(7));
                let aes = Aes::new(&key);
                let mut block: [u8; 16] = core::array::from_fn(|i| seed.wrapping_add(i as u8));
                let original = block;
                aes.encrypt_block(&mut block);
                assert_ne!(block, original, "seed {seed} did not change the block");
                aes.decrypt_block(&mut block);
                assert_eq!(block, original, "seed {seed} did not round-trip");
            }
        }
    }

    mod sp_800_38a_cbc_vectors {
        //! The four-block CBC chains from **NIST SP 800-38A, Appendix F.1.1 /
        //! F.1.2 (CBC-AES128)** and **F.2.1 / F.2.2 (CBC-AES256)**, with their
        //! published IVs. CBC is chained, so a wrong `MixColumns` corrupts
        //! block 2 onward and this catches it where a single-block vector
        //! cannot.

        use super::*;

        const IV: &str = "000102030405060708090a0b0c0d0e0f";
        const K128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
        const K256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

        const PT: &str = "6bc1bee22e409f96e93d7e117393172a\
                          ae2d8a571e03ac9c9eb76fac45af8e51\
                          30c81c46a35ce411e5fbc1191a0a52ef\
                          f69f2445df4f9b17ad2b417be66c3710";

        const CT128: &str = "7649abac8119b246cee98e9b12e9197d\
                             5086cb9b507219ee95db113a917678b2\
                             73bed6b8e3c1743b7116e69e22229516\
                             3ff1caa1681fac09120eca307586e1a7";

        const CT256: &str = "f58c4c04d6e5f1ba779eabfb5f7bfbd6\
                             9cfc4e967edb808d679f777bc6702c7d\
                             39f23369a9d9bacfa530e26304231461\
                             b2eb05e2c39be9fcda6c19078c6a9d1b";

        #[test]
        fn cbc_aes128_encryption_matches_sp_800_38a_f_1_1() {
            let out = cbc_encrypt_nopad(hex(K128).as_slice(), &arr::<16>(IV), &hex(PT)).unwrap();
            assert_eq!(
                out,
                hex(IV).into_iter().chain(hex(CT128)).collect::<Vec<u8>>()
            );
        }

        #[test]
        fn cbc_aes256_encryption_matches_sp_800_38a_f_2_1() {
            let out = cbc_encrypt_nopad(hex(K256).as_slice(), &arr::<16>(IV), &hex(PT)).unwrap();
            assert_eq!(
                out,
                hex(IV).into_iter().chain(hex(CT256)).collect::<Vec<u8>>()
            );
        }

        #[test]
        fn cbc_aes128_decryption_matches_sp_800_38a_f_1_2() {
            let stream: Vec<u8> = hex(IV).into_iter().chain(hex(CT128)).collect();
            assert_eq!(
                cbc_decrypt_nopad(hex(K128).as_slice(), &stream).unwrap(),
                hex(PT)
            );
        }

        #[test]
        fn cbc_aes256_decryption_matches_sp_800_38a_f_2_2() {
            let stream: Vec<u8> = hex(IV).into_iter().chain(hex(CT256)).collect();
            assert_eq!(
                cbc_decrypt_nopad(hex(K256).as_slice(), &stream).unwrap(),
                hex(PT)
            );
        }

        #[test]
        fn the_encrypted_stream_begins_with_the_iv_unchanged() {
            // The PDF standard security handler recovers the IV by reading the
            // first 16 bytes of the encrypted stream; a stream that started
            // with ciphertext instead would decrypt to the right answer while
            // breaking every caller.
            let iv = arr::<16>(IV);
            let out = cbc_encrypt_nopad(hex(K128).as_slice(), &iv, &hex(PT)).unwrap();
            assert_eq!(&out[..BLOCK], &iv[..]);
        }
    }

    mod openssl_streams {
        //! Streams reproduced from **OpenSSL 3.5.9** `enc`, an implementation
        //! independent of both this file and the specification text:
        //!
        //! - `openssl enc -aes-128-cbc -K 2b7e151628aed2a6abf7158809cf4f3c \
        //!      -iv 000102030405060708090a0b0c0d0e0f -in <abc>` (PKCS#7 default)
        //! - `openssl enc -aes-256-cbc -K 603deb...dff4 -iv 000102...0e0f \
        //!      -in <20 bytes>` (PKCS#7 default)
        //! - `openssl enc -aes-128-cbc -K 2b7e...f3c -iv 000102...0e0f \
        //!      -in <32 bytes>` (PKCS#7 default)
        //!
        //! The hex below is that tool's stdout, prefixed here by the IV the
        //! PDF convention prepends. These are the vectors that hold the padded
        //! path down, which SP 800-38A never exercises: every vector there is
        //! unpadded and a whole number of blocks.

        use super::*;

        const IV: &str = "000102030405060708090a0b0c0d0e0f";
        const K128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
        const K256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

        fn with_iv(iv: &str, ct: &str) -> Vec<u8> {
            hex(iv).into_iter().chain(hex(ct)).collect()
        }

        #[test]
        fn a_three_byte_plaintext_padded_by_openssl_encrypts_to_the_same_stream() {
            let expected = with_iv(IV, "f327e7290b9b923d29d949db2c9f75cc");
            let out = cbc_encrypt_padded(hex(K128).as_slice(), &arr::<16>(IV), b"abc").unwrap();
            assert_eq!(out, expected);
        }

        #[test]
        fn a_twenty_byte_plaintext_padded_by_openssl_encrypts_to_the_same_stream() {
            let pt = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac");
            let expected = with_iv(
                IV,
                "f58c4c04d6e5f1ba779eabfb5f7bfbd68d99fefe25debc6c0b1eedaac5e98e7e",
            );
            let out = cbc_encrypt_padded(hex(K256).as_slice(), &arr::<16>(IV), &pt).unwrap();
            assert_eq!(out, expected);
        }

        #[test]
        fn an_exact_block_multiple_gains_a_whole_extra_padding_block() {
            let pt = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
            let expected =
                with_iv(IV, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b255e21d7100b988ffec32feeafaf23538");
            let out = cbc_encrypt_padded(hex(K128).as_slice(), &arr::<16>(IV), &pt).unwrap();
            assert_eq!(out, expected);
            // The unpadded form of the same plaintext is the SP 800-38A pair:
            // identical up to the trailing block, which is the contract that
            // says "padding" is the only difference between the two modes. The
            // extra block is ciphertext, so it is checked by decrypting it
            // rather than by looking at the bytes.
            let nopad = cbc_encrypt_nopad(hex(K128).as_slice(), &arr::<16>(IV), &pt).unwrap();
            assert_eq!(&out[..nopad.len()], &nopad[..]);
            let recovered = cbc_decrypt_padded(hex(K128).as_slice(), &out).unwrap();
            assert_eq!(recovered, pt);
            let tail =
                cbc_decrypt_nopad(hex(K128).as_slice(), &out[..nopad.len() + BLOCK]).unwrap();
            assert!(tail[nopad.len() - BLOCK..].iter().all(|b| *b == 16));
        }

        #[test]
        fn an_empty_plaintext_still_produces_one_padding_block() {
            let out = cbc_encrypt_padded(hex(K128).as_slice(), &arr::<16>(IV), b"").unwrap();
            assert_eq!(out.len(), 32);
            assert_eq!(
                cbc_decrypt_padded(hex(K128).as_slice(), &out).unwrap(),
                Vec::<u8>::new()
            );
        }

        #[test]
        fn the_openssl_padded_streams_decrypt_back_to_their_plaintexts() {
            for (key, iv, ct, pt) in [
                (K128, IV, "f327e7290b9b923d29d949db2c9f75cc", "616263"),
                (
                    K256,
                    IV,
                    "f58c4c04d6e5f1ba779eabfb5f7bfbd68d99fefe25debc6c0b1eedaac5e98e7e",
                    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac",
                ),
            ] {
                let stream = with_iv(iv, ct);
                assert_eq!(
                    cbc_decrypt_padded(hex(key).as_slice(), &stream).unwrap(),
                    hex(pt)
                );
            }
        }
    }

    mod padding_and_length_rules {
        //! The refusals. Each of these is a case where returning something
        //! plausible instead of an error is how a wrong key or a corrupt file
        //! becomes corrupted PDF text.

        use super::*;

        const IV: &str = "000102030405060708090a0b0c0d0e0f";
        const K128: &str = "2b7e151628aed2a6abf7158809cf4f3c";

        fn padded_abc() -> (Aes, Vec<u8>) {
            let key = arr::<16>(K128);
            let aes = Aes::new(&key);
            let stream = cbc_encrypt_padded(&key, &arr::<16>(IV), b"abc").unwrap();
            (aes, stream)
        }

        #[test]
        fn a_corrupted_final_block_is_rejected_rather_than_returned() {
            let (aes, mut stream) = padded_abc();
            // The final plaintext block ends in the run byte 13; flipping one
            // bit of it makes the run describe a different length than the
            // block actually carries, which is exactly the shape a wrong key
            // produces.
            edit_final_plaintext(&aes, &mut stream, |block| block[15] ^= 1);
            assert_eq!(
                cbc_decrypt_padded(&arr::<16>(K128), &stream),
                Err(AesError::Padding)
            );
        }

        #[test]
        fn a_padding_run_longer_than_the_block_size_is_rejected() {
            let (aes, mut stream) = padded_abc();
            let target = 17u8;
            edit_final_plaintext(&aes, &mut stream, |block| {
                block[15] = target;
            });
            assert_eq!(
                cbc_decrypt_padded(&arr::<16>(K128), &stream),
                Err(AesError::Padding)
            );
        }

        #[test]
        fn a_zero_padding_run_is_rejected() {
            let (aes, mut stream) = padded_abc();
            edit_final_plaintext(&aes, &mut stream, |block| block[15] = 0);
            assert_eq!(
                cbc_decrypt_padded(&arr::<16>(K128), &stream),
                Err(AesError::Padding)
            );
        }

        #[test]
        fn a_run_whose_bytes_are_not_all_the_run_length_is_rejected() {
            // The trap this file exists to avoid: reading only the last byte
            // would call `02 02 03` a three-byte run and hand back `02 02` as
            // if they were plaintext. The run-length byte says 3; the run is
            // not three bytes of 3.
            let (aes, mut stream) = padded_abc();
            edit_final_plaintext(&aes, &mut stream, |block| {
                block[12] = 2;
                block[13] = 2;
                block[14] = 2;
                block[15] = 3;
            });
            assert_eq!(
                cbc_decrypt_padded(&arr::<16>(K128), &stream),
                Err(AesError::Padding)
            );
        }

        #[test]
        fn every_single_bit_flip_of_the_final_block_never_reads_back_as_the_original_plaintext() {
            let stream = cbc_encrypt_padded(&arr::<16>(K128), &arr::<16>(IV), b"abc").unwrap();
            let n = stream.len();
            for byte in 0..BLOCK {
                for bit in 0..8u8 {
                    let mut corrupt = stream.clone();
                    corrupt[n - BLOCK + byte] ^= 1 << bit;
                    assert_ne!(
                        cbc_decrypt_padded(&arr::<16>(K128), &corrupt)
                            .ok()
                            .as_deref(),
                        Some(&b"abc"[..]),
                        "flip of byte {byte} bit {bit} still read back as the original plaintext"
                    );
                }
            }
        }

        #[test]
        fn the_padding_check_refuses_overwhelmingly_most_of_those_flips() {
            // One ciphertext byte difference avalanches through AES
            // decryption — `InvMixColumns` runs in every middle round — so a
            // flipped final block lands on a *random* plaintext block, and a
            // random block spells valid PKCS#7 padding with probability
            // ~1/256. The four cases above pin the check deterministically;
            // this one records that the check is what is catching the rest,
            // and would notice it being weakened to a constant-time no-op that
            // only compared the last byte.
            let stream = cbc_encrypt_padded(&arr::<16>(K128), &arr::<16>(IV), b"abc").unwrap();
            let n = stream.len();
            let mut accepted = 0;
            for byte in 0..BLOCK {
                for bit in 0..8u8 {
                    let mut corrupt = stream.clone();
                    corrupt[n - BLOCK + byte] ^= 1 << bit;
                    if cbc_decrypt_padded(&arr::<16>(K128), &corrupt).is_ok() {
                        accepted += 1;
                    }
                }
            }
            assert!(
                accepted <= 2,
                "{accepted} of 128 flipped blocks were accepted"
            );
        }

        #[test]
        fn no_single_bit_key_error_ever_reads_back_as_the_original_plaintext() {
            // The property that actually matters for a wrong key: whatever the
            // padding check lets through, the caller never receives the text it
            // was looking for. Swept over every single-bit key change.
            let stream = cbc_encrypt_padded(&arr::<16>(K128), &arr::<16>(IV), b"abc").unwrap();
            for byte in 0..BLOCK {
                for bit in 0..8u8 {
                    let mut wrong = arr::<16>(K128);
                    wrong[byte] ^= 1 << bit;
                    assert_ne!(
                        cbc_decrypt_padded(&wrong, &stream).ok().as_deref(),
                        Some(&b"abc"[..]),
                        "key byte {byte} bit {bit} read back as the original plaintext"
                    );
                }
            }
        }

        #[test]
        fn an_empty_stream_is_refused_by_both_decrypt_entry_points() {
            let key = hex(K128);
            assert!(cbc_decrypt_padded(&key, b"").is_err());
            assert!(cbc_decrypt_nopad(&key, b"").is_err());
            // IV present, no ciphertext behind it.
            assert_eq!(
                cbc_decrypt_nopad(&key, &hex(IV)),
                Err(AesError::CiphertextLength(0))
            );
        }

        #[test]
        fn a_stream_whose_length_is_not_a_whole_number_of_blocks_is_refused() {
            let key = hex(K128);
            for extra in [1usize, 5, 15, 17] {
                let mut data = cbc_encrypt_padded(&key, &arr::<16>(IV), b"abc").unwrap();
                data.extend(core::iter::repeat_n(0u8, extra));
                let body = data.len() - BLOCK;
                assert_eq!(
                    cbc_decrypt_nopad(&key, &data),
                    Err(AesError::CiphertextLength(body))
                );
                assert!(cbc_decrypt_padded(&key, &data).is_err());
            }
        }

        #[test]
        fn nopad_encrypt_refuses_a_plaintext_that_is_not_a_positive_whole_number_of_blocks() {
            let key = hex(K128);
            assert_eq!(
                cbc_encrypt_nopad(&key, &arr::<16>(IV), b""),
                Err(AesError::CiphertextLength(0))
            );
            assert_eq!(
                cbc_encrypt_nopad(&key, &arr::<16>(IV), b"abc"),
                Err(AesError::CiphertextLength(3))
            );
            assert!(cbc_encrypt_nopad(&key, &arr::<16>(IV), &[0u8; 48]).is_ok());
        }

        #[test]
        fn a_key_that_is_neither_16_nor_32_bytes_is_refused_by_every_entry_point() {
            let iv = arr::<16>(IV);
            for len in [0usize, 1, 8, 15, 17, 24, 31, 33, 64] {
                let key = vec![0u8; len];
                let err = Err(AesError::KeyLength(len));
                assert_eq!(cbc_encrypt_padded(&key, &iv, b"abc"), err);
                assert_eq!(cbc_encrypt_nopad(&key, &iv, &[0u8; 32]), err);
                assert_eq!(cbc_decrypt_padded(&key, &[0u8; 64]), err);
                assert_eq!(cbc_decrypt_nopad(&key, &[0u8; 64]), err);
            }
        }
    }
}
