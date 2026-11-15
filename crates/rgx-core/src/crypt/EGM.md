# crypt

## Overview
Cryptographic primitives, assembled for one consumer. These are not a general-purpose crypto library and are not exposed for general use. They exist because the PDF standard security handler (ISO 32000-1 §7.6.3, ISO 32000-2 §7.6.4) names exactly these algorithms and a reader cannot decrypt a file without them, and because pulling in a third-party crate for `md5` alone would be a heavier dependency than the two hundred lines it replaces.

Every primitive here is validated against a published specification vector, not against itself: MD5 against RFC 1321 Appendix A.5, RC4 against RFC 6229, AES against FIPS 197 and NIST SP 800-38A, SHA-384/512 against FIPS 180-4 Appendix B. That distinction matters more here than usual: a cryptographic primitive that is subtly wrong does not fail loudly, it produces ciphertext that decrypts to plausible garbage, and a search tool cannot tell that apart from text.

## Interface
- `pub mod md5` — RFC 1321.
  - `pub struct Md5` — `pub fn new() -> Self`, `pub fn update(&mut self, data: &[u8])`, `pub fn finalize(self) -> [u8; 16]`.
  - `pub fn hash(data: &[u8]) -> [u8; 16]`.
- `pub mod rc4` — the RC4 stream cipher.
  - `pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8>` — allocates and returns the transformed buffer.
  - `pub fn rc4_in_place(key: &[u8], buf: &mut [u8])` — transforms a buffer the caller already owns.
- `pub mod aes` — FIPS 197.
  - `pub struct Aes` — `pub fn new(key: &[u8; 16]) -> Self`, `pub fn new256(key: &[u8; 32]) -> Self`, `pub fn encrypt_block(&self, block: &mut [u8; 16])`, `pub fn decrypt_block(&self, block: &mut [u8; 16])`.
  - `pub fn cbc_encrypt_padded(key: &[u8], iv: &[u8; 16], pt: &[u8]) -> Result<Vec<u8>>`.
  - `pub fn cbc_encrypt_nopad(key: &[u8], iv: &[u8; 16], pt: &[u8]) -> Result<Vec<u8>>`.
  - `pub fn cbc_decrypt_padded(key: &[u8], data: &[u8]) -> Result<Vec<u8>>`.
  - `pub fn cbc_decrypt_nopad(key: &[u8], data: &[u8]) -> Result<Vec<u8>>`.
  - `pub enum AesError { KeyLength(usize), CiphertextLength(usize), Padding }` and `pub type Result<T> = core::result::Result<T, AesError>`.
- `pub mod sha512` — FIPS 180-4.
  - `pub struct Sha384` — `pub fn new() -> Self`, `pub fn update(&mut self, data: &[u8])`, `pub fn finalize(self) -> [u8; 48]`.
  - `pub struct Sha512` — `pub fn new() -> Self`, `pub fn update(&mut self, data: &[u8])`, `pub fn finalize(self) -> [u8; 64]`.
  - `pub fn hash384(data: &[u8]) -> [u8; 48]`, `pub fn hash512(data: &[u8]) -> [u8; 64]`.

## Invariants
- Each primitive matches its published specification vector; none is validated against another implementation in this tree.
- MD5's per-step constants (`T`) and rotations (`S`) are tabulated from RFC 1321 §3.4 rather than derived at run time, so the digest does not depend on a floating-point rounding difference.
- SHA-384 is not SHA-512 truncated: §6.6 gives it its own initial hash value H(0), and the truncation keeps the *leftmost* 48 bytes of the resulting 64-byte state. One compression function serves both.
- The SHA-2 padded length field is 128 bits and is carried as a `u128`, never as a `u64` bit count of the message — `total_len * 8` in `u64` wraps at 2^61 bytes, and the digest would then be one of a different message.
- `update` may be called any number of times and with empty slices; the digest depends only on the concatenated bytes, and `finalize` consumes the hasher.
- An `AesError` is always a refusal, never a truncation: a caller that gets `Err` knows nothing was returned rather than something shortened.
- `Aes::new` takes a 128-bit key and `Aes::new256` a 256-bit one; neither is a key-stretching function, so the caller must have derived the key already.
- RC4 with an empty key leaves the buffer untouched instead of dividing by zero — a panic on a hostile file is not an acceptable answer to "this PDF is malformed".

## Side Effects
- None beyond the caller's own buffers: no file, process, lock or global state is touched; the crate allocates its return values and drops them on return.
- Not every entry point is a pure function: `Aes::encrypt_block`/`Aes::decrypt_block` and `rc4_in_place` transform the caller's own block or buffer in place, and the three hashers keep their streaming state behind `&mut self`.

## Verification
- Run: `cargo test --release --locked --workspace`
