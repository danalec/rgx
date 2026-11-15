// SPDX-License-Identifier: Apache-2.0

//! Cryptographic primitives, assembled for one consumer.
//!
//! These are not a general-purpose crypto library and are not exposed for
//! general use. They exist because the PDF standard security handler
//! (ISO 32000-1 §7.6.3, ISO 32000-2 §7.6.4) names exactly these algorithms
//! and a reader cannot decrypt a file without them, and because pulling in a
//! third-party crate for `md5` alone would be a heavier dependency than the
//! two hundred lines it replaces.
//!
//! **Every primitive here is validated against a published specification
//! vector, not against itself.** MD5 against RFC 1321 Appendix A.5, RC4
//! against RFC 6229, AES against FIPS 197 and NIST SP 800-38A, SHA-384/512
//! against FIPS 180-4 Appendix B. That distinction matters more here than
//! usual: a cryptographic primitive that is subtly wrong does not fail
//! loudly, it produces ciphertext that decrypts to plausible garbage, and a
//! search tool cannot tell that apart from text.

pub mod aes;
pub mod md5;
pub mod rc4;
pub mod sha512;
