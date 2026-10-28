// SPDX-License-Identifier: Apache-2.0

//! The standard security handler — ISO 32000-1 §7.6.3 for revisions 2
//! through 4, ISO 32000-2 §7.6.4.3 for revision 6. This is the scheme that
//! encrypts nearly every PDF which carries an `/Encrypt` dictionary.
//!
//! The scope is the part a byte-slice reader can honestly answer: **an empty
//! user password**. That is not a corner case. A file printed from a Word
//! export, or written by most scanners, carries `/Encrypt` and still opens in
//! any viewer without a prompt, because the user password *is* empty and only
//! the owner password guards it. Before this module those files yielded no
//! text at all; now they yield their pages.
//!
//! What stays out, and why:
//!
//! - **A non-empty user password.** It is a secret, and a search tool has no
//!   business guessing one or picking one up from the environment. The
//!   honest answer is a decline, which leaves the file's raw bytes
//!   searchable — the same contract every other "not mine" answer follows.
//! - **Non-standard handlers.** `/Filter` values other than `/Standard`
//!   (`/Adobe.PubSec`, the old Acrobat 3 bullet scheme) have no published
//!   algorithm to implement. Detected and named.
//! - **Public-key handlers**, where `/V` is 6 for a reason unrelated to key
//!   length and `/Recipients` is populated, are a different scheme and are
//!   not attempted.
//! - **Revision 5.** Deprecated, and — unlike revision 6 — its `/U` carries no
//!   tag that independently confirms a derived key. Decrypting with an
//!   unverified key produces mojibake that reads as a successful extraction,
//!   which is the one failure mode this module is built to prevent.
//!
//! **Every key here is proved against `/U` before it is used.** A file whose
//! `/U` does not reproduce under the derived key is declined, not decrypted.
//! That check is what separates "encrypted, readable" from "encrypted, and
//! here is a page of noise that a reader cannot tell from text".

use alloc::string::String;
use alloc::vec::Vec;

use rgx_core::crypt::md5::{self, Md5};
use rgx_core::crypt::{aes, rc4, sha512};
use rgx_core::sha256::Sha256;

use crate::pdf_full::{PdfError, PdfObject};

/// The 32-byte padding string the spec appends to every password before
/// hashing it (ISO 32000-1 Table 20).
///
/// It earns its own constant because it is also the *plaintext* the `/U`
/// entry of a revision-2 file is built from, so a candidate key can be
/// checked against it directly — a check that needs no reference to the
/// rest of the file.
const PASSWORD_PAD: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

/// How bytes are encrypted once the file key exists. This is `/V` from the
/// encryption dictionary and it — not `/R` — decides the cipher: a revision
/// 4 and a revision 6 file differ in how the key is *derived*, while `/V`
/// says what is done with it afterwards.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Method {
    /// `/V` 1 (40-bit, `/Length` 40) and `/V` 2 (up to 128-bit).
    Rc4,
    /// `/V` 4 — AES-128 in CBC, with a per-object key.
    AesV2,
    /// `/V` 5 — AES-256 in CBC, with a per-object key.
    AesV3,
}

impl Method {
    fn from_v(v: i64) -> Option<Method> {
        match v {
            1 | 2 => Some(Method::Rc4),
            4 => Some(Method::AesV2),
            5 => Some(Method::AesV3),
            // `/V` 0 is "not encrypted" and `/V` 3 is an unpublished
            // algorithm with no specification to implement. Both are declines,
            // not errors: the pipeline wants a bail here, not a note.
            _ => None,
        }
    }

    /// File encryption key length in bytes for a given `/V`.
    ///
    /// The length follows **`/V`, not the cipher.** `/V` 1 and `/V` 2 are both
    /// RC4, but only the first is 40-bit — `/V` 2 exists precisely to allow a
    /// longer RC4 key, and taking the length from the cipher instead of from
    /// the version silently truncates every 128-bit RC4 file to five bytes.
    /// That truncation does not fail visibly: Algorithm 2 still produces a
    /// key, it is just the wrong one, and the `/U` proof is the only thing
    /// that catches it.
    ///
    /// An absent `/Length` means 40 bits, per the specification, even though
    /// every producer since Acrobat 4 writes the entry explicitly.
    fn key_len(version: i64, length_bits: Option<i64>) -> usize {
        match version {
            1 => 5,
            5 => 32,
            _ => (length_bits.unwrap_or(40) / 8).clamp(5, 16) as usize,
        }
    }
}

/// Why a file could not be decrypted. Carried as a value rather than a
/// `String` so the caller can render one line per cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    /// A required entry of the `/Encrypt` dictionary is absent or the wrong
    /// type. The text says which.
    Malformed(&'static str),
    /// The derived key does not reproduce `/U`: the user password is not
    /// empty, so this module declines rather than returning noise.
    PasswordRequired,
    /// A scheme this module does not implement, named.
    Unsupported(&'static str),
}

impl From<SecurityError> for PdfError {
    fn from(e: SecurityError) -> Self {
        match e {
            SecurityError::Malformed(m) => PdfError::Security(m),
            SecurityError::PasswordRequired => PdfError::Security("non-empty user password"),
            SecurityError::Unsupported(m) => PdfError::Security(m),
        }
    }
}

/// A proved file key, plus what is needed to derive an object's own key from
/// it. Held for the whole document: the derivation is the expensive part and
/// it happens once.
///
/// `Debug` prints nothing about the key. These values decrypt a document; a
/// key in a log line is a key in a log line, whatever the log is for.
pub struct Security {
    pub(crate) key: Vec<u8>,
    method: Method,
    revision: u32,
    /// File key length in bytes, as `/Length` states it. The object-key
    /// derivation mixes in the first *n* bytes of the file key rather than
    /// all of it, so this has to survive independently of the cipher.
    key_len: usize,
}

impl Security {
    /// Derive a decryptor from the `/Encrypt` dictionary and the document's
    /// first file identifier.
    pub fn new(encrypt: &[(String, PdfObject)], id: &[u8]) -> Result<Security, SecurityError> {
        // A non-standard handler names itself, and refusing by name is a
        // more useful line than a generic "encrypted".
        match PdfObject::dict_get(encrypt, "Filter") {
            Some(PdfObject::Name(n)) if n.as_str() == "Standard" => {}
            Some(PdfObject::Name(n)) if n.as_str() == "Adobe.PubSec" => {
                return Err(SecurityError::Unsupported("Adobe.PubSec"));
            }
            Some(PdfObject::Name(_)) => {
                return Err(SecurityError::Unsupported("non-standard handler"));
            }
            // An absent `/Filter` is legal and means Standard.
            _ => {}
        }

        let revision = dict_int(encrypt, "R").unwrap_or(0) as u32;
        let version = dict_int(encrypt, "V").unwrap_or(0);
        let method = Method::from_v(version).ok_or(SecurityError::Unsupported("unsupported /V"))?;

        let key = match revision {
            2..=4 => Self::derive_legacy(encrypt, revision, id)?,
            6 => Self::derive_r6(encrypt)?,
            5 => return Err(SecurityError::Unsupported("revision 5")),
            _ => return Err(SecurityError::Unsupported("unsupported /R")),
        };

        let key_len = Method::key_len(
            dict_int(encrypt, "V").unwrap_or(1),
            dict_int(encrypt, "Length"),
        );
        Ok(Security {
            key,
            method,
            revision,
            key_len,
        })
    }

    /// ISO 32000-1 Algorithm 2, followed by the `/U` proof of Algorithm 4
    /// (revision 2) or Algorithm 5 (revision 3 and greater).
    fn derive_legacy(
        encrypt: &[(String, PdfObject)],
        revision: u32,
        id: &[u8],
    ) -> Result<Vec<u8>, SecurityError> {
        let key_len = Method::key_len(
            dict_int(encrypt, "V").unwrap_or(1),
            dict_int(encrypt, "Length"),
        );
        let u = string_field(encrypt, "U").ok_or(SecurityError::Malformed("no /U"))?;
        let o = string_field(encrypt, "O").ok_or(SecurityError::Malformed("no /O"))?;
        let p = dict_int(encrypt, "P").ok_or(SecurityError::Malformed("no /P"))?;

        let mut h = Md5::new();
        h.update(&PASSWORD_PAD); // (a): an empty password is the padding itself
        h.update(&o); // (b)
        h.update(&(p as u32).to_le_bytes()); // (c): 32-bit, low byte first
        h.update(id); // (d)
                      // (e): from revision 4, a file that leaves its metadata in the clear
                      // appends a fixed marker, so the key differs by this one word.
        if revision >= 4 && !metadata_is_encrypted(encrypt) {
            h.update(&[0xFF, 0xFF, 0xFF, 0xFF]);
        }
        let mut digest = h.finalize(); // (f)

        // (g): 50 further rounds, each over `key_len` bytes. For a 128-bit key
        // that re-hashes the whole digest 50 times; for a 40-bit one it feeds
        // only the first five bytes back, which is what makes the two
        // revisions' keys unrelated despite sharing a hash function.
        if revision >= 3 {
            for _ in 0..50 {
                digest = md5::hash(&digest[..key_len]);
            }
        }
        let key = digest[..key_len].to_vec(); // (h)

        if !u_proves(&key, revision, id, &u) {
            return Err(SecurityError::PasswordRequired);
        }
        Ok(key)
    }

    /// ISO 32000-2 Algorithm 2.A + 2.B, reached from an empty user password.
    fn derive_r6(encrypt: &[(String, PdfObject)]) -> Result<Vec<u8>, SecurityError> {
        let u = string_field(encrypt, "U").ok_or(SecurityError::Malformed("no /U"))?;
        // `/U` is 48 bytes: a 32-byte hash, an 8-byte validation salt and an
        // 8-byte key salt. Both salts feed the same function, and only the
        // validation one reproduces the tag — which is the entire test.
        if u.len() < 48 {
            return Err(SecurityError::Malformed("short /U"));
        }
        let validation = hardened_hash(6, b"", &u[32..40], &[])?;
        if validation[..32] != u[..32] {
            return Err(SecurityError::PasswordRequired);
        }

        let intermediate = hardened_hash(6, b"", &u[40..48], &[])?;
        let ue = string_field(encrypt, "UE").ok_or(SecurityError::Malformed("no /UE"))?;
        // The CBC helper takes its IV from the first 16 bytes of its input and
        // strips it from the output — the PDF *stream* convention, where the
        // IV genuinely is stored as the stream's first block. `/UE` is not a
        // stream: it is one bare ciphertext block with an implied all-zero IV,
        // so it has to be handed over with those sixteen bytes attached. The
        // helper then removes them again, and what comes back is the key.
        //
        // Feeding `/UE` in directly instead would spend the first block on an
        // IV that is all zeros and leave a sixteen-byte "key" — half the
        // right answer, failing later as a padding error on some unrelated
        // stream.
        if ue.len() % 16 != 0 || ue.is_empty() {
            return Err(SecurityError::Malformed("bad /UE"));
        }
        let mut buf = Vec::with_capacity(16 + ue.len());
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&ue);
        aes::cbc_decrypt_nopad(&intermediate, &buf).map_err(|_| SecurityError::Malformed("bad /UE"))
    }

    /// ISO 32000-1 §7.6.2 Algorithm 1 (for `/V` 4 and below) and Algorithm 1.A
    /// (for `/V` 5).
    ///
    /// This is not a secret choice — it is what stops a ciphertext block
    /// lifted from one object into another from decrypting, so an object key
    /// is never reused across objects.
    ///
    /// Three things here are load-bearing and each one is a place where the
    /// obvious reading is wrong:
    ///
    /// - **RC4 mixes the object number too.** The common claim that "RC4
    ///   uses the file key unchanged and only AES mixes it in" is false, and
    ///   following it produces a reader that decrypts nothing at revision 2
    ///   or 3 — the two revisions that are still all over older corpora.
    /// - **AES-128 appends the literal `sAlT`** to the digest before the
    ///   second hash. It is in the specification, it is in every
    ///   implementation, and nobody remembers it.
    /// - **`/V` 5 uses the file key as is** (Algorithm 1.A), with no object
    ///   number and no second hash. Deriving one for revision 6 breaks the
    ///   newest and most common revision in the wild.
    ///
    /// All three were settled by measurement against libqpdf 12.4.2 rather
    /// than by reading the specification, which is twice wrong on this page.
    pub(crate) fn object_key(&self, num: u32, gen: u16) -> Vec<u8> {
        let n = if self.revision <= 2 { 5 } else { self.key_len };
        let take = (n + 5).min(16);
        match self.method {
            // Algorithm 1.A: the file key, whole, for `/V` 5.
            Method::AesV3 => self.key.clone(),
            Method::Rc4 => self.derive_object_digest(&self.key[..n], num, gen)[..take].to_vec(),
            Method::AesV2 => {
                // `sAlT` is appended to the *running hash*, not to its
                // output. Feeding the first digest's bytes into a fresh MD5
                // instead is a different computation that produces a
                // different key, and the failure is a padding check on the
                // first AES block — which is indistinguishable, to a reader,
                // from a corrupt file.
                let mut h = md5::Md5::new();
                h.update(&self.key[..n]);
                h.update(&num_le(num));
                h.update(&gen.to_le_bytes());
                h.update(b"sAlT");
                h.finalize()[..take].to_vec()
            }
        }
    }

    /// The digest half of Algorithm 1, shared by the RC4 key and used on
    /// its own so the AES branch can restart the hash with `sAlT` appended to
    /// the running state.
    fn derive_object_digest(&self, key: &[u8], num: u32, gen: u16) -> [u8; 16] {
        let mut h = md5::Md5::new();
        h.update(key);
        h.update(&num_le(num));
        h.update(&gen.to_le_bytes());
        h.finalize()
    }

    /// Decrypt a stream.
    ///
    /// Encryption is applied *after* the `/Filter` chain on write, so this
    /// must run *before* Flate or LZW on read. The reverse order is the
    /// classic reason a correctly-keyed page comes out as noise.
    pub fn decrypt_stream(&self, num: u32, gen: u16, data: &[u8]) -> Option<Vec<u8>> {
        let key = self.object_key(num, gen);
        match self.method {
            Method::Rc4 => Some(rc4::rc4(&key, data)),
            // The IV is not stored anywhere: it is the first block of the
            // stream itself.
            Method::AesV2 | Method::AesV3 => aes::cbc_decrypt_padded(&key, data).ok(),
        }
    }

    /// Decrypt a string.
    ///
    /// ISO 32000-1 §7.6.2: up to revision 3, a string no longer than the
    /// file key is left in the clear, because there is no room for a
    /// keystream worth the trouble. Missing that exemption turns every short
    /// string in a revision-3 file into noise.
    pub fn decrypt_string(&self, num: u32, gen: u16, data: &[u8]) -> Option<Vec<u8>> {
        if self.revision <= 3 && data.len() <= self.key.len() {
            return Some(data.to_vec());
        }
        self.decrypt_stream(num, gen, data)
    }
}

/// Recompute `/U` from the candidate key and compare, which is ISO 32000-1
/// Algorithm 6.
///
/// The chain is applied *forward from the hash*, not backward from `/U`:
/// RC4 is symmetric, so a reader who runs the twenty rounds in the same
/// order over `/U` is not inverting the encryption, they are applying the
/// keystream one more time and will disagree with every conforming file.
fn u_proves(key: &[u8], revision: u32, id: &[u8], u: &[u8]) -> bool {
    if revision == 2 {
        return rc4::rc4(key, &PASSWORD_PAD) == u;
    }
    let mut h = Md5::new();
    h.update(&PASSWORD_PAD);
    h.update(id);
    let mut e: Vec<u8> = h.finalize().to_vec();
    for i in 0..20u8 {
        let k: Vec<u8> = key.iter().map(|b| b ^ i).collect();
        e = rc4::rc4(&k, &e);
    }
    // Only the first 16 bytes are defined for revision 3 and greater; the
    // remaining 16 are arbitrary padding the spec permits any producer to
    // write, so comparing them would reject conforming files.
    u.len() >= 16 && e == u[..16]
}

/// ISO 32000-2 Algorithm 2.B, with the initial hash of Algorithm 2.A folded
/// in because no caller wants them apart.
///
/// The AES step is what makes revision 6 different from every earlier one:
/// a candidate costs a full block-cipher pass per round, and both the loop
/// count and the hash width are chosen from the previous round's output, so
/// there is no fixed amount of work to precompute.
fn hardened_hash(
    revision: u32,
    password: &[u8],
    salt: &[u8],
    udata: &[u8],
) -> Result<Vec<u8>, SecurityError> {
    // Algorithm 2.A: the initial hash over password, salt and user data.
    let mut k = Sha256::hash(&[password, salt, udata].concat()).to_vec();

    // Revision 5 stops here in the published text; `Security::new` refuses
    // revision 5 before reaching this point, so reaching it is a bug.
    if revision < 6 {
        return Ok(k[..32].to_vec());
    }

    // Algorithm 2.B step (b). `count` is 1-based, matching the spec's own
    // termination test, which compares the last byte of E against `count - 32`.
    let mut count: u32 = 0;
    loop {
        count += 1;

        // (b)(1): K1 = 64 repetitions of password || K || udata.
        let mut k1 = Vec::new();
        for _ in 0..64 {
            k1.extend_from_slice(password);
            k1.extend_from_slice(&k);
            k1.extend_from_slice(udata);
        }

        // (b)(2): AES-128 in CBC under the first 32 bytes of K.
        //
        // Without padding, as the specification says. K1 is 64 repetitions
        // of password || K || udata, and for the only password this module
        // supports — the empty one — that is 64 times 32, 48 or 64 bytes, so
        // it is already a whole number of blocks and nothing needs padding.
        // Adding a padding block here is not a subtle difference: it shifts
        // every subsequent byte, changes `e[-1]` (the byte the termination
        // test reads), and makes the derived key wrong in a way that looks
        // exactly like a file with a different password.
        let mut aes_key = [0u8; 16];
        let mut aes_iv = [0u8; 16];
        aes_key.copy_from_slice(&k[..16]);
        aes_iv.copy_from_slice(&k[16..32]);
        let mut e = aes::cbc_encrypt_nopad(&aes_key, &aes_iv, &k1)
            .map_err(|_| SecurityError::Malformed("unaligned key schedule"))?;
        // The CBC helpers prepend the IV so they mirror each other, as the
        // PDF stream convention requires. Algorithm 2.B does not: `E` is the
        // ciphertext alone, and the bytes the termination test reads are its
        // last. Leaving the IV attached would make every subsequent value
        // wrong while still producing a well-formed 2064-byte buffer.
        if e.len() < 16 {
            return Err(SecurityError::Malformed("short cipher block"));
        }
        e.drain(..16);

        // (b)(3): the *sum* of the first 16 bytes, mod 3, picks the width.
        // It is a byte sum, not a 128-bit integer reduced mod 3; the two
        // agree on roughly one block in four and picking the wrong one
        // yields a key that is wrong without ever looking wrong.
        k = match e[..16].iter().map(|b| *b as u32).sum::<u32>() % 3 {
            0 => Sha256::hash(&e).to_vec(),
            1 => sha512::hash384(&e).to_vec(),
            _ => sha512::hash512(&e).to_vec(),
        };

        // (b)(4): termination. Both conditions are needed: the first lets a
        // long chain finish, the second stops a short one from exiting
        // before it has done any work.
        if count >= 64 && e[e.len() - 1] as u32 <= count - 32 {
            break;
        }
    }
    Ok(k[..32].to_vec())
}

// ---------------------------------------------------------------------------
// small readers for the dictionary, kept here so the shape of a malformed
// `/Encrypt` is one file's problem rather than every call site's
// ---------------------------------------------------------------------------

fn dict_int(dict: &[(String, PdfObject)], key: &str) -> Option<i64> {
    match PdfObject::dict_get(dict, key) {
        Some(PdfObject::Int(v)) => Some(*v),
        _ => None,
    }
}

fn string_field(dict: &[(String, PdfObject)], key: &str) -> Option<Vec<u8>> {
    match PdfObject::dict_get(dict, key) {
        Some(PdfObject::String(b)) => Some(b.clone()),
        _ => None,
    }
}

/// `/EncryptMetadata` defaults to **true** — the opposite of the usual
/// convention for optional booleans in PDF, and reading a missing entry as
/// "metadata is in the clear" flips the key on every revision-4 file that
/// takes the default.
fn metadata_is_encrypted(dict: &[(String, PdfObject)]) -> bool {
    !matches!(
        PdfObject::dict_get(dict, "EncryptMetadata"),
        Some(PdfObject::Bool(false))
    )
}

fn num_le(num: u32) -> [u8; 3] {
    let b = num.to_le_bytes();
    [b[0], b[1], b[2]]
}

#[cfg(all(test, feature = "pdf"))]
mod tests {
    //! The vectors below are encrypted by libqpdf 12.4.2 (through pikepdf
    //! 10.17.0) and checked against the file keys libqpdf itself derived, so
    //! a self-consistent implementation that read the spec wrong in the same
    //! direction twice would still fail here rather than agree with itself.
    use super::*;
    use alloc::vec;

    fn hexs(b: &[u8]) -> alloc::string::String {
        b.iter().map(|x| alloc::format!("{x:02x}")).collect()
    }

    fn fixture(name: &str) -> Vec<u8> {
        // `cargo test` runs with the crate root as the working directory.
        let path = alloc::format!("testdata/{name}");
        std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    #[test]
    fn every_revision_the_fixture_set_covers_opens_and_yields_its_pages() {
        for name in [
            "r2_rc4_40.pdf",
            "r3_rc4_128.pdf",
            "r4_aes_128.pdf",
            "r6_aes_256.pdf",
        ] {
            let data = fixture(name);
            let doc = crate::pdf_full::PdfDocument::parse(&data)
                .unwrap_or_else(|e| panic!("{name} did not open: {e}"));
            assert!(
                doc.is_encrypted_open(),
                "{name} opened without a proved key"
            );
            let mut report = crate::pdf_full::FontReport::default();
            let page = doc
                .page_text(0, &mut report)
                .unwrap_or_else(|| panic!("{name} page 1 produced no text"));
            assert!(
                page.contains("RGX CRYPTOPROVA"),
                "{name} page 1 came back as {page:?}"
            );
        }
    }

    #[test]
    fn the_file_key_matches_the_one_the_reference_implementation_derived() {
        // libqpdf 12.4.2, via pikepdf 10.17.0, over the same files. These are
        // its own numbers rather than ours, which is the whole point: an
        // implementation that misread the specification in the same direction
        // on both the derivation and the use would round-trip perfectly and
        // agree with nothing else.
        for (name, want) in [
            ("r2_rc4_40.pdf", "7738f364df"),
            ("r3_rc4_128.pdf", "2de86c317ea13d380d99033dd785ec6e"),
            ("r4_aes_128.pdf", "6dfde187210df970f75d67706f77e157"),
            (
                "r6_aes_256.pdf",
                "5093d43a0fcb80b0e33e2b02b019ab7dd58a9b955ae9550e604b2d794d2ed341",
            ),
        ] {
            let data = fixture(name);
            let doc = crate::pdf_full::PdfDocument::parse(&data).expect("opens");
            assert_eq!(hexs(&doc.security_key()), want, "{name}");
        }
    }

    #[test]
    fn a_file_that_needs_a_password_is_a_refusal_rather_than_a_page_of_noise() {
        // The same document encrypted with a non-empty user password. Every
        // byte is still decryptable — the key simply is not ours to derive,
        // because deriving it means guessing a secret. The honest answer is a
        // bail, which leaves the raw bytes searchable.
        let data = fixture("r4_userpw.pdf");
        let err = crate::pdf_full::PdfDocument::parse(&data)
            .err()
            .expect("a password-protected file must not open");
        assert!(
            matches!(
                err,
                crate::pdf_full::PdfError::Security("non-empty user password")
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn a_non_standard_handler_is_named_rather_than_called_encrypted() {
        let dict = vec![
            ("Filter".into(), PdfObject::Name("Adobe.PubSec".into())),
            ("V".into(), PdfObject::Int(4)),
            ("R".into(), PdfObject::Int(4)),
        ];
        assert_eq!(
            Security::new(&dict, &[]).err().expect("declined"),
            SecurityError::Unsupported("Adobe.PubSec")
        );
    }

    #[test]
    fn a_missing_encrypt_metadata_entry_means_metadata_is_encrypted() {
        // The default is the opposite of every other optional boolean in the
        // format, and reading a missing entry as "metadata is in the clear"
        // changes the file key on every revision-4 document that takes it.
        assert!(metadata_is_encrypted(&[]));
        assert!(metadata_is_encrypted(&[(
            "EncryptMetadata".into(),
            PdfObject::Bool(true)
        )]));
        assert!(!metadata_is_encrypted(&[(
            "EncryptMetadata".into(),
            PdfObject::Bool(false)
        )]));
    }

    #[test]
    fn revision_three_or_less_leaves_a_string_shorter_than_the_key_in_the_clear() {
        let s = Security {
            key: vec![0u8; 16],
            method: Method::Rc4,
            revision: 3,
            key_len: 16,
        };
        let short = b"abc";
        assert_eq!(
            s.decrypt_string(1, 0, short).as_deref(),
            Some(&short[..]),
            "a string with no room for a keystream is stored unencrypted"
        );
    }
}
