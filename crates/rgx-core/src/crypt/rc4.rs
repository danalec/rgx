// SPDX-License-Identifier: Apache-2.0

//! RC4 stream cipher.
//!
//! Here so that `rgx` can read the ISO 32000-1 §7.6 standard security
//! handler, which encrypts each object with RC4 under a per-object key.
//! RC4 itself is broken and RFC 6229 §3 says so; this is a reader for
//! files that already exist, not a cipher to reach for.

extern crate alloc;

/// Symmetric stream cipher. The PDF standard security handler uses it with
/// the key varying per object, so there is no "encrypt" vs "decrypt"
/// distinction here: the same keystream both ways is the whole point.
pub fn rc4(key: &[u8], data: &[u8]) -> alloc::vec::Vec<u8> {
    let mut buf = data.to_vec();
    rc4_in_place(key, &mut buf);
    buf
}

/// In-place form, for callers that already own the buffer they are
/// decrypting and would otherwise pay a second allocation per object.
pub fn rc4_in_place(key: &[u8], buf: &mut [u8]) {
    // The KSA indexes `key[i % key.len()]`; with an empty key that is a
    // division by zero, and a panic on a hostile file is not an acceptable
    // answer to "this PDF is malformed". An empty key leaves `S` the
    // identity, which is exactly the keystream this returns — pass the
    // buffer through untouched. §7.6.2 always supplies 5..=16 bytes.
    if key.is_empty() {
        return;
    }

    let mut s = [0u8; 256];
    for (i, slot) in s.iter_mut().enumerate() {
        *slot = i as u8;
    }

    let mut j: u8 = 0;
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, usize::from(j));
    }

    let mut i: u8 = 0;
    j = 0;
    for byte in buf.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[usize::from(i)]);
        s.swap(usize::from(i), usize::from(j));
        *byte ^= s[usize::from(s[usize::from(i)].wrapping_add(s[usize::from(j)]))];
    }
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

    /// RC4 is a stream cipher, so its keystream is recoverable by
    /// encrypting zeros. This yields `len` bytes of keystream for `key`.
    fn keystream(key: &[u8], len: usize) -> alloc::vec::Vec<u8> {
        rc4(key, &alloc::vec![0u8; len])
    }

    /// RFC 6229, "Test Vectors for the Stream Cipher RC4", §2. The two keys
    /// are the RFC's own: "Key 1" is the byte-index key 0x01, 0x02, 0x03, …
    /// truncated to each length, and "Key 2" is the SHA-256 of "Internet
    /// Engineering Task Force" truncated from the least-significant end.
    /// The RFC publishes keystream bytes at stream offsets; each entry here
    /// is one published 16-byte window, copied verbatim.
    const RFC6229: &[(&str, &[u8], usize, &[u8])] = &[
        // Key 1, offset 0.
        (
            "key1/40/off0",
            &[0x01, 0x02, 0x03, 0x04, 0x05],
            0,
            &[
                0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11,
                0x18, 0xa8,
            ],
        ),
        (
            "key1/40/off240",
            &[0x01, 0x02, 0x03, 0x04, 0x05],
            240,
            &[
                0x28, 0xcb, 0x11, 0x32, 0xc9, 0x6c, 0xe2, 0x86, 0x42, 0x1d, 0xca, 0xad, 0xb8, 0xb6,
                0x9e, 0xae,
            ],
        ),
        (
            "key1/56/off0",
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            0,
            &[
                0x29, 0x3f, 0x02, 0xd4, 0x7f, 0x37, 0xc9, 0xb6, 0x33, 0xf2, 0xaf, 0x52, 0x85, 0xfe,
                0xb4, 0x6b,
            ],
        ),
        (
            "key1/56/off240",
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            240,
            &[
                0x91, 0x4f, 0x02, 0x53, 0x1c, 0x92, 0x18, 0x81, 0x0d, 0xf6, 0x0f, 0x67, 0xe3, 0x38,
                0x15, 0x4c,
            ],
        ),
        (
            "key1/64/off0",
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            0,
            &[
                0x97, 0xab, 0x8a, 0x1b, 0xf0, 0xaf, 0xb9, 0x61, 0x32, 0xf2, 0xf6, 0x72, 0x58, 0xda,
                0x15, 0xa8,
            ],
        ),
        (
            "key1/64/off240",
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            240,
            &[
                0x96, 0x36, 0xeb, 0xc9, 0x84, 0x19, 0x26, 0xf4, 0xf7, 0xd1, 0xf3, 0x62, 0xbd, 0xdf,
                0x6e, 0x18,
            ],
        ),
        (
            "key1/80/off0",
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a],
            0,
            &[
                0xed, 0xe3, 0xb0, 0x46, 0x43, 0xe5, 0x86, 0xcc, 0x90, 0x7d, 0xc2, 0x18, 0x51, 0x70,
                0x99, 0x02,
            ],
        ),
        (
            "key1/80/off240",
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a],
            240,
            &[
                0x3c, 0xfd, 0x6c, 0xb5, 0x8e, 0xe0, 0xfd, 0xde, 0x64, 0x01, 0x76, 0xad, 0x00, 0x00,
                0x04, 0x4d,
            ],
        ),
        (
            "key1/128/off0",
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
            0,
            &[
                0x9a, 0xc7, 0xcc, 0x9a, 0x60, 0x9d, 0x1e, 0xf7, 0xb2, 0x93, 0x28, 0x99, 0xcd, 0xe4,
                0x1b, 0x97,
            ],
        ),
        (
            "key1/128/off240",
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
            240,
            &[
                0x06, 0x59, 0x02, 0xe4, 0xb6, 0x20, 0xf6, 0xcc, 0x36, 0xc8, 0x58, 0x9f, 0x66, 0x43,
                0x2f, 0x2b,
            ],
        ),
        (
            "key1/192/off0",
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            ],
            0,
            &[
                0x05, 0x95, 0xe5, 0x7f, 0xe5, 0xf0, 0xbb, 0x3c, 0x70, 0x6e, 0xda, 0xc8, 0xa4, 0xb2,
                0xdb, 0x11,
            ],
        ),
        (
            "key1/192/off240",
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            ],
            240,
            &[
                0xb0, 0x6b, 0x9b, 0x1e, 0x19, 0x5d, 0x13, 0xd8, 0xf4, 0xa7, 0x99, 0x5c, 0x45, 0x53,
                0xac, 0x05,
            ],
        ),
        (
            "key1/256/off0",
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20,
            ],
            0,
            &[
                0xea, 0xa6, 0xbd, 0x25, 0x88, 0x0b, 0xf9, 0x3d, 0x3f, 0x5d, 0x1e, 0x4c, 0xa2, 0x61,
                0x1d, 0x91,
            ],
        ),
        (
            "key1/256/off240",
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20,
            ],
            240,
            &[
                0x11, 0x4a, 0xe3, 0x44, 0xde, 0xd7, 0x1b, 0x35, 0xf2, 0xe6, 0x0f, 0xeb, 0xad, 0x72,
                0x7f, 0xd8,
            ],
        ),
        // Key 2, offset 0.
        (
            "key2/40/off0",
            &[0x83, 0x32, 0x22, 0x77, 0x2a],
            0,
            &[
                0x80, 0xad, 0x97, 0xbd, 0xc9, 0x73, 0xdf, 0x8a, 0x2e, 0x87, 0x9e, 0x92, 0xa4, 0x97,
                0xef, 0xda,
            ],
        ),
        (
            "key2/40/off256",
            &[0x83, 0x32, 0x22, 0x77, 0x2a],
            256,
            &[
                0xf0, 0xda, 0xf5, 0xba, 0xb3, 0xd5, 0x96, 0x83, 0x98, 0x57, 0x84, 0x6f, 0x73, 0xfb,
                0xfe, 0x5a,
            ],
        ),
        (
            "key2/128/off0",
            &[
                0xeb, 0xb4, 0x62, 0x27, 0xc6, 0xcc, 0x8b, 0x37, 0x64, 0x19, 0x10, 0x83, 0x32, 0x22,
                0x77, 0x2a,
            ],
            0,
            &[
                0x72, 0x0c, 0x94, 0xb6, 0x3e, 0xdf, 0x44, 0xe1, 0x31, 0xd9, 0x50, 0xca, 0x21, 0x1a,
                0x5a, 0x30,
            ],
        ),
        (
            "key2/128/off256",
            &[
                0xeb, 0xb4, 0x62, 0x27, 0xc6, 0xcc, 0x8b, 0x37, 0x64, 0x19, 0x10, 0x83, 0x32, 0x22,
                0x77, 0x2a,
            ],
            256,
            &[
                0x48, 0x47, 0xd8, 0x1d, 0xa4, 0x94, 0x2d, 0xbc, 0x24, 0x9d, 0xef, 0xc4, 0x8c, 0x92,
                0x2b, 0x9f,
            ],
        ),
        (
            "key2/256/off0",
            &[
                0x1a, 0xda, 0x31, 0xd5, 0xcf, 0x68, 0x82, 0x21, 0xc1, 0x09, 0x16, 0x39, 0x08, 0xeb,
                0xe5, 0x1d, 0xeb, 0xb4, 0x62, 0x27, 0xc6, 0xcc, 0x8b, 0x37, 0x64, 0x19, 0x10, 0x83,
                0x32, 0x22, 0x77, 0x2a,
            ],
            0,
            &[
                0xdd, 0x5b, 0xcb, 0x00, 0x18, 0xe9, 0x22, 0xd4, 0x94, 0x75, 0x9d, 0x7c, 0x39, 0x5d,
                0x02, 0xd3,
            ],
        ),
        (
            "key2/256/off256",
            &[
                0x1a, 0xda, 0x31, 0xd5, 0xcf, 0x68, 0x82, 0x21, 0xc1, 0x09, 0x16, 0x39, 0x08, 0xeb,
                0xe5, 0x1d, 0xeb, 0xb4, 0x62, 0x27, 0xc6, 0xcc, 0x8b, 0x37, 0x64, 0x19, 0x10, 0x83,
                0x32, 0x22, 0x77, 0x2a,
            ],
            256,
            &[
                0xf8, 0xcb, 0x62, 0x74, 0xdb, 0x99, 0xb8, 0x0b, 0x1d, 0x20, 0x12, 0xa9, 0x8e, 0xd4,
                0x8f, 0x0e,
            ],
        ),
    ];

    #[test]
    fn the_keystream_matches_the_rfc_6229_vectors() {
        for (name, key, offset, want) in RFC6229 {
            let ks = keystream(key, offset + 16);
            assert_eq!(&ks[*offset..offset + 16], *want, "{name}");
        }
    }

    /// The canonical `Key`/`Plaintext` pair. RFC 6229 publishes keystream
    /// only, so this states the same fact end to end: running the cipher
    /// over real text reproduces the well-known `bbf316e8d940af0ad3`.
    #[test]
    fn key_plaintext_encrypts_to_the_published_ciphertext() {
        assert_eq!(hex(&rc4(b"Key", b"Plaintext")), "bbf316e8d940af0ad3");
    }

    /// `rc4_in_place` is what the PDF handler calls per object. If it and
    /// `rc4` ever diverge, a caller picks one and silently gets wrong bytes,
    /// so the two are compared rather than assumed equal.
    #[test]
    fn in_place_and_allocating_forms_agree() {
        let key = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a";
        let data: alloc::vec::Vec<u8> = (0..300u32).map(|i| (i * 13 % 256) as u8).collect();

        let mut buf = data.clone();
        rc4_in_place(key, &mut buf);
        assert_eq!(buf, rc4(key, &data));
    }

    /// The property the whole cipher rests on: encryption and decryption
    /// are the same operation. If this fails, a PDF whose object bytes were
    /// encrypted cannot be decrypted by this code at all.
    #[test]
    fn encrypting_twice_restores_the_plaintext() {
        let key = b"\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00";
        let data: alloc::vec::Vec<u8> = (0..1024u32).map(|i| (i * 29 % 256) as u8).collect();

        let round_trip = rc4(key, &rc4(key, &data));
        assert_eq!(round_trip, data);
    }

    /// The keystream must not restart at a buffer boundary; a `reset` of
    /// `i`/`j` between chunks would still satisfy every vector above,
    /// because they are all one-shot.
    #[test]
    fn the_keystream_runs_past_the_first_block() {
        let key = b"\x01\x02\x03\x04\x05";
        let ks = keystream(key, 512);
        assert_eq!(&ks[..16], &keystream(key, 16)[..]);
        assert_ne!(&ks[16..32], &ks[..16]);
        assert_ne!(&ks[496..512], &ks[480..496]);
    }

    /// An empty key leaves the buffer untouched. §7.6.2 never produces one,
    /// so the property asserted is that a malformed file yields the input
    /// rather than a division-by-zero panic.
    #[test]
    fn an_empty_key_returns_the_buffer_unchanged() {
        let data: alloc::vec::Vec<u8> = (0..64u32).map(|i| i as u8).collect();
        assert_eq!(rc4(&[], &data), data);
        let mut buf = data.clone();
        rc4_in_place(&[], &mut buf);
        assert_eq!(buf, data);
    }

    /// Lengths a PDF object stream can take, plus zero. The cipher must not
    /// depend on the input length, and an empty output must stay empty.
    #[test]
    fn any_length_round_trips_including_empty() {
        let key = b"\x10\x20\x30\x40\x50";
        for len in [0usize, 1, 2, 255, 256, 257, 4096] {
            let data: alloc::vec::Vec<u8> = (0..len as u32).map(|i| (i * 17 % 256) as u8).collect();
            let ct = rc4(key, &data);
            assert_eq!(ct.len(), len);
            assert_eq!(rc4(key, &ct), data, "len {len}");
        }
    }
}
