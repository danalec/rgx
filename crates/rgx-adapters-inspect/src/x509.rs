// SPDX-License-Identifier: Apache-2.0

//! X.509 certificate metadata (PEM/DER), hand-rolled: minimal DER TLV
//! walker plus a reduced port of the X.509 reader of the `io` project by
//! Dan Gohman, whose work is used here under Apache-2.0. Only
//! structural parsing — no signature verification. See `NOTICE`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Write as _;
use rgx_core::{bail, decline, Result};
use rgx_core::{Adapter, Outcome};

/// X.509 certificates: PEM (`-----BEGIN CERTIFICATE-----`) or raw DER.
pub struct X509Cert;
impl Adapter for X509Cert {
    fn name(&self) -> &'static str {
        "x509"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["pem", "crt", "cer", "der", "cert"]
    }

    /// The same extension is two different questions. A `.pem` is
    /// base64 text that ripgrep already reads perfectly; replacing it
    /// with a description is a subset (a [`rgx_core::Reach::Render`]
    /// case). A `.der`/`.crt` is binary; replacing it is a strict
    /// superset ([`rgx_core::Reach::Reveal`]). The two cannot be one
    /// answer, so `Reach` is a property of the file, not the extension.
    /// The test is the searcher's own NUL heuristic.
    fn reach_needs_bytes(&self) -> bool {
        true
    }
    fn reach_for(&self, data: &[u8]) -> rgx_core::Reach {
        if rgx_core::memchr::memchr(0, data).is_some() {
            rgx_core::Reach::Reveal
        } else {
            rgx_core::Reach::Render
        }
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let der = if data.starts_with(b"-----BEGIN") {
            pem_to_der(data)?
        } else {
            // A DER certificate is a SEQUENCE, so it opens with 0x30. A file
            // that does not is not a certificate at all — a decline, so the
            // bytes are searched raw instead of earning a note that says
            // "overruns buffer" about a file that was never DER. A file
            // that *does* open with 0x30 and then overruns is a corrupt
            // certificate, and that is worth reporting.
            if !data.first().is_some_and(|b| *b == 0x30) {
                decline!("not a DER certificate (does not open with a SEQUENCE)");
            }
            data.to_vec()
        };
        let text = describe_cert(&der)?;
        Ok(Outcome::Text(text.into_bytes()))
    }
}

// ---------------------------------------------------------------------------
// PEM -> DER (inline base64, no crates)
// ---------------------------------------------------------------------------

fn pem_to_der(data: &[u8]) -> Result<Vec<u8>> {
    let text = String::from_utf8_lossy(data);
    let label_start = text
        .find("-----BEGIN ")
        .ok_or_else(|| rgx_core::anyhow!("no PEM begin line"))?;
    let after_begin = label_start + "-----BEGIN ".len();
    let rel_end = text[after_begin..]
        .find("-----")
        .ok_or_else(|| rgx_core::anyhow!("malformed PEM begin line"))?;
    let label = text[after_begin..after_begin + rel_end].trim().to_string();
    if !label.ends_with("CERTIFICATE") {
        decline!("PEM block is {label}, not a certificate");
    }
    let body_start = after_begin + rel_end + "-----".len();
    let end_marker = format!("-----END {label}-----");
    let body_end = text[body_start..]
        .find(&end_marker)
        .map(|p| body_start + p)
        .ok_or_else(|| rgx_core::anyhow!("no PEM end line"))?;
    let body: Vec<u8> = text[body_start..body_end]
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    base64_decode(&body)
}

fn base64_decode(input: &[u8]) -> Result<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for &b in input {
        if b == b'=' {
            break;
        }
        let v = val(b).ok_or_else(|| rgx_core::anyhow!("invalid base64 byte {b:#x}"))?;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// minimal DER walker
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct Der<'a> {
    tag: u8,
    value: &'a [u8],
}

struct DerIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        DerIter { data, pos: 0 }
    }
}

fn read_der<'a>(data: &'a [u8], pos: &mut usize) -> Result<Der<'a>> {
    if *pos + 2 > data.len() {
        bail!("DER truncated at tag");
    }
    let tag = data[*pos];
    let lb = data[*pos + 1];
    *pos += 2;
    let len: usize = if lb & 0x80 == 0 {
        lb as usize
    } else {
        let n = (lb & 0x7f) as usize;
        if n == 0 || n > 4 || *pos + n > data.len() {
            bail!("DER bad long-form length");
        }
        let mut l: usize = 0;
        for i in 0..n {
            l = (l << 8) | data[*pos + i] as usize;
        }
        *pos += n;
        l
    };
    if *pos + len > data.len() {
        bail!("DER value overruns buffer");
    }
    let value = &data[*pos..*pos + len];
    *pos += len;
    Ok(Der { tag, value })
}

impl<'a> Iterator for DerIter<'a> {
    type Item = Result<Der<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }
        let start = self.pos;
        match read_der(self.data, &mut self.pos) {
            Ok(d) => Some(Ok(d)),
            Err(e) => {
                // fuse: if the header itself failed we did not advance — force
                // progress so `.flatten()` loops over us always terminate
                if self.pos == start {
                    self.pos = self.data.len();
                }
                Some(Err(e))
            }
        }
    }
}

fn first_child<'a>(obj: &Der<'a>) -> Result<Option<Der<'a>>> {
    // constructed: children live inside value; BIT STRING/OCTET STRING are
    // primitive unless tagged otherwise. We only descend into SEQUENCE/SET/
    // context tags.
    DerIter::new(obj.value).next().transpose()
}

// OID content bytes we care about
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_C: &[u8] = &[0x55, 0x04, 0x06];
const OID_O: &[u8] = &[0x55, 0x04, 0x0A];
const OID_OU: &[u8] = &[0x55, 0x04, 0x0B];
const OID_ST: &[u8] = &[0x55, 0x04, 0x08];
const OID_L: &[u8] = &[0x55, 0x04, 0x07];
const OID_EMAIL: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01];
const OID_EXT_SAN: &[u8] = &[0x55, 0x1D, 0x11];
const OID_EXT_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];

// ---------------------------------------------------------------------------
// certificate description
// ---------------------------------------------------------------------------

/// A `GeneralName` `iPAddress`: four bytes of IPv4, sixteen of IPv6.
///
/// The IPv6 form is RFC 5952 — lowercase, no leading zeros, and the longest
/// run of two or more zero groups written as `::`. That is the spelling
/// every other tool prints and the one a pattern is written against; a
/// certificate description that said `0:0:0:0:0:0:0:1` would be correct and
/// unsearchable by anyone who typed `::1`.
///
/// Anything else is not an address, and is reported by length rather than
/// guessed at — a wrong address in a certificate description is worse than
/// an honest `iPAddress(3 bytes)`.
fn ip_address(v: &[u8]) -> String {
    match v.len() {
        4 => format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]),
        16 => {
            let groups: [u16; 8] =
                core::array::from_fn(|i| u16::from_be_bytes([v[2 * i], v[2 * i + 1]]));
            let (mut best_start, mut best_len) = (0usize, 0usize);
            let (mut run_start, mut run_len) = (0usize, 0usize);
            for (i, g) in groups.iter().enumerate() {
                if *g == 0 {
                    if run_len == 0 {
                        run_start = i;
                    }
                    run_len += 1;
                    // strictly longer, so an earlier run wins a tie (RFC 5952)
                    if run_len > best_len {
                        best_start = run_start;
                        best_len = run_len;
                    }
                } else {
                    run_len = 0;
                }
            }
            let mut out = String::new();
            let mut i = 0usize;
            while i < 8 {
                if best_len >= 2 && i == best_start {
                    out.push_str("::");
                    i += best_len;
                    continue;
                }
                if !out.is_empty() && !out.ends_with(':') {
                    out.push(':');
                }
                let _ = write!(out, "{:x}", groups[i]);
                i += 1;
            }
            out
        }
        n => format!("iPAddress({n} bytes)"),
    }
}

fn describe_cert(der: &[u8]) -> Result<String> {
    let mut top = DerIter::new(der);
    let cert = top.next().ok_or_else(|| rgx_core::anyhow!("empty DER"))??;
    if cert.tag != 0x30 {
        decline!("not a DER SEQUENCE (tag {:#x})", cert.tag);
    }
    let mut cert_fields = DerIter::new(cert.value);

    // tbsCertificate
    let tbs = cert_fields
        .next()
        .ok_or_else(|| rgx_core::anyhow!("missing tbsCertificate"))??;
    if tbs.tag != 0x30 {
        bail!("tbsCertificate is not a SEQUENCE");
    }
    let mut t = DerIter::new(tbs.value);

    // optional version [0] EXPLICIT
    let mut version = 1u8;
    let mut next = t
        .next()
        .ok_or_else(|| rgx_core::anyhow!("truncated tbs"))??;
    if next.tag == 0xA0 {
        if let Some(inner) = first_child(&next)? {
            let v = inner.value.first().copied().unwrap_or(0);
            version = v + 1;
        }
        next = t
            .next()
            .ok_or_else(|| rgx_core::anyhow!("truncated tbs"))??;
    }

    // serialNumber INTEGER
    if next.tag != 0x02 {
        bail!("expected serialNumber INTEGER, tag {:#x}", next.tag);
    }
    let serial = {
        let mut s = next.value;
        while s.len() > 1 && s[0] == 0 {
            s = &s[1..];
        }
        s.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let _sig_alg_in_tbs = t
        .next()
        .ok_or_else(|| rgx_core::anyhow!("truncated tbs"))??;

    // issuer Name
    let issuer_obj = t
        .next()
        .ok_or_else(|| rgx_core::anyhow!("truncated tbs"))??;
    let issuer = dn_to_string(issuer_obj.value);

    // validity SEQUENCE { UTCTime/GeneralizedTime, UTCTime/GeneralizedTime }
    let validity_obj = t
        .next()
        .ok_or_else(|| rgx_core::anyhow!("truncated tbs"))??;
    let mut v = DerIter::new(validity_obj.value);
    let nb = v
        .next()
        .ok_or_else(|| rgx_core::anyhow!("missing notBefore"))??;
    let na = v
        .next()
        .ok_or_else(|| rgx_core::anyhow!("missing notAfter"))??;
    let not_before = parse_time(nb)?;
    let not_after = parse_time(na)?;

    // subject Name
    let subject_obj = t
        .next()
        .ok_or_else(|| rgx_core::anyhow!("truncated tbs"))??;
    let subject = dn_to_string(subject_obj.value);

    // subjectPublicKeyInfo
    let spki = t
        .next()
        .ok_or_else(|| rgx_core::anyhow!("truncated tbs"))??;
    let mut spki_fields = DerIter::new(spki.value);
    let spki_alg = spki_fields
        .next()
        .ok_or_else(|| rgx_core::anyhow!("missing SPKI alg"))??;
    let spki_key = spki_fields
        .next()
        .ok_or_else(|| rgx_core::anyhow!("missing SPKI key"))??;
    let (pk_kind, pk_bits) = public_key_info(spki_alg, spki_key);

    // extensions [3] EXPLICIT (optional)
    let mut sans: Vec<String> = Vec::new();
    let mut is_ca = false;
    for field in t {
        let field = field?;
        if field.tag != 0xA3 {
            continue;
        }
        let Some(ext_seq) = first_child(&field)? else {
            continue;
        };
        for ext in DerIter::new(ext_seq.value) {
            let ext = ext?;
            let mut ef = DerIter::new(ext.value);
            let Some(Ok(oid)) = ef.next() else { continue };
            let Some(Ok(_crit)) = ef.next() else { continue };
            let Some(Ok(octets)) = ef.next() else {
                continue;
            };
            if octets.tag != 0x04 {
                continue;
            }
            if oid.value == OID_EXT_SAN {
                // extnValue OCTET STRING wraps a SEQUENCE OF GeneralName
                let names_src = match first_child(&octets)? {
                    Some(inner) => inner.value,
                    None => octets.value,
                };
                for name in DerIter::new(names_src) {
                    let name = name?;
                    // dNSName [2] and URI [6] are IA5Strings; iPAddress [7] is
                    // a bare 4- or 16-byte OCTET STRING, and `from_utf8` takes
                    // it happily — a zero address is twenty NULs, which is
                    // valid UTF-8 and is why a rendered certificate could
                    // carry a NUL into the searcher. Format the address, and
                    // hold the two text tags to printable ASCII.
                    match name.tag {
                        0x82 | 0x86 => {
                            if name.value.iter().all(|b| (0x20..0x7f).contains(b)) {
                                sans.push(String::from_utf8_lossy(name.value).into_owned());
                            }
                        }
                        0x87 => sans.push(ip_address(name.value)),
                        _ => {}
                    }
                }
            } else if oid.value == OID_EXT_BASIC_CONSTRAINTS {
                if let Some(seq) = first_child(&octets)? {
                    if let Some(Ok(b)) = DerIter::new(seq.value).next() {
                        if b.tag == 0x01 {
                            is_ca = b.value.first().copied().unwrap_or(0) != 0;
                        }
                    }
                }
            }
        }
    }

    let mut out = String::new();
    let _ = writeln!(out, "version: v{version}");
    let _ = writeln!(out, "serial: {serial}");
    let _ = writeln!(out, "subject: {subject}");
    let _ = writeln!(out, "issuer: {issuer}");
    let _ = writeln!(out, "not_before: {not_before}");
    let _ = writeln!(out, "not_after: {not_after}");
    let _ = writeln!(out, "public_key: {pk_kind}");
    let _ = writeln!(out, "public_key_bits: {pk_bits}");
    if !sans.is_empty() {
        let _ = writeln!(out, "san: {}", sans.join(", "));
    }
    let _ = writeln!(out, "ca: {is_ca}");
    Ok(out)
}

fn dn_to_string(raw: &[u8]) -> String {
    let mut parts: Vec<String> = Vec::new();
    // Name = SEQUENCE OF SET OF SEQUENCE { OID, value }
    for set in DerIter::new(raw).flatten() {
        for rdn in DerIter::new(set.value).flatten() {
            let mut attr = DerIter::new(rdn.value).flatten();
            let Some(oid) = attr.next() else { continue };
            let Some(value) = attr.next() else { continue };
            let name = match oid.value {
                OID_CN => "CN",
                OID_C => "C",
                OID_O => "O",
                OID_OU => "OU",
                OID_ST => "ST",
                OID_L => "L",
                OID_EMAIL => "email",
                _ => continue,
            };
            let v = String::from_utf8_lossy(value.value);
            parts.push(format!("{name}={v}"));
        }
    }
    parts.join(", ")
}

fn public_key_info(alg: Der, key: Der) -> (&'static str, usize) {
    // key is a BIT STRING: first byte = unused-bits count
    let bits = key.value.len().saturating_sub(1) * 8;
    let mut kind = "unknown";
    for f in DerIter::new(alg.value).flatten() {
        if f.tag == 0x06 {
            kind = match f.value {
                OID_RSA => "rsa",
                OID_EC => "ec",
                OID_ED25519 => "ed25519",
                _ => "unknown",
            };
            break;
        }
    }
    (kind, bits)
}

/// UTCTime `YYMMDDHHMMSSZ` or GeneralizedTime `YYYYMMDDHHMMSSZ` -> unix ts.
fn parse_time(obj: Der) -> Result<i64> {
    let b = obj.value;
    let nd = |r: &[u8]| -> Result<i64> {
        let mut v: i64 = 0;
        for &c in r {
            if !c.is_ascii_digit() {
                bail!("bad time digits");
            }
            v = v * 10 + (c - b'0') as i64;
        }
        Ok(v)
    };
    let (year, rest): (i64, &[u8]) = match obj.tag {
        0x17 => {
            if b.len() < 2 {
                bail!("UTCTime too short");
            }
            let yy = nd(&b[0..2])?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &b[2..])
        }
        0x18 => {
            if b.len() < 4 {
                bail!("GeneralizedTime too short");
            }
            (nd(&b[0..4])?, &b[4..])
        }
        _ => bail!("unexpected time tag {:#x}", obj.tag),
    };
    if rest.len() < 10 {
        bail!("time too short");
    }
    let mo = nd(&rest[0..2])?;
    let d = nd(&rest[2..4])?;
    let h = nd(&rest[4..6])?;
    let mi = nd(&rest[6..8])?;
    let sec = nd(&rest[8..10])?;
    Ok(ymd_hms_to_unix(year, mo, d, h, mi, sec))
}

fn ymd_hms_to_unix(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    let days = days_from_civil(y, mo, d);
    days * 86400 + h * 3600 + mi * 60 + s
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    // Howard Hinnant's days_from_civil
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- tiny DER encoder for fixtures ----
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = value.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push(len as u8);
        }
        out.extend_from_slice(value);
        out
    }
    fn seq(v: &[u8]) -> Vec<u8> {
        tlv(0x30, v)
    }
    fn set(v: &[u8]) -> Vec<u8> {
        tlv(0x31, v)
    }
    fn oid(v: &[u8]) -> Vec<u8> {
        tlv(0x06, v)
    }
    fn utf8(s: &str) -> Vec<u8> {
        tlv(0x0C, s.as_bytes())
    }
    fn printable(s: &str) -> Vec<u8> {
        tlv(0x13, s.as_bytes())
    }
    fn integer(v: &[u8]) -> Vec<u8> {
        tlv(0x02, v)
    }
    fn bitstr(v: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8];
        body.extend_from_slice(v);
        tlv(0x03, &body)
    }
    fn utc(s: &str) -> Vec<u8> {
        tlv(0x17, s.as_bytes())
    }

    fn dn(attrs: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (o, v) in attrs {
            let mut rdn = oid(o);
            rdn.extend_from_slice(v);
            body.extend_from_slice(&set(&seq(&rdn)));
        }
        seq(&body)
    }

    /// Build a minimal v3 self-signed-shaped certificate DER.
    fn mini_cert_der() -> Vec<u8> {
        mini_cert_der_with_sans(&[tlv(0x82, b"example.com")])
    }

    /// The same certificate, with the SAN extension carrying `names` as its
    /// `GeneralName` list instead of a single dNSName.
    fn mini_cert_der_with_sans(names: &[Vec<u8>]) -> Vec<u8> {
        // version [0] { INTEGER 2 }
        let version = tlv(0xA0, &integer(&[2]));
        let serial = integer(&[0x01, 0xAB]);
        // signature alg: sha256WithRSAEncryption — content only matters as a field
        let sig_alg = seq(&oid(&[
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ]));
        let issuer = dn(&[(OID_C, printable("US")), (OID_CN, utf8("Test CA"))]);
        let validity = seq(&[utc("230101120000Z"), utc("240101120000Z")].concat());
        let subject = dn(&[(OID_CN, utf8("example.com"))]);
        // SPKI: rsaEncryption + 256-byte BIT STRING (2048 bits)
        let spki_alg = seq(&oid(OID_RSA));
        let spki = seq(&[spki_alg, bitstr(&[0xAA; 256])].concat());
        // extensions [3] { SEQUENCE { SEQUENCE { OID SAN, BOOLEAN true, OCTET STRING { SEQUENCE { GeneralName... } } },
        //                          SEQUENCE { OID basicConstraints, BOOLEAN true, OCTET STRING { SEQUENCE { BOOLEAN true } } } } }
        let san_val = seq(&names.concat());
        let san_ext = seq(&[oid(OID_EXT_SAN), tlv(0x01, &[0xFF]), tlv(0x04, &san_val)].concat());
        let bc_val = seq(&tlv(0x01, &[0xFF]));
        let bc_ext = seq(&[
            oid(OID_EXT_BASIC_CONSTRAINTS),
            tlv(0x01, &[0xFF]),
            tlv(0x04, &bc_val),
        ]
        .concat());
        let mut ext_seq_body = san_ext;
        ext_seq_body.extend_from_slice(&bc_ext);
        let extensions = tlv(0xA3, &seq(&ext_seq_body));

        let mut tbs_body = version;
        tbs_body.extend_from_slice(&serial);
        tbs_body.extend_from_slice(&sig_alg);
        tbs_body.extend_from_slice(&issuer);
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(&subject);
        tbs_body.extend_from_slice(&spki);
        tbs_body.extend_from_slice(&extensions);
        let tbs = seq(&tbs_body);

        let mut cert_body = tbs;
        cert_body.extend_from_slice(&sig_alg);
        cert_body.extend_from_slice(&bitstr(&[0xCC; 32]));
        seq(&cert_body)
    }

    /// The rendering of a certificate is text, and a NUL in it was not
    /// cosmetic: `BinaryDetection::Quit` reports nothing at all once a NUL
    /// sits in the first 64 KiB, so the NULs of a zero-address SAN took the
    /// whole `.crt` out of `-c`, out of `-l` and out of the exit status, on
    /// files `rg` had counted. `iPAddress` is a bare OCTET STRING, so
    /// `from_utf8` accepted it and printed it verbatim.
    #[test]
    fn a_san_ip_address_is_an_address_and_never_a_nul() {
        let der = mini_cert_der_with_sans(&[
            tlv(0x82, b"example.com"),
            tlv(0x87, &[0; 16]),        // IPv6 loopback, sixteen NUL bytes
            tlv(0x87, &[127, 0, 0, 1]), // IPv4 loopback
        ]);
        let text = describe_cert(&der).unwrap();
        assert!(
            !text.contains('\0'),
            "a NUL reached the rendering:\n{text:?}"
        );
        assert!(text.contains("san: example.com, ::, 127.0.0.1"), "{text}");
    }

    /// A dNSName is IA5String, but a malformed one carrying control bytes
    /// must not become part of the rendering either — same NUL, same loss.
    #[test]
    fn a_san_name_holding_control_bytes_is_dropped() {
        let der = mini_cert_der_with_sans(&[tlv(0x82, b"a\0b\x01c")]);
        let text = describe_cert(&der).unwrap();
        assert!(!text.contains('\0'), "{text:?}");
        assert!(!text.contains('\x01'), "{text:?}");
    }

    #[test]
    fn ip_address_formats_both_families_and_reports_the_rest() {
        assert_eq!(ip_address(&[10, 1, 2, 3]), "10.1.2.3");
        assert_eq!(
            ip_address(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "2001:db8::1"
        );
        // the loopback a pattern is actually written against
        assert_eq!(
            ip_address(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            "::1"
        );
        // a single zero group is not a run, and stays written out
        assert_eq!(
            ip_address(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5]),
            "2001:db8:0:1:2:3:4:5"
        );
        // no zero groups at all
        assert_eq!(
            ip_address(&[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6]),
            "2001:db8:1:2:3:4:5:6"
        );
        assert_eq!(ip_address(&[1, 2, 3]), "iPAddress(3 bytes)");
    }

    #[test]
    fn parses_der_certificate() {
        let der = mini_cert_der();
        let text = describe_cert(&der).unwrap();
        assert!(text.contains("version: v3"), "{text}");
        assert!(text.contains("serial: 01:AB"), "{text}");
        assert!(text.contains("subject: CN=example.com"), "{text}");
        assert!(text.contains("issuer: C=US, CN=Test CA"), "{text}");
        assert!(text.contains("public_key: rsa"), "{text}");
        assert!(text.contains("public_key_bits: 2048"), "{text}");
        assert!(text.contains("san: example.com"), "{text}");
        assert!(text.contains("ca: true"), "{text}");
        // 2023-01-01 12:00:00 UTC
        assert!(text.contains("not_before: 1672574400"), "{text}");
        // 2024-01-01 12:00:00 UTC
        assert!(text.contains("not_after: 1704110400"), "{text}");
    }

    #[test]
    fn parses_pem_certificate() {
        let der = mini_cert_der();
        let b64 = |b: &[u8]| {
            const TBL: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in b.chunks(3) {
                let b0 = chunk[0] as u32;
                let b1 = *chunk.get(1).unwrap_or(&0) as u32;
                let b2 = *chunk.get(2).unwrap_or(&0) as u32;
                let n = (b0 << 16) | (b1 << 8) | b2;
                out.push(TBL[(n >> 18) as usize & 63] as char);
                out.push(TBL[(n >> 12) as usize & 63] as char);
                if chunk.len() > 1 {
                    out.push(TBL[(n >> 6) as usize & 63] as char);
                } else {
                    out.push('=');
                }
                if chunk.len() > 2 {
                    out.push(TBL[n as usize & 63] as char);
                } else {
                    out.push('=');
                }
            }
            out
        };
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            b64(&der)
        );
        match X509Cert.extract(pem.as_bytes(), "c.pem").unwrap() {
            Outcome::Text(t) => {
                let s = String::from_utf8(t).unwrap();
                assert!(s.contains("subject: CN=example.com"), "{s}");
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(X509Cert
            .extract(b"hello world, not a cert", "x.crt")
            .is_err());
        assert!(X509Cert
            .extract(
                b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
                "x.pem"
            )
            .is_err());
    }

    #[test]
    fn utc_time_rolls_century() {
        // 49 -> 2049, 50 -> 1950
        let t49 = parse_time(Der {
            tag: 0x17,
            value: b"490101000000Z",
        })
        .unwrap();
        let t50 = parse_time(Der {
            tag: 0x17,
            value: b"500101000000Z",
        })
        .unwrap();
        assert!(t49 > t50);
    }

    mod fuzz {
        use super::*;

        #[test]
        fn x509_never_panics_on_mutation() {
            rgx_core::fuzzkit::assert_never_panics(
                vec![
                    ("cert", mini_cert_der()),
                    ("pem-magic", b"-----BEGIN CERTIFICATE-----".to_vec()),
                    ("seq-only", vec![0x30, 0x03, 0x02, 0x01, 0x01]),
                    ("empty", vec![]),
                ],
                1500,
                "x509",
                |data| {
                    let _ = X509Cert.extract(data, "fuzz.crt");
                },
            );
        }
    }
}
