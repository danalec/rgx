// SPDX-License-Identifier: Apache-2.0

//! The name tokeniser codec of CRAM 3.1.
//!
//! The codec writes a block of read names as a set of token byte streams,
//! one per token position and token type, and reads them back.  A name is
//! compared with an earlier name, the one its first token names, and is
//! stored either as a series of differences to that name or as a mark that
//! it is an exact duplicate of it.
//!
//! The pseudocode this follows is section 5 of the "CRAM codec
//! specification" of the hts-specs repository, the document the CRAM 3.1
//! specification points at.  The frames the tests carry were written by the
//! reference implementation of that codec, the htscodecs library, and not by
//! this reader.
//!
//! The entropy coding of the token streams is not part of this module: the
//! streams are decoded by a callback, which is given the `use_arith` flag of
//! the frame and the compressed bytes of one stream.

use alloc::vec;
use alloc::vec::Vec;

/// The largest a decoded block may be.
///
/// The size comes from the frame itself, so a corrupt one could ask for a
/// gigabyte before it is refused.  The ceiling is the same one the other
/// decompressors of this crate use.
#[cfg(feature = "cram")]
const MAX_OUTPUT: usize = 32 << 20;

/// The number of token positions a name may have.
///
/// The specification permits a maximum of 128 tokens within any single read
/// name.
#[cfg(feature = "cram")]
const MAX_TOKENS: usize = 128;

/// The number of names a block may hold.
///
/// The reference implementation refuses a context with more than a million
/// names.
#[cfg(feature = "cram")]
const MAX_NAMES: usize = 1_000_000;

/// The token types of the specification.
///
/// The type of a token stream is the low six bits of its type byte; the two
/// top bits of that byte are the flags of the stream.
#[cfg(feature = "cram")]
mod ty {
    /// The type of the token at a position.
    pub const TYPE: u8 = 0;
    /// A nul terminated string.
    pub const STRING: u8 = 1;
    /// A single character.
    pub const CHAR: u8 = 2;
    /// A number that may carry leading zeros.
    pub const DIGITS0: u8 = 3;
    /// The length of the number of a DIGITS0 token.
    pub const DZLEN: u8 = 4;
    /// The name is a duplicate of an earlier one.
    pub const DUP: u8 = 5;
    /// The name differs from an earlier one.
    pub const DIFF: u8 = 6;
    /// A number.
    pub const DIGITS: u8 = 7;
    /// The difference to the number of the name before.
    pub const DELTA: u8 = 8;
    /// The difference to the number of the name before, leading zeros included.
    pub const DELTA0: u8 = 9;
    /// The token is the one of the name before.
    pub const MATCH: u8 = 10;
    /// The token holds nothing.
    pub const NOP: u8 = 11;
    /// The name ends here.
    pub const END: u8 = 12;
}

/// One token byte stream of the frame, and how far it has been read.
#[cfg(feature = "cram")]
#[derive(Clone)]
enum Stream {
    /// The bytes of a stream, and how many of them have been read.
    Bytes { data: Vec<u8>, at: usize },
    /// The stream of types that was left out of the frame.
    ///
    /// A stream of types that is all MATCH but for its first value may be
    /// left out of the frame.  It is regenerated as the type of the stream
    /// that opened the position, followed by a match for every name that
    /// reads it.
    Types { kind: u8, at: usize },
}

/// The value of one token of a name.
///
/// The specification keeps the tokens of the names decoded so far in a two
/// dimensional array, so that a MATCH or a DELTA token can copy from the
/// name it names.  This is that array, with the names one after the other.
#[cfg(feature = "cram")]
#[derive(Clone, Copy)]
enum Token {
    /// A token with no value: the NOP token, and the end of a name.
    Empty,
    /// A single character.
    Char(u8),
    /// A string, as the place it starts in the output and its length.
    Str { at: usize, len: usize },
    /// A number.
    Digits(u32),
    /// A number that may carry leading zeros, with the length it is written
    /// with.
    Digits0 { value: u32, len: u8 },
}

/// Where the bytes and the tokens of one name are.
#[cfg(feature = "cram")]
struct Name {
    /// Where the bytes of the name start in the output.
    at: usize,
    /// The length of the name, its terminating nul byte included.
    len: usize,
    /// The first token of the name in the token vector.
    first: usize,
    /// The number of tokens of the name.
    tokens: usize,
}

/// The decoder of one token stream.
///
/// It is given the `use_arith` flag of the frame and the compressed bytes
/// of the stream, and answers the bytes of the stream, or `None` when it
/// cannot.
#[cfg(feature = "cram")]
pub(crate) type Entropy<'a> = dyn Fn(bool, &[u8]) -> Option<Vec<u8>> + 'a;

/// Decode a block of read names that was written with the name tokeniser
/// codec of CRAM 3.1.
///
/// The `entropy` callback decodes one token stream: it is given the
/// `use_arith` flag of the frame and the compressed bytes of the stream, and
/// answers the bytes of the stream, or `None` when it cannot.
///
/// The names are answered one after the other, each one terminated by a nul
/// byte, as the reference decoder does.
///
/// `None` is answered when the frame is not one this reader can decode; the
/// reasons are named in the comments of the code.
#[cfg(feature = "cram")]
pub(crate) fn decode(block: &[u8], entropy: &Entropy<'_>) -> Option<Vec<u8>> {
    let (num_reads, limit, mut streams) = read_streams(block, entropy)?;
    decode_names(num_reads, limit, &mut streams)
}

/// Read the header of a frame and the token streams it holds.
///
/// The token streams are indexed by the token position and the token type.
#[cfg(feature = "cram")]
fn read_streams(
    block: &[u8],
    entropy: &Entropy<'_>,
) -> Option<(usize, usize, Vec<Option<Stream>>)> {
    // The header: the size of the uncompressed name buffer, the number of
    // names, and the flag that says which entropy coder wrote the streams.
    let mut at = 0usize;
    let limit = read_u32(block, &mut at)? as usize;
    let num_reads = read_u32(block, &mut at)? as usize;
    let use_arith = *block.get(at)?;
    at += 1;

    // The size comes from the frame, so a corrupt one could ask for a
    // gigabyte before it is refused.
    if limit > MAX_OUTPUT {
        return None;
    }
    // The reference implementation refuses a context with more than a
    // million names.
    if num_reads > MAX_NAMES {
        return None;
    }

    // The token streams, indexed by the position and the type.
    let mut streams: Vec<Option<Stream>> = vec![None; MAX_TOKENS * 16];
    // The position of the tokens, which starts before the first one.
    let mut position: i32 = -1;
    while at < block.len() {
        // The type byte of the stream: the type in the low six bits, and the
        // two flags in the top bits.
        let ttype = block[at];
        at += 1;
        let new_position = ttype & 128 != 0;
        let duplicate = ttype & 64 != 0;
        let kind = ttype & 63;
        if kind > ty::END {
            // A token type that is not one of the thirteen.
            return None;
        }
        if new_position {
            position += 1;
            if position as usize >= MAX_TOKENS {
                // A name may not have more than 128 tokens.
                return None;
            }
        }
        if position < 0 {
            // The first stream of a frame opens the first position.
            return None;
        }
        let position = position as usize;
        if duplicate {
            // The stream is a copy of an earlier one: the two bytes say
            // which position and which type it copies.
            let from_position = *block.get(at)? as usize;
            let from_kind = *block.get(at + 1)? as usize;
            at += 2;
            if from_kind > ty::END as usize {
                // The type it copies is not one of the thirteen.
                return None;
            }
            let from = from_position * 16 + from_kind;
            let to = position * 16 + kind as usize;
            if from >= to {
                // A stream may only copy one that comes before it.
                return None;
            }
            let data = match streams.get(from)?.as_ref()? {
                Stream::Bytes { data, .. } => data.clone(),
                // The stream of types that was regenerated is not in the
                // frame, so there is nothing to copy.
                Stream::Types { .. } => return None,
            };
            streams[to] = Some(Stream::Bytes { data, at: 0 });
        } else {
            // The stream is a compressed byte stream: a uint7 length and
            // that many bytes, which the entropy coder decodes.
            let len = read_uint7(block, &mut at)? as usize;
            let end = at.checked_add(len)?;
            if end > block.len() {
                // The stream runs past the end of the frame.
                return None;
            }
            let data = entropy(use_arith != 0, &block[at..end])?;
            at = end;
            streams[position * 16 + kind as usize] = Some(Stream::Bytes { data, at: 0 });
        }
        if new_position && kind != ty::TYPE {
            // A stream of types that is all MATCH but for its first value
            // may be left out of the frame; it is regenerated here.
            streams[position * 16 + ty::TYPE as usize] = Some(Stream::Types { kind, at: 0 });
        }
    }
    Some((num_reads, limit, streams))
}

/// Decode the names of a frame.
#[cfg(feature = "cram")]
fn decode_names(num_reads: usize, limit: usize, streams: &mut [Option<Stream>]) -> Option<Vec<u8>> {
    // The names, one after the other, each one terminated by a nul byte.
    let mut out: Vec<u8> = Vec::with_capacity(limit);
    // The tokens of the names, one name after the other.
    let mut tokens: Vec<Token> = Vec::new();
    // Where the names are.
    let mut names: Vec<Name> = Vec::with_capacity(num_reads);

    for n in 0..num_reads {
        // The type at the first position says whether the name is a
        // duplicate of an earlier one or a difference to one.
        let kind = take_type(streams, 0)?;
        if kind != ty::DUP && kind != ty::DIFF {
            // The first position holds only the duplicate and the difference
            // marks.
            return None;
        }
        // The distance says how many names back the name is compared with.
        let dist = take_u32(streams, 0, kind)? as usize;
        if dist > n {
            // The distance points before the first name.
            return None;
        }
        // A distance of zero points at the name itself, so there is no name
        // to copy from: the reference implementation writes such a distance
        // when the names share no punctuation, and its decoder then builds
        // the name from its own tokens alone.
        let m = n - dist;
        if kind == ty::DUP {
            if dist == 0 {
                // A name cannot be a duplicate of itself.
                return None;
            }
            // The name is the one it names, byte for byte.
            let previous = names.get(m)?;
            let len = previous.len;
            let start = previous.at;
            if out.len() + len > limit {
                // The name does not fit the size the frame declares.
                return None;
            }
            let at = out.len();
            out.resize(at + len, 0);
            let (head, tail) = out.split_at_mut(at);
            let bytes = head.get(start..start + len)?;
            tail[..len].copy_from_slice(bytes);
            names.push(Name {
                at,
                len: previous.len,
                first: previous.first,
                tokens: previous.tokens,
            });
            continue;
        }
        // The name is a difference to the name it names, and is built from
        // its tokens, one per position.
        let at = out.len();
        let first = tokens.len();
        let mut position = 1usize;
        loop {
            if position >= MAX_TOKENS {
                // A name may not have more than 128 tokens.
                return None;
            }
            let kind = take_type(streams, position)?;
            match kind {
                ty::CHAR => {
                    // A single character.
                    let byte = take_byte(streams, position, ty::CHAR)?;
                    append(&mut out, limit, &[byte])?;
                    tokens.push(Token::Char(byte));
                }
                ty::STRING => {
                    // A nul terminated string; the nul is not part of the
                    // name.
                    let (start, len) = take_string(streams, position, ty::STRING, &mut out, limit)?;
                    tokens.push(Token::Str { at: start, len });
                }
                ty::DIGITS => {
                    // A number, written as base ten digits.
                    let value = take_u32(streams, position, ty::DIGITS)?;
                    let mut digits = [0u8; 10];
                    let len = write_decimal(&mut digits, value);
                    append(&mut out, limit, &digits[..len])?;
                    tokens.push(Token::Digits(value));
                }
                ty::DIGITS0 => {
                    // A number and the length it is written with; the
                    // length is the size of the number in base ten, the
                    // leading zeros included.
                    let value = take_u32(streams, position, ty::DIGITS0)?;
                    let len = take_byte(streams, position, ty::DZLEN)?;
                    let mut text = [0u8; 255];
                    let len = write_padded(&mut text, value, len)?;
                    append(&mut out, limit, &text[..len])?;
                    tokens.push(Token::Digits0 {
                        value,
                        len: len as u8,
                    });
                }
                ty::DELTA => {
                    // A byte added to the number of the name before.
                    let delta = take_byte(streams, position, ty::DELTA)?;
                    let previous = token_of(&names, &tokens, m, position)?;
                    let value = match previous {
                        Token::Digits(value) => value,
                        // The specification says the token of the name before
                        // must be a number.
                        _ => return None,
                    };
                    let value = value.checked_add(u32::from(delta))?;
                    let mut digits = [0u8; 10];
                    let len = write_decimal(&mut digits, value);
                    append(&mut out, limit, &digits[..len])?;
                    tokens.push(Token::Digits(value));
                }
                ty::DELTA0 => {
                    // As DELTA, for a number with leading zeros; the length
                    // is the one of the name before.
                    let delta = take_byte(streams, position, ty::DELTA0)?;
                    let previous = token_of(&names, &tokens, m, position)?;
                    let (value, len) = match previous {
                        Token::Digits0 { value, len } => (value, len),
                        // The specification says the token of the name before
                        // must be a number with leading zeros.
                        _ => return None,
                    };
                    let value = value.checked_add(u32::from(delta))?;
                    let mut text = [0u8; 255];
                    let width = write_padded(&mut text, value, len)?;
                    append(&mut out, limit, &text[..width])?;
                    tokens.push(Token::Digits0 { value, len });
                }
                ty::MATCH => {
                    // The token of the name before, as it is.
                    //
                    // The specification allows a match only against a
                    // character, a string, a number or a number with leading
                    // zeros.  The reference implementation stores a delta as
                    // the number it adds up to, so a match against a delta
                    // is a match against a number there, and its encoder
                    // writes such frames.
                    let previous = token_of(&names, &tokens, m, position)?;
                    match previous {
                        Token::Char(byte) => {
                            append(&mut out, limit, &[byte])?;
                            tokens.push(Token::Char(byte));
                        }
                        Token::Str { at: start, len } => {
                            // The string, byte for byte.
                            if out.len() + len > limit {
                                // The string does not fit the size the frame
                                // declares.
                                return None;
                            }
                            let at = out.len();
                            out.resize(at + len, 0);
                            let (head, tail) = out.split_at_mut(at);
                            let bytes = head.get(start..start + len)?;
                            tail[..len].copy_from_slice(bytes);
                            tokens.push(Token::Str { at, len });
                        }
                        Token::Digits(value) => {
                            let mut digits = [0u8; 10];
                            let len = write_decimal(&mut digits, value);
                            append(&mut out, limit, &digits[..len])?;
                            tokens.push(Token::Digits(value));
                        }
                        Token::Digits0 { value, len } => {
                            let mut text = [0u8; 255];
                            let width = write_padded(&mut text, value, len)?;
                            append(&mut out, limit, &text[..width])?;
                            tokens.push(Token::Digits0 { value, len });
                        }
                        // The specification does not allow a match against a
                        // token that holds nothing.
                        Token::Empty => return None,
                    }
                }
                ty::NOP => {
                    // The token holds nothing, but it uses its position, so
                    // that the positions of the names stay in step.
                    tokens.push(Token::Empty);
                }
                ty::END => {
                    // The name ends with a nul byte.
                    append(&mut out, limit, &[0])?;
                    break;
                }
                // The type mark is not a token, and the duplicate and the
                // difference marks are only for the first position.
                _ => return None,
            }
            position += 1;
        }
        names.push(Name {
            at,
            len: out.len() - at,
            first,
            tokens: tokens.len() - first,
        });
    }
    Some(out)
}

/// The token at a position of an earlier name.
///
/// The tokens of a name are the ones of the positions from the first one
/// onwards, so the token of a position is the one before it in the list.
#[cfg(feature = "cram")]
fn token_of(names: &[Name], tokens: &[Token], n: usize, position: usize) -> Option<Token> {
    let name = names.get(n)?;
    if position == 0 || position > name.tokens {
        // The name has no token at that position.
        return None;
    }
    tokens.get(name.first + position - 1).copied()
}

/// Take the type of the token at a position from the stream of types.
///
/// A type that is not one of the thirteen of the specification is refused.
#[cfg(feature = "cram")]
fn take_type(streams: &mut [Option<Stream>], position: usize) -> Option<u8> {
    let stream = streams
        .get_mut(position * 16 + ty::TYPE as usize)?
        .as_mut()?;
    match stream {
        Stream::Bytes { data, at } => {
            let kind = *data.get(*at)?;
            *at += 1;
            if kind > ty::END {
                return None;
            }
            Some(kind)
        }
        Stream::Types { kind, at } => {
            // The first name that reads the position takes the type of the
            // stream that opened it, and the names after it match.
            let value = if *at == 0 { *kind } else { ty::MATCH };
            *at += 1;
            Some(value)
        }
    }
}

/// Take one byte from a token stream.
#[cfg(feature = "cram")]
fn take_byte(streams: &mut [Option<Stream>], position: usize, kind: u8) -> Option<u8> {
    let stream = streams.get_mut(position * 16 + kind as usize)?.as_mut()?;
    match stream {
        Stream::Bytes { data, at } => {
            let byte = *data.get(*at)?;
            *at += 1;
            Some(byte)
        }
        // Only the stream of types is ever regenerated.
        Stream::Types { .. } => None,
    }
}

/// Take a little endian 32 bit number from a token stream.
#[cfg(feature = "cram")]
fn take_u32(streams: &mut [Option<Stream>], position: usize, kind: u8) -> Option<u32> {
    let stream = streams.get_mut(position * 16 + kind as usize)?.as_mut()?;
    match stream {
        Stream::Bytes { data, at } => {
            let bytes = data.get(*at..*at + 4)?;
            *at += 4;
            Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }
        // Only the stream of types is ever regenerated.
        Stream::Types { .. } => None,
    }
}

/// Take a nul terminated string from a token stream and append it to the
/// name buffer.
///
/// The terminating nul is not part of the name, and a string that is not
/// terminated is refused.
#[cfg(feature = "cram")]
fn take_string(
    streams: &mut [Option<Stream>],
    position: usize,
    kind: u8,
    out: &mut Vec<u8>,
    limit: usize,
) -> Option<(usize, usize)> {
    let stream = streams.get_mut(position * 16 + kind as usize)?.as_mut()?;
    let Stream::Bytes { data, at: cursor } = stream else {
        // Only the stream of types is ever regenerated.
        return None;
    };
    let start = *cursor;
    let mut end = start;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    if end == data.len() {
        // The string is not terminated.
        return None;
    }
    let len = end - start;
    if out.len() + len > limit {
        return None;
    }
    let at = out.len();
    out.extend_from_slice(&data[start..end]);
    *cursor = end + 1;
    Some((at, len))
}

/// Append bytes to the name buffer, keeping it within the size the frame
/// declares.
#[cfg(feature = "cram")]
fn append(out: &mut Vec<u8>, limit: usize, bytes: &[u8]) -> Option<()> {
    if out.len() + bytes.len() > limit {
        return None;
    }
    out.extend_from_slice(bytes);
    Some(())
}

/// Write the base ten digits of a number, most significant digit first, and
/// answer how many bytes they take.
#[cfg(feature = "cram")]
fn write_decimal(out: &mut [u8; 10], value: u32) -> usize {
    let mut digits = [0u8; 10];
    let mut at = 10;
    let mut value = value;
    loop {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let len = 10 - at;
    out[..len].copy_from_slice(&digits[at..]);
    len
}

/// Write the base ten digits of a number, left padded with zeros to the
/// length the frame gives.
///
/// The specification says the length is the size of the number in base ten,
/// the leading zeros included, so a length of zero, or one shorter than the
/// number of digits, is refused.
#[cfg(feature = "cram")]
fn write_padded(out: &mut [u8; 255], value: u32, len: u8) -> Option<usize> {
    let mut digits = [0u8; 10];
    let mut at = 10;
    let mut value = value;
    loop {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let count = 10 - at;
    let len = len as usize;
    if len == 0 || len < count {
        return None;
    }
    for byte in out.iter_mut().take(len - count) {
        *byte = b'0';
    }
    out[len - count..len].copy_from_slice(&digits[at..]);
    Some(len)
}

/// Read a little endian 32 bit number.
#[cfg(feature = "cram")]
fn read_u32(block: &[u8], at: &mut usize) -> Option<u32> {
    let bytes = block.get(*at..*at + 4)?;
    *at += 4;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a uint7: seven bits a byte, the most significant group first, with
/// the top bit set on every byte but the last.
///
/// A number that does not fit a 32 bit integer is refused.
#[cfg(feature = "cram")]
fn read_uint7(block: &[u8], at: &mut usize) -> Option<u32> {
    let mut value: u32 = 0;
    for _ in 0..5 {
        let byte = *block.get(*at)?;
        *at += 1;
        value = value
            .checked_mul(128)?
            .checked_add(u32::from(byte & 0x7f))?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    // Five groups are enough for a 32 bit number.
    None
}

#[cfg(all(test, feature = "cram"))]
/// The frame of the example of the specification, written by the
/// reference implementation of the codec.
pub(crate) const SPEC_FRAME: &[u8] = &[
    0x59, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x80, 0x05, 0xa0, 0x03, 0x01, 0x06, 0x00,
    0x06, 0x0e, 0x20, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x81, 0x14, 0xa0, 0x0b, 0x0a, 0x00, 0x30, 0x31, 0x35, 0x36, 0x37, 0x38, 0x3a, 0x49, 0x5f, 0x06,
    0x28, 0x95, 0x61, 0x45, 0x73, 0x00, 0x87, 0x06, 0x20, 0x04, 0x02, 0x00, 0x00, 0x00, 0x82, 0x03,
    0x20, 0x01, 0x3a, 0x80, 0x08, 0xa0, 0x03, 0x03, 0x07, 0x08, 0x0a, 0x01, 0x18, 0x07, 0x06, 0x20,
    0x04, 0x7b, 0x00, 0x00, 0x00, 0x08, 0x03, 0x20, 0x01, 0x01, 0x82, 0x03, 0x20, 0x01, 0x3a, 0x80,
    0x05, 0xa0, 0x03, 0x01, 0x07, 0x00, 0x07, 0x0e, 0x20, 0x0c, 0x65, 0xf0, 0x00, 0x00, 0x64, 0x06,
    0x00, 0x00, 0x2d, 0xb2, 0x00, 0x00, 0x82, 0x03, 0x20, 0x01, 0x3a, 0x80, 0x05, 0xa0, 0x03, 0x01,
    0x03, 0x00, 0x03, 0x0e, 0x20, 0x0c, 0xe3, 0x06, 0x00, 0x00, 0xa3, 0x21, 0x00, 0x00, 0x21, 0x3f,
    0x00, 0x00, 0x04, 0x05, 0x20, 0x03, 0x05, 0x05, 0x05, 0x82, 0x03, 0x20, 0x01, 0x23, 0x87, 0x06,
    0x20, 0x04, 0x09, 0x00, 0x00, 0x00, 0x80, 0x05, 0xa0, 0x03, 0x01, 0x0c, 0x00,
];

#[cfg(all(test, feature = "cram"))]
/// The names the reference implementation decodes the frame of the
/// example into.
pub(crate) const SPEC_NAMES: &[u8] = &[
    0x49, 0x31, 0x37, 0x5f, 0x30, 0x38, 0x37, 0x36, 0x35, 0x3a, 0x32, 0x3a, 0x31, 0x32, 0x33, 0x3a,
    0x36, 0x31, 0x35, 0x34, 0x31, 0x3a, 0x30, 0x31, 0x37, 0x36, 0x33, 0x23, 0x39, 0x00, 0x49, 0x31,
    0x37, 0x5f, 0x30, 0x38, 0x37, 0x36, 0x35, 0x3a, 0x32, 0x3a, 0x31, 0x32, 0x33, 0x3a, 0x31, 0x36,
    0x33, 0x36, 0x3a, 0x30, 0x38, 0x36, 0x31, 0x31, 0x23, 0x39, 0x00, 0x49, 0x31, 0x37, 0x5f, 0x30,
    0x38, 0x37, 0x36, 0x35, 0x3a, 0x32, 0x3a, 0x31, 0x32, 0x34, 0x3a, 0x34, 0x35, 0x36, 0x31, 0x33,
    0x3a, 0x31, 0x36, 0x31, 0x36, 0x31, 0x23, 0x39, 0x00,
];

#[cfg(all(test, feature = "cram"))]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};

    /// The streams of the frame of the example: the bytes the frame carries
    /// and the bytes the reference implementation decodes them into.
    const SPEC_STREAMS: &[(&[u8], &[u8])] = &[
        (&[0xa0, 0x03, 0x01, 0x06, 0x00], &[0x06, 0x06, 0x06]),
        (
            &[
                0x20, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            ],
            &[
                0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            ],
        ),
        (
            &[
                0xa0, 0x0b, 0x0a, 0x00, 0x30, 0x31, 0x35, 0x36, 0x37, 0x38, 0x3a, 0x49, 0x5f, 0x06,
                0x28, 0x95, 0x61, 0x45, 0x73, 0x00,
            ],
            &[
                0x49, 0x31, 0x37, 0x5f, 0x30, 0x38, 0x37, 0x36, 0x35, 0x3a, 0x00,
            ],
        ),
        (
            &[0x20, 0x04, 0x02, 0x00, 0x00, 0x00],
            &[0x02, 0x00, 0x00, 0x00],
        ),
        (&[0x20, 0x01, 0x3a], &[0x3a]),
        (
            &[0xa0, 0x03, 0x03, 0x07, 0x08, 0x0a, 0x01, 0x18],
            &[0x07, 0x0a, 0x08],
        ),
        (
            &[0x20, 0x04, 0x7b, 0x00, 0x00, 0x00],
            &[0x7b, 0x00, 0x00, 0x00],
        ),
        (&[0x20, 0x01, 0x01], &[0x01]),
        (&[0x20, 0x01, 0x3a], &[0x3a]),
        (&[0xa0, 0x03, 0x01, 0x07, 0x00], &[0x07, 0x07, 0x07]),
        (
            &[
                0x20, 0x0c, 0x65, 0xf0, 0x00, 0x00, 0x64, 0x06, 0x00, 0x00, 0x2d, 0xb2, 0x00, 0x00,
            ],
            &[
                0x65, 0xf0, 0x00, 0x00, 0x64, 0x06, 0x00, 0x00, 0x2d, 0xb2, 0x00, 0x00,
            ],
        ),
        (&[0x20, 0x01, 0x3a], &[0x3a]),
        (&[0xa0, 0x03, 0x01, 0x03, 0x00], &[0x03, 0x03, 0x03]),
        (
            &[
                0x20, 0x0c, 0xe3, 0x06, 0x00, 0x00, 0xa3, 0x21, 0x00, 0x00, 0x21, 0x3f, 0x00, 0x00,
            ],
            &[
                0xe3, 0x06, 0x00, 0x00, 0xa3, 0x21, 0x00, 0x00, 0x21, 0x3f, 0x00, 0x00,
            ],
        ),
        (&[0x20, 0x03, 0x05, 0x05, 0x05], &[0x05, 0x05, 0x05]),
        (&[0x20, 0x01, 0x23], &[0x23]),
        (
            &[0x20, 0x04, 0x09, 0x00, 0x00, 0x00],
            &[0x09, 0x00, 0x00, 0x00],
        ),
        (&[0xa0, 0x03, 0x01, 0x0c, 0x00], &[0x0c, 0x0c, 0x0c]),
    ];

    /// A frame with a name that is an exact duplicate of an earlier one.
    const DUP_FRAME: &[u8] = &[
        0x77, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x80, 0x07, 0xa0, 0x04, 0x02, 0x05,
        0x06, 0x01, 0x07, 0x05, 0x06, 0x20, 0x04, 0x03, 0x00, 0x00, 0x00, 0x06, 0x0e, 0x20, 0x0c,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x81, 0x14, 0xa0,
        0x0b, 0x0a, 0x00, 0x30, 0x31, 0x35, 0x36, 0x37, 0x38, 0x3a, 0x49, 0x5f, 0x06, 0x28, 0x95,
        0x61, 0x45, 0x73, 0x00, 0x87, 0x06, 0x20, 0x04, 0x02, 0x00, 0x00, 0x00, 0x82, 0x03, 0x20,
        0x01, 0x3a, 0x80, 0x08, 0xa0, 0x03, 0x03, 0x07, 0x08, 0x0a, 0x01, 0x18, 0x07, 0x06, 0x20,
        0x04, 0x7b, 0x00, 0x00, 0x00, 0x08, 0x03, 0x20, 0x01, 0x01, 0x82, 0x03, 0x20, 0x01, 0x3a,
        0x80, 0x05, 0xa0, 0x03, 0x01, 0x07, 0x00, 0x07, 0x0e, 0x20, 0x0c, 0x65, 0xf0, 0x00, 0x00,
        0x64, 0x06, 0x00, 0x00, 0x2d, 0xb2, 0x00, 0x00, 0x82, 0x03, 0x20, 0x01, 0x3a, 0x80, 0x05,
        0xa0, 0x03, 0x01, 0x03, 0x00, 0x03, 0x0e, 0x20, 0x0c, 0xe3, 0x06, 0x00, 0x00, 0xa3, 0x21,
        0x00, 0x00, 0x21, 0x3f, 0x00, 0x00, 0x04, 0x05, 0x20, 0x03, 0x05, 0x05, 0x05, 0x82, 0x03,
        0x20, 0x01, 0x23, 0x87, 0x06, 0x20, 0x04, 0x09, 0x00, 0x00, 0x00, 0x80, 0x05, 0xa0, 0x03,
        0x01, 0x0c, 0x00,
    ];

    /// The streams of the frame with the duplicate name.
    const DUP_STREAMS: &[(&[u8], &[u8])] = &[
        (
            &[0xa0, 0x04, 0x02, 0x05, 0x06, 0x01, 0x07],
            &[0x06, 0x06, 0x06, 0x05],
        ),
        (
            &[0x20, 0x04, 0x03, 0x00, 0x00, 0x00],
            &[0x03, 0x00, 0x00, 0x00],
        ),
        (
            &[
                0x20, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            ],
            &[
                0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            ],
        ),
        (
            &[
                0xa0, 0x0b, 0x0a, 0x00, 0x30, 0x31, 0x35, 0x36, 0x37, 0x38, 0x3a, 0x49, 0x5f, 0x06,
                0x28, 0x95, 0x61, 0x45, 0x73, 0x00,
            ],
            &[
                0x49, 0x31, 0x37, 0x5f, 0x30, 0x38, 0x37, 0x36, 0x35, 0x3a, 0x00,
            ],
        ),
        (
            &[0x20, 0x04, 0x02, 0x00, 0x00, 0x00],
            &[0x02, 0x00, 0x00, 0x00],
        ),
        (&[0x20, 0x01, 0x3a], &[0x3a]),
        (
            &[0xa0, 0x03, 0x03, 0x07, 0x08, 0x0a, 0x01, 0x18],
            &[0x07, 0x0a, 0x08],
        ),
        (
            &[0x20, 0x04, 0x7b, 0x00, 0x00, 0x00],
            &[0x7b, 0x00, 0x00, 0x00],
        ),
        (&[0x20, 0x01, 0x01], &[0x01]),
        (&[0x20, 0x01, 0x3a], &[0x3a]),
        (&[0xa0, 0x03, 0x01, 0x07, 0x00], &[0x07, 0x07, 0x07]),
        (
            &[
                0x20, 0x0c, 0x65, 0xf0, 0x00, 0x00, 0x64, 0x06, 0x00, 0x00, 0x2d, 0xb2, 0x00, 0x00,
            ],
            &[
                0x65, 0xf0, 0x00, 0x00, 0x64, 0x06, 0x00, 0x00, 0x2d, 0xb2, 0x00, 0x00,
            ],
        ),
        (&[0x20, 0x01, 0x3a], &[0x3a]),
        (&[0xa0, 0x03, 0x01, 0x03, 0x00], &[0x03, 0x03, 0x03]),
        (
            &[
                0x20, 0x0c, 0xe3, 0x06, 0x00, 0x00, 0xa3, 0x21, 0x00, 0x00, 0x21, 0x3f, 0x00, 0x00,
            ],
            &[
                0xe3, 0x06, 0x00, 0x00, 0xa3, 0x21, 0x00, 0x00, 0x21, 0x3f, 0x00, 0x00,
            ],
        ),
        (&[0x20, 0x03, 0x05, 0x05, 0x05], &[0x05, 0x05, 0x05]),
        (&[0x20, 0x01, 0x23], &[0x23]),
        (
            &[0x20, 0x04, 0x09, 0x00, 0x00, 0x00],
            &[0x09, 0x00, 0x00, 0x00],
        ),
        (&[0xa0, 0x03, 0x01, 0x0c, 0x00], &[0x0c, 0x0c, 0x0c]),
    ];

    /// The names the reference implementation decodes the frame with the
    /// duplicate name into.
    const DUP_NAMES: &[u8] = &[
        0x49, 0x31, 0x37, 0x5f, 0x30, 0x38, 0x37, 0x36, 0x35, 0x3a, 0x32, 0x3a, 0x31, 0x32, 0x33,
        0x3a, 0x36, 0x31, 0x35, 0x34, 0x31, 0x3a, 0x30, 0x31, 0x37, 0x36, 0x33, 0x23, 0x39, 0x00,
        0x49, 0x31, 0x37, 0x5f, 0x30, 0x38, 0x37, 0x36, 0x35, 0x3a, 0x32, 0x3a, 0x31, 0x32, 0x33,
        0x3a, 0x31, 0x36, 0x33, 0x36, 0x3a, 0x30, 0x38, 0x36, 0x31, 0x31, 0x23, 0x39, 0x00, 0x49,
        0x31, 0x37, 0x5f, 0x30, 0x38, 0x37, 0x36, 0x35, 0x3a, 0x32, 0x3a, 0x31, 0x32, 0x34, 0x3a,
        0x34, 0x35, 0x36, 0x31, 0x33, 0x3a, 0x31, 0x36, 0x31, 0x36, 0x31, 0x23, 0x39, 0x00, 0x49,
        0x31, 0x37, 0x5f, 0x30, 0x38, 0x37, 0x36, 0x35, 0x3a, 0x32, 0x3a, 0x31, 0x32, 0x33, 0x3a,
        0x36, 0x31, 0x35, 0x34, 0x31, 0x3a, 0x30, 0x31, 0x37, 0x36, 0x33, 0x23, 0x39, 0x00,
    ];

    /// A frame whose token streams were written with the arithmetic coder.
    const ARITH_FRAME: &[u8] = &[
        0x59, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x80, 0x05, 0xa0, 0x03, 0x01, 0x06,
        0x00, 0x06, 0x09, 0x00, 0x0c, 0x02, 0x00, 0x72, 0x16, 0xb3, 0x22, 0x06, 0x81, 0x14, 0xa0,
        0x0b, 0x0a, 0x00, 0x30, 0x31, 0x35, 0x36, 0x37, 0x38, 0x3a, 0x49, 0x5f, 0x06, 0x28, 0x95,
        0x61, 0x45, 0x73, 0x00, 0x87, 0x06, 0x20, 0x04, 0x02, 0x00, 0x00, 0x00, 0x82, 0x03, 0x20,
        0x01, 0x3a, 0x80, 0x08, 0xa0, 0x03, 0x03, 0x07, 0x08, 0x0a, 0x01, 0x18, 0x07, 0x06, 0x20,
        0x04, 0x7b, 0x00, 0x00, 0x00, 0x08, 0x03, 0x20, 0x01, 0x01, 0x82, 0x03, 0x20, 0x01, 0x3a,
        0x80, 0x05, 0xa0, 0x03, 0x01, 0x07, 0x00, 0x07, 0x0e, 0x20, 0x0c, 0x65, 0xf0, 0x00, 0x00,
        0x64, 0x06, 0x00, 0x00, 0x2d, 0xb2, 0x00, 0x00, 0x82, 0x03, 0x20, 0x01, 0x3a, 0x80, 0x05,
        0xa0, 0x03, 0x01, 0x03, 0x00, 0x03, 0x0e, 0x20, 0x0c, 0xe3, 0x06, 0x00, 0x00, 0xa3, 0x21,
        0x00, 0x00, 0x21, 0x3f, 0x00, 0x00, 0x04, 0x05, 0x20, 0x03, 0x05, 0x05, 0x05, 0x82, 0x03,
        0x20, 0x01, 0x23, 0x87, 0x06, 0x20, 0x04, 0x09, 0x00, 0x00, 0x00, 0x80, 0x05, 0xa0, 0x03,
        0x01, 0x0c, 0x00,
    ];

    /// The streams of the frame written with the arithmetic coder.
    const ARITH_STREAMS: &[(&[u8], &[u8])] = &[
        (&[0xa0, 0x03, 0x01, 0x06, 0x00], &[0x06, 0x06, 0x06]),
        (
            &[0x00, 0x0c, 0x02, 0x00, 0x72, 0x16, 0xb3, 0x22, 0x06],
            &[
                0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            ],
        ),
        (
            &[
                0xa0, 0x0b, 0x0a, 0x00, 0x30, 0x31, 0x35, 0x36, 0x37, 0x38, 0x3a, 0x49, 0x5f, 0x06,
                0x28, 0x95, 0x61, 0x45, 0x73, 0x00,
            ],
            &[
                0x49, 0x31, 0x37, 0x5f, 0x30, 0x38, 0x37, 0x36, 0x35, 0x3a, 0x00,
            ],
        ),
        (
            &[0x20, 0x04, 0x02, 0x00, 0x00, 0x00],
            &[0x02, 0x00, 0x00, 0x00],
        ),
        (&[0x20, 0x01, 0x3a], &[0x3a]),
        (
            &[0xa0, 0x03, 0x03, 0x07, 0x08, 0x0a, 0x01, 0x18],
            &[0x07, 0x0a, 0x08],
        ),
        (
            &[0x20, 0x04, 0x7b, 0x00, 0x00, 0x00],
            &[0x7b, 0x00, 0x00, 0x00],
        ),
        (&[0x20, 0x01, 0x01], &[0x01]),
        (&[0x20, 0x01, 0x3a], &[0x3a]),
        (&[0xa0, 0x03, 0x01, 0x07, 0x00], &[0x07, 0x07, 0x07]),
        (
            &[
                0x20, 0x0c, 0x65, 0xf0, 0x00, 0x00, 0x64, 0x06, 0x00, 0x00, 0x2d, 0xb2, 0x00, 0x00,
            ],
            &[
                0x65, 0xf0, 0x00, 0x00, 0x64, 0x06, 0x00, 0x00, 0x2d, 0xb2, 0x00, 0x00,
            ],
        ),
        (&[0x20, 0x01, 0x3a], &[0x3a]),
        (&[0xa0, 0x03, 0x01, 0x03, 0x00], &[0x03, 0x03, 0x03]),
        (
            &[
                0x20, 0x0c, 0xe3, 0x06, 0x00, 0x00, 0xa3, 0x21, 0x00, 0x00, 0x21, 0x3f, 0x00, 0x00,
            ],
            &[
                0xe3, 0x06, 0x00, 0x00, 0xa3, 0x21, 0x00, 0x00, 0x21, 0x3f, 0x00, 0x00,
            ],
        ),
        (&[0x20, 0x03, 0x05, 0x05, 0x05], &[0x05, 0x05, 0x05]),
        (&[0x20, 0x01, 0x23], &[0x23]),
        (
            &[0x20, 0x04, 0x09, 0x00, 0x00, 0x00],
            &[0x09, 0x00, 0x00, 0x00],
        ),
        (&[0xa0, 0x03, 0x01, 0x0c, 0x00], &[0x0c, 0x0c, 0x0c]),
    ];

    /// A frame with numbers that carry leading zeros, and with a difference
    /// to the number of the name before.
    const DELTA0_FRAME: &[u8] = &[
        0x1c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x80, 0x05, 0xa0, 0x04, 0x01, 0x06,
        0x00, 0x06, 0x12, 0x20, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x81, 0x08, 0xa0, 0x03, 0x03, 0x00, 0x3a, 0x41, 0x01,
        0x06, 0x80, 0x08, 0xa0, 0x04, 0x03, 0x03, 0x09, 0x0a, 0x01, 0x64, 0x03, 0x06, 0x20, 0x04,
        0x01, 0x00, 0x00, 0x00, 0x04, 0x03, 0x20, 0x01, 0x04, 0x09, 0x05, 0xa0, 0x02, 0x01, 0x01,
        0x00, 0x80, 0x05, 0xa0, 0x04, 0x01, 0x0c, 0x00,
    ];

    /// The streams of the frame with the numbers that carry leading zeros.
    const DELTA0_STREAMS: &[(&[u8], &[u8])] = &[
        (&[0xa0, 0x04, 0x01, 0x06, 0x00], &[0x06, 0x06, 0x06, 0x06]),
        (
            &[
                0x20, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00,
            ],
            &[
                0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x00, 0x00,
            ],
        ),
        (
            &[0xa0, 0x03, 0x03, 0x00, 0x3a, 0x41, 0x01, 0x06],
            &[0x41, 0x3a, 0x00],
        ),
        (
            &[0xa0, 0x04, 0x03, 0x03, 0x09, 0x0a, 0x01, 0x64],
            &[0x03, 0x09, 0x0a, 0x09],
        ),
        (
            &[0x20, 0x04, 0x01, 0x00, 0x00, 0x00],
            &[0x01, 0x00, 0x00, 0x00],
        ),
        (&[0x20, 0x01, 0x04], &[0x04]),
        (&[0xa0, 0x02, 0x01, 0x01, 0x00], &[0x01, 0x01]),
        (&[0xa0, 0x04, 0x01, 0x0c, 0x00], &[0x0c, 0x0c, 0x0c, 0x0c]),
    ];

    /// The names the reference implementation decodes the frame with the
    /// numbers that carry leading zeros into.
    const DELTA0_NAMES: &[u8] = &[
        0x41, 0x3a, 0x30, 0x30, 0x30, 0x31, 0x00, 0x41, 0x3a, 0x30, 0x30, 0x30, 0x32, 0x00, 0x41,
        0x3a, 0x30, 0x30, 0x30, 0x32, 0x00, 0x41, 0x3a, 0x30, 0x30, 0x30, 0x33, 0x00,
    ];

    /// A frame whose token streams include ones that are duplicates of an
    /// earlier stream.
    const DUPSTREAM_FRAME: &[u8] = &[
        0x18, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x80, 0x05, 0xa0, 0x02, 0x01, 0x06,
        0x00, 0x06, 0x0a, 0x20, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x05,
        0xa0, 0x02, 0x01, 0x01, 0x00, 0x01, 0x0e, 0xa0, 0x0a, 0x05, 0x00, 0x31, 0x33, 0x3a, 0x58,
        0x05, 0x34, 0x31, 0x40, 0x23, 0x03, 0x80, 0x05, 0xa0, 0x02, 0x01, 0x07, 0x00, 0x07, 0x0a,
        0x20, 0x08, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x80, 0x05, 0xa0, 0x02, 0x01,
        0x02, 0x00, 0x02, 0x04, 0x20, 0x02, 0x3a, 0x3a, 0xc0, 0x02, 0x00, 0x07, 0x0a, 0x20, 0x08,
        0x09, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xc0, 0x03, 0x00, 0x42, 0x03, 0x02, 0xc0,
        0x02, 0x00, 0x07, 0x0a, 0x20, 0x08, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xc0,
        0x03, 0x00, 0x42, 0x03, 0x02, 0xc0, 0x02, 0x00, 0x47, 0x02, 0x07, 0x80, 0x05, 0xa0, 0x02,
        0x01, 0x0c, 0x00,
    ];

    /// The streams of the frame with the duplicate streams.
    const DUPSTREAM_STREAMS: &[(&[u8], &[u8])] = &[
        (&[0xa0, 0x02, 0x01, 0x06, 0x00], &[0x06, 0x06]),
        (
            &[0x20, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ),
        (&[0xa0, 0x02, 0x01, 0x01, 0x00], &[0x01, 0x01]),
        (
            &[
                0xa0, 0x0a, 0x05, 0x00, 0x31, 0x33, 0x3a, 0x58, 0x05, 0x34, 0x31, 0x40, 0x23, 0x03,
            ],
            &[0x58, 0x3a, 0x31, 0x3a, 0x00, 0x58, 0x3a, 0x33, 0x3a, 0x00],
        ),
        (&[0xa0, 0x02, 0x01, 0x07, 0x00], &[0x07, 0x07]),
        (
            &[0x20, 0x08, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00],
            &[0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00],
        ),
        (&[0xa0, 0x02, 0x01, 0x02, 0x00], &[0x02, 0x02]),
        (&[0x20, 0x02, 0x3a, 0x3a], &[0x3a, 0x3a]),
        (
            &[0x20, 0x08, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00],
            &[0x09, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00],
        ),
        (
            &[0x20, 0x08, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00],
            &[0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00],
        ),
        (&[0xa0, 0x02, 0x01, 0x0c, 0x00], &[0x0c, 0x0c]),
    ];

    /// The names the reference implementation decodes the frame with the
    /// duplicate streams into.
    const DUPSTREAM_NAMES: &[u8] = &[
        0x58, 0x3a, 0x31, 0x3a, 0x32, 0x3a, 0x39, 0x3a, 0x31, 0x3a, 0x32, 0x00, 0x58, 0x3a, 0x33,
        0x3a, 0x34, 0x3a, 0x38, 0x3a, 0x33, 0x3a, 0x34, 0x00,
    ];

    /// The callback that answers the streams of a frame.
    ///
    /// The frames the tests carry are the ones of the reference
    /// implementation, and so are the streams they hold: the callback hands
    /// them over in the order the frame presents them, and checks that the
    /// frame walk took the right bytes.
    fn streams<'a>(
        frame: &'a [(&'static [u8], &'static [u8])],
    ) -> impl Fn(bool, &[u8]) -> Option<Vec<u8>> + 'a {
        let at = RefCell::new(0usize);
        move |_use_arith: bool, data: &[u8]| {
            let index = *at.borrow();
            let (compressed, decoded) = frame.get(index)?;
            *at.borrow_mut() += 1;
            assert_eq!(*compressed, data, "the frame walk took the wrong bytes");
            let mut out = Vec::new();
            out.extend_from_slice(decoded);
            Some(out)
        }
    }

    /// The callback that answers the streams of a frame without looking at
    /// the bytes, for the frames that are refused before or after their
    /// streams are read.
    fn loose<'a>(
        frame: &'a [(&'static [u8], &'static [u8])],
    ) -> impl Fn(bool, &[u8]) -> Option<Vec<u8>> + 'a {
        let at = RefCell::new(0usize);
        move |_use_arith: bool, _data: &[u8]| {
            let index = *at.borrow();
            let (_, decoded) = frame.get(index)?;
            *at.borrow_mut() += 1;
            let mut out = Vec::new();
            out.extend_from_slice(decoded);
            Some(out)
        }
    }

    /// A frame that carries the given token streams.
    ///
    /// Each stream is given as the position it opens, the type it holds and
    /// the bytes it has.  The frame carries a placeholder for the
    /// compressed bytes, which the callbacks of the tests do not look at.
    fn frame_of(streams: &[(usize, u8, &[u8])], names: usize, limit: usize) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&(limit as u32).to_le_bytes());
        frame.extend_from_slice(&(names as u32).to_le_bytes());
        frame.push(0);
        let mut position = usize::MAX;
        for (at, kind, bytes) in streams {
            let mut ttype = *kind;
            if *at != position {
                ttype |= 128;
                position = *at;
            }
            frame.push(ttype);
            frame.push(bytes.len() as u8);
            frame.push(0);
        }
        frame
    }

    #[test]
    fn the_names_of_the_example_of_the_specification_are_decoded() {
        let names = decode(SPEC_FRAME, &streams(SPEC_STREAMS));
        assert_eq!(names.as_deref(), Some(SPEC_NAMES));
    }

    #[test]
    fn the_duplicate_name_is_decoded() {
        let names = decode(DUP_FRAME, &streams(DUP_STREAMS));
        assert_eq!(names.as_deref(), Some(DUP_NAMES));
    }

    #[test]
    fn the_frame_of_the_arithmetic_coder_is_decoded() {
        let names = decode(ARITH_FRAME, &streams(ARITH_STREAMS));
        assert_eq!(names.as_deref(), Some(SPEC_NAMES));
    }

    #[test]
    fn the_arithmetic_coder_is_the_one_the_frame_asks_for() {
        let flags = RefCell::new(Vec::new());
        let index = Cell::new(0usize);
        let entropy = |use_arith: bool, _data: &[u8]| {
            flags.borrow_mut().push(use_arith);
            let at = index.get();
            index.set(at + 1);
            let (_, decoded) = ARITH_STREAMS.get(at)?;
            let mut out = Vec::new();
            out.extend_from_slice(decoded);
            Some(out)
        };
        assert!(decode(ARITH_FRAME, &entropy).is_some());
        assert!(!flags.borrow().is_empty());
        assert!(
            flags.borrow().iter().all(|flag| *flag),
            "the frame asks for the arithmetic coder"
        );
    }

    #[test]
    fn the_numbers_with_leading_zeros_are_decoded() {
        let names = decode(DELTA0_FRAME, &streams(DELTA0_STREAMS));
        assert_eq!(names.as_deref(), Some(DELTA0_NAMES));
    }

    #[test]
    fn the_duplicate_streams_are_decoded() {
        let names = decode(DUPSTREAM_FRAME, &streams(DUPSTREAM_STREAMS));
        assert_eq!(names.as_deref(), Some(DUPSTREAM_NAMES));
    }

    #[test]
    fn the_frame_that_is_too_short_is_refused() {
        assert!(decode(&[0x00, 0x00], &streams(SPEC_STREAMS)).is_none());
    }

    #[test]
    fn the_size_that_asks_for_too_much_is_refused() {
        let mut frame = SPEC_FRAME.to_vec();
        frame[0..4].copy_from_slice(&(MAX_OUTPUT as u32 + 1).to_le_bytes());
        assert!(decode(&frame, &loose(SPEC_STREAMS)).is_none());
    }

    #[test]
    fn the_number_of_names_that_asks_for_too_much_is_refused() {
        let mut frame = SPEC_FRAME.to_vec();
        frame[4..8].copy_from_slice(&(MAX_NAMES as u32 + 1).to_le_bytes());
        assert!(decode(&frame, &loose(SPEC_STREAMS)).is_none());
    }

    #[test]
    fn the_token_type_that_is_not_one_of_the_thirteen_is_refused() {
        let mut frame = SPEC_FRAME.to_vec();
        // The type of the first stream is 13, which is not one of them.
        frame[9] = 0x8d;
        assert!(decode(&frame, &loose(SPEC_STREAMS)).is_none());
    }

    #[test]
    fn the_stream_that_runs_past_the_end_of_the_frame_is_refused() {
        assert!(decode(&SPEC_FRAME[..20], &loose(SPEC_STREAMS)).is_none());
    }

    #[test]
    fn the_distance_that_points_outside_the_names_is_refused() {
        let mut streams = SPEC_STREAMS.to_vec();
        // The second name points three names back, and there are only two.
        streams[1].1 = &[
            0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        assert!(decode(SPEC_FRAME, &loose(&streams)).is_none());
    }

    #[test]
    fn the_match_of_a_name_with_no_name_before_is_refused() {
        let mut streams = SPEC_STREAMS.to_vec();
        // The second name points at itself, so it has no name to match the
        // tokens of its first position against.
        streams[1].1 = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        assert!(decode(SPEC_FRAME, &loose(&streams)).is_none());
    }

    #[test]
    fn the_duplicate_of_a_name_that_is_not_there_is_refused() {
        let mut streams = DUP_STREAMS.to_vec();
        // The fourth name points three names back, and there are only two
        // before it.
        streams[1].1 = &[0x09, 0x00, 0x00, 0x00];
        assert!(decode(DUP_FRAME, &loose(&streams)).is_none());
    }

    #[test]
    fn the_name_that_does_not_end_is_refused() {
        let mut streams = SPEC_STREAMS.to_vec();
        // The last position holds a token that does nothing, so the names go
        // on looking for an end that is not there.
        streams[17].1 = &[0x0b, 0x0b, 0x0b];
        assert!(decode(SPEC_FRAME, &loose(&streams)).is_none());
    }

    #[test]
    fn the_length_of_zero_of_a_number_is_refused() {
        let mut streams = SPEC_STREAMS.to_vec();
        // The fifteenth stream of the frame is the length of the numbers
        // that carry leading zeros.
        streams[14].1 = &[0x00, 0x00, 0x00];
        assert!(decode(SPEC_FRAME, &loose(&streams)).is_none());
    }

    #[test]
    fn the_length_shorter_than_the_number_is_refused() {
        let mut streams = SPEC_STREAMS.to_vec();
        // The numbers are four digits long, and the length says one.
        streams[14].1 = &[0x01, 0x01, 0x01];
        assert!(decode(SPEC_FRAME, &loose(&streams)).is_none());
    }

    #[test]
    fn the_delta_of_a_token_that_is_not_a_number_is_refused() {
        // The second name holds a difference to the number of the name
        // before, but that token is a character.
        let frame = frame_of(
            &[
                (0, ty::TYPE, &[ty::DIFF, ty::DIFF]),
                (0, ty::DIFF, &[0, 0, 0, 0, 1, 0, 0, 0]),
                (1, ty::TYPE, &[ty::CHAR, ty::DELTA]),
                (1, ty::CHAR, b"a"),
                (1, ty::DELTA, &[1]),
                (2, ty::TYPE, &[ty::END, ty::END]),
            ],
            2,
            64,
        );
        let streams: &[(&[u8], &[u8])] = &[
            (&[0], &[ty::DIFF, ty::DIFF]),
            (&[0], &[0, 0, 0, 0, 1, 0, 0, 0]),
            (&[0], &[ty::CHAR, ty::DELTA]),
            (&[0], b"a"),
            (&[0], &[1]),
            (&[0], &[ty::END, ty::END]),
        ];
        assert!(decode(&frame, &loose(streams)).is_none());
    }

    #[test]
    fn the_match_of_a_token_that_holds_nothing_is_refused() {
        // The second name matches the token of the name before, but that
        // token holds nothing.
        let frame = frame_of(
            &[
                (0, ty::TYPE, &[ty::DIFF, ty::DIFF]),
                (0, ty::DIFF, &[0, 0, 0, 0, 1, 0, 0, 0]),
                (1, ty::TYPE, &[ty::NOP, ty::MATCH]),
                (2, ty::TYPE, &[ty::END, ty::END]),
            ],
            2,
            64,
        );
        let streams: &[(&[u8], &[u8])] = &[
            (&[0], &[ty::DIFF, ty::DIFF]),
            (&[0], &[0, 0, 0, 0, 1, 0, 0, 0]),
            (&[0], &[ty::NOP, ty::MATCH]),
            (&[0], &[ty::END, ty::END]),
        ];
        assert!(decode(&frame, &loose(streams)).is_none());
    }
}
