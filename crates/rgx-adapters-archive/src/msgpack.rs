// SPDX-License-Identifier: Apache-2.0

//! A MessagePack reader.
//!
//! **Why a borg reader needs one.** A borg segment keeps its metadata as
//! MessagePack maps, and the path of every file in a backup is a key in one
//! of those maps. There is no way to report the structure of a backup
//! without decoding them.
//!
//! **The dialect.** borg packs with `use_bin_type=False` and
//! `strict_types=False`, so its byte strings are MessagePack *strings* and
//! not `bin`, and its integers use the compact forms. This reader accepts
//! the whole grammar anyway: a decoder that refused the `bin` family would
//! be a decoder that breaks on the next producer, and the price of accepting
//! it is one match arm.
//!
//! **The integers are big-endian.** MessagePack stores them in network byte
//! order, and a reader that reaches for the little-endian conversion every
//! other binary format in this crate uses decodes a `mode` of 16895 as
//! 65345 and a timestamp of 1792419512700472100 as 2633477522910390040.
//! Nothing crashes: the numbers are simply other numbers, and the paths
//! that come with them are the paths of a different archive. The test
//! `the_integers_are_in_network_byte_order` pins it.
//!
//! **What it is not.** A reader, not a validator. It decodes what it can and
//! says so when it cannot; it never guesses a length, and it never allocates
//! on a length it has not checked against the bytes it holds.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// The deepest nesting a value may have.
///
/// The grammar is recursive and the input is not trusted: a map that holds a
/// map that holds a map ... is a stack overflow, and the budget this reader
/// spends is the depth it is willing to descend.
const MAX_DEPTH: u32 = 64;

/// A decoded MessagePack value.
///
/// The variants a borg repository does not write are decoded anyway. A
/// decoder that only knows the fields one producer happens to use is a
/// decoder that breaks on the next producer, and the price of decoding them
/// is a match arm each. The ones no reader in this crate looks at are
/// allowed to go unread.
#[allow(dead_code)]
pub enum Value {
    Nil,
    Bool(bool),
    /// A signed integer.
    Int(i64),
    /// An unsigned integer too large for an `i64`.
    UInt(u64),
    F32(f32),
    F64(f64),
    /// A string. borg has no separate byte type: it packs with
    /// `use_bin_type=False`, so a path, a user name and a chunk id are all
    /// strings, and all of them come back as bytes.
    Str(Vec<u8>),
    /// A binary blob, for a producer that does use the `bin` family.
    Bin(Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    /// An extension type and its payload.
    Ext(i8, Vec<u8>),
}

impl Value {
    /// The value under `key`, when this is a map with string keys.
    pub fn get(&self, key: &str) -> Option<&Value> {
        let Value::Map(pairs) = self else {
            return None;
        };
        pairs.iter().find_map(|(k, v)| match k {
            Value::Str(s) if s == key.as_bytes() => Some(v),
            _ => None,
        })
    }

    /// The bytes of a string or a binary value.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Str(s) | Value::Bin(s) => Some(s),
            _ => None,
        }
    }

    /// The value as an integer, whether it was packed signed or unsigned.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::UInt(u) => i64::try_from(*u).ok(),
            _ => None,
        }
    }

    /// The value as an unsigned integer.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::UInt(u) => Some(*u),
            Value::Int(i) => u64::try_from(*i).ok(),
            _ => None,
        }
    }

    /// The elements of an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
}

/// A MessagePack reader over a byte slice.
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    depth: u32,
}

impl<'a> Decoder<'a> {
    /// A reader over `data`, positioned at its first byte.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            depth: 0,
        }
    }

    /// true when every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Decode the next value.
    pub fn decode(&mut self) -> Result<Value, String> {
        let tag = self.take(1)?[0];
        match tag {
            0x00..=0x7f => Ok(Value::UInt(u64::from(tag))),
            0xe0..=0xff => Ok(Value::Int(i64::from(tag as i8))),
            0x80..=0x8f => self.map(usize::from(tag & 0x0f)),
            0x90..=0x9f => self.array(usize::from(tag & 0x0f)),
            0xa0..=0xbf => self.str(usize::from(tag & 0x1f)),
            0xc0 => Ok(Value::Nil),
            // 0xc1 is the one byte the MessagePack grammar leaves unused.
            0xc1 => Err("reserved byte 0xc1".to_string()),
            0xc2 => Ok(Value::Bool(false)),
            0xc3 => Ok(Value::Bool(true)),
            0xc4 => {
                let n = self.u8()? as usize;
                self.bin(n)
            }
            0xc5 => {
                let n = self.u16()? as usize;
                self.bin(n)
            }
            0xc6 => {
                let n = self.u32()? as usize;
                self.bin(n)
            }
            0xc7 => {
                let n = self.u8()? as usize;
                let t = self.i8()?;
                self.ext(t, n)
            }
            0xc8 => {
                let n = self.u16()? as usize;
                let t = self.i8()?;
                self.ext(t, n)
            }
            0xc9 => {
                let n = self.u32()? as usize;
                let t = self.i8()?;
                self.ext(t, n)
            }
            0xca => {
                let mut a = [0u8; 4];
                a.copy_from_slice(self.take(4)?);
                Ok(Value::F32(f32::from_be_bytes(a)))
            }
            0xcb => {
                let mut a = [0u8; 8];
                a.copy_from_slice(self.take(8)?);
                Ok(Value::F64(f64::from_be_bytes(a)))
            }
            0xcc => Ok(Value::UInt(u64::from(self.u8()?))),
            0xcd => Ok(Value::UInt(u64::from(self.u16()?))),
            0xce => Ok(Value::UInt(u64::from(self.u32()?))),
            0xcf => Ok(Value::UInt(self.u64()?)),
            0xd0 => Ok(Value::Int(i64::from(self.i8()?))),
            0xd1 => Ok(Value::Int(i64::from(self.i16()?))),
            0xd2 => Ok(Value::Int(i64::from(self.i32()?))),
            0xd3 => Ok(Value::Int(self.i64()?)),
            0xd4 => {
                let t = self.i8()?;
                self.ext(t, 1)
            }
            0xd5 => {
                let t = self.i8()?;
                self.ext(t, 2)
            }
            0xd6 => {
                let t = self.i8()?;
                self.ext(t, 4)
            }
            0xd7 => {
                let t = self.i8()?;
                self.ext(t, 8)
            }
            0xd8 => {
                let t = self.i8()?;
                self.ext(t, 16)
            }
            0xd9 => {
                let n = self.u8()? as usize;
                self.str(n)
            }
            0xda => {
                let n = self.u16()? as usize;
                self.str(n)
            }
            0xdb => {
                let n = self.u32()? as usize;
                self.str(n)
            }
            0xdc => {
                let n = self.u16()? as usize;
                self.array(n)
            }
            0xdd => {
                let n = self.u32()? as usize;
                self.array(n)
            }
            0xde => {
                let n = self.u16()? as usize;
                self.map(n)
            }
            0xdf => {
                let n = self.u32()? as usize;
                self.map(n)
            }
        }
    }

    fn array(&mut self, n: usize) -> Result<Value, String> {
        self.enter()?;
        let mut items = Vec::new();
        for _ in 0..n {
            items.push(self.decode()?);
        }
        self.depth -= 1;
        Ok(Value::Array(items))
    }

    fn map(&mut self, n: usize) -> Result<Value, String> {
        self.enter()?;
        let mut pairs = Vec::new();
        for _ in 0..n {
            let key = self.decode()?;
            let value = self.decode()?;
            pairs.push((key, value));
        }
        self.depth -= 1;
        Ok(Value::Map(pairs))
    }

    fn enter(&mut self) -> Result<(), String> {
        if self.depth >= MAX_DEPTH {
            return Err("nesting is deeper than this reader descends".to_string());
        }
        self.depth += 1;
        Ok(())
    }

    fn str(&mut self, n: usize) -> Result<Value, String> {
        Ok(Value::Str(self.take(n)?.to_vec()))
    }

    fn bin(&mut self, n: usize) -> Result<Value, String> {
        Ok(Value::Bin(self.take(n)?.to_vec()))
    }

    fn ext(&mut self, t: i8, n: usize) -> Result<Value, String> {
        Ok(Value::Ext(t, self.take(n)?.to_vec()))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| "length overflows".to_string())?;
        if end > self.data.len() {
            return Err("the value claims more bytes than the input holds".to_string());
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    fn i8(&mut self) -> Result<i8, String> {
        Ok(self.take(1)?[0] as i8)
    }

    fn i16(&mut self) -> Result<i16, String> {
        let b = self.take(2)?;
        Ok(i16::from_be_bytes([b[0], b[1]]))
    }

    fn i32(&mut self) -> Result<i32, String> {
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i64(&mut self) -> Result<i64, String> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(i64::from_be_bytes(a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let bytes: Vec<u8> = s
            .as_bytes()
            .chunks(2)
            .map(|p| {
                let hi = (p[0] as char).to_digit(16).unwrap() as u8;
                let lo = (p[1] as char).to_digit(16).unwrap() as u8;
                hi << 4 | lo
            })
            .collect();
        bytes
    }

    #[test]
    fn the_dialect_borg_packs_decodes() {
        // A map of two string keys, the shape borg writes its metadata in:
        // {"path": "f.txt", "size": 19}
        let bytes = hex("82a470617468a5662e747874a473697a6513");
        let mut d = Decoder::new(&bytes);
        let v = d.decode().expect("a map decodes");
        assert_eq!(v.get("path").and_then(Value::as_bytes), Some(&b"f.txt"[..]));
        assert_eq!(v.get("size").and_then(Value::as_i64), Some(19));
        assert!(d.is_empty());
    }

    #[test]
    fn the_integers_are_in_network_byte_order() {
        // The mode of a file with 777 permissions, and the timestamp borg
        // stores, as borg packs them: big-endian, like the network byte
        // order the format specifies.
        let bytes = hex("cd41ffcf18dff40cd6fd8b24");
        let mut d = Decoder::new(&bytes);
        assert_eq!(d.decode().expect("a uint16").as_i64(), Some(16895));
        assert_eq!(
            d.decode().expect("a uint64").as_i64(),
            Some(1792419512700472100)
        );
    }

    #[test]
    fn a_truncated_value_is_an_error_and_not_a_panic() {
        let bytes = hex("a4706174");
        let mut d = Decoder::new(&bytes);
        assert!(d.decode().is_err());
    }

    #[test]
    fn a_deeply_nested_value_is_refused_rather_than_overflowing_the_stack() {
        // 200 nested single-element maps.
        let mut bytes = vec![0x91u8; 200];
        bytes.push(0xc0);
        let mut d = Decoder::new(&bytes);
        assert!(d.decode().is_err());
    }
}
