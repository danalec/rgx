// SPDX-License-Identifier: Apache-2.0

//! Independent reimplementation of memmap2-rs error type.

use std::io;

#[derive(Debug)]
pub(crate) enum Error {
    LengthOverflow,
    OffsetBeyondFile,
}

pub(crate) fn to_io_error(e: Error) -> io::Error {
    let msg = match e {
        Error::LengthOverflow => "memory map length overflows isize",
        Error::OffsetBeyondFile => "memory map offset is larger than length",
    };
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        to_io_error(e)
    }
}
