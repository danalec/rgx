// SPDX-License-Identifier: Apache-2.0

//! Independent reimplementation of memmap2-rs MmapOptions builder.

use std::fmt;
use std::io;
use std::mem;

use crate::memmap2::error::{to_io_error, Error};
use crate::memmap2::mmap::Mmap;
use crate::memmap2::mmap_mut::MmapMut;
use crate::memmap2::platform::MmapAsRawDesc;

#[derive(Clone, Default)]
pub struct MmapOptions {
    offset: u64,
    len: Option<usize>,
    stack: bool,
    populate: bool,
}

impl MmapOptions {
    pub fn new() -> MmapOptions {
        MmapOptions::default()
    }

    pub fn offset(&mut self, offset: u64) -> &mut Self {
        self.offset = offset;
        self
    }

    pub fn len(&mut self, len: usize) -> &mut Self {
        self.len = Some(len);
        self
    }

    pub fn stack(&mut self) -> &mut Self {
        self.stack = true;
        self
    }

    pub fn populate(&mut self) -> &mut Self {
        self.populate = true;
        self
    }

    fn get_len<T: MmapAsRawDesc>(&self, file: &T) -> io::Result<usize> {
        match self.len {
            Some(n) => {
                if std::mem::size_of::<usize>() < 8 && n > isize::MAX as usize {
                    return Err(to_io_error(Error::LengthOverflow).into());
                }
                Ok(n)
            }
            None => {
                let desc = file.as_raw_desc();
                let file_len = crate::memmap2::platform::file_len_for_desc(&desc)?;
                if file_len < self.offset {
                    return Err(to_io_error(Error::OffsetBeyondFile).into());
                }
                let len = file_len - self.offset;
                if std::mem::size_of::<usize>() < 8 && len > isize::MAX as u64 {
                    return Err(to_io_error(Error::LengthOverflow).into());
                }
                Ok(len as usize)
            }
        }
    }

    pub unsafe fn map<T: MmapAsRawDesc>(&self, file: T) -> io::Result<Mmap> {
        let len = self.get_len(&file)?;
        let desc = file.as_raw_desc();
        crate::memmap2::platform::map(&desc, len, self.offset, self.populate).map(Mmap::from_inner)
    }

    pub unsafe fn map_exec<T: MmapAsRawDesc>(&self, file: T) -> io::Result<Mmap> {
        let len = self.get_len(&file)?;
        let desc = file.as_raw_desc();
        crate::memmap2::platform::map_exec(&desc, len, self.offset, self.populate)
            .map(Mmap::from_inner)
    }

    pub unsafe fn map_mut<T: MmapAsRawDesc>(&self, file: T) -> io::Result<MmapMut> {
        let len = self.get_len(&file)?;
        let desc = file.as_raw_desc();
        crate::memmap2::platform::map_mut(&desc, len, self.offset, self.populate)
            .map(MmapMut::from_inner)
    }

    pub unsafe fn map_copy<T: MmapAsRawDesc>(&self, file: T) -> io::Result<MmapMut> {
        let len = self.get_len(&file)?;
        let desc = file.as_raw_desc();
        crate::memmap2::platform::map_copy(&desc, len, self.offset, self.populate)
            .map(MmapMut::from_inner)
    }

    pub unsafe fn map_copy_read_only<T: MmapAsRawDesc>(&self, file: T) -> io::Result<Mmap> {
        let len = self.get_len(&file)?;
        let desc = file.as_raw_desc();
        crate::memmap2::platform::map_copy_read_only(&desc, len, self.offset, self.populate)
            .map(Mmap::from_inner)
    }

    pub fn map_anon(&self) -> io::Result<MmapMut> {
        let len = self.len.unwrap_or(0);
        if mem::size_of::<usize>() < 8 && len > isize::MAX as usize {
            return Err(to_io_error(Error::LengthOverflow).into());
        }
        crate::memmap2::platform::map_anon(len, self.stack, self.populate).map(MmapMut::from_inner)
    }
}

impl fmt::Debug for MmapOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmapOptions")
            .field("offset", &self.offset)
            .field("len", &self.len)
            .field("stack", &self.stack)
            .field("populate", &self.populate)
            .finish()
    }
}
