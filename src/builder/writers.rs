use sha2::{Digest as dg, Sha256};
use std::io::{self, Write};

use crate::digest::finish_sha256;
use oci_spec::image::Digest;

pub struct HashingWriter<W> {
    inner_writer: W,
    hasher: Sha256,
    written_bytes_count: u64,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner_writer: W) -> Self {
        Self {
            inner_writer,
            hasher: Sha256::new(),
            written_bytes_count: 0,
        }
    }

    pub fn finalize(self) -> (Digest, u64) {
        let digest = finish_sha256(self.hasher);
        (digest, self.written_bytes_count)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner_writer.write_all(buf)?;
        self.hasher.update(buf);
        self.written_bytes_count += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner_writer.flush()
    }
}

pub struct SplitWriter<A, B> {
    first_writer: A,
    second_writer: B,
}

impl<A, B> SplitWriter<A, B> {
    pub fn new(first_writer: A, second_writer: B) -> Self {
        Self {
            first_writer,
            second_writer,
        }
    }

    pub fn into_inner(self) -> (A, B) {
        (self.first_writer, self.second_writer)
    }
}

impl<A: Write, B: Write> Write for SplitWriter<A, B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.first_writer.write_all(buf)?;
        self.second_writer.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.first_writer.flush()?;
        self.second_writer.flush()
    }
}
