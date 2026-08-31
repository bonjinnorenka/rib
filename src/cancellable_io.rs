use std::io::{self, Write};

use tokio_util::sync::CancellationToken;

pub struct CancellableWriter<W> {
    inner: W,
    cancellation: CancellationToken,
    operation: &'static str,
}

impl<W> CancellableWriter<W> {
    pub fn new(inner: W, cancellation: CancellationToken, operation: &'static str) -> Self {
        Self {
            inner,
            cancellation,
            operation,
        }
    }

    pub fn into_inner(self) -> W {
        self.inner
    }

    fn check_cancelled(&self) -> io::Result<()> {
        if self.cancellation.is_cancelled() {
            Err(io::Error::other(format!("{} cancelled", self.operation)))
        } else {
            Ok(())
        }
    }
}

impl<W: Write> Write for CancellableWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_cancelled()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check_cancelled()?;
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CancelAfterPartialWrite {
        bytes: Vec<u8>,
        cancellation: CancellationToken,
    }

    impl Write for CancelAfterPartialWrite {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let written = buffer.len().min(1);
            self.bytes.extend_from_slice(&buffer[..written]);
            self.cancellation.cancel();
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn interrupts_writes() {
        let cancellation = CancellationToken::new();
        let mut writer = CancellableWriter::new(Vec::new(), cancellation.clone(), "layer build");
        writer.write_all(b"before").unwrap();

        cancellation.cancel();

        let error = writer.write_all(b"after").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(writer.into_inner(), b"before");
    }

    #[test]
    fn stops_an_in_progress_write_all() {
        let cancellation = CancellationToken::new();
        let inner = CancelAfterPartialWrite {
            bytes: Vec::new(),
            cancellation: cancellation.clone(),
        };
        let mut writer = CancellableWriter::new(inner, cancellation, "layer build");

        let error = writer.write_all(b"payload").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(writer.into_inner().bytes, b"p");
    }
}
