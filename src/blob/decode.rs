use crate::cancellable_io::CancellableWriter;
use anyhow::{Context, Result, bail};
use oci_spec::image::MediaType;
use std::{
    fs::File,
    io::{Seek, SeekFrom, copy},
};
use tokio_util::sync::CancellationToken;

pub(super) fn decode_to_temp(
    reader: &mut File,
    media_type: &MediaType,
    cancellation: &CancellationToken,
) -> Result<File> {
    match media_type {
        MediaType::ImageLayer | MediaType::ImageLayerNonDistributable => {
            reader.seek(SeekFrom::Start(0))?;
            reader.try_clone().context("cloning uncompressed layer")
        }
        MediaType::ImageLayerGzip | MediaType::ImageLayerNonDistributableGzip => {
            gunzip_to_temp(reader, cancellation)
        }
        MediaType::ImageLayerZstd | MediaType::ImageLayerNonDistributableZstd => {
            zstd_to_temp(reader, cancellation)
        }
        MediaType::Other(value) if value.ends_with(".tar.gzip") || value.ends_with("+gzip") => {
            gunzip_to_temp(reader, cancellation)
        }
        MediaType::Other(value) if value.ends_with("+zstd") => zstd_to_temp(reader, cancellation),
        other => bail!("unsupported layer media type {other}"),
    }
}

fn gunzip_to_temp(reader: &mut File, cancellation: &CancellationToken) -> Result<File> {
    reader
        .seek(SeekFrom::Start(0))
        .context("seeking compressed data")?;
    let mut decoder = flate2::read::GzDecoder::new(reader);
    copy_to_temp(&mut decoder, cancellation).context("gunzip")
}

fn zstd_to_temp(reader: &mut File, cancellation: &CancellationToken) -> Result<File> {
    reader
        .seek(SeekFrom::Start(0))
        .context("seeking compressed data")?;
    let mut decoder = zstd::stream::read::Decoder::new(reader).context("creating zstd decoder")?;
    copy_to_temp(&mut decoder, cancellation).context("zstd")
}

fn copy_to_temp(reader: &mut impl std::io::Read, cancellation: &CancellationToken) -> Result<File> {
    let temporary = tempfile::tempfile().context("creating decompression tempfile")?;
    let mut writer = CancellableWriter::new(temporary, cancellation.clone(), "layer decompression");
    copy(reader, &mut writer).context("decompressing layer")?;
    let mut temporary = writer.into_inner();
    temporary
        .seek(SeekFrom::Start(0))
        .context("rewinding decompressed layer")?;
    Ok(temporary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn zstd_stream_is_decoded() {
        let mut compressed = tempfile::tempfile().unwrap();
        zstd::stream::copy_encode(b"uncompressed layer bytes".as_slice(), &mut compressed, 1)
            .unwrap();
        compressed.flush().unwrap();
        let mut decoded = zstd_to_temp(&mut compressed, &CancellationToken::new()).unwrap();
        let mut bytes = Vec::new();
        decoded.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"uncompressed layer bytes");
    }

    #[test]
    fn decompression_observes_cancellation() {
        let mut compressed = tempfile::tempfile().unwrap();
        zstd::stream::copy_encode(b"uncompressed layer bytes".as_slice(), &mut compressed, 1)
            .unwrap();
        compressed.flush().unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = zstd_to_temp(&mut compressed, &cancellation).unwrap_err();

        assert!(format!("{error:#}").contains("layer decompression cancelled"));
    }
}
