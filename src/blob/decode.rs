use crate::cancellable_io::CancellableWriter;
use anyhow::{Context, Result, bail};
use oci_spec::image::MediaType;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, copy},
};
use tokio_util::sync::CancellationToken;

pub(super) fn decode_to_temp(
    reader: &mut File,
    media_type: &MediaType,
    max_decompressed_bytes: u64,
    cancellation: &CancellationToken,
) -> Result<File> {
    match media_type {
        MediaType::ImageLayer | MediaType::ImageLayerNonDistributable => {
            let size = reader.metadata().context("stat uncompressed layer")?.len();
            if size > max_decompressed_bytes {
                bail!(
                    "uncompressed layer size ({size} bytes) exceeds limit of {max_decompressed_bytes} bytes"
                );
            }
            reader.seek(SeekFrom::Start(0))?;
            reader.try_clone().context("cloning uncompressed layer")
        }
        MediaType::ImageLayerGzip | MediaType::ImageLayerNonDistributableGzip => {
            gunzip_to_temp(reader, max_decompressed_bytes, cancellation)
        }
        MediaType::ImageLayerZstd | MediaType::ImageLayerNonDistributableZstd => {
            zstd_to_temp(reader, max_decompressed_bytes, cancellation)
        }
        MediaType::Other(value) if value.ends_with(".tar.gzip") || value.ends_with("+gzip") => {
            gunzip_to_temp(reader, max_decompressed_bytes, cancellation)
        }
        MediaType::Other(value) if value.ends_with("+zstd") => {
            zstd_to_temp(reader, max_decompressed_bytes, cancellation)
        }
        other => bail!("unsupported layer media type {other}"),
    }
}

fn gunzip_to_temp(
    reader: &mut File,
    max_decompressed_bytes: u64,
    cancellation: &CancellationToken,
) -> Result<File> {
    reader
        .seek(SeekFrom::Start(0))
        .context("seeking compressed data")?;
    let mut decoder = flate2::read::GzDecoder::new(reader);
    copy_to_temp(&mut decoder, max_decompressed_bytes, cancellation).context("gunzip")
}

fn zstd_to_temp(
    reader: &mut File,
    max_decompressed_bytes: u64,
    cancellation: &CancellationToken,
) -> Result<File> {
    reader
        .seek(SeekFrom::Start(0))
        .context("seeking compressed data")?;
    let mut decoder = zstd::stream::read::Decoder::new(reader).context("creating zstd decoder")?;
    copy_to_temp(&mut decoder, max_decompressed_bytes, cancellation).context("zstd")
}

fn copy_to_temp(
    reader: &mut impl Read,
    max_decompressed_bytes: u64,
    cancellation: &CancellationToken,
) -> Result<File> {
    let temporary = tempfile::tempfile().context("creating decompression tempfile")?;
    let mut writer = CancellableWriter::new(temporary, cancellation.clone(), "layer decompression");
    let mut bounded = reader.take(max_decompressed_bytes.saturating_add(1));
    let copied = copy(&mut bounded, &mut writer).context("decompressing layer")?;
    if copied > max_decompressed_bytes {
        bail!("decompressed layer exceeds maximum allowed size of {max_decompressed_bytes} bytes");
    }
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
        let mut decoded = zstd_to_temp(&mut compressed, 1024, &CancellationToken::new()).unwrap();
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

        let error = zstd_to_temp(&mut compressed, 1024, &cancellation).unwrap_err();

        assert!(format!("{error:#}").contains("layer decompression cancelled"));
    }

    #[test]
    fn decompression_rejects_gzip_and_zstd_bombs_above_limit() {
        let payload = vec![0_u8; 32 * 1024];

        let mut gz = tempfile::tempfile().unwrap();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::fast());
            enc.write_all(&payload).unwrap();
            enc.finish().unwrap();
        }
        let err = gunzip_to_temp(&mut gz, 4096, &CancellationToken::new())
            .unwrap_err()
            .to_string();
        assert!(format!("{err:#}").contains("gunzip"));

        let mut zst = tempfile::tempfile().unwrap();
        zstd::stream::copy_encode(payload.as_slice(), &mut zst, 1).unwrap();
        zst.flush().unwrap();
        let err = zstd_to_temp(&mut zst, 4096, &CancellationToken::new())
            .unwrap_err()
            .to_string();
        assert!(format!("{err:#}").contains("zstd"));
    }
}
