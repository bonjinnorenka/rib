use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use oci_spec::image::{Digest, DigestAlgorithm};
use sha2::{Sha256, Sha512};
use tempfile::NamedTempFile;
use tokio_util::sync::CancellationToken;

use crate::blob::BlobFile;

pub const DEFAULT_CACHE_DIR: &str = ".rib-cache";

/// Immutable, content-addressed files. The layer store calls these blocking
/// methods on the blocking pool, under its concurrency limit.
#[derive(Clone)]
pub struct CacheController {
    cache_dir: PathBuf,
}

impl CacheController {
    pub fn new(cache_dir_path: Option<&Path>) -> Result<Self> {
        let cache_dir = cache_dir_path
            .unwrap_or(Path::new(DEFAULT_CACHE_DIR))
            .to_path_buf();
        std::fs::create_dir_all(&cache_dir)
            .with_context(|| format!("creating cache dir {}", cache_dir.display()))?;
        Ok(Self { cache_dir })
    }

    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.cache_dir.join(digest.to_string().replace(':', "-"))
    }

    pub fn lookup(
        &self,
        digest: &Digest,
        cancellation: &CancellationToken,
    ) -> Result<Option<BlobFile>> {
        let path = self.blob_path(digest);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "cannot read cached layer; re-downloading");
                return Ok(None);
            }
        };
        match matches_digest(&mut file, digest, cancellation) {
            Ok(true) => Ok(Some(BlobFile::cached(path))),
            result => {
                ensure!(!cancellation.is_cancelled(), "cache verification cancelled");
                match result {
                    Ok(false) => {
                        tracing::warn!(%digest, "cached layer digest mismatch; re-downloading")
                    }
                    Err(error) => {
                        tracing::warn!(%digest, %error, "cannot verify cached layer; re-downloading")
                    }
                    Ok(true) => unreachable!(),
                }
                Ok(None)
            }
        }
    }

    pub fn staging_file(&self) -> Result<NamedTempFile> {
        NamedTempFile::new_in(&self.cache_dir).context("creating cache staging file")
    }

    /// The caller must have verified the downloaded digest and size. Concurrent
    /// publishers atomically replace the path with identical content, preserving
    /// the files held by existing readers.
    pub fn publish(&self, file: NamedTempFile, digest: &Digest) -> Result<BlobFile> {
        let path = self.blob_path(digest);
        file.persist(&path)
            .with_context(|| format!("publishing cached layer {digest}"))?;
        Ok(BlobFile::cached(path))
    }
}

fn matches_digest(
    file: &mut File,
    expected: &Digest,
    cancellation: &CancellationToken,
) -> Result<bool> {
    fn hash<D: sha2::Digest>(file: &mut File, cancellation: &CancellationToken) -> Result<String> {
        let mut hasher = D::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            ensure!(!cancellation.is_cancelled(), "cache verification cancelled");
            let count = file.read(&mut buffer).context("reading cached layer")?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok(hex::encode(hasher.finalize()))
    }
    let actual = match expected.algorithm() {
        DigestAlgorithm::Sha256 => hash::<Sha256>(file, cancellation)?,
        DigestAlgorithm::Sha512 => hash::<Sha512>(file, cancellation)?,
        other => anyhow::bail!("unsupported cache digest algorithm {other}"),
    };
    Ok(actual == expected.digest())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha256_digest;
    use std::io::Write;

    #[test]
    fn publication_is_atomic_and_visible_to_existing_controllers() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheController::new(Some(directory.path())).unwrap();
        let other = cache.clone();
        let payload = b"complete layer";
        let digest = sha256_digest(payload);
        let cancellation = CancellationToken::new();
        let mut pending = cache.staging_file().unwrap();
        pending.write_all(b"complete ").unwrap();
        assert!(other.lookup(&digest, &cancellation).unwrap().is_none());
        pending.write_all(b"layer").unwrap();
        cache.publish(pending, &digest).unwrap();
        let mut reader = other
            .lookup(&digest, &cancellation)
            .unwrap()
            .unwrap()
            .open()
            .unwrap();
        let mut replacement = cache.staging_file().unwrap();
        replacement.write_all(b"partial").unwrap();
        drop(replacement);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, payload);
        assert!(other.lookup(&digest, &cancellation).unwrap().is_some());
        assert!(
            !cache
                .blob_path(&digest)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains(':')
        );
    }

    #[test]
    fn lookup_rejects_corruption_and_observes_cancellation() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheController::new(Some(directory.path())).unwrap();
        let digest = sha256_digest(b"expected");
        std::fs::write(cache.blob_path(&digest), b"corrupt").unwrap();
        let cancellation = CancellationToken::new();
        assert!(cache.lookup(&digest, &cancellation).unwrap().is_none());
        cancellation.cancel();
        assert!(cache.lookup(&digest, &cancellation).is_err());
    }
    #[test]
    fn concurrent_publishers_preserve_open_readers() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheController::new(Some(directory.path())).unwrap();
        let payload = vec![42_u8; 128 * 1024];
        let digest = sha256_digest(&payload);
        let mut initial = cache.staging_file().unwrap();
        initial.write_all(&payload).unwrap();
        let mut reader = cache.publish(initial, &digest).unwrap().open().unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let barrier = &barrier;
            for _ in 0..2 {
                let cache = &cache;
                let digest = &digest;
                let payload = &payload;
                scope.spawn(move || {
                    let mut pending = cache.staging_file().unwrap();
                    pending.write_all(payload).unwrap();
                    barrier.wait();
                    cache.publish(pending, digest).unwrap();
                });
            }
        });
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, payload);
        assert!(
            cache
                .lookup(&digest, &CancellationToken::new())
                .unwrap()
                .is_some()
        );
    }
}
