mod decode;
mod file;
pub(crate) use file::BlobFile;

use std::collections::HashMap;
use std::fs::File;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, ensure};
use futures_util::{TryStreamExt, stream};
use oci_spec::image::{Descriptor, Digest};
use tempfile::NamedTempFile;
use tokio::sync::{OnceCell, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::cache::CacheController;
use crate::digest::short_digest;
use crate::image::{Image, ImageSource, layer::LayerSource};
use crate::limits::DEFAULT_MAX_DECOMPRESSED_BYTES;
use crate::progress::Progress;
use crate::registry::RegistryClient;

pub trait LayerProvider: Send + Sync {
    /// Each call returns an independent reader positioned at the beginning.
    fn blob_file(&self, source: &LayerSource) -> Result<File>;
    fn uncompressed_file(
        &self,
        source: &LayerSource,
        cancellation: &CancellationToken,
    ) -> Result<File>;
}

type BlobCell = Arc<OnceCell<Arc<BlobFile>>>;

/// Shared source for archive exports and fallback uploads. OnceCell coalesces
/// requests for a digest and allows another attempt after failure/cancellation.
/// Readers never share a file cursor.
pub struct LayerStore {
    files: Mutex<HashMap<Digest, BlobCell>>,
    cache: Option<CacheController>,
    slots: Arc<Semaphore>,
    jobs: usize,
    max_decompressed_bytes: u64,
}

impl LayerStore {
    #[allow(dead_code)]
    pub fn new(cache: Option<CacheController>, jobs: usize) -> Result<Self> {
        Self::with_max_decompressed_bytes(cache, jobs, DEFAULT_MAX_DECOMPRESSED_BYTES)
    }

    pub fn with_max_decompressed_bytes(
        cache: Option<CacheController>,
        jobs: usize,
        max_decompressed_bytes: u64,
    ) -> Result<Self> {
        ensure!(jobs > 0, "layer store jobs must be greater than zero");
        ensure!(
            max_decompressed_bytes > 0,
            "max decompressed bytes must be greater than zero"
        );
        Ok(Self {
            files: Mutex::new(HashMap::new()),
            cache,
            slots: Arc::new(Semaphore::new(jobs)),
            jobs,
            max_decompressed_bytes,
        })
    }

    fn cell(&self, digest: &Digest) -> Result<BlobCell> {
        Ok(self
            .files
            .lock()
            .map_err(|_| anyhow!("layer store lock poisoned"))?
            .entry(digest.clone())
            .or_default()
            .clone())
    }

    pub async fn get(
        &self,
        client: Option<&RegistryClient>,
        source: &ImageSource,
        descriptor: &Descriptor,
        progress: &Progress,
    ) -> Result<Arc<BlobFile>> {
        let cell = self.cell(descriptor.digest())?;
        let blob = cell
            .get_or_try_init(|| async {
                let permit = self
                    .slots
                    .clone()
                    .acquire_owned()
                    .await
                    .context("layer store closed")?;
                let cancellation = CancellationToken::new();
                let _cancel_on_drop = cancellation.clone().drop_guard();
                let cache = self.cache.clone();
                let digest = descriptor.digest().clone();
                // Keep the permit in the worker until cancellation is observed.
                let (cached, permit) = tokio::task::spawn_blocking(move || {
                    let cached = cache
                        .as_ref()
                        .map(|cache| cache.lookup(&digest, &cancellation))
                        .transpose()?
                        .flatten();
                    Ok::<_, anyhow::Error>((cached, permit))
                })
                .await
                .context("cache verification worker panicked")??;
                let _permit = permit;
                if let Some(blob) = cached {
                    progress.note(format!("cache hit for layer `{}`", descriptor.digest()));
                    return Ok(Arc::new(blob));
                }

                let client = client.context("base layer requires a source registry client")?;
                let cache = self.cache.clone();
                let mut temporary = tokio::task::spawn_blocking(move || match cache {
                    Some(cache) => cache.staging_file(),
                    None => NamedTempFile::new().context("creating layer staging file"),
                })
                .await
                .context("layer staging worker panicked")??;
                let task = progress.bytes(
                    format!("pull layer {}", short_digest(descriptor.digest())),
                    descriptor.size(),
                );
                let bar = task.progress_bar();
                client
                    .fetch_layer_to_file(
                        &source.reference,
                        descriptor,
                        temporary.as_file_mut(),
                        move |bytes| {
                            if let Some(bar) = &bar {
                                bar.inc(bytes);
                            }
                        },
                    )
                    .await?;
                let cache = self.cache.clone();
                let digest = descriptor.digest().clone();
                let blob = tokio::task::spawn_blocking(move || match cache {
                    Some(cache) => cache.publish(temporary, &digest),
                    None => Ok(BlobFile::temporary(temporary)),
                })
                .await
                .context("layer publication worker panicked")??;
                task.done();
                Ok::<_, anyhow::Error>(Arc::new(blob))
            })
            .await?;
        Ok(blob.clone())
    }

    pub async fn prefetch(
        &self,
        client: Option<&RegistryClient>,
        base: &Image,
        progress: &Progress,
    ) -> Result<()> {
        if base.layers.is_empty() {
            return Ok(());
        }
        let source = base
            .source
            .as_ref()
            .context("base image layers are missing their registry source")?;
        stream::iter(base.layers.iter().map(Ok::<_, anyhow::Error>))
            .try_for_each_concurrent(self.jobs, |descriptor| async move {
                self.get(client, source, descriptor, progress).await?;
                Ok(())
            })
            .await
    }
}

impl LayerProvider for LayerStore {
    fn blob_file(&self, source: &LayerSource) -> Result<File> {
        match source {
            LayerSource::Built(layer) => layer.open_compressed(),
            LayerSource::FromBase { descriptor, .. } => self
                .cell(descriptor.digest())?
                .get()
                .with_context(|| format!("layer {} was not downloaded", descriptor.digest()))?
                .open(),
        }
    }

    fn uncompressed_file(
        &self,
        source: &LayerSource,
        cancellation: &CancellationToken,
    ) -> Result<File> {
        match source {
            LayerSource::Built(layer) => layer.open_uncompressed(),
            LayerSource::FromBase { .. } => decode::decode_to_temp(
                &mut self.blob_file(source)?,
                source.descriptor().media_type(),
                self.max_decompressed_bytes,
                cancellation,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{digest::sha256_digest, progress::ProgressMode};
    use oci_spec::image::{DescriptorBuilder, MediaType};
    use std::io::{Read, Seek, SeekFrom, Write};

    #[tokio::test]
    async fn cached_layer_is_shared_but_readers_have_independent_cursors() {
        let directory = tempfile::tempdir().unwrap();
        let cache = CacheController::new(Some(directory.path())).unwrap();
        let digest = sha256_digest(b"abcdef");
        let mut file = cache.staging_file().unwrap();
        file.write_all(b"abcdef").unwrap();
        cache.publish(file, &digest).unwrap();
        let store = LayerStore::new(Some(cache), 2).unwrap();
        let source = ImageSource {
            reference: "source.test/base:v1".parse().unwrap(),
            manifest_digest: sha256_digest(b"manifest"),
        };
        let descriptor = DescriptorBuilder::default()
            .digest(digest)
            .size(6_u64)
            .media_type(MediaType::ImageLayer)
            .build()
            .unwrap();
        let progress = Progress::new(ProgressMode::Quiet);
        let (a, b) = tokio::try_join!(
            store.get(None, &source, &descriptor, &progress),
            store.get(None, &source, &descriptor, &progress)
        )
        .unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let mut first = a.open().unwrap();
        let mut second = b.open().unwrap();
        first.seek(SeekFrom::Start(3)).unwrap();
        let mut bytes = Vec::new();
        second.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcdef");
        assert!(Arc::ptr_eq(
            &a,
            &store
                .get(None, &source, &descriptor, &progress)
                .await
                .unwrap()
        ));
    }

    #[test]
    fn temporary_readers_are_independent() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"abcdef").unwrap();
        let blob = BlobFile::temporary(file);
        let mut a = blob.open().unwrap();
        let mut b = blob.open().unwrap();
        a.seek(SeekFrom::Start(3)).unwrap();
        let mut bytes = Vec::new();
        b.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abcdef");
    }
}
