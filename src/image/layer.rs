use crate::image::ImageSource;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use oci_spec::image::{Descriptor, DescriptorBuilder, Digest, MediaType};

#[derive(Debug, Clone)]
pub struct Layer {
    /// Digest of the uncompressed tar used by config.rootfs.diff_ids
    diff_id: Digest,
    descriptor: Descriptor,
    uncompressed_size: u64,
    storage: Arc<LayerStorage>,
}

#[derive(Debug)]
struct LayerStorage {
    _dir: tempfile::TempDir,
    compressed_path: PathBuf,
    uncompressed_path: Option<PathBuf>,
}

impl Layer {
    pub(crate) fn from_built_tar(
        directory: tempfile::TempDir,
        diff_id: Digest,
        digest: Digest,
        uncompressed_size: u64,
        compressed_size: u64,
        retain_uncompressed: bool,
    ) -> Result<Self> {
        let compressed_path = directory.path().join("layer.tar.gz");
        let uncompressed_path = retain_uncompressed.then(|| directory.path().join("layer.tar"));
        Ok(Self {
            diff_id,
            descriptor: DescriptorBuilder::default()
                .media_type(MediaType::ImageLayerGzip)
                .digest(digest)
                .size(compressed_size)
                .build()
                .context("building layer descriptor")?,
            uncompressed_size,
            storage: Arc::new(LayerStorage {
                _dir: directory,
                compressed_path,
                uncompressed_path,
            }),
        })
    }

    pub fn diff_id(&self) -> &Digest {
        &self.diff_id
    }
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    #[cfg(test)]
    pub fn compressed_path(&self) -> &std::path::Path {
        &self.storage.compressed_path
    }

    pub fn size(&self) -> u64 {
        self.descriptor.size()
    }

    pub fn open_compressed(&self) -> Result<std::fs::File> {
        std::fs::File::open(&self.storage.compressed_path)
            .with_context(|| format!("opening {}", self.storage.compressed_path.display()))
    }

    pub fn open_uncompressed(&self) -> Result<std::fs::File> {
        let path = self
            .storage
            .uncompressed_path
            .as_ref()
            .context("uncompressed layer was not retained")?;
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))
    }

    #[cfg(test)]
    pub fn compressed_bytes(&self) -> Result<Vec<u8>> {
        std::fs::read(&self.storage.compressed_path)
            .with_context(|| format!("reading {}", self.storage.compressed_path.display()))
    }

    #[cfg(test)]
    pub fn uncompressed_bytes(&self) -> Result<Vec<u8>> {
        let path = self
            .storage
            .uncompressed_path
            .as_ref()
            .context("uncompressed layer was not retained")?;
        std::fs::read(path).with_context(|| format!("reading {}", path.display()))
    }
}

#[derive(Debug, Clone)]
pub enum LayerSource {
    /// A new layer we built ourselves. The compressed blob is always retained;
    /// the uncompressed tar is retained only when a Docker archive needs it
    Built(Box<Layer>),
    /// A layer carried over from the base image. Only the descriptor and
    /// a back-reference to the source repository are kept here
    FromBase {
        descriptor: Box<Descriptor>,
        source: ImageSource,
    },
}

impl LayerSource {
    pub fn descriptor(&self) -> &Descriptor {
        match self {
            Self::Built(layer) => layer.descriptor(),
            Self::FromBase { descriptor, .. } => descriptor,
        }
    }
}
