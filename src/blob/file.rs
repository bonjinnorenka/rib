use anyhow::{Context, Result};
use std::{fs::File, path::PathBuf};
use tempfile::NamedTempFile;

/// Owns temporary storage, or refers to an immutable published cache entry.
enum Storage {
    Temporary(NamedTempFile),
    Cached(PathBuf),
}

pub struct BlobFile {
    storage: Storage,
}

impl BlobFile {
    pub fn temporary(file: NamedTempFile) -> Self {
        Self {
            storage: Storage::Temporary(file),
        }
    }
    pub(crate) fn cached(path: PathBuf) -> Self {
        Self {
            storage: Storage::Cached(path),
        }
    }

    pub fn open(&self) -> Result<File> {
        match &self.storage {
            Storage::Temporary(file) => file.reopen().context("opening temporary layer"),
            Storage::Cached(path) => {
                File::open(path).with_context(|| format!("opening cached layer {}", path.display()))
            }
        }
    }
}
