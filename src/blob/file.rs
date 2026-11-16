use anyhow::{Context, Result};
use std::{fs::File, path::PathBuf};
use tempfile::NamedTempFile;

use crate::safe_fs::reopen_verified_readonly;

/// Owns temporary storage, or holds a verified read-only handle to a published cache entry.
enum Storage {
    Temporary(NamedTempFile),
    Cached {
        file: File,
        path: PathBuf,
        #[cfg(unix)]
        dev_ino: (u64, u64),
    },
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

    pub(crate) fn cached(file: File, path: PathBuf) -> Result<Self> {
        #[cfg(unix)]
        let dev_ino = crate::safe_fs::file_dev_ino(&file)?;
        Ok(Self {
            storage: Storage::Cached {
                file,
                path,
                #[cfg(unix)]
                dev_ino,
            },
        })
    }

    pub fn open(&self) -> Result<File> {
        match &self.storage {
            Storage::Temporary(file) => file.reopen().context("opening temporary layer"),
            Storage::Cached {
                file,
                path,
                #[cfg(unix)]
                dev_ino,
            } => reopen_verified_readonly(
                file,
                path,
                #[cfg(unix)]
                *dev_ino,
            ),
        }
    }
}
