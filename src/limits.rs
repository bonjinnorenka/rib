//! Resource exhaustion limits and shared download budget enforcement.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};

pub const DEFAULT_MAX_BLOB_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_blob_bytes: u64,
    pub max_total_download_bytes: u64,
    pub max_decompressed_bytes: u64,
    pub max_manifest_bytes: u64,
    pub transfer_timeout: Duration,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_blob_bytes: DEFAULT_MAX_BLOB_BYTES,
            max_total_download_bytes: DEFAULT_MAX_TOTAL_DOWNLOAD_BYTES,
            max_decompressed_bytes: DEFAULT_MAX_DECOMPRESSED_BYTES,
            max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            transfer_timeout: DEFAULT_TRANSFER_TIMEOUT,
        }
    }
}

impl ResourceLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_blob_bytes == 0 {
            bail!("--max-blob-size must be greater than zero");
        }
        if self.max_total_download_bytes == 0 {
            bail!("--max-total-download must be greater than zero");
        }
        if self.max_decompressed_bytes == 0 {
            bail!("--max-decompressed-size must be greater than zero");
        }
        if self.max_manifest_bytes == 0 {
            bail!("max manifest size must be greater than zero");
        }
        if self.transfer_timeout.is_zero() {
            bail!("--transfer-timeout must be greater than zero");
        }
        Ok(())
    }
}

/// Thread-safe cumulative byte budget across all registry downloads in a build.
#[derive(Debug, Clone)]
pub struct DownloadBudget {
    max_total_bytes: u64,
    used_bytes: Arc<AtomicU64>,
}

impl DownloadBudget {
    pub fn new(max_total_bytes: u64) -> Self {
        Self {
            max_total_bytes,
            used_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn reserve(&self, bytes: u64) -> Result<()> {
        self.used_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let next = current.checked_add(bytes)?;
                (next <= self.max_total_bytes).then_some(next)
            })
            .map(|_| ())
            .map_err(|current| {
                anyhow::anyhow!(
                    "total registry download size exceeds limit of {} bytes (already used {current} bytes, next chunk {bytes} bytes)",
                    self.max_total_bytes
                )
            })
    }

    #[cfg(test)]
    pub fn used(&self) -> u64 {
        self.used_bytes.load(Ordering::Relaxed)
    }
}

/// Parse an integer byte count with optional IEC/SI unit suffix (`K`, `KiB`, `M`, `MiB`, `G`, `GiB`).
pub fn parse_byte_size(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("byte size cannot be empty");
    }
    let split_idx = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (digits, suffix) = trimmed.split_at(split_idx);
    if digits.is_empty() {
        bail!("invalid byte size {raw:?}");
    }
    let base: u64 = digits
        .parse()
        .with_context(|| format!("invalid byte size number {raw:?}"))?;
    let multiplier: u64 = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "kib" => 1024,
        "m" | "mb" => 1_000_000,
        "mib" => 1024 * 1024,
        "g" | "gb" => 1_000_000_000,
        "gib" => 1024 * 1024 * 1024,
        other => bail!("unknown byte size unit {other:?} in {raw:?}"),
    };
    base.checked_mul(multiplier)
        .with_context(|| format!("byte size overflows u64: {raw:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_byte_sizes_and_units() {
        assert_eq!(parse_byte_size("1024").unwrap(), 1024);
        assert_eq!(parse_byte_size("64KiB").unwrap(), 65536);
        assert_eq!(parse_byte_size("10MiB").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_byte_size("2G").unwrap(), 2_000_000_000);
        assert_eq!(parse_byte_size("1GiB").unwrap(), 1024 * 1024 * 1024);
        assert!(parse_byte_size("").is_err());
        assert!(parse_byte_size("10TiB").is_err());
        assert!(parse_byte_size("0").unwrap() == 0);
    }

    #[test]
    fn download_budget_enforces_cumulative_limit() {
        let budget = DownloadBudget::new(100);
        budget.reserve(60).unwrap();
        budget.reserve(40).unwrap();
        assert!(budget.reserve(1).is_err());
        assert_eq!(budget.used(), 100);
    }
}
