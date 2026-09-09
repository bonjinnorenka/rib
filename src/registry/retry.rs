use oci_client::errors::{OciDistributionError, OciErrorCode};
use std::{
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::warn;

#[derive(Clone, Copy)]
pub(super) struct RetryPolicy {
    pub(super) max_attempts: usize,
    pub(super) initial_delay: Duration,
    pub(super) max_delay: Duration,
}

pub(super) async fn retry_registry<T, F, Fut>(
    operation: &str,
    policy: RetryPolicy,
    mut action: F,
) -> oci_client::errors::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = oci_client::errors::Result<T>>,
{
    debug_assert!(policy.max_attempts > 0);
    let mut attempt = 1;
    loop {
        match action().await {
            Ok(value) => return Ok(value),
            Err(error) if attempt < policy.max_attempts && is_retryable_registry_error(&error) => {
                let delay = policy.delay_after(attempt);
                warn!(
                    operation,
                    attempt,
                    max_attempts = policy.max_attempts,
                    delay_ms = delay.as_millis(),
                    error = %error,
                    "transient registry operation failed; retrying"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

impl RetryPolicy {
    fn delay_after(self, failed_attempt: usize) -> Duration {
        let exponent = u32::try_from(failed_attempt.saturating_sub(1))
            .unwrap_or(u32::MAX)
            .min(31);
        let base = self
            .initial_delay
            .saturating_mul(1_u32 << exponent)
            .min(self.max_delay);
        if base.is_zero() || base == self.max_delay {
            return base;
        }

        // A small additive jitter prevents concurrent builders from retrying
        let window = base / 4;
        let window_nanos = u64::try_from(window.as_nanos()).unwrap_or(u64::MAX);
        let entropy = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let jitter = Duration::from_nanos(entropy % window_nanos.saturating_add(1));
        base.saturating_add(jitter).min(self.max_delay)
    }
}

pub(super) fn is_retryable_registry_error(error: &OciDistributionError) -> bool {
    match error {
        OciDistributionError::RequestError(error) => {
            error.is_timeout()
                || error.is_connect()
                || error.is_body()
                || error
                    .status()
                    .is_some_and(|status| is_retryable_status(status.as_u16()))
        }
        OciDistributionError::ServerError { code, .. } => is_retryable_status(*code),
        OciDistributionError::RegistryError { envelope, .. } => {
            !envelope.errors.is_empty()
                && envelope
                    .errors
                    .iter()
                    .all(|error| error.code == OciErrorCode::Toomanyrequests)
        }
        OciDistributionError::IoError(error) => is_retryable_io_error(error),
        _ => false,
    }
}

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 500 | 502..=599)
}

fn is_retryable_io_error(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    match error.kind() {
        ErrorKind::BrokenPipe
        | ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::HostUnreachable
        | ErrorKind::Interrupted
        | ErrorKind::NetworkDown
        | ErrorKind::NetworkUnreachable
        | ErrorKind::NotConnected
        | ErrorKind::TimedOut
        | ErrorKind::UnexpectedEof
        | ErrorKind::WouldBlock => true,
        ErrorKind::Other => error.get_ref().is_some_and(|source| {
            source
                .downcast_ref::<oci_client::errors::DigestError>()
                .is_none()
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    fn retry_policy_for_test(max_attempts: usize) -> RetryPolicy {
        RetryPolicy {
            max_attempts,
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    fn server_error(code: u16) -> OciDistributionError {
        OciDistributionError::ServerError {
            code,
            url: "https://registry.example.test/v2/".to_string(),
            message: "fixture".to_string(),
        }
    }

    #[test]
    fn retry_classifier_rejects_integrity_and_authentication_errors() {
        let digest_error = oci_client::errors::DigestError::VerificationError {
            expected: "sha256:expected".to_string(),
            actual: "sha256:actual".to_string(),
        };
        let digest_io = OciDistributionError::IoError(std::io::Error::other(digest_error));
        assert!(!is_retryable_registry_error(&digest_io));
        assert!(!is_retryable_registry_error(
            &OciDistributionError::UnauthorizedError {
                url: "https://registry.example.test/v2/".to_string()
            }
        ));
        assert!(is_retryable_registry_error(&server_error(429)));
        assert!(is_retryable_registry_error(&server_error(503)));
    }

    #[test]
    fn retry_delay_has_bounded_jitter() {
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
        };

        let delay = policy.delay_after(1);

        assert!(delay >= Duration::from_millis(100));
        assert!(delay <= Duration::from_millis(125));
    }

    #[tokio::test]
    async fn transient_registry_errors_are_retried_with_a_bound() {
        let attempts = AtomicUsize::new(0);
        let result = retry_registry("fixture", retry_policy_for_test(3), || {
            let attempt = attempts.fetch_add(1, AtomicOrdering::Relaxed);
            std::future::ready(if attempt < 2 {
                Err(server_error(503))
            } else {
                Ok(42)
            })
        })
        .await
        .unwrap();

        assert_eq!(result, 42);
        assert_eq!(attempts.load(AtomicOrdering::Relaxed), 3);
    }

    #[tokio::test]
    async fn permanent_registry_errors_are_not_retried() {
        let attempts = AtomicUsize::new(0);
        let result = retry_registry("fixture", retry_policy_for_test(3), || {
            attempts.fetch_add(1, AtomicOrdering::Relaxed);
            std::future::ready(Err::<(), _>(OciDistributionError::UnauthorizedError {
                url: "https://registry.example.test/v2/".to_string(),
            }))
        })
        .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(AtomicOrdering::Relaxed), 1);
    }
}
