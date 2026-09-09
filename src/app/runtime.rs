use crate::progress::Progress;
use anyhow::{Context, Result, bail};
use std::future::Future;

pub(crate) async fn run_until_interrupted<F>(operation: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    tokio::select! {
        result = operation => result,
        signal = interruption_signal() => {
            signal?;
            bail!("interrupted")
        }
    }
}

async fn interruption_signal() -> Result<()> {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .context("installing Ctrl-C handler")
    };

    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("installing SIGTERM handler")?;
        tokio::select! {
            result = ctrl_c => result,
            signal = terminate.recv() => {
                signal.context("SIGTERM signal stream closed")?;
                Ok(())
            }
        }
    }

    #[cfg(not(unix))]
    ctrl_c.await
}

pub(crate) fn init_tracing(progress: &Progress) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("RIB_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(progress.tracing_writer())
        .with_ansi(progress.tracing_ansi())
        .try_init();
}
