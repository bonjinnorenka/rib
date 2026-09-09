use super::{config::CargoMetadata, plan::CargoBuildPlan};
use crate::progress::Progress;
use anyhow::{Context, Result, bail};
use std::{ffi::OsString, path::Path, process::Stdio};
use tokio::process::Command;

pub(super) fn cargo_executable() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

pub(super) async fn read_metadata(cargo: &OsString, current_dir: &Path) -> Result<CargoMetadata> {
    let mut command = Command::new(cargo);
    command
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(current_dir)
        .kill_on_drop(true);
    let output = command.output().await.context("running cargo metadata")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed with {}:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).context("parsing cargo metadata output")
}

pub(super) async fn run_cargo_build(
    cargo: &OsString,
    plan: &CargoBuildPlan,
    progress: &Progress,
) -> Result<()> {
    let task = progress.spinner(format!("cargo build ({})", plan.package_name));
    let mut command = Command::new(cargo);
    command
        .arg("build")
        .arg("--manifest-path")
        .arg(&plan.manifest_path)
        .args(&plan.cargo_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let status = command.status().await.context("running cargo build")?;
    if !status.success() {
        bail!("cargo build failed with {status}");
    }
    task.done();
    Ok(())
}

pub(super) fn validate_artifact(artifact: &Path) -> Result<()> {
    let metadata = std::fs::metadata(artifact)
        .with_context(|| format!("reading built artifact {}", artifact.display()))?;
    if !metadata.is_file() {
        bail!(
            "configured artifact is not a regular file: {}",
            artifact.display()
        );
    }
    Ok(())
}
