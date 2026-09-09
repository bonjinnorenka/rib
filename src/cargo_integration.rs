mod cli;
mod config;
mod plan;
mod process;
#[cfg(test)]
mod tests;

use crate::{auth::Credentials, progress::Progress};
use anyhow::{Context, Result};
use cli::{CargoRibCommand, parse_args};
use plan::{resolve_plan, select_package};
use process::{cargo_executable, read_metadata, run_cargo_build, validate_artifact};

pub(crate) async fn run() -> Result<()> {
    let cli = parse_args();
    let arguments = match cli.command {
        CargoRibCommand::Build(arguments) => *arguments,
    };
    let progress = Progress::new(arguments.global.progress);
    crate::app::runtime::init_tracing(&progress);
    let credentials = Credentials::load(
        &arguments.global.credential,
        arguments.global.docker_config.as_deref(),
    )?;
    let current_dir = std::env::current_dir().context("reading current directory")?;
    let cargo = cargo_executable();
    let metadata = read_metadata(&cargo, &current_dir).await?;
    let package = select_package(&metadata, &current_dir)?;
    let plan = resolve_plan(&arguments, package, &current_dir)?;

    run_cargo_build(&cargo, &plan, &progress).await?;
    validate_artifact(&plan.artifact)?;

    plan.image.run(credentials, progress).await
}
