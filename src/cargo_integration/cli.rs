use crate::{
    cli::{CacheArgs, GlobalArgs, ImageConfigArgs, RegistryClientArgs, ResourceLimitArgs},
    output_target::OutputTarget,
};
use clap::{Args, Parser, Subcommand};
use std::{ffi::OsString, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "cargo-rib",
    bin_name = "cargo rib",
    version,
    about = "Build a Rust package and package its explicit artifact as an OCI image"
)]
pub(super) struct CargoRibCli {
    #[command(subcommand)]
    pub(super) command: CargoRibCommand,
}

#[derive(Subcommand)]
pub(super) enum CargoRibCommand {
    /// Build an image and write it to one or more outputs
    Build(Box<CargoRibArgs>),
}

#[derive(Args)]
pub(super) struct CargoRibArgs {
    /// Path to the binary produced by cargo build. Required here or in package.metadata.rib
    #[arg(long)]
    pub(super) artifact: Option<PathBuf>,

    /// OCI platform, for example linux/amd64. Required here or in package.metadata.rib
    #[arg(long)]
    pub(super) platform: Option<String>,

    /// Base image reference or the exact value `scratch`
    #[arg(long)]
    pub(super) from: Option<String>,

    /// Output target. Repeatable; replaces targets from package.metadata.rib
    #[arg(long = "to")]
    pub(super) targets: Vec<OutputTarget>,

    /// Forbid pushing to container registries; allow only local archive outputs
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    pub(super) local_only: Option<bool>,

    /// Exact path of the artifact inside the image. Defaults to /app/<artifact-name>
    #[arg(long)]
    pub(super) destination: Option<String>,

    /// Additional file or directory to copy. Repeatable and appended after configured copies
    #[arg(long = "copy")]
    pub(super) copies: Vec<String>,

    /// Restrict COPY sources and artifact to files inside these directories (repeatable)
    #[arg(long = "copy-root")]
    pub(super) copy_roots: Vec<PathBuf>,

    #[command(flatten)]
    pub(super) image: ImageConfigArgs,

    /// Image creation timestamp: epoch, now, or an RFC3339 value
    #[arg(long)]
    pub(super) creation_time: Option<String>,

    /// Maximum number of COPY layers and blob transfers processed concurrently
    #[arg(long)]
    pub(super) jobs: Option<usize>,

    #[command(flatten)]
    pub(super) global: GlobalArgs,

    #[command(flatten)]
    pub(super) client: RegistryClientArgs,

    #[command(flatten)]
    pub(super) limits: ResourceLimitArgs,

    #[command(flatten)]
    pub(super) cache: CacheArgs,

    /// Arguments passed to cargo build. Must follow `--`
    #[arg(last = true, allow_hyphen_values = true)]
    pub(super) cargo_args: Vec<String>,
}

pub(super) fn parse_args() -> CargoRibCli {
    let mut arguments: Vec<OsString> = std::env::args_os().collect();
    if arguments.get(1).is_some_and(|argument| argument == "rib") {
        arguments.remove(1);
    }
    CargoRibCli::parse_from(arguments)
}
