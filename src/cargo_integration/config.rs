use crate::app::spec::parse_argv;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

/// An argv value in `package.metadata.rib`: either one shell-quoted line
/// (`entrypoint = "/bin/sh -c 'echo hi'"`) or an explicit array
/// (`entrypoint = ["/bin/sh", "-c", "echo hi"]`)
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(super) enum ConfigArgv {
    Line(String),
    Argv(Vec<String>),
}

impl ConfigArgv {
    pub(super) fn into_argv(self) -> Result<Vec<String>> {
        match self {
            Self::Line(line) => parse_argv(&line),
            Self::Argv(argv) => Ok(argv),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub(super) struct CargoRibConfig {
    pub(super) artifact: Option<PathBuf>,
    pub(super) platform: Option<String>,
    pub(super) from: Option<String>,
    pub(super) to: Vec<String>,
    pub(super) local_only: Option<bool>,
    pub(super) destination: Option<String>,
    pub(super) copies: Vec<String>,
    pub(super) entrypoint: Option<ConfigArgv>,
    pub(super) cmd: Option<ConfigArgv>,
    pub(super) labels: Vec<String>,
    pub(super) env: Vec<String>,
    pub(super) ports: Vec<String>,
    pub(super) workdir: Option<String>,
    pub(super) user: Option<String>,
    pub(super) keep_cmd: Option<bool>,
    pub(super) creation_time: Option<String>,
    pub(super) jobs: Option<usize>,
    pub(super) cargo_args: Vec<String>,
    pub(super) from_plain_http: Option<bool>,
    pub(super) from_skip_tls: Option<bool>,
    pub(super) to_plain_http: Option<bool>,
    pub(super) to_skip_tls: Option<bool>,
    pub(super) cache: Option<bool>,
    pub(super) cache_path: Option<PathBuf>,
    pub(super) read_timeout: Option<u64>,
    pub(super) connect_timeout: Option<u64>,
    pub(super) max_attempts: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CargoMetadata {
    pub(super) packages: Vec<CargoPackage>,
    #[serde(default)]
    pub(super) workspace_default_members: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CargoPackage {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) manifest_path: PathBuf,
    pub(super) metadata: serde_json::Value,
}

pub(super) fn parse_config(package: &CargoPackage) -> Result<CargoRibConfig> {
    let value = package
        .metadata
        .get("rib")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    serde_json::from_value(value)
        .with_context(|| format!("parsing package.metadata.rib for {}", package.name))
}
