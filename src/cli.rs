use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

use crate::app::spec::{
    CacheSpec, CopyDirective, ImageBuildSpec, RegistryOverrides, default_jobs, parse_argv,
};
use crate::limits::{ResourceLimits, parse_byte_size};
use crate::output_target::OutputTarget;
use crate::progress::ProgressMode;
use crate::registry::NetworkPolicy;

#[derive(Parser)]
#[command(name = "rib", version, about = "Minimal jib-like OCI image builder")]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

/// Arguments shared verbatim between `rib` (where they are global) and
/// `cargo rib build`
#[derive(Args)]
pub struct GlobalArgs {
    /// Path to docker config.json. Default: $DOCKER_CONFIG/config.json or ~/.docker/config.json
    #[arg(long, global = true)]
    pub docker_config: Option<PathBuf>,

    /// Explicit credential, repeatable. Form: <registry>=<user>:<pass>
    /// Takes precedence over docker config
    #[arg(long = "credential", global = true)]
    pub credential: Vec<String>,

    /// Progress output format
    #[arg(long, global = true, value_enum, default_value_t = ProgressMode::Auto)]
    pub progress: ProgressMode,
}

#[derive(Subcommand)]
pub enum Command {
    /// Build an image and write it to one or more outputs
    Build(Box<BuildArgs>),
}

/// Container-config arguments accepted by both `rib build` and
/// `cargo rib build`
#[derive(Args)]
pub struct ImageConfigArgs {
    /// Entrypoint argv as one shell-quoted line
    /// Quotes group words: '/bin/sh -c "echo hello world"'
    #[arg(long = "entrypoint", verbatim_doc_comment)]
    pub entrypoint: Option<String>,

    /// Cmd argv as one shell-quoted line, like the entrypoint
    #[arg(long = "cmd")]
    pub cmd: Option<String>,

    /// Image label. Repeatable. Form: key=value
    #[arg(long = "label")]
    pub labels: Vec<String>,

    /// Exposed port. Repeatable. Form: 8080 or 8080/tcp
    #[arg(long = "port")]
    pub ports: Vec<String>,

    /// Working directory for the container
    #[arg(long)]
    pub workdir: Option<String>,

    /// User the container runs as
    #[arg(long)]
    pub user: Option<String>,

    /// Keep the base image Cmd when overriding entrypoint
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    pub keep_cmd: Option<bool>,
}

/// Registry transport arguments shared by both binaries. Timeouts stay
/// `Option` so `cargo rib` can tell "user passed a flag" apart from the
/// default and let the flag override `package.metadata.rib`
#[derive(Args)]
pub struct RegistryClientArgs {
    /// Use HTTP for the source registry
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    pub from_plain_http: Option<bool>,

    /// Disable TLS certificate verification for the source registry
    /// INSECURE: accepts any certificate, including a forged one, so a
    /// network attacker could serve a malicious base image undetected. The
    /// underlying HTTP client has no per-host toggle, so this weakens every
    /// request this build makes to the source registry. Use only for a
    /// trusted local or development registry, never in production
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    pub from_skip_tls: Option<bool>,

    /// Use HTTP for registry output targets
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    pub to_plain_http: Option<bool>,

    /// Disable TLS certificate verification for registry output targets
    /// INSECURE: accepts any certificate, including a forged one. All `--to
    /// registry:...` targets in this run share one HTTP client, so this
    /// weakens TLS for every target registry, not just the one you intend
    /// Use only for a trusted local or development registry, never in
    /// production
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    pub to_skip_tls: Option<bool>,

    /// Registry read timeout in seconds [default: 60]
    #[arg(long)]
    pub read_timeout: Option<u64>,

    /// Registry connect timeout in seconds [default: 30]
    #[arg(long)]
    pub connect_timeout: Option<u64>,

    /// Attempts per registry operation before giving up [default: 3]
    #[arg(long)]
    pub max_attempts: Option<usize>,

    /// Restrict source and target registries to these hostnames (repeatable)
    #[arg(long = "allow-registry")]
    pub allow_registry: Vec<String>,

    /// Restrict credential transmission (Basic/Bearer exchange) to these hostnames (repeatable)
    #[arg(long = "allow-auth-host")]
    pub allow_auth_host: Vec<String>,

    /// Allow external descriptor blob URLs and restrict blob CDN redirects to these hostnames (repeatable)
    #[arg(long = "allow-blob-host")]
    pub allow_blob_host: Vec<String>,

    /// Allow loopback and RFC1918/ULA private IPs for local test registries (cloud metadata remains blocked)
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    pub allow_private_network: Option<bool>,
}

impl RegistryClientArgs {
    pub(crate) fn network_policy(&self) -> NetworkPolicy {
        NetworkPolicy {
            allowed_registries: self.allow_registry.clone(),
            allowed_auth_hosts: self.allow_auth_host.clone(),
            allowed_blob_hosts: self.allow_blob_host.clone(),
            allow_private_network: self.allow_private_network.unwrap_or(false),
        }
    }
}

impl From<&RegistryClientArgs> for RegistryOverrides {
    fn from(arguments: &RegistryClientArgs) -> Self {
        Self {
            source_plain_http: arguments.from_plain_http,
            source_skip_tls: arguments.source_skip_tls(),
            target_plain_http: arguments.to_plain_http,
            target_skip_tls: arguments.target_skip_tls(),
            connect_timeout: arguments.connect_timeout.map(Duration::from_secs),
            read_timeout: arguments.read_timeout.map(Duration::from_secs),
            max_attempts: arguments.max_attempts,
        }
    }
}

impl RegistryClientArgs {
    fn source_skip_tls(&self) -> Option<bool> {
        self.from_skip_tls
    }

    fn target_skip_tls(&self) -> Option<bool> {
        self.to_skip_tls
    }
}

/// Resource limits shared between `rib build` and `cargo rib build`
#[derive(Args, Default)]
pub struct ResourceLimitArgs {
    /// Maximum size of a single downloaded registry blob (supports K/M/G/KiB/MiB/GiB)
    #[arg(long = "max-blob-size", value_parser = parse_byte_size)]
    pub max_blob_size: Option<u64>,

    /// Maximum cumulative bytes downloaded from registries in one build
    #[arg(long = "max-total-download", value_parser = parse_byte_size)]
    pub max_total_download: Option<u64>,

    /// Maximum decompressed size of a single base image layer
    #[arg(long = "max-decompressed-size", value_parser = parse_byte_size)]
    pub max_decompressed_size: Option<u64>,

    /// Maximum duration in seconds for a single registry transfer operation [default: 600]
    #[arg(long = "transfer-timeout")]
    pub transfer_timeout: Option<u64>,
}

impl From<&ResourceLimitArgs> for ResourceLimits {
    fn from(arguments: &ResourceLimitArgs) -> Self {
        let defaults = Self::default();
        Self {
            max_blob_bytes: arguments.max_blob_size.unwrap_or(defaults.max_blob_bytes),
            max_total_download_bytes: arguments
                .max_total_download
                .unwrap_or(defaults.max_total_download_bytes),
            max_decompressed_bytes: arguments
                .max_decompressed_size
                .unwrap_or(defaults.max_decompressed_bytes),
            max_manifest_bytes: defaults.max_manifest_bytes,
            transfer_timeout: arguments
                .transfer_timeout
                .map(Duration::from_secs)
                .unwrap_or(defaults.transfer_timeout),
        }
    }
}

/// Layer-cache arguments shared by both binaries
#[derive(Args)]
pub struct CacheArgs {
    /// Cache downloaded base layers. Uses ./.rib-cache unless --cache-path is set
    #[arg(long = "cache", action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    pub cache: Option<bool>,

    /// Directory for cached layers
    #[arg(long = "cache-path")]
    pub cache_path: Option<PathBuf>,
}

impl From<CacheArgs> for CacheSpec {
    fn from(arguments: CacheArgs) -> Self {
        Self {
            enable: arguments.cache.unwrap_or_default(),
            cache_path: arguments.cache_path,
        }
    }
}

#[derive(Args)]
pub struct BuildArgs {
    /// Base image reference or the exact value `scratch`
    #[arg(long)]
    pub from: String,

    /// Output target. Repeatable. Forms:
    ///   oci-archive:<path>[@<tag>]
    ///   docker-archive:<path>[@<tag>]
    ///   registry:<image-ref>
    #[arg(long = "to", required = true, verbatim_doc_comment)]
    pub targets: Vec<OutputTarget>,

    /// Forbid pushing to container registries; allow only local archive outputs
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    pub local_only: Option<bool>,

    /// Copy a local path into the image. Repeatable; each --copy
    /// becomes its own layer in flag order
    ///
    /// Form: <src>:<dst>[,key=value,...]
    ///
    /// Destination semantics follow Dockerfile COPY:
    ///   /app/              destination directory
    ///   /app/file         exact destination path for a single file
    ///   <directory>:/app/ copy directory contents into /app/
    ///
    /// Quote globs so the shell does not expand them before rib:
    ///   --copy 'target/release/*.so:/lib/'
    ///
    /// Options:
    ///   mode=<octal>          file mode, for example mode=0755
    ///   chown=<uid>[:<gid>]   ownership; gid defaults to 0
    #[arg(long = "copy", verbatim_doc_comment)]
    pub copies: Vec<String>,

    /// Restrict COPY sources to files and directories inside these directories (repeatable)
    #[arg(long = "copy-root")]
    pub copy_roots: Vec<PathBuf>,

    /// Maximum number of COPY layers and blob transfers processed concurrently
    #[arg(long, default_value_t = default_jobs())]
    pub jobs: usize,

    #[command(flatten)]
    pub image: ImageConfigArgs,

    /// Target platform
    #[arg(long, default_value = "linux/amd64")]
    pub platform: String,

    /// Image creation timestamp: epoch, now, or an RFC3339 value
    #[arg(long, default_value = "epoch")]
    pub creation_time: String,

    #[command(flatten)]
    pub client: RegistryClientArgs,

    #[command(flatten)]
    pub limits: ResourceLimitArgs,

    #[command(flatten)]
    pub cache: CacheArgs,
}

impl TryFrom<BuildArgs> for ImageBuildSpec {
    type Error = anyhow::Error;

    fn try_from(arguments: BuildArgs) -> Result<Self> {
        let copies = arguments
            .copies
            .into_iter()
            .map(CopyDirective::parse)
            .collect::<Result<_>>()?;

        let network_policy = arguments.client.network_policy();
        let limits = ResourceLimits::from(&arguments.limits);
        Ok(Self {
            from: arguments.from,
            targets: arguments.targets,
            local_only: arguments.local_only.unwrap_or(false),
            copies,
            copy_roots: arguments.copy_roots,
            jobs: arguments.jobs,
            platform: arguments.platform,
            entrypoint: arguments
                .image
                .entrypoint
                .as_deref()
                .map(parse_argv)
                .transpose()?,
            cmd: arguments.image.cmd.as_deref().map(parse_argv).transpose()?,
            labels: arguments.image.labels,
            ports: arguments.image.ports,
            workdir: arguments.image.workdir,
            user: arguments.image.user,
            creation_time: arguments.creation_time,
            keep_cmd: arguments.image.keep_cmd.unwrap_or_default(),
            transport: RegistryOverrides::from(&arguments.client).into(),
            network_policy,
            limits,
            cache: arguments.cache.into(),
        })
    }
}

pub fn parse() -> Cli {
    Cli::parse()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::spec::RegistryClientSpec;
    use crate::registry::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT};
    use std::path::Path;

    #[test]
    fn global_arguments_parse_after_the_subcommand() {
        let cli = Cli::try_parse_from([
            "rib",
            "build",
            "--from",
            "scratch",
            "--to",
            "oci-archive:image.tar",
            "--docker-config",
            "/tmp/config.json",
            "--progress",
            "quiet",
        ])
        .unwrap();
        assert_eq!(
            cli.global.docker_config.as_deref(),
            Some(Path::new("/tmp/config.json"))
        );
    }

    #[test]
    fn registry_client_arguments_fall_back_to_defaults() {
        let arguments = RegistryClientArgs {
            from_plain_http: None,
            from_skip_tls: None,
            to_plain_http: None,
            to_skip_tls: None,
            read_timeout: None,
            connect_timeout: None,
            max_attempts: Some(5),
            allow_registry: Vec::new(),
            allow_auth_host: Vec::new(),
            allow_blob_host: Vec::new(),
            allow_private_network: None,
        };
        let spec: RegistryClientSpec = RegistryOverrides::from(&arguments).into();
        assert_eq!(spec.read_timeout, DEFAULT_READ_TIMEOUT);
        assert_eq!(spec.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
        assert_eq!(spec.max_attempts, 5);
    }
    #[test]
    fn boolean_flags_preserve_short_form_and_allow_explicit_false() {
        for explicit in ["--cache", "--cache=true", "--cache=false"] {
            let cli = Cli::try_parse_from([
                "rib",
                "build",
                "--from",
                "scratch",
                "--to",
                "oci-archive:image.tar",
                explicit,
            ])
            .unwrap();
            let Command::Build(args) = cli.command;
            let spec = ImageBuildSpec::try_from(*args).unwrap();
            assert_eq!(spec.cache.enable, explicit != "--cache=false");
        }
        assert!(
            Cli::try_parse_from([
                "rib",
                "build",
                "--from",
                "scratch",
                "--to",
                "oci-archive:image.tar",
                "--cache=maybe"
            ])
            .is_err()
        );
    }
}
