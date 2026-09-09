use crate::{
    builder::copy::CopySpec, image::Platform, output_target::OutputTarget,
    registry::RegistryOptions,
};
use anyhow::{Context, Result, bail};
use oci_client::Reference;
use std::str::FromStr;
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

#[derive(Debug, Clone)]
pub(crate) struct CopyDirective {
    description: String,
    specification: CopySpec,
}

impl CopyDirective {
    pub(crate) fn parse(raw: String) -> Result<Self> {
        let specification =
            CopySpec::from_str(&raw).with_context(|| format!("parsing COPY directive {raw:?}"))?;
        Ok(Self::new(raw, specification))
    }

    pub(crate) fn new(description: String, specification: CopySpec) -> Self {
        Self {
            description,
            specification,
        }
    }

    #[cfg(test)]
    pub(crate) fn description(&self) -> &str {
        &self.description
    }

    #[cfg(test)]
    pub(crate) fn specification(&self) -> &CopySpec {
        &self.specification
    }

    pub(super) fn into_parts(self) -> (String, CopySpec) {
        (self.description, self.specification)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RegistryClientSpec {
    pub(crate) source_plain_http: bool,
    pub(crate) source_skip_tls: bool,
    pub(crate) target_plain_http: bool,
    pub(crate) target_skip_tls: bool,
    pub(crate) connect_timeout: Duration,
    pub(crate) read_timeout: Duration,
    pub(crate) max_attempts: usize,
}

impl Default for RegistryClientSpec {
    fn default() -> Self {
        Self {
            source_plain_http: false,
            source_skip_tls: false,
            target_plain_http: false,
            target_skip_tls: false,
            connect_timeout: crate::registry::DEFAULT_CONNECT_TIMEOUT,
            read_timeout: crate::registry::DEFAULT_READ_TIMEOUT,
            max_attempts: crate::registry::DEFAULT_MAX_ATTEMPTS,
        }
    }
}

/// Optional transport settings shared by CLI and metadata adapters.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RegistryOverrides {
    pub source_plain_http: Option<bool>,
    pub source_skip_tls: Option<bool>,
    pub target_plain_http: Option<bool>,
    pub target_skip_tls: Option<bool>,
    pub connect_timeout: Option<Duration>,
    pub read_timeout: Option<Duration>,
    pub max_attempts: Option<usize>,
}

impl RegistryOverrides {
    pub fn with_fallback(self, fallback: Self) -> Self {
        Self {
            source_plain_http: self.source_plain_http.or(fallback.source_plain_http),
            source_skip_tls: self.source_skip_tls.or(fallback.source_skip_tls),
            target_plain_http: self.target_plain_http.or(fallback.target_plain_http),
            target_skip_tls: self.target_skip_tls.or(fallback.target_skip_tls),
            connect_timeout: self.connect_timeout.or(fallback.connect_timeout),
            read_timeout: self.read_timeout.or(fallback.read_timeout),
            max_attempts: self.max_attempts.or(fallback.max_attempts),
        }
    }
}

impl From<RegistryOverrides> for RegistryClientSpec {
    fn from(settings: RegistryOverrides) -> Self {
        let defaults = Self::default();
        Self {
            source_plain_http: settings
                .source_plain_http
                .unwrap_or(defaults.source_plain_http),
            source_skip_tls: settings.source_skip_tls.unwrap_or(defaults.source_skip_tls),
            target_plain_http: settings
                .target_plain_http
                .unwrap_or(defaults.target_plain_http),
            target_skip_tls: settings.target_skip_tls.unwrap_or(defaults.target_skip_tls),
            connect_timeout: settings.connect_timeout.unwrap_or(defaults.connect_timeout),
            read_timeout: settings.read_timeout.unwrap_or(defaults.read_timeout),
            max_attempts: settings.max_attempts.unwrap_or(defaults.max_attempts),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CacheSpec {
    pub(crate) enable: bool,
    pub(crate) cache_path: Option<PathBuf>,
}

/// Parse a shell-quoted command line into argv, so values like
/// `/bin/sh -c "echo hello world"` keep quoted words together
pub(crate) fn parse_argv(line: &str) -> Result<Vec<String>> {
    shlex::split(line)
        .ok_or_else(|| anyhow::anyhow!("invalid shell quoting in command line {line:?}"))
}

#[derive(Debug)]
pub(crate) struct ImageBuildSpec {
    pub(crate) from: String,
    pub(crate) targets: Vec<OutputTarget>,
    pub(crate) copies: Vec<CopyDirective>,
    pub(crate) jobs: usize,
    pub(crate) platform: String,
    pub(crate) entrypoint: Option<Vec<String>>,
    pub(crate) cmd: Option<Vec<String>>,
    pub(crate) labels: Vec<String>,
    pub(crate) ports: Vec<String>,
    pub(crate) workdir: Option<String>,
    pub(crate) user: Option<String>,
    pub(crate) creation_time: String,
    pub(crate) keep_cmd: bool,
    pub(crate) transport: RegistryClientSpec,
    pub(crate) cache: CacheSpec,
}

pub(crate) fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(4)
}

pub struct BuildRequest {
    pub(super) source: Option<Reference>,
    pub(super) targets: Vec<OutputTarget>,
    pub(super) copies: Vec<CopyDirective>,
    pub(super) jobs: usize,
    pub(super) platform: Platform,
    pub(super) entrypoint: Option<Vec<String>>,
    pub(super) cmd: Option<Vec<String>>,
    pub(super) labels: BTreeMap<String, String>,
    pub(super) ports: Vec<String>,
    pub(super) workdir: Option<String>,
    pub(super) user: Option<String>,
    pub(super) creation_time: Option<String>,
    pub(super) keep_cmd: bool,
    pub(super) source_registry: RegistryOptions,
    pub(super) target_registry: RegistryOptions,
    pub(super) cache: CacheSpec,
}

#[cfg(test)]
impl BuildRequest {
    #[cfg(test)]
    pub(crate) fn copies(&self) -> &[CopyDirective] {
        &self.copies
    }

    #[cfg(test)]
    pub(crate) fn cmd(&self) -> Option<&[String]> {
        self.cmd.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn entrypoint(&self) -> Option<&[String]> {
        self.entrypoint.as_deref()
    }
    pub(crate) fn cache(&self) -> &CacheSpec {
        &self.cache
    }
    pub(crate) fn transport(&self) -> (&RegistryOptions, &RegistryOptions) {
        (&self.source_registry, &self.target_registry)
    }
    pub(crate) fn keep_cmd(&self) -> bool {
        self.keep_cmd
    }
}

impl TryFrom<ImageBuildSpec> for BuildRequest {
    type Error = anyhow::Error;

    fn try_from(specification: ImageBuildSpec) -> Result<Self> {
        if specification.jobs == 0 {
            bail!("jobs must be greater than zero");
        }
        if specification.transport.max_attempts == 0 {
            bail!("max attempts must be greater than zero");
        }
        if specification.transport.connect_timeout.is_zero()
            || specification.transport.read_timeout.is_zero()
        {
            bail!("registry timeouts must be greater than zero");
        }
        if specification.targets.is_empty() {
            bail!("at least one output target is required");
        }
        let source = if specification.from == "scratch" {
            None
        } else {
            Some(specification.from.parse().with_context(|| {
                format!("parsing source image reference {:?}", specification.from)
            })?)
        };
        let labels = specification
            .labels
            .into_iter()
            .map(|label| {
                let (key, value) = label.split_once('=').ok_or_else(|| {
                    anyhow::anyhow!("invalid label {label:?}; expected key=value")
                })?;
                Ok((key.to_string(), value.to_string()))
            })
            .collect::<Result<_>>()?;
        let ports = specification
            .ports
            .into_iter()
            .map(|port| {
                if port.contains('/') {
                    port
                } else {
                    format!("{port}/tcp")
                }
            })
            .collect();
        let (source_registry, target_registry) = registry_options(
            source.as_ref(),
            &specification.targets,
            specification.transport,
        );

        Ok(Self {
            source,
            targets: specification.targets,
            copies: specification.copies,
            jobs: specification.jobs,
            platform: Platform::from_str(&specification.platform)?,
            entrypoint: specification.entrypoint,
            cmd: specification.cmd,
            labels,
            ports,
            workdir: specification.workdir,
            user: specification.user,
            creation_time: parse_creation_time(&specification.creation_time)?,
            keep_cmd: specification.keep_cmd,
            source_registry,
            target_registry,
            cache: specification.cache,
        })
    }
}

fn registry_options(
    source: Option<&Reference>,
    targets: &[OutputTarget],
    transport: RegistryClientSpec,
) -> (RegistryOptions, RegistryOptions) {
    let source = RegistryOptions {
        plain_http_hosts: source
            .filter(|_| transport.source_plain_http)
            .map(|source| source.resolve_registry().to_string())
            .into_iter()
            .collect(),
        skip_tls_verify: source.is_some() && transport.source_skip_tls,
        connect_timeout: transport.connect_timeout,
        read_timeout: transport.read_timeout,
        max_attempts: transport.max_attempts,
    };
    let mut target_hosts: Vec<String> = if transport.target_plain_http {
        targets
            .iter()
            .filter_map(|target| match target {
                OutputTarget::Registry { reference } => {
                    Some(reference.resolve_registry().to_string())
                }
                _ => None,
            })
            .collect()
    } else {
        Vec::new()
    };
    target_hosts.sort();
    target_hosts.dedup();
    let target = RegistryOptions {
        plain_http_hosts: target_hosts,
        skip_tls_verify: transport.target_skip_tls,
        connect_timeout: transport.connect_timeout,
        read_timeout: transport.read_timeout,
        max_attempts: transport.max_attempts,
    };
    (source, target)
}

fn parse_creation_time(value: &str) -> Result<Option<String>> {
    match value {
        "epoch" => Ok(None),
        "now" => Ok(Some(
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        )),
        value => {
            chrono::DateTime::parse_from_rfc3339(value).with_context(|| {
                format!("invalid creation time {value:?} (expected `epoch`, `now`, or RFC3339)")
            })?;
            Ok(Some(value.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_lines_support_shell_quoting() {
        assert_eq!(
            parse_argv(r#"/bin/sh -c "echo hello world""#).unwrap(),
            vec!["/bin/sh", "-c", "echo hello world"]
        );
        assert_eq!(
            parse_argv("java -jar app.jar").unwrap(),
            vec!["java", "-jar", "app.jar"]
        );
        assert!(parse_argv(r#"unterminated "quote"#).is_err());
    }

    #[test]
    fn zero_transport_values_are_rejected() {
        let target = "oci-archive:image.tar".parse::<OutputTarget>().unwrap();
        let specification = |transport: RegistryClientSpec| ImageBuildSpec {
            from: "scratch".to_string(),
            targets: vec![target.clone()],
            copies: Vec::new(),
            jobs: 1,
            platform: "linux/amd64".to_string(),
            entrypoint: None,
            cmd: None,
            labels: Vec::new(),
            ports: Vec::new(),
            workdir: None,
            user: None,
            creation_time: "epoch".to_string(),
            keep_cmd: false,
            transport,
            cache: CacheSpec::default(),
        };

        let zero_attempts = RegistryClientSpec {
            max_attempts: 0,
            ..RegistryClientSpec::default()
        };
        assert!(
            BuildRequest::try_from(specification(zero_attempts))
                .map(|_| ())
                .unwrap_err()
                .to_string()
                .contains("max attempts")
        );

        let zero_timeout = RegistryClientSpec {
            read_timeout: Duration::ZERO,
            ..RegistryClientSpec::default()
        };
        assert!(
            BuildRequest::try_from(specification(zero_timeout))
                .map(|_| ())
                .unwrap_err()
                .to_string()
                .contains("timeouts")
        );

        assert!(BuildRequest::try_from(specification(RegistryClientSpec::default())).is_ok());
    }

    #[test]
    fn creation_time_modes_are_validated() {
        assert!(parse_creation_time("epoch").unwrap().is_none());
        let now = parse_creation_time("now").unwrap().unwrap();
        assert!(chrono::DateTime::parse_from_rfc3339(&now).is_ok());
        assert_eq!(
            parse_creation_time("2024-01-15T12:00:00Z").unwrap(),
            Some("2024-01-15T12:00:00Z".to_string())
        );
        assert!(parse_creation_time("yesterday").is_err());
    }

    #[test]
    fn registry_transport_options_are_role_scoped() {
        let source: Reference = "source.test/base:latest".parse().unwrap();
        let targets = vec![
            "registry:target.test/app:v1"
                .parse::<OutputTarget>()
                .unwrap(),
            "registry:target.test/other:v1"
                .parse::<OutputTarget>()
                .unwrap(),
        ];
        let (source_options, target_options) = registry_options(
            Some(&source),
            &targets,
            RegistryClientSpec {
                source_plain_http: true,
                source_skip_tls: true,
                target_plain_http: true,
                target_skip_tls: false,
                read_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(60),
                max_attempts: 3,
            },
        );

        assert_eq!(source_options.plain_http_hosts, vec!["source.test"]);
        assert!(source_options.skip_tls_verify);
        assert_eq!(target_options.plain_http_hosts, vec!["target.test"]);
        assert!(!target_options.skip_tls_verify);
    }

    #[test]
    fn registry_transport_defaults_are_strict() {
        let source: Reference = "source.test/base:latest".parse().unwrap();
        let (source_options, target_options) =
            registry_options(Some(&source), &[], RegistryClientSpec::default());
        assert!(source_options.plain_http_hosts.is_empty());
        assert!(!source_options.skip_tls_verify);
        assert!(target_options.plain_http_hosts.is_empty());
        assert!(!target_options.skip_tls_verify);
    }

    #[test]
    fn exact_scratch_is_not_parsed_as_a_registry_reference() {
        let target = "oci-archive:image.tar".parse::<OutputTarget>().unwrap();
        let specification = |from: &str| ImageBuildSpec {
            from: from.to_string(),
            targets: vec![target.clone()],
            copies: Vec::new(),
            jobs: 1,
            platform: "linux/amd64".to_string(),
            entrypoint: None,
            cmd: None,
            labels: Vec::new(),
            ports: Vec::new(),
            workdir: None,
            user: None,
            creation_time: "epoch".to_string(),
            keep_cmd: false,
            transport: RegistryClientSpec::default(),
            cache: CacheSpec {
                enable: false,
                cache_path: None,
            },
        };

        assert!(
            BuildRequest::try_from(specification("scratch"))
                .unwrap()
                .source
                .is_none()
        );
        assert!(
            BuildRequest::try_from(specification("scratch:latest"))
                .unwrap()
                .source
                .is_some()
        );
    }

    #[test]
    fn scratch_ignores_source_registry_transport_flags() {
        let (source_options, _) = registry_options(
            None,
            &[],
            RegistryClientSpec {
                source_plain_http: true,
                source_skip_tls: true,
                ..RegistryClientSpec::default()
            },
        );

        assert!(source_options.plain_http_hosts.is_empty());
        assert!(!source_options.skip_tls_verify);
    }
}
