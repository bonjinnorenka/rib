use super::{
    cli::CargoRibArgs,
    config::{CargoMetadata, CargoPackage, parse_config},
};
use crate::{
    app::spec::{
        BuildRequest, CacheSpec, CopyDirective, ImageBuildSpec, RegistryOverrides, default_jobs,
        parse_argv,
    },
    builder::copy::CopySpec,
    limits::ResourceLimits,
    output_target::OutputTarget,
};
use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub(super) struct CargoBuildPlan {
    pub(super) artifact: PathBuf,
    pub(super) cargo_args: Vec<String>,
    pub(super) manifest_path: PathBuf,
    pub(super) package_name: String,
    pub(super) image: BuildRequest,
}

pub(super) fn select_package<'a>(
    metadata: &'a CargoMetadata,
    current_dir: &Path,
) -> Result<&'a CargoPackage> {
    let current_dir = current_dir
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", current_dir.display()))?;
    let mut containing: Vec<&CargoPackage> = metadata
        .packages
        .iter()
        .filter(|package| {
            package
                .manifest_path
                .parent()
                .and_then(|path| path.canonicalize().ok())
                .is_some_and(|path| current_dir.starts_with(path))
        })
        .collect();
    containing.sort_by_key(|package| {
        package
            .manifest_path
            .parent()
            .map(Path::components)
            .map(Iterator::count)
            .unwrap_or(0)
    });
    if let Some(package) = containing.pop() {
        return Ok(package);
    }

    if metadata.workspace_default_members.len() == 1 {
        let id = &metadata.workspace_default_members[0];
        if let Some(package) = metadata.packages.iter().find(|package| &package.id == id) {
            return Ok(package);
        }
    }
    if metadata.packages.len() == 1 {
        return Ok(&metadata.packages[0]);
    }

    bail!("cannot select a package from this workspace; run cargo rib from the package directory")
}

pub(super) fn resolve_plan(
    arguments: &CargoRibArgs,
    package: &CargoPackage,
    current_dir: &Path,
) -> Result<CargoBuildPlan> {
    let manifest_dir = package.manifest_path.parent().ok_or_else(|| {
        anyhow!(
            "manifest has no parent: {}",
            package.manifest_path.display()
        )
    })?;
    let mut config = parse_config(package)?;

    let artifact = match &arguments.artifact {
        Some(path) => resolve_path(path, current_dir),
        None => {
            let path = config.artifact.take().ok_or_else(|| {
                anyhow!("artifact is required; set --artifact or package.metadata.rib.artifact")
            })?;
            resolve_path(&path, manifest_dir)
        }
    };
    let platform = arguments
        .platform
        .clone()
        .or(config.platform.take())
        .ok_or_else(|| {
            anyhow!("platform is required; set --platform or package.metadata.rib.platform")
        })?;
    let from = arguments
        .from
        .clone()
        .or(config.from.take())
        .ok_or_else(|| {
            anyhow!("base image is required; set --from or package.metadata.rib.from")
        })?;
    let destination = match arguments.destination.clone().or(config.destination.take()) {
        Some(destination) => destination,
        None => default_destination(&artifact)?,
    };
    validate_artifact_destination(&destination)?;

    let targets = if arguments.targets.is_empty() {
        config
            .to
            .iter()
            .map(|target| parse_config_target(target, manifest_dir))
            .collect::<Result<Vec<_>>>()?
    } else {
        arguments.targets.clone()
    };
    if targets.is_empty() {
        bail!("at least one output is required; set --to or package.metadata.rib.to");
    }
    let local_only = arguments.local_only.or(config.local_only).unwrap_or(false);

    let mut copies = parse_copies_at(&config.copies, manifest_dir)?;
    copies.extend(parse_copies_at(&arguments.copies, current_dir)?);
    copies.push(CopyDirective::new(
        format!("artifact {} → {destination}", artifact.display()),
        CopySpec::executable(&artifact, &destination)?,
    ));

    let entrypoint = match (&arguments.image.entrypoint, config.entrypoint.take()) {
        (Some(line), _) => Some(parse_argv(line)?),
        (None, Some(configured)) => Some(configured.into_argv()?),
        (None, None) => Some(vec![destination.clone()]),
    };
    let cmd = match (&arguments.image.cmd, config.cmd.take()) {
        (Some(line), _) => Some(parse_argv(line)?),
        (None, Some(configured)) => Some(configured.into_argv()?),
        (None, None) => None,
    };

    let mut labels = config.labels;
    labels.extend(arguments.image.labels.iter().cloned());
    let mut envs = config.env;
    envs.extend(arguments.image.envs.iter().cloned());
    let mut ports = config.ports;
    ports.extend(arguments.image.ports.iter().cloned());
    let mut cargo_args = config.cargo_args;
    cargo_args.extend(arguments.cargo_args.iter().cloned());

    let transport = RegistryOverrides::from(&arguments.client).with_fallback(RegistryOverrides {
        source_plain_http: config.from_plain_http,
        source_skip_tls: config.from_skip_tls,
        target_plain_http: config.to_plain_http,
        target_skip_tls: config.to_skip_tls,
        read_timeout: config.read_timeout.map(std::time::Duration::from_secs),
        connect_timeout: config.connect_timeout.map(std::time::Duration::from_secs),
        max_attempts: config.max_attempts,
    });
    let cache = CacheSpec {
        enable: arguments.cache.cache.or(config.cache).unwrap_or_default(),
        cache_path: arguments.cache.cache_path.clone().or(config.cache_path),
    };

    let network_policy = arguments.client.network_policy();
    let limits = ResourceLimits::from(&arguments.limits);
    let image_specification = ImageBuildSpec {
        from,
        targets,
        local_only,
        copies,
        copy_roots: arguments.copy_roots.clone(),
        jobs: arguments.jobs.or(config.jobs).unwrap_or_else(default_jobs),
        platform,
        entrypoint,
        cmd,
        labels,
        envs,
        ports,
        workdir: arguments.image.workdir.clone().or(config.workdir),
        user: arguments.image.user.clone().or(config.user),
        keep_cmd: arguments
            .image
            .keep_cmd
            .or(config.keep_cmd)
            .unwrap_or_default(),
        creation_time: arguments
            .creation_time
            .clone()
            .or(config.creation_time)
            .unwrap_or_else(|| "epoch".to_string()),
        transport: transport.into(),
        network_policy,
        limits,
        cache,
    };

    Ok(CargoBuildPlan {
        artifact,
        cargo_args,
        manifest_path: package.manifest_path.clone(),
        package_name: package.name.clone(),
        image: BuildRequest::try_from(image_specification)?,
    })
}

fn resolve_path(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn default_destination(artifact: &Path) -> Result<String> {
    let name = artifact
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow!(
                "artifact path has no UTF-8 filename: {}",
                artifact.display()
            )
        })?;
    Ok(format!("/app/{name}"))
}

pub(super) fn validate_artifact_destination(destination: &str) -> Result<()> {
    if !destination.starts_with('/') || destination.ends_with('/') {
        bail!("destination must be an absolute file path: {destination:?}");
    }
    Ok(())
}

fn parse_config_target(raw: &str, manifest_dir: &Path) -> Result<OutputTarget> {
    let target: OutputTarget = raw
        .parse()
        .with_context(|| format!("parsing package.metadata.rib.to entry {raw:?}"))?;
    Ok(match target {
        OutputTarget::OciArchive { path, tag } => OutputTarget::OciArchive {
            path: resolve_path(&path, manifest_dir),
            tag,
        },
        OutputTarget::DockerArchive { path, tag } => OutputTarget::DockerArchive {
            path: resolve_path(&path, manifest_dir),
            tag,
        },
        registry => registry,
    })
}

pub(super) fn parse_copies_at(raw_copies: &[String], base: &Path) -> Result<Vec<CopyDirective>> {
    raw_copies
        .iter()
        .map(|raw| {
            let mut specification = CopySpec::from_str(raw)
                .with_context(|| format!("parsing COPY directive {raw:?}"))?;
            specification.resolve_relative_to(base)?;
            Ok(CopyDirective::new(raw.clone(), specification))
        })
        .collect()
}
