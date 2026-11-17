use super::spec::{BuildRequest, CopyDirective};
use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::{Context, Result};
use indicatif::HumanBytes;
use tokio_util::sync::CancellationToken;

use super::push::push_registry;
use crate::archive::{write_docker_archive, write_oci_archive};
use crate::auth::Credentials;
use crate::blob::{LayerProvider, LayerStore};
use crate::builder::layer::build_copy_layer_with_roots;
use crate::cache::CacheController;
use crate::digest::short_digest;
use crate::image::Image;
use crate::image::assemble::{AssembleOptions, ImageBundle, assemble};
use crate::image::layer::Layer;
use crate::output_target::OutputTarget;
use crate::progress::Progress;
use crate::registry::{RegistryClient, RegistryOptions};
use crate::safe_fs::CopyRoot;

type ArchiveWrite = fn(
    &ImageBundle,
    &dyn LayerProvider,
    &std::path::Path,
    Option<&str>,
    &CancellationToken,
) -> Result<()>;

impl BuildRequest {
    pub async fn run(self, credentials: Credentials, progress: Progress) -> Result<()> {
        report_transport_options(&self.source_registry, &self.target_registry, &progress);
        let source_client = if self.source.is_some() {
            Some(
                RegistryClient::with_options(
                    credentials.clone(),
                    self.platform.clone(),
                    self.source_registry,
                )
                .context("creating source registry client")?,
            )
        } else {
            None
        };
        let target_client =
            if !self.local_only && self.targets.iter().any(OutputTarget::is_registry) {
                Some(
                    RegistryClient::with_options(
                        credentials,
                        self.platform.clone(),
                        self.target_registry,
                    )
                    .context("creating target registry client")?,
                )
            } else {
                None
            };

        let resolve_base = async {
            match (&self.source, source_client.as_ref()) {
                (Some(source), Some(client)) => {
                    let task = progress.spinner(format!("pull manifest {source}"));
                    let base = client.pull_base(source).await?;
                    task.done_with(format!("{} layer(s)", base.layers.len()));
                    Ok::<_, anyhow::Error>(base)
                }
                (None, None) => {
                    let task = progress.spinner(format!("initialize scratch ({})", self.platform));
                    let base = Image::scratch(&self.platform)?;
                    task.done_with("empty base");
                    Ok(base)
                }
                _ => unreachable!("source reference and client are created together"),
            }
        };
        let retain_uncompressed = self
            .targets
            .iter()
            .any(|target| matches!(target, OutputTarget::DockerArchive { .. }));
        let copies = build_copy_layers(
            self.copies,
            Arc::new(self.copy_roots),
            self.jobs,
            retain_uncompressed,
            progress.clone(),
        );
        let (base, new_layers) = tokio::try_join!(resolve_base, copies)?;

        let cache_controller = if self.cache.enable {
            Some(
                tokio::task::spawn_blocking(move || {
                    CacheController::new(self.cache.cache_path.as_deref())
                })
                .await
                .context("cache initialization worker panicked")??,
            )
        } else {
            None
        };
        let layer_store = Arc::new(LayerStore::with_max_decompressed_bytes(
            cache_controller,
            self.jobs,
            self.max_decompressed_bytes,
        )?);
        if self.targets.iter().any(OutputTarget::is_archive) {
            layer_store
                .prefetch(source_client.as_ref(), &base, &progress)
                .await?;
        }

        let task = progress.spinner("assemble manifest + config");
        let bundle = assemble(AssembleOptions {
            base,
            new_layers,
            entrypoint: self.entrypoint,
            cmd: self.cmd,
            labels: self.labels,
            envs: self.envs,
            ports: self.ports,
            workdir: self.workdir,
            user: self.user,
            creation_time: self.creation_time,
            keep_cmd: self.keep_cmd,
        })?;
        task.done_with(format!(
            "manifest {}",
            short_digest(&bundle.manifest_digest)
        ));

        for target in self.targets {
            match target {
                OutputTarget::OciArchive { path, tag } => {
                    write_archive_target(
                        "oci-archive",
                        write_oci_archive,
                        &bundle,
                        &layer_store,
                        path,
                        tag,
                        &progress,
                    )
                    .await?;
                }
                OutputTarget::DockerArchive { path, tag } => {
                    write_archive_target(
                        "docker-archive",
                        write_docker_archive,
                        &bundle,
                        &layer_store,
                        path,
                        tag,
                        &progress,
                    )
                    .await?;
                }
                OutputTarget::Registry { reference } => {
                    anyhow::ensure!(
                        !self.local_only,
                        "--local-only forbids pushing to registry {reference}"
                    );
                    let target_client = target_client
                        .as_ref()
                        .context("target registry client was not initialized")?;
                    push_registry(
                        source_client.as_ref(),
                        target_client,
                        &reference,
                        &bundle,
                        layer_store.clone(),
                        self.jobs,
                        progress.clone(),
                    )
                    .await?;
                }
            }
        }

        print_summary(&bundle);
        Ok(())
    }
}

async fn write_archive_target(
    kind: &str,
    write: ArchiveWrite,
    bundle: &ImageBundle,
    layer_store: &Arc<LayerStore>,
    path: std::path::PathBuf,
    tag: Option<String>,
    progress: &Progress,
) -> Result<()> {
    let task = progress.spinner(format!("write {kind} → {}", path.display()));
    let bundle = bundle.clone();
    let layers = layer_store.clone();
    let archive_path = path.clone();
    let cancellation = CancellationToken::new();
    let cancel_on_drop = cancellation.clone().drop_guard();
    tokio::task::spawn_blocking(move || {
        write(
            &bundle,
            layers.as_ref(),
            &archive_path,
            tag.as_deref(),
            &cancellation,
        )
    })
    .await
    .with_context(|| format!("{kind} worker panicked"))??;
    cancel_on_drop.disarm();
    task.done_with(HumanBytes(std::fs::metadata(path)?.len()).to_string());
    Ok(())
}

fn report_transport_options(
    source: &RegistryOptions,
    target: &RegistryOptions,
    progress: &Progress,
) {
    let mut plain_http_hosts = source.plain_http_hosts.clone();
    plain_http_hosts.extend(target.plain_http_hosts.iter().cloned());
    plain_http_hosts.sort();
    plain_http_hosts.dedup();
    if !plain_http_hosts.is_empty() {
        progress.note(format!("plain http: {}", plain_http_hosts.join(", ")));
    }
    if source.skip_tls_verify || target.skip_tls_verify {
        progress.note("⚠ TLS verification disabled (--*-skip-tls)");
    }
}

async fn build_copy_layers(
    copies: Vec<CopyDirective>,
    copy_roots: Arc<Vec<CopyRoot>>,
    jobs: usize,
    retain_uncompressed: bool,
    progress: Progress,
) -> Result<Vec<Layer>> {
    if copies.is_empty() {
        return Ok(Vec::new());
    }

    let count = copies.len();
    let cancellation = CancellationToken::new();
    let cancel_on_drop = cancellation.clone().drop_guard();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(jobs));
    let mut tasks = tokio::task::JoinSet::new();
    for (index, directive) in copies.into_iter().enumerate() {
        let (description, specification) = directive.into_parts();
        let copy_roots = copy_roots.clone();
        let semaphore = semaphore.clone();
        let cancellation = cancellation.clone();
        let task = progress.spinner(format!("copy [{}/{}] {description}", index + 1, count));
        tasks.spawn(async move {
            let permit = semaphore
                .acquire_owned()
                .await
                .context("COPY worker semaphore closed")?;
            let layer = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                build_copy_layer_with_roots(
                    &specification,
                    &copy_roots,
                    retain_uncompressed,
                    cancellation,
                )
            })
            .await
            .with_context(|| format!("COPY worker panicked for {description:?}"))?
            .with_context(|| format!("building COPY layer {description:?}"))?;
            task.done_with(format!(
                "{} → {}",
                HumanBytes(layer.uncompressed_size()),
                HumanBytes(layer.size())
            ));
            Ok::<_, anyhow::Error>((index, layer))
        });
    }

    let mut ordered = vec![None; count];
    while let Some(result) = tasks.join_next().await {
        let error = match result {
            Ok(Ok((index, layer))) => {
                ordered[index] = Some(layer);
                continue;
            }
            Ok(Err(error)) => error,
            Err(error) => anyhow::Error::new(error).context("COPY coordinator task failed"),
        };
        cancellation.cancel();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        return Err(error);
    }
    let result: Result<Vec<Layer>> = ordered
        .into_iter()
        .enumerate()
        .map(|(index, layer)| {
            layer.ok_or_else(|| anyhow::anyhow!("COPY layer {index} produced no result"))
        })
        .collect();
    if result.is_ok() {
        cancel_on_drop.disarm();
    }
    result
}

fn print_summary(bundle: &ImageBundle) {
    eprintln!();
    eprintln!("layers:           {}", bundle.layers.len());
    eprintln!("config digest:    {}", bundle.config_digest);
    eprintln!("image digest:     {}", bundle.manifest_digest);
    if !std::io::stdout().is_terminal() {
        print!("{}", bundle.manifest_digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::copy::CopySpec;
    use crate::progress::ProgressMode;
    use std::str::FromStr;
    use tempfile::TempDir;
    #[tokio::test]
    async fn concurrent_copy_keeps_input_order() {
        let directory = TempDir::new().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        let copies = vec![
            CopyDirective::new(
                first.display().to_string(),
                CopySpec::from_str(&format!("{}:/same", first.display())).unwrap(),
            ),
            CopyDirective::new(
                second.display().to_string(),
                CopySpec::from_str(&format!("{}:/same", second.display())).unwrap(),
            ),
        ];
        let layers = build_copy_layers(
            copies,
            Arc::new(Vec::new()),
            2,
            false,
            Progress::new(ProgressMode::Quiet),
        )
        .await
        .unwrap();
        assert_eq!(layers.len(), 2);
        assert_ne!(
            layers[0].descriptor().digest(),
            layers[1].descriptor().digest()
        );
    }
}
