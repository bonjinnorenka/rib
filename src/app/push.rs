use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use indicatif::HumanBytes;
use oci_client::Reference;

use crate::blob::LayerStore;
use crate::digest::short_digest;
use crate::image::assemble::ImageBundle;
use crate::image::layer::LayerSource;
use crate::progress::Progress;
use crate::registry::RegistryClient;

#[derive(Clone, Copy)]
enum LayerPush {
    Reused,
    Mounted,
    Uploaded,
}

pub(crate) async fn push_registry(
    source_client: Option<&RegistryClient>,
    target_client: &RegistryClient,
    reference: &Reference,
    bundle: &ImageBundle,
    local_layers: Arc<LayerStore>,
    jobs: usize,
    progress: Progress,
) -> Result<()> {
    let stage = progress.spinner(format!("push registry → {reference}"));
    let target_registry = reference.resolve_registry().to_string();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(jobs));
    let mut tasks = tokio::task::JoinSet::new();

    for layer in unique_layers(&bundle.layers) {
        let source_client = source_client.cloned();
        let target_client = target_client.clone();
        let reference = reference.clone();
        let target_registry = target_registry.clone();
        let semaphore = semaphore.clone();
        let progress = progress.clone();
        let local_layers = local_layers.clone();
        tasks.spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .context("blob upload semaphore closed")?;
            push_one_layer(
                source_client.as_ref(),
                &target_client,
                &reference,
                &target_registry,
                layer,
                local_layers,
                progress,
            )
            .await
        });
    }

    let mut reused = 0;
    let mut mounted = 0;
    let mut uploaded = 0;
    while let Some(result) = tasks.join_next().await {
        match result.context("blob upload task panicked")?? {
            LayerPush::Reused => reused += 1,
            LayerPush::Mounted => mounted += 1,
            LayerPush::Uploaded => uploaded += 1,
        }
    }

    if target_client
        .blob_exists(reference, &bundle.config_digest)
        .await?
    {
        progress.note(format!(
            "config {} already exists, skip",
            short_digest(&bundle.config_digest)
        ));
    } else {
        target_client
            .push_blob_bytes(reference, &bundle.config_digest, &bundle.config_bytes)
            .await?;
        progress.note(format!(
            "config {} uploaded ({})",
            short_digest(&bundle.config_digest),
            HumanBytes(bundle.config_bytes.len() as u64)
        ));
    }

    target_client
        .push_manifest(reference, &bundle.manifest_bytes)
        .await?;
    progress.note(format!(
        "manifest {} pushed",
        short_digest(&bundle.manifest_digest)
    ));
    stage.done_with(format!(
        "{mounted} mounted, {uploaded} uploaded, {reused} reused"
    ));
    Ok(())
}

fn unique_layers(layers: &[LayerSource]) -> Vec<LayerSource> {
    let mut seen = HashSet::with_capacity(layers.len());
    layers
        .iter()
        .filter(|layer| seen.insert(layer.descriptor().digest().clone()))
        .cloned()
        .collect()
}

async fn push_one_layer(
    source_client: Option<&RegistryClient>,
    target_client: &RegistryClient,
    reference: &Reference,
    target_registry: &str,
    layer: LayerSource,
    local_layers: Arc<LayerStore>,
    progress: Progress,
) -> Result<LayerPush> {
    let descriptor = layer.descriptor().clone();
    let digest = descriptor.digest().clone();
    let size = descriptor.size();

    if target_client.blob_exists(reference, &digest).await? {
        progress.note(format!(
            "layer {} already exists, skip ({})",
            short_digest(&digest),
            HumanBytes(size)
        ));
        return Ok(LayerPush::Reused);
    }

    if let LayerSource::FromBase { source, .. } = &layer
        && source.reference.resolve_registry() == target_registry
    {
        match target_client
            .mount_blob(reference, &source.repository_reference(), &digest)
            .await
        {
            Ok(()) => {
                progress.note(format!(
                    "layer {} mounted from {}",
                    short_digest(&digest),
                    source.reference
                ));
                return Ok(LayerPush::Mounted);
            }
            Err(error) => progress.note(format!(
                "layer {} mount failed ({}), fallback upload",
                short_digest(&digest),
                error
            )),
        }
    }

    let mut file = match &layer {
        LayerSource::Built(layer) => layer.open_compressed()?,
        LayerSource::FromBase { source, descriptor } => local_layers
            .get(source_client, source, descriptor, &progress)
            .await?
            .open()?,
    };

    let task = progress.bytes(format!("push layer {}", short_digest(&digest)), size);
    let bar = task.progress_bar();
    target_client
        .push_blob_from_file(reference, &digest, &mut file, move |bytes| {
            if let Some(bar) = &bar {
                bar.inc(bytes);
            }
        })
        .await?;
    task.done();
    Ok(LayerPush::Uploaded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::image::{DescriptorBuilder, Digest, MediaType};

    use crate::digest::sha256_digest;
    use crate::image::ImageSource;

    fn base_layer(digest: Digest, size: u64) -> LayerSource {
        LayerSource::FromBase {
            descriptor: Box::new(
                DescriptorBuilder::default()
                    .media_type(MediaType::ImageLayerGzip)
                    .digest(digest)
                    .size(size)
                    .build()
                    .unwrap(),
            ),
            source: ImageSource {
                reference: "source.test/base:latest".parse().unwrap(),
                manifest_digest: sha256_digest(b"manifest"),
            },
        }
    }

    #[test]
    fn unique_layers_preserve_first_digest_order() {
        let repeated = sha256_digest(b"repeated");
        let other = sha256_digest(b"other");
        let layers = vec![
            base_layer(repeated.clone(), 10),
            base_layer(other.clone(), 20),
            base_layer(repeated.clone(), 30),
        ];

        let unique = unique_layers(&layers);

        assert_eq!(unique.len(), 2);
        assert_eq!(unique[0].descriptor().digest(), &repeated);
        assert_eq!(unique[0].descriptor().size(), 10);
        assert_eq!(unique[1].descriptor().digest(), &other);
    }
}
