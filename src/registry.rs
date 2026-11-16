// Adapter around oci-client. OCI descriptors are converted to oci-spec at the
// boundary; layer blobs remain lazy so pushes can cross-mount them

mod net_policy;
mod retry;
mod token;
pub use net_policy::{NetworkPolicy, unique_hosts};
use net_policy::{PolicyDnsResolver, ValidatingProxy};
use retry::{RetryPolicy, retry_registry};

use std::collections::HashMap;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::TryStreamExt;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::errors::{DigestError, OciDistributionError, OciEnvelope};
use oci_client::manifest::{
    IMAGE_MANIFEST_LIST_MEDIA_TYPE, IMAGE_MANIFEST_MEDIA_TYPE, OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MEDIA_TYPE, OciDescriptor, OciImageManifest, OciManifest, Versioned,
};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use oci_spec::image::{Descriptor, DescriptorBuilder, Digest, ImageConfiguration, MediaType};
use reqwest::header::{ACCEPT, CONTENT_LENGTH, HeaderMap};
use secrecy::ExposeSecret;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;
use tracing::warn;

use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::auth::{Credential, Credentials};
use crate::digest::{finish_sha256, sha256_digest};
use crate::image::{Image, ImageSource, Platform};
use crate::limits::{DownloadBudget, ResourceLimits};

const UPLOAD_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const DOCKER_DIGEST_HEADER: &str = "Docker-Content-Digest";
const DISTRIBUTION_MANIFEST_ACCEPT: &str = concat!(
    "application/vnd.docker.distribution.manifest.v2+json, ",
    "application/vnd.docker.distribution.manifest.list.v2+json, ",
    "application/vnd.oci.image.manifest.v1+json, ",
    "application/vnd.oci.image.index.v1+json"
);

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_MAX_ATTEMPTS: usize = 3;

/// Transport options for one registry-client role. Pull and push use separate
/// clients so disabling TLS verification for a development source cannot
/// silently weaken a production target
#[derive(Debug, Clone)]
pub struct RegistryOptions {
    pub plain_http_hosts: Vec<String>,
    pub registry_hosts: Vec<String>,
    /// If true, accept invalid TLS certs and hostnames. Applies globally —
    /// oci-client's reqwest backend has no per-host hook for this
    pub skip_tls_verify: bool,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub max_attempts: usize,
    pub network_policy: NetworkPolicy,
    pub limits: ResourceLimits,
}

impl Default for RegistryOptions {
    fn default() -> Self {
        Self {
            plain_http_hosts: Vec::new(),
            registry_hosts: Vec::new(),
            skip_tls_verify: false,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            network_policy: NetworkPolicy::default(),
            limits: ResourceLimits::default(),
        }
    }
}

impl RegistryOptions {
    fn client_config(&self, proxy_url: Option<&str>) -> ClientConfig {
        ClientConfig {
            protocol: if self.plain_http_hosts.is_empty() {
                ClientProtocol::Https
            } else {
                ClientProtocol::HttpsExcept(self.plain_http_hosts.clone())
            },
            accept_invalid_certificates: self.skip_tls_verify,
            connect_timeout: Some(self.connect_timeout),
            read_timeout: Some(self.read_timeout),
            https_proxy: proxy_url.map(str::to_string),
            http_proxy: proxy_url.map(str::to_string),
            ..Default::default()
        }
    }
}

type RepoClientKey = (String, String, bool);

#[derive(Clone)]
pub struct RegistryClient {
    tokens: token::TokenClient,
    blob_http: reqwest::Client,
    proxied_http: reqwest::Client,
    proxy: Arc<ValidatingProxy>,
    repo_clients: Arc<tokio::sync::Mutex<HashMap<RepoClientKey, (Client, RegistryAuth)>>>,
    download_budget: DownloadBudget,
    options: RegistryOptions,
    credentials: Arc<Credentials>,
    platform: Platform,
    retry_policy: RetryPolicy,
}

impl RegistryClient {
    #[allow(unused)]
    pub fn new(credentials: Credentials, platform: Platform) -> Result<Self> {
        Self::with_options(credentials, platform, RegistryOptions::default())
    }

    pub fn with_options(
        credentials: Credentials,
        platform: Platform,
        options: RegistryOptions,
    ) -> Result<Self> {
        options.network_policy.validate()?;
        options.limits.validate()?;
        let tokens =
            token::TokenClient::new(&options).context("creating registry token HTTP client")?;
        let resolver = Arc::new(PolicyDnsResolver::new(
            options.network_policy.allow_private_network,
        ));
        let blob_http = reqwest::Client::builder()
            .danger_accept_invalid_certs(options.skip_tls_verify)
            .connect_timeout(options.connect_timeout)
            .read_timeout(options.read_timeout)
            .dns_resolver(resolver)
            .pool_max_idle_per_host(0)
            .no_proxy()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("creating registry blob fallback HTTP client")?;
        let proxy = Arc::new(
            ValidatingProxy::start(
                options.network_policy.clone(),
                options.plain_http_hosts.clone(),
                options.registry_hosts.clone(),
                options.connect_timeout,
            )
            .context("starting registry validating proxy")?,
        );
        let proxy_url = proxy.url();
        let https_proxy =
            reqwest::Proxy::https(&proxy_url).context("configuring registry HTTPS proxy")?;
        let http_proxy =
            reqwest::Proxy::http(&proxy_url).context("configuring registry HTTP proxy")?;
        let proxied_http = reqwest::Client::builder()
            .danger_accept_invalid_certs(options.skip_tls_verify)
            .connect_timeout(options.connect_timeout)
            .read_timeout(options.read_timeout)
            .proxy(https_proxy)
            .proxy(http_proxy)
            .pool_max_idle_per_host(0)
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .context("creating bounded manifest HTTP client")?;
        let download_budget = DownloadBudget::new(options.limits.max_total_download_bytes);
        Ok(Self {
            tokens,
            blob_http,
            proxied_http,
            proxy,
            repo_clients: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            download_budget,
            credentials: Arc::new(credentials),
            platform,
            retry_policy: RetryPolicy {
                max_attempts: options.max_attempts,
                initial_delay: Duration::from_millis(250),
                max_delay: Duration::from_secs(2),
            },
            options,
        })
    }

    fn build_oci_client(&self) -> oci_client::errors::Result<Client> {
        let resolver_platform = self.platform.clone();
        let cfg = ClientConfig {
            // The default resolver selects the host platform, which is wrong
            // for cross-builds
            platform_resolver: Some(Box::new(move |entries| {
                entries
                    .iter()
                    .find(|e| {
                        e.platform.as_ref().is_some_and(|p| {
                            resolver_platform.matches(
                                &p.os.to_string(),
                                &p.architecture.to_string(),
                                p.variant.as_deref(),
                            )
                        })
                    })
                    .map(|e| e.digest.clone())
            })),
            ..self.options.client_config(Some(&self.proxy.url()))
        };
        Client::try_from(cfg)
    }

    async fn client_for_repo(
        &self,
        reference: &Reference,
        is_push: bool,
    ) -> oci_client::errors::Result<(Client, RegistryAuth)> {
        let registry = reference.resolve_registry().to_string();
        self.options
            .network_policy
            .check_registry_host(&registry)
            .map_err(|error| OciDistributionError::AuthenticationFailure(error.to_string()))?;
        let key = (
            registry.clone(),
            reference.repository().to_string(),
            is_push,
        );
        if let Some(cached) = self.repo_clients.lock().await.get(&key).cloned() {
            return Ok(cached);
        }

        let raw_auth = self.registry_auth_for(&registry);
        let resolved_auth = self
            .tokens
            .resolve_auth(reference, &raw_auth, is_push)
            .await?;
        let client = self.build_oci_client()?;
        client.store_auth_if_needed(&registry, &resolved_auth).await;

        let mut guard = self.repo_clients.lock().await;
        let entry = guard.entry(key).or_insert_with(|| (client, resolved_auth));
        Ok(entry.clone())
    }

    /// Pull base image: resolve manifest list -> platform manifest -> config
    /// Layer bytes are not fetched
    pub async fn pull_base(&self, reference: &Reference) -> Result<Image> {
        let transfer_timeout = self.options.limits.transfer_timeout;
        let (manifest, manifest_digest, config_bytes) =
            retry_registry("pull manifest and config", self.retry_policy, || async {
                with_transfer_timeout(transfer_timeout, "pulling manifest and config", async {
                    let (_client, auth) = self.client_for_repo(reference, false).await?;
                    self.pull_manifest_and_config_bounded(reference, &auth)
                        .await
                })
                .await
            })
            .await
            .with_context(|| format!("pulling manifest+config for {reference}"))?;

        let config: ImageConfiguration =
            serde_json::from_slice(&config_bytes).context("parsing image config JSON")?;
        let computed = sha256_digest(&config_bytes);
        let from_manifest: Digest = manifest
            .config
            .digest
            .parse()
            .context("parsing config descriptor digest")?;
        if computed != from_manifest {
            bail!(
                "config blob digest mismatch: manifest says {}, computed {}",
                from_manifest,
                computed
            );
        }
        validate_platform(&self.platform, &config)?;

        let layers: Vec<Descriptor> = manifest
            .layers
            .iter()
            .map(to_oci_spec_descriptor)
            .collect::<Result<_>>()?;

        Ok(Image {
            source: Some(ImageSource {
                reference: reference.clone(),
                manifest_digest: manifest_digest.parse().context("parsing manifest digest")?,
            }),
            config,
            layers,
        })
    }

    fn scheme_for_registry(&self, registry: &str) -> &'static str {
        if self
            .options
            .plain_http_hosts
            .iter()
            .any(|host| host == registry)
        {
            "http"
        } else {
            "https"
        }
    }

    fn v2_manifest_url(&self, reference: &Reference) -> String {
        let registry = reference.resolve_registry();
        format!(
            "{scheme}://{registry}/v2/{repository}/manifests/{reference_id}{ns}",
            scheme = self.scheme_for_registry(registry),
            repository = reference.repository(),
            reference_id = reference
                .digest()
                .unwrap_or_else(|| reference.tag().unwrap_or("latest")),
            ns = reference
                .namespace()
                .map(|ns| format!("?ns={ns}"))
                .unwrap_or_default(),
        )
    }

    fn v2_blob_url(&self, reference: &Reference, digest: &str) -> String {
        let registry = reference.resolve_registry();
        format!(
            "{scheme}://{registry}/v2/{repository}/blobs/{digest}{ns}",
            scheme = self.scheme_for_registry(registry),
            repository = reference.repository(),
            ns = reference
                .namespace()
                .map(|ns| format!("?ns={ns}"))
                .unwrap_or_default(),
        )
    }

    async fn read_bounded_registry_bytes(
        &self,
        url: &str,
        auth: &RegistryAuth,
        accept: &str,
        kind: &str,
        expected_size: Option<u64>,
    ) -> oci_client::errors::Result<(Vec<u8>, HeaderMap)> {
        let req = self.proxied_http.get(url).header(ACCEPT, accept);
        let req = match auth {
            RegistryAuth::Anonymous => req,
            RegistryAuth::Basic(user, pass) => req.basic_auth(user, Some(pass)),
            RegistryAuth::Bearer(token) => req.bearer_auth(token),
        };
        let mut response = req.send().await?;
        let status = response.status();
        let headers = response.headers().clone();

        let max_bytes = self.options.limits.max_manifest_bytes;
        let declared_content_length = parse_content_length(&headers, kind)?;
        if let Some(cl) = declared_content_length {
            if cl > max_bytes {
                return Err(OciDistributionError::SpecViolationError(format!(
                    "{kind} Content-Length ({cl} bytes) exceeds limit of {max_bytes} bytes"
                )));
            }
            if status.is_success()
                && let Some(expected) = expected_size
                && cl != expected
            {
                return Err(OciDistributionError::SpecViolationError(format!(
                    "{kind} Content-Length ({cl} bytes) does not match expected size ({expected} bytes)"
                )));
            }
        }

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            let chunk_len = chunk.len() as u64;
            let next_len = (body.len() as u64).checked_add(chunk_len).ok_or_else(|| {
                OciDistributionError::SpecViolationError(format!("{kind} byte counter overflow"))
            })?;
            if next_len > max_bytes {
                return Err(OciDistributionError::SpecViolationError(format!(
                    "{kind} stream exceeded limit of {max_bytes} bytes (received at least {next_len} bytes)"
                )));
            }
            if let Some(cl) = declared_content_length
                && next_len > cl
            {
                return Err(OciDistributionError::SpecViolationError(format!(
                    "{kind} stream exceeded declared Content-Length of {cl} bytes"
                )));
            }
            if status.is_success() {
                if let Some(expected) = expected_size
                    && next_len > expected
                {
                    return Err(OciDistributionError::SpecViolationError(format!(
                        "{kind} stream exceeded declared descriptor size of {expected} bytes"
                    )));
                }
                self.download_budget
                    .reserve(chunk_len)
                    .map_err(|error| OciDistributionError::SpecViolationError(error.to_string()))?;
            }
            body.extend_from_slice(&chunk);
        }

        if let Some(cl) = declared_content_length
            && (body.len() as u64) != cl
        {
            return Err(OciDistributionError::SpecViolationError(format!(
                "{kind} body size ({}) does not match Content-Length ({cl})",
                body.len()
            )));
        }

        validate_registry_response(status, &body, url)?;

        if let Some(expected) = expected_size
            && (body.len() as u64) != expected
        {
            return Err(OciDistributionError::SpecViolationError(format!(
                "{kind} size ({}) does not match expected descriptor size ({expected})",
                body.len()
            )));
        }

        Ok((body, headers))
    }

    async fn pull_manifest_raw_bounded(
        &self,
        reference: &Reference,
        auth: &RegistryAuth,
        expected_size: Option<u64>,
    ) -> oci_client::errors::Result<(Vec<u8>, String)> {
        let url = self.v2_manifest_url(reference);
        let (body, headers) = self
            .read_bounded_registry_bytes(
                &url,
                auth,
                DISTRIBUTION_MANIFEST_ACCEPT,
                "image manifest",
                expected_size,
            )
            .await?;
        let digest_header = digest_header_value(&headers)?;
        let digest = validate_payload_digest(&body, digest_header.as_deref(), reference.digest())?;
        Ok((body, digest))
    }

    async fn pull_manifest_bounded(
        &self,
        reference: &Reference,
        auth: &RegistryAuth,
        expected_size: Option<u64>,
    ) -> oci_client::errors::Result<(OciManifest, String)> {
        let (body, digest) = self
            .pull_manifest_raw_bounded(reference, auth, expected_size)
            .await?;
        validate_manifest_version(&body)?;
        let manifest = serde_json::from_slice(&body)
            .map_err(|e| OciDistributionError::ManifestParsingError(e.to_string()))?;
        Ok((manifest, digest))
    }

    async fn pull_config_bounded(
        &self,
        reference: &Reference,
        auth: &RegistryAuth,
        descriptor: &OciDescriptor,
    ) -> oci_client::errors::Result<Vec<u8>> {
        let expected_size = u64::try_from(descriptor.size).map_err(|_| {
            OciDistributionError::SpecViolationError(format!(
                "invalid negative config descriptor size: {}",
                descriptor.size
            ))
        })?;
        let max_manifest_bytes = self.options.limits.max_manifest_bytes;
        if expected_size > max_manifest_bytes {
            return Err(OciDistributionError::SpecViolationError(format!(
                "image config size ({expected_size} bytes) exceeds limit of {max_manifest_bytes} bytes"
            )));
        }
        let url = self.v2_blob_url(reference, &descriptor.digest);
        let (config_bytes, headers) = self
            .read_bounded_registry_bytes(
                &url,
                auth,
                DISTRIBUTION_MANIFEST_ACCEPT,
                "image config",
                Some(expected_size),
            )
            .await?;
        let digest_header = digest_header_value(&headers)?;
        validate_payload_digest(
            &config_bytes,
            digest_header.as_deref(),
            Some(&descriptor.digest),
        )?;
        Ok(config_bytes)
    }

    async fn pull_manifest_and_config_bounded(
        &self,
        reference: &Reference,
        auth: &RegistryAuth,
    ) -> oci_client::errors::Result<(OciImageManifest, String, Vec<u8>)> {
        let (top_manifest, top_digest) = self.pull_manifest_bounded(reference, auth, None).await?;
        let (manifest, manifest_digest) = match top_manifest {
            OciManifest::Image(image_manifest) => (image_manifest, top_digest),
            OciManifest::ImageIndex(image_index) => {
                let selected = image_index
                    .manifests
                    .iter()
                    .find(|entry| {
                        entry.platform.as_ref().is_some_and(|p| {
                            self.platform.matches(
                                &p.os.to_string(),
                                &p.architecture.to_string(),
                                p.variant.as_deref(),
                            )
                        })
                    })
                    .ok_or_else(|| {
                        OciDistributionError::ImageManifestNotFoundError(
                            "no entry found in image index manifest matching target platform"
                                .to_string(),
                        )
                    })?;
                let entry_size = u64::try_from(selected.size).map_err(|_| {
                    OciDistributionError::SpecViolationError(format!(
                        "invalid negative manifest descriptor size: {}",
                        selected.size
                    ))
                })?;
                let max_manifest_bytes = self.options.limits.max_manifest_bytes;
                if entry_size > max_manifest_bytes {
                    return Err(OciDistributionError::SpecViolationError(format!(
                        "platform manifest size ({entry_size} bytes) exceeds limit of {max_manifest_bytes} bytes"
                    )));
                }
                let platform_ref = reference.clone_with_digest(selected.digest.clone());
                let (selected_manifest, _) = self
                    .pull_manifest_bounded(
                        &platform_ref,
                        auth,
                        (entry_size > 0).then_some(entry_size),
                    )
                    .await?;
                match selected_manifest {
                    OciManifest::Image(manifest) => (manifest, selected.digest.clone()),
                    OciManifest::ImageIndex(_) => {
                        return Err(OciDistributionError::ImageManifestNotFoundError(
                            "received Image Index manifest instead".to_string(),
                        ));
                    }
                }
            }
        };

        let config_bytes = self
            .pull_config_bounded(reference, auth, &manifest.config)
            .await?;
        Ok((manifest, manifest_digest, config_bytes))
    }

    fn registry_auth_for(&self, registry: &str) -> RegistryAuth {
        match self.credentials.resolve(registry) {
            None => RegistryAuth::Anonymous,
            Some(c) => match c {
                Credential::IdentityToken {
                    identity_token,
                    source: _,
                } => RegistryAuth::Bearer(identity_token.expose_secret().to_string()),
                Credential::Basic {
                    username,
                    password,
                    source: _,
                } => RegistryAuth::Basic(username, password.expose_secret().to_string()),
            },
        }
    }

    /// Fetch a blob (layer or any other content-addressable object)
    /// `repo_ref` should reference the repository the blob lives in (registry + repo);
    /// the digest in the descriptor identifies the actual blob
    pub async fn fetch_layer_to_file<F>(
        &self,
        reference: &Reference,
        descriptor: &Descriptor,
        file: &mut File,
        on_progress: F,
    ) -> Result<()>
    where
        F: Fn(u64) + Send + Sync,
    {
        if descriptor.size() > self.options.limits.max_blob_bytes {
            bail!(
                "blob {} size ({} bytes) exceeds --max-blob-size limit of {} bytes",
                descriptor.digest(),
                descriptor.size(),
                self.options.limits.max_blob_bytes
            );
        }
        // Strip unvalidated external descriptor URLs before passing to oci-client;
        // allowed external URLs are handled below through our policy-enforced HTTP client.
        let oc = OciDescriptor {
            media_type: descriptor.media_type().to_string(),
            digest: descriptor.digest().to_string(),
            size: i64::try_from(descriptor.size())
                .context("descriptor size does not fit in i64")?,
            urls: None,
            annotations: descriptor
                .annotations()
                .as_ref()
                .map(|a| a.clone().into_iter().collect()),
            artifact_type: descriptor.artifact_type().as_ref().map(ToString::to_string),
        };
        let fallback_urls = descriptor.urls().clone().unwrap_or_default();

        let destination = file.try_clone().context("cloning download file")?;
        let on_progress = Arc::new(on_progress);
        let reported_bytes = AtomicU64::new(0);
        let transfer_timeout = self.options.limits.transfer_timeout;
        retry_registry("pull blob", self.retry_policy, || {
            with_transfer_timeout(
                transfer_timeout,
                "pulling layer blob",
                self.fetch_layer_once(
                    &destination,
                    reference,
                    &oc,
                    &fallback_urls,
                    on_progress.as_ref(),
                    &reported_bytes,
                ),
            )
        })
        .await
        .with_context(|| format!("pulling blob {} from {}", descriptor.digest(), reference))
    }

    async fn fetch_layer_once<F>(
        &self,
        file: &File,
        reference: &Reference,
        descriptor: &OciDescriptor,
        fallback_urls: &[String],
        on_progress: &F,
        reported_bytes: &AtomicU64,
    ) -> oci_client::errors::Result<()>
    where
        F: Fn(u64) + Sync + ?Sized,
    {
        // The caller owns a private staging file. Retries reset only that file.
        let mut writer = tokio::fs::File::from_std(file.try_clone()?);
        writer.set_len(0).await?;
        writer.seek(SeekFrom::Start(0)).await?;
        let expected_size = u64::try_from(descriptor.size).map_err(|_| {
            OciDistributionError::SpecViolationError(format!(
                "invalid negative descriptor size: {}",
                descriptor.size
            ))
        })?;
        let max_blob_bytes = self.options.limits.max_blob_bytes;
        if expected_size > max_blob_bytes {
            return Err(OciDistributionError::SpecViolationError(format!(
                "blob size ({expected_size} bytes) exceeds limit of {max_blob_bytes} bytes"
            )));
        }

        let (client, _) = self.client_for_repo(reference, false).await?;
        let stream_result = client.pull_blob_stream(reference, descriptor).await;
        match stream_result {
            Ok(mut stream) => {
                if let Some(content_len) = stream.content_length
                    && (content_len > expected_size || content_len > max_blob_bytes)
                {
                    return Err(OciDistributionError::SpecViolationError(format!(
                        "blob Content-Length ({content_len} bytes) exceeds allowed limit (expected {expected_size}, max {max_blob_bytes})"
                    )));
                }
                let mut attempt_bytes = 0_u64;
                let mut hasher = Sha256::new();

                while let Some(chunk) = stream.try_next().await? {
                    self.write_bounded_chunk(
                        &mut writer,
                        &mut hasher,
                        &chunk,
                        &mut attempt_bytes,
                        expected_size,
                        max_blob_bytes,
                        on_progress,
                        reported_bytes,
                    )
                    .await?;
                }

                writer.flush().await?;
                writer.sync_all().await?;
                verify_layer_digest(&descriptor.digest, hasher)?;
                if attempt_bytes != expected_size {
                    return Err(OciDistributionError::SpecViolationError(format!(
                        "blob size mismatch: expected {expected_size}, received {attempt_bytes}"
                    )));
                }
                Ok(())
            }
            Err(primary_error) => {
                if fallback_urls.is_empty()
                    || self.options.network_policy.allowed_blob_hosts.is_empty()
                {
                    return Err(primary_error);
                }
                self.fetch_from_external_urls(
                    &mut writer,
                    descriptor,
                    expected_size,
                    max_blob_bytes,
                    fallback_urls,
                    on_progress,
                    reported_bytes,
                    primary_error,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn write_bounded_chunk<F>(
        &self,
        writer: &mut tokio::fs::File,
        hasher: &mut Sha256,
        chunk: &[u8],
        attempt_bytes: &mut u64,
        expected_size: u64,
        max_blob_bytes: u64,
        on_progress: &F,
        reported_bytes: &AtomicU64,
    ) -> oci_client::errors::Result<()>
    where
        F: Fn(u64) + Sync + ?Sized,
    {
        let chunk_len = chunk.len() as u64;
        let next_bytes = attempt_bytes.checked_add(chunk_len).ok_or_else(|| {
            OciDistributionError::SpecViolationError("blob byte counter overflow".into())
        })?;
        if next_bytes > expected_size {
            return Err(OciDistributionError::SpecViolationError(format!(
                "blob stream exceeded declared size {expected_size} bytes (received at least {next_bytes} bytes)"
            )));
        }
        if next_bytes > max_blob_bytes {
            return Err(OciDistributionError::SpecViolationError(format!(
                "blob stream exceeded --max-blob-size limit of {max_blob_bytes} bytes"
            )));
        }
        self.download_budget
            .reserve(chunk_len)
            .map_err(|error| OciDistributionError::SpecViolationError(error.to_string()))?;

        hasher.update(chunk);
        writer.write_all(chunk).await?;
        *attempt_bytes = next_bytes;
        report_progress_high_det(reported_bytes, *attempt_bytes, on_progress);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn fetch_from_external_urls<F>(
        &self,
        writer: &mut tokio::fs::File,
        descriptor: &OciDescriptor,
        expected_size: u64,
        max_blob_bytes: u64,
        fallback_urls: &[String],
        on_progress: &F,
        reported_bytes: &AtomicU64,
        primary_error: OciDistributionError,
    ) -> oci_client::errors::Result<()>
    where
        F: Fn(u64) + Sync + ?Sized,
    {
        let mut last_error = primary_error;
        for raw_url in fallback_urls {
            let Ok(mut current_url) = reqwest::Url::parse(raw_url) else {
                continue;
            };
            if let Err(error) = self
                .options
                .network_policy
                .check_external_blob_url(&current_url, &self.options.plain_http_hosts)
            {
                warn!(url = %raw_url, %error, "ignoring disallowed external blob URL");
                continue;
            }

            // Follow at most 5 redirects, validating every hop and never attaching auth headers.
            let mut hops = 0usize;
            let response = loop {
                let resp = match self
                    .blob_http
                    .get(current_url.clone())
                    .header(
                        reqwest::header::ACCEPT,
                        "application/vnd.oci.image.manifest.v1+json",
                    )
                    .send()
                    .await
                {
                    Ok(resp) => resp,
                    Err(error) => {
                        last_error = OciDistributionError::RequestError(error);
                        break None;
                    }
                };
                if resp.status().is_redirection() && hops < 5 {
                    let Some(loc) = resp
                        .headers()
                        .get(reqwest::header::LOCATION)
                        .and_then(|v| v.to_str().ok())
                    else {
                        break None;
                    };
                    let Ok(next_url) = current_url.join(loc) else {
                        break None;
                    };
                    if let Err(error) = self
                        .options
                        .network_policy
                        .check_external_blob_url(&next_url, &self.options.plain_http_hosts)
                    {
                        warn!(url = %next_url, %error, "blocked external blob redirect");
                        break None;
                    }
                    current_url = next_url;
                    hops += 1;
                    continue;
                }
                break Some(resp);
            };

            let Some(mut response) = response else {
                continue;
            };
            if !response.status().is_success() {
                last_error = OciDistributionError::ServerError {
                    code: response.status().as_u16(),
                    url: current_url.to_string(),
                    message: "external blob fetch failed".into(),
                };
                continue;
            }
            if let Some(content_len) = response.content_length()
                && (content_len > expected_size || content_len > max_blob_bytes)
            {
                return Err(OciDistributionError::SpecViolationError(format!(
                    "external blob Content-Length ({content_len} bytes) exceeds allowed limit (expected {expected_size}, max {max_blob_bytes})"
                )));
            }

            writer.set_len(0).await?;
            writer.seek(SeekFrom::Start(0)).await?;
            let mut attempt_bytes = 0_u64;
            let mut hasher = Sha256::new();
            while let Some(chunk) = response.chunk().await? {
                self.write_bounded_chunk(
                    writer,
                    &mut hasher,
                    &chunk,
                    &mut attempt_bytes,
                    expected_size,
                    max_blob_bytes,
                    on_progress,
                    reported_bytes,
                )
                .await?;
            }
            writer.flush().await?;
            writer.sync_all().await?;
            verify_layer_digest(&descriptor.digest, hasher)?;
            if attempt_bytes != expected_size {
                return Err(OciDistributionError::SpecViolationError(format!(
                    "blob size mismatch: expected {expected_size}, received {attempt_bytes}"
                )));
            }
            return Ok(());
        }
        Err(last_error)
    }

    /// Check if a blob already exists in the target repository
    /// Avoids re-uploading layers that the registry already has
    pub async fn blob_exists(&self, reference: &Reference, digest: &Digest) -> Result<bool> {
        retry_registry("check blob", self.retry_policy, || async {
            let (client, _) = self.client_for_repo(reference, true).await?;
            client.blob_exists(reference, digest.as_ref()).await
        })
        .await
        .with_context(|| format!("checking blob {digest} in {reference}"))
    }

    /// Attempt a cross-repository mount in the same registry
    pub async fn mount_blob(
        &self,
        target: &Reference,
        source: &Reference,
        digest: &Digest,
    ) -> Result<()> {
        let auth = self.registry_auth_for(target.resolve_registry());
        retry_registry("mount blob", self.retry_policy, || async {
            let registry = target.resolve_registry();
            if registry != source.resolve_registry() {
                return Err(OciDistributionError::SpecViolationError(
                    "blob mounts require source and target in the same registry".into(),
                ));
            }
            let mount_auth = self.tokens.auth_for_mount(target, source, &auth).await?;

            // Client::clone shares the auth store and token cache. A fresh
            // instance keeps each mount's token independent of other sources
            // and ordinary pull/push authentication.
            let client = Client::try_from(self.options.client_config(Some(&self.proxy.url())))?;
            client.store_auth_if_needed(registry, &mount_auth).await;
            client.mount_blob(target, source, digest.as_ref()).await
        })
        .await
        .with_context(|| format!("mounting blob {digest} from {} to {}", source, target))
    }

    pub async fn push_blob_from_file<F>(
        &self,
        reference: &Reference,
        digest: &Digest,
        file: &mut std::fs::File,
        on_progress: F,
    ) -> Result<()>
    where
        F: Fn(u64) + Send + Sync + 'static,
    {
        file.seek(SeekFrom::Start(0))
            .context("rewinding blob file")?;

        let source = file.try_clone().context("cloning blob file handle")?;
        let on_progress = Arc::new(on_progress);
        let reported_bytes = AtomicU64::new(0);
        retry_registry("push blob", self.retry_policy, || {
            self.push_blob_file_once(
                reference,
                digest,
                &source,
                on_progress.as_ref(),
                &reported_bytes,
            )
        })
        .await
        .with_context(|| format!("pushing blob {digest} to {reference}"))
    }

    async fn push_blob_file_once<F>(
        &self,
        reference: &Reference,
        digest: &Digest,
        source: &std::fs::File,
        on_progress: &F,
        reported_bytes: &AtomicU64,
    ) -> oci_client::errors::Result<()>
    where
        F: Fn(u64) + Sync + ?Sized,
    {
        let (client, _) = self.client_for_repo(reference, true).await?;
        let mut file = source.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut async_file = tokio::fs::File::from_std(file);
        // Tokio files cap each blocking read at 2 MiB by default. Raise that
        // cap as well as ReaderStream's capacity so one stream item maps to
        // one intended registry PATCH
        async_file.set_max_buf_size(UPLOAD_CHUNK_SIZE);
        let mut attempt_bytes = 0_u64;
        let stream = ReaderStream::with_capacity(async_file, UPLOAD_CHUNK_SIZE)
            .map_ok(|chunk| {
                attempt_bytes += chunk.len() as u64;
                report_progress_high_det(reported_bytes, attempt_bytes, on_progress);
                chunk
            })
            .map_err(oci_client::errors::OciDistributionError::from);
        client
            .push_blob_stream(reference, stream, digest.as_ref())
            .await?;
        Ok(())
    }

    pub async fn push_blob_bytes(
        &self,
        reference: &Reference,
        digest: &Digest,
        bytes: &[u8],
    ) -> Result<()> {
        let bytes = bytes::Bytes::copy_from_slice(bytes);
        retry_registry("push config blob", self.retry_policy, || async {
            let (client, _) = self.client_for_repo(reference, true).await?;
            client
                .push_blob(reference, bytes.clone(), digest.as_ref())
                .await
        })
        .await
        .with_context(|| format!("pushing blob {digest} to {reference}"))?;
        Ok(())
    }

    pub async fn push_manifest(&self, reference: &Reference, manifest_json: &[u8]) -> Result<()> {
        let body = bytes::Bytes::copy_from_slice(manifest_json);
        retry_registry("push manifest", self.retry_policy, || async {
            let (client, _) = self.client_for_repo(reference, true).await?;
            client
                .push_manifest_raw(
                    reference,
                    body.clone(),
                    reqwest::header::HeaderValue::from_static(
                        "application/vnd.oci.image.manifest.v1+json",
                    ),
                )
                .await
        })
        .await
        .with_context(|| format!("pushing manifest to {reference}"))?;
        Ok(())
    }
}

fn parse_content_length(
    headers: &HeaderMap,
    kind: &str,
) -> oci_client::errors::Result<Option<u64>> {
    let mut parsed = None;
    for raw in headers.get_all(CONTENT_LENGTH) {
        let value = raw
            .to_str()
            .map_err(|_| {
                OciDistributionError::SpecViolationError(format!(
                    "{kind} has non-ASCII Content-Length header"
                ))
            })?
            .trim()
            .parse::<u64>()
            .map_err(|_| {
                OciDistributionError::SpecViolationError(format!(
                    "{kind} has invalid Content-Length header"
                ))
            })?;
        if let Some(prev) = parsed
            && prev != value
        {
            return Err(OciDistributionError::SpecViolationError(format!(
                "{kind} has conflicting Content-Length headers ({prev} vs {value})"
            )));
        }
        parsed = Some(value);
    }
    Ok(parsed)
}

fn digest_header_value(headers: &HeaderMap) -> oci_client::errors::Result<Option<String>> {
    match headers.get(DOCKER_DIGEST_HEADER) {
        Some(value) => {
            let s = value.to_str()?;
            Ok((!s.is_empty()).then(|| s.to_string()))
        }
        None => Ok(None),
    }
}

fn verify_expected_digest(body: &[u8], expected: &str) -> oci_client::errors::Result<()> {
    let (algorithm, _) = expected
        .split_once(':')
        .ok_or(DigestError::MissingAlgorithm)?;
    let actual_hex = match algorithm {
        "sha256" => hex::encode(Sha256::digest(body)),
        "sha384" => hex::encode(Sha384::digest(body)),
        "sha512" => hex::encode(Sha512::digest(body)),
        other => return Err(DigestError::UnsupportedAlgorithm(other.to_string()).into()),
    };
    let actual = format!("{algorithm}:{actual_hex}");
    if actual != expected {
        return Err(DigestError::VerificationError {
            expected: expected.to_string(),
            actual,
        }
        .into());
    }
    Ok(())
}

fn validate_payload_digest(
    body: &[u8],
    digest_header: Option<&str>,
    expected_digest: Option<&str>,
) -> oci_client::errors::Result<String> {
    if let Some(expected) = expected_digest {
        verify_expected_digest(body, expected)?;
    }
    if let Some(header) = digest_header {
        if expected_digest != Some(header) {
            verify_expected_digest(body, header)?;
        }
        return Ok(header.to_string());
    }
    if let Some(expected) = expected_digest {
        return Ok(expected.to_string());
    }
    Ok(sha256_digest(body).to_string())
}

fn validate_registry_response(
    status: reqwest::StatusCode,
    body: &[u8],
    url: &str,
) -> oci_client::errors::Result<()> {
    match status {
        reqwest::StatusCode::OK => Ok(()),
        reqwest::StatusCode::UNAUTHORIZED => Err(OciDistributionError::UnauthorizedError {
            url: url.to_string(),
        }),
        s if s.is_success() => Err(OciDistributionError::SpecViolationError(format!(
            "Expected HTTP Status {}, got {} instead",
            reqwest::StatusCode::OK,
            status,
        ))),
        s if s.is_client_error() => match serde_json::from_slice::<OciEnvelope>(body) {
            Ok(envelope) => Err(OciDistributionError::RegistryError {
                envelope,
                url: url.to_string(),
            }),
            Err(_) => Err(OciDistributionError::ServerError {
                code: s.as_u16(),
                url: url.to_string(),
                message: String::from_utf8_lossy(body).to_string(),
            }),
        },
        s => {
            let text = std::str::from_utf8(body)?;
            Err(OciDistributionError::ServerError {
                code: s.as_u16(),
                url: url.to_string(),
                message: text.to_string(),
            })
        }
    }
}

fn validate_manifest_version(body: &[u8]) -> oci_client::errors::Result<()> {
    let versioned: Versioned = serde_json::from_slice(body)
        .map_err(|e| OciDistributionError::VersionedParsingError(e.to_string()))?;
    if versioned.schema_version != 2 {
        return Err(OciDistributionError::UnsupportedSchemaVersionError(
            versioned.schema_version,
        ));
    }
    if let Some(media_type) = versioned.media_type
        && media_type != IMAGE_MANIFEST_MEDIA_TYPE
        && media_type != OCI_IMAGE_MEDIA_TYPE
        && media_type != IMAGE_MANIFEST_LIST_MEDIA_TYPE
        && media_type != OCI_IMAGE_INDEX_MEDIA_TYPE
    {
        return Err(OciDistributionError::UnsupportedMediaTypeError(media_type));
    }
    Ok(())
}

async fn with_transfer_timeout<T, Fut>(
    duration: Duration,
    operation: &str,
    fut: Fut,
) -> oci_client::errors::Result<T>
where
    Fut: std::future::Future<Output = oci_client::errors::Result<T>>,
{
    tokio::time::timeout(duration, fut).await.map_err(|_| {
        OciDistributionError::IoError(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "{operation} exceeded transfer timeout of {}s",
                duration.as_secs()
            ),
        ))
    })?
}

fn verify_layer_digest(expected: &str, hasher: Sha256) -> oci_client::errors::Result<()> {
    if !expected.starts_with("sha256:") {
        warn!(
            digest = expected,
            "skipping verification of non-sha256 blob"
        );
        return Ok(());
    }
    let actual = finish_sha256(hasher);
    if actual.as_ref() != expected {
        return Err(OciDistributionError::IoError(std::io::Error::other(
            oci_client::errors::DigestError::VerificationError {
                expected: expected.to_string(),
                actual: actual.to_string(),
            },
        )));
    }
    Ok(())
}

fn validate_platform(requested: &Platform, config: &ImageConfiguration) -> Result<()> {
    let os = config.os().to_string();
    let architecture = config.architecture().to_string();
    let variant = config.variant().as_deref();
    if requested.matches(&os, &architecture, variant) {
        return Ok(());
    }

    let actual = match variant {
        Some(variant) => format!("{os}/{architecture}/{variant}"),
        None => format!("{os}/{architecture}"),
    };
    bail!(
        "base image platform {actual} does not match requested platform {requested}; \
         use a matching base image manifest"
    );
}

fn report_progress_high_det<F>(reported: &AtomicU64, observed: u64, on_progress: &F)
where
    F: Fn(u64) + ?Sized,
{
    let previous = reported.fetch_max(observed, Ordering::Relaxed);
    if observed > previous {
        on_progress(observed - previous);
    }
}

/// Bridge oci-client's descriptor type to oci-spec's
fn to_oci_spec_descriptor(d: &OciDescriptor) -> Result<Descriptor> {
    let media_type = MediaType::from(d.media_type.as_str());
    let size: u64 = u64::try_from(d.size)
        .with_context(|| format!("descriptor size is negative: {}", d.size))?;
    let digest: oci_spec::image::Digest = d
        .digest
        .parse()
        .with_context(|| format!("malformed descriptor digest {}", d.digest))?;
    let mut b = DescriptorBuilder::default()
        .media_type(media_type)
        .digest(digest)
        .size(size);
    if let Some(urls) = &d.urls {
        b = b.urls(urls.clone());
    }
    if let Some(ann) = &d.annotations {
        b = b.annotations(
            ann.clone()
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>(),
        );
    }
    if let Some(artifact_type) = &d.artifact_type {
        b = b.artifact_type(MediaType::from(artifact_type.as_str()));
    }
    b.build().context("building descriptor")
}

#[cfg(test)]
mod tests {
    use super::retry::is_retryable_registry_error;
    use super::*;
    use oci_spec::image::{Arch, ImageConfigurationBuilder, Os, RootFsBuilder};
    use std::str::FromStr;

    fn image_config(os: Os, architecture: Arch, variant: Option<&str>) -> ImageConfiguration {
        let rootfs = RootFsBuilder::default()
            .diff_ids(Vec::<String>::new())
            .build()
            .unwrap();
        let mut builder = ImageConfigurationBuilder::default()
            .os(os)
            .architecture(architecture)
            .rootfs(rootfs);
        if let Some(variant) = variant {
            builder = builder.variant(variant.to_string());
        }
        builder.build().unwrap()
    }

    #[test]
    fn descriptor_bridge_round_trips_basic_fields() {
        let oc = OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
            size: 1234,
            urls: Some(vec!["https://example.com/blob".into()]),
            annotations: None,
            artifact_type: None,
        };
        let d = to_oci_spec_descriptor(&oc).unwrap();
        assert_eq!(d.size(), 1234);
        assert_eq!(d.urls().as_ref().unwrap().len(), 1);
        assert!(matches!(d.media_type(), MediaType::ImageLayerGzip));
    }

    #[test]
    fn descriptor_bridge_keeps_unknown_media_type() {
        let oc = OciDescriptor {
            media_type: "application/vnd.example.weird+stuff".into(),
            digest: "sha256:".to_string() + &"a".repeat(64),
            size: 1,
            urls: None,
            annotations: None,
            artifact_type: None,
        };
        let d = to_oci_spec_descriptor(&oc).unwrap();
        match d.media_type() {
            MediaType::Other(s) => assert_eq!(s, "application/vnd.example.weird+stuff"),
            other => panic!("unexpected media type: {:?}", other),
        }
    }

    #[test]
    fn descriptor_rejects_negative_size() {
        let oc = OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            digest: "sha256:".to_string() + &"a".repeat(64),
            size: -1,
            urls: None,
            annotations: None,
            artifact_type: None,
        };
        assert!(to_oci_spec_descriptor(&oc).is_err());
    }

    #[test]
    fn base_config_must_match_requested_platform() {
        let config = image_config(Os::Linux, Arch::Amd64, None);
        assert!(validate_platform(&Platform::from_str("linux/amd64").unwrap(), &config).is_ok());

        let error = validate_platform(&Platform::from_str("linux/arm64").unwrap(), &config)
            .unwrap_err()
            .to_string();
        assert!(error.contains("linux/amd64"));
        assert!(error.contains("linux/arm64"));
    }

    #[test]
    fn platform_variant_is_checked_when_both_sides_provide_one() {
        let config = image_config(Os::Linux, Arch::ARM64, Some("v8"));
        assert!(validate_platform(&Platform::from_str("linux/arm64/v8").unwrap(), &config).is_ok());
        assert!(
            validate_platform(&Platform::from_str("linux/arm64/v7").unwrap(), &config).is_err()
        );
    }

    #[test]
    fn layer_digest_mismatch_is_a_non_retryable_error() {
        let mut hasher = Sha256::new();
        hasher.update(b"tampered bytes");
        let expected = format!("sha256:{}", "0".repeat(64));
        let error = verify_layer_digest(&expected, hasher).unwrap_err();
        assert!(!is_retryable_registry_error(&error));
        // The message must name both digests so the user can compare them
        let message = error.to_string();
        assert!(message.contains(&expected), "unexpected error: {message}");
        assert!(
            message.contains(sha256_digest(b"tampered bytes").as_ref()),
            "unexpected error: {message}"
        );

        let mut hasher = Sha256::new();
        hasher.update(b"payload");
        assert!(verify_layer_digest(sha256_digest(b"payload").as_ref(), hasher).is_ok());
    }

    #[tokio::test]
    async fn upload_reader_emits_one_item_per_configured_chunk() {
        let file = tempfile::tempfile().unwrap();
        file.set_len((UPLOAD_CHUNK_SIZE * 2 + 1) as u64).unwrap();
        let mut async_file = tokio::fs::File::from_std(file);
        async_file.set_max_buf_size(UPLOAD_CHUNK_SIZE);
        let mut stream = ReaderStream::with_capacity(async_file, UPLOAD_CHUNK_SIZE);
        let mut sizes = Vec::new();

        while let Some(chunk) = stream.try_next().await.unwrap() {
            sizes.push(chunk.len());
        }

        assert_eq!(sizes, [UPLOAD_CHUNK_SIZE, UPLOAD_CHUNK_SIZE, 1]);
    }

    const TEST_TLS_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIC9TCCAd2gAwIBAgIUMlwyge7TFOWNOr6pXGjhJd7kZVYwDQYJKoZIhvcNAQEL\n\
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTExNjEzMzQ1NVoYDzIxMjYx\n\
MDIzMTMzNDU1WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB\n\
AQUAA4IBDwAwggEKAoIBAQCvnAakiRhig2vMj+S8E3sZ+Q+xj+DrIfdJVVBs0GGM\n\
VHVnXaL4aT1/KBCvHuVik8glEnDhTdiUM8AO73vVUYfq+n8IsS1eHndEvn4eClZI\n\
I+Y1a2fgbRlL12La3G1g6xnYssEzJnsG9JA8+xTANPp3RrcqJElldmB8q9pEfNSK\n\
AbQuLwzLrQdE6PqAKxnAy80FhvDYARZ01lqK73E7WLS9HDoAqGYxe3HtFMSR/q57\n\
PpCwO62vnf4omFNIcGHViwvrKQpqI6u6baJvC9O9TzBWrOJ46vd6SvL2pxpPAPwr\n\
7+LWvwT6LyZWrWXBY8kJuxyQsOhFceKrv8tub2tU6YLDAgMBAAGjPTA7MBoGA1Ud\n\
EQQTMBGCCWxvY2FsaG9zdIcEfwAAATAdBgNVHQ4EFgQUFTUk/w6E8j8tOkxPe/KN\n\
Dru1Cb8wDQYJKoZIhvcNAQELBQADggEBAHLeHxguuw+kNXW/YPN0xFzJLj1/UiZh\n\
uS8xQ7caIdaA2WTwJq9n4JK8TuK7GtL7cZutCYtmuspyhm0+9UtuelQe1ZItYpVj\n\
TQXfCg+OCrHvChpt6WgQt0rUEbHeqnKrptlAlMCAaIpASLM6C1cWd/qlmAGao+2i\n\
sEuiemavrczlbDOhilyrdxEEvrb6t+49DCIWpxq4za1F0+WQ1L8Iigus+zhkicBX\n\
EL9kSWKPxL3W7soXYnPGplu8KkY+tfNdaOX12AdPdzkWgh2jvVyHTad/XXDHqif2\n\
TaI1GagkvSQZvwMgDvhjJIEHz8CKJeaE1X1PeUhDn6uRnJEsIr3l8+A=\n\
-----END CERTIFICATE-----\n";

    const TEST_TLS_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCvnAakiRhig2vM\n\
j+S8E3sZ+Q+xj+DrIfdJVVBs0GGMVHVnXaL4aT1/KBCvHuVik8glEnDhTdiUM8AO\n\
73vVUYfq+n8IsS1eHndEvn4eClZII+Y1a2fgbRlL12La3G1g6xnYssEzJnsG9JA8\n\
+xTANPp3RrcqJElldmB8q9pEfNSKAbQuLwzLrQdE6PqAKxnAy80FhvDYARZ01lqK\n\
73E7WLS9HDoAqGYxe3HtFMSR/q57PpCwO62vnf4omFNIcGHViwvrKQpqI6u6baJv\n\
C9O9TzBWrOJ46vd6SvL2pxpPAPwr7+LWvwT6LyZWrWXBY8kJuxyQsOhFceKrv8tu\n\
b2tU6YLDAgMBAAECggEAFlpP5iWlOvTrhdBTFzWLl9TCEKH1yTg7l9QKNq+Xmxst\n\
Dok2s1QCBet9pCzUmeWhtkZQo/0aslKcAcquAossN9bG0L5svew21kNBHmXGccxQ\n\
A0C2qjR44dR6us0QByQl2BV4zh/5zPrYWUrEa2rS7tfLfMu9o/KbeYMOd2VEUISM\n\
oThZLXApYOlQwdtomf3kVxFSxal0lzW5tbfp6gODJ/L3Lyz1ooWEqe4wXecdzzYc\n\
90Px+voGHJ5vFKJTTLorD0BRdQbWGDJ7dBRcksBhJK5dM47/z5nl0PiDk0FllQVA\n\
4Bcmx5J9EyGxztqqHRJzmRF4ppfCPOjw6qnCS94NAQKBgQDvTVw02zXlljzLTala\n\
LtnYAmBNC+oFu+ghprro7ZQVxiCIPlucRMK3as7x9UWdDlnOiMIpF5WjqgW0QDoW\n\
BmiwGlNpi+O6MrPedgynW83jAJw+ns2XwGuSCzxyqLYlG2/WqhxBR9qls9aLE2pu\n\
EgRTlnL/XXmXsNxpcNbYfSwNgwKBgQC73O1I0Q+gVG2m97QQDXrwQcPUQRDrggzx\n\
hyuk6ET756KqBXDqGgsPGicQakmeJp7IvZKk2XWhjF2Z92nK8r+sHRUxPrlfXJ8z\n\
SrGyVLWowQ8MQVfigBCuePCfTzsp2Rz9V2oGsnmtNPPLgLmttfZ5FJnMbPWg0yRD\n\
QNfyHCnxwQKBgQCtYiO4uEtouV36/54AlYmJFM+pg0RgOzGJkEBEnD57OD5B+Mxv\n\
gPKD6oNelBOII+m11yi2lTv6hSn028Q6SRJ45doh0xWAx1PDj0zDxaR7IOoUBQN5\n\
PBW0jyeQ++RdJm/13PLz6ZfmD1MXGU43yh4QYiWYGKYM3jwUuYkw+iB8+QJ/Uuwx\n\
0PJ2805RGGI+GNfabDKbPhV6YnoFPJdtrFzaFlcodePw82SLfR8OHzDLTgO+Et2a\n\
3Skfwy8yIcQT7oE4GcC8mgAV0wIPQ5S02wKJLPQKsF4nbNMaiejYTXmro80x/qGX\n\
K12cV9gHxMwNKaAoK0nsmU9/HH4Wg5kbuMK1wQKBgDSyPusRU8k18NjKOAgZwZsX\n\
13wjsa9Bn5ZTPux7aFBE+46S9Kt0TDWeVMq+Rot8FMOax+XtEONM38HCfh8VBqKO\n\
m5uh6b/3c6cXDEwhCzlcZTbYLW8k0zO1dJk0oB7SvCnEhsmDIEWLovjOjoJlB7dA\n\
seTuix+/DtzfmDHobU29\n\
-----END PRIVATE KEY-----\n";

    #[derive(Clone)]
    struct RecordedRequest {
        #[allow(dead_code)]
        method: String,
        path: String,
        headers: HashMap<String, String>,
    }

    struct MockHttpServer {
        port: u16,
        requests: Arc<tokio::sync::Mutex<Vec<RecordedRequest>>>,
        shutdown: tokio_util::sync::CancellationToken,
    }

    impl Drop for MockHttpServer {
        fn drop(&mut self) {
            self.shutdown.cancel();
        }
    }

    #[derive(Clone)]
    struct MockHttpResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl MockHttpResponse {
        fn json(status: u16, body: &str) -> Self {
            Self {
                status,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: body.as_bytes().to_vec(),
            }
        }

        fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Self {
            Self {
                status,
                headers: vec![("Content-Type".into(), content_type.into())],
                body,
            }
        }
    }

    fn test_tls_acceptor() -> tokio_rustls::TlsAcceptor {
        use rustls_pki_types::pem::PemObject;
        use rustls_pki_types::{CertificateDer, PrivateKeyDer};
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(TEST_TLS_CERT_PEM.as_bytes())
                .map(|item| item.unwrap())
                .collect();
        let key = PrivateKeyDer::from_pem_slice(TEST_TLS_KEY_PEM.as_bytes()).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
    }

    async fn spawn_mock_server<F>(tls: bool, handler: F) -> MockHttpServer
    where
        F: Fn(&RecordedRequest) -> MockHttpResponse + Send + Sync + 'static,
    {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let shutdown = tokio_util::sync::CancellationToken::new();
        let acceptor = tls.then(test_tls_acceptor);
        let handler = Arc::new(handler);

        let task_reqs = requests.clone();
        let task_shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        let acceptor = acceptor.clone();
                        let handler = handler.clone();
                        let reqs = task_reqs.clone();
                        tokio::spawn(async move {
                            let mut io: Box<dyn AsyncReadWrite + Send + Unpin> = match acceptor {
                                Some(acc) => match acc.accept(stream).await {
                                    Ok(s) => Box::new(s),
                                    Err(_) => return,
                                },
                                None => Box::new(stream),
                            };
                            let mut reader = BufReader::new(&mut io);
                            let mut first = String::new();
                            if reader.read_line(&mut first).await.unwrap_or(0) == 0 {
                                return;
                            }
                            let mut parts = first.split_whitespace();
                            let method = parts.next().unwrap_or("").to_string();
                            let path = parts.next().unwrap_or("").to_string();
                            let mut headers = HashMap::new();
                            loop {
                                let mut line = String::new();
                                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                                    break;
                                }
                                let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                                if trimmed.is_empty() {
                                    break;
                                }
                                if let Some((k, v)) = trimmed.split_once(':') {
                                    headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                                }
                            }
                            let rec = RecordedRequest { method, path, headers };
                            reqs.lock().await.push(rec.clone());
                            let resp = handler(&rec);
                            let reason = match resp.status {
                                200 => "OK",
                                302 => "Found",
                                307 => "Temporary Redirect",
                                401 => "Unauthorized",
                                404 => "Not Found",
                                _ => "Status",
                            };
                            let mut head = format!(
                                "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                                resp.status,
                                reason,
                                resp.body.len()
                            );
                            for (k, v) in resp.headers {
                                head.push_str(&format!("{k}: {v}\r\n"));
                            }
                            head.push_str("\r\n");
                            let inner = reader.into_inner();
                            let _ = inner.write_all(head.as_bytes()).await;
                            let _ = inner.write_all(&resp.body).await;
                            let _ = inner.shutdown().await;
                        });
                    }
                }
            }
        });

        MockHttpServer {
            port,
            requests,
            shutdown,
        }
    }

    trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
    impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite> AsyncReadWrite for T {}

    fn minimal_image_fixtures() -> (String, String, String, Vec<u8>, String, String) {
        let layer_bytes = b"mock-layer-bytes".to_vec();
        let layer_digest = sha256_digest(&layer_bytes).to_string();
        let config_json = format!(
            r#"{{"architecture":"amd64","os":"linux","rootfs":{{"type":"layers","diff_ids":["{layer_digest}"]}}}}"#
        );
        let config_digest = sha256_digest(config_json.as_bytes()).to_string();
        let manifest_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":{}}}]}}"#,
            config_json.len(),
            layer_bytes.len()
        );
        let manifest_digest = sha256_digest(manifest_json.as_bytes()).to_string();
        (
            manifest_json,
            manifest_digest,
            config_json,
            layer_bytes,
            config_digest,
            layer_digest,
        )
    }

    #[tokio::test]
    async fn tls_registry_rejects_untrusted_certificate_by_default() {
        let server = spawn_mock_server(true, |_| MockHttpResponse::json(200, "{}")).await;
        let registry = format!("127.0.0.1:{}", server.port);
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                registry_hosts: vec![registry],
                skip_tls_verify: false,
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        assert!(client.pull_base(&reference).await.is_err());
    }

    #[tokio::test]
    async fn tls_registry_pull_and_bearer_auth_succeed_when_configured() {
        let (manifest_json, manifest_digest, config_json, layer_bytes, config_digest, layer_digest) =
            minimal_image_fixtures();
        let port_holder = Arc::new(std::sync::atomic::AtomicU16::new(0));
        let port_ref = port_holder.clone();
        let server = spawn_mock_server(true, move |req| {
            let port = port_ref.load(Ordering::Relaxed);
            match req.path.as_str() {
                "/v2/" => {
                    if !req.headers.contains_key("authorization") {
                        MockHttpResponse {
                            status: 401,
                            headers: vec![(
                                "WWW-Authenticate".into(),
                                format!(
                                    r#"Bearer realm="https://127.0.0.1:{port}/token",service="reg""#
                                ),
                            )],
                            body: Vec::new(),
                        }
                    } else {
                        MockHttpResponse::json(200, "{}")
                    }
                }
                p if p.starts_with("/token") => {
                    assert_eq!(
                        req.headers.get("authorization").map(String::as_str),
                        Some("Basic YWxpY2U6c2VjcmV0")
                    );
                    MockHttpResponse::json(200, r#"{"token":"tok-123"}"#)
                }
                "/v2/test/app/manifests/v1" => MockHttpResponse {
                    status: 200,
                    headers: vec![
                        (
                            "Content-Type".into(),
                            "application/vnd.oci.image.manifest.v1+json".into(),
                        ),
                        ("Docker-Content-Digest".into(), manifest_digest.clone()),
                    ],
                    body: manifest_json.as_bytes().to_vec(),
                },
                p if p == format!("/v2/test/app/blobs/{config_digest}") => MockHttpResponse::bytes(
                    200,
                    "application/json",
                    config_json.as_bytes().to_vec(),
                ),
                p if p == format!("/v2/test/app/blobs/{layer_digest}") => {
                    MockHttpResponse::bytes(200, "application/octet-stream", layer_bytes.clone())
                }
                _ => MockHttpResponse::json(404, "{}"),
            }
        })
        .await;
        port_holder.store(server.port, Ordering::Relaxed);

        let registry = format!("127.0.0.1:{}", server.port);
        let creds = Credentials::load(&[format!("{registry}=alice:secret")], None).unwrap();
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let client = RegistryClient::with_options(
            creds,
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                registry_hosts: vec![registry],
                skip_tls_verify: true,
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        let image = client.pull_base(&reference).await.unwrap();
        assert_eq!(image.layers.len(), 1);
        let mut tmp = tempfile::tempfile().unwrap();
        client
            .fetch_layer_to_file(&reference, &image.layers[0], &mut tmp, |_| {})
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn token_client_rejects_untrusted_bearer_realm_without_sending_credentials() {
        let evil = spawn_mock_server(false, |_| {
            MockHttpResponse::json(200, r#"{"token":"evil"}"#)
        })
        .await;
        let evil_port = evil.port;
        let reg = spawn_mock_server(false, move |req| {
            if req.path == "/v2/" {
                MockHttpResponse {
                    status: 401,
                    headers: vec![(
                        "WWW-Authenticate".into(),
                        format!(
                            r#"Bearer realm="http://127.0.0.1:{evil_port}/steal",service="evil""#
                        ),
                    )],
                    body: Vec::new(),
                }
            } else {
                MockHttpResponse::json(404, "{}")
            }
        })
        .await;

        let registry = format!("127.0.0.1:{}", reg.port);
        let creds = Credentials::load(&[format!("{registry}=alice:supersecret")], None).unwrap();
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let client = RegistryClient::with_options(
            creds,
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry.clone()],
                registry_hosts: vec![registry],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        let err = client.pull_base(&reference).await.unwrap_err().to_string();
        assert!(err.contains("pulling manifest+config"), "got: {err}");
        assert!(
            evil.requests.lock().await.is_empty(),
            "credentials must NEVER be sent to untrusted realm"
        );
    }

    #[tokio::test]
    async fn token_client_allows_explicit_auth_host_and_blocks_redirects() {
        let evil = spawn_mock_server(false, |_| {
            MockHttpResponse::json(200, r#"{"token":"evil"}"#)
        })
        .await;
        let evil_port = evil.port;
        let auth_srv = spawn_mock_server(false, move |req| {
            if req.path.contains("redirect=1") {
                MockHttpResponse {
                    status: 302,
                    headers: vec![(
                        "Location".into(),
                        format!("http://127.0.0.1:{evil_port}/steal"),
                    )],
                    body: Vec::new(),
                }
            } else {
                MockHttpResponse::json(200, r#"{"token":"allowed-tok"}"#)
            }
        })
        .await;
        let auth_port = auth_srv.port;
        let reg = spawn_mock_server(false, move |req| {
            if req.path == "/v2/" {
                MockHttpResponse {
                    status: 401,
                    headers: vec![(
                        "WWW-Authenticate".into(),
                        format!(
                            r#"Bearer realm="http://127.0.0.1:{auth_port}/token?redirect=1",service="ext""#
                        ),
                    )],
                    body: Vec::new(),
                }
            } else {
                MockHttpResponse::json(404, "{}")
            }
        })
        .await;

        let registry = format!("127.0.0.1:{}", reg.port);
        let auth_host = format!("127.0.0.1:{auth_port}");
        let creds = Credentials::load(&[format!("{registry}=alice:supersecret")], None).unwrap();
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let client = RegistryClient::with_options(
            creds,
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry.clone()],
                registry_hosts: vec![registry],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allowed_auth_hosts: vec![auth_host],
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        assert!(client.pull_base(&reference).await.is_err());
        assert!(
            evil.requests.lock().await.is_empty(),
            "TokenClient must not follow 302 redirects"
        );
    }

    #[tokio::test]
    async fn ssrf_blocks_localhost_by_default() {
        let server = spawn_mock_server(false, |_| MockHttpResponse::json(200, "{}")).await;
        let registry = format!("127.0.0.1:{}", server.port);
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry.clone()],
                registry_hosts: vec![registry],
                max_attempts: 1,
                network_policy: NetworkPolicy::default(), // allow_private_network = false
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        assert!(client.pull_base(&reference).await.is_err());
        assert!(
            server.requests.lock().await.is_empty(),
            "loopback registry must be blocked before connecting"
        );
    }

    #[tokio::test]
    async fn ssrf_blocks_https_to_http_downgrade_redirect_and_metadata_redirect() {
        let evil = spawn_mock_server(false, |_| {
            MockHttpResponse::bytes(200, "application/octet-stream", b"x".to_vec())
        })
        .await;
        let evil_port = evil.port;
        let (manifest_json, manifest_digest, config_json, _, config_digest, layer_digest) =
            minimal_image_fixtures();
        let reg = spawn_mock_server(true, move |req| match req.path.as_str() {
            "/v2/" => MockHttpResponse::json(200, "{}"),
            "/v2/test/app/manifests/v1" => MockHttpResponse {
                status: 200,
                headers: vec![
                    (
                        "Content-Type".into(),
                        "application/vnd.oci.image.manifest.v1+json".into(),
                    ),
                    ("Docker-Content-Digest".into(), manifest_digest.clone()),
                ],
                body: manifest_json.as_bytes().to_vec(),
            },
            p if p == format!("/v2/test/app/blobs/{config_digest}") => {
                MockHttpResponse::bytes(200, "application/json", config_json.as_bytes().to_vec())
            }
            p if p == format!("/v2/test/app/blobs/{layer_digest}") => MockHttpResponse {
                status: 307,
                headers: vec![(
                    "Location".into(),
                    format!("http://127.0.0.1:{evil_port}/downgrade"),
                )],
                body: Vec::new(),
            },
            _ => MockHttpResponse::json(404, "{}"),
        })
        .await;

        let registry = format!("127.0.0.1:{}", reg.port);
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                registry_hosts: vec![registry],
                skip_tls_verify: true,
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        let image = client.pull_base(&reference).await.unwrap();
        let mut tmp = tempfile::tempfile().unwrap();
        assert!(
            client
                .fetch_layer_to_file(&reference, &image.layers[0], &mut tmp, |_| {})
                .await
                .is_err()
        );
        assert!(
            evil.requests.lock().await.is_empty(),
            "HTTPS->HTTP downgrade redirect must be blocked by proxy"
        );
    }

    #[tokio::test]
    async fn external_descriptor_urls_are_ignored_unless_allow_blob_host_is_set() {
        let layer_bytes = b"external-blob-payload".to_vec();
        let layer_digest = sha256_digest(&layer_bytes);
        let ext = spawn_mock_server(false, move |_| {
            MockHttpResponse::bytes(200, "application/octet-stream", layer_bytes.clone())
        })
        .await;
        let reg = spawn_mock_server(false, |_| MockHttpResponse::json(404, "{}")).await;
        let registry = format!("127.0.0.1:{}", reg.port);
        let ext_host = format!("127.0.0.1:{}", ext.port);
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayer)
            .digest(layer_digest)
            .size(21_u64)
            .urls(vec![format!("http://{ext_host}/blob")])
            .build()
            .unwrap();

        // Without allow_blob_hosts: external URL must not be contacted.
        let strict_client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry.clone()],
                registry_hosts: vec![registry.clone()],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();
        let mut tmp = tempfile::tempfile().unwrap();
        assert!(
            strict_client
                .fetch_layer_to_file(&reference, &descriptor, &mut tmp, |_| {})
                .await
                .is_err()
        );
        assert!(ext.requests.lock().await.is_empty());

        // With allow_blob_hosts: external URL succeeds and verifies digest.
        let allowed_client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry.clone(), ext_host.clone()],
                registry_hosts: vec![registry],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allowed_blob_hosts: vec![ext_host],
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();
        allowed_client
            .fetch_layer_to_file(&reference, &descriptor, &mut tmp, |_| {})
            .await
            .unwrap();
        assert_eq!(ext.requests.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn cdn_redirect_across_hosts_succeeds_without_leaking_credentials() {
        let (manifest_json, manifest_digest, config_json, layer_bytes, config_digest, layer_digest) =
            minimal_image_fixtures();
        let cdn = spawn_mock_server(false, move |_| {
            MockHttpResponse::bytes(200, "application/octet-stream", layer_bytes.clone())
        })
        .await;
        let cdn_port = cdn.port;
        let reg_port_holder = Arc::new(std::sync::atomic::AtomicU16::new(0));
        let reg_port_ref = reg_port_holder.clone();
        let reg = spawn_mock_server(false, move |req| {
            let reg_port = reg_port_ref.load(Ordering::Relaxed);
            match req.path.as_str() {
                "/v2/" => {
                    if !req.headers.contains_key("authorization") {
                        MockHttpResponse {
                            status: 401,
                            headers: vec![(
                                "WWW-Authenticate".into(),
                                format!(
                                    r#"Bearer realm="http://127.0.0.1:{reg_port}/token",service="reg""#
                                ),
                            )],
                            body: Vec::new(),
                        }
                    } else {
                        MockHttpResponse::json(200, "{}")
                    }
                }
                p if p.starts_with("/token") => {
                    MockHttpResponse::json(200, r#"{"token":"secret-bearer"}"#)
                }
                "/v2/test/app/manifests/v1" => MockHttpResponse {
                    status: 200,
                    headers: vec![
                        (
                            "Content-Type".into(),
                            "application/vnd.oci.image.manifest.v1+json".into(),
                        ),
                        ("Docker-Content-Digest".into(), manifest_digest.clone()),
                    ],
                    body: manifest_json.as_bytes().to_vec(),
                },
                p if p == format!("/v2/test/app/blobs/{config_digest}") => {
                    MockHttpResponse::bytes(200, "application/json", config_json.as_bytes().to_vec())
                }
                p if p == format!("/v2/test/app/blobs/{layer_digest}") => MockHttpResponse {
                    status: 307,
                    headers: vec![(
                        "Location".into(),
                        format!("http://127.0.0.1:{cdn_port}/cdn-blob"),
                    )],
                    body: Vec::new(),
                },
                _ => MockHttpResponse::json(404, "{}"),
            }
        })
        .await;
        reg_port_holder.store(reg.port, Ordering::Relaxed);

        let registry = format!("127.0.0.1:{}", reg.port);
        let cdn_host = format!("127.0.0.1:{cdn_port}");
        let creds = Credentials::load(&[format!("{registry}=alice:secret")], None).unwrap();
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let client = RegistryClient::with_options(
            creds,
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry.clone(), cdn_host],
                registry_hosts: vec![registry],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        let image = client.pull_base(&reference).await.unwrap();
        let mut tmp = tempfile::tempfile().unwrap();
        client
            .fetch_layer_to_file(&reference, &image.layers[0], &mut tmp, |_| {})
            .await
            .unwrap();

        let cdn_reqs = cdn.requests.lock().await;
        assert_eq!(cdn_reqs.len(), 1);
        assert!(
            !cdn_reqs[0].headers.contains_key("authorization"),
            "CDN redirect must not leak registry Authorization header"
        );
    }

    #[tokio::test]
    async fn allow_registry_only_blocks_unallowed_registry_and_redirect_before_connect() {
        let (manifest_json, manifest_digest, config_json, _, config_digest, layer_digest) =
            minimal_image_fixtures();
        let evil = spawn_mock_server(false, |_| {
            MockHttpResponse::bytes(200, "application/octet-stream", b"evil".to_vec())
        })
        .await;
        let evil_port = evil.port;
        let reg = spawn_mock_server(false, move |req| match req.path.as_str() {
            "/v2/" => MockHttpResponse::json(200, "{}"),
            "/v2/test/app/manifests/v1" => MockHttpResponse {
                status: 200,
                headers: vec![
                    (
                        "Content-Type".into(),
                        "application/vnd.oci.image.manifest.v1+json".into(),
                    ),
                    ("Docker-Content-Digest".into(), manifest_digest.clone()),
                ],
                body: manifest_json.as_bytes().to_vec(),
            },
            p if p == format!("/v2/test/app/blobs/{config_digest}") => {
                MockHttpResponse::bytes(200, "application/json", config_json.as_bytes().to_vec())
            }
            p if p == format!("/v2/test/app/blobs/{layer_digest}") => MockHttpResponse {
                status: 307,
                headers: vec![(
                    "Location".into(),
                    format!("http://127.0.0.1:{evil_port}/blob"),
                )],
                body: Vec::new(),
            },
            _ => MockHttpResponse::json(404, "{}"),
        })
        .await;

        let registry = format!("127.0.0.1:{}", reg.port);
        let evil_host = format!("127.0.0.1:{evil_port}");
        let client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry.clone(), evil_host.clone()],
                registry_hosts: vec![registry.clone()],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allowed_registries: vec![registry.clone()],
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        // Direct pull to an unallowed registry is blocked before connecting.
        let evil_ref: Reference = format!("{evil_host}/test/app:v1").parse().unwrap();
        assert!(client.pull_base(&evil_ref).await.is_err());
        assert!(
            evil.requests.lock().await.is_empty(),
            "unallowed registry must be rejected before connecting"
        );

        // Allowed registry succeeds for manifest/config, but 307 redirect to unallowed host is blocked before connect.
        let allowed_ref: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let image = client.pull_base(&allowed_ref).await.unwrap();
        let mut tmp = tempfile::tempfile().unwrap();
        assert!(
            client
                .fetch_layer_to_file(&allowed_ref, &image.layers[0], &mut tmp, |_| {})
                .await
                .is_err(),
            "redirect to host outside --allow-registry must be rejected"
        );
        assert!(
            evil.requests.lock().await.is_empty(),
            "proxy must reject unallowed redirect target before connecting"
        );
    }

    #[tokio::test]
    async fn allow_registry_auth_host_and_cdn_host_work_with_role_separation() {
        let (manifest_json, manifest_digest, config_json, layer_bytes, config_digest, layer_digest) =
            minimal_image_fixtures();
        let cdn = spawn_mock_server(false, move |_| {
            MockHttpResponse::bytes(200, "application/octet-stream", layer_bytes.clone())
        })
        .await;
        let cdn_port = cdn.port;
        let auth_srv = spawn_mock_server(false, |req| {
            if req.path.starts_with("/token") {
                assert_eq!(
                    req.headers.get("authorization").map(String::as_str),
                    Some("Basic YWxpY2U6c2VjcmV0")
                );
                MockHttpResponse::json(200, r#"{"token":"role-tok"}"#)
            } else {
                MockHttpResponse::json(404, "{}")
            }
        })
        .await;
        let auth_port = auth_srv.port;
        let evil = spawn_mock_server(false, |_| {
            MockHttpResponse::bytes(200, "application/octet-stream", b"evil".to_vec())
        })
        .await;
        let evil_port = evil.port;

        let redirect_mode = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let redirect_mode_srv = redirect_mode.clone();
        let reg = spawn_mock_server(false, move |req| match req.path.as_str() {
            "/v2/" => {
                if !req.headers.contains_key("authorization") {
                    let realm_port = if redirect_mode_srv.load(Ordering::Relaxed) == 3 {
                        cdn_port
                    } else {
                        auth_port
                    };
                    MockHttpResponse {
                        status: 401,
                        headers: vec![(
                            "WWW-Authenticate".into(),
                            format!(
                                r#"Bearer realm="http://127.0.0.1:{realm_port}/token",service="reg""#
                            ),
                        )],
                        body: Vec::new(),
                    }
                } else {
                    MockHttpResponse::json(200, "{}")
                }
            }
            "/v2/test/app/manifests/v1" => MockHttpResponse {
                status: 200,
                headers: vec![
                    (
                        "Content-Type".into(),
                        "application/vnd.oci.image.manifest.v1+json".into(),
                    ),
                    ("Docker-Content-Digest".into(), manifest_digest.clone()),
                ],
                body: manifest_json.as_bytes().to_vec(),
            },
            p if p == format!("/v2/test/app/blobs/{config_digest}") => {
                MockHttpResponse::bytes(200, "application/json", config_json.as_bytes().to_vec())
            }
            p if p == format!("/v2/test/app/blobs/{layer_digest}") => {
                let target_port = match redirect_mode_srv.load(Ordering::Relaxed) {
                    0 => cdn_port,
                    1 => auth_port,
                    _ => evil_port,
                };
                MockHttpResponse {
                    status: 307,
                    headers: vec![(
                        "Location".into(),
                        format!("http://127.0.0.1:{target_port}/cdn-blob"),
                    )],
                    body: Vec::new(),
                }
            }
            _ => MockHttpResponse::json(404, "{}"),
        })
        .await;

        let registry = format!("127.0.0.1:{}", reg.port);
        let auth_host = format!("127.0.0.1:{auth_port}");
        let cdn_host = format!("127.0.0.1:{cdn_port}");
        let evil_host = format!("127.0.0.1:{evil_port}");
        let creds = Credentials::load(&[format!("{registry}=alice:secret")], None).unwrap();
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();

        let make_client = || {
            RegistryClient::with_options(
                creds.clone(),
                Platform::from_str("linux/amd64").unwrap(),
                RegistryOptions {
                    plain_http_hosts: vec![
                        registry.clone(),
                        auth_host.clone(),
                        cdn_host.clone(),
                        evil_host.clone(),
                    ],
                    registry_hosts: vec![registry.clone()],
                    max_attempts: 1,
                    network_policy: NetworkPolicy {
                        allowed_registries: vec![registry.clone()],
                        allowed_auth_hosts: vec![auth_host.clone()],
                        allowed_blob_hosts: vec![cdn_host.clone()],
                        allow_private_network: true,
                    },
                    ..RegistryOptions::default()
                },
            )
            .unwrap()
        };

        // 1. Valid path: registry + allowed_auth_host + allowed_blob_host succeed.
        let client = make_client();
        let image = client.pull_base(&reference).await.unwrap();
        let mut tmp = tempfile::tempfile().unwrap();
        client
            .fetch_layer_to_file(&reference, &image.layers[0], &mut tmp, |_| {})
            .await
            .unwrap();
        assert_eq!(auth_srv.requests.lock().await.len(), 1);
        assert_eq!(cdn.requests.lock().await.len(), 1);
        assert!(
            !cdn.requests.lock().await[0]
                .headers
                .contains_key("authorization")
        );

        // 2. Blob redirect to auth_host must be blocked before connecting to auth_srv.
        redirect_mode.store(1, Ordering::Relaxed);
        assert!(
            client
                .fetch_layer_to_file(&reference, &image.layers[0], &mut tmp, |_| {})
                .await
                .is_err(),
            "blob redirect to auth-only host must be rejected"
        );
        assert_eq!(
            auth_srv.requests.lock().await.len(),
            1,
            "auth_srv must not receive redirected blob request"
        );

        // 3. Blob redirect to unallowed evil host must be blocked before connecting.
        redirect_mode.store(2, Ordering::Relaxed);
        assert!(
            client
                .fetch_layer_to_file(&reference, &image.layers[0], &mut tmp, |_| {})
                .await
                .is_err()
        );
        assert!(evil.requests.lock().await.is_empty());

        // 4. Auth realm pointing to cdn_host must be rejected without sending credentials.
        redirect_mode.store(3, Ordering::Relaxed);
        let client2 = make_client();
        assert!(client2.pull_base(&reference).await.is_err());
        assert_eq!(
            cdn.requests.lock().await.len(),
            1,
            "cdn must not receive credential token request"
        );
    }

    #[tokio::test]
    async fn dns_rebinding_and_metadata_ip_resolution_are_blocked_before_connect() {
        let (manifest_json, manifest_digest, config_json, _, config_digest, _) =
            minimal_image_fixtures();
        let reg = spawn_mock_server(false, move |req| match req.path.as_str() {
            "/v2/" => MockHttpResponse::json(200, "{}"),
            "/v2/test/app/manifests/v1" => MockHttpResponse {
                status: 200,
                headers: vec![
                    (
                        "Content-Type".into(),
                        "application/vnd.oci.image.manifest.v1+json".into(),
                    ),
                    ("Docker-Content-Digest".into(), manifest_digest.clone()),
                ],
                body: manifest_json.as_bytes().to_vec(),
            },
            p if p == format!("/v2/test/app/blobs/{config_digest}") => {
                MockHttpResponse::bytes(200, "application/json", config_json.as_bytes().to_vec())
            }
            _ => MockHttpResponse::json(404, "{}"),
        })
        .await;

        // Case A: Hostname resolves to [127.0.0.1, 100.100.100.200] -> blocked before connecting.
        let multi_host = "reg-multi-meta.invalid";
        let _multi_guard = net_policy::set_test_dns_override(
            multi_host,
            vec![vec![
                "127.0.0.1".parse().unwrap(),
                "100.100.100.200".parse().unwrap(),
            ]],
        );
        let multi_registry = format!("{multi_host}:{}", reg.port);
        let multi_ref: Reference = format!("{multi_registry}/test/app:v1").parse().unwrap();
        let multi_client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![multi_registry.clone()],
                registry_hosts: vec![multi_registry.clone()],
                connect_timeout: Duration::from_millis(200),
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allowed_registries: vec![multi_registry],
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();
        let multi_err = format!(
            "{:#}",
            multi_client.pull_base(&multi_ref).await.unwrap_err()
        );
        assert!(
            multi_err.contains("forbidden") || multi_err.contains("blocked"),
            "expected policy block for multi-record metadata IP, got: {multi_err}"
        );
        assert!(
            reg.requests.lock().await.is_empty(),
            "multi-record DNS containing metadata IP must be blocked before connecting"
        );

        // Case B: TOCTOU DNS rebinding across /v2/ discovery -> proxy manifest fetch.
        let toctou_host = "reg-toctou-rebind.invalid";
        let _toctou_guard = net_policy::set_test_dns_override(
            toctou_host,
            vec![
                vec!["127.0.0.1".parse().unwrap()],
                vec!["100.100.100.200".parse().unwrap()],
            ],
        );
        let toctou_registry = format!("{toctou_host}:{}", reg.port);
        let toctou_ref: Reference = format!("{toctou_registry}/test/app:v1").parse().unwrap();
        let toctou_client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![toctou_registry.clone()],
                registry_hosts: vec![toctou_registry.clone()],
                connect_timeout: Duration::from_millis(200),
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allowed_registries: vec![toctou_registry],
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();
        let toctou_err = format!(
            "{:#}",
            toctou_client.pull_base(&toctou_ref).await.unwrap_err()
        );
        assert!(
            toctou_err.contains("403")
                || toctou_err.contains("forbidden")
                || toctou_err.contains("blocked"),
            "expected proxy policy rejection on rebound metadata IP, got: {toctou_err}"
        );
        let recorded = reg.requests.lock().await;
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].path, "/v2/");
    }

    #[tokio::test]
    async fn allow_private_network_still_blocks_cloud_metadata_requests() {
        for metadata_host in [
            "100.100.100.200",
            "168.63.129.16",
            "169.254.169.254",
            "metadata.google.internal",
            "metadata.azure.com",
            "instance-data.ec2.internal",
            "instance-data:80",
            "metadata:80",
        ] {
            let reference: Reference = format!("{metadata_host}/test/app:v1").parse().unwrap();
            let client = RegistryClient::with_options(
                Credentials::default(),
                Platform::from_str("linux/amd64").unwrap(),
                RegistryOptions {
                    plain_http_hosts: vec![metadata_host.to_string()],
                    registry_hosts: vec![metadata_host.to_string()],
                    connect_timeout: Duration::from_millis(200),
                    max_attempts: 1,
                    network_policy: NetworkPolicy {
                        allow_private_network: true,
                        ..NetworkPolicy::default()
                    },
                    ..RegistryOptions::default()
                },
            )
            .unwrap();
            let err = client.pull_base(&reference).await.unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("forbidden") || msg.contains("blocked"),
                "expected policy block for {metadata_host}, got: {msg}"
            );
        }

        // Also verify IPv6 and IPv4-mapped metadata addresses are blocked when returned by DNS
        // or via a 307 redirect through ValidatingProxy, even with allow_private_network=true.
        for (idx, meta_ip) in [
            "fd00:ec2::254",
            "::ffff:100.100.100.200",
            "::ffff:168.63.129.16",
        ]
        .into_iter()
        .enumerate()
        {
            let host = format!("meta-dns-{idx}.invalid");
            let _guard =
                net_policy::set_test_dns_override(&host, vec![vec![meta_ip.parse().unwrap()]]);
            let reference: Reference = format!("{host}/test/app:v1").parse().unwrap();
            let client = RegistryClient::with_options(
                Credentials::default(),
                Platform::from_str("linux/amd64").unwrap(),
                RegistryOptions {
                    plain_http_hosts: vec![host.clone()],
                    registry_hosts: vec![host],
                    connect_timeout: Duration::from_millis(200),
                    max_attempts: 1,
                    network_policy: NetworkPolicy {
                        allow_private_network: true,
                        ..NetworkPolicy::default()
                    },
                    ..RegistryOptions::default()
                },
            )
            .unwrap();
            let err = client.pull_base(&reference).await.unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("forbidden") || msg.contains("blocked"),
                "expected policy block for DNS->{meta_ip}, got: {msg}"
            );
        }

        // Verify direct metadata redirects (IPv6, Alibaba, Azure WireServer, single-label DNS)
        // through ValidatingProxy are blocked even with allow_private_network=true.
        for (redirect_host, redirect_url) in [
            (
                "[fd00:ec2::254]",
                "http://[fd00:ec2::254]/latest/meta-data/",
            ),
            (
                "100.100.100.200",
                "http://100.100.100.200/latest/meta-data/",
            ),
            (
                "168.63.129.16",
                "http://168.63.129.16/machine?comp=goalstate",
            ),
            ("instance-data", "http://instance-data/latest/meta-data/"),
        ] {
            let (manifest_json, manifest_digest, config_json, _, config_digest, layer_digest) =
                minimal_image_fixtures();
            let redirect_url_owned = redirect_url.to_string();
            let reg = spawn_mock_server(false, move |req| match req.path.as_str() {
                "/v2/" => MockHttpResponse::json(200, "{}"),
                "/v2/test/app/manifests/v1" => MockHttpResponse {
                    status: 200,
                    headers: vec![
                        (
                            "Content-Type".into(),
                            "application/vnd.oci.image.manifest.v1+json".into(),
                        ),
                        ("Docker-Content-Digest".into(), manifest_digest.clone()),
                    ],
                    body: manifest_json.as_bytes().to_vec(),
                },
                p if p == format!("/v2/test/app/blobs/{config_digest}") => MockHttpResponse::bytes(
                    200,
                    "application/json",
                    config_json.as_bytes().to_vec(),
                ),
                p if p == format!("/v2/test/app/blobs/{layer_digest}") => MockHttpResponse {
                    status: 307,
                    headers: vec![("Location".into(), redirect_url_owned.clone())],
                    body: Vec::new(),
                },
                _ => MockHttpResponse::json(404, "{}"),
            })
            .await;
            let registry = format!("127.0.0.1:{}", reg.port);
            let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
            let client = RegistryClient::with_options(
                Credentials::default(),
                Platform::from_str("linux/amd64").unwrap(),
                RegistryOptions {
                    plain_http_hosts: vec![registry.clone(), redirect_host.to_string()],
                    registry_hosts: vec![registry],
                    connect_timeout: Duration::from_millis(200),
                    max_attempts: 1,
                    network_policy: NetworkPolicy {
                        allow_private_network: true,
                        ..NetworkPolicy::default()
                    },
                    ..RegistryOptions::default()
                },
            )
            .unwrap();
            let image = client.pull_base(&reference).await.unwrap();
            let mut tmp = tempfile::tempfile().unwrap();
            let err = client
                .fetch_layer_to_file(&reference, &image.layers[0], &mut tmp, |_| {})
                .await
                .unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("403") || msg.contains("forbidden") || msg.contains("blocked"),
                "expected proxy block for {redirect_url} redirect, got: {msg}"
            );
        }
    }

    #[tokio::test]
    async fn blob_download_aborts_during_stream_when_exceeding_declared_size() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let task_shutdown = shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { break; };
                        tokio::spawn(async move {
                            let mut reader = BufReader::new(&mut stream);
                            let mut line = String::new();
                            loop {
                                line.clear();
                                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                                    return;
                                }
                                if line.trim_end_matches(&['\r', '\n'][..]).is_empty() {
                                    break;
                                }
                            }
                            let inner = reader.into_inner();
                            // Chunked response with 1024 bytes when descriptor declares 64 bytes.
                            let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n400\r\n";
                            let _ = inner.write_all(head.as_bytes()).await;
                            let _ = inner.write_all(&vec![b'A'; 1024]).await;
                            let _ = inner.write_all(b"\r\n0\r\n\r\n").await;
                            let _ = inner.shutdown().await;
                        });
                    }
                }
            }
        });

        let registry = format!("127.0.0.1:{port}");
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let expected_digest = sha256_digest(&[b'A'; 64]);
        let descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayer)
            .digest(expected_digest)
            .size(64_u64)
            .build()
            .unwrap();
        let client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry.clone()],
                registry_hosts: vec![registry],
                max_attempts: 2,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        let mut tmp = tempfile::tempfile().unwrap();
        let err = client
            .fetch_layer_to_file(&reference, &descriptor, &mut tmp, |_| {})
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("exceeded declared size"), "got: {msg}");
        shutdown.cancel();
    }

    #[tokio::test]
    async fn blob_size_limit_aborts_build_without_publishing_cache_or_archive() {
        use crate::app::spec::{BuildRequest, CacheSpec, ImageBuildSpec, RegistryClientSpec};
        use crate::output_target::OutputTarget;
        use crate::progress::{Progress, ProgressMode};

        let layer_bytes = vec![b'X'; 512];
        let layer_digest = sha256_digest(&layer_bytes).to_string();
        let config_json = format!(
            r#"{{"architecture":"amd64","os":"linux","rootfs":{{"type":"layers","diff_ids":["{layer_digest}"]}}}}"#
        );
        let config_digest = sha256_digest(config_json.as_bytes()).to_string();
        let manifest_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":{}}}]}}"#,
            config_json.len(),
            layer_bytes.len()
        );
        let manifest_digest = sha256_digest(manifest_json.as_bytes()).to_string();

        let server = spawn_mock_server(false, move |req| match req.path.as_str() {
            "/v2/" => MockHttpResponse::json(200, "{}"),
            "/v2/test/app/manifests/v1" => MockHttpResponse {
                status: 200,
                headers: vec![
                    (
                        "Content-Type".into(),
                        "application/vnd.oci.image.manifest.v1+json".into(),
                    ),
                    ("Docker-Content-Digest".into(), manifest_digest.clone()),
                ],
                body: manifest_json.as_bytes().to_vec(),
            },
            p if p == format!("/v2/test/app/blobs/{config_digest}") => {
                MockHttpResponse::bytes(200, "application/json", config_json.as_bytes().to_vec())
            }
            p if p == format!("/v2/test/app/blobs/{layer_digest}") => {
                MockHttpResponse::bytes(200, "application/octet-stream", layer_bytes.clone())
            }
            _ => MockHttpResponse::json(404, "{}"),
        })
        .await;

        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        let archive_path = dir.path().join("out.tar");
        let spec = ImageBuildSpec {
            from: format!("127.0.0.1:{}/test/app:v1", server.port),
            targets: vec![OutputTarget::OciArchive {
                path: archive_path.clone(),
                tag: None,
            }],
            local_only: true,
            copies: Vec::new(),
            copy_roots: Vec::new(),
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
            transport: RegistryClientSpec {
                source_plain_http: true,
                ..RegistryClientSpec::default()
            },
            network_policy: NetworkPolicy {
                allow_private_network: true,
                ..NetworkPolicy::default()
            },
            limits: ResourceLimits {
                max_blob_bytes: 128,
                ..ResourceLimits::default()
            },
            cache: CacheSpec {
                enable: true,
                cache_path: Some(cache_dir.clone()),
            },
        };

        let request = BuildRequest::try_from(spec).unwrap();
        let err = request
            .run(Credentials::default(), Progress::new(ProgressMode::Quiet))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("--max-blob-size"));
        assert!(!archive_path.exists(), "incomplete archive must not exist");
        let cache_entries: Vec<_> = std::fs::read_dir(&cache_dir).unwrap().collect();
        assert!(
            cache_entries.is_empty(),
            "failed blob must not be published to cache"
        );
    }

    #[tokio::test]
    async fn cumulative_total_download_limit_is_enforced_across_layers() {
        let layer1 = vec![1_u8; 128];
        let layer2 = vec![2_u8; 128];
        let d1 = sha256_digest(&layer1);
        let d2 = sha256_digest(&layer2);
        let p1 = format!("/v2/test/app/blobs/{d1}");
        let p2 = format!("/v2/test/app/blobs/{d2}");
        let server = spawn_mock_server(false, move |req| {
            if req.path == "/v2/" {
                MockHttpResponse::json(200, "{}")
            } else if req.path == p1 {
                MockHttpResponse::bytes(200, "application/octet-stream", layer1.clone())
            } else if req.path == p2 {
                MockHttpResponse::bytes(200, "application/octet-stream", layer2.clone())
            } else {
                MockHttpResponse::json(404, "{}")
            }
        })
        .await;

        let registry = format!("127.0.0.1:{}", server.port);
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry.clone()],
                registry_hosts: vec![registry],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                limits: ResourceLimits {
                    max_total_download_bytes: 200,
                    ..ResourceLimits::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        let desc1 = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayer)
            .digest(d1)
            .size(128_u64)
            .build()
            .unwrap();
        let desc2 = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayer)
            .digest(d2)
            .size(128_u64)
            .build()
            .unwrap();

        let mut f1 = tempfile::tempfile().unwrap();
        client
            .fetch_layer_to_file(&reference, &desc1, &mut f1, |_| {})
            .await
            .unwrap();
        let mut f2 = tempfile::tempfile().unwrap();
        let err = client
            .fetch_layer_to_file(&reference, &desc2, &mut f2, |_| {})
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("total registry download size exceeds"));
    }

    #[tokio::test]
    async fn slowloris_registry_is_aborted_by_transfer_timeout() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let task_shutdown = shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { break; };
                        tokio::spawn(async move {
                            let mut reader = BufReader::new(&mut stream);
                            let mut line = String::new();
                            loop {
                                line.clear();
                                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                                    return;
                                }
                                if line.trim_end_matches(&['\r', '\n'][..]).is_empty() {
                                    break;
                                }
                            }
                            let inner = reader.into_inner();
                            let _ = inner
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\npartial")
                                .await;
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        });
                    }
                }
            }
        });

        let registry = format!("127.0.0.1:{port}");
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let descriptor = DescriptorBuilder::default()
            .media_type(MediaType::ImageLayer)
            .digest(sha256_digest(&[0_u8; 500]))
            .size(500_u64)
            .build()
            .unwrap();
        let client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry.clone()],
                registry_hosts: vec![registry],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                limits: ResourceLimits {
                    transfer_timeout: Duration::from_millis(150),
                    ..ResourceLimits::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        let mut tmp = tempfile::tempfile().unwrap();
        let err = client
            .fetch_layer_to_file(&reference, &descriptor, &mut tmp, |_| {})
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("transfer timeout"));
        shutdown.cancel();
    }

    #[tokio::test]
    async fn end_to_end_tls_base_multi_copy_and_reproducibility() {
        use crate::app::spec::{
            BuildRequest, CacheSpec, CopyDirective, ImageBuildSpec, RegistryClientSpec,
        };
        use crate::output_target::OutputTarget;
        use crate::progress::{Progress, ProgressMode};
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use oci_spec::image::{ImageConfiguration, ImageIndex, ImageManifest};
        use std::io::{Read, Write};

        // Build a valid gzip-compressed tar base layer with distinct diff_id and digest.
        let mut base_tar = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut base_tar);
            let mut header = tar::Header::new_gnu();
            let content = b"debian-like-base-release\n";
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, "etc/os-release", &content[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let base_diff_id = sha256_digest(&base_tar).to_string();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&base_tar).unwrap();
        let base_gz = encoder.finish().unwrap();
        let base_digest = sha256_digest(&base_gz).to_string();

        let config_json = format!(
            r#"{{"architecture":"amd64","os":"linux","config":{{"Cmd":["/bin/sh"]}},"rootfs":{{"type":"layers","diff_ids":["{base_diff_id}"]}}}}"#
        );
        let config_digest = sha256_digest(config_json.as_bytes()).to_string();
        let manifest_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"{base_digest}","size":{}}}]}}"#,
            config_json.len(),
            base_gz.len()
        );
        let manifest_digest = sha256_digest(manifest_json.as_bytes()).to_string();

        let port_holder = Arc::new(std::sync::atomic::AtomicU16::new(0));
        let port_ref = port_holder.clone();
        let server = spawn_mock_server(true, move |req| {
            let port = port_ref.load(Ordering::Relaxed);
            match req.path.as_str() {
                "/v2/" => {
                    if !req.headers.contains_key("authorization") {
                        MockHttpResponse {
                            status: 401,
                            headers: vec![(
                                "WWW-Authenticate".into(),
                                format!(
                                    r#"Bearer realm="https://127.0.0.1:{port}/token",service="reg""#
                                ),
                            )],
                            body: Vec::new(),
                        }
                    } else {
                        MockHttpResponse::json(200, "{}")
                    }
                }
                p if p.starts_with("/token") => MockHttpResponse::json(200, r#"{"token":"ok"}"#),
                "/v2/library/debian/manifests/bookworm" => MockHttpResponse {
                    status: 200,
                    headers: vec![
                        (
                            "Content-Type".into(),
                            "application/vnd.oci.image.manifest.v1+json".into(),
                        ),
                        ("Docker-Content-Digest".into(), manifest_digest.clone()),
                    ],
                    body: manifest_json.as_bytes().to_vec(),
                },
                p if p == format!("/v2/library/debian/blobs/{config_digest}") => {
                    MockHttpResponse::bytes(
                        200,
                        "application/json",
                        config_json.as_bytes().to_vec(),
                    )
                }
                p if p == format!("/v2/library/debian/blobs/{base_digest}") => {
                    MockHttpResponse::bytes(200, "application/octet-stream", base_gz.clone())
                }
                _ => MockHttpResponse::json(404, "{}"),
            }
        })
        .await;
        port_holder.store(server.port, Ordering::Relaxed);

        let workspace = tempfile::tempdir().unwrap();
        let inputs = workspace.path().join("inputs");
        std::fs::create_dir_all(inputs.join("data/nested")).unwrap();
        std::fs::write(inputs.join("probe"), b"#!/bin/sh\necho ok\n").unwrap();
        std::fs::write(inputs.join("settings.conf"), b"mode=ci\n").unwrap();
        std::fs::write(inputs.join("data/top.txt"), b"top\n").unwrap();
        std::fs::write(inputs.join("data/nested/sub.txt"), b"sub\n").unwrap();

        let out_a = workspace.path().join("out-a.tar");
        let out_b = workspace.path().join("out-b.tar");
        let cache_dir = workspace.path().join("cache");
        let registry = format!("127.0.0.1:{}", server.port);
        let creds = Credentials::load(&[format!("{registry}=ci:pass")], None).unwrap();

        let build_once = |out: std::path::PathBuf| {
            let spec = ImageBuildSpec {
                from: format!("{registry}/library/debian:bookworm"),
                targets: vec![OutputTarget::OciArchive {
                    path: out,
                    tag: Some("ci".to_string()),
                }],
                local_only: true,
                copies: vec![
                    CopyDirective::parse(format!(
                        "{}:/app/probe,mode=0755,chown=65532:65532",
                        inputs.join("probe").display()
                    ))
                    .unwrap(),
                    CopyDirective::parse(format!(
                        "{}:/app/config/settings.conf,mode=0640,chown=65532:65532",
                        inputs.join("settings.conf").display()
                    ))
                    .unwrap(),
                    CopyDirective::parse(format!(
                        "{}:/app/data/,chown=65532:65532",
                        inputs.join("data").display()
                    ))
                    .unwrap(),
                ],
                copy_roots: vec![inputs.clone()],
                jobs: 2,
                platform: "linux/amd64".to_string(),
                entrypoint: Some(vec!["/app/probe".to_string()]),
                cmd: None,
                labels: vec!["org.test.ci=true".to_string()],
                ports: Vec::new(),
                workdir: Some("/app".to_string()),
                user: Some("65532:65532".to_string()),
                creation_time: "epoch".to_string(),
                keep_cmd: false,
                transport: RegistryClientSpec {
                    source_skip_tls: true,
                    ..RegistryClientSpec::default()
                },
                network_policy: NetworkPolicy {
                    allowed_registries: vec![registry.clone()],
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                limits: ResourceLimits::default(),
                cache: CacheSpec {
                    enable: true,
                    cache_path: Some(cache_dir.clone()),
                },
            };
            BuildRequest::try_from(spec).unwrap()
        };

        build_once(out_a.clone())
            .run(creds.clone(), Progress::new(ProgressMode::Quiet))
            .await
            .unwrap();
        build_once(out_b.clone())
            .run(creds, Progress::new(ProgressMode::Quiet))
            .await
            .unwrap();

        let bytes_a = std::fs::read(&out_a).unwrap();
        let bytes_b = std::fs::read(&out_b).unwrap();
        assert_eq!(
            sha256_digest(&bytes_a),
            sha256_digest(&bytes_b),
            "OCI archive across cache miss + cache hit must be byte-reproducible"
        );

        let read_entry = |name: &str| -> Vec<u8> {
            let mut archive = tar::Archive::new(bytes_a.as_slice());
            for entry in archive.entries().unwrap() {
                let mut entry = entry.unwrap();
                if entry.path().unwrap().to_string_lossy() == name {
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf).unwrap();
                    return buf;
                }
            }
            panic!("missing archive entry {name}");
        };

        let index: ImageIndex = serde_json::from_slice(&read_entry("index.json")).unwrap();
        let manifest_desc = &index.manifests()[0];
        let manifest_bytes = read_entry(&crate::digest::blob_path(manifest_desc.digest()));
        assert_eq!(sha256_digest(&manifest_bytes), *manifest_desc.digest());
        let manifest: ImageManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(manifest.layers().len(), 4);

        let config_bytes = read_entry(&crate::digest::blob_path(manifest.config().digest()));
        assert_eq!(sha256_digest(&config_bytes), *manifest.config().digest());
        let config: ImageConfiguration = serde_json::from_slice(&config_bytes).unwrap();
        assert_eq!(config.rootfs().diff_ids().len(), 4);
        assert_eq!(config.rootfs().diff_ids()[0], base_diff_id);
        for layer in manifest.layers() {
            let blob = read_entry(&crate::digest::blob_path(layer.digest()));
            assert_eq!(sha256_digest(&blob), *layer.digest());
            assert_eq!(blob.len() as u64, layer.size());
        }
    }

    async fn spawn_raw_http_server<F, Fut>(handler: F) -> (u16, tokio_util::sync::CancellationToken)
    where
        F: Fn(String, tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let handler = Arc::new(handler);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break; };
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            let mut reader = BufReader::new(stream);
                            let mut first = String::new();
                            if reader.read_line(&mut first).await.unwrap_or(0) == 0 {
                                return;
                            }
                            let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
                            loop {
                                let mut line = String::new();
                                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                                    return;
                                }
                                if line.trim_end_matches(&['\r', '\n'][..]).is_empty() {
                                    break;
                                }
                            }
                            handler(path, reader.into_inner()).await;
                        });
                    }
                }
            }
        });
        (port, shutdown)
    }

    #[tokio::test]
    async fn manifest_content_length_exceeding_limit_is_rejected_before_body_read() {
        use tokio::io::AsyncWriteExt;

        let (port, shutdown) = spawn_raw_http_server(|path, mut stream| async move {
            match path.as_str() {
                "/v2/" => {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                        .await;
                }
                "/v2/test/app/manifests/v1" => {
                    // Declare a huge Content-Length and stall before completing the body.
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.oci.image.manifest.v1+json\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n{\"schemaVersion\":2}",
                        )
                        .await;
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                }
                _ => {
                    let _ = stream
                        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                        .await;
                }
            }
        })
        .await;

        let registry = format!("127.0.0.1:{port}");
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry.clone()],
                registry_hosts: vec![registry],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                limits: ResourceLimits {
                    max_manifest_bytes: 512,
                    transfer_timeout: Duration::from_millis(500),
                    ..ResourceLimits::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        let started = std::time::Instant::now();
        let err = client.pull_base(&reference).await.unwrap_err();
        let elapsed = started.elapsed();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exceeds") && msg.contains("limit"),
            "expected immediate manifest Content-Length limit error, got: {msg}"
        );
        assert!(
            elapsed < Duration::from_millis(350),
            "expected immediate abort before reading body, took {elapsed:?}"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn chunked_manifest_and_manifest_index_abort_mid_stream_without_content_length() {
        use tokio::io::AsyncWriteExt;

        // Case A: Single manifest served as chunked transfer (no Content-Length) exceeding limit on chunk 1.
        let (port_a, shutdown_a) = spawn_raw_http_server(|path, mut stream| async move {
            match path.as_str() {
                "/v2/" => {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                        .await;
                }
                "/v2/test/app/manifests/v1" => {
                    let chunk = vec![b' '; 300];
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.oci.image.manifest.v1+json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                        chunk.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&chunk).await;
                    let _ = stream.write_all(b"\r\n").await;
                    // Stall instead of terminating chunked stream; client must abort on chunk 1.
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                }
                _ => {}
            }
        })
        .await;

        let registry_a = format!("127.0.0.1:{port_a}");
        let reference_a: Reference = format!("{registry_a}/test/app:v1").parse().unwrap();
        let client_a = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry_a.clone()],
                registry_hosts: vec![registry_a],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                limits: ResourceLimits {
                    max_manifest_bytes: 256,
                    transfer_timeout: Duration::from_millis(500),
                    ..ResourceLimits::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        let started = std::time::Instant::now();
        let err = client_a.pull_base(&reference_a).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exceeded") && msg.contains("limit"),
            "expected streaming manifest limit error, got: {msg}"
        );
        assert!(
            started.elapsed() < Duration::from_millis(350),
            "expected mid-stream abort before stall"
        );
        shutdown_a.cancel();

        // Case B: Image Index fits in limit, selects platform manifest, and platform manifest
        // overflows mid-stream without Content-Length.
        let (manifest_json, manifest_digest, _, _, _, _) = minimal_image_fixtures();
        let oversized_platform_manifest = format!("{}{}", " ".repeat(700), manifest_json);
        let platform_digest = sha256_digest(oversized_platform_manifest.as_bytes()).to_string();
        let index_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{platform_digest}","size":128,"platform":{{"architecture":"amd64","os":"linux"}}}}]}}"#
        );
        assert!(index_json.len() <= 512);
        let index_bytes = index_json.into_bytes();
        let platform_path = format!("/v2/test/app/manifests/{platform_digest}");
        let platform_path_check = platform_path.clone();

        let (port_b, shutdown_b) = spawn_raw_http_server(move |path, mut stream| {
            let index_bytes = index_bytes.clone();
            let platform_path = platform_path.clone();
            async move {
                if path == "/v2/" {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                        .await;
                } else if path == "/v2/test/app/manifests/v1" {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.oci.image.index.v1+json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                        index_bytes.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&index_bytes).await;
                    let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
                } else if path == platform_path {
                    let chunk = vec![b' '; 600];
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.oci.image.manifest.v1+json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                        chunk.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&chunk).await;
                    let _ = stream.write_all(b"\r\n").await;
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                }
            }
        })
        .await;

        let registry_b = format!("127.0.0.1:{port_b}");
        let reference_b: Reference = format!("{registry_b}/test/app:v1").parse().unwrap();
        let client_b = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry_b.clone()],
                registry_hosts: vec![registry_b],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                limits: ResourceLimits {
                    max_manifest_bytes: 512,
                    transfer_timeout: Duration::from_millis(500),
                    ..ResourceLimits::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        let started_b = std::time::Instant::now();
        let err_b = client_b.pull_base(&reference_b).await.unwrap_err();
        let msg_b = format!("{err_b:#}");
        assert!(
            msg_b.contains("exceeded") && (msg_b.contains("limit") || msg_b.contains("declared")),
            "expected platform manifest streaming limit error, got: {msg_b}"
        );
        assert!(started_b.elapsed() < Duration::from_millis(350));
        shutdown_b.cancel();

        // Case C: Image Index entry declares size > max_manifest_bytes -> rejected before requesting platform manifest.
        let index_oversized_entry = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":4096,"platform":{{"architecture":"amd64","os":"linux"}}}}]}}"#
        );
        let platform_requests = Arc::new(AtomicU64::new(0));
        let platform_requests_srv = platform_requests.clone();
        let index_srv = spawn_mock_server(false, move |req| {
            if req.path == "/v2/" {
                MockHttpResponse::json(200, "{}")
            } else if req.path == "/v2/test/app/manifests/v1" {
                MockHttpResponse::bytes(
                    200,
                    "application/vnd.oci.image.index.v1+json",
                    index_oversized_entry.as_bytes().to_vec(),
                )
            } else if req.path == platform_path_check
                || req.path == format!("/v2/test/app/manifests/{manifest_digest}")
            {
                platform_requests_srv.fetch_add(1, Ordering::Relaxed);
                MockHttpResponse::json(200, "{}")
            } else {
                MockHttpResponse::json(404, "{}")
            }
        })
        .await;

        let registry_c = format!("127.0.0.1:{}", index_srv.port);
        let reference_c: Reference = format!("{registry_c}/test/app:v1").parse().unwrap();
        let client_c = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![registry_c.clone()],
                registry_hosts: vec![registry_c],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                limits: ResourceLimits {
                    max_manifest_bytes: 512,
                    ..ResourceLimits::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();
        let err_c = client_c.pull_base(&reference_c).await.unwrap_err();
        assert!(format!("{err_c:#}").contains("exceeds limit"));
        assert_eq!(
            platform_requests.load(Ordering::Relaxed),
            0,
            "oversized index entry must be rejected before fetching platform manifest"
        );
    }

    #[tokio::test]
    async fn config_download_aborts_during_stream_and_rejects_lying_content_length() {
        use tokio::io::AsyncWriteExt;

        let (_, _, config_json, _, config_digest, layer_digest) = minimal_image_fixtures();
        let manifest_small_config = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":16}}]}}"#,
            config_json.len()
        );
        let manifest_small_digest = sha256_digest(manifest_small_config.as_bytes()).to_string();

        // Mode 0: chunked config without Content-Length exceeding limit mid-stream before delay.
        // Mode 1: lying Content-Length larger than declared config size and max_manifest_bytes.
        // Mode 2: lying Content-Length smaller than declared config size.
        let mode = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let mode_srv = mode.clone();
        let cfg_path = format!("/v2/test/app/blobs/{config_digest}");
        let (port, shutdown) = spawn_raw_http_server(move |path, mut stream| {
            let manifest_small_config = manifest_small_config.clone();
            let manifest_small_digest = manifest_small_digest.clone();
            let cfg_path = cfg_path.clone();
            let mode = mode_srv.load(Ordering::Relaxed);
            async move {
                if path == "/v2/" {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                        .await;
                } else if path == "/v2/test/app/manifests/v1" {
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.oci.image.manifest.v1+json\r\nDocker-Content-Digest: {manifest_small_digest}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        manifest_small_config.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(manifest_small_config.as_bytes()).await;
                } else if path == cfg_path {
                    match mode {
                        0 => {
                            let chunk = vec![b'C'; 400];
                            let head = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                                chunk.len()
                            );
                            let _ = stream.write_all(head.as_bytes()).await;
                            let _ = stream.write_all(&chunk).await;
                            let _ = stream.write_all(b"\r\n").await;
                            tokio::time::sleep(Duration::from_millis(1200)).await;
                        }
                        1 => {
                            let _ = stream
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999\r\nConnection: close\r\n\r\n{}")
                                .await;
                            tokio::time::sleep(Duration::from_millis(1200)).await;
                        }
                        _ => {
                            let _ = stream
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                                .await;
                        }
                    }
                }
            }
        })
        .await;

        let registry = format!("127.0.0.1:{port}");
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let make_client = || {
            RegistryClient::with_options(
                Credentials::default(),
                Platform::from_str("linux/amd64").unwrap(),
                RegistryOptions {
                    plain_http_hosts: vec![registry.clone()],
                    registry_hosts: vec![registry.clone()],
                    max_attempts: 1,
                    network_policy: NetworkPolicy {
                        allow_private_network: true,
                        ..NetworkPolicy::default()
                    },
                    limits: ResourceLimits {
                        max_manifest_bytes: 512,
                        transfer_timeout: Duration::from_millis(500),
                        ..ResourceLimits::default()
                    },
                    ..RegistryOptions::default()
                },
            )
            .unwrap()
        };

        // Mode 0: chunked overflow aborts immediately during stream without waiting for stall.
        let started = std::time::Instant::now();
        let err0 = format!(
            "{:#}",
            make_client().pull_base(&reference).await.unwrap_err()
        );
        assert!(
            err0.contains("exceeded") && (err0.contains("limit") || err0.contains("declared")),
            "expected streaming config limit error, got: {err0}"
        );
        assert!(started.elapsed() < Duration::from_millis(350));

        // Mode 1: lying oversized Content-Length aborts immediately before body stall.
        mode.store(1, Ordering::Relaxed);
        let started1 = std::time::Instant::now();
        let err1 = format!(
            "{:#}",
            make_client().pull_base(&reference).await.unwrap_err()
        );
        assert!(
            err1.contains("Content-Length") && err1.contains("exceeds"),
            "expected lying Content-Length rejection, got: {err1}"
        );
        assert!(started1.elapsed() < Duration::from_millis(350));

        // Mode 2: lying undersized Content-Length rejected before body parse.
        mode.store(2, Ordering::Relaxed);
        let err2 = format!(
            "{:#}",
            make_client().pull_base(&reference).await.unwrap_err()
        );
        assert!(
            err2.contains("Content-Length") && err2.contains("does not match"),
            "expected undersized Content-Length rejection, got: {err2}"
        );
        shutdown.cancel();

        // Pre-flight check: manifest declaring config.size > max_manifest_bytes never fetches config blob.
        let oversized_cfg_manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{config_digest}","size":2048}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{layer_digest}","size":16}}]}}"#,
        );
        let oversized_cfg_manifest_digest =
            sha256_digest(oversized_cfg_manifest.as_bytes()).to_string();
        let cfg_requests = Arc::new(AtomicU64::new(0));
        let cfg_requests_srv = cfg_requests.clone();
        let preflight_srv = spawn_mock_server(false, move |req| {
            if req.path == "/v2/" {
                MockHttpResponse::json(200, "{}")
            } else if req.path == "/v2/test/app/manifests/v1" {
                MockHttpResponse {
                    status: 200,
                    headers: vec![
                        (
                            "Content-Type".into(),
                            "application/vnd.oci.image.manifest.v1+json".into(),
                        ),
                        (
                            "Docker-Content-Digest".into(),
                            oversized_cfg_manifest_digest.clone(),
                        ),
                    ],
                    body: oversized_cfg_manifest.as_bytes().to_vec(),
                }
            } else if req.path.starts_with("/v2/test/app/blobs/") {
                cfg_requests_srv.fetch_add(1, Ordering::Relaxed);
                MockHttpResponse::bytes(200, "application/json", config_json.as_bytes().to_vec())
            } else {
                MockHttpResponse::json(404, "{}")
            }
        })
        .await;

        let preflight_reg = format!("127.0.0.1:{}", preflight_srv.port);
        let preflight_ref: Reference = format!("{preflight_reg}/test/app:v1").parse().unwrap();
        let preflight_client = RegistryClient::with_options(
            Credentials::default(),
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                plain_http_hosts: vec![preflight_reg.clone()],
                registry_hosts: vec![preflight_reg],
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                limits: ResourceLimits {
                    max_manifest_bytes: 512,
                    ..ResourceLimits::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();
        let preflight_err = format!(
            "{:#}",
            preflight_client
                .pull_base(&preflight_ref)
                .await
                .unwrap_err()
        );
        assert!(preflight_err.contains("exceeds limit"));
        assert_eq!(
            cfg_requests.load(Ordering::Relaxed),
            0,
            "oversized config descriptor must be rejected before fetching config blob"
        );
    }

    #[tokio::test]
    async fn oversized_manifest_fails_closed_without_publishing_archive_or_cache() {
        use crate::app::spec::{BuildRequest, CacheSpec, ImageBuildSpec, RegistryClientSpec};
        use crate::output_target::OutputTarget;
        use crate::progress::{Progress, ProgressMode};
        use tokio::io::AsyncWriteExt;

        let (port, shutdown) = spawn_raw_http_server(|path, mut stream| async move {
            match path.as_str() {
                "/v2/" => {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                        .await;
                }
                "/v2/test/app/manifests/v1" => {
                    let chunk = vec![b' '; 600];
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.oci.image.manifest.v1+json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                        chunk.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&chunk).await;
                    let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
                }
                _ => {}
            }
        })
        .await;

        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        let archive_path = dir.path().join("out.tar");
        let spec = ImageBuildSpec {
            from: format!("127.0.0.1:{port}/test/app:v1"),
            targets: vec![OutputTarget::OciArchive {
                path: archive_path.clone(),
                tag: None,
            }],
            local_only: true,
            copies: Vec::new(),
            copy_roots: Vec::new(),
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
            transport: RegistryClientSpec {
                source_plain_http: true,
                max_attempts: 1,
                ..RegistryClientSpec::default()
            },
            network_policy: NetworkPolicy {
                allow_private_network: true,
                ..NetworkPolicy::default()
            },
            limits: ResourceLimits {
                max_manifest_bytes: 256,
                ..ResourceLimits::default()
            },
            cache: CacheSpec {
                enable: true,
                cache_path: Some(cache_dir.clone()),
            },
        };

        let request = BuildRequest::try_from(spec).unwrap();
        let err = request
            .run(Credentials::default(), Progress::new(ProgressMode::Quiet))
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exceeded") && msg.contains("limit"),
            "got: {msg}"
        );
        assert!(!archive_path.exists(), "incomplete archive must not exist");
        assert!(
            !cache_dir.exists() || std::fs::read_dir(&cache_dir).unwrap().next().is_none(),
            "cache must remain empty on failed manifest pull"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn multi_platform_image_index_resolves_target_platform_within_limits() {
        let (manifest_json, manifest_digest, config_json, layer_bytes, config_digest, layer_digest) =
            minimal_image_fixtures();
        let arm_digest = format!("sha256:{}", "b".repeat(64));
        let index_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{arm_digest}","size":123,"platform":{{"architecture":"arm64","os":"linux"}}}},{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{manifest_digest}","size":{},"platform":{{"architecture":"amd64","os":"linux"}}}}]}}"#,
            manifest_json.len()
        );
        let index_digest = sha256_digest(index_json.as_bytes()).to_string();

        let port_holder = Arc::new(std::sync::atomic::AtomicU16::new(0));
        let port_ref = port_holder.clone();
        let manifest_path = format!("/v2/test/app/manifests/{manifest_digest}");
        let manifest_digest_srv = manifest_digest.clone();
        let server = spawn_mock_server(true, move |req| {
            let port = port_ref.load(Ordering::Relaxed);
            if req.path == "/v2/" {
                if !req.headers.contains_key("authorization") {
                    MockHttpResponse {
                        status: 401,
                        headers: vec![(
                            "WWW-Authenticate".into(),
                            format!(
                                r#"Bearer realm="https://127.0.0.1:{port}/token",service="reg""#
                            ),
                        )],
                        body: Vec::new(),
                    }
                } else {
                    MockHttpResponse::json(200, "{}")
                }
            } else if req.path.starts_with("/token") {
                MockHttpResponse::json(200, r#"{"token":"index-tok"}"#)
            } else if req.path == "/v2/test/app/manifests/v1" {
                MockHttpResponse {
                    status: 200,
                    headers: vec![
                        (
                            "Content-Type".into(),
                            "application/vnd.oci.image.index.v1+json".into(),
                        ),
                        ("Docker-Content-Digest".into(), index_digest.clone()),
                    ],
                    body: index_json.as_bytes().to_vec(),
                }
            } else if req.path == manifest_path {
                MockHttpResponse {
                    status: 200,
                    headers: vec![
                        (
                            "Content-Type".into(),
                            "application/vnd.oci.image.manifest.v1+json".into(),
                        ),
                        ("Docker-Content-Digest".into(), manifest_digest_srv.clone()),
                    ],
                    body: manifest_json.as_bytes().to_vec(),
                }
            } else if req.path == format!("/v2/test/app/blobs/{config_digest}") {
                MockHttpResponse::bytes(200, "application/json", config_json.as_bytes().to_vec())
            } else if req.path == format!("/v2/test/app/blobs/{layer_digest}") {
                MockHttpResponse::bytes(200, "application/octet-stream", layer_bytes.clone())
            } else {
                MockHttpResponse::json(404, "{}")
            }
        })
        .await;
        port_holder.store(server.port, Ordering::Relaxed);

        let registry = format!("127.0.0.1:{}", server.port);
        let creds = Credentials::load(&[format!("{registry}=alice:secret")], None).unwrap();
        let reference: Reference = format!("{registry}/test/app:v1").parse().unwrap();
        let client = RegistryClient::with_options(
            creds,
            Platform::from_str("linux/amd64").unwrap(),
            RegistryOptions {
                registry_hosts: vec![registry.clone()],
                skip_tls_verify: true,
                max_attempts: 1,
                network_policy: NetworkPolicy {
                    allowed_registries: vec![registry],
                    allow_private_network: true,
                    ..NetworkPolicy::default()
                },
                ..RegistryOptions::default()
            },
        )
        .unwrap();

        let image = client.pull_base(&reference).await.unwrap();
        assert_eq!(
            image.source.as_ref().unwrap().manifest_digest.as_ref(),
            manifest_digest
        );
        assert_eq!(image.layers.len(), 1);
    }
}
