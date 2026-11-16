//! Registry token exchange and auth destination enforcement.
//! Pre-exchanges Bearer tokens so `oci-client` never contacts unvalidated realms
//! or sends credentials across arbitrary redirects.

use std::sync::Arc;

use http_auth::parser::ChallengeParser;
use oci_client::Reference;
use oci_client::errors::{OciDistributionError, Result};
use oci_client::secrets::RegistryAuth;
use reqwest::header::{HeaderMap, WWW_AUTHENTICATE};
use reqwest::{StatusCode, Url};
use serde::Deserialize;

use super::RegistryOptions;
use super::net_policy::{NetworkPolicy, PolicyDnsResolver};

const MAX_TOKEN_RESPONSE_BYTES: usize = 1024 * 1024;

struct BearerChallenge {
    realm: String,
    service: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

#[derive(Clone)]
pub(super) struct TokenClient {
    http: reqwest::Client,
    plain_http_hosts: Vec<String>,
    network_policy: NetworkPolicy,
}

impl TokenClient {
    pub(super) fn new(options: &RegistryOptions) -> Result<Self> {
        let resolver = Arc::new(PolicyDnsResolver::new(
            options.network_policy.allow_private_network,
        ));
        Ok(Self {
            http: reqwest::Client::builder()
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
                .build()?,
            plain_http_hosts: options.plain_http_hosts.clone(),
            network_policy: options.network_policy.clone(),
        })
    }

    /// Resolve an authentication token for a single repository operation,
    /// enforcing auth-host and SSRF policies before sending any credentials.
    pub(super) async fn resolve_auth(
        &self,
        reference: &Reference,
        auth: &RegistryAuth,
        is_push: bool,
    ) -> Result<RegistryAuth> {
        let scope = if is_push {
            format!("repository:{}:pull,push", reference.repository())
        } else {
            format!("repository:{}:pull", reference.repository())
        };
        self.resolve_scopes(reference, &[("scope", scope)], auth, true)
            .await
    }

    /// Obtain a token covering target pull/push and source pull in the same
    /// registry. Preserve the supplied auth when no bearer exchange is needed.
    pub(super) async fn auth_for_mount(
        &self,
        target: &Reference,
        source: &Reference,
        auth: &RegistryAuth,
    ) -> Result<RegistryAuth> {
        let mut scopes = vec![(
            "scope",
            format!("repository:{}:pull,push", target.repository()),
        )];
        if source.repository() != target.repository() {
            scopes.push(("scope", format!("repository:{}:pull", source.repository())));
        }
        self.resolve_scopes(target, &scopes, auth, false).await
    }

    async fn resolve_scopes(
        &self,
        target: &Reference,
        scopes: &[(&str, String)],
        auth: &RegistryAuth,
        allow_subset_not_found: bool,
    ) -> Result<RegistryAuth> {
        let registry = target.resolve_registry();
        self.network_policy
            .check_registry_host(registry)
            .map_err(|error| OciDistributionError::AuthenticationFailure(error.to_string()))?;

        if matches!(auth, RegistryAuth::Bearer(_)) {
            return Ok(auth.clone());
        }

        let allow_plain_http = self.plain_http_hosts.iter().any(|host| host == registry);
        let scheme = if allow_plain_http { "http" } else { "https" };
        let base = format!("{scheme}://{registry}/v2/");
        let base_url = Url::parse(&base)
            .map_err(|error| OciDistributionError::UrlParseError(error.to_string()))?;

        let discovery = self.http.get(&base).send().await?;
        if discovery.status() == StatusCode::NOT_FOUND
            && allow_subset_not_found
            && matches!(auth, RegistryAuth::Anonymous)
        {
            // Minimal read-only OCI/registry subsets may not implement GET /v2/ for anonymous pulls.
            return Ok(RegistryAuth::Anonymous);
        }
        if discovery.status().is_redirection() {
            return Err(OciDistributionError::AuthenticationFailure(
                "registry /v2/ discovery returned an unexpected redirect".into(),
            ));
        }
        if discovery.status() != StatusCode::UNAUTHORIZED {
            discovery.error_for_status_ref()?;
        }

        let Some(challenge) = bearer_challenge(discovery.headers())? else {
            if matches!(auth, RegistryAuth::Basic(..)) {
                self.network_policy
                    .check_auth_destination(registry, &base_url, allow_plain_http)
                    .map_err(|error| {
                        OciDistributionError::AuthenticationFailure(error.to_string())
                    })?;
            }
            return Ok(auth.clone());
        };

        let realm = Url::parse(&challenge.realm)
            .map_err(|error| OciDistributionError::UrlParseError(error.to_string()))?;
        self.network_policy
            .check_auth_destination(registry, &realm, allow_plain_http)
            .map_err(|error| OciDistributionError::AuthenticationFailure(error.to_string()))?;

        let mut query: Vec<(&str, String)> = scopes.to_vec();
        if let Some(service) = challenge.service {
            query.push(("service", service));
        }

        let request = self.http.get(realm).query(&query);
        let request = match auth {
            RegistryAuth::Basic(username, password) => request.basic_auth(username, Some(password)),
            _ => request,
        };
        let mut response = request.send().await?;
        if response.status() != StatusCode::OK {
            // Do not include token endpoint bodies in errors:
            // servers may echo credentials or tokens in them.
            return Err(OciDistributionError::ServerError {
                code: response.status().as_u16(),
                url: base,
                message: "registry token request failed".into(),
            });
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_TOKEN_RESPONSE_BYTES as u64)
        {
            return Err(OciDistributionError::AuthenticationFailure(
                "registry token response exceeded maximum allowed size".into(),
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len().saturating_add(chunk.len()) > MAX_TOKEN_RESPONSE_BYTES {
                return Err(OciDistributionError::AuthenticationFailure(
                    "registry token response exceeded maximum allowed size".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let token: TokenResponse = serde_json::from_slice(&body)
            .map_err(|error| OciDistributionError::RegistryTokenDecodeError(error.to_string()))?;
        let token = token
            .token
            .filter(|token| !token.is_empty())
            .or_else(|| token.access_token.filter(|token| !token.is_empty()))
            .ok_or_else(|| {
                OciDistributionError::AuthenticationFailure(
                    "registry token response contained no token".into(),
                )
            })?;
        Ok(RegistryAuth::Bearer(token))
    }
}

fn bearer_challenge(headers: &HeaderMap) -> Result<Option<BearerChallenge>> {
    for header in headers.get_all(WWW_AUTHENTICATE) {
        for challenge in ChallengeParser::new(header.to_str()?) {
            let challenge = challenge
                .map_err(|error| OciDistributionError::AuthenticationFailure(error.to_string()))?;
            if !challenge.scheme.eq_ignore_ascii_case("bearer") {
                continue;
            }
            let mut realm = None;
            let mut service = None;
            for (key, value) in &challenge.params {
                if key.eq_ignore_ascii_case("realm") {
                    realm = Some(value.to_unescaped());
                } else if key.eq_ignore_ascii_case("service") {
                    service = Some(value.to_unescaped());
                }
            }
            return Ok(Some(BearerChallenge {
                realm: realm.ok_or_else(|| {
                    OciDistributionError::AuthenticationFailure(
                        "registry bearer challenge is missing its realm".into(),
                    )
                })?,
                service,
            }));
        }
    }
    Ok(None)
}
