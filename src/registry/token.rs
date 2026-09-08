//! Registry token exchange for operations requiring access to two repositories.
//! oci-client 0.17 can only request a token scoped to a single repository.

use http_auth::parser::ChallengeParser;
use oci_client::Reference;
use oci_client::errors::{OciDistributionError, Result};
use oci_client::secrets::RegistryAuth;
use reqwest::header::{HeaderMap, WWW_AUTHENTICATE};
use reqwest::{StatusCode, Url};
use serde::Deserialize;

use super::RegistryOptions;

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
}

impl TokenClient {
    pub(super) fn new(options: &RegistryOptions) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .danger_accept_invalid_certs(options.skip_tls_verify)
                .connect_timeout(options.connect_timeout)
                .read_timeout(options.read_timeout)
                .user_agent(concat!(
                    env!("CARGO_PKG_NAME"),
                    "/",
                    env!("CARGO_PKG_VERSION")
                ))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            plain_http_hosts: options.plain_http_hosts.clone(),
        })
    }

    /// Obtain a token covering target pull/push and source pull in the same
    /// registry. Preserve the supplied auth when no bearer exchange is needed.
    pub(super) async fn auth_for_mount(
        &self,
        target: &Reference,
        source: &Reference,
        auth: &RegistryAuth,
    ) -> Result<RegistryAuth> {
        if matches!(auth, RegistryAuth::Bearer(_)) {
            return Ok(auth.clone());
        }
        let registry = target.resolve_registry();
        let scheme = if self.plain_http_hosts.iter().any(|host| host == registry) {
            "http"
        } else {
            "https"
        };
        let base = format!("{scheme}://{registry}/v2/");
        let discovery = self.http.get(&base).send().await?;
        if discovery.status() != StatusCode::UNAUTHORIZED {
            discovery.error_for_status_ref()?;
        }
        let Some(challenge) = bearer_challenge(discovery.headers())? else {
            // Let oci-client handle Basic/anonymous registry authentication.
            return Ok(auth.clone());
        };
        let realm = Url::parse(&challenge.realm)
            .map_err(|error| OciDistributionError::UrlParseError(error.to_string()))?;
        // Allow local HTTP registries, but never downgrade the
        // credentials of an HTTPS registry to a plaintext realm.
        if realm.scheme() != "https" && !(scheme == "http" && realm.scheme() == "http") {
            return Err(OciDistributionError::AuthenticationFailure(
                "insecure registry token realm".into(),
            ));
        }
        let mut scopes = vec![(
            "scope",
            format!("repository:{}:pull,push", target.repository()),
        )];
        if source.repository() != target.repository() {
            scopes.push(("scope", format!("repository:{}:pull", source.repository())));
        }
        if let Some(service) = challenge.service {
            scopes.push(("service", service));
        }
        let request = self.http.get(realm).query(&scopes);
        let request = match auth {
            RegistryAuth::Basic(username, password) => request.basic_auth(username, Some(password)),
            _ => request,
        };
        let response = request.send().await?;
        if response.status() != StatusCode::OK {
            // Do not include token endpoint bodies in errors:
            // servers may echo credentials or tokens in them.
            return Err(OciDistributionError::ServerError {
                code: response.status().as_u16(),
                url: base.clone(),
                message: "registry mount token request failed".into(),
            });
        }
        let token: TokenResponse = response.json().await?;
        let token = token
            .token
            .filter(|token| !token.is_empty())
            .or_else(|| token.access_token.filter(|token| !token.is_empty()))
            .ok_or_else(|| {
                OciDistributionError::AuthenticationFailure(
                    "registry mount token response contained no token".into(),
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
