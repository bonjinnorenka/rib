//! Network destination policy, SSRF protection, DNS validation, and local validating proxy.

use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::Url;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::debug;

const MAX_PROXY_HEAD_BYTES: usize = 64 * 1024;
const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Controls which remote registries, auth servers, blob hosts, and IP ranges
/// `rib` is permitted to connect to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkPolicy {
    /// If non-empty, source and target registry hosts must match an entry here.
    pub allowed_registries: Vec<String>,
    /// If non-empty, only matching hosts may receive credentials (Basic auth or
    /// Bearer token exchange). When empty, defaults to the registry host itself
    /// plus well-known public registry auth hosts over HTTPS.
    pub allowed_auth_hosts: Vec<String>,
    /// If non-empty, permits external descriptor `urls` from matching hosts and
    /// restricts CDN/redirect hosts to `allowed_registries` / registry hosts +
    /// `allowed_blob_hosts` + `allowed_auth_hosts`.
    pub allowed_blob_hosts: Vec<String>,
    /// Allow loopback and RFC1918/ULA private IPs (for local test registries).
    /// Link-local and cloud metadata addresses remain blocked regardless.
    pub allow_private_network: bool,
}

impl NetworkPolicy {
    pub fn validate(&self) -> Result<()> {
        for (flag, list) in [
            ("--allow-registry", &self.allowed_registries),
            ("--allow-auth-host", &self.allowed_auth_hosts),
            ("--allow-blob-host", &self.allowed_blob_hosts),
        ] {
            for pattern in list {
                validate_host_pattern(pattern)
                    .with_context(|| format!("invalid {flag} entry {pattern:?}"))?;
            }
        }
        Ok(())
    }

    pub fn check_registry_host(&self, registry: &str) -> Result<()> {
        let (host, port) = parse_host_port(registry, 443)?;
        check_blocked_hostname(&host, self.allow_private_network)?;
        if let Ok(ip) = strip_ipv6_brackets(&host).parse::<IpAddr>() {
            check_ip(ip, self.allow_private_network)
                .with_context(|| format!("registry host {registry:?} uses blocked IP {ip}"))?;
        }
        if !self.allowed_registries.is_empty()
            && !matches_any_host_pattern(&self.allowed_registries, &host, Some(port), 443)
        {
            bail!(
                "registry {registry:?} is not allowed by --allow-registry ({})",
                self.allowed_registries.join(", ")
            );
        }
        Ok(())
    }

    /// Validate whether credentials may be sent to `url` when authenticating for `registry`.
    pub fn check_auth_destination(
        &self,
        registry: &str,
        url: &Url,
        allow_plain_http_for_registry: bool,
    ) -> Result<()> {
        if !url.username().is_empty() || url.password().is_some() {
            bail!("authentication URL must not embed credentials");
        }
        let scheme = url.scheme();
        if scheme != "https" && !(allow_plain_http_for_registry && scheme == "http") {
            bail!("insecure authentication URL scheme {scheme:?}");
        }
        let target_host = url
            .host_str()
            .ok_or_else(|| anyhow!("authentication URL has no host"))?;
        let default_port = if scheme == "http" { 80 } else { 443 };
        let target_port = url.port().unwrap_or(default_port);

        check_blocked_hostname(target_host, self.allow_private_network)?;
        if let Ok(ip) = strip_ipv6_brackets(target_host).parse::<IpAddr>() {
            check_ip(ip, self.allow_private_network).with_context(|| {
                format!("authentication URL host {target_host:?} uses blocked IP {ip}")
            })?;
        }

        if !self.allowed_auth_hosts.is_empty() {
            if !matches_any_host_pattern(
                &self.allowed_auth_hosts,
                target_host,
                Some(target_port),
                default_port,
            ) {
                bail!(
                    "authentication destination {target_host}:{target_port} is not allowed by --allow-auth-host"
                );
            }
            return Ok(());
        }

        let (reg_host, reg_port) = parse_host_port(registry, default_port)?;
        if normalize_host_eq(&reg_host, target_host) && reg_port == target_port {
            return Ok(());
        }

        if scheme == "https" && target_port == 443 && is_builtin_auth_host(&reg_host, target_host) {
            return Ok(());
        }

        bail!(
            "refusing to send credentials for registry {registry:?} to untrusted auth host {target_host:?}; pass --allow-auth-host {target_host} if intentional"
        );
    }

    /// Validate whether an external `descriptor.urls` entry may be fetched.
    pub fn check_external_blob_url(&self, url: &Url, plain_http_hosts: &[String]) -> Result<()> {
        if self.allowed_blob_hosts.is_empty() {
            bail!("external descriptor blob URLs are disabled unless --allow-blob-host is set");
        }
        if !url.username().is_empty() || url.password().is_some() {
            bail!("blob URL must not embed credentials");
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("blob URL has no host"))?;
        let scheme = url.scheme();
        let default_port = match scheme {
            "https" => 443,
            "http" => {
                let port = url.port().unwrap_or(80);
                if !host_matches_list(plain_http_hosts, host, port, 80) {
                    bail!("plain HTTP blob URL to {host:?} is not permitted");
                }
                80
            }
            other => bail!("unsupported blob URL scheme {other:?}"),
        };
        let port = url.port().unwrap_or(default_port);

        check_blocked_hostname(host, self.allow_private_network)?;
        if let Ok(ip) = strip_ipv6_brackets(host).parse::<IpAddr>() {
            check_ip(ip, self.allow_private_network)
                .with_context(|| format!("blob URL host {host:?} uses blocked IP {ip}"))?;
        }
        if !matches_any_host_pattern(&self.allowed_blob_hosts, host, Some(port), default_port) {
            bail!("blob URL host {host:?} is not allowed by --allow-blob-host");
        }
        Ok(())
    }

    /// Validate a proxied TCP/HTTP connection from `oci-client`.
    fn check_proxy_target(
        &self,
        host: &str,
        port: u16,
        is_plain_http: bool,
        plain_http_hosts: &[String],
        registry_hosts: &[String],
    ) -> Result<()> {
        if is_plain_http && !host_matches_list(plain_http_hosts, host, port, 80) {
            bail!("plain HTTP connection to {host}:{port} is not permitted");
        }
        check_blocked_hostname(host, self.allow_private_network)?;
        if let Ok(ip) = strip_ipv6_brackets(host).parse::<IpAddr>() {
            check_ip(ip, self.allow_private_network)
                .with_context(|| format!("target {host}:{port} uses blocked IP {ip}"))?;
        }
        let default_port = if is_plain_http { 80 } else { 443 };
        if !self.allowed_blob_hosts.is_empty() {
            let allowed =
                matches_any_host_pattern(&self.allowed_blob_hosts, host, Some(port), default_port)
                    || matches_any_host_pattern(
                        &self.allowed_registries,
                        host,
                        Some(port),
                        default_port,
                    )
                    || matches_any_host_pattern(
                        &self.allowed_auth_hosts,
                        host,
                        Some(port),
                        default_port,
                    )
                    || host_matches_list(registry_hosts, host, port, default_port);
            if !allowed {
                bail!("outbound target {host}:{port} is not in allowed registry/blob hosts");
            }
        }
        Ok(())
    }
}

fn is_builtin_auth_host(registry_host: &str, auth_host: &str) -> bool {
    let reg = normalize_registry_alias(registry_host);
    let auth = auth_host.to_ascii_lowercase();
    match reg.as_str() {
        "registry-1.docker.io" => auth == "auth.docker.io",
        "registry.gitlab.com" => auth == "gitlab.com",
        _ => false,
    }
}

fn normalize_registry_alias(host: &str) -> String {
    let lower = host.trim_end_matches('.').to_ascii_lowercase();
    match lower.as_str() {
        "docker.io" | "index.docker.io" | "registry-1.docker.io" => {
            "registry-1.docker.io".to_string()
        }
        _ => lower,
    }
}

fn normalize_host_eq(a: &str, b: &str) -> bool {
    strip_ipv6_brackets(a)
        .trim_end_matches('.')
        .eq_ignore_ascii_case(strip_ipv6_brackets(b).trim_end_matches('.'))
}

fn strip_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

fn parse_host_port(value: &str, default_port: u16) -> Result<(String, u16)> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.contains("://") || trimmed.contains('/') {
        bail!("invalid registry host {value:?}");
    }
    if trimmed.starts_with('[') {
        if let Some(end) = trimmed.find(']') {
            let host = &trimmed[1..end];
            let rest = &trimmed[end + 1..];
            if rest.is_empty() {
                return Ok((host.to_string(), default_port));
            }
            if let Some(port_str) = rest.strip_prefix(':') {
                let port: u16 = port_str
                    .parse()
                    .with_context(|| format!("invalid port in {value:?}"))?;
                return Ok((host.to_string(), port));
            }
        }
        bail!("invalid IPv6 host {value:?}");
    }
    if let Some((host, port_str)) = trimmed.rsplit_once(':')
        && !host.contains(':')
    {
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid port in {value:?}"))?;
        return Ok((host.to_string(), port));
    }
    Ok((trimmed.to_string(), default_port))
}

fn validate_host_pattern(pattern: &str) -> Result<()> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        bail!("host pattern cannot be empty");
    }
    if trimmed.contains("://") || trimmed.contains('/') || trimmed.contains('@') {
        bail!("host pattern must be a hostname or host:port, not a URL");
    }
    let (host_part, _port) = if let Some(rest) = trimmed.strip_prefix("*.") {
        if rest.is_empty() || rest.contains('*') {
            bail!("invalid wildcard host pattern");
        }
        let (h, p) = parse_host_port(rest, 443)?;
        if h.split('.').filter(|seg| !seg.is_empty()).count() < 2 {
            bail!("wildcard pattern must include at least two domain labels after '*.'");
        }
        (h, p)
    } else {
        if trimmed.contains('*') {
            bail!("wildcards are only supported as a leading '*.' prefix");
        }
        parse_host_port(trimmed, 443)?
    };
    if host_part.is_empty() {
        bail!("host cannot be empty");
    }
    Ok(())
}

fn matches_any_host_pattern(
    patterns: &[String],
    host: &str,
    port: Option<u16>,
    default_port: u16,
) -> bool {
    patterns
        .iter()
        .any(|pattern| host_pattern_matches(pattern, host, port, default_port))
}

fn host_pattern_matches(pattern: &str, host: &str, port: Option<u16>, default_port: u16) -> bool {
    let trimmed = pattern.trim();
    let effective_port = port.unwrap_or(default_port);

    if let Some(rest) = trimmed.strip_prefix("*.") {
        let Ok((pat_host, pat_port)) = parse_host_port(rest, default_port) else {
            return false;
        };
        if trimmed.contains(':') && pat_port != effective_port {
            return false;
        }
        let host_norm = strip_ipv6_brackets(host)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let pat_norm = pat_host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(prefix) = host_norm.strip_suffix(&format!(".{pat_norm}")) {
            return !prefix.is_empty();
        }
        return false;
    }

    let Ok((pat_host, pat_port)) = parse_host_port(trimmed, default_port) else {
        return false;
    };
    let has_explicit_port = if trimmed.starts_with('[') {
        trimmed.contains("]:")
    } else {
        trimmed.matches(':').count() == 1
    };
    if has_explicit_port && pat_port != effective_port {
        return false;
    }
    normalize_host_eq(&pat_host, host)
        || normalize_registry_alias(&pat_host) == normalize_registry_alias(host)
}

fn host_matches_list(list: &[String], host: &str, port: u16, default_port: u16) -> bool {
    list.iter()
        .any(|entry| host_pattern_matches(entry, host, Some(port), default_port))
}

pub fn check_blocked_hostname(host: &str, allow_private_network: bool) -> Result<()> {
    let normalized = strip_ipv6_brackets(host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if normalized.is_empty() {
        bail!("empty hostname is not allowed");
    }
    if matches!(
        normalized.as_str(),
        "metadata.google.internal" | "metadata.goog" | "metadata" | "instance-data"
    ) || normalized.ends_with(".metadata.google.internal")
    {
        bail!("access to cloud metadata hostname {host:?} is forbidden");
    }
    if !allow_private_network && (normalized == "localhost" || normalized.ends_with(".localhost")) {
        bail!("access to localhost {host:?} is forbidden (pass --allow-private-network to allow)");
    }
    Ok(())
}

pub fn check_ip(ip: IpAddr, allow_private_network: bool) -> Result<()> {
    match ip {
        IpAddr::V4(v4) => check_ipv4(v4, allow_private_network),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return check_ipv4(mapped, allow_private_network);
            }
            if let Some(compat) = v6.to_ipv4() {
                // `::127.0.0.1` etc. (excluding `::` and `::1` handled below)
                if !v6.is_unspecified() && !v6.is_loopback() {
                    return check_ipv4(compat, allow_private_network);
                }
            }
            check_ipv6(v6, allow_private_network)
        }
    }
}

fn check_ipv4(v4: Ipv4Addr, allow_private_network: bool) -> Result<()> {
    let octets = v4.octets();
    // Always block unspecified (0.0.0.0/8), link-local / cloud metadata (169.254.0.0/16),
    // multicast (224.0.0.0/4), and reserved/broadcast (240.0.0.0/4).
    if octets[0] == 0 {
        bail!("unspecified IPv4 address {v4} is forbidden");
    }
    if v4.is_link_local() {
        bail!("link-local/metadata IPv4 address {v4} is forbidden");
    }
    if v4.is_multicast() || octets[0] >= 240 {
        bail!("multicast/reserved IPv4 address {v4} is forbidden");
    }
    if !allow_private_network {
        if v4.is_loopback() {
            bail!(
                "loopback IPv4 address {v4} is forbidden (pass --allow-private-network to allow)"
            );
        }
        if v4.is_private() {
            bail!("private IPv4 address {v4} is forbidden (pass --allow-private-network to allow)");
        }
        // RFC 6598 CGNAT 100.64.0.0/10
        if octets[0] == 100 && (64..=127).contains(&octets[1]) {
            bail!("shared/CGNAT IPv4 address {v4} is forbidden");
        }
        // Benchmarking 198.18.0.0/15, documentation TEST-NETs, IETF protocol assignments
        if (octets[0] == 192 && octets[1] == 0 && (octets[2] == 0 || octets[2] == 2))
            || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        {
            bail!("non-public IPv4 address {v4} is forbidden");
        }
    }
    Ok(())
}

fn check_ipv6(v6: Ipv6Addr, allow_private_network: bool) -> Result<()> {
    let segments = v6.segments();
    if v6.is_unspecified() {
        bail!("unspecified IPv6 address {v6} is forbidden");
    }
    if v6.is_multicast() {
        bail!("multicast IPv6 address {v6} is forbidden");
    }
    // fe80::/10 link-local
    if (segments[0] & 0xffc0) == 0xfe80 {
        bail!("link-local IPv6 address {v6} is forbidden");
    }
    // 100::/64 discard-only, 2001:db8::/32 documentation
    if (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
    {
        bail!("reserved IPv6 address {v6} is forbidden");
    }
    // AWS IPv6 metadata fd00:ec2::254 is always forbidden even when private networks are allowed
    if segments == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254] {
        bail!("cloud metadata IPv6 address {v6} is forbidden");
    }
    if !allow_private_network {
        if v6.is_loopback() {
            bail!(
                "loopback IPv6 address {v6} is forbidden (pass --allow-private-network to allow)"
            );
        }
        // fc00::/7 Unique Local Addresses
        if (segments[0] & 0xfe00) == 0xfc00 {
            bail!(
                "private ULA IPv6 address {v6} is forbidden (pass --allow-private-network to allow)"
            );
        }
    }
    Ok(())
}

pub async fn resolve_and_validate(
    host: &str,
    port: u16,
    allow_private_network: bool,
) -> Result<Vec<SocketAddr>> {
    check_blocked_hostname(host, allow_private_network)?;
    let clean_host = strip_ipv6_brackets(host);
    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        check_ip(ip, allow_private_network)?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((clean_host, port))
        .await
        .with_context(|| format!("resolving {clean_host}:{port}"))?
        .collect();
    if resolved.is_empty() {
        bail!("DNS resolution for {clean_host}:{port} returned no addresses");
    }
    for addr in &resolved {
        check_ip(addr.ip(), allow_private_network).with_context(|| {
            format!(
                "DNS resolution for {clean_host} returned blocked IP {}",
                addr.ip()
            )
        })?;
    }
    Ok(resolved)
}

/// Reqwest DNS resolver that validates every resolved address against [`NetworkPolicy`].
#[derive(Clone)]
pub struct PolicyDnsResolver {
    allow_private_network: bool,
}

impl PolicyDnsResolver {
    pub fn new(allow_private_network: bool) -> Self {
        Self {
            allow_private_network,
        }
    }
}

impl Resolve for PolicyDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow_private = self.allow_private_network;
        Box::pin(async move {
            let addrs = resolve_and_validate(name.as_str(), 0, allow_private)
                .await
                .map_err(|error| {
                    Box::new(std::io::Error::other(error))
                        as Box<dyn std::error::Error + Send + Sync>
                })?;
            let iter: Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
            as Pin<
                Box<
                    dyn Future<
                            Output = std::result::Result<
                                Addrs,
                                Box<dyn std::error::Error + Send + Sync>,
                            >,
                        > + Send,
                >,
            >
    }
}

/// Loopback proxy used to enforce DNS/IP/redirect/HTTP-downgrade validation on `oci-client`.
pub struct ValidatingProxy {
    addr: SocketAddr,
    shutdown: CancellationToken,
}

impl ValidatingProxy {
    pub fn start(
        policy: NetworkPolicy,
        plain_http_hosts: Vec<String>,
        registry_hosts: Vec<String>,
        connect_timeout: Duration,
    ) -> Result<Self> {
        let std_listener =
            std::net::TcpListener::bind("127.0.0.1:0").context("binding local validating proxy")?;
        std_listener
            .set_nonblocking(true)
            .context("setting proxy listener nonblocking")?;
        let addr = std_listener
            .local_addr()
            .context("reading proxy local address")?;
        let listener =
            TcpListener::from_std(std_listener).context("converting proxy listener to tokio")?;
        let shutdown = CancellationToken::new();
        let state = Arc::new(ProxyState {
            policy,
            plain_http_hosts,
            registry_hosts,
            connect_timeout,
        });
        let task_shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _peer)) = accepted else {
                            break;
                        };
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(error) = handle_proxy_client(stream, state).await {
                                debug!(%error, "validating proxy rejected or closed connection");
                            }
                        });
                    }
                }
            }
        });
        Ok(Self { addr, shutdown })
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for ValidatingProxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

struct ProxyState {
    policy: NetworkPolicy,
    plain_http_hosts: Vec<String>,
    registry_hosts: Vec<String>,
    connect_timeout: Duration,
}

async fn handle_proxy_client(client_stream: TcpStream, state: Arc<ProxyState>) -> Result<()> {
    let mut reader = BufReader::new(client_stream);
    let head = tokio::time::timeout(PROXY_HANDSHAKE_TIMEOUT, read_http_head(&mut reader))
        .await
        .context("proxy request timed out")??;
    if head.is_empty() {
        return Ok(());
    }

    let head_str = std::str::from_utf8(&head).context("non-UTF-8 proxy request head")?;
    let mut lines = head_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("empty proxy request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(|| anyhow!("missing HTTP method"))?;
    let target = parts.next().ok_or_else(|| anyhow!("missing HTTP target"))?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(target, 443)?;
        if let Err(error) = state.policy.check_proxy_target(
            &host,
            port,
            false,
            &state.plain_http_hosts,
            &state.registry_hosts,
        ) {
            send_forbidden(reader.get_mut(), &error).await;
            return Err(error);
        }
        let addrs =
            match resolve_and_validate(&host, port, state.policy.allow_private_network).await {
                Ok(addrs) => addrs,
                Err(error) => {
                    send_forbidden(reader.get_mut(), &error).await;
                    return Err(error);
                }
            };
        let mut upstream = connect_validated(&addrs, state.connect_timeout).await?;
        let mut client = reader.into_inner();
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        return Ok(());
    }

    // Plain HTTP proxy request (only allowed for explicitly configured plain_http_hosts).
    let parsed = match Url::parse(target) {
        Ok(url) if url.scheme() == "http" => url,
        Ok(url) => {
            let err = anyhow!("disallowed proxy URL scheme {:?}", url.scheme());
            send_forbidden(reader.get_mut(), &err).await;
            return Err(err);
        }
        Err(error) => {
            let err = anyhow!("invalid proxy URL {target:?}: {error}");
            send_forbidden(reader.get_mut(), &err).await;
            return Err(err);
        }
    };
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("proxy URL has no host"))?;
    let port = parsed.port().unwrap_or(80);
    if let Err(error) = state.policy.check_proxy_target(
        host,
        port,
        true,
        &state.plain_http_hosts,
        &state.registry_hosts,
    ) {
        send_forbidden(reader.get_mut(), &error).await;
        return Err(error);
    }
    let addrs = match resolve_and_validate(host, port, state.policy.allow_private_network).await {
        Ok(addrs) => addrs,
        Err(error) => {
            send_forbidden(reader.get_mut(), &error).await;
            return Err(error);
        }
    };
    let mut upstream = connect_validated(&addrs, state.connect_timeout).await?;

    let path_and_query = match parsed.query() {
        Some(q) => format!("{}?{q}", parsed.path()),
        None => parsed.path().to_string(),
    };
    let mut rewritten = format!("{method} {path_and_query} {version}\r\n");
    let mut seen_host = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("proxy-connection")
                || name.eq_ignore_ascii_case("connection")
            {
                continue;
            }
            if name.eq_ignore_ascii_case("host") {
                seen_host = true;
            }
        }
        rewritten.push_str(line);
        rewritten.push_str("\r\n");
    }
    if !seen_host {
        if parsed.port().is_some() {
            rewritten.push_str(&format!("Host: {host}:{port}\r\n"));
        } else {
            rewritten.push_str(&format!("Host: {host}\r\n"));
        }
    }
    // Force Connection: close so reqwest never reuses a proxy socket across redirect hosts.
    rewritten.push_str("Connection: close\r\n\r\n");
    upstream.write_all(rewritten.as_bytes()).await?;
    let buffered = reader.buffer();
    if !buffered.is_empty() {
        upstream.write_all(buffered).await?;
    }
    let mut client = reader.into_inner();
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

async fn read_http_head(reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let read = reader
            .take((MAX_PROXY_HEAD_BYTES - head.len()) as u64)
            .read_until(b'\n', &mut line)
            .await?;
        if read == 0 {
            return Ok(head);
        }
        head.extend_from_slice(&line);
        if head.len() >= MAX_PROXY_HEAD_BYTES {
            bail!("proxy request headers exceed {MAX_PROXY_HEAD_BYTES} bytes");
        }
        if line == b"\r\n" || line == b"\n" {
            return Ok(head);
        }
    }
}

async fn connect_validated(addrs: &[SocketAddr], connect_timeout: Duration) -> Result<TcpStream> {
    let mut last_error = None;
    for addr in addrs {
        match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => last_error = Some(anyhow!("connect {addr}: {err}")),
            Err(_) => last_error = Some(anyhow!("connect {addr} timed out")),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("no validated addresses to connect")))
}

async fn send_forbidden(stream: &mut TcpStream, error: &anyhow::Error) {
    let body = format!("blocked by rib network policy: {error}");
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Helper to dedupe and collect host strings from a list of hosts.
pub fn unique_hosts(hosts: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for host in hosts {
        let key = host.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(host);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_policy_blocks_localhost_private_link_local_and_metadata_by_default() {
        for ip in [
            "127.0.0.1",
            "127.0.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(
                check_ip(parsed, false).is_err(),
                "expected {ip} to be blocked when allow_private_network=false"
            );
        }
    }

    #[test]
    fn ip_policy_allows_public_ips_and_keeps_metadata_blocked_even_with_allow_private() {
        for public in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(check_ip(public.parse().unwrap(), false).is_ok());
        }
        assert!(check_ip("127.0.0.1".parse().unwrap(), true).is_ok());
        assert!(check_ip("10.0.0.1".parse().unwrap(), true).is_ok());
        assert!(check_ip("::1".parse().unwrap(), true).is_ok());

        for always_blocked in [
            "169.254.169.254",
            "169.254.0.1",
            "::ffff:169.254.169.254",
            "fe80::1",
            "fd00:ec2::254",
            "0.0.0.0",
        ] {
            assert!(
                check_ip(always_blocked.parse().unwrap(), true).is_err(),
                "expected {always_blocked} to remain blocked even when allow_private_network=true"
            );
        }
    }

    #[test]
    fn hostname_policy_blocks_metadata_and_localhost() {
        assert!(check_blocked_hostname("metadata.google.internal", false).is_err());
        assert!(check_blocked_hostname("metadata.google.internal.", true).is_err());
        assert!(check_blocked_hostname("metadata", true).is_err());
        assert!(check_blocked_hostname("localhost", false).is_err());
        assert!(check_blocked_hostname("sub.localhost", false).is_err());
        assert!(check_blocked_hostname("localhost", true).is_ok());
    }

    #[test]
    fn auth_destination_policy_allows_same_host_and_builtin_and_blocks_arbitrary_realms() {
        let policy = NetworkPolicy::default();
        assert!(
            policy
                .check_auth_destination(
                    "ghcr.io",
                    &Url::parse("https://ghcr.io/token").unwrap(),
                    false
                )
                .is_ok()
        );
        assert!(
            policy
                .check_auth_destination(
                    "registry-1.docker.io",
                    &Url::parse("https://auth.docker.io/token").unwrap(),
                    false
                )
                .is_ok()
        );
        // Arbitrary third-party realm must be rejected by default
        assert!(
            policy
                .check_auth_destination(
                    "ghcr.io",
                    &Url::parse("https://evil.example/steal").unwrap(),
                    false
                )
                .is_err()
        );
        // HTTPS -> HTTP downgrade must be rejected
        assert!(
            policy
                .check_auth_destination(
                    "ghcr.io",
                    &Url::parse("http://ghcr.io/token").unwrap(),
                    false
                )
                .is_err()
        );
        // Embedded credentials in realm must be rejected
        assert!(
            policy
                .check_auth_destination(
                    "ghcr.io",
                    &Url::parse("https://user:pass@ghcr.io/token").unwrap(),
                    false
                )
                .is_err()
        );
    }

    #[test]
    fn explicit_auth_allowlist_overrides_default_and_supports_external_auth() {
        let policy = NetworkPolicy {
            allowed_auth_hosts: vec!["auth.corp.example".to_string()],
            ..NetworkPolicy::default()
        };
        assert!(
            policy
                .check_auth_destination(
                    "registry.corp.example",
                    &Url::parse("https://auth.corp.example/oauth/token").unwrap(),
                    false
                )
                .is_ok()
        );
        // Built-in auth.docker.io is rejected when explicit allowlist doesn't include it
        assert!(
            policy
                .check_auth_destination(
                    "registry-1.docker.io",
                    &Url::parse("https://auth.docker.io/token").unwrap(),
                    false
                )
                .is_err()
        );
    }

    #[test]
    fn wildcard_validation_rejects_overbroad_patterns() {
        let bad = NetworkPolicy {
            allowed_registries: vec!["*.com".to_string()],
            ..NetworkPolicy::default()
        };
        assert!(bad.validate().is_err());

        let good = NetworkPolicy {
            allowed_registries: vec!["*.pkg.dev".to_string()],
            ..NetworkPolicy::default()
        };
        assert!(good.validate().is_ok());
        assert!(
            good.check_registry_host("asia-northeast1-docker.pkg.dev")
                .is_ok()
        );
        assert!(good.check_registry_host("evil.example").is_err());
    }
}
