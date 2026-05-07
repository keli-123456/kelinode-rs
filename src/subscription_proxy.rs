use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use crate::config::{SubscriptionProxyConfig, SubscriptionProxyProfile};

pub const DEFAULT_HTTPS_LISTEN: &str = "0.0.0.0:443";
pub const DEFAULT_CHALLENGE_DIR: &str = "/etc/v2node/subproxy/challenges";
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionProxyInboundRequest {
    pub method: String,
    pub path: String,
    pub raw_query: String,
    pub host: String,
    pub remote_addr: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionProxyUpstreamRequest {
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub head_only: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionProxyUpstreamResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub content_length: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionProxyClientResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionProxyStatus {
    pub status: String,
    pub enabled: bool,
    pub running: bool,
    pub mode: String,
    pub https_listen: String,
    pub profiles: usize,
    pub certificate_domain: String,
    pub certificate_owner_site_id: String,
    pub certificate_id: String,
    pub need_certificate: bool,
    pub csr_pem: String,
    pub validation_ready: bool,
    pub cert_not_after: String,
    pub last_error: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionProxyServeMode {
    Https,
    HttpFallback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionProxyRoute {
    Health,
    Upstream(SubscriptionProxyUpstreamRequest),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionProxyRouteError {
    NotFound,
    MethodNotAllowed,
    BadGateway(String),
}

impl SubscriptionProxyRouteError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::BadGateway(_) => 502,
        }
    }
}

pub fn normalize_subscription_proxy_config(
    source: &SubscriptionProxyConfig,
) -> Result<SubscriptionProxyConfig, String> {
    let mut config = source.clone();
    config.https_listen = first_non_empty(config.https_listen.trim(), DEFAULT_HTTPS_LISTEN);
    config.http_listen = config.http_listen.trim().to_string();
    config.cert_file = config.cert_file.trim().to_string();
    config.key_file = config.key_file.trim().to_string();
    config.certificate_domain = config.certificate_domain.trim().to_string();
    config.challenge_dir = first_non_empty(config.challenge_dir.trim(), DEFAULT_CHALLENGE_DIR);
    config.site_id = config.site_id.trim().to_string();
    config.upstream_base_url = trim_trailing_slashes(config.upstream_base_url.trim());
    config.subscribe_path = trim_subscription_path(&config.subscribe_path);
    if config.max_response_bytes == 0 {
        config.max_response_bytes = DEFAULT_MAX_RESPONSE_BYTES;
    }

    if !config.site_id.is_empty() || !config.upstream_base_url.is_empty() {
        config.profiles.push(SubscriptionProxyProfile {
            site_id: config.site_id.clone(),
            upstream_base_url: config.upstream_base_url.clone(),
            subscribe_path: config.subscribe_path.clone(),
        });
    }

    let mut seen = BTreeSet::new();
    let mut profiles = Vec::new();
    for profile in config.profiles {
        let site_id = profile.site_id.trim().to_string();
        let upstream_base_url = trim_trailing_slashes(profile.upstream_base_url.trim());
        let subscribe_path = first_non_empty(&trim_subscription_path(&profile.subscribe_path), "s");
        if site_id.is_empty() || upstream_base_url.is_empty() {
            continue;
        }
        if !is_valid_upstream_base_url(&upstream_base_url) {
            return Err(format!("invalid subscription proxy upstream for site {site_id}"));
        }
        let dedupe_key = site_id.to_ascii_lowercase();
        if !seen.insert(dedupe_key) {
            continue;
        }
        profiles.push(SubscriptionProxyProfile {
            site_id,
            upstream_base_url,
            subscribe_path,
        });
    }

    config.profiles = profiles;
    config.enabled = config.enabled || !config.profiles.is_empty();
    if config.enabled && config.profiles.is_empty() {
        return Err("subscription proxy enabled without profiles".to_string());
    }

    Ok(config)
}

pub fn normalize_subscription_proxy_config_with_public_ipv4<F>(
    source: &SubscriptionProxyConfig,
    mut detect_public_ipv4: F,
) -> Result<SubscriptionProxyConfig, String>
where
    F: FnMut() -> Result<String, String>,
{
    let mut config = normalize_subscription_proxy_config(source)?;
    if config.enabled {
        let (domain, _) = resolve_subscription_certificate_domain(
            &config.certificate_domain,
            &mut detect_public_ipv4,
        )?;
        config.certificate_domain = domain;
    }
    Ok(config)
}

pub fn resolve_subscription_certificate_domain<F>(
    domain: &str,
    mut detect_public_ipv4: F,
) -> Result<(String, bool), String>
where
    F: FnMut() -> Result<String, String>,
{
    let domain = domain.trim();
    match domain.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) | Err(_) if !domain.is_empty() => Ok((domain.to_string(), false)),
        Ok(IpAddr::V6(_)) => {
            let original = domain.to_string();
            let Some(ipv4) = detect_valid_public_ipv4(&mut detect_public_ipv4) else {
                return Ok((original, false));
            };
            Ok((ipv4.clone(), ipv4 != original))
        }
        Ok(IpAddr::V4(_)) | Err(_) => {
            let Some(ipv4) = detect_valid_public_ipv4(&mut detect_public_ipv4) else {
                return Ok((String::new(), false));
            };
            Ok((ipv4, true))
        }
    }
}

pub fn plan_subscription_proxy_request(
    profiles: &[SubscriptionProxyProfile],
    request: &SubscriptionProxyInboundRequest,
) -> Result<SubscriptionProxyRoute, SubscriptionProxyRouteError> {
    let method = request.method.trim().to_ascii_uppercase();
    if method != "GET" && method != "HEAD" {
        return Err(SubscriptionProxyRouteError::MethodNotAllowed);
    }

    if request.path == "/health" {
        return Ok(SubscriptionProxyRoute::Health);
    }

    let Some(rest) = request.path.strip_prefix("/sub/") else {
        return Err(SubscriptionProxyRouteError::NotFound);
    };
    let Some((site_id, token_part)) = rest.split_once('/') else {
        return Err(SubscriptionProxyRouteError::NotFound);
    };
    if site_id.trim().is_empty() || token_part.trim().is_empty() {
        return Err(SubscriptionProxyRouteError::NotFound);
    }
    let Some(profile) = profiles
        .iter()
        .find(|profile| profile.site_id.eq_ignore_ascii_case(site_id))
    else {
        return Err(SubscriptionProxyRouteError::NotFound);
    };
    let token = percent_decode_path_segment(token_part)
        .map_err(SubscriptionProxyRouteError::BadGateway)?;
    if token.trim().is_empty() {
        return Err(SubscriptionProxyRouteError::NotFound);
    }

    let url = build_subscription_upstream_url(profile, &token, &request.raw_query)
        .map_err(SubscriptionProxyRouteError::BadGateway)?;
    let mut headers = forwarded_headers(&request.headers);
    if !request.host.trim().is_empty() {
        headers.insert("X-Forwarded-Host".to_string(), request.host.trim().to_string());
    }
    if let Some(ip) = client_ip(&request.remote_addr) {
        headers.insert("X-Forwarded-For".to_string(), ip);
    }

    Ok(SubscriptionProxyRoute::Upstream(
        SubscriptionProxyUpstreamRequest {
            url,
            headers,
            head_only: method == "HEAD",
        },
    ))
}

pub fn build_subscription_upstream_url(
    profile: &SubscriptionProxyProfile,
    token: &str,
    raw_query: &str,
) -> Result<String, String> {
    let base = trim_trailing_slashes(profile.upstream_base_url.trim());
    if !is_valid_upstream_base_url(&base) {
        return Err("invalid base url".to_string());
    }
    let subscribe_path = first_non_empty(&trim_subscription_path(&profile.subscribe_path), "s");
    let token = token.trim();
    if token.is_empty() {
        return Err("empty subscription token".to_string());
    }

    let mut url = format!(
        "{}/{}/{}",
        base,
        subscribe_path,
        percent_encode_path_segment(token)
    );
    let query = raw_query.trim_start_matches('?');
    if !query.is_empty() {
        url.push('?');
        url.push_str(query);
    }
    Ok(url)
}

pub fn plan_subscription_proxy_response(
    response: SubscriptionProxyUpstreamResponse,
    max_response_bytes: u64,
    head_only: bool,
) -> Result<SubscriptionProxyClientResponse, SubscriptionProxyRouteError> {
    let max_response_bytes = if max_response_bytes == 0 {
        DEFAULT_MAX_RESPONSE_BYTES
    } else {
        max_response_bytes
    };
    if response
        .content_length
        .map(|length| length > max_response_bytes)
        .unwrap_or(false)
        || response.body.len() as u64 > max_response_bytes
    {
        return Err(SubscriptionProxyRouteError::BadGateway(
            "upstream response too large".to_string(),
        ));
    }

    Ok(SubscriptionProxyClientResponse {
        status: response.status,
        headers: forwarded_headers(&response.headers),
        body: if head_only { Vec::new() } else { response.body },
    })
}

pub fn subscription_proxy_certificate_owner_site_id(
    profiles: &[SubscriptionProxyProfile],
) -> String {
    for profile in profiles {
        let site_id = profile.site_id.trim();
        if !site_id.is_empty() {
            return site_id.to_string();
        }
    }
    String::new()
}

pub fn prepare_subscription_proxy_certificate_status<F, G, H>(
    config: &SubscriptionProxyConfig,
    mut certificate_not_after: F,
    mut ensure_csr: G,
    mut file_readable: H,
) -> SubscriptionProxyStatus
where
    F: FnMut(&str) -> String,
    G: FnMut(&str, &str) -> Result<String, String>,
    H: FnMut(&str) -> bool,
{
    let cert_file = config.cert_file.trim();
    let key_file = config.key_file.trim();
    let certificate_domain = config.certificate_domain.trim();
    let mut status = SubscriptionProxyStatus {
        certificate_domain: certificate_domain.to_string(),
        certificate_id: config.zerossl.certificate_id.trim().to_string(),
        cert_not_after: certificate_not_after(cert_file),
        ..SubscriptionProxyStatus::default()
    };

    if certificate_domain.is_empty() {
        return status;
    }

    match ensure_csr(key_file, certificate_domain) {
        Ok(csr_pem) => status.csr_pem = csr_pem,
        Err(err) => {
            status.last_error = err;
            return status;
        }
    }

    if !file_readable(cert_file) || !file_readable(key_file) {
        status.need_certificate = true;
    }

    status
}

pub fn plan_subscription_proxy_serve_mode<F>(
    config: &SubscriptionProxyConfig,
    mut file_readable: F,
) -> Result<SubscriptionProxyServeMode, String>
where
    F: FnMut(&str) -> bool,
{
    let cert_file = config.cert_file.trim();
    let key_file = config.key_file.trim();
    if file_readable(cert_file) && file_readable(key_file) {
        return Ok(SubscriptionProxyServeMode::Https);
    }
    if config.allow_http_fallback {
        return Ok(SubscriptionProxyServeMode::HttpFallback);
    }
    Err(format!(
        "subscription proxy certificate files are not readable: cert={cert_file} key={key_file}"
    ))
}

fn first_non_empty(value: &str, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn trim_subscription_path(value: &str) -> String {
    value.trim().trim_matches('/').to_string()
}

fn trim_trailing_slashes(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

fn is_valid_upstream_base_url(value: &str) -> bool {
    let Some(after_scheme) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    after_scheme
        .split('/')
        .next()
        .map(|host| !host.trim().is_empty())
        .unwrap_or(false)
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified())
}

fn detect_valid_public_ipv4<F>(detect_public_ipv4: &mut F) -> Option<String>
where
    F: FnMut() -> Result<String, String>,
{
    let Ok(ipv4) = detect_public_ipv4() else {
        return None;
    };
    let Ok(parsed) = ipv4.trim().parse::<Ipv4Addr>() else {
        return None;
    };
    if !is_public_ipv4(parsed) {
        return None;
    }
    Some(parsed.to_string())
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut output = String::new();
    for byte in value.as_bytes() {
        match *byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => output.push(*byte as char),
            _ => output.push_str(&format!("%{byte:02X}")),
        }
    }
    output
}

fn percent_decode_path_segment(value: &str) -> Result<String, String> {
    let mut output = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("invalid escaped token".to_string());
            }
            let hi = hex_value(bytes[index + 1])
                .ok_or_else(|| "invalid escaped token".to_string())?;
            let lo = hex_value(bytes[index + 2])
                .ok_or_else(|| "invalid escaped token".to_string())?;
            output.push((hi << 4) | lo);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| "invalid escaped token".to_string())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn forwarded_headers(source: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    source
        .iter()
        .filter(|(key, _)| !is_hop_by_hop_header(key) && !key.eq_ignore_ascii_case("host"))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn is_hop_by_hop_header(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn client_ip(remote_addr: &str) -> Option<String> {
    let text = remote_addr.trim();
    if text.is_empty() {
        return None;
    }
    if let Some(rest) = text.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return Some(host.to_string());
        }
    }
    if text.matches(':').count() == 1 {
        let (host, port) = text.rsplit_once(':')?;
        if !host.is_empty() && port.chars().all(|character| character.is_ascii_digit()) {
            return Some(host.to_string());
        }
    }
    Some(text.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        build_subscription_upstream_url, normalize_subscription_proxy_config,
        normalize_subscription_proxy_config_with_public_ipv4,
        plan_subscription_proxy_request, plan_subscription_proxy_response,
        plan_subscription_proxy_serve_mode, prepare_subscription_proxy_certificate_status,
        resolve_subscription_certificate_domain, subscription_proxy_certificate_owner_site_id,
        SubscriptionProxyInboundRequest, SubscriptionProxyRoute, SubscriptionProxyRouteError,
        SubscriptionProxyServeMode, SubscriptionProxyUpstreamResponse,
        DEFAULT_CHALLENGE_DIR, DEFAULT_HTTPS_LISTEN, DEFAULT_MAX_RESPONSE_BYTES,
    };
    use crate::config::{
        SubscriptionProxyConfig, SubscriptionProxyProfile, SubscriptionProxyZeroSslConfig,
    };

    #[test]
    fn normalizes_single_subscription_proxy_profile() {
        let config = normalize_subscription_proxy_config(&SubscriptionProxyConfig {
            enabled: true,
            site_id: " site-a ".to_string(),
            upstream_base_url: " https://panel.example.test/ ".to_string(),
            subscribe_path: " /answer/land/ ".to_string(),
            ..SubscriptionProxyConfig::default()
        })
        .unwrap();

        assert!(config.enabled);
        assert_eq!(config.https_listen, DEFAULT_HTTPS_LISTEN);
        assert_eq!(config.challenge_dir, DEFAULT_CHALLENGE_DIR);
        assert_eq!(config.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
        assert_eq!(config.profiles.len(), 1);
        assert_eq!(config.profiles[0].site_id, "site-a");
        assert_eq!(config.profiles[0].upstream_base_url, "https://panel.example.test");
        assert_eq!(config.profiles[0].subscribe_path, "answer/land");
    }

    #[test]
    fn resolves_ipv6_certificate_domain_to_public_ipv4() {
        let (domain, changed) =
            resolve_subscription_certificate_domain("2607:f358:1a:e::d4d9:5831", || {
                Ok("8.8.8.8".to_string())
            })
            .unwrap();

        assert_eq!(domain, "8.8.8.8");
        assert!(changed);
    }

    #[test]
    fn resolves_empty_certificate_domain_to_public_ipv4_like_go_agent() {
        let (domain, changed) =
            resolve_subscription_certificate_domain("", || Ok("8.8.8.8".to_string())).unwrap();

        assert_eq!(domain, "8.8.8.8");
        assert!(changed);
    }

    #[test]
    fn keeps_ipv4_and_hostname_certificate_domains_without_detection() {
        let (domain, changed) = resolve_subscription_certificate_domain("152.53.135.140", || {
            panic!("IPv4 certificate domains must not probe another address")
        })
        .unwrap();
        assert_eq!(domain, "152.53.135.140");
        assert!(!changed);

        let (domain, changed) = resolve_subscription_certificate_domain("sub.example.test", || {
            panic!("host certificate domains must not probe another address")
        })
        .unwrap();
        assert_eq!(domain, "sub.example.test");
        assert!(!changed);
    }

    #[test]
    fn normalizes_certificate_domain_with_public_ipv4_resolver() {
        let config = normalize_subscription_proxy_config_with_public_ipv4(
            &SubscriptionProxyConfig {
                enabled: true,
                certificate_domain: "2607:f358:1a:e::d4d9:5831".to_string(),
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test".to_string(),
                ..SubscriptionProxyConfig::default()
            },
            || Ok("8.8.8.8".to_string()),
        )
        .unwrap();

        assert_eq!(config.certificate_domain, "8.8.8.8");
        assert_eq!(config.profiles.len(), 1);
    }

    #[test]
    fn keeps_original_certificate_domain_when_public_ipv4_detection_fails() {
        let (domain, changed) =
            resolve_subscription_certificate_domain("2607:f358:1a:e::d4d9:5831", || {
                Ok("10.0.0.1".to_string())
            })
            .unwrap();
        assert_eq!(domain, "2607:f358:1a:e::d4d9:5831");
        assert!(!changed);

        let (domain, changed) =
            resolve_subscription_certificate_domain("2607:f358:1a:e::d4d9:5831", || {
                Err("network unavailable".to_string())
            })
            .unwrap();
        assert_eq!(domain, "2607:f358:1a:e::d4d9:5831");
        assert!(!changed);
    }

    #[test]
    fn certificate_owner_site_id_uses_first_non_empty_profile() {
        let owner = subscription_proxy_certificate_owner_site_id(&[
            SubscriptionProxyProfile {
                site_id: " ".to_string(),
                upstream_base_url: String::new(),
                subscribe_path: String::new(),
            },
            SubscriptionProxyProfile {
                site_id: " site-a ".to_string(),
                upstream_base_url: String::new(),
                subscribe_path: String::new(),
            },
            SubscriptionProxyProfile {
                site_id: "site-b".to_string(),
                upstream_base_url: String::new(),
                subscribe_path: String::new(),
            },
        ]);

        assert_eq!(owner, "site-a");
    }

    #[test]
    fn prepares_certificate_status_and_marks_missing_files() {
        let status = prepare_subscription_proxy_certificate_status(
            &SubscriptionProxyConfig {
                cert_file: " /etc/v2node/fullchain.pem ".to_string(),
                key_file: " /etc/v2node/private.key ".to_string(),
                certificate_domain: " sub.example.test ".to_string(),
                zerossl: SubscriptionProxyZeroSslConfig {
                    certificate_id: " cert-1 ".to_string(),
                    ..SubscriptionProxyZeroSslConfig::default()
                },
                ..SubscriptionProxyConfig::default()
            },
            |path| {
                assert_eq!(path, "/etc/v2node/fullchain.pem");
                "2026-06-01T00:00:00Z".to_string()
            },
            |key_file, domain| {
                assert_eq!(key_file, "/etc/v2node/private.key");
                assert_eq!(domain, "sub.example.test");
                Ok("-----BEGIN CERTIFICATE REQUEST-----test".to_string())
            },
            |_| false,
        );

        assert_eq!(status.certificate_domain, "sub.example.test");
        assert_eq!(status.certificate_id, "cert-1");
        assert_eq!(status.cert_not_after, "2026-06-01T00:00:00Z");
        assert_eq!(status.csr_pem, "-----BEGIN CERTIFICATE REQUEST-----test");
        assert!(status.need_certificate);
        assert!(status.last_error.is_empty());
    }

    #[test]
    fn certificate_status_keeps_csr_errors_non_fatal() {
        let status = prepare_subscription_proxy_certificate_status(
            &SubscriptionProxyConfig {
                key_file: "/etc/v2node/private.key".to_string(),
                certificate_domain: "sub.example.test".to_string(),
                ..SubscriptionProxyConfig::default()
            },
            |_| String::new(),
            |_, _| Err("key write failed".to_string()),
            |_| false,
        );

        assert_eq!(status.last_error, "key write failed");
        assert!(!status.need_certificate);
        assert!(status.csr_pem.is_empty());
    }

    #[test]
    fn plans_https_or_http_fallback_from_certificate_files() {
        let https = plan_subscription_proxy_serve_mode(
            &SubscriptionProxyConfig {
                cert_file: "/etc/v2node/fullchain.pem".to_string(),
                key_file: "/etc/v2node/private.key".to_string(),
                ..SubscriptionProxyConfig::default()
            },
            |_| true,
        )
        .unwrap();
        assert_eq!(https, SubscriptionProxyServeMode::Https);

        let http = plan_subscription_proxy_serve_mode(
            &SubscriptionProxyConfig {
                cert_file: "/etc/v2node/fullchain.pem".to_string(),
                key_file: "/etc/v2node/private.key".to_string(),
                allow_http_fallback: true,
                ..SubscriptionProxyConfig::default()
            },
            |_| false,
        )
        .unwrap();
        assert_eq!(http, SubscriptionProxyServeMode::HttpFallback);

        let err = plan_subscription_proxy_serve_mode(
            &SubscriptionProxyConfig {
                cert_file: "/etc/v2node/fullchain.pem".to_string(),
                key_file: "/etc/v2node/private.key".to_string(),
                ..SubscriptionProxyConfig::default()
            },
            |_| false,
        )
        .unwrap_err();
        assert!(err.contains("certificate files are not readable"));
    }

    #[test]
    fn deduplicates_profiles_case_insensitively() {
        let config = normalize_subscription_proxy_config(&SubscriptionProxyConfig {
            profiles: vec![
                SubscriptionProxyProfile {
                    site_id: "Site-A".to_string(),
                    upstream_base_url: "https://one.example.test".to_string(),
                    subscribe_path: String::new(),
                },
                SubscriptionProxyProfile {
                    site_id: "site-a".to_string(),
                    upstream_base_url: "https://two.example.test".to_string(),
                    subscribe_path: "s".to_string(),
                },
            ],
            ..SubscriptionProxyConfig::default()
        })
        .unwrap();

        assert_eq!(config.profiles.len(), 1);
        assert_eq!(config.profiles[0].site_id, "Site-A");
        assert_eq!(config.profiles[0].subscribe_path, "s");
    }

    #[test]
    fn rejects_enabled_proxy_without_valid_profiles() {
        let err = normalize_subscription_proxy_config(&SubscriptionProxyConfig {
            enabled: true,
            profiles: vec![SubscriptionProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "not-a-url".to_string(),
                subscribe_path: "s".to_string(),
            }],
            ..SubscriptionProxyConfig::default()
        })
        .unwrap_err();

        assert!(err.contains("invalid subscription proxy upstream"));
    }

    #[test]
    fn builds_upstream_subscription_url() {
        let url = build_subscription_upstream_url(
            &SubscriptionProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test/root/".to_string(),
                subscribe_path: "/answer/land/".to_string(),
            },
            "token 123",
            "?flag=sing-box",
        )
        .unwrap();

        assert_eq!(
            url,
            "https://panel.example.test/root/answer/land/token%20123?flag=sing-box"
        );
    }

    #[test]
    fn plans_health_request() {
        let route = plan_subscription_proxy_request(
            &[],
            &SubscriptionProxyInboundRequest {
                method: "GET".to_string(),
                path: "/health".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
        )
        .unwrap();

        assert_eq!(route, SubscriptionProxyRoute::Health);
    }

    #[test]
    fn plans_subscription_upstream_request_and_forwarded_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("User-Agent".to_string(), "Hiddify".to_string());
        headers.insert("Connection".to_string(), "close".to_string());
        headers.insert("Host".to_string(), "proxy.example.test".to_string());
        let route = plan_subscription_proxy_request(
            &[SubscriptionProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test".to_string(),
                subscribe_path: "answer/land".to_string(),
            }],
            &SubscriptionProxyInboundRequest {
                method: "HEAD".to_string(),
                path: "/sub/site-a/token%20123".to_string(),
                raw_query: "flag=sing-box".to_string(),
                host: "proxy.example.test".to_string(),
                remote_addr: "198.51.100.8:51234".to_string(),
                headers,
            },
        )
        .unwrap();

        let SubscriptionProxyRoute::Upstream(upstream) = route else {
            panic!("expected upstream route");
        };
        assert!(upstream.head_only);
        assert_eq!(
            upstream.url,
            "https://panel.example.test/answer/land/token%20123?flag=sing-box"
        );
        assert_eq!(upstream.headers["User-Agent"], "Hiddify");
        assert_eq!(upstream.headers["X-Forwarded-Host"], "proxy.example.test");
        assert_eq!(upstream.headers["X-Forwarded-For"], "198.51.100.8");
        assert!(!upstream.headers.contains_key("Connection"));
        assert!(!upstream.headers.contains_key("Host"));
    }

    #[test]
    fn rejects_unknown_site_and_methods_like_go_handler() {
        let profile = SubscriptionProxyProfile {
            site_id: "site-a".to_string(),
            upstream_base_url: "https://panel.example.test".to_string(),
            subscribe_path: "s".to_string(),
        };

        let err = plan_subscription_proxy_request(
            &[profile.clone()],
            &SubscriptionProxyInboundRequest {
                method: "POST".to_string(),
                path: "/sub/site-a/token".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.status_code(), 405);

        let err = plan_subscription_proxy_request(
            &[profile],
            &SubscriptionProxyInboundRequest {
                method: "GET".to_string(),
                path: "/sub/missing/token".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
        )
        .unwrap_err();
        assert_eq!(err, SubscriptionProxyRouteError::NotFound);
        assert_eq!(err.status_code(), 404);
    }

    #[test]
    fn plans_subscription_response_with_header_filtering() {
        let mut headers = BTreeMap::new();
        headers.insert(
            "Subscription-Userinfo".to_string(),
            "upload=0; download=1".to_string(),
        );
        headers.insert("Connection".to_string(), "close".to_string());

        let response = plan_subscription_proxy_response(
            SubscriptionProxyUpstreamResponse {
                status: 200,
                headers,
                body: b"ok".to_vec(),
                content_length: Some(2),
            },
            1024,
            false,
        )
        .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok".to_vec());
        assert_eq!(
            response.headers["Subscription-Userinfo"],
            "upload=0; download=1"
        );
        assert!(!response.headers.contains_key("Connection"));
    }

    #[test]
    fn enforces_response_size_and_head_body_rules() {
        let err = plan_subscription_proxy_response(
            SubscriptionProxyUpstreamResponse {
                status: 200,
                body: vec![1, 2, 3],
                content_length: Some(3),
                ..SubscriptionProxyUpstreamResponse::default()
            },
            2,
            false,
        )
        .unwrap_err();
        assert_eq!(err.status_code(), 502);

        let response = plan_subscription_proxy_response(
            SubscriptionProxyUpstreamResponse {
                status: 200,
                body: b"ok".to_vec(),
                ..SubscriptionProxyUpstreamResponse::default()
            },
            1024,
            true,
        )
        .unwrap();

        assert!(response.body.is_empty());
    }
}
