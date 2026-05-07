use std::collections::BTreeMap;
use std::collections::BTreeSet;

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
        plan_subscription_proxy_request, SubscriptionProxyInboundRequest,
        SubscriptionProxyRoute, SubscriptionProxyRouteError, DEFAULT_CHALLENGE_DIR,
        DEFAULT_HTTPS_LISTEN, DEFAULT_MAX_RESPONSE_BYTES,
    };
    use crate::config::{SubscriptionProxyConfig, SubscriptionProxyProfile};

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
}
