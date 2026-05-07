use std::collections::BTreeSet;

use crate::config::{SubscriptionProxyConfig, SubscriptionProxyProfile};

pub const DEFAULT_HTTPS_LISTEN: &str = "0.0.0.0:443";
pub const DEFAULT_CHALLENGE_DIR: &str = "/etc/v2node/subproxy/challenges";
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

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

#[cfg(test)]
mod tests {
    use super::{
        build_subscription_upstream_url, normalize_subscription_proxy_config,
        DEFAULT_CHALLENGE_DIR, DEFAULT_HTTPS_LISTEN, DEFAULT_MAX_RESPONSE_BYTES,
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
}
