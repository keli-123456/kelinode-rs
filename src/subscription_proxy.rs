use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufReader, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::config::{SubscriptionProxyConfig, SubscriptionProxyProfile, WebsiteProxyProfile};

pub const DEFAULT_HTTPS_LISTEN: &str = "0.0.0.0:443";
pub const DEFAULT_CHALLENGE_DIR: &str = "/etc/kelinode/subproxy/challenges";
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionProxyInboundRequest {
    pub method: String,
    pub path: String,
    pub raw_query: String,
    pub host: String,
    pub remote_addr: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionProxyUpstreamRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub head_only: bool,
    pub follow_redirects: bool,
    pub response_rewrite: Option<WebsiteProxyRewriteContext>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebsiteProxyRewriteContext {
    pub upstream_base_url: String,
    pub proxy_path_prefix: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionProxyUpstreamResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub set_cookie_headers: Vec<String>,
    pub body: Vec<u8>,
    pub content_length: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionProxyClientResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub set_cookie_headers: Vec<String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionProxyFileWrite {
    pub path: String,
    pub content: String,
    pub mode: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionProxyStatus {
    pub status: String,
    pub enabled: bool,
    pub running: bool,
    pub mode: String,
    pub https_listen: String,
    pub profiles: usize,
    pub website_profiles: usize,
    pub certificate_domain: String,
    pub certificate_owner_site_id: String,
    pub certificate_id: String,
    pub need_certificate: bool,
    pub csr_pem: String,
    pub validation_ready: bool,
    pub cert_not_after: String,
    pub last_error: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionProxyServeMode {
    Https,
    HttpFallback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionProxyApplyAction {
    Disabled,
    Unchanged,
    Start,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionProxyApplyPlan {
    pub action: SubscriptionProxyApplyAction,
    pub fingerprint: String,
    pub status: SubscriptionProxyStatus,
    pub serve_mode: Option<SubscriptionProxyServeMode>,
    pub profiles: Vec<SubscriptionProxyProfile>,
    pub website_profiles: Vec<WebsiteProxyProfile>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionProxyHttpServerPlan {
    pub listen: String,
    pub challenge_dir: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionProxyMainServerPlan {
    pub listen: String,
    pub mode: SubscriptionProxyServeMode,
    pub cert_file: String,
    pub key_file: String,
    pub max_response_bytes: u64,
    pub profiles: Vec<SubscriptionProxyProfile>,
    pub website_profiles: Vec<WebsiteProxyProfile>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionProxyCsrPlan {
    pub key_file: String,
    pub common_name: String,
    pub subject_alt_name: String,
    pub generate_key: bool,
}

#[derive(Debug)]
pub struct SubscriptionProxyServerHandle {
    listen: String,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

#[derive(Debug, Default)]
pub struct SubscriptionProxyRuntimeManager {
    fingerprint: String,
    status: SubscriptionProxyStatus,
    main_server: Option<SubscriptionProxyServerHandle>,
    http_server: Option<SubscriptionProxyServerHandle>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionProxyRoute {
    Health,
    ChallengeFile(String),
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

impl SubscriptionProxyServerHandle {
    pub fn listen(&self) -> &str {
        &self.listen
    }

    pub fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for SubscriptionProxyServerHandle {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

pub fn parse_subscription_proxy_http_request(
    raw: &[u8],
    remote_addr: &str,
) -> Result<SubscriptionProxyInboundRequest, String> {
    let Some(header_end) = http_header_end(raw) else {
        return Err("incomplete http request".to_string());
    };
    let head =
        std::str::from_utf8(&raw[..header_end]).map_err(|_| "invalid utf-8 request".to_string())?;
    let body_start = header_end + 4;
    let body = raw.get(body_start..).unwrap_or_default().to_vec();
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing http request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing http method".to_string())?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| "missing http target".to_string())?;
    let version = parts
        .next()
        .ok_or_else(|| "missing http version".to_string())?;
    if !version.starts_with("HTTP/") {
        return Err("invalid http version".to_string());
    }
    let (path, raw_query) = target
        .split_once('?')
        .map(|(path, query)| (path.to_string(), query.to_string()))
        .unwrap_or_else(|| (target.to_string(), String::new()));
    if path.is_empty() || !path.starts_with('/') {
        return Err("invalid http path".to_string());
    }

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err("invalid http header".to_string());
        };
        let key = key.trim();
        if key.is_empty() {
            return Err("invalid http header".to_string());
        }
        headers.insert(key.to_string(), value.trim().to_string());
    }
    let host = headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.clone())
        .unwrap_or_default();

    Ok(SubscriptionProxyInboundRequest {
        method,
        path,
        raw_query,
        host,
        remote_addr: remote_addr.to_string(),
        headers,
        body,
    })
}

pub fn render_subscription_proxy_http_response(
    response: &SubscriptionProxyClientResponse,
) -> Vec<u8> {
    let mut output = Vec::new();
    let reason = http_reason_phrase(response.status);
    output.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", response.status, reason).as_bytes());
    output.extend_from_slice(format!("Content-Length: {}\r\n", response.body.len()).as_bytes());
    output.extend_from_slice(b"Connection: close\r\n");
    for (key, value) in &response.headers {
        if valid_http_header_name(key) && valid_http_header_value(value) {
            output.extend_from_slice(format!("{key}: {value}\r\n").as_bytes());
        }
    }
    for value in &response.set_cookie_headers {
        if valid_http_header_value(value) {
            output.extend_from_slice(format!("Set-Cookie: {value}\r\n").as_bytes());
        }
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&response.body);
    output
}

pub fn subscription_proxy_error_response(
    error: &SubscriptionProxyRouteError,
) -> SubscriptionProxyClientResponse {
    let mut headers = BTreeMap::new();
    headers.insert(
        "Content-Type".to_string(),
        "text/plain; charset=utf-8".to_string(),
    );
    let message = match error {
        SubscriptionProxyRouteError::NotFound => "not found",
        SubscriptionProxyRouteError::MethodNotAllowed => "method not allowed",
        SubscriptionProxyRouteError::BadGateway(_) => "bad gateway",
    };
    SubscriptionProxyClientResponse {
        status: error.status_code(),
        headers,
        set_cookie_headers: Vec::new(),
        body: format!("{message}\n").into_bytes(),
    }
}

fn subscription_proxy_bad_request_response(error: &str) -> SubscriptionProxyClientResponse {
    let mut headers = BTreeMap::new();
    headers.insert(
        "Content-Type".to_string(),
        "text/plain; charset=utf-8".to_string(),
    );
    SubscriptionProxyClientResponse {
        status: 400,
        headers,
        set_cookie_headers: Vec::new(),
        body: format!("{error}\n").into_bytes(),
    }
}

impl SubscriptionProxyRuntimeManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn status(&self) -> SubscriptionProxyStatus {
        self.status.clone()
    }

    pub fn apply<F, G, H, I>(
        &mut self,
        config: &SubscriptionProxyConfig,
        certificate_not_after: F,
        ensure_csr: G,
        mut file_readable: H,
        write_file: I,
    ) -> Result<SubscriptionProxyApplyPlan, String>
    where
        F: FnMut(&str) -> String,
        G: FnMut(&str, &str) -> Result<String, String>,
        H: FnMut(&str) -> bool,
        I: FnMut(&SubscriptionProxyFileWrite) -> Result<(), String>,
    {
        let normalized = normalize_subscription_proxy_config(config)?;
        let certificate_status = prepare_subscription_proxy_certificate_status_with_file_writes(
            &normalized,
            certificate_not_after,
            ensure_csr,
            &mut file_readable,
            write_file,
        );
        let mut plan = plan_subscription_proxy_apply(
            &normalized,
            &self.fingerprint,
            certificate_status,
            &mut file_readable,
        );
        if plan.action == SubscriptionProxyApplyAction::Unchanged {
            let mut status = self.status.clone();
            merge_subscription_proxy_status(&mut status, &plan.status);
            plan.status = status;
        }
        self.fingerprint = match plan.action {
            SubscriptionProxyApplyAction::Disabled => String::new(),
            SubscriptionProxyApplyAction::Unchanged
            | SubscriptionProxyApplyAction::Start
            | SubscriptionProxyApplyAction::Error => plan.fingerprint.clone(),
        };
        self.status = plan.status.clone();
        Ok(plan)
    }

    pub fn apply_with_file_system<G>(
        &mut self,
        config: &SubscriptionProxyConfig,
        ensure_csr: G,
    ) -> Result<SubscriptionProxyApplyPlan, String>
    where
        G: FnMut(&str, &str) -> Result<String, String>,
    {
        self.apply(
            config,
            |_| String::new(),
            ensure_csr,
            subscription_proxy_file_readable,
            write_subscription_proxy_file,
        )
    }

    pub fn apply_and_start_with_file_system<G>(
        &mut self,
        config: &SubscriptionProxyConfig,
        ensure_csr: G,
    ) -> Result<SubscriptionProxyApplyPlan, String>
    where
        G: FnMut(&str, &str) -> Result<String, String>,
    {
        let normalized = normalize_subscription_proxy_config(config)?;
        let plan = self.apply_with_file_system(&normalized, ensure_csr)?;
        if let Err(err) = self.sync_servers_for_apply_plan(&normalized, &plan) {
            self.status.status = "error".to_string();
            self.status.running = false;
            self.status.mode = "error".to_string();
            self.status.last_error = err.clone();
            return Err(err);
        }
        Ok(plan)
    }

    fn sync_servers_for_apply_plan(
        &mut self,
        config: &SubscriptionProxyConfig,
        plan: &SubscriptionProxyApplyPlan,
    ) -> Result<(), String> {
        match plan.action {
            SubscriptionProxyApplyAction::Disabled => {
                self.stop_servers();
                Ok(())
            }
            SubscriptionProxyApplyAction::Unchanged => Ok(()),
            SubscriptionProxyApplyAction::Error => {
                self.stop_main_server();
                self.http_server = spawn_subscription_proxy_http_challenge_server(config.clone())?;
                Ok(())
            }
            SubscriptionProxyApplyAction::Start => {
                self.http_server = spawn_subscription_proxy_http_challenge_server(config.clone())?;
                let Some(mode) = plan.serve_mode else {
                    self.stop_main_server();
                    return Ok(());
                };
                match mode {
                    SubscriptionProxyServeMode::HttpFallback => {
                        self.main_server =
                            Some(spawn_subscription_proxy_main_http_fallback_server(
                                plan_subscription_proxy_main_server(config, mode),
                            )?);
                        Ok(())
                    }
                    SubscriptionProxyServeMode::Https => {
                        self.main_server = Some(spawn_subscription_proxy_main_https_server(
                            plan_subscription_proxy_main_server(config, mode),
                        )?);
                        Ok(())
                    }
                }
            }
        }
    }

    fn stop_servers(&mut self) {
        self.stop_main_server();
        if let Some(server) = self.http_server.take() {
            server.stop();
        }
    }

    fn stop_main_server(&mut self) {
        if let Some(server) = self.main_server.take() {
            server.stop();
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
            return Err(format!(
                "invalid subscription proxy upstream for site {site_id}"
            ));
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
    let mut seen = BTreeSet::new();
    let mut website_profiles = Vec::new();
    for profile in config.website_profiles {
        let site_id = profile.site_id.trim().to_string();
        let upstream_base_url = trim_trailing_slashes(profile.upstream_base_url.trim());
        let path_prefix = normalize_proxy_path_prefix(&profile.path_prefix);
        if site_id.is_empty() || upstream_base_url.is_empty() {
            continue;
        }
        if !is_valid_upstream_base_url(&upstream_base_url) {
            return Err(format!("invalid website proxy upstream for site {site_id}"));
        }
        let dedupe_key = format!("{}\0{}", site_id.to_ascii_lowercase(), path_prefix);
        if !seen.insert(dedupe_key) {
            continue;
        }
        website_profiles.push(WebsiteProxyProfile {
            site_id,
            upstream_base_url,
            path_prefix,
        });
    }

    config.website_profiles = website_profiles;
    config.enabled =
        config.enabled || !config.profiles.is_empty() || !config.website_profiles.is_empty();
    if config.enabled && config.profiles.is_empty() && config.website_profiles.is_empty() {
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
    website_profiles: &[WebsiteProxyProfile],
    request: &SubscriptionProxyInboundRequest,
) -> Result<SubscriptionProxyRoute, SubscriptionProxyRouteError> {
    let method = request.method.trim().to_ascii_uppercase();

    if request.path == "/health" {
        if method != "GET" && method != "HEAD" {
            return Err(SubscriptionProxyRouteError::MethodNotAllowed);
        }
        return Ok(SubscriptionProxyRoute::Health);
    }

    if let Some(rest) = request.path.strip_prefix("/sub/") {
        if method != "GET" && method != "HEAD" {
            return Err(SubscriptionProxyRouteError::MethodNotAllowed);
        }
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
        return Ok(SubscriptionProxyRoute::Upstream(
            SubscriptionProxyUpstreamRequest {
                method,
                url,
                headers: upstream_forwarded_headers(request),
                body: Vec::new(),
                head_only: request.method.trim().eq_ignore_ascii_case("HEAD"),
                follow_redirects: true,
                response_rewrite: None,
            },
        ));
    }

    if !is_allowed_website_proxy_method(&method) {
        return Err(SubscriptionProxyRouteError::MethodNotAllowed);
    }

    let Some((profile, path_prefix, upstream_path)) =
        website_proxy_match(website_profiles, &request.path)
    else {
        return Err(SubscriptionProxyRouteError::NotFound);
    };
    let url = build_website_upstream_url(profile, &upstream_path, &request.raw_query)
        .map_err(SubscriptionProxyRouteError::BadGateway)?;
    let head_only = method == "HEAD";
    let body = if head_only {
        Vec::new()
    } else {
        request.body.clone()
    };

    Ok(SubscriptionProxyRoute::Upstream(
        SubscriptionProxyUpstreamRequest {
            method,
            url,
            headers: upstream_forwarded_headers(request),
            body,
            head_only,
            follow_redirects: false,
            response_rewrite: Some(WebsiteProxyRewriteContext {
                upstream_base_url: trim_trailing_slashes(profile.upstream_base_url.trim()),
                proxy_path_prefix: path_prefix,
            }),
        },
    ))
}

pub fn build_website_upstream_url(
    profile: &WebsiteProxyProfile,
    upstream_path: &str,
    raw_query: &str,
) -> Result<String, String> {
    let base = trim_trailing_slashes(profile.upstream_base_url.trim());
    if !is_valid_upstream_base_url(&base) {
        return Err("invalid base url".to_string());
    }
    let path = if upstream_path.trim().is_empty() {
        "/"
    } else {
        upstream_path
    };
    let mut url = format!("{base}/{}", path.trim_start_matches('/'));
    if path == "/" {
        url = format!("{base}/");
    }
    let query = raw_query.trim_start_matches('?');
    if !query.is_empty() {
        url.push('?');
        url.push_str(query);
    }
    Ok(url)
}

fn upstream_forwarded_headers(
    request: &SubscriptionProxyInboundRequest,
) -> BTreeMap<String, String> {
    let mut headers = forwarded_headers(&request.headers);
    if !request.host.trim().is_empty() {
        headers.insert(
            "X-Forwarded-Host".to_string(),
            request.host.trim().to_string(),
        );
    }
    headers.insert("X-Forwarded-Proto".to_string(), "https".to_string());
    if let Some(ip) = client_ip(&request.remote_addr) {
        append_forwarded_for(&mut headers, &ip);
    }
    headers
}

pub fn plan_subscription_proxy_http_request(
    config: &SubscriptionProxyConfig,
    request: &SubscriptionProxyInboundRequest,
) -> Result<SubscriptionProxyRoute, SubscriptionProxyRouteError> {
    let method = request.method.trim().to_ascii_uppercase();
    if method != "GET" && method != "HEAD" {
        return Err(SubscriptionProxyRouteError::MethodNotAllowed);
    }

    if request.path == "/health" {
        return Ok(SubscriptionProxyRoute::Health);
    }

    let Some(name) = request
        .path
        .strip_prefix("/.well-known/pki-validation/")
        .and_then(challenge_request_file_name)
    else {
        return Err(SubscriptionProxyRouteError::NotFound);
    };
    let challenge_dir = first_non_empty(config.challenge_dir.trim(), DEFAULT_CHALLENGE_DIR);
    Ok(SubscriptionProxyRoute::ChallengeFile(join_posix_path(
        &challenge_dir,
        &name,
    )))
}

pub fn plan_subscription_proxy_http_server(
    config: &SubscriptionProxyConfig,
) -> Option<SubscriptionProxyHttpServerPlan> {
    let listen = config.http_listen.trim();
    if listen.is_empty() {
        return None;
    }
    Some(SubscriptionProxyHttpServerPlan {
        listen: listen.to_string(),
        challenge_dir: first_non_empty(config.challenge_dir.trim(), DEFAULT_CHALLENGE_DIR),
    })
}

pub fn plan_subscription_proxy_main_server(
    config: &SubscriptionProxyConfig,
    mode: SubscriptionProxyServeMode,
) -> SubscriptionProxyMainServerPlan {
    SubscriptionProxyMainServerPlan {
        listen: first_non_empty(config.https_listen.trim(), DEFAULT_HTTPS_LISTEN),
        mode,
        cert_file: config.cert_file.trim().to_string(),
        key_file: config.key_file.trim().to_string(),
        max_response_bytes: if config.max_response_bytes == 0 {
            DEFAULT_MAX_RESPONSE_BYTES
        } else {
            config.max_response_bytes
        },
        profiles: config.profiles.clone(),
        website_profiles: config.website_profiles.clone(),
    }
}

pub fn spawn_subscription_proxy_main_http_fallback_server(
    plan: SubscriptionProxyMainServerPlan,
) -> Result<SubscriptionProxyServerHandle, String> {
    if plan.mode != SubscriptionProxyServeMode::HttpFallback {
        return Err(
            "subscription proxy main server only supports HTTP fallback in this runtime"
                .to_string(),
        );
    }
    let listen = plan.listen.clone();
    let profiles = plan.profiles.clone();
    let website_profiles = plan.website_profiles.clone();
    let max_response_bytes = plan.max_response_bytes;
    spawn_subscription_proxy_blocking_server(listen, move |request| {
        handle_subscription_proxy_request(
            &profiles,
            &website_profiles,
            &request,
            max_response_bytes,
            |upstream| fetch_subscription_proxy_upstream_blocking(upstream, max_response_bytes),
        )
        .unwrap_or_else(|err| subscription_proxy_error_response(&err))
    })
}

pub fn spawn_subscription_proxy_main_https_server(
    plan: SubscriptionProxyMainServerPlan,
) -> Result<SubscriptionProxyServerHandle, String> {
    if plan.mode != SubscriptionProxyServeMode::Https {
        return Err("subscription proxy HTTPS server requires https mode".to_string());
    }
    let tls_config = Arc::new(load_subscription_proxy_tls_config(
        &plan.cert_file,
        &plan.key_file,
    )?);
    let listen = plan.listen.clone();
    let profiles = plan.profiles.clone();
    let website_profiles = plan.website_profiles.clone();
    let max_response_bytes = plan.max_response_bytes;
    spawn_subscription_proxy_tls_blocking_server(listen, tls_config, move |request| {
        handle_subscription_proxy_request(
            &profiles,
            &website_profiles,
            &request,
            max_response_bytes,
            |upstream| fetch_subscription_proxy_upstream_blocking(upstream, max_response_bytes),
        )
        .unwrap_or_else(|err| subscription_proxy_error_response(&err))
    })
}

pub fn spawn_subscription_proxy_http_challenge_server(
    config: SubscriptionProxyConfig,
) -> Result<Option<SubscriptionProxyServerHandle>, String> {
    let Some(plan) = plan_subscription_proxy_http_server(&config) else {
        return Ok(None);
    };
    let mut config = config;
    config.challenge_dir = plan.challenge_dir;
    let listen = plan.listen;
    spawn_subscription_proxy_blocking_server(listen, move |request| {
        handle_subscription_proxy_http_request(
            &config,
            &request,
            read_subscription_proxy_file_optional,
        )
        .unwrap_or_else(|err| subscription_proxy_error_response(&err))
    })
    .map(Some)
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
    rewrite: Option<&WebsiteProxyRewriteContext>,
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

    let (headers, set_cookie_headers) = rewrite_response_headers(
        forwarded_headers(&response.headers),
        response.set_cookie_headers,
        rewrite,
    );

    Ok(SubscriptionProxyClientResponse {
        status: response.status,
        headers,
        set_cookie_headers,
        body: if head_only { Vec::new() } else { response.body },
    })
}

pub fn fetch_subscription_proxy_upstream_blocking(
    request: &SubscriptionProxyUpstreamRequest,
    max_response_bytes: u64,
) -> Result<SubscriptionProxyUpstreamResponse, SubscriptionProxyRouteError> {
    let max_response_bytes = if max_response_bytes == 0 {
        DEFAULT_MAX_RESPONSE_BYTES
    } else {
        max_response_bytes
    };
    let redirect_policy = if request.follow_redirects {
        reqwest::redirect::Policy::limited(5)
    } else {
        reqwest::redirect::Policy::none()
    };
    let client = reqwest::blocking::Client::builder()
        .redirect(redirect_policy)
        .build()
        .map_err(|err| SubscriptionProxyRouteError::BadGateway(err.to_string()))?;
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|err| SubscriptionProxyRouteError::BadGateway(err.to_string()))?;
    let mut builder = client.request(method, &request.url);
    for (key, value) in &request.headers {
        let name = reqwest::header::HeaderName::from_bytes(key.as_bytes())
            .map_err(|err| SubscriptionProxyRouteError::BadGateway(err.to_string()))?;
        let value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|err| SubscriptionProxyRouteError::BadGateway(err.to_string()))?;
        builder = builder.header(name, value);
    }
    if !request.body.is_empty() {
        builder = builder.body(request.body.clone());
    }

    let response = builder
        .send()
        .map_err(|err| SubscriptionProxyRouteError::BadGateway(err.to_string()))?;
    let status = response.status().as_u16();
    let content_length = response.content_length();
    if content_length
        .map(|length| length > max_response_bytes)
        .unwrap_or(false)
    {
        return Err(SubscriptionProxyRouteError::BadGateway(
            "upstream response too large".to_string(),
        ));
    }
    let set_cookie_headers = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(|value| value.to_string()))
        .collect();
    let headers = response
        .headers()
        .iter()
        .filter(|(key, _)| !key.as_str().eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(key, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (key.as_str().to_string(), value.to_string()))
        })
        .collect();
    let body = if request.head_only {
        Vec::new()
    } else {
        read_limited_upstream_body(response, max_response_bytes)
            .map_err(SubscriptionProxyRouteError::BadGateway)?
    };

    Ok(SubscriptionProxyUpstreamResponse {
        status,
        headers,
        set_cookie_headers,
        body,
        content_length,
    })
}

pub fn handle_subscription_proxy_request<F>(
    profiles: &[SubscriptionProxyProfile],
    website_profiles: &[WebsiteProxyProfile],
    request: &SubscriptionProxyInboundRequest,
    max_response_bytes: u64,
    mut fetch_upstream: F,
) -> Result<SubscriptionProxyClientResponse, SubscriptionProxyRouteError>
where
    F: FnMut(
        &SubscriptionProxyUpstreamRequest,
    ) -> Result<SubscriptionProxyUpstreamResponse, SubscriptionProxyRouteError>,
{
    let head_only = request.method.trim().eq_ignore_ascii_case("HEAD");
    match plan_subscription_proxy_request(profiles, website_profiles, request)? {
        SubscriptionProxyRoute::Health => Ok(plan_subscription_proxy_health_response(head_only)),
        SubscriptionProxyRoute::Upstream(upstream) => {
            let head_only = upstream.head_only;
            let response = fetch_upstream(&upstream)?;
            plan_subscription_proxy_response(
                response,
                max_response_bytes,
                head_only,
                upstream.response_rewrite.as_ref(),
            )
        }
        SubscriptionProxyRoute::ChallengeFile(_) => Err(SubscriptionProxyRouteError::NotFound),
    }
}

pub fn handle_subscription_proxy_http_request<F>(
    config: &SubscriptionProxyConfig,
    request: &SubscriptionProxyInboundRequest,
    mut read_file: F,
) -> Result<SubscriptionProxyClientResponse, SubscriptionProxyRouteError>
where
    F: FnMut(&str) -> Result<Option<Vec<u8>>, String>,
{
    let head_only = request.method.trim().eq_ignore_ascii_case("HEAD");
    match plan_subscription_proxy_http_request(config, request)? {
        SubscriptionProxyRoute::Health => Ok(plan_subscription_proxy_health_response(head_only)),
        SubscriptionProxyRoute::ChallengeFile(path) => {
            let Some(body) = read_file(&path).map_err(SubscriptionProxyRouteError::BadGateway)?
            else {
                return Err(SubscriptionProxyRouteError::NotFound);
            };
            let mut headers = BTreeMap::new();
            headers.insert(
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            );
            Ok(SubscriptionProxyClientResponse {
                status: 200,
                headers,
                set_cookie_headers: Vec::new(),
                body: if head_only { Vec::new() } else { body },
            })
        }
        SubscriptionProxyRoute::Upstream(_) => Err(SubscriptionProxyRouteError::NotFound),
    }
}

pub fn plan_subscription_proxy_health_response(head_only: bool) -> SubscriptionProxyClientResponse {
    let mut headers = BTreeMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    SubscriptionProxyClientResponse {
        status: 200,
        headers,
        set_cookie_headers: Vec::new(),
        body: if head_only {
            Vec::new()
        } else {
            br#"{"status":"ok"}"#.to_vec()
        },
    }
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
    let cert_not_after = subscription_proxy_cert_not_after(
        cert_file,
        &config.zerossl.expires_at,
        &mut certificate_not_after,
    );
    let mut status = SubscriptionProxyStatus {
        certificate_domain: certificate_domain.to_string(),
        certificate_id: config.zerossl.certificate_id.trim().to_string(),
        cert_not_after,
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

pub fn prepare_subscription_proxy_certificate_status_with_file_writes<F, G, H, I>(
    config: &SubscriptionProxyConfig,
    mut certificate_not_after: F,
    mut ensure_csr: G,
    mut file_readable: H,
    mut write_file: I,
) -> SubscriptionProxyStatus
where
    F: FnMut(&str) -> String,
    G: FnMut(&str, &str) -> Result<String, String>,
    H: FnMut(&str) -> bool,
    I: FnMut(&SubscriptionProxyFileWrite) -> Result<(), String>,
{
    let cert_file = config.cert_file.trim();
    let key_file = config.key_file.trim();
    let certificate_domain = config.certificate_domain.trim();
    let cert_not_after = subscription_proxy_cert_not_after(
        cert_file,
        &config.zerossl.expires_at,
        &mut certificate_not_after,
    );
    let mut status = SubscriptionProxyStatus {
        certificate_domain: certificate_domain.to_string(),
        certificate_id: config.zerossl.certificate_id.trim().to_string(),
        cert_not_after,
        ..SubscriptionProxyStatus::default()
    };

    match plan_subscription_proxy_validation_file(config) {
        Ok(Some(write)) => match write_file(&write) {
            Ok(()) => status.validation_ready = true,
            Err(err) => status.last_error = err,
        },
        Ok(None) => {}
        Err(err) => status.last_error = err,
    }

    match plan_subscription_proxy_certificate_file(config) {
        Ok(Some(write)) => match write_file(&write) {
            Ok(()) => {
                status.cert_not_after = subscription_proxy_cert_not_after(
                    cert_file,
                    &config.zerossl.expires_at,
                    &mut certificate_not_after,
                )
            }
            Err(err) => status.last_error = err,
        },
        Ok(None) => {}
        Err(err) => status.last_error = err,
    }

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

pub fn plan_subscription_proxy_validation_file(
    config: &SubscriptionProxyConfig,
) -> Result<Option<SubscriptionProxyFileWrite>, String> {
    let validation_path = config.zerossl.validation_path.trim();
    let validation_content = config.zerossl.validation_content.trim();
    if validation_path.is_empty() || validation_content.is_empty() {
        return Ok(None);
    }

    let file_name = validation_file_name(validation_path)
        .ok_or_else(|| format!("invalid validation path: {validation_path}"))?;
    let challenge_dir = first_non_empty(config.challenge_dir.trim(), DEFAULT_CHALLENGE_DIR);
    Ok(Some(SubscriptionProxyFileWrite {
        path: join_posix_path(&challenge_dir, &file_name),
        content: validation_content_string(validation_content),
        mode: 0o644,
    }))
}

pub fn plan_subscription_proxy_certificate_file(
    config: &SubscriptionProxyConfig,
) -> Result<Option<SubscriptionProxyFileWrite>, String> {
    let certificate = config.zerossl.certificate_pem.trim();
    if certificate.is_empty() {
        return Ok(None);
    }
    let cert_file = config.cert_file.trim();
    if cert_file.is_empty() {
        return Err("subscription proxy cert file is empty".to_string());
    }

    let ca_bundle = config.zerossl.ca_bundle_pem.trim();
    let mut fullchain = certificate.to_string();
    if !ca_bundle.is_empty() {
        fullchain.push('\n');
        fullchain.push_str(ca_bundle);
    }
    fullchain.push('\n');

    Ok(Some(SubscriptionProxyFileWrite {
        path: cert_file.to_string(),
        content: fullchain,
        mode: 0o644,
    }))
}

pub fn plan_subscription_proxy_csr(
    key_file: &str,
    certificate_domain: &str,
    key_exists: bool,
) -> Result<SubscriptionProxyCsrPlan, String> {
    let key_file = key_file.trim();
    if key_file.is_empty() {
        return Err("subscription proxy key file is empty".to_string());
    }
    let common_name = normalize_certificate_name(certificate_domain)?;
    let subject_alt_name = certificate_subject_alt_name(&common_name)?;

    Ok(SubscriptionProxyCsrPlan {
        key_file: key_file.to_string(),
        common_name,
        subject_alt_name,
        generate_key: !key_exists,
    })
}

pub fn ensure_subscription_proxy_csr_with_openssl(
    key_file: &str,
    certificate_domain: &str,
) -> Result<String, String> {
    let plan = plan_subscription_proxy_csr(
        key_file,
        certificate_domain,
        subscription_proxy_file_readable(key_file),
    )?;
    if plan.generate_key {
        create_subscription_proxy_key_parent(&plan.key_file)?;
        run_openssl(&[
            "genrsa".to_string(),
            "-out".to_string(),
            plan.key_file.clone(),
            "2048".to_string(),
        ])?;
        set_subscription_proxy_file_mode(Path::new(&plan.key_file), 0o600)?;
    }

    let output = run_openssl(&[
        "req".to_string(),
        "-new".to_string(),
        "-sha256".to_string(),
        "-batch".to_string(),
        "-key".to_string(),
        plan.key_file,
        "-subj".to_string(),
        format!("/CN={}", plan.common_name),
        "-addext".to_string(),
        format!("subjectAltName={}", plan.subject_alt_name),
    ])?;
    String::from_utf8(output).map_err(|err| format!("decode openssl csr output: {err}"))
}

pub fn write_subscription_proxy_file(write: &SubscriptionProxyFileWrite) -> Result<(), String> {
    let path = Path::new(write.path.trim());
    if path.as_os_str().is_empty() {
        return Err("subscription proxy file path is empty".to_string());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|err| {
                format!("create subscription proxy dir {}: {err}", parent.display())
            })?;
        }
    }
    fs::write(path, write.content.as_bytes())
        .map_err(|err| format!("write subscription proxy file {}: {err}", path.display()))?;
    set_subscription_proxy_file_mode(path, write.mode)?;
    Ok(())
}

pub fn subscription_proxy_file_readable(path: &str) -> bool {
    let path = path.trim();
    if path.is_empty() {
        return false;
    }
    fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

pub fn plan_subscription_proxy_apply<F>(
    config: &SubscriptionProxyConfig,
    current_fingerprint: &str,
    certificate_status: SubscriptionProxyStatus,
    mut file_readable: F,
) -> SubscriptionProxyApplyPlan
where
    F: FnMut(&str) -> bool,
{
    if !config.enabled || (config.profiles.is_empty() && config.website_profiles.is_empty()) {
        return SubscriptionProxyApplyPlan {
            action: SubscriptionProxyApplyAction::Disabled,
            fingerprint: String::new(),
            status: SubscriptionProxyStatus {
                status: "disabled".to_string(),
                enabled: false,
                running: false,
                mode: "disabled".to_string(),
                ..SubscriptionProxyStatus::default()
            },
            serve_mode: None,
            profiles: Vec::new(),
            website_profiles: Vec::new(),
        };
    }

    let fingerprint = subscription_proxy_fingerprint(config);
    if !current_fingerprint.is_empty() && current_fingerprint == fingerprint {
        return SubscriptionProxyApplyPlan {
            action: SubscriptionProxyApplyAction::Unchanged,
            fingerprint,
            status: certificate_status,
            serve_mode: None,
            profiles: config.profiles.clone(),
            website_profiles: config.website_profiles.clone(),
        };
    }

    let certificate_owner_site_id = subscription_proxy_certificate_owner_site_id(&config.profiles);
    match plan_subscription_proxy_serve_mode(config, &mut file_readable) {
        Ok(serve_mode) => {
            let mode = match serve_mode {
                SubscriptionProxyServeMode::Https => "https",
                SubscriptionProxyServeMode::HttpFallback => "http",
            };
            let mut status = SubscriptionProxyStatus {
                status: "running".to_string(),
                enabled: true,
                running: true,
                mode: mode.to_string(),
                https_listen: config.https_listen.trim().to_string(),
                profiles: config.profiles.len(),
                website_profiles: config.website_profiles.len(),
                certificate_owner_site_id,
                ..SubscriptionProxyStatus::default()
            };
            merge_subscription_proxy_status(&mut status, &certificate_status);
            SubscriptionProxyApplyPlan {
                action: SubscriptionProxyApplyAction::Start,
                fingerprint,
                status,
                serve_mode: Some(serve_mode),
                profiles: config.profiles.clone(),
                website_profiles: config.website_profiles.clone(),
            }
        }
        Err(err) => {
            let mut status = SubscriptionProxyStatus {
                status: "error".to_string(),
                enabled: true,
                running: false,
                mode: "error".to_string(),
                https_listen: config.https_listen.trim().to_string(),
                profiles: config.profiles.len(),
                website_profiles: config.website_profiles.len(),
                certificate_owner_site_id,
                last_error: err,
                ..SubscriptionProxyStatus::default()
            };
            merge_subscription_proxy_status(&mut status, &certificate_status);
            SubscriptionProxyApplyPlan {
                action: SubscriptionProxyApplyAction::Error,
                fingerprint,
                status,
                serve_mode: None,
                profiles: config.profiles.clone(),
                website_profiles: config.website_profiles.clone(),
            }
        }
    }
}

pub fn subscription_proxy_fingerprint(config: &SubscriptionProxyConfig) -> String {
    let mut parts = vec![
        config.https_listen.trim().to_string(),
        config.http_listen.trim().to_string(),
        config.cert_file.trim().to_string(),
        config.key_file.trim().to_string(),
        config.certificate_domain.trim().to_string(),
        config.challenge_dir.trim().to_string(),
        config.zerossl.certificate_id.trim().to_string(),
        config.zerossl.validation_path.trim().to_string(),
        config.zerossl.validation_content.trim().to_string(),
        config.zerossl.certificate_pem.trim().to_string(),
        config.zerossl.ca_bundle_pem.trim().to_string(),
        config.allow_http_fallback.to_string(),
        config.max_response_bytes.to_string(),
    ];
    let mut profiles = config.profiles.clone();
    profiles.sort_by(|left, right| left.site_id.cmp(&right.site_id));
    for profile in profiles {
        parts.push(profile.site_id.trim().to_string());
        parts.push(profile.upstream_base_url.trim_end_matches('/').to_string());
        parts.push(profile.subscribe_path.trim_matches('/').to_string());
    }
    let mut website_profiles = config.website_profiles.clone();
    website_profiles.sort_by(|left, right| {
        left.path_prefix
            .cmp(&right.path_prefix)
            .then_with(|| left.site_id.cmp(&right.site_id))
    });
    for profile in website_profiles {
        parts.push(profile.site_id.trim().to_string());
        parts.push(profile.upstream_base_url.trim_end_matches('/').to_string());
        parts.push(normalize_proxy_path_prefix(&profile.path_prefix));
    }
    parts.join("\0")
}

fn merge_subscription_proxy_status(
    target: &mut SubscriptionProxyStatus,
    source: &SubscriptionProxyStatus,
) {
    if !source.certificate_domain.is_empty() {
        target.certificate_domain = source.certificate_domain.clone();
    }
    if !source.certificate_owner_site_id.is_empty() {
        target.certificate_owner_site_id = source.certificate_owner_site_id.clone();
    }
    if !source.certificate_id.is_empty() {
        target.certificate_id = source.certificate_id.clone();
    }
    target.need_certificate = source.need_certificate;
    target.csr_pem = source.csr_pem.clone();
    target.validation_ready = source.validation_ready;
    if !source.cert_not_after.is_empty() {
        target.cert_not_after = source.cert_not_after.clone();
    }
    if !source.last_error.is_empty() {
        target.last_error = source.last_error.clone();
    }
}

fn subscription_proxy_cert_not_after<F>(
    cert_file: &str,
    expires_at: &str,
    certificate_not_after: &mut F,
) -> String
where
    F: FnMut(&str) -> String,
{
    first_non_empty(certificate_not_after(cert_file).trim(), expires_at.trim())
}

fn normalize_certificate_name(value: &str) -> Result<String, String> {
    let name = value.trim();
    if name.is_empty() {
        return Err("subscription proxy certificate domain is empty".to_string());
    }
    if name
        .chars()
        .any(|character| character.is_control() || matches!(character, '/' | ',' | '\\'))
    {
        return Err(format!(
            "invalid subscription proxy certificate domain: {name}"
        ));
    }
    Ok(name.to_string())
}

fn certificate_subject_alt_name(name: &str) -> Result<String, String> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok(format!("IP:{ip}"));
    }
    if !is_valid_dns_certificate_name(name) {
        return Err(format!(
            "invalid subscription proxy certificate domain: {name}"
        ));
    }
    Ok(format!("DNS:{name}"))
}

fn is_valid_dns_certificate_name(name: &str) -> bool {
    let name = name.trim().trim_start_matches("*.");
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn create_subscription_proxy_key_parent(key_file: &str) -> Result<(), String> {
    let path = Path::new(key_file);
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create subscription proxy key dir {}: {err}",
            parent.display()
        )
    })
}

fn run_openssl(args: &[String]) -> Result<Vec<u8>, String> {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .map_err(|err| format!("run openssl: {err}"))?;
    if output.status.success() {
        return Ok(output.stdout);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let detail = if stderr.is_empty() {
        format!("exit status {}", output.status)
    } else {
        stderr
    };
    Err(format!("openssl {} failed: {detail}", args.join(" ")))
}

fn spawn_subscription_proxy_blocking_server<F>(
    listen: String,
    handler: F,
) -> Result<SubscriptionProxyServerHandle, String>
where
    F: Fn(SubscriptionProxyInboundRequest) -> SubscriptionProxyClientResponse
        + Send
        + Sync
        + 'static,
{
    let listener = TcpListener::bind(&listen)
        .map_err(|err| format!("bind subscription proxy server {listen}: {err}"))?;
    let bound_listen = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| listen.clone());
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("set subscription proxy server nonblocking {listen}: {err}"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handler = Arc::new(handler);
    let join = thread::spawn(move || {
        serve_subscription_proxy_listener(listener, thread_stop, handler);
    });
    Ok(SubscriptionProxyServerHandle {
        listen: bound_listen,
        stop,
        join: Some(join),
    })
}

fn spawn_subscription_proxy_tls_blocking_server<F>(
    listen: String,
    tls_config: Arc<rustls::ServerConfig>,
    handler: F,
) -> Result<SubscriptionProxyServerHandle, String>
where
    F: Fn(SubscriptionProxyInboundRequest) -> SubscriptionProxyClientResponse
        + Send
        + Sync
        + 'static,
{
    let listener = TcpListener::bind(&listen)
        .map_err(|err| format!("bind subscription proxy HTTPS server {listen}: {err}"))?;
    let bound_listen = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| listen.clone());
    listener.set_nonblocking(true).map_err(|err| {
        format!("set subscription proxy HTTPS server nonblocking {listen}: {err}")
    })?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handler = Arc::new(handler);
    let join = thread::spawn(move || {
        serve_subscription_proxy_tls_listener(listener, thread_stop, tls_config, handler);
    });
    Ok(SubscriptionProxyServerHandle {
        listen: bound_listen,
        stop,
        join: Some(join),
    })
}

fn serve_subscription_proxy_listener<F>(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    handler: Arc<F>,
) where
    F: Fn(SubscriptionProxyInboundRequest) -> SubscriptionProxyClientResponse
        + Send
        + Sync
        + 'static,
{
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let handler = Arc::clone(&handler);
                thread::spawn(move || {
                    let _ = serve_subscription_proxy_stream(stream, handler);
                });
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return,
        }
    }
}

fn serve_subscription_proxy_tls_listener<F>(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    tls_config: Arc<rustls::ServerConfig>,
    handler: Arc<F>,
) where
    F: Fn(SubscriptionProxyInboundRequest) -> SubscriptionProxyClientResponse
        + Send
        + Sync
        + 'static,
{
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let handler = Arc::clone(&handler);
                let tls_config = Arc::clone(&tls_config);
                thread::spawn(move || {
                    let _ = serve_subscription_proxy_tls_stream(stream, tls_config, handler);
                });
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return,
        }
    }
}

fn serve_subscription_proxy_stream<F>(mut stream: TcpStream, handler: Arc<F>) -> Result<(), String>
where
    F: Fn(SubscriptionProxyInboundRequest) -> SubscriptionProxyClientResponse,
{
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let remote_addr = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_default();
    let response = match read_subscription_proxy_http_request(
        &mut stream,
        32 * 1024,
        DEFAULT_MAX_REQUEST_BODY_BYTES as usize,
    )
    .and_then(|raw| parse_subscription_proxy_http_request(&raw, &remote_addr))
    {
        Ok(request) => handler(request),
        Err(err) => subscription_proxy_bad_request_response(&err),
    };
    let bytes = render_subscription_proxy_http_response(&response);
    stream
        .write_all(&bytes)
        .map_err(|err| format!("write subscription proxy response: {err}"))?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn serve_subscription_proxy_tls_stream<F>(
    stream: TcpStream,
    tls_config: Arc<rustls::ServerConfig>,
    handler: Arc<F>,
) -> Result<(), String>
where
    F: Fn(SubscriptionProxyInboundRequest) -> SubscriptionProxyClientResponse,
{
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let remote_addr = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_default();
    let connection = rustls::ServerConnection::new(tls_config)
        .map_err(|err| format!("create subscription proxy TLS connection: {err}"))?;
    let mut stream = rustls::StreamOwned::new(connection, stream);
    let response = match read_subscription_proxy_http_request(
        &mut stream,
        32 * 1024,
        DEFAULT_MAX_REQUEST_BODY_BYTES as usize,
    )
    .and_then(|raw| parse_subscription_proxy_http_request(&raw, &remote_addr))
    {
        Ok(request) => handler(request),
        Err(err) => subscription_proxy_bad_request_response(&err),
    };
    let bytes = render_subscription_proxy_http_response(&response);
    stream
        .write_all(&bytes)
        .map_err(|err| format!("write subscription proxy HTTPS response: {err}"))?;
    stream
        .flush()
        .map_err(|err| format!("flush subscription proxy HTTPS response: {err}"))?;
    stream.conn.send_close_notify();
    let _ = stream.sock.shutdown(Shutdown::Both);
    Ok(())
}

fn load_subscription_proxy_tls_config(
    cert_file: &str,
    key_file: &str,
) -> Result<rustls::ServerConfig, String> {
    let cert_file = cert_file.trim();
    let key_file = key_file.trim();
    if cert_file.is_empty() || key_file.is_empty() {
        return Err("subscription proxy HTTPS requires cert_file and key_file".to_string());
    }

    let certs = load_subscription_proxy_certs(cert_file)?;
    let key = load_subscription_proxy_private_key(key_file)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| format!("configure subscription proxy TLS versions: {err}"))?;
    let mut config = builder
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| format!("load subscription proxy TLS certificate: {err}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn load_subscription_proxy_certs(
    cert_file: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let file = fs::File::open(cert_file)
        .map_err(|err| format!("open subscription proxy cert file {cert_file}: {err}"))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("parse subscription proxy cert file {cert_file}: {err}"))?;
    if certs.is_empty() {
        return Err(format!(
            "subscription proxy cert file {cert_file} has no certificates"
        ));
    }
    Ok(certs)
}

fn load_subscription_proxy_private_key(
    key_file: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let file = fs::File::open(key_file)
        .map_err(|err| format!("open subscription proxy key file {key_file}: {err}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|err| format!("parse subscription proxy key file {key_file}: {err}"))?
        .ok_or_else(|| format!("subscription proxy key file {key_file} has no private key"))
}

fn read_subscription_proxy_http_request_head<R: Read>(
    mut reader: R,
    max_header_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|err| format!("read subscription proxy request: {err}"))?;
        if read == 0 {
            return Err("incomplete http request".to_string());
        }
        output.extend_from_slice(&chunk[..read]);
        if output.len() > max_header_bytes {
            return Err("http request header too large".to_string());
        }
        if output.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(output);
        }
    }
}

fn read_subscription_proxy_http_request<R: Read>(
    mut reader: R,
    max_header_bytes: usize,
    max_body_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut raw = read_subscription_proxy_http_request_head(&mut reader, max_header_bytes)?;
    let Some(header_end) = http_header_end(&raw) else {
        return Err("incomplete http request".to_string());
    };
    let content_length = request_content_length(&raw[..header_end])?;
    let body_start = header_end + 4;
    let already_read = raw.len().saturating_sub(body_start);

    if content_length.is_none() && request_has_chunked_body(&raw[..header_end]) {
        return Err("chunked request bodies are not supported".to_string());
    }

    let Some(content_length) = content_length else {
        raw.truncate(body_start);
        return Ok(raw);
    };
    if content_length > max_body_bytes {
        return Err("http request body too large".to_string());
    }
    if already_read > content_length {
        raw.truncate(body_start + content_length);
        return Ok(raw);
    }

    let remaining = content_length - already_read;
    if remaining == 0 {
        return Ok(raw);
    }
    let mut body = vec![0u8; remaining];
    reader
        .read_exact(&mut body)
        .map_err(|err| format!("read subscription proxy request body: {err}"))?;
    raw.extend_from_slice(&body);
    Ok(raw)
}

fn read_subscription_proxy_file_optional(path: &str) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(content) => Ok(Some(content)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("read subscription proxy file {path}: {err}")),
    }
}

fn read_limited_upstream_body<R: Read>(
    reader: R,
    max_response_bytes: u64,
) -> Result<Vec<u8>, String> {
    let max_response_bytes = if max_response_bytes == 0 {
        DEFAULT_MAX_RESPONSE_BYTES
    } else {
        max_response_bytes
    };
    let mut reader = reader.take(max_response_bytes.saturating_add(1));
    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .map_err(|err| format!("read upstream response: {err}"))?;
    if body.len() as u64 > max_response_bytes {
        return Err("upstream response too large".to_string());
    }
    Ok(body)
}

fn http_reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        502 => "Bad Gateway",
        _ => "OK",
    }
}

fn valid_http_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
            )
        })
}

fn valid_http_header_value(value: &str) -> bool {
    !value.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
}

fn http_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn request_content_length(head: &[u8]) -> Result<Option<usize>, String> {
    let text = std::str::from_utf8(head).map_err(|_| "invalid utf-8 request".to_string())?;
    let mut length = None;
    for line in text.split("\r\n").skip(1) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("content-length") {
            continue;
        }
        let parsed = value
            .trim()
            .parse::<usize>()
            .map_err(|_| "invalid content-length header".to_string())?;
        if length.map(|existing| existing != parsed).unwrap_or(false) {
            return Err("conflicting content-length headers".to_string());
        }
        length = Some(parsed);
    }
    Ok(length)
}

fn request_has_chunked_body(head: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    text.split("\r\n").skip(1).any(|line| {
        let Some((key, value)) = line.split_once(':') else {
            return false;
        };
        key.trim().eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
    })
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

fn normalize_proxy_path_prefix(value: &str) -> String {
    let value = value.trim().trim_end_matches('/');
    if value.is_empty() || value == "/" {
        return "/".to_string();
    }
    if value.starts_with('/') {
        value.to_string()
    } else {
        format!("/{value}")
    }
}

fn join_posix_path(root: &str, child: &str) -> String {
    format!(
        "{}/{}",
        root.trim_end_matches('/'),
        child.trim_start_matches('/')
    )
}

fn validation_file_name(path: &str) -> Option<String> {
    let cleaned = path.trim().trim_end_matches('/');
    let name = cleaned.rsplit('/').next()?.trim();
    if name.is_empty() || name == "." || name == ".." || name.contains('\\') {
        return None;
    }
    Some(name.to_string())
}

fn challenge_request_file_name(path: &str) -> Option<String> {
    let name = path.trim();
    if name.is_empty() || name.contains('/') || name.contains("..") || name.contains('\\') {
        return None;
    }
    Some(name.to_string())
}

fn validation_content_string(content: &str) -> String {
    format!("{}\n", content.trim())
}

#[cfg(unix)]
fn set_subscription_proxy_file_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("chmod subscription proxy file {}: {err}", path.display()))
}

#[cfg(not(unix))]
fn set_subscription_proxy_file_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
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
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(*byte as char)
            }
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
            let hi =
                hex_value(bytes[index + 1]).ok_or_else(|| "invalid escaped token".to_string())?;
            let lo =
                hex_value(bytes[index + 2]).ok_or_else(|| "invalid escaped token".to_string())?;
            output.push((hi << 4) | lo);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| "invalid escaped token".to_string())
}

fn is_allowed_website_proxy_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    )
}

fn website_proxy_match<'a>(
    profiles: &'a [WebsiteProxyProfile],
    request_path: &str,
) -> Option<(&'a WebsiteProxyProfile, String, String)> {
    let request_path = if request_path.is_empty() {
        "/"
    } else {
        request_path
    };
    profiles
        .iter()
        .filter_map(|profile| {
            let prefix = normalize_proxy_path_prefix(&profile.path_prefix);
            if !website_proxy_path_matches(&prefix, request_path) {
                return None;
            }
            let upstream_path = website_proxy_upstream_path(&prefix, request_path);
            Some((profile, prefix, upstream_path))
        })
        .max_by_key(|(_, prefix, _)| prefix.len())
}

fn website_proxy_path_matches(prefix: &str, request_path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    request_path == prefix
        || request_path
            .strip_prefix(prefix)
            .map(|rest| rest.starts_with('/'))
            .unwrap_or(false)
}

fn website_proxy_upstream_path(prefix: &str, request_path: &str) -> String {
    if prefix == "/" {
        return if request_path.is_empty() {
            "/".to_string()
        } else {
            request_path.to_string()
        };
    }
    let stripped = request_path.strip_prefix(prefix).unwrap_or(request_path);
    if stripped.is_empty() {
        "/".to_string()
    } else if stripped.starts_with('/') {
        stripped.to_string()
    } else {
        format!("/{stripped}")
    }
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
        .filter(|(key, _)| {
            !is_hop_by_hop_header(key)
                && !key.eq_ignore_ascii_case("host")
                && !key.eq_ignore_ascii_case("content-length")
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn rewrite_response_headers(
    mut headers: BTreeMap<String, String>,
    extra_set_cookie_headers: Vec<String>,
    rewrite: Option<&WebsiteProxyRewriteContext>,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut set_cookie_headers = extra_set_cookie_headers;
    let cookie_keys = headers
        .keys()
        .filter(|key| key.eq_ignore_ascii_case("set-cookie"))
        .cloned()
        .collect::<Vec<_>>();
    for key in cookie_keys {
        if let Some(value) = headers.remove(&key) {
            set_cookie_headers.push(value);
        }
    }

    let Some(rewrite) = rewrite else {
        return (headers, set_cookie_headers);
    };
    for (key, value) in headers.iter_mut() {
        if key.eq_ignore_ascii_case("location") {
            *value = rewrite_website_location(value, rewrite);
        }
    }
    let set_cookie_headers = set_cookie_headers
        .into_iter()
        .map(|value| rewrite_website_set_cookie(&value, rewrite))
        .collect();
    (headers, set_cookie_headers)
}

fn rewrite_website_location(value: &str, rewrite: &WebsiteProxyRewriteContext) -> String {
    let base = trim_trailing_slashes(rewrite.upstream_base_url.trim());
    let prefix = normalize_proxy_path_prefix(&rewrite.proxy_path_prefix);
    let value = value.trim();
    if let Some(rest) = value.strip_prefix(&base) {
        if rest.is_empty() || rest.starts_with('/') || rest.starts_with('?') {
            return prefixed_proxy_path(&prefix, &first_non_empty(rest, "/"));
        }
    }
    if value.starts_with('/') {
        return prefixed_proxy_path(&prefix, value);
    }
    value.to_string()
}

fn rewrite_website_set_cookie(value: &str, rewrite: &WebsiteProxyRewriteContext) -> String {
    let prefix = normalize_proxy_path_prefix(&rewrite.proxy_path_prefix);
    let mut parts = value.split(';');
    let Some(first) = parts.next() else {
        return value.to_string();
    };
    let mut output = vec![first.trim().to_string()];
    let mut has_path = false;
    for part in parts {
        let trimmed = part.trim();
        if trimmed.eq_ignore_ascii_case("domain") || starts_with_header_attr(trimmed, "domain") {
            continue;
        }
        if starts_with_header_attr(trimmed, "path") {
            has_path = true;
            if prefix != "/" {
                output.push(format!("Path={prefix}"));
            } else {
                output.push(trimmed.to_string());
            }
            continue;
        }
        output.push(trimmed.to_string());
    }
    if prefix != "/" && !has_path {
        output.push(format!("Path={prefix}"));
    }
    output.join("; ")
}

fn starts_with_header_attr(value: &str, name: &str) -> bool {
    value
        .get(..name.len())
        .map(|prefix| prefix.eq_ignore_ascii_case(name))
        .unwrap_or(false)
        && value
            .as_bytes()
            .get(name.len())
            .map(|byte| *byte == b'=')
            .unwrap_or(false)
}

fn prefixed_proxy_path(prefix: &str, path: &str) -> String {
    let path = if path.trim().is_empty() { "/" } else { path };
    if path.starts_with('?') {
        return if prefix == "/" {
            format!("/{path}")
        } else {
            format!("{prefix}{path}")
        };
    }
    if prefix == "/" {
        if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        }
    } else if path == "/" {
        prefix.to_string()
    } else {
        format!(
            "{}/{}",
            prefix.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

fn append_forwarded_for(headers: &mut BTreeMap<String, String>, ip: &str) {
    let ip = ip.trim();
    if ip.is_empty() {
        return;
    }

    let existing_key = headers
        .keys()
        .find(|key| key.eq_ignore_ascii_case("X-Forwarded-For"))
        .cloned()
        .unwrap_or_else(|| "X-Forwarded-For".to_string());
    let existing = headers
        .get(&existing_key)
        .map(|value| value.trim())
        .unwrap_or("");
    let value = if existing.is_empty() {
        ip.to_string()
    } else {
        format!("{existing}, {ip}")
    };
    headers.insert(existing_key, value);
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
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::Path;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        build_subscription_upstream_url, build_website_upstream_url,
        handle_subscription_proxy_http_request, handle_subscription_proxy_request,
        normalize_subscription_proxy_config, normalize_subscription_proxy_config_with_public_ipv4,
        parse_subscription_proxy_http_request, plan_subscription_proxy_apply,
        plan_subscription_proxy_certificate_file, plan_subscription_proxy_csr,
        plan_subscription_proxy_health_response, plan_subscription_proxy_http_request,
        plan_subscription_proxy_http_server, plan_subscription_proxy_main_server,
        plan_subscription_proxy_request, plan_subscription_proxy_response,
        plan_subscription_proxy_serve_mode, plan_subscription_proxy_validation_file,
        prepare_subscription_proxy_certificate_status,
        prepare_subscription_proxy_certificate_status_with_file_writes, read_limited_upstream_body,
        read_subscription_proxy_http_request, read_subscription_proxy_http_request_head,
        render_subscription_proxy_http_response, resolve_subscription_certificate_domain,
        spawn_subscription_proxy_http_challenge_server,
        spawn_subscription_proxy_main_http_fallback_server,
        spawn_subscription_proxy_main_https_server, subscription_proxy_certificate_owner_site_id,
        subscription_proxy_error_response, subscription_proxy_file_readable,
        subscription_proxy_fingerprint, write_subscription_proxy_file,
        SubscriptionProxyApplyAction, SubscriptionProxyClientResponse, SubscriptionProxyFileWrite,
        SubscriptionProxyInboundRequest, SubscriptionProxyMainServerPlan, SubscriptionProxyRoute,
        SubscriptionProxyRouteError, SubscriptionProxyRuntimeManager, SubscriptionProxyServeMode,
        SubscriptionProxyStatus, SubscriptionProxyUpstreamResponse, WebsiteProxyRewriteContext,
        DEFAULT_CHALLENGE_DIR, DEFAULT_HTTPS_LISTEN, DEFAULT_MAX_RESPONSE_BYTES,
    };
    use crate::config::{
        SubscriptionProxyConfig, SubscriptionProxyProfile, SubscriptionProxyZeroSslConfig,
        WebsiteProxyProfile,
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
        assert_eq!(
            config.profiles[0].upstream_base_url,
            "https://panel.example.test"
        );
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
    fn certificate_status_falls_back_to_zerossl_expiry_when_cert_date_unavailable() {
        let status = prepare_subscription_proxy_certificate_status(
            &SubscriptionProxyConfig {
                cert_file: "/etc/v2node/fullchain.pem".to_string(),
                zerossl: SubscriptionProxyZeroSslConfig {
                    expires_at: "2026-07-01T00:00:00Z".to_string(),
                    ..SubscriptionProxyZeroSslConfig::default()
                },
                ..SubscriptionProxyConfig::default()
            },
            |_| " ".to_string(),
            |_, _| Ok("csr".to_string()),
            |_| true,
        );

        assert_eq!(status.cert_not_after, "2026-07-01T00:00:00Z");
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
    fn plans_validation_file_write_from_zerossl_challenge() {
        let write = plan_subscription_proxy_validation_file(&SubscriptionProxyConfig {
            challenge_dir: " /var/lib/v2node/challenges/ ".to_string(),
            zerossl: SubscriptionProxyZeroSslConfig {
                validation_path: "/.well-known/pki-validation/token.txt".to_string(),
                validation_content: " challenge-token ".to_string(),
                ..SubscriptionProxyZeroSslConfig::default()
            },
            ..SubscriptionProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(write.path, "/var/lib/v2node/challenges/token.txt");
        assert_eq!(write.content, "challenge-token\n");
        assert_eq!(write.mode, 0o644);
    }

    #[test]
    fn skips_or_rejects_invalid_validation_file_plans() {
        let none = plan_subscription_proxy_validation_file(&SubscriptionProxyConfig {
            zerossl: SubscriptionProxyZeroSslConfig {
                validation_path: "/.well-known/pki-validation/token.txt".to_string(),
                ..SubscriptionProxyZeroSslConfig::default()
            },
            ..SubscriptionProxyConfig::default()
        })
        .unwrap();
        assert!(none.is_none());

        let err = plan_subscription_proxy_validation_file(&SubscriptionProxyConfig {
            zerossl: SubscriptionProxyZeroSslConfig {
                validation_path: "/".to_string(),
                validation_content: "challenge-token".to_string(),
                ..SubscriptionProxyZeroSslConfig::default()
            },
            ..SubscriptionProxyConfig::default()
        })
        .unwrap_err();
        assert!(err.contains("invalid validation path"));
    }

    #[test]
    fn plans_certificate_fullchain_write_from_zerossl_payload() {
        let write = plan_subscription_proxy_certificate_file(&SubscriptionProxyConfig {
            cert_file: " /etc/v2node/fullchain.pem ".to_string(),
            zerossl: SubscriptionProxyZeroSslConfig {
                certificate_pem: " -----BEGIN CERTIFICATE-----\nleaf ".to_string(),
                ca_bundle_pem: " -----BEGIN CERTIFICATE-----\nca ".to_string(),
                ..SubscriptionProxyZeroSslConfig::default()
            },
            ..SubscriptionProxyConfig::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(write.path, "/etc/v2node/fullchain.pem");
        assert_eq!(
            write.content,
            "-----BEGIN CERTIFICATE-----\nleaf\n-----BEGIN CERTIFICATE-----\nca\n"
        );
        assert_eq!(write.mode, 0o644);
    }

    #[test]
    fn certificate_file_plan_requires_cert_path_only_when_payload_exists() {
        let none =
            plan_subscription_proxy_certificate_file(&SubscriptionProxyConfig::default()).unwrap();
        assert!(none.is_none());

        let err = plan_subscription_proxy_certificate_file(&SubscriptionProxyConfig {
            zerossl: SubscriptionProxyZeroSslConfig {
                certificate_pem: "-----BEGIN CERTIFICATE-----".to_string(),
                ..SubscriptionProxyZeroSslConfig::default()
            },
            ..SubscriptionProxyConfig::default()
        })
        .unwrap_err();
        assert!(err.contains("cert file is empty"));
    }

    #[test]
    fn plans_subscription_proxy_csr_for_dns_and_ip_domains() {
        let dns = plan_subscription_proxy_csr(
            "/etc/v2node/subproxy/private.key",
            "sub.example.test",
            false,
        )
        .unwrap();
        assert!(dns.generate_key);
        assert_eq!(dns.common_name, "sub.example.test");
        assert_eq!(dns.subject_alt_name, "DNS:sub.example.test");

        let ipv6 = plan_subscription_proxy_csr(
            "/etc/v2node/subproxy/private.key",
            "2607:f358:1a:e::d4d9:5831",
            true,
        )
        .unwrap();
        assert!(!ipv6.generate_key);
        assert_eq!(ipv6.subject_alt_name, "IP:2607:f358:1a:e::d4d9:5831");
    }

    #[test]
    fn rejects_invalid_subscription_proxy_csr_inputs() {
        let err = plan_subscription_proxy_csr("", "sub.example.test", true).unwrap_err();
        assert!(err.contains("key file is empty"));

        let err =
            plan_subscription_proxy_csr("/etc/v2node/private.key", "bad/name", true).unwrap_err();
        assert!(err.contains("invalid subscription proxy certificate domain"));

        let err = plan_subscription_proxy_csr("/etc/v2node/private.key", "-bad.example.test", true)
            .unwrap_err();
        assert!(err.contains("invalid subscription proxy certificate domain"));
    }

    #[test]
    fn prepares_certificate_status_with_file_write_executor() {
        let writes = RefCell::new(Vec::new());
        let status = prepare_subscription_proxy_certificate_status_with_file_writes(
            &SubscriptionProxyConfig {
                cert_file: "/etc/v2node/fullchain.pem".to_string(),
                key_file: "/etc/v2node/private.key".to_string(),
                certificate_domain: "sub.example.test".to_string(),
                challenge_dir: "/var/lib/v2node/challenges".to_string(),
                zerossl: SubscriptionProxyZeroSslConfig {
                    certificate_id: "cert-1".to_string(),
                    validation_path: "/.well-known/pki-validation/token.txt".to_string(),
                    validation_content: "challenge-token".to_string(),
                    certificate_pem: "-----BEGIN CERTIFICATE-----\nleaf".to_string(),
                    ca_bundle_pem: "-----BEGIN CERTIFICATE-----\nca".to_string(),
                    ..SubscriptionProxyZeroSslConfig::default()
                },
                ..SubscriptionProxyConfig::default()
            },
            |path| format!("not-after:{path}"),
            |_, _| Ok("csr".to_string()),
            |_| false,
            |write| {
                writes.borrow_mut().push(write.clone());
                Ok(())
            },
        );

        assert!(status.validation_ready);
        assert!(status.need_certificate);
        assert_eq!(status.certificate_id, "cert-1");
        assert_eq!(status.cert_not_after, "not-after:/etc/v2node/fullchain.pem");
        assert_eq!(status.csr_pem, "csr");
        assert!(status.last_error.is_empty());
        assert_eq!(writes.borrow().len(), 2);
        assert_eq!(
            writes.borrow()[0].path,
            "/var/lib/v2node/challenges/token.txt"
        );
        assert_eq!(writes.borrow()[1].path, "/etc/v2node/fullchain.pem");
    }

    #[test]
    fn certificate_status_file_write_falls_back_to_zerossl_expiry() {
        let status = prepare_subscription_proxy_certificate_status_with_file_writes(
            &SubscriptionProxyConfig {
                cert_file: "/etc/v2node/fullchain.pem".to_string(),
                zerossl: SubscriptionProxyZeroSslConfig {
                    certificate_pem: "-----BEGIN CERTIFICATE-----\nleaf".to_string(),
                    expires_at: "2026-07-02T00:00:00Z".to_string(),
                    ..SubscriptionProxyZeroSslConfig::default()
                },
                ..SubscriptionProxyConfig::default()
            },
            |_| String::new(),
            |_, _| Ok("csr".to_string()),
            |_| true,
            |_| Ok(()),
        );

        assert_eq!(status.cert_not_after, "2026-07-02T00:00:00Z");
    }

    #[test]
    fn writes_subscription_proxy_file_and_parent_dir() {
        let dir = temp_test_dir("subscription-proxy-write");
        let path = dir.join("nested").join("token.txt");
        write_subscription_proxy_file(&SubscriptionProxyFileWrite {
            path: path.to_string_lossy().to_string(),
            content: "challenge-token\n".to_string(),
            mode: 0o644,
        })
        .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "challenge-token\n");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn detects_readable_subscription_proxy_files() {
        let dir = temp_test_dir("subscription-proxy-readable");
        let path = dir.join("token.txt");
        fs::write(&path, "ok").unwrap();

        assert!(subscription_proxy_file_readable(&path.to_string_lossy()));
        assert!(!subscription_proxy_file_readable(""));
        assert!(!subscription_proxy_file_readable(&dir.to_string_lossy()));
        assert!(!subscription_proxy_file_readable(
            &dir.join("missing.txt").to_string_lossy()
        ));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn subscription_proxy_fingerprint_is_stable_for_profile_order() {
        let mut left = SubscriptionProxyConfig {
            https_listen: "0.0.0.0:443".to_string(),
            cert_file: "/etc/v2node/fullchain.pem".to_string(),
            zerossl: SubscriptionProxyZeroSslConfig {
                certificate_id: "cert-1".to_string(),
                validation_content: "challenge".to_string(),
                ..SubscriptionProxyZeroSslConfig::default()
            },
            profiles: vec![
                SubscriptionProxyProfile {
                    site_id: "site-b".to_string(),
                    upstream_base_url: "https://b.example.test/".to_string(),
                    subscribe_path: "/s/".to_string(),
                },
                SubscriptionProxyProfile {
                    site_id: "site-a".to_string(),
                    upstream_base_url: "https://a.example.test".to_string(),
                    subscribe_path: "answer/land".to_string(),
                },
            ],
            ..SubscriptionProxyConfig::default()
        };
        let mut right = left.clone();
        right.profiles.reverse();

        assert_eq!(
            subscription_proxy_fingerprint(&left),
            subscription_proxy_fingerprint(&right)
        );

        left.zerossl.certificate_pem = "new cert".to_string();
        assert_ne!(
            subscription_proxy_fingerprint(&left),
            subscription_proxy_fingerprint(&right)
        );
    }

    #[test]
    fn apply_plan_disables_empty_proxy() {
        let plan = plan_subscription_proxy_apply(
            &SubscriptionProxyConfig::default(),
            "",
            SubscriptionProxyStatus::default(),
            |_| false,
        );

        assert_eq!(plan.action, SubscriptionProxyApplyAction::Disabled);
        assert_eq!(plan.status.status, "disabled");
        assert_eq!(plan.status.mode, "disabled");
        assert!(plan.profiles.is_empty());
    }

    #[test]
    fn apply_plan_skips_unchanged_fingerprint() {
        let config = normalized_proxy_for_apply();
        let fingerprint = subscription_proxy_fingerprint(&config);

        let plan = plan_subscription_proxy_apply(
            &config,
            &fingerprint,
            SubscriptionProxyStatus {
                certificate_domain: "proxy.example.test".to_string(),
                ..SubscriptionProxyStatus::default()
            },
            |_| true,
        );

        assert_eq!(plan.action, SubscriptionProxyApplyAction::Unchanged);
        assert_eq!(plan.fingerprint, fingerprint);
        assert_eq!(plan.status.certificate_domain, "proxy.example.test");
    }

    #[test]
    fn apply_plan_starts_with_http_fallback_when_cert_files_missing() {
        let mut config = normalized_proxy_for_apply();
        config.allow_http_fallback = true;
        let plan = plan_subscription_proxy_apply(
            &config,
            "",
            SubscriptionProxyStatus {
                certificate_domain: "proxy.example.test".to_string(),
                need_certificate: true,
                csr_pem: "csr".to_string(),
                ..SubscriptionProxyStatus::default()
            },
            |_| false,
        );

        assert_eq!(plan.action, SubscriptionProxyApplyAction::Start);
        assert_eq!(
            plan.serve_mode,
            Some(SubscriptionProxyServeMode::HttpFallback)
        );
        assert_eq!(plan.status.status, "running");
        assert_eq!(plan.status.mode, "http");
        assert_eq!(plan.status.certificate_owner_site_id, "site-a");
        assert!(plan.status.need_certificate);
        assert_eq!(plan.status.csr_pem, "csr");
    }

    #[test]
    fn apply_plan_reports_error_when_cert_files_missing_without_fallback() {
        let config = normalized_proxy_for_apply();
        let plan = plan_subscription_proxy_apply(
            &config,
            "",
            SubscriptionProxyStatus {
                last_error: "csr failed".to_string(),
                ..SubscriptionProxyStatus::default()
            },
            |_| false,
        );

        assert_eq!(plan.action, SubscriptionProxyApplyAction::Error);
        assert_eq!(plan.status.status, "error");
        assert_eq!(plan.status.mode, "error");
        assert_eq!(plan.status.last_error, "csr failed");
        assert_eq!(plan.status.certificate_owner_site_id, "site-a");
    }

    #[test]
    fn runtime_manager_tracks_start_and_unchanged_status() {
        let mut manager = SubscriptionProxyRuntimeManager::new();
        let mut config = normalized_proxy_for_apply();
        config.allow_http_fallback = true;

        let first = manager
            .apply(
                &config,
                |_| String::new(),
                |_, _| Ok("csr".to_string()),
                |_| false,
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(first.action, SubscriptionProxyApplyAction::Start);
        assert_eq!(first.status.mode, "http");
        assert_eq!(manager.status().csr_pem, "csr");
        assert!(!manager.fingerprint().is_empty());

        let second = manager
            .apply(
                &config,
                |_| String::new(),
                |_, _| Ok("new csr".to_string()),
                |_| false,
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(second.action, SubscriptionProxyApplyAction::Unchanged);
        assert_eq!(manager.status().status, "running");
        assert_eq!(manager.status().mode, "http");
        assert_eq!(manager.status().csr_pem, "new csr");
    }

    #[test]
    fn runtime_manager_disables_and_clears_fingerprint() {
        let mut manager = SubscriptionProxyRuntimeManager::new();
        let mut config = normalized_proxy_for_apply();
        config.allow_http_fallback = true;

        manager
            .apply(
                &config,
                |_| String::new(),
                |_, _| Ok("csr".to_string()),
                |_| false,
                |_| Ok(()),
            )
            .unwrap();
        assert!(!manager.fingerprint().is_empty());

        let plan = manager
            .apply(
                &SubscriptionProxyConfig::default(),
                |_| String::new(),
                |_, _| Ok("csr".to_string()),
                |_| false,
                |_| Ok(()),
            )
            .unwrap();

        assert_eq!(plan.action, SubscriptionProxyApplyAction::Disabled);
        assert!(manager.fingerprint().is_empty());
        assert_eq!(manager.status().status, "disabled");
    }

    #[test]
    fn runtime_manager_can_apply_with_real_file_system_helpers() {
        let dir = temp_test_dir("subscription-proxy-manager-fs");
        let cert_file = dir.join("fullchain.pem");
        let key_file = dir.join("private.key");
        fs::write(&key_file, "key").unwrap();

        let mut config = normalized_proxy_for_apply();
        config.cert_file = cert_file.to_string_lossy().to_string();
        config.key_file = key_file.to_string_lossy().to_string();
        config.challenge_dir = dir.join("challenges").to_string_lossy().to_string();
        config.zerossl.validation_path = "/.well-known/pki-validation/token.txt".to_string();
        config.zerossl.validation_content = "challenge-token".to_string();
        config.zerossl.certificate_pem = "-----BEGIN CERTIFICATE-----\nleaf".to_string();

        let mut manager = SubscriptionProxyRuntimeManager::new();
        let plan = manager
            .apply_with_file_system(&config, |_, _| Ok("csr".to_string()))
            .unwrap();

        assert_eq!(plan.action, SubscriptionProxyApplyAction::Start);
        assert_eq!(plan.serve_mode, Some(SubscriptionProxyServeMode::Https));
        assert_eq!(manager.status().csr_pem, "csr");
        assert!(dir.join("challenges").join("token.txt").is_file());
        assert!(cert_file.is_file());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_manager_start_boundary_runs_https_server() {
        let dir = temp_test_dir("subscription-proxy-manager-https-boundary");
        let cert_file = dir.join("fullchain.pem");
        let key_file = dir.join("private.key");
        write_test_certificate_pair(&cert_file, &key_file);

        let mut config = normalized_proxy_for_apply();
        config.https_listen = "127.0.0.1:0".to_string();
        config.cert_file = cert_file.to_string_lossy().to_string();
        config.key_file = key_file.to_string_lossy().to_string();
        let mut manager = SubscriptionProxyRuntimeManager::new();

        let plan = manager
            .apply_and_start_with_file_system(&config, |_, _| Ok("csr".to_string()))
            .unwrap();

        assert_eq!(plan.action, SubscriptionProxyApplyAction::Start);
        assert_eq!(plan.serve_mode, Some(SubscriptionProxyServeMode::Https));
        assert_eq!(manager.status().status, "running");
        assert_eq!(manager.status().mode, "https");
        assert!(manager.status().running);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn subscription_proxy_https_server_serves_health() {
        let dir = temp_test_dir("subscription-proxy-https-server");
        let cert_file = dir.join("fullchain.pem");
        let key_file = dir.join("private.key");
        write_test_certificate_pair(&cert_file, &key_file);
        let mut config = normalized_proxy_for_apply();
        config.https_listen = "127.0.0.1:0".to_string();
        config.cert_file = cert_file.to_string_lossy().to_string();
        config.key_file = key_file.to_string_lossy().to_string();
        let plan = plan_subscription_proxy_main_server(&config, SubscriptionProxyServeMode::Https);

        let server = spawn_subscription_proxy_main_https_server(plan).unwrap();
        let response = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .no_proxy()
            .build()
            .unwrap()
            .get(format!("https://{}/health", server.listen()))
            .send()
            .unwrap();

        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.text().unwrap(), r#"{"status":"ok"}"#);

        server.stop();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn certificate_status_records_file_write_errors() {
        let status = prepare_subscription_proxy_certificate_status_with_file_writes(
            &SubscriptionProxyConfig {
                certificate_domain: "sub.example.test".to_string(),
                challenge_dir: "/var/lib/v2node/challenges".to_string(),
                zerossl: SubscriptionProxyZeroSslConfig {
                    validation_path: "/.well-known/pki-validation/token.txt".to_string(),
                    validation_content: "challenge-token".to_string(),
                    ..SubscriptionProxyZeroSslConfig::default()
                },
                ..SubscriptionProxyConfig::default()
            },
            |_| String::new(),
            |_, _| Ok("csr".to_string()),
            |_| false,
            |_| Err("write failed".to_string()),
        );

        assert_eq!(status.last_error, "write failed");
        assert!(!status.validation_ready);
        assert_eq!(status.csr_pem, "csr");
        assert!(status.need_certificate);
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
    fn normalizes_website_proxy_profiles_and_enables_shared_gateway() {
        let config = normalize_subscription_proxy_config(&SubscriptionProxyConfig {
            website_profiles: vec![
                WebsiteProxyProfile {
                    site_id: " site-a ".to_string(),
                    upstream_base_url: " https://panel.example.test/ ".to_string(),
                    path_prefix: " shop/ ".to_string(),
                },
                WebsiteProxyProfile {
                    site_id: "site-a".to_string(),
                    upstream_base_url: "https://ignored.example.test".to_string(),
                    path_prefix: "/shop".to_string(),
                },
            ],
            ..SubscriptionProxyConfig::default()
        })
        .unwrap();

        assert!(config.enabled);
        assert!(config.profiles.is_empty());
        assert_eq!(config.website_profiles.len(), 1);
        assert_eq!(config.website_profiles[0].site_id, "site-a");
        assert_eq!(
            config.website_profiles[0].upstream_base_url,
            "https://panel.example.test"
        );
        assert_eq!(config.website_profiles[0].path_prefix, "/shop");
    }

    #[test]
    fn builds_website_upstream_url() {
        let url = build_website_upstream_url(
            &WebsiteProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test/root/".to_string(),
                path_prefix: "/site/site-a".to_string(),
            },
            "/admin/login",
            "?redirect=/cart",
        )
        .unwrap();

        assert_eq!(
            url,
            "https://panel.example.test/root/admin/login?redirect=/cart"
        );
    }

    #[test]
    fn plans_health_request() {
        let route = plan_subscription_proxy_request(
            &[],
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
    fn plans_health_response_like_go_handler() {
        let response = plan_subscription_proxy_health_response(false);
        assert_eq!(response.status, 200);
        assert_eq!(response.headers["Content-Type"], "application/json");
        assert_eq!(response.body, br#"{"status":"ok"}"#.to_vec());

        let response = plan_subscription_proxy_health_response(true);
        assert!(response.body.is_empty());
    }

    #[test]
    fn plans_http_challenge_file_request() {
        let route = plan_subscription_proxy_http_request(
            &SubscriptionProxyConfig {
                challenge_dir: "/var/lib/v2node/challenges".to_string(),
                ..SubscriptionProxyConfig::default()
            },
            &SubscriptionProxyInboundRequest {
                method: "HEAD".to_string(),
                path: "/.well-known/pki-validation/token.txt".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
        )
        .unwrap();

        assert_eq!(
            route,
            SubscriptionProxyRoute::ChallengeFile(
                "/var/lib/v2node/challenges/token.txt".to_string()
            )
        );
    }

    #[test]
    fn plans_http_server_only_when_listen_is_configured() {
        assert!(plan_subscription_proxy_http_server(&SubscriptionProxyConfig::default()).is_none());

        let plan = plan_subscription_proxy_http_server(&SubscriptionProxyConfig {
            http_listen: " 0.0.0.0:80 ".to_string(),
            ..SubscriptionProxyConfig::default()
        })
        .unwrap();

        assert_eq!(plan.listen, "0.0.0.0:80");
        assert_eq!(plan.challenge_dir, DEFAULT_CHALLENGE_DIR);
    }

    #[test]
    fn plans_main_server_from_https_listen_even_for_http_fallback() {
        let config = normalize_subscription_proxy_config(&SubscriptionProxyConfig {
            enabled: true,
            https_listen: " 0.0.0.0:8443 ".to_string(),
            cert_file: " /etc/v2node/fullchain.pem ".to_string(),
            key_file: " /etc/v2node/private.key ".to_string(),
            max_response_bytes: 4096,
            profiles: vec![SubscriptionProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test".to_string(),
                subscribe_path: "s".to_string(),
            }],
            ..SubscriptionProxyConfig::default()
        })
        .unwrap();

        let plan =
            plan_subscription_proxy_main_server(&config, SubscriptionProxyServeMode::HttpFallback);

        assert_eq!(plan.listen, "0.0.0.0:8443");
        assert_eq!(plan.mode, SubscriptionProxyServeMode::HttpFallback);
        assert_eq!(plan.cert_file, "/etc/v2node/fullchain.pem");
        assert_eq!(plan.key_file, "/etc/v2node/private.key");
        assert_eq!(plan.max_response_bytes, 4096);
        assert_eq!(plan.profiles.len(), 1);
    }

    #[test]
    fn rejects_invalid_http_challenge_file_request() {
        let err = plan_subscription_proxy_http_request(
            &SubscriptionProxyConfig::default(),
            &SubscriptionProxyInboundRequest {
                method: "POST".to_string(),
                path: "/.well-known/pki-validation/token.txt".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
        )
        .unwrap_err();
        assert_eq!(err.status_code(), 405);

        let err = plan_subscription_proxy_http_request(
            &SubscriptionProxyConfig::default(),
            &SubscriptionProxyInboundRequest {
                method: "GET".to_string(),
                path: "/.well-known/pki-validation/../token.txt".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
        )
        .unwrap_err();
        assert_eq!(err, SubscriptionProxyRouteError::NotFound);
    }

    #[test]
    fn plans_subscription_upstream_request_and_forwarded_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("User-Agent".to_string(), "Hiddify".to_string());
        headers.insert("Connection".to_string(), "close".to_string());
        headers.insert("Host".to_string(), "proxy.example.test".to_string());
        headers.insert("X-Forwarded-For".to_string(), "203.0.113.9".to_string());
        headers.insert("CF-Connecting-IP".to_string(), "203.0.113.9".to_string());
        let route = plan_subscription_proxy_request(
            &[SubscriptionProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test".to_string(),
                subscribe_path: "answer/land".to_string(),
            }],
            &[],
            &SubscriptionProxyInboundRequest {
                method: "HEAD".to_string(),
                path: "/sub/site-a/token%20123".to_string(),
                raw_query: "flag=sing-box".to_string(),
                host: "proxy.example.test".to_string(),
                remote_addr: "198.51.100.8:51234".to_string(),
                headers,
                body: Vec::new(),
            },
        )
        .unwrap();

        let SubscriptionProxyRoute::Upstream(upstream) = route else {
            panic!("expected upstream route");
        };
        assert_eq!(upstream.method, "HEAD");
        assert!(upstream.head_only);
        assert!(upstream.follow_redirects);
        assert_eq!(
            upstream.url,
            "https://panel.example.test/answer/land/token%20123?flag=sing-box"
        );
        assert_eq!(upstream.headers["User-Agent"], "Hiddify");
        assert_eq!(upstream.headers["X-Forwarded-Host"], "proxy.example.test");
        assert_eq!(
            upstream.headers["X-Forwarded-For"],
            "203.0.113.9, 198.51.100.8"
        );
        assert_eq!(upstream.headers["CF-Connecting-IP"], "203.0.113.9");
        assert!(!upstream.headers.contains_key("Connection"));
        assert!(!upstream.headers.contains_key("Host"));
    }

    #[test]
    fn plans_direct_website_proxy_request_with_post_body() {
        let mut headers = BTreeMap::new();
        headers.insert("Host".to_string(), "2.56.116.39".to_string());
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Content-Length".to_string(), "13".to_string());
        headers.insert("Connection".to_string(), "close".to_string());

        let route = plan_subscription_proxy_request(
            &[],
            &[WebsiteProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test".to_string(),
                path_prefix: "/".to_string(),
            }],
            &SubscriptionProxyInboundRequest {
                method: "POST".to_string(),
                path: "/api/order".to_string(),
                raw_query: "plan=1".to_string(),
                host: "2.56.116.39".to_string(),
                remote_addr: "198.51.100.8:51234".to_string(),
                headers,
                body: br#"{"qty":1}"#.to_vec(),
            },
        )
        .unwrap();

        let SubscriptionProxyRoute::Upstream(upstream) = route else {
            panic!("expected upstream route");
        };
        assert_eq!(upstream.method, "POST");
        assert_eq!(upstream.url, "https://panel.example.test/api/order?plan=1");
        assert_eq!(upstream.body, br#"{"qty":1}"#.to_vec());
        assert!(!upstream.follow_redirects);
        assert_eq!(upstream.headers["Content-Type"], "application/json");
        assert_eq!(upstream.headers["X-Forwarded-Host"], "2.56.116.39");
        assert_eq!(upstream.headers["X-Forwarded-Proto"], "https");
        assert_eq!(upstream.headers["X-Forwarded-For"], "198.51.100.8");
        assert!(!upstream.headers.contains_key("Content-Length"));
        assert!(!upstream.headers.contains_key("Connection"));
        assert_eq!(
            upstream.response_rewrite,
            Some(WebsiteProxyRewriteContext {
                upstream_base_url: "https://panel.example.test".to_string(),
                proxy_path_prefix: "/".to_string(),
            })
        );
    }

    #[test]
    fn plans_path_prefixed_website_proxy_request() {
        let route = plan_subscription_proxy_request(
            &[],
            &[WebsiteProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test".to_string(),
                path_prefix: "/site/site-a".to_string(),
            }],
            &SubscriptionProxyInboundRequest {
                method: "GET".to_string(),
                path: "/site/site-a/admin/login".to_string(),
                raw_query: "from=proxy".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
        )
        .unwrap();

        let SubscriptionProxyRoute::Upstream(upstream) = route else {
            panic!("expected upstream route");
        };
        assert_eq!(
            upstream.url,
            "https://panel.example.test/admin/login?from=proxy"
        );
        assert_eq!(
            upstream.response_rewrite,
            Some(WebsiteProxyRewriteContext {
                upstream_base_url: "https://panel.example.test".to_string(),
                proxy_path_prefix: "/site/site-a".to_string(),
            })
        );
    }

    #[test]
    fn subscription_route_takes_precedence_over_root_website_proxy() {
        let route = plan_subscription_proxy_request(
            &[SubscriptionProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test".to_string(),
                subscribe_path: "s".to_string(),
            }],
            &[WebsiteProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://shop.example.test".to_string(),
                path_prefix: "/".to_string(),
            }],
            &SubscriptionProxyInboundRequest {
                method: "GET".to_string(),
                path: "/sub/site-a/token".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
        )
        .unwrap();

        let SubscriptionProxyRoute::Upstream(upstream) = route else {
            panic!("expected upstream route");
        };
        assert_eq!(upstream.url, "https://panel.example.test/s/token");
        assert!(upstream.response_rewrite.is_none());
    }

    #[test]
    fn handles_subscription_proxy_request_with_injected_upstream_fetcher() {
        let response = handle_subscription_proxy_request(
            &[SubscriptionProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test".to_string(),
                subscribe_path: "s".to_string(),
            }],
            &[],
            &SubscriptionProxyInboundRequest {
                method: "GET".to_string(),
                path: "/sub/site-a/token".to_string(),
                raw_query: "flag=sing-box".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
            1024,
            |request| {
                assert_eq!(
                    request.url,
                    "https://panel.example.test/s/token?flag=sing-box"
                );
                Ok(SubscriptionProxyUpstreamResponse {
                    status: 200,
                    body: b"subscription".to_vec(),
                    ..SubscriptionProxyUpstreamResponse::default()
                })
            },
        )
        .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"subscription".to_vec());
    }

    #[test]
    fn handles_website_proxy_request_with_response_rewrite() {
        let response = handle_subscription_proxy_request(
            &[],
            &[WebsiteProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test".to_string(),
                path_prefix: "/site/site-a".to_string(),
            }],
            &SubscriptionProxyInboundRequest {
                method: "GET".to_string(),
                path: "/site/site-a/checkout".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
            1024,
            |request| {
                assert_eq!(request.url, "https://panel.example.test/checkout");
                let mut headers = BTreeMap::new();
                headers.insert(
                    "Location".to_string(),
                    "https://panel.example.test/login".to_string(),
                );
                Ok(SubscriptionProxyUpstreamResponse {
                    status: 302,
                    headers,
                    set_cookie_headers: vec![
                        "session=abc; Domain=panel.example.test; Path=/; HttpOnly".to_string(),
                        "xsrf=token; Domain=panel.example.test; Path=/; SameSite=Lax".to_string(),
                    ],
                    ..SubscriptionProxyUpstreamResponse::default()
                })
            },
        )
        .unwrap();

        assert_eq!(response.status, 302);
        assert_eq!(response.headers["Location"], "/site/site-a/login");
        assert_eq!(
            response.set_cookie_headers,
            vec![
                "session=abc; Path=/site/site-a; HttpOnly".to_string(),
                "xsrf=token; Path=/site/site-a; SameSite=Lax".to_string(),
            ]
        );
    }

    #[test]
    fn handles_subscription_proxy_http_challenge_with_injected_reader() {
        let response = handle_subscription_proxy_http_request(
            &SubscriptionProxyConfig {
                challenge_dir: "/var/lib/v2node/challenges".to_string(),
                ..SubscriptionProxyConfig::default()
            },
            &SubscriptionProxyInboundRequest {
                method: "HEAD".to_string(),
                path: "/.well-known/pki-validation/token.txt".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
            |path| {
                assert_eq!(path, "/var/lib/v2node/challenges/token.txt");
                Ok(Some(b"challenge-token\n".to_vec()))
            },
        )
        .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers["Content-Type"],
            "text/plain; charset=utf-8"
        );
        assert!(response.body.is_empty());

        let err = handle_subscription_proxy_http_request(
            &SubscriptionProxyConfig::default(),
            &SubscriptionProxyInboundRequest {
                method: "GET".to_string(),
                path: "/.well-known/pki-validation/missing.txt".to_string(),
                ..SubscriptionProxyInboundRequest::default()
            },
            |_| Ok(None),
        )
        .unwrap_err();
        assert_eq!(err, SubscriptionProxyRouteError::NotFound);
    }

    #[test]
    fn parses_minimal_http_request_for_subscription_proxy_server() {
        let request = parse_subscription_proxy_http_request(
            b"HEAD /sub/site-a/token?flag=sing-box HTTP/1.1\r\nHost: proxy.example.test\r\nUser-Agent: Keli\r\n\r\n",
            "198.51.100.8:51234",
        )
        .unwrap();

        assert_eq!(request.method, "HEAD");
        assert_eq!(request.path, "/sub/site-a/token");
        assert_eq!(request.raw_query, "flag=sing-box");
        assert_eq!(request.host, "proxy.example.test");
        assert_eq!(request.remote_addr, "198.51.100.8:51234");
        assert_eq!(request.headers["User-Agent"], "Keli");
        assert!(request.body.is_empty());
    }

    #[test]
    fn parses_http_request_body_without_requiring_utf8_body() {
        let request = parse_subscription_proxy_http_request(
            b"POST /api/order HTTP/1.1\r\nHost: proxy.example.test\r\nContent-Length: 3\r\n\r\n\xff\x00\x01",
            "198.51.100.8:51234",
        )
        .unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api/order");
        assert_eq!(request.body, vec![0xff, 0x00, 0x01]);
    }

    #[test]
    fn reads_http_request_head_with_size_limit() {
        let raw = b"GET /health HTTP/1.1\r\nHost: proxy.example.test\r\n\r\n";
        let head =
            read_subscription_proxy_http_request_head(Cursor::new(raw.to_vec()), 1024).unwrap();
        assert_eq!(head, raw);

        let err = read_subscription_proxy_http_request_head(
            Cursor::new(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n".to_vec()),
            8,
        )
        .unwrap_err();
        assert_eq!(err, "http request header too large");
    }

    #[test]
    fn reads_http_request_body_with_size_limit() {
        let raw = b"POST /api/order HTTP/1.1\r\nHost: proxy.example.test\r\nContent-Length: 5\r\n\r\nhello";
        let request =
            read_subscription_proxy_http_request(Cursor::new(raw.to_vec()), 1024, 5).unwrap();
        assert_eq!(request, raw);

        let err =
            read_subscription_proxy_http_request(Cursor::new(raw.to_vec()), 1024, 4).unwrap_err();
        assert_eq!(err, "http request body too large");
    }

    #[test]
    fn renders_http_response_and_route_errors() {
        let mut headers = BTreeMap::new();
        headers.insert("Content-Type".to_string(), "text/plain".to_string());
        headers.insert("Bad\nHeader".to_string(), "ignored".to_string());
        let response = render_subscription_proxy_http_response(&SubscriptionProxyClientResponse {
            status: 200,
            headers,
            set_cookie_headers: vec![
                "session=abc; Path=/; HttpOnly".to_string(),
                "xsrf=token; Path=/".to_string(),
            ],
            body: b"ok".to_vec(),
        });
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.contains("Content-Type: text/plain\r\n"));
        assert!(text.contains("Set-Cookie: session=abc; Path=/; HttpOnly\r\n"));
        assert!(text.contains("Set-Cookie: xsrf=token; Path=/\r\n"));
        assert!(text.ends_with("\r\n\r\nok"));

        let response =
            subscription_proxy_error_response(&SubscriptionProxyRouteError::MethodNotAllowed);
        assert_eq!(response.status, 405);
        assert_eq!(response.body, b"method not allowed\n".to_vec());
    }

    #[test]
    fn server_spawn_boundaries_do_not_fake_https_support() {
        let err =
            spawn_subscription_proxy_main_http_fallback_server(SubscriptionProxyMainServerPlan {
                listen: "127.0.0.1:0".to_string(),
                mode: SubscriptionProxyServeMode::Https,
                cert_file: "/etc/v2node/fullchain.pem".to_string(),
                key_file: "/etc/v2node/private.key".to_string(),
                max_response_bytes: 1024,
                profiles: Vec::new(),
                website_profiles: Vec::new(),
            })
            .unwrap_err();
        assert!(err.contains("only supports HTTP fallback"));

        let handle =
            spawn_subscription_proxy_http_challenge_server(SubscriptionProxyConfig::default())
                .unwrap();
        assert!(handle.is_none());
    }

    #[test]
    fn http_fallback_server_proxies_website_post_and_rewrites_redirects() {
        let (upstream_base_url, upstream_join) = spawn_website_test_upstream();
        let config = normalize_subscription_proxy_config(&SubscriptionProxyConfig {
            enabled: true,
            https_listen: "127.0.0.1:0".to_string(),
            allow_http_fallback: true,
            website_profiles: vec![WebsiteProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: upstream_base_url.clone(),
                path_prefix: "/site/site-a".to_string(),
            }],
            ..SubscriptionProxyConfig::default()
        })
        .unwrap();
        let server = spawn_subscription_proxy_main_http_fallback_server(
            plan_subscription_proxy_main_server(&config, SubscriptionProxyServeMode::HttpFallback),
        )
        .unwrap();

        let mut stream = TcpStream::connect(server.listen()).unwrap();
        stream
            .write_all(
                b"POST /site/site-a/checkout?plan=1 HTTP/1.1\r\nHost: proxy.example.test\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n\r\npayload",
            )
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        server.stop();
        let upstream_request = upstream_join.join().unwrap();

        assert!(upstream_request.starts_with("POST /checkout?plan=1 HTTP/1.1\r\n"));
        assert!(upstream_request
            .to_ascii_lowercase()
            .contains("x-forwarded-host: proxy.example.test\r\n"));
        assert!(upstream_request.ends_with("\r\n\r\npayload"));
        assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
        let response_lower = response.to_ascii_lowercase();
        assert!(response_lower.contains("location: /site/site-a/login\r\n"));
        assert!(response_lower.contains("set-cookie: session=abc; path=/site/site-a; httponly\r\n"));
        assert!(
            response_lower.contains("set-cookie: xsrf=token; path=/site/site-a; samesite=lax\r\n")
        );
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
            &[],
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
            &[],
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
                set_cookie_headers: Vec::new(),
                body: b"ok".to_vec(),
                content_length: Some(2),
            },
            1024,
            false,
            None,
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
            None,
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
            None,
        )
        .unwrap();

        assert!(response.body.is_empty());
    }

    #[test]
    fn reads_limited_upstream_body_without_buffering_oversized_payloads() {
        let body = read_limited_upstream_body(Cursor::new(b"hello".to_vec()), 5).unwrap();
        assert_eq!(body, b"hello");

        let err = read_limited_upstream_body(Cursor::new(b"too-large".to_vec()), 3).unwrap_err();
        assert_eq!(err, "upstream response too large");
    }

    fn temp_test_dir(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("kelinode-rs-{label}-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_test_certificate_pair(cert_file: &Path, key_file: &Path) {
        if let Some(parent) = cert_file.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        fs::write(cert_file, generated.cert.pem()).unwrap();
        fs::write(key_file, generated.key_pair.serialize_pem()).unwrap();
    }

    fn spawn_website_test_upstream() -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let response_base_url = base_url.clone();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = stream.read(&mut chunk).unwrap();
                if read == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..read]);
                let Some(header_end) = raw.windows(4).position(|window| window == b"\r\n\r\n")
                else {
                    continue;
                };
                let head = String::from_utf8_lossy(&raw[..header_end]);
                let content_length = head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if raw.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {response_base_url}/login\r\nSet-Cookie: session=abc; Domain=panel.example.test; Path=/; HttpOnly\r\nSet-Cookie: xsrf=token; Domain=panel.example.test; Path=/; SameSite=Lax\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8(raw).unwrap()
        });
        (base_url, join)
    }

    fn normalized_proxy_for_apply() -> SubscriptionProxyConfig {
        normalize_subscription_proxy_config(&SubscriptionProxyConfig {
            enabled: true,
            https_listen: "0.0.0.0:443".to_string(),
            certificate_domain: "proxy.example.test".to_string(),
            cert_file: "/etc/v2node/fullchain.pem".to_string(),
            key_file: "/etc/v2node/private.key".to_string(),
            profiles: vec![SubscriptionProxyProfile {
                site_id: "site-a".to_string(),
                upstream_base_url: "https://panel.example.test".to_string(),
                subscribe_path: "s".to_string(),
            }],
            ..SubscriptionProxyConfig::default()
        })
        .unwrap()
    }
}
