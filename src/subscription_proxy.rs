use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscriptionProxyCsrPlan {
    pub key_file: String,
    pub common_name: String,
    pub subject_alt_name: String,
    pub generate_key: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionProxyRuntimeManager {
    fingerprint: String,
    status: SubscriptionProxyStatus,
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
    }
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

pub fn fetch_subscription_proxy_upstream_blocking(
    request: &SubscriptionProxyUpstreamRequest,
    max_response_bytes: u64,
) -> Result<SubscriptionProxyUpstreamResponse, SubscriptionProxyRouteError> {
    let max_response_bytes = if max_response_bytes == 0 {
        DEFAULT_MAX_RESPONSE_BYTES
    } else {
        max_response_bytes
    };
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|err| SubscriptionProxyRouteError::BadGateway(err.to_string()))?;
    let mut builder = if request.head_only {
        client.head(&request.url)
    } else {
        client.get(&request.url)
    };
    for (key, value) in &request.headers {
        let name = reqwest::header::HeaderName::from_bytes(key.as_bytes())
            .map_err(|err| SubscriptionProxyRouteError::BadGateway(err.to_string()))?;
        let value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|err| SubscriptionProxyRouteError::BadGateway(err.to_string()))?;
        builder = builder.header(name, value);
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
    let headers = response
        .headers()
        .iter()
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
        body,
        content_length,
    })
}

pub fn plan_subscription_proxy_health_response(head_only: bool) -> SubscriptionProxyClientResponse {
    let mut headers = BTreeMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    SubscriptionProxyClientResponse {
        status: 200,
        headers,
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
    if !config.enabled || config.profiles.is_empty() {
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
        };
    }

    let certificate_owner_site_id =
        subscription_proxy_certificate_owner_site_id(&config.profiles);
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
        return Err(format!("invalid subscription proxy certificate domain: {name}"));
    }
    Ok(name.to_string())
}

fn certificate_subject_alt_name(name: &str) -> Result<String, String> {
    if let Ok(ip) = name.parse::<IpAddr>() {
        return Ok(format!("IP:{ip}"));
    }
    if !is_valid_dns_certificate_name(name) {
        return Err(format!("invalid subscription proxy certificate domain: {name}"));
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
    fs::create_dir_all(parent)
        .map_err(|err| format!("create subscription proxy key dir {}: {err}", parent.display()))
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
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        build_subscription_upstream_url, normalize_subscription_proxy_config,
        normalize_subscription_proxy_config_with_public_ipv4,
        plan_subscription_proxy_health_response, plan_subscription_proxy_http_request,
        plan_subscription_proxy_http_server, plan_subscription_proxy_main_server,
        plan_subscription_proxy_request, plan_subscription_proxy_response,
        plan_subscription_proxy_apply, plan_subscription_proxy_certificate_file,
        plan_subscription_proxy_csr,
        plan_subscription_proxy_serve_mode, plan_subscription_proxy_validation_file,
        prepare_subscription_proxy_certificate_status,
        prepare_subscription_proxy_certificate_status_with_file_writes,
        read_limited_upstream_body,
        resolve_subscription_certificate_domain, subscription_proxy_certificate_owner_site_id,
        subscription_proxy_file_readable, subscription_proxy_fingerprint,
        write_subscription_proxy_file, SubscriptionProxyApplyAction, SubscriptionProxyFileWrite,
        SubscriptionProxyInboundRequest, SubscriptionProxyRoute, SubscriptionProxyRouteError,
        SubscriptionProxyRuntimeManager, SubscriptionProxyServeMode, SubscriptionProxyStatus,
        SubscriptionProxyUpstreamResponse,
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
        let none = plan_subscription_proxy_certificate_file(&SubscriptionProxyConfig::default())
            .unwrap();
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
            plan_subscription_proxy_csr("/etc/v2node/private.key", "bad/name", true)
                .unwrap_err();
        assert!(err.contains("invalid subscription proxy certificate domain"));

        let err = plan_subscription_proxy_csr(
            "/etc/v2node/private.key",
            "-bad.example.test",
            true,
        )
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
        assert_eq!(plan.serve_mode, Some(SubscriptionProxyServeMode::HttpFallback));
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

        let plan = plan_subscription_proxy_main_server(
            &config,
            SubscriptionProxyServeMode::HttpFallback,
        );

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

    #[test]
    fn reads_limited_upstream_body_without_buffering_oversized_payloads() {
        let body = read_limited_upstream_body(Cursor::new(b"hello".to_vec()), 5).unwrap();
        assert_eq!(body, b"hello");

        let err =
            read_limited_upstream_body(Cursor::new(b"too-large".to_vec()), 3).unwrap_err();
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

    fn normalized_proxy_for_apply() -> SubscriptionProxyConfig {
        normalize_subscription_proxy_config(&SubscriptionProxyConfig {
            enabled: true,
            https_listen: "0.0.0.0:443".to_string(),
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
