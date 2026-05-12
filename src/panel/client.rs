use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use reqwest::{Client, Method, RequestBuilder, StatusCode};

use super::contract::{
    CONTENT_TYPE_MSGPACK, HEADER_RESPONSE_FORMAT, PATH_V1_UNIPROXY_ALIVE,
    PATH_V1_UNIPROXY_ALIVE_LIST, PATH_V1_UNIPROXY_PUSH, PATH_V1_UNIPROXY_USER,
    PATH_V1_UNIPROXY_USER_DELTA, PATH_V2_MACHINE_NODES, PATH_V2_MACHINE_STATUS,
    PATH_V2_SERVER_CONFIG, PATH_V2_SERVER_HANDSHAKE, PATH_V2_SERVER_REPORT,
    RESPONSE_FORMAT_MSGPACK,
};
use super::types::{
    AliveMap, CommonNode, NodeInfo, RealtimeBootstrap, UserDeltaBody, UserInfo, UserListBody,
    UserTraffic,
};
use crate::config::{NodeConfig, DEFAULT_TIMEOUT_SECS};
use crate::machine::{
    MachineNodesEnvelope, MachineNodesResponse, MachineStatusPayload, MachineStatusResponse,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PanelClientOptions {
    pub api_host: String,
    pub token: String,
    pub node_id: u32,
    pub machine_id: u32,
    pub timeout: Duration,
    pub config_dir: String,
}

#[derive(Debug)]
pub struct PanelClient {
    client: Client,
    options: PanelClientOptions,
    node_etag: Option<String>,
    user_etag: Option<String>,
}

impl From<&NodeConfig> for PanelClientOptions {
    fn from(config: &NodeConfig) -> Self {
        let timeout = if config.timeout == 0 {
            DEFAULT_TIMEOUT_SECS
        } else {
            config.timeout
        };

        Self {
            api_host: config.url.clone(),
            token: config.token.clone(),
            node_id: config.node_id,
            machine_id: config.machine_id,
            timeout: Duration::from_secs(timeout),
            config_dir: config.config_dir.clone(),
        }
    }
}

impl PanelClient {
    pub fn new(options: PanelClientOptions) -> Result<Self> {
        if options.api_host.trim().is_empty() {
            return Err(anyhow!("api_host is required"));
        }
        if options.token.trim().is_empty() {
            return Err(anyhow!("token is required"));
        }
        if options.node_id == 0 && options.machine_id == 0 {
            return Err(anyhow!("node_id or machine_id is required"));
        }

        let timeout = if options.timeout.is_zero() {
            Duration::from_secs(30)
        } else {
            options.timeout
        };
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .context("build panel http client")?;

        Ok(Self {
            client,
            options,
            node_etag: None,
            user_etag: None,
        })
    }

    pub fn options(&self) -> &PanelClientOptions {
        &self.options
    }

    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.options.api_host.trim_end_matches('/'), path)
    }

    pub async fn get_node_info(&mut self) -> Result<Option<NodeInfo>> {
        let mut request = self.base_request(Method::GET, PATH_V2_SERVER_CONFIG);
        if let Some(etag) = &self.node_etag {
            request = request.header(IF_NONE_MATCH, etag);
        }

        let response = request.send().await.context("request node config")?;
        if response.status() == StatusCode::NOT_MODIFIED {
            self.node_etag = response
                .headers()
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
                .or_else(|| self.node_etag.clone());
            return Ok(None);
        }
        ensure_success(response.status(), "node config")?;
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response.bytes().await.context("read node config")?;
        let common: CommonNode = serde_json::from_slice(&body).context("decode node config")?;
        let node = NodeInfo::from_common_with_config_dir(
            &self.options.api_host,
            self.options.node_id,
            &self.options.config_dir,
            common,
        )
        .map_err(|err| anyhow!(err))?;
        self.node_etag = etag;
        Ok(Some(node))
    }

    pub async fn get_user_list(&mut self) -> Result<Option<Vec<UserInfo>>> {
        let mut request = self
            .base_request(Method::GET, PATH_V1_UNIPROXY_USER)
            .header(HEADER_RESPONSE_FORMAT, RESPONSE_FORMAT_MSGPACK);
        if let Some(etag) = &self.user_etag {
            request = request.header(IF_NONE_MATCH, etag);
        }

        let response = request.send().await.context("request user list")?;
        if response.status() == StatusCode::NOT_MODIFIED {
            self.user_etag = response
                .headers()
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
                .or_else(|| self.user_etag.clone());
            return Ok(None);
        }
        ensure_success(response.status(), "user list")?;
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        let content_type = content_type.map(str::to_string);
        let body = response.bytes().await.context("read user list")?;
        let user_list = decode_user_list_body(&body, content_type.as_deref())?;
        self.user_etag = etag;
        Ok(Some(user_list.users))
    }

    pub async fn get_user_delta(&self, since: i64) -> Result<UserDeltaBody> {
        let response = self
            .base_request(Method::GET, PATH_V1_UNIPROXY_USER_DELTA)
            .query(&[("since", since.to_string())])
            .header(HEADER_RESPONSE_FORMAT, RESPONSE_FORMAT_MSGPACK)
            .send()
            .await
            .context("request user delta")?;
        ensure_success(response.status(), "user delta")?;
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response.bytes().await.context("read user delta")?;
        decode_user_delta_body(&body, content_type.as_deref())
    }

    pub async fn get_alive_list(&self) -> Result<AliveMap> {
        let response = self
            .base_request(Method::GET, PATH_V1_UNIPROXY_ALIVE_LIST)
            .send()
            .await
            .context("request alive list")?;
        ensure_success(response.status(), "alive list")?;
        let body = response.bytes().await.context("read alive list")?;
        serde_json::from_slice(&body).context("decode alive list")
    }

    pub async fn get_realtime_bootstrap(&self) -> Result<Option<RealtimeBootstrap>> {
        let response = self
            .base_request(Method::POST, PATH_V2_SERVER_HANDSHAKE)
            .send()
            .await
            .context("request realtime bootstrap")?;
        if response.status() == StatusCode::NOT_FOUND
            || response.status() == StatusCode::METHOD_NOT_ALLOWED
        {
            return Ok(None);
        }
        ensure_success(response.status(), "realtime bootstrap")?;
        let body = response.bytes().await.context("read realtime bootstrap")?;
        let payload: HandshakeResponse =
            serde_json::from_slice(&body).context("decode realtime bootstrap")?;
        Ok(Some(RealtimeBootstrap {
            enabled: payload.websocket.enabled,
            url: payload.websocket.ws_url.trim().to_string(),
        }))
    }

    pub async fn report_user_traffic(&self, traffic: &[UserTraffic]) -> Result<()> {
        let mut body = BTreeMap::<String, [i64; 2]>::new();
        for row in traffic {
            body.insert(row.uid.to_string(), [row.upload, row.download]);
        }
        let response = self
            .base_request(Method::POST, PATH_V1_UNIPROXY_PUSH)
            .json(&body)
            .send()
            .await
            .context("report user traffic")?;
        ensure_success(response.status(), "report user traffic")
    }

    pub async fn report_snapshot(
        &self,
        traffic: &[UserTraffic],
        online: &BTreeMap<u32, Vec<String>>,
    ) -> Result<bool> {
        let mut traffic_body = BTreeMap::<String, [i64; 2]>::new();
        for row in traffic {
            traffic_body.insert(row.uid.to_string(), [row.upload, row.download]);
        }
        let alive_body = online
            .iter()
            .map(|(uid, ips)| (uid.to_string(), ips.clone()))
            .collect::<BTreeMap<_, _>>();
        let online_body = online
            .iter()
            .map(|(uid, ips)| (uid.to_string(), ips.len()))
            .collect::<BTreeMap<_, _>>();

        let response = self
            .base_request(Method::POST, PATH_V2_SERVER_REPORT)
            .json(&ReportSnapshotBody {
                traffic: traffic_body,
                alive: alive_body,
                online: online_body,
            })
            .send()
            .await
            .context("report snapshot")?;
        if response.status() == StatusCode::NOT_FOUND
            || response.status() == StatusCode::METHOD_NOT_ALLOWED
        {
            return Ok(false);
        }
        ensure_success(response.status(), "report snapshot")?;
        Ok(true)
    }

    pub async fn report_online_users(&self, alive_ips: &BTreeMap<u32, Vec<String>>) -> Result<()> {
        let body = alive_ips
            .iter()
            .map(|(uid, ips)| (uid.to_string(), ips.clone()))
            .collect::<BTreeMap<_, _>>();
        let response = self
            .base_request(Method::POST, PATH_V1_UNIPROXY_ALIVE)
            .json(&body)
            .send()
            .await
            .context("report online users")?;
        ensure_success(response.status(), "report online users")
    }

    pub async fn get_machine_nodes(&self) -> Result<MachineNodesResponse> {
        self.ensure_machine_identity()?;

        let response = self
            .client
            .post(self.endpoint(PATH_V2_MACHINE_NODES))
            .json(&self.machine_identity_body())
            .send()
            .await
            .context("request machine nodes")?;
        ensure_success(response.status(), "machine nodes")?;
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = response.bytes().await.context("read machine nodes")?;
        let envelope: MachineNodesEnvelope = serde_json::from_slice(&body).map_err(|error| {
            anyhow!(
                "decode machine nodes: {error}; content_type={}; body_prefix={}",
                content_type,
                safe_response_preview(&body, &self.options.token)
            )
        })?;
        Ok(envelope.into_response())
    }

    pub async fn report_machine_status(
        &self,
        mut payload: MachineStatusPayload,
    ) -> Result<MachineStatusResponse> {
        self.ensure_machine_identity()?;
        if payload.machine_id == 0 {
            payload.machine_id = self.options.machine_id;
        }

        let body = MachineStatusRequestBody {
            machine_id: payload.machine_id,
            token: self.options.token.clone(),
            status: payload.status,
        };
        let response = self
            .client
            .post(self.endpoint(PATH_V2_MACHINE_STATUS))
            .json(&body)
            .send()
            .await
            .context("report machine status")?;
        ensure_success(response.status(), "machine status")?;
        let body = response.bytes().await.context("read machine status")?;
        if body.iter().all(|byte| byte.is_ascii_whitespace()) {
            return Ok(MachineStatusResponse::default());
        }
        serde_json::from_slice(&body).context("decode machine status")
    }

    fn base_request(&self, method: Method, path: &str) -> RequestBuilder {
        let mut query = vec![
            ("node_type".to_string(), "v2node".to_string()),
            ("node_id".to_string(), self.options.node_id.to_string()),
            ("token".to_string(), self.options.token.clone()),
        ];
        if self.options.machine_id > 0 {
            query.push((
                "machine_id".to_string(),
                self.options.machine_id.to_string(),
            ));
        }

        self.client
            .request(method, self.endpoint(path))
            .query(&query)
    }

    fn ensure_machine_identity(&self) -> Result<()> {
        if self.options.machine_id == 0 {
            return Err(anyhow!("machine_id is required"));
        }
        if self.options.token.trim().is_empty() {
            return Err(anyhow!("token is required"));
        }
        Ok(())
    }

    fn machine_identity_body(&self) -> MachineIdentityBody {
        MachineIdentityBody {
            machine_id: self.options.machine_id,
            token: self.options.token.clone(),
        }
    }
}

#[derive(serde::Serialize)]
struct MachineIdentityBody {
    machine_id: u32,
    token: String,
}

#[derive(serde::Serialize)]
struct MachineStatusRequestBody {
    machine_id: u32,
    token: String,
    status: BTreeMap<String, serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct HandshakeResponse {
    #[serde(default)]
    websocket: HandshakeWebsocket,
}

#[derive(Default, serde::Deserialize)]
struct HandshakeWebsocket {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    ws_url: String,
}

#[derive(serde::Serialize)]
struct ReportSnapshotBody {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    traffic: BTreeMap<String, [i64; 2]>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    alive: BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    online: BTreeMap<String, usize>,
}

fn ensure_success(status: StatusCode, label: &str) -> Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        Err(anyhow!("{label} request failed: {status}"))
    }
}

fn safe_response_preview(body: &[u8], token: &str) -> String {
    const LIMIT: usize = 240;
    let mut text = String::from_utf8_lossy(&body[..body.len().min(LIMIT)]).to_string();
    let token = token.trim();
    if !token.is_empty() {
        text = text.replace(token, "[redacted]");
    }
    text.chars()
        .map(|value| {
            if value.is_control() && !matches!(value, '\n' | '\r' | '\t') {
                ' '
            } else {
                value
            }
        })
        .collect()
}

fn decode_user_list_body(body: &[u8], content_type: Option<&str>) -> Result<UserListBody> {
    if is_msgpack_content_type(content_type) {
        rmp_serde::from_slice(body).context("decode msgpack user list")
    } else {
        serde_json::from_slice(body).context("decode json user list")
    }
}

fn decode_user_delta_body(body: &[u8], content_type: Option<&str>) -> Result<UserDeltaBody> {
    if is_msgpack_content_type(content_type) {
        rmp_serde::from_slice(body).context("decode msgpack user delta")
    } else {
        serde_json::from_slice(body).context("decode json user delta")
    }
}

fn is_msgpack_content_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .map(|value| {
            value == CONTENT_TYPE_MSGPACK
                || value == "application/msgpack"
                || value == "application/vnd.msgpack"
                || value == "application/vnd.msgpack+binary"
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        decode_user_delta_body, decode_user_list_body, is_msgpack_content_type,
        safe_response_preview, PanelClient, PanelClientOptions,
    };
    use crate::panel::contract::{
        PATH_V2_MACHINE_NODES, PATH_V2_SERVER_CONFIG, PATH_V2_SERVER_HANDSHAKE,
        PATH_V2_SERVER_REPORT,
    };
    use crate::panel::types::{UserDeltaBody, UserInfo, UserListBody};

    #[test]
    fn endpoint_joins_trimmed_host_and_path() {
        let client = PanelClient::new(PanelClientOptions {
            api_host: "https://panel.example.test/".to_string(),
            token: "token".to_string(),
            node_id: 1,
            machine_id: 0,
            timeout: Duration::from_secs(1),
            config_dir: "/etc/v2node".to_string(),
        })
        .unwrap();

        assert_eq!(
            client.endpoint(PATH_V2_SERVER_CONFIG),
            "https://panel.example.test/api/v2/server/config"
        );
        assert_eq!(
            client.endpoint(PATH_V2_SERVER_HANDSHAKE),
            "https://panel.example.test/api/v2/server/handshake"
        );
        assert_eq!(
            client.endpoint(PATH_V2_SERVER_REPORT),
            "https://panel.example.test/api/v2/server/report"
        );
    }

    #[test]
    fn validates_identity() {
        let err = PanelClient::new(PanelClientOptions {
            api_host: "https://panel.example.test".to_string(),
            token: String::new(),
            node_id: 1,
            machine_id: 0,
            timeout: Duration::from_secs(1),
            config_dir: "/etc/v2node".to_string(),
        })
        .unwrap_err();

        assert!(err.to_string().contains("token"));
    }

    #[test]
    fn machine_client_allows_machine_only_identity() {
        let client = PanelClient::new(PanelClientOptions {
            api_host: "https://panel.example.test".to_string(),
            token: "token".to_string(),
            node_id: 0,
            machine_id: 3,
            timeout: Duration::from_secs(1),
            config_dir: "/etc/v2node".to_string(),
        })
        .unwrap();

        assert_eq!(
            client.endpoint(PATH_V2_MACHINE_NODES),
            "https://panel.example.test/api/v2/server/machine/nodes"
        );
    }

    #[test]
    fn decodes_json_user_delta_body() {
        let expected = incremental_delta();
        let body = serde_json::to_vec(&expected).expect("encode json");

        let decoded =
            decode_user_delta_body(&body, Some("application/json")).expect("decode json delta");

        assert_eq!(decoded, expected);
    }

    #[test]
    fn decodes_msgpack_user_delta_body() {
        let expected = incremental_delta();
        let body = rmp_serde::to_vec_named(&expected).expect("encode msgpack");

        let decoded = decode_user_delta_body(&body, Some("application/x-msgpack; charset=binary"))
            .expect("decode msgpack delta");

        assert_eq!(decoded, expected);
    }

    #[test]
    fn decodes_empty_and_full_user_delta_bodies() {
        let empty = UserDeltaBody {
            revision: 8,
            ..UserDeltaBody::default()
        };
        let full = UserDeltaBody {
            full: true,
            revision: 9,
            users: vec![user(1, "user-a")],
            deleted: Vec::new(),
            upsert: Vec::new(),
        };

        let empty_body = serde_json::to_vec(&empty).expect("encode empty delta");
        let full_body = rmp_serde::to_vec_named(&full).expect("encode full delta");

        assert_eq!(
            decode_user_delta_body(&empty_body, Some("application/json")).unwrap(),
            empty
        );
        assert_eq!(
            decode_user_delta_body(&full_body, Some("application/msgpack")).unwrap(),
            full
        );
    }

    #[test]
    fn reports_malformed_user_delta_bodies_by_format() {
        let json_err =
            decode_user_delta_body(b"{not-json", Some("application/json")).expect_err("json error");
        let msgpack_err = decode_user_delta_body(b"{not-msgpack", Some("application/x-msgpack"))
            .expect_err("msgpack error");

        assert!(json_err.to_string().contains("decode json user delta"));
        assert!(msgpack_err
            .to_string()
            .contains("decode msgpack user delta"));
    }

    #[test]
    fn decodes_msgpack_user_list_body() {
        let expected = UserListBody {
            users: vec![user(1, "user-a"), user(2, "user-b")],
        };
        let body = rmp_serde::to_vec_named(&expected).expect("encode msgpack list");

        let decoded = decode_user_list_body(&body, Some("application/vnd.msgpack"))
            .expect("decode msgpack list");

        assert_eq!(decoded, expected);
    }

    #[test]
    fn reports_malformed_user_list_bodies_by_format() {
        let json_err =
            decode_user_list_body(b"{not-json", Some("application/json")).expect_err("json error");
        let msgpack_err = decode_user_list_body(b"{not-msgpack", Some("application/msgpack"))
            .expect_err("msgpack error");

        assert!(json_err.to_string().contains("decode json user list"));
        assert!(msgpack_err.to_string().contains("decode msgpack user list"));
    }

    #[test]
    fn safe_response_preview_redacts_token() {
        let preview = safe_response_preview(
            b"{\"message\":\"bad token secret-token value\",\"control\":\"\x01\"}",
            "secret-token",
        );

        assert!(!preview.contains("secret-token"));
        assert!(preview.contains("[redacted]"));
        assert!(!preview.contains('\u{0001}'));
    }

    #[test]
    fn recognizes_msgpack_content_type_aliases() {
        assert!(is_msgpack_content_type(Some("application/x-msgpack")));
        assert!(is_msgpack_content_type(Some(
            "application/msgpack; charset=binary"
        )));
        assert!(is_msgpack_content_type(Some("application/vnd.msgpack")));
        assert!(is_msgpack_content_type(Some(
            "application/vnd.msgpack+binary"
        )));
        assert!(!is_msgpack_content_type(Some("application/json")));
        assert!(!is_msgpack_content_type(None));
    }

    fn incremental_delta() -> UserDeltaBody {
        UserDeltaBody {
            full: false,
            revision: 7,
            users: Vec::new(),
            deleted: vec![user(1, "user-a")],
            upsert: vec![user(2, "user-b")],
        }
    }

    fn user(id: u32, uuid: &str) -> UserInfo {
        UserInfo {
            id,
            uuid: uuid.to_string(),
            speed_limit: id * 10,
            device_limit: id,
        }
    }
}
