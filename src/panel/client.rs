use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use reqwest::{Client, Method, RequestBuilder, StatusCode};

use super::contract::{
    CONTENT_TYPE_MSGPACK, HEADER_RESPONSE_FORMAT, PATH_V1_UNIPROXY_ALIVE,
    PATH_V1_UNIPROXY_ALIVE_LIST, PATH_V1_UNIPROXY_PUSH, PATH_V1_UNIPROXY_USER,
    PATH_V1_UNIPROXY_USER_DELTA, PATH_V2_SERVER_CONFIG, RESPONSE_FORMAT_MSGPACK,
};
use super::types::{
    AliveMap, CommonNode, NodeInfo, UserDeltaBody, UserInfo, UserListBody, UserTraffic,
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
        let node = NodeInfo::from_common(&self.options.api_host, self.options.node_id, common)
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
        let is_msgpack = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.contains(CONTENT_TYPE_MSGPACK))
            .unwrap_or(false);
        let body = response.bytes().await.context("read user list")?;
        let user_list: UserListBody = if is_msgpack {
            rmp_serde::from_slice(&body).context("decode msgpack user list")?
        } else {
            serde_json::from_slice(&body).context("decode json user list")?
        };
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
        let body = response.bytes().await.context("read user delta")?;
        serde_json::from_slice(&body).context("decode user delta")
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

    fn base_request(&self, method: Method, path: &str) -> RequestBuilder {
        let mut query = vec![
            ("node_type".to_string(), "v2node".to_string()),
            ("node_id".to_string(), self.options.node_id.to_string()),
            ("token".to_string(), self.options.token.clone()),
        ];
        if self.options.machine_id > 0 {
            query.push(("machine_id".to_string(), self.options.machine_id.to_string()));
        }

        self.client.request(method, self.endpoint(path)).query(&query)
    }
}

fn ensure_success(status: StatusCode, label: &str) -> Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        Err(anyhow!("{label} request failed: {status}"))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{PanelClient, PanelClientOptions};
    use crate::panel::contract::PATH_V2_SERVER_CONFIG;

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
}
