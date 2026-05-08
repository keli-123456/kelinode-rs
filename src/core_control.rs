use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeliCoreControlClient {
    addr: String,
    timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeliCoreControlError {
    pub message: String,
}

impl KeliCoreControlError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for KeliCoreControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for KeliCoreControlError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum KeliCoreCommand {
    ApplyConfig { config: Value },
    DrainTraffic { minimum_bytes: u64 },
    Status,
    Stop,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeliCoreResponse {
    Applied {
        decision: String,
        status: Value,
        listeners: Vec<Value>,
    },
    Traffic {
        records: Vec<KeliCoreTrafficRecord>,
    },
    Status {
        status: Value,
        listeners: Vec<Value>,
    },
    Stopped,
    Error {
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct KeliCoreTrafficRecord {
    pub node_tag: String,
    pub user_uuid: String,
    pub upload: u64,
    pub download: u64,
    #[serde(default)]
    pub online_ips: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeliCoreApplyResult {
    pub decision: String,
    pub status: Value,
    pub listeners: Vec<Value>,
}

impl KeliCoreControlClient {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn status(&self) -> Result<KeliCoreResponse, KeliCoreControlError> {
        self.send(&KeliCoreCommand::Status)
    }

    pub fn apply_config(&self, config: Value) -> Result<KeliCoreApplyResult, KeliCoreControlError> {
        match self.send(&KeliCoreCommand::ApplyConfig { config })? {
            KeliCoreResponse::Applied {
                decision,
                status,
                listeners,
            } => Ok(KeliCoreApplyResult {
                decision,
                status,
                listeners,
            }),
            KeliCoreResponse::Error { message } => Err(KeliCoreControlError::new(message)),
            response => Err(KeliCoreControlError::new(format!(
                "unexpected keli-core-rs apply response: {response:?}"
            ))),
        }
    }

    pub fn drain_traffic(
        &self,
        minimum_bytes: u64,
    ) -> Result<Vec<KeliCoreTrafficRecord>, KeliCoreControlError> {
        match self.send(&KeliCoreCommand::DrainTraffic { minimum_bytes })? {
            KeliCoreResponse::Traffic { records } => Ok(records),
            KeliCoreResponse::Error { message } => Err(KeliCoreControlError::new(message)),
            response => Err(KeliCoreControlError::new(format!(
                "unexpected keli-core-rs drain response: {response:?}"
            ))),
        }
    }

    pub fn stop(&self) -> Result<(), KeliCoreControlError> {
        match self.send(&KeliCoreCommand::Stop)? {
            KeliCoreResponse::Stopped => Ok(()),
            KeliCoreResponse::Error { message } => Err(KeliCoreControlError::new(message)),
            response => Err(KeliCoreControlError::new(format!(
                "unexpected keli-core-rs stop response: {response:?}"
            ))),
        }
    }

    fn send(&self, command: &KeliCoreCommand) -> Result<KeliCoreResponse, KeliCoreControlError> {
        let mut stream = TcpStream::connect(self.addr.trim()).map_err(|err| {
            KeliCoreControlError::new(format!("connect keli-core-rs control {}: {err}", self.addr))
        })?;
        stream.set_read_timeout(Some(self.timeout)).map_err(|err| {
            KeliCoreControlError::new(format!("set keli-core-rs read timeout: {err}"))
        })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|err| {
                KeliCoreControlError::new(format!("set keli-core-rs write timeout: {err}"))
            })?;

        let body = serde_json::to_string(command)
            .map_err(|err| KeliCoreControlError::new(format!("encode control command: {err}")))?;
        writeln!(stream, "{body}")
            .map_err(|err| KeliCoreControlError::new(format!("write control command: {err}")))?;

        let mut response = String::new();
        BufReader::new(stream)
            .read_line(&mut response)
            .map_err(|err| KeliCoreControlError::new(format!("read control response: {err}")))?;
        if response.trim().is_empty() {
            return Err(KeliCoreControlError::new("empty control response"));
        }
        serde_json::from_str(response.trim())
            .map_err(|err| KeliCoreControlError::new(format!("decode control response: {err}")))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use serde_json::json;

    use super::{KeliCoreControlClient, KeliCoreResponse};

    #[test]
    fn drains_traffic_over_json_line_control_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut command = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(command.trim()).unwrap(),
                json!({
                    "type": "drain_traffic",
                    "minimum_bytes": 1024
                })
            );
            writeln!(
                stream,
                "{}",
                json!({
                    "type": "traffic",
                    "records": [{
                        "node_tag": "panel|socks|1",
                        "user_uuid": "uuid-a",
                        "upload": 10,
                        "download": 20
                    }]
                })
            )
            .unwrap();
        });

        let records = KeliCoreControlClient::new(addr.to_string())
            .with_timeout(Duration::from_secs(2))
            .drain_traffic(1024)
            .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|socks|1");
        assert_eq!(records[0].upload, 10);
        join.join().unwrap();
    }

    #[test]
    fn parses_status_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut command = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(command.trim()).unwrap(),
                json!({ "type": "status" })
            );
            writeln!(
                stream,
                "{}",
                json!({
                    "type": "status",
                    "status": "running",
                    "listeners": []
                })
            )
            .unwrap();
        });

        let response = KeliCoreControlClient::new(addr.to_string())
            .status()
            .unwrap();

        assert!(matches!(response, KeliCoreResponse::Status { .. }));
        join.join().unwrap();
    }

    #[test]
    fn applies_config_over_json_line_control_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut command = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(command.trim()).unwrap(),
                json!({
                    "type": "apply_config",
                    "config": {
                        "instance_id": "node-a",
                        "inbounds": []
                    }
                })
            );
            writeln!(
                stream,
                "{}",
                json!({
                    "type": "applied",
                    "decision": "updated",
                    "status": "running",
                    "listeners": []
                })
            )
            .unwrap();
        });

        let applied = KeliCoreControlClient::new(addr.to_string())
            .apply_config(json!({
                "instance_id": "node-a",
                "inbounds": []
            }))
            .unwrap();

        assert_eq!(applied.decision, "updated");
        assert_eq!(applied.status, json!("running"));
        join.join().unwrap();
    }
}
