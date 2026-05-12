use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command};

use crate::core::{CoreKind, CorePlan};
use crate::core_control::{KeliCoreControlClient, KELI_CORE_CONTROL_TOKEN_ENV};

const DEFAULT_NATIVE_INSTALL_DIR: &str = "/usr/local/v2node";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessSpec {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub working_dir: Option<PathBuf>,
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Stopped,
    Exited(Option<i32>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStatus {
    pub name: String,
    pub pid: Option<u32>,
    pub state: ProcessState,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessError {
    pub message: String,
}

pub trait ProcessSupervisor {
    fn start(&mut self, spec: &ProcessSpec) -> Result<ProcessStatus, ProcessError>;
    fn reload(&mut self, spec: &ProcessSpec) -> Result<ProcessStatus, ProcessError>;
    fn stop(&mut self, name: &str) -> Result<ProcessStatus, ProcessError>;
    fn status(&mut self, name: &str) -> Result<ProcessStatus, ProcessError>;
}

#[derive(Default)]
pub struct SystemProcessSupervisor {
    children: BTreeMap<String, Child>,
    statuses: BTreeMap<String, ProcessStatus>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryProcessSupervisor {
    pub starts: Vec<ProcessSpec>,
    pub stops: Vec<String>,
    statuses: BTreeMap<String, ProcessStatus>,
}

impl ProcessError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl ProcessStatus {
    pub fn running(name: impl Into<String>, pid: u32) -> Self {
        Self {
            name: name.into(),
            pid: Some(pid),
            state: ProcessState::Running,
            message: "running".to_string(),
        }
    }

    pub fn stopped(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pid: None,
            state: ProcessState::Stopped,
            message: message.into(),
        }
    }

    pub fn exited(name: impl Into<String>, code: Option<i32>) -> Self {
        Self {
            name: name.into(),
            pid: None,
            state: ProcessState::Exited(code),
            message: match code {
                Some(value) => format!("exited with code {value}"),
                None => "exited without code".to_string(),
            },
        }
    }

    pub fn is_running(&self) -> bool {
        self.state == ProcessState::Running
    }
}

impl ProcessSupervisor for SystemProcessSupervisor {
    fn start(&mut self, spec: &ProcessSpec) -> Result<ProcessStatus, ProcessError> {
        let current = self.status(&spec.name)?;
        if current.is_running() {
            return Ok(current);
        }

        let mut command = Command::new(&spec.command);
        command.args(&spec.args);
        command.envs(&spec.env);
        if let Some(working_dir) = &spec.working_dir {
            command.current_dir(working_dir);
        }

        let child = command
            .spawn()
            .map_err(|err| ProcessError::new(format!("start process {}: {err}", spec.name)))?;
        let status = ProcessStatus::running(&spec.name, child.id());
        self.children.insert(spec.name.clone(), child);
        self.statuses.insert(spec.name.clone(), status.clone());
        Ok(status)
    }

    fn reload(&mut self, spec: &ProcessSpec) -> Result<ProcessStatus, ProcessError> {
        self.stop(&spec.name)?;
        self.start(spec)
    }

    fn stop(&mut self, name: &str) -> Result<ProcessStatus, ProcessError> {
        let Some(mut child) = self.children.remove(name) else {
            let status = ProcessStatus::stopped(name, "process is not running");
            self.statuses.insert(name.to_string(), status.clone());
            return Ok(status);
        };

        match child.try_wait().map_err(|err| {
            ProcessError::new(format!("inspect process {name} before stop: {err}"))
        })? {
            Some(exit) => {
                let status = ProcessStatus::exited(name, exit.code());
                self.statuses.insert(name.to_string(), status.clone());
                Ok(status)
            }
            None => {
                child
                    .kill()
                    .map_err(|err| ProcessError::new(format!("stop process {name}: {err}")))?;
                let exit = child
                    .wait()
                    .map_err(|err| ProcessError::new(format!("wait process {name}: {err}")))?;
                let status = ProcessStatus {
                    name: name.to_string(),
                    pid: None,
                    state: ProcessState::Stopped,
                    message: format!("stopped with code {:?}", exit.code()),
                };
                self.statuses.insert(name.to_string(), status.clone());
                Ok(status)
            }
        }
    }

    fn status(&mut self, name: &str) -> Result<ProcessStatus, ProcessError> {
        let exit_code = if let Some(child) = self.children.get_mut(name) {
            match child
                .try_wait()
                .map_err(|err| ProcessError::new(format!("inspect process {name}: {err}")))?
            {
                Some(exit) => Some(exit.code()),
                None => return Ok(ProcessStatus::running(name, child.id())),
            }
        } else {
            None
        };

        if let Some(code) = exit_code {
            self.children.remove(name);
            let status = ProcessStatus::exited(name, code);
            self.statuses.insert(name.to_string(), status.clone());
            return Ok(status);
        }

        Ok(self
            .statuses
            .get(name)
            .cloned()
            .unwrap_or_else(|| ProcessStatus::stopped(name, "process was never started")))
    }
}

impl ProcessSupervisor for MemoryProcessSupervisor {
    fn start(&mut self, spec: &ProcessSpec) -> Result<ProcessStatus, ProcessError> {
        self.starts.push(spec.clone());
        let status = ProcessStatus::running(&spec.name, self.starts.len() as u32);
        self.statuses.insert(spec.name.clone(), status.clone());
        Ok(status)
    }

    fn reload(&mut self, spec: &ProcessSpec) -> Result<ProcessStatus, ProcessError> {
        self.stop(&spec.name)?;
        self.start(spec)
    }

    fn stop(&mut self, name: &str) -> Result<ProcessStatus, ProcessError> {
        self.stops.push(name.to_string());
        let status = ProcessStatus::stopped(name, "stopped");
        self.statuses.insert(name.to_string(), status.clone());
        Ok(status)
    }

    fn status(&mut self, name: &str) -> Result<ProcessStatus, ProcessError> {
        Ok(self
            .statuses
            .get(name)
            .cloned()
            .unwrap_or_else(|| ProcessStatus::stopped(name, "process was never started")))
    }
}

pub fn core_process_spec(
    plan: &CorePlan,
    command_override: Option<&str>,
) -> Result<ProcessSpec, ProcessError> {
    let command = command_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| default_core_command(&plan.kind))
        .ok_or_else(|| ProcessError::new("core command is not configured"))?;

    let config_path = absolute_process_path(&plan.config_path);

    Ok(ProcessSpec {
        name: format!("core:{}", core_kind_label(&plan.kind)),
        command,
        args: core_process_args(&plan.kind, &config_path)?,
        working_dir: config_path.parent().map(|path| path.to_path_buf()),
        env: core_process_env(&plan.kind, &config_path)?,
    })
}

pub fn sidecar_process_spec(
    plan: &CorePlan,
    command: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
) -> Result<ProcessSpec, ProcessError> {
    let CoreKind::Sidecar(_) = &plan.kind else {
        return Err(ProcessError::new(
            "sidecar process spec requires a sidecar core plan",
        ));
    };
    let command = command.trim();
    if command.is_empty() {
        return Err(ProcessError::new("sidecar command is not configured"));
    }
    let config_path = absolute_process_path(&plan.config_path);
    let config = config_path.display().to_string();
    Ok(ProcessSpec {
        name: format!("core:{}", core_kind_label(&plan.kind)),
        command: command.to_string(),
        args: args
            .iter()
            .map(|arg| arg.replace("{config}", &config))
            .collect(),
        working_dir: config_path.parent().map(|path| path.to_path_buf()),
        env: env
            .iter()
            .filter_map(|(key, value)| {
                let key = key.trim();
                if key.is_empty() {
                    None
                } else {
                    Some((key.to_string(), value.replace("{config}", &config)))
                }
            })
            .collect(),
    })
}

fn default_core_command(kind: &CoreKind) -> Option<String> {
    match kind {
        CoreKind::Xray => Some("xray".to_string()),
        CoreKind::SingBox => Some("sing-box".to_string()),
        CoreKind::Mihomo => Some("mihomo".to_string()),
        CoreKind::KeliCoreRs => Some(default_binary_command(
            "keli-core-rs",
            Path::new(DEFAULT_NATIVE_INSTALL_DIR),
        )),
        CoreKind::Sidecar(_) => None,
    }
}

fn default_binary_command(binary_name: &str, install_dir: &Path) -> String {
    let installed = install_dir.join(binary_name);
    if installed.is_file() {
        installed.display().to_string()
    } else {
        binary_name.to_string()
    }
}

fn core_process_args(kind: &CoreKind, config_path: &PathBuf) -> Result<Vec<String>, ProcessError> {
    let config = config_path.display().to_string();
    match kind {
        CoreKind::Xray => Ok(vec!["run".to_string(), "-config".to_string(), config]),
        CoreKind::SingBox => Ok(vec!["run".to_string(), "-c".to_string(), config]),
        CoreKind::Mihomo => Ok(vec!["-f".to_string(), config]),
        CoreKind::KeliCoreRs => Ok(vec![
            "run-config".to_string(),
            config,
            "--control".to_string(),
            keli_core_rs_control_addr(config_path),
        ]),
        CoreKind::Sidecar(name) => Err(ProcessError::new(format!(
            "sidecar process args are not implemented for {name}",
        ))),
    }
}

fn core_process_env(
    kind: &CoreKind,
    config_path: &Path,
) -> Result<BTreeMap<String, String>, ProcessError> {
    let mut env = BTreeMap::new();
    let CoreKind::KeliCoreRs = kind else {
        return Ok(env);
    };

    let Some(config_dir) = config_path.parent() else {
        return Ok(env);
    };

    env.insert(
        "KELI_CORE_GEOIP_DIR".to_string(),
        join_process_path(config_dir, "geoip"),
    );
    env.insert(
        "KELI_CORE_GEOSITE_DIR".to_string(),
        join_process_path(config_dir, "geosite"),
    );
    env.insert(
        KELI_CORE_CONTROL_TOKEN_ENV.to_string(),
        keli_core_rs_control_token(config_path)?,
    );
    Ok(env)
}

fn join_process_path(base: &Path, segment: &str) -> String {
    let base = base.display().to_string();
    if base.starts_with('/') {
        return format!("{}/{}", base.trim_end_matches('/'), segment);
    }
    Path::new(&base).join(segment).display().to_string()
}

pub fn keli_core_rs_control_addr(config_path: &PathBuf) -> String {
    let config_path = absolute_process_path(config_path);
    let hash = fnv1a64(config_path.display().to_string().as_bytes());
    format!("127.0.0.1:{}", 18080 + (hash % 1000))
}

pub fn keli_core_rs_control_client(
    config_path: &Path,
) -> Result<KeliCoreControlClient, ProcessError> {
    let config_path = absolute_process_path(config_path);
    let token = keli_core_rs_control_token(&config_path)?;
    Ok(KeliCoreControlClient::new(keli_core_rs_control_addr(&config_path)).with_token(token))
}

pub fn keli_core_rs_control_token_path(config_path: &Path) -> PathBuf {
    let config_path = absolute_process_path(config_path);
    config_path.with_extension("control.token")
}

pub fn keli_core_rs_control_token(config_path: &Path) -> Result<String, ProcessError> {
    let token_path = keli_core_rs_control_token_path(config_path);
    if let Ok(contents) = fs::read_to_string(&token_path) {
        let token = contents.trim();
        if !token.is_empty() {
            return Ok(token.to_string());
        }
    }

    let token = generate_keli_core_rs_control_token()?;
    if let Some(parent) = token_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            ProcessError::new(format!(
                "create keli-core-rs control token directory {}: {err}",
                parent.display()
            ))
        })?;
    }
    fs::write(&token_path, format!("{token}\n")).map_err(|err| {
        ProcessError::new(format!(
            "write keli-core-rs control token {}: {err}",
            token_path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).map_err(|err| {
            ProcessError::new(format!(
                "secure keli-core-rs control token {}: {err}",
                token_path.display()
            ))
        })?;
    }
    Ok(token)
}

fn generate_keli_core_rs_control_token() -> Result<String, ProcessError> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|err| ProcessError::new(format!("generate keli-core-rs control token: {err}")))?;
    Ok(bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn absolute_process_path(path: &Path) -> PathBuf {
    if path.is_absolute() || path.to_string_lossy().starts_with('/') {
        return path.to_path_buf();
    }
    env::current_dir()
        .map(|current_dir| current_dir.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn core_kind_label(kind: &CoreKind) -> String {
    match kind {
        CoreKind::Xray => "xray".to_string(),
        CoreKind::SingBox => "sing-box".to_string(),
        CoreKind::Mihomo => "mihomo".to_string(),
        CoreKind::KeliCoreRs => "keli-core-rs".to_string(),
        CoreKind::Sidecar(name) => format!("sidecar-{name}"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use crate::core::{CoreKind, CorePlan};
    use crate::core_control::{KeliCoreResponse, KELI_CORE_CONTROL_TOKEN_ENV};

    use super::{
        core_process_spec, default_binary_command, keli_core_rs_control_addr,
        keli_core_rs_control_client, keli_core_rs_control_token, keli_core_rs_control_token_path,
        sidecar_process_spec, MemoryProcessSupervisor, ProcessState, ProcessStatus,
        ProcessSupervisor,
    };

    #[test]
    fn builds_xray_process_spec_from_core_plan() {
        let plan = CorePlan {
            kind: CoreKind::Xray,
            config_path: PathBuf::from("/srv/v2node/config.json"),
            listen_tags: Vec::new(),
            inbounds: Vec::new(),
        };

        let spec = core_process_spec(&plan, None).unwrap();

        assert_eq!(spec.name, "core:xray");
        assert_eq!(spec.command, "xray");
        assert_eq!(spec.args, vec!["run", "-config", "/srv/v2node/config.json"]);
        assert_eq!(spec.working_dir, Some(PathBuf::from("/srv/v2node")));
        assert!(spec.env.is_empty());
    }

    #[test]
    fn builds_keli_core_rs_process_spec_from_core_plan() {
        let dir = temp_test_dir("keli-core-rs-spec");
        let config_path = dir.join("keli-core-rs.json");
        let plan = CorePlan {
            kind: CoreKind::KeliCoreRs,
            config_path: config_path.clone(),
            listen_tags: Vec::new(),
            inbounds: Vec::new(),
        };

        let spec = core_process_spec(&plan, None).unwrap();
        let control_addr = keli_core_rs_control_addr(&plan.config_path);
        let config = config_path.display().to_string();

        assert_eq!(spec.name, "core:keli-core-rs");
        assert_eq!(spec.command, "keli-core-rs");
        assert_eq!(
            spec.args,
            vec![
                "run-config".to_string(),
                config.clone(),
                "--control".to_string(),
                control_addr
            ]
        );
        assert_eq!(spec.working_dir, Some(dir.clone()));
        assert_eq!(
            spec.env["KELI_CORE_GEOIP_DIR"],
            dir.join("geoip").display().to_string()
        );
        assert_eq!(
            spec.env["KELI_CORE_GEOSITE_DIR"],
            dir.join("geosite").display().to_string()
        );
        assert!(!spec.env[KELI_CORE_CONTROL_TOKEN_ENV].is_empty());
        assert!(!config.contains(&spec.env[KELI_CORE_CONTROL_TOKEN_ENV]));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn command_override_replaces_default_binary() {
        let plan = CorePlan {
            kind: CoreKind::SingBox,
            config_path: PathBuf::from("/etc/v2node/sing-box.json"),
            listen_tags: Vec::new(),
            inbounds: Vec::new(),
        };

        let spec = core_process_spec(&plan, Some("/usr/local/bin/sing-box")).unwrap();

        assert_eq!(spec.command, "/usr/local/bin/sing-box");
        assert_eq!(spec.args, vec!["run", "-c", "/etc/v2node/sing-box.json"]);
    }

    #[test]
    fn default_binary_command_prefers_installed_native_binary() {
        let dir = temp_test_dir("installed-binary");
        let binary = dir.join("keli-core-rs");
        fs::write(&binary, "binary").unwrap();

        let command = default_binary_command("keli-core-rs", &dir);

        assert_eq!(command, binary.display().to_string());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn default_binary_command_falls_back_to_path_lookup() {
        let dir = temp_test_dir("missing-binary");

        let command = default_binary_command("keli-core-rs", &dir);

        assert_eq!(command, "keli-core-rs");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn core_process_spec_absolutizes_relative_config_path() {
        let rel_root = PathBuf::from(format!(
            "kelinode-rs-relative-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let rel_config = rel_root.join("v2node/config.json");
        let plan = CorePlan {
            kind: CoreKind::KeliCoreRs,
            config_path: rel_config.clone(),
            listen_tags: Vec::new(),
            inbounds: Vec::new(),
        };

        let spec = core_process_spec(&plan, None).unwrap();

        assert!(PathBuf::from(&spec.args[1]).is_absolute());
        assert!(spec.working_dir.as_ref().unwrap().is_absolute());
        assert!(PathBuf::from(&spec.env["KELI_CORE_GEOIP_DIR"]).is_absolute());
        assert!(PathBuf::from(&spec.env["KELI_CORE_GEOSITE_DIR"]).is_absolute());
        assert!(!spec.env[KELI_CORE_CONTROL_TOKEN_ENV].is_empty());
        assert_eq!(spec.args[3], keli_core_rs_control_addr(&plan.config_path));
        fs::remove_dir_all(rel_root).ok();
    }

    #[test]
    fn keli_core_rs_control_token_is_persisted_and_reused() {
        let dir = temp_test_dir("control-token");
        let config_path = dir.join("config.json");

        let first = keli_core_rs_control_token(&config_path).unwrap();
        let second = keli_core_rs_control_token(&config_path).unwrap();
        let token_path = keli_core_rs_control_token_path(&config_path);

        assert_eq!(first, second);
        assert_eq!(fs::read_to_string(token_path).unwrap().trim(), first);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn keli_core_rs_control_client_sends_generated_token() {
        let dir = temp_test_dir("control-client-token");
        let config_path = dir.join("config.json");
        let token = keli_core_rs_control_token(&config_path).unwrap();
        let addr = keli_core_rs_control_addr(&config_path);
        let listener = TcpListener::bind(&addr).unwrap();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut command = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut command)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(command.trim()).unwrap(),
                json!({
                    "type": "status",
                    "token": token
                })
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

        let response = keli_core_rs_control_client(&config_path)
            .unwrap()
            .status()
            .unwrap();

        assert!(matches!(response, KeliCoreResponse::Status { .. }));
        join.join().unwrap();
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn core_process_spec_refuses_sidecar_without_explicit_args() {
        let plan = CorePlan {
            kind: CoreKind::Sidecar("naive".to_string()),
            config_path: PathBuf::from("/srv/v2node/sidecar-naive-1.json"),
            listen_tags: Vec::new(),
            inbounds: Vec::new(),
        };

        let err = core_process_spec(&plan, None).unwrap_err();

        assert!(err.message.contains("core command is not configured"));
    }

    #[test]
    fn sidecar_process_spec_uses_explicit_command_and_args() {
        let plan = CorePlan {
            kind: CoreKind::Sidecar("mieru".to_string()),
            config_path: PathBuf::from("/srv/v2node/sidecar-mieru-2.json"),
            listen_tags: Vec::new(),
            inbounds: Vec::new(),
        };

        let spec = sidecar_process_spec(
            &plan,
            "/usr/local/bin/mieru",
            &["run".to_string(), "-c".to_string(), "{config}".to_string()],
            &BTreeMap::from([("MITA_CONFIG_JSON_FILE".to_string(), "{config}".to_string())]),
        )
        .unwrap();

        assert_eq!(spec.name, "core:sidecar-mieru");
        assert_eq!(spec.command, "/usr/local/bin/mieru");
        assert_eq!(
            spec.args,
            vec!["run", "-c", "/srv/v2node/sidecar-mieru-2.json"]
        );
        assert_eq!(
            spec.env["MITA_CONFIG_JSON_FILE"],
            "/srv/v2node/sidecar-mieru-2.json"
        );
        assert_eq!(spec.working_dir, Some(PathBuf::from("/srv/v2node")));
    }

    #[test]
    fn sidecar_process_spec_rejects_non_sidecar_plan() {
        let plan = CorePlan {
            kind: CoreKind::Xray,
            config_path: PathBuf::from("/srv/v2node/config.json"),
            listen_tags: Vec::new(),
            inbounds: Vec::new(),
        };

        let err =
            sidecar_process_spec(&plan, "/usr/local/bin/naive", &[], &BTreeMap::new()).unwrap_err();

        assert!(err.message.contains("requires a sidecar core plan"));
    }

    #[test]
    fn sidecar_process_spec_rejects_empty_command() {
        let plan = CorePlan {
            kind: CoreKind::Sidecar("naive".to_string()),
            config_path: PathBuf::from("/srv/v2node/sidecar-naive-1.json"),
            listen_tags: Vec::new(),
            inbounds: Vec::new(),
        };

        let err = sidecar_process_spec(&plan, "  ", &["{config}".to_string()], &BTreeMap::new())
            .unwrap_err();

        assert!(err.message.contains("sidecar command is not configured"));
    }

    #[test]
    fn memory_supervisor_start_reload_stop_status() {
        let plan = CorePlan {
            kind: CoreKind::Xray,
            config_path: PathBuf::from("/srv/v2node/config.json"),
            listen_tags: Vec::new(),
            inbounds: Vec::new(),
        };
        let spec = core_process_spec(&plan, None).unwrap();
        let mut supervisor = MemoryProcessSupervisor::default();

        let started = supervisor.start(&spec).unwrap();
        let reloaded = supervisor.reload(&spec).unwrap();
        let stopped = supervisor.stop(&spec.name).unwrap();

        assert_eq!(started.state, ProcessState::Running);
        assert_eq!(reloaded.state, ProcessState::Running);
        assert_eq!(stopped.state, ProcessState::Stopped);
        assert_eq!(supervisor.starts.len(), 2);
        assert_eq!(supervisor.stops, vec!["core:xray", "core:xray"]);
    }

    #[test]
    fn missing_status_is_stopped() {
        let mut supervisor = MemoryProcessSupervisor::default();

        let status = supervisor.status("core:xray").unwrap();

        assert_eq!(
            status,
            ProcessStatus::stopped("core:xray", "process was never started")
        );
    }

    fn temp_test_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "kelinode-rs-process-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
