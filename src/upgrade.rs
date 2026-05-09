use std::env;
use std::path::PathBuf;
use std::process::Command;

use serde::Serialize;
use serde_json::Value;

use crate::machine::MachineUpgradeCommand;

const DEFAULT_RELEASE_OWNER: &str = "keli-123456";
const DEFAULT_RELEASE_PLATFORM: &str = "linux-x86_64";

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UpgradeStatus {
    pub id: String,
    pub status: String,
    pub component: String,
    pub target_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub started_at: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub finished_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeLaunchPlan {
    pub target_version: String,
    pub command: String,
    pub args: Vec<String>,
    pub log_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseUpgradeSpec {
    pub name: String,
    pub owner: String,
    pub repository: String,
    pub binary: String,
    pub install_dir: String,
    pub service_name: String,
    pub platform: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeComponent {
    Node,
    Core,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpgradeManager {
    status: Option<UpgradeStatus>,
}

pub trait UpgradeExecutor {
    fn launch(&mut self, plan: &UpgradeLaunchPlan) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemUpgradeExecutor;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryUpgradeExecutor {
    pub launches: Vec<UpgradeLaunchPlan>,
    pub fail_with: Option<String>,
}

impl UpgradeManager {
    pub fn current_status(&self) -> Option<UpgradeStatus> {
        self.status.clone()
    }

    pub fn current_status_value(&self) -> Option<Value> {
        self.status
            .as_ref()
            .and_then(|status| serde_json::to_value(status).ok())
    }

    pub fn request<E: UpgradeExecutor>(
        &mut self,
        command: MachineUpgradeCommand,
        current_version: &str,
        now: i64,
        executor: &mut E,
    ) -> Result<Option<UpgradeStatus>, String> {
        let id = command.id.trim().to_string();
        let target_version = command.target_version.trim().to_string();
        let component = UpgradeComponent::from_command_value(&command.component)?;
        if id.is_empty() || !valid_kelinode_version(&target_version) {
            return Err("invalid upgrade command".to_string());
        }

        if let Some(status) = &self.status {
            if status.id == id && matches!(status.status.as_str(), "running" | "succeeded") {
                return Ok(Some(status.clone()));
            }
        }

        let mut status = UpgradeStatus {
            id,
            status: "running".to_string(),
            component: component.status_name().to_string(),
            target_version: target_version.clone(),
            error: String::new(),
            started_at: now,
            finished_at: 0,
            updated_at: now,
        };

        if component == UpgradeComponent::Node && versions_equal(current_version, &target_version) {
            status.status = "succeeded".to_string();
            status.finished_at = now;
            self.status = Some(status.clone());
            return Ok(Some(status));
        }

        let plan = upgrade_launch_plan_for_component(&target_version, component);
        if let Err(error) = executor.launch(&plan) {
            status.status = "failed".to_string();
            status.error = truncate_upgrade_error(&error);
            status.finished_at = now;
            status.updated_at = now;
        }

        self.status = Some(status.clone());
        Ok(Some(status))
    }
}

impl UpgradeExecutor for SystemUpgradeExecutor {
    fn launch(&mut self, plan: &UpgradeLaunchPlan) -> Result<(), String> {
        let output = Command::new(&plan.command)
            .args(&plan.args)
            .output()
            .map_err(|err| format!("start update launcher {}: {err}", plan.command))?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = first_non_empty(stderr.trim(), stdout.trim());
            Err(format!(
                "update launcher exited with {}: {detail}",
                output.status
            ))
        }
    }
}

impl UpgradeExecutor for MemoryUpgradeExecutor {
    fn launch(&mut self, plan: &UpgradeLaunchPlan) -> Result<(), String> {
        self.launches.push(plan.clone());
        if let Some(error) = &self.fail_with {
            Err(error.clone())
        } else {
            Ok(())
        }
    }
}

pub fn upgrade_launch_plan(target_version: &str) -> UpgradeLaunchPlan {
    release_upgrade_launch_plan(target_version, &ReleaseUpgradeSpec::native_node())
}

pub fn upgrade_launch_plan_for_component(
    target_version: &str,
    component: UpgradeComponent,
) -> UpgradeLaunchPlan {
    release_upgrade_launch_plan(target_version, &component.release_spec())
}

impl UpgradeComponent {
    fn from_command_value(value: &str) -> Result<Self, String> {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty()
            || matches!(
                value.as_str(),
                "node" | "agent" | "v2node" | "kelinode" | "kelinode-rs"
            )
        {
            return Ok(Self::Node);
        }
        if matches!(value.as_str(), "core" | "keli-core" | "keli-core-rs") {
            return Ok(Self::Core);
        }
        Err("invalid upgrade component".to_string())
    }

    fn status_name(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Core => "core",
        }
    }

    fn release_spec(self) -> ReleaseUpgradeSpec {
        match self {
            Self::Node => ReleaseUpgradeSpec::native_node(),
            Self::Core => ReleaseUpgradeSpec::native_core(),
        }
    }
}

impl ReleaseUpgradeSpec {
    pub fn native_node() -> Self {
        Self {
            name: "kelinode-rs".to_string(),
            owner: DEFAULT_RELEASE_OWNER.to_string(),
            repository: "kelinode-rs".to_string(),
            binary: "kelinode-rs".to_string(),
            install_dir: "/usr/local/v2node".to_string(),
            service_name: "v2node".to_string(),
            platform: DEFAULT_RELEASE_PLATFORM.to_string(),
        }
    }

    pub fn native_core() -> Self {
        Self {
            name: "keli-core-rs".to_string(),
            owner: DEFAULT_RELEASE_OWNER.to_string(),
            repository: "keli-core-rs".to_string(),
            binary: "keli-core-rs".to_string(),
            install_dir: "/usr/local/v2node".to_string(),
            service_name: "v2node".to_string(),
            platform: DEFAULT_RELEASE_PLATFORM.to_string(),
        }
    }

    fn asset_prefix(&self, target_version: &str) -> String {
        format!("{}-{}-{}", self.name, target_version, self.platform)
    }

    fn release_asset_url(&self, target_version: &str, suffix: &str) -> String {
        format!(
            "https://github.com/{}/{}/releases/download/{}/{}{}",
            self.owner,
            self.repository,
            target_version,
            self.asset_prefix(target_version),
            suffix
        )
    }
}

pub fn release_upgrade_launch_plan(
    target_version: &str,
    spec: &ReleaseUpgradeSpec,
) -> UpgradeLaunchPlan {
    let target_version = target_version.trim().to_string();
    let script = release_upgrade_shell_script(&target_version, spec);

    if tool_exists("systemd-run") {
        return UpgradeLaunchPlan {
            target_version: target_version.clone(),
            command: "systemd-run".to_string(),
            args: vec![
                "--unit".to_string(),
                format!(
                    "{}-self-update-{}",
                    sanitize_systemd_unit_part(&spec.name),
                    sanitize_systemd_unit_part(&target_version)
                ),
                format!("--description={} self update", spec.name),
                "/bin/sh".to_string(),
                "-c".to_string(),
                script,
            ],
            log_path: None,
        };
    }

    let detached = format!("sleep 1; {script}");
    UpgradeLaunchPlan {
        target_version,
        command: "/bin/sh".to_string(),
        args: vec![
            "-c".to_string(),
            format!(
                "nohup /bin/sh -c {} >/tmp/{}-self-update.log 2>&1 &",
                shell_quote(&detached),
                sanitize_systemd_unit_part(&spec.name)
            ),
        ],
        log_path: Some(format!(
            "/tmp/{}-self-update.log",
            sanitize_systemd_unit_part(&spec.name)
        )),
    }
}

fn release_upgrade_shell_script(target_version: &str, spec: &ReleaseUpgradeSpec) -> String {
    let asset_prefix = spec.asset_prefix(target_version);
    let manifest_url = spec.release_asset_url(target_version, ".manifest.json");
    let archive_url = spec.release_asset_url(target_version, ".tar.gz");
    let mut lines = Vec::new();
    lines.push("set -eu".to_string());
    lines.push(format!("target_version={}", shell_quote(target_version)));
    lines.push(format!("component={}", shell_quote(&spec.name)));
    lines.push(format!("binary_name={}", shell_quote(&spec.binary)));
    lines.push(format!("asset_prefix={}", shell_quote(&asset_prefix)));
    lines.push(format!("manifest_url={}", shell_quote(&manifest_url)));
    lines.push(format!("archive_url={}", shell_quote(&archive_url)));
    lines.push(format!("install_dir={}", shell_quote(&spec.install_dir)));
    lines.push(format!("service_name={}", shell_quote(&spec.service_name)));
    lines.push("work_dir=$(mktemp -d \"/tmp/${component}.upgrade.XXXXXX\")".to_string());
    lines.push("cleanup() { rm -rf \"$work_dir\"; }".to_string());
    lines.push("trap cleanup EXIT".to_string());
    lines.push(
        "backup_dir=\"${install_dir}.backup.${component}.${target_version}.$(date +%Y%m%d%H%M%S)\""
            .to_string(),
    );
    lines.push("restore_backup() {".to_string());
    lines.push("  if [ -d \"$backup_dir\" ]; then".to_string());
    lines.push("    rm -rf \"$install_dir\"".to_string());
    lines.push("    mv \"$backup_dir\" \"$install_dir\"".to_string());
    lines.push("    restart_service || true".to_string());
    lines.push("  fi".to_string());
    lines.push("}".to_string());
    lines.push("restart_service() {".to_string());
    lines.push(
        "  if [ -n \"$service_name\" ] && command -v systemctl >/dev/null 2>&1; then".to_string(),
    );
    lines.push("    systemctl restart \"$service_name\" >/dev/null 2>&1 && return 0".to_string());
    lines.push("  fi".to_string());
    lines.push(
        "  if [ -n \"$service_name\" ] && command -v service >/dev/null 2>&1; then".to_string(),
    );
    lines.push("    service \"$service_name\" restart >/dev/null 2>&1 && return 0".to_string());
    lines.push("  fi".to_string());
    lines.push("  return 0".to_string());
    lines.push("}".to_string());
    lines.push("if ! command -v curl >/dev/null 2>&1; then exit 1; fi".to_string());
    lines.push("if ! command -v tar >/dev/null 2>&1; then exit 1; fi".to_string());
    lines.push("if ! command -v sha256sum >/dev/null 2>&1; then exit 1; fi".to_string());
    lines.push("if [ -d \"$install_dir\" ]; then".to_string());
    lines.push("  cp -a \"$install_dir\" \"$backup_dir\"".to_string());
    lines.push("fi".to_string());
    lines.push("mkdir -p \"$install_dir\"".to_string());
    lines.push("manifest_file=\"$work_dir/${asset_prefix}.manifest.json\"".to_string());
    lines.push("archive_file=\"$work_dir/${asset_prefix}.tar.gz\"".to_string());
    lines.push(
        "if ! curl -fsSL \"$manifest_url\" -o \"$manifest_file\"; then restore_backup; exit 1; fi"
            .to_string(),
    );
    lines.push("manifest_sha=$(sed -n 's/.*\"sha256\"[[:space:]]*:[[:space:]]*\"\\([0-9a-fA-F]\\{64\\}\\)\".*/\\1/p' \"$manifest_file\" | head -n 1)".to_string());
    lines.push("manifest_binary=$(sed -n 's/.*\"binary\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' \"$manifest_file\" | head -n 1)".to_string());
    lines.push("if [ -z \"$manifest_sha\" ]; then restore_backup; exit 1; fi".to_string());
    lines.push("if [ -n \"$manifest_binary\" ] && [ \"$manifest_binary\" != \"$binary_name\" ]; then restore_backup; exit 1; fi".to_string());
    lines.push(
        "if ! curl -fsSL \"$archive_url\" -o \"$archive_file\"; then restore_backup; exit 1; fi"
            .to_string(),
    );
    lines.push("(cd \"$work_dir\" && printf '%s  %s\\n' \"$manifest_sha\" \"${asset_prefix}.tar.gz\" | sha256sum -c -) || { restore_backup; exit 1; }".to_string());
    lines.push(
        "if ! tar -xzf \"$archive_file\" -C \"$work_dir\"; then restore_backup; exit 1; fi"
            .to_string(),
    );
    lines.push(
        "extracted_binary=$(find \"$work_dir\" -type f -name \"$binary_name\" | head -n 1)"
            .to_string(),
    );
    lines.push("if [ -z \"$extracted_binary\" ]; then restore_backup; exit 1; fi".to_string());
    lines.push("cp \"$extracted_binary\" \"$install_dir/$binary_name\"".to_string());
    lines.push("chmod 0755 \"$install_dir/$binary_name\"".to_string());
    lines.push("installed_version=\"\"".to_string());
    lines.push("if [ -x \"$install_dir/$binary_name\" ]; then".to_string());
    lines.push("  installed_version=$(\"$install_dir/$binary_name\" version 2>/dev/null | awk '{print $2}' | head -n 1 || true)".to_string());
    lines.push("fi".to_string());
    lines.push("normalize_version() {".to_string());
    lines.push("  printf '%s' \"$1\" | sed 's/^[vV]//'".to_string());
    lines.push("}".to_string());
    lines.push("if [ \"$(normalize_version \"$installed_version\")\" != \"$(normalize_version \"$target_version\")\" ]; then".to_string());
    lines.push("  restore_backup".to_string());
    lines.push("  exit 1".to_string());
    lines.push("fi".to_string());
    lines.push(
        "printf '%s\\n' \"$target_version\" > \"$install_dir/.installed_version\"".to_string(),
    );
    lines.push(
        "printf '%s\\n' \"$target_version\" > \"$install_dir/.${component}_version\"".to_string(),
    );
    lines.push("restart_service".to_string());
    lines.push("rm -rf \"$backup_dir\"".to_string());
    lines.join("\n")
}

pub fn valid_kelinode_version(version: &str) -> bool {
    let version = version.trim();
    let mut chars = version.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() && first != 'v' && first != 'V' {
        return false;
    }
    version.len() <= 64
        && version
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

pub fn versions_equal(current: &str, target: &str) -> bool {
    trim_version_prefix(current) == trim_version_prefix(target)
}

fn trim_version_prefix(value: &str) -> String {
    value
        .trim()
        .trim_start_matches(|ch| ch == 'v' || ch == 'V')
        .to_string()
}

fn sanitize_systemd_unit_part(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            output.push(ch);
        } else if !output.ends_with('-') {
            output.push('-');
        }
    }
    let output = output.trim_matches(|ch| ch == '.' || ch == '-').to_string();
    if output.is_empty() {
        "latest".to_string()
    } else {
        output
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn truncate_upgrade_error(value: &str) -> String {
    let value = value.trim();
    if value.len() <= 1000 {
        value.to_string()
    } else {
        value.chars().take(1000).collect()
    }
}

fn tool_exists(tool: &str) -> bool {
    let Some(paths) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&paths).any(|path| {
        candidate_tool_paths(&path, tool).iter().any(|candidate| {
            std::fs::metadata(candidate)
                .map(|metadata| metadata.is_file())
                .unwrap_or(false)
        })
    })
}

fn candidate_tool_paths(path: &PathBuf, tool: &str) -> Vec<PathBuf> {
    if cfg!(windows) {
        vec![path.join(format!("{tool}.exe")), path.join(tool)]
    } else {
        vec![path.join(tool)]
    }
}

fn first_non_empty<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use crate::machine::MachineUpgradeCommand;

    use super::{
        release_upgrade_launch_plan, release_upgrade_shell_script, shell_quote,
        valid_kelinode_version, versions_equal, MemoryUpgradeExecutor, ReleaseUpgradeSpec,
        UpgradeManager,
    };

    #[test]
    fn validates_versions_like_go_agent() {
        assert!(valid_kelinode_version("v0.3.24"));
        assert!(valid_kelinode_version("0.3.24"));
        assert!(!valid_kelinode_version(""));
        assert!(!valid_kelinode_version("../bad"));
    }

    #[test]
    fn already_current_version_marks_upgrade_succeeded() {
        let mut manager = UpgradeManager::default();
        let mut executor = MemoryUpgradeExecutor::default();

        let status = manager
            .request(
                MachineUpgradeCommand {
                    id: "upgrade-1".to_string(),
                    target_version: "v1.2.3".to_string(),
                    component: String::new(),
                },
                "1.2.3",
                100,
                &mut executor,
            )
            .unwrap()
            .unwrap();

        assert_eq!(status.status, "succeeded");
        assert_eq!(status.component, "node");
        assert_eq!(status.finished_at, 100);
        assert!(executor.launches.is_empty());
    }

    #[test]
    fn launch_failure_marks_upgrade_failed() {
        let mut manager = UpgradeManager::default();
        let mut executor = MemoryUpgradeExecutor {
            fail_with: Some("download failed".to_string()),
            ..MemoryUpgradeExecutor::default()
        };

        let status = manager
            .request(
                MachineUpgradeCommand {
                    id: "upgrade-1".to_string(),
                    target_version: "v1.2.4".to_string(),
                    component: String::new(),
                },
                "v1.2.3",
                200,
                &mut executor,
            )
            .unwrap()
            .unwrap();

        assert_eq!(status.status, "failed");
        assert_eq!(status.error, "download failed");
        assert_eq!(executor.launches.len(), 1);
    }

    #[test]
    fn ignores_duplicate_running_upgrade() {
        let mut manager = UpgradeManager::default();
        let mut executor = MemoryUpgradeExecutor::default();
        let command = MachineUpgradeCommand {
            id: "upgrade-1".to_string(),
            target_version: "v1.2.4".to_string(),
            component: String::new(),
        };

        manager
            .request(command.clone(), "v1.2.3", 200, &mut executor)
            .unwrap();
        manager
            .request(command, "v1.2.3", 201, &mut executor)
            .unwrap();

        assert_eq!(executor.launches.len(), 1);
        assert_eq!(manager.current_status().unwrap().started_at, 200);
    }

    #[test]
    fn core_upgrade_targets_core_release_even_when_node_version_matches() {
        let mut manager = UpgradeManager::default();
        let mut executor = MemoryUpgradeExecutor::default();

        let status = manager
            .request(
                MachineUpgradeCommand {
                    id: "upgrade-core-1".to_string(),
                    target_version: "v1.2.4".to_string(),
                    component: "core".to_string(),
                },
                "v1.2.4",
                210,
                &mut executor,
            )
            .unwrap()
            .unwrap();

        assert_eq!(status.status, "running");
        assert_eq!(status.component, "core");
        assert_eq!(executor.launches.len(), 1);
        assert!(executor.launches[0]
            .args
            .iter()
            .any(|arg| arg.contains("keli-core-rs-v1.2.4-linux-x86_64.tar.gz")));
    }

    #[test]
    fn rejects_unknown_upgrade_component() {
        let mut manager = UpgradeManager::default();
        let mut executor = MemoryUpgradeExecutor::default();

        let error = manager
            .request(
                MachineUpgradeCommand {
                    id: "upgrade-bad".to_string(),
                    target_version: "v1.2.4".to_string(),
                    component: "browser".to_string(),
                },
                "v1.2.3",
                210,
                &mut executor,
            )
            .unwrap_err();

        assert_eq!(error, "invalid upgrade component");
        assert!(executor.launches.is_empty());
    }

    #[test]
    fn quotes_shell_values_like_go_agent() {
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
        assert!(versions_equal("v1.2.3", "1.2.3"));
    }

    #[test]
    fn upgrade_shell_script_downloads_manifest_and_verifies_sha256() {
        let script = release_upgrade_shell_script("v1.2.5", &ReleaseUpgradeSpec::native_node());

        assert!(script.contains("restore_backup()"));
        assert!(script.contains("kelinode-rs-v1.2.5-linux-x86_64.manifest.json"));
        assert!(script.contains("kelinode-rs-v1.2.5-linux-x86_64.tar.gz"));
        assert!(script.contains("manifest_sha=$(sed"));
        assert!(script.contains("sha256sum -c -"));
        assert!(script.contains("tar -xzf \"$archive_file\""));
        assert!(script.contains("cp \"$extracted_binary\" \"$install_dir/$binary_name\""));
        assert!(script.contains("${install_dir}.backup.${component}.${target_version}."));
        assert!(script.contains(".installed_version"));
        assert!(script.contains(".${component}_version"));
        assert!(script.contains("normalize_version"));
        assert!(script.contains("rm -rf \"$backup_dir\""));
    }

    #[test]
    fn release_upgrade_spec_can_target_native_core_assets() {
        let spec = ReleaseUpgradeSpec::native_core();
        let script = release_upgrade_shell_script("v0.1.1", &spec);

        assert!(script.contains("component='keli-core-rs'"));
        assert!(script.contains("binary_name='keli-core-rs'"));
        assert!(script.contains("keli-core-rs-v0.1.1-linux-x86_64.manifest.json"));
        assert!(script.contains("keli-core-rs-v0.1.1-linux-x86_64.tar.gz"));
    }

    #[test]
    fn release_upgrade_launch_plan_uses_component_log_name() {
        let plan = release_upgrade_launch_plan("v1.2.5", &ReleaseUpgradeSpec::native_node());

        assert_eq!(plan.target_version, "v1.2.5");
        if let Some(log_path) = plan.log_path {
            assert!(log_path.contains("kelinode-rs-self-update.log"));
        } else {
            assert!(plan
                .args
                .iter()
                .any(|arg| arg.contains("kelinode-rs-self-update-v1.2.5")));
        }
    }
}
