use std::env;
use std::path::PathBuf;
use std::process::Command;

use serde::Serialize;
use serde_json::Value;

use crate::machine::MachineUpgradeCommand;

const INSTALL_SCRIPT_URL: &str =
    "https://raw.githubusercontent.com/keli-123456/kelinode/main/script/install.sh";

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UpgradeStatus {
    pub id: String,
    pub status: String,
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
            target_version: target_version.clone(),
            error: String::new(),
            started_at: now,
            finished_at: 0,
            updated_at: now,
        };

        if versions_equal(current_version, &target_version) {
            status.status = "succeeded".to_string();
            status.finished_at = now;
            self.status = Some(status.clone());
            return Ok(Some(status));
        }

        let plan = upgrade_launch_plan(&target_version);
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
            Err(format!("update launcher exited with {}: {detail}", output.status))
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
    let target_version = target_version.trim().to_string();
    let script = upgrade_shell_script(&target_version);

    if tool_exists("systemd-run") {
        return UpgradeLaunchPlan {
            target_version: target_version.clone(),
            command: "systemd-run".to_string(),
            args: vec![
                "--unit".to_string(),
                format!("v2node-self-update-{}", sanitize_systemd_unit_part(&target_version)),
                "--description=v2node self update".to_string(),
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
                "nohup /bin/sh -c {} >/tmp/v2node-self-update.log 2>&1 &",
                shell_quote(&detached)
            ),
        ],
        log_path: Some("/tmp/v2node-self-update.log".to_string()),
    }
}

fn upgrade_shell_script(target_version: &str) -> String {
    let mut lines = Vec::new();
    lines.push("set -eu".to_string());
    lines.push(format!("target_version={}", shell_quote(target_version)));
    lines.push(format!("install_script_url={}", shell_quote(INSTALL_SCRIPT_URL)));
    lines.push("install_dir=/usr/local/v2node".to_string());
    lines.push(
        "backup_dir=\"/usr/local/v2node.backup.${target_version}.$(date +%Y%m%d%H%M%S)\""
            .to_string(),
    );
    lines.push("restore_backup() {".to_string());
    lines.push("  if [ -d \"$backup_dir\" ]; then".to_string());
    lines.push("    rm -rf \"$install_dir\"".to_string());
    lines.push("    mv \"$backup_dir\" \"$install_dir\"".to_string());
    lines.push("    if command -v systemctl >/dev/null 2>&1; then".to_string());
    lines.push("      systemctl restart v2node >/dev/null 2>&1 || true".to_string());
    lines.push("    elif command -v service >/dev/null 2>&1; then".to_string());
    lines.push("      service v2node restart >/dev/null 2>&1 || true".to_string());
    lines.push("    fi".to_string());
    lines.push("  fi".to_string());
    lines.push("}".to_string());
    lines.push("if [ -d \"$install_dir\" ]; then".to_string());
    lines.push("  cp -a \"$install_dir\" \"$backup_dir\"".to_string());
    lines.push("fi".to_string());
    lines.push("if ! curl -fsSL \"$install_script_url\" -o /tmp/v2node-install.sh; then".to_string());
    lines.push("  restore_backup".to_string());
    lines.push("  exit 1".to_string());
    lines.push("fi".to_string());
    lines.push("if ! bash /tmp/v2node-install.sh \"$target_version\"; then".to_string());
    lines.push("  restore_backup".to_string());
    lines.push("  exit 1".to_string());
    lines.push("fi".to_string());
    lines.push("installed_version=\"\"".to_string());
    lines.push("if [ -f \"$install_dir/.installed_version\" ]; then".to_string());
    lines.push("  installed_version=$(cat \"$install_dir/.installed_version\" || true)".to_string());
    lines.push("elif [ -x \"$install_dir/v2node\" ]; then".to_string());
    lines.push("  installed_version=$(\"$install_dir/v2node\" version 2>/dev/null | awk '{print $2}' | head -n 1 || true)".to_string());
    lines.push("fi".to_string());
    lines.push("normalize_version() {".to_string());
    lines.push("  printf '%s' \"$1\" | sed 's/^[vV]//'".to_string());
    lines.push("}".to_string());
    lines.push("if [ \"$(normalize_version \"$installed_version\")\" != \"$(normalize_version \"$target_version\")\" ]; then".to_string());
    lines.push("  restore_backup".to_string());
    lines.push("  exit 1".to_string());
    lines.push("fi".to_string());
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
    let output = output
        .trim_matches(|ch| ch == '.' || ch == '-')
        .to_string();
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
    env::split_paths(&paths).any(|path| candidate_tool_paths(&path, tool).iter().any(|candidate| {
        std::fs::metadata(candidate)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    }))
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
        shell_quote, upgrade_shell_script, valid_kelinode_version, versions_equal,
        MemoryUpgradeExecutor, UpgradeManager,
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
                },
                "1.2.3",
                100,
                &mut executor,
            )
            .unwrap()
            .unwrap();

        assert_eq!(status.status, "succeeded");
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
        };

        manager.request(command.clone(), "v1.2.3", 200, &mut executor).unwrap();
        manager.request(command, "v1.2.3", 201, &mut executor).unwrap();

        assert_eq!(executor.launches.len(), 1);
        assert_eq!(manager.current_status().unwrap().started_at, 200);
    }

    #[test]
    fn quotes_shell_values_like_go_agent() {
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
        assert!(versions_equal("v1.2.3", "1.2.3"));
    }

    #[test]
    fn upgrade_shell_script_verifies_install_and_restores_backup() {
        let script = upgrade_shell_script("v1.2.5");

        assert!(script.contains("restore_backup()"));
        assert!(script.contains("/usr/local/v2node.backup.${target_version}."));
        assert!(script.contains(".installed_version"));
        assert!(script.contains("normalize_version"));
        assert!(script.contains("bash /tmp/v2node-install.sh \"$target_version\""));
        assert!(script.contains("rm -rf \"$backup_dir\""));
    }
}
