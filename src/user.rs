use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::config::{normalize_config_dir, DEFAULT_CONFIG_DIR};
use crate::panel::types::UserInfo;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserDeltaApplyResult {
    pub next: Vec<UserInfo>,
    pub deleted_applied: Vec<UserInfo>,
    pub added: Vec<UserInfo>,
    pub updated: Vec<UserInfo>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserListDiff {
    pub deleted: Vec<UserInfo>,
    pub added: Vec<UserInfo>,
    pub updated: Vec<UserInfo>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct UserSyncState {
    pub revision: i64,
    pub users: Vec<UserInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

pub fn apply_user_delta(
    old: &[UserInfo],
    deleted: &[UserInfo],
    upsert: &[UserInfo],
) -> UserDeltaApplyResult {
    let mut old_map = user_map_by_uuid(old);
    let mut result = UserDeltaApplyResult::default();

    for user in deleted {
        if let Some(old_user) = old_map.remove(&user.uuid) {
            result.deleted_applied.push(old_user);
        }
    }

    for user in upsert {
        if old_map.contains_key(&user.uuid) {
            result.updated.push(user.clone());
        } else {
            result.added.push(user.clone());
        }
        old_map.insert(user.uuid.clone(), user.clone());
    }

    result.next = old_map.into_values().collect();
    result
}

pub fn compare_user_list(old: &[UserInfo], new: &[UserInfo]) -> UserListDiff {
    let mut old_map = user_map_by_uuid(old);
    let mut diff = UserListDiff::default();

    for user in new {
        let Some(old_user) = old_map.remove(&user.uuid) else {
            diff.added.push(user.clone());
            continue;
        };
        if user_changed(&old_user, user) {
            diff.updated.push(user.clone());
        }
    }

    diff.deleted = old_map.into_values().collect();
    diff
}

fn user_map_by_uuid(users: &[UserInfo]) -> BTreeMap<String, UserInfo> {
    users
        .iter()
        .map(|user| (user.uuid.clone(), user.clone()))
        .collect()
}

fn user_changed(old: &UserInfo, new: &UserInfo) -> bool {
    old.id != new.id
        || old.speed_limit != new.speed_limit
        || old.device_limit != new.device_limit
}

pub fn user_sync_state_path(config_dir: &str, api_host: &str, node_id: u32) -> String {
    let mut base_dir = normalize_config_dir(config_dir);
    if base_dir == DEFAULT_CONFIG_DIR {
        base_dir = user_sync_state_dir();
    }
    format!(
        "{}/user_sync_{}_{}.json",
        base_dir.trim_end_matches('/'),
        sha1_hex(api_host.as_bytes()),
        node_id
    )
}

pub fn load_user_sync_state(path: impl AsRef<Path>) -> Result<UserSyncState, String> {
    let path = path.as_ref();
    let data = fs::read_to_string(path)
        .map_err(|err| format!("read user sync state {}: {err}", path.display()))?;
    serde_json::from_str(&data)
        .map_err(|err| format!("decode user sync state {}: {err}", path.display()))
}

pub fn save_user_sync_state(
    path: impl AsRef<Path>,
    state: &UserSyncState,
) -> Result<(), String> {
    let path = path.as_ref();
    let data = serde_json::to_vec(state)
        .map_err(|err| format!("encode user sync state {}: {err}", path.display()))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create user sync state dir {}: {err}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, data)
        .map_err(|err| format!("write user sync state {}: {err}", tmp.display()))?;
    fs::rename(&tmp, path)
        .map_err(|err| format!("replace user sync state {}: {err}", path.display()))
}

fn user_sync_state_dir() -> String {
    std::env::var("V2NODE_STATE_DIR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_CONFIG_DIR.to_string())
}

fn sha1_hex(data: &[u8]) -> String {
    let digest = Sha1::digest(data);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        apply_user_delta, compare_user_list, load_user_sync_state, save_user_sync_state,
        user_sync_state_path, UserSyncState,
    };
    use crate::panel::types::UserInfo;

    #[test]
    fn apply_user_delta_deletes_adds_and_updates_by_uuid() {
        let old = vec![
            user(1, "a", 0, 1),
            user(2, "b", 0, 1),
            user(3, "c", 0, 1),
        ];
        let deleted = vec![user(2, "b", 0, 1), user(99, "missing", 0, 1)];
        let upsert = vec![user(3, "c", 10, 1), user(4, "d", 0, 2)];

        let result = apply_user_delta(&old, &deleted, &upsert);

        assert_eq!(uuids(&result.next), vec!["a", "c", "d"]);
        assert_eq!(uuids(&result.deleted_applied), vec!["b"]);
        assert_eq!(uuids(&result.added), vec!["d"]);
        assert_eq!(uuids(&result.updated), vec!["c"]);
        assert_eq!(result.next[1].speed_limit, 10);
    }

    #[test]
    fn compare_user_list_detects_user_changes() {
        let old = vec![user(1, "a", 0, 1), user(2, "b", 0, 1)];
        let new = vec![user(1, "a", 0, 2), user(3, "c", 0, 1)];

        let diff = compare_user_list(&old, &new);

        assert_eq!(uuids(&diff.deleted), vec!["b"]);
        assert_eq!(uuids(&diff.added), vec!["c"]);
        assert_eq!(uuids(&diff.updated), vec!["a"]);
    }

    #[test]
    fn user_sync_state_path_matches_go_layout() {
        let path = user_sync_state_path("/srv/v2node", "https://panel.example.test", 7);

        assert!(path.starts_with("/srv/v2node/user_sync_"));
        assert!(path.ends_with("_7.json"));
    }

    #[test]
    fn saves_and_loads_user_sync_state() {
        let dir = temp_test_dir("user-sync-state");
        let path = dir.join("state").join("user_sync.json");
        let state = UserSyncState {
            revision: 42,
            users: vec![user(1, "a", 0, 1)],
            updated_at: None,
        };

        save_user_sync_state(&path, &state).unwrap();
        let loaded = load_user_sync_state(&path).unwrap();

        assert_eq!(loaded, state);

        let _ = fs::remove_dir_all(dir);
    }

    fn user(id: u32, uuid: &str, speed_limit: u32, device_limit: u32) -> UserInfo {
        UserInfo {
            id,
            uuid: uuid.to_string(),
            speed_limit,
            device_limit,
        }
    }

    fn uuids(users: &[UserInfo]) -> Vec<&str> {
        users.iter().map(|user| user.uuid.as_str()).collect()
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
}
