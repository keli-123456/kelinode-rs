use std::collections::BTreeMap;

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

#[cfg(test)]
mod tests {
    use super::{apply_user_delta, compare_user_list};
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
}
