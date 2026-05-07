use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreKind {
    Xray,
    SingBox,
    Mihomo,
    Sidecar(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorePlan {
    pub kind: CoreKind,
    pub config_path: PathBuf,
    pub listen_tags: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoreApplyResult {
    pub restarted: bool,
    pub changed_tags: Vec<String>,
}

pub trait CoreAdapter {
    fn apply(&mut self, plan: CorePlan) -> Result<CoreApplyResult, CoreError>;
    fn stop(&mut self) -> Result<(), CoreError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreError {
    pub message: String,
}

impl CoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{CoreKind, CorePlan};

    #[test]
    fn core_plan_can_represent_external_xray() {
        let plan = CorePlan {
            kind: CoreKind::Xray,
            config_path: PathBuf::from("/etc/v2node/config.json"),
            listen_tags: vec!["[panel]-vless:1".to_string()],
        };

        assert_eq!(plan.listen_tags.len(), 1);
    }
}
