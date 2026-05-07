use std::collections::BTreeMap;

use crate::config::NodeConfig;
use crate::panel::client::{PanelClient, PanelClientOptions};
use crate::panel::types::UserTraffic;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeActivitySnapshot {
    pub traffic: Vec<UserTraffic>,
    pub online: BTreeMap<u32, Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeActivityTarget {
    pub tag: String,
    pub config: NodeConfig,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeActivityReport {
    pub skipped: bool,
    pub unified: bool,
    pub legacy_traffic: bool,
    pub legacy_online: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeActivityBatchReport {
    pub reported: usize,
    pub skipped: usize,
    pub failures: Vec<NodeActivityFailure>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeActivityFailure {
    pub tag: String,
    pub error: String,
}

pub trait NodeActivitySender {
    fn report_snapshot(
        &mut self,
        traffic: &[UserTraffic],
        online: &BTreeMap<u32, Vec<String>>,
    ) -> Result<bool, String>;

    fn report_user_traffic(&mut self, traffic: &[UserTraffic]) -> Result<(), String>;

    fn report_online_users(&mut self, online: &BTreeMap<u32, Vec<String>>) -> Result<(), String>;
}

impl NodeActivitySnapshot {
    pub fn is_empty(&self) -> bool {
        self.traffic.is_empty() && self.online.is_empty()
    }
}

pub fn report_activity_with_fallback<S>(
    sender: &mut S,
    snapshot: &NodeActivitySnapshot,
) -> Result<NodeActivityReport, String>
where
    S: NodeActivitySender,
{
    if snapshot.is_empty() {
        return Ok(NodeActivityReport {
            skipped: true,
            ..NodeActivityReport::default()
        });
    }

    if sender.report_snapshot(&snapshot.traffic, &snapshot.online)? {
        return Ok(NodeActivityReport {
            unified: true,
            ..NodeActivityReport::default()
        });
    }

    let mut report = NodeActivityReport::default();
    if !snapshot.traffic.is_empty() {
        sender.report_user_traffic(&snapshot.traffic)?;
        report.legacy_traffic = true;
    }
    if !snapshot.online.is_empty() {
        sender.report_online_users(&snapshot.online)?;
        report.legacy_online = true;
    }
    Ok(report)
}

pub fn report_activity_batch_with<F>(
    targets: &[NodeActivityTarget],
    snapshots: &BTreeMap<String, NodeActivitySnapshot>,
    mut report_one: F,
) -> NodeActivityBatchReport
where
    F: FnMut(&NodeActivityTarget, &NodeActivitySnapshot) -> Result<NodeActivityReport, String>,
{
    let mut batch = NodeActivityBatchReport::default();
    for target in targets {
        let Some(snapshot) = snapshots.get(&target.tag) else {
            batch.skipped += 1;
            continue;
        };
        match report_one(target, snapshot) {
            Ok(report) if report.skipped => batch.skipped += 1,
            Ok(_) => batch.reported += 1,
            Err(error) => batch.failures.push(NodeActivityFailure {
                tag: target.tag.clone(),
                error,
            }),
        }
    }
    batch
}

pub async fn report_activity_to_panel(
    config: &NodeConfig,
    snapshot: &NodeActivitySnapshot,
) -> Result<NodeActivityReport, String> {
    if snapshot.is_empty() {
        return Ok(NodeActivityReport {
            skipped: true,
            ..NodeActivityReport::default()
        });
    }

    let options = PanelClientOptions::from(config);
    let client = PanelClient::new(options).map_err(|err| err.to_string())?;
    if client
        .report_snapshot(&snapshot.traffic, &snapshot.online)
        .await
        .map_err(|err| err.to_string())?
    {
        return Ok(NodeActivityReport {
            unified: true,
            ..NodeActivityReport::default()
        });
    }

    let mut report = NodeActivityReport::default();
    if !snapshot.traffic.is_empty() {
        client
            .report_user_traffic(&snapshot.traffic)
            .await
            .map_err(|err| err.to_string())?;
        report.legacy_traffic = true;
    }
    if !snapshot.online.is_empty() {
        client
            .report_online_users(&snapshot.online)
            .await
            .map_err(|err| err.to_string())?;
        report.legacy_online = true;
    }
    Ok(report)
}

pub async fn report_activity_batch_to_panel(
    targets: &[NodeActivityTarget],
    snapshots: &BTreeMap<String, NodeActivitySnapshot>,
) -> NodeActivityBatchReport {
    let mut batch = NodeActivityBatchReport::default();
    for target in targets {
        let Some(snapshot) = snapshots.get(&target.tag) else {
            batch.skipped += 1;
            continue;
        };
        match report_activity_to_panel(&target.config, snapshot).await {
            Ok(report) if report.skipped => batch.skipped += 1,
            Ok(_) => batch.reported += 1,
            Err(error) => batch.failures.push(NodeActivityFailure {
                tag: target.tag.clone(),
                error,
            }),
        }
    }
    batch
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        report_activity_batch_with, report_activity_with_fallback, NodeActivityReport,
        NodeActivitySender, NodeActivitySnapshot, NodeActivityTarget,
    };
    use crate::config::NodeConfig;
    use crate::panel::types::UserTraffic;

    #[test]
    fn skips_empty_activity_snapshot() {
        let mut sender = FakeSender::default();

        let report =
            report_activity_with_fallback(&mut sender, &NodeActivitySnapshot::default()).unwrap();

        assert_eq!(
            report,
            NodeActivityReport {
                skipped: true,
                ..NodeActivityReport::default()
            }
        );
        assert!(sender.calls.is_empty());
    }

    #[test]
    fn uses_unified_snapshot_when_supported() {
        let mut sender = FakeSender {
            unified_supported: true,
            ..FakeSender::default()
        };

        let report = report_activity_with_fallback(&mut sender, &sample_snapshot()).unwrap();

        assert!(report.unified);
        assert_eq!(sender.calls, vec!["snapshot"]);
    }

    #[test]
    fn falls_back_to_legacy_reports_when_unified_snapshot_is_not_supported() {
        let mut sender = FakeSender::default();

        let report = report_activity_with_fallback(&mut sender, &sample_snapshot()).unwrap();

        assert!(report.legacy_traffic);
        assert!(report.legacy_online);
        assert_eq!(sender.calls, vec!["snapshot", "traffic", "online"]);
    }

    #[test]
    fn batch_reporting_matches_targets_by_tag_and_records_failures() {
        let targets = vec![
            target("node-a"),
            target("node-b"),
            target("node-missing"),
            target("node-fail"),
        ];
        let mut snapshots = BTreeMap::new();
        snapshots.insert("node-a".to_string(), sample_snapshot());
        snapshots.insert("node-b".to_string(), NodeActivitySnapshot::default());
        snapshots.insert("node-fail".to_string(), sample_snapshot());

        let report = report_activity_batch_with(&targets, &snapshots, |target, snapshot| {
            if target.tag == "node-fail" {
                return Err("send failed".to_string());
            }
            if snapshot.is_empty() {
                return Ok(NodeActivityReport {
                    skipped: true,
                    ..NodeActivityReport::default()
                });
            }
            Ok(NodeActivityReport {
                unified: true,
                ..NodeActivityReport::default()
            })
        });

        assert_eq!(report.reported, 1);
        assert_eq!(report.skipped, 2);
        assert_eq!(report.failures[0].tag, "node-fail");
    }

    fn sample_snapshot() -> NodeActivitySnapshot {
        let mut online = BTreeMap::new();
        online.insert(7, vec!["198.51.100.7".to_string()]);
        NodeActivitySnapshot {
            traffic: vec![UserTraffic {
                uid: 7,
                upload: 10,
                download: 20,
            }],
            online,
        }
    }

    fn target(tag: &str) -> NodeActivityTarget {
        NodeActivityTarget {
            tag: tag.to_string(),
            config: NodeConfig::default(),
        }
    }

    #[derive(Default)]
    struct FakeSender {
        unified_supported: bool,
        calls: Vec<&'static str>,
    }

    impl NodeActivitySender for FakeSender {
        fn report_snapshot(
            &mut self,
            _traffic: &[UserTraffic],
            _online: &BTreeMap<u32, Vec<String>>,
        ) -> Result<bool, String> {
            self.calls.push("snapshot");
            Ok(self.unified_supported)
        }

        fn report_user_traffic(&mut self, _traffic: &[UserTraffic]) -> Result<(), String> {
            self.calls.push("traffic");
            Ok(())
        }

        fn report_online_users(
            &mut self,
            _online: &BTreeMap<u32, Vec<String>>,
        ) -> Result<(), String> {
            self.calls.push("online");
            Ok(())
        }
    }
}
