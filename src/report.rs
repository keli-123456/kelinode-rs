use std::collections::BTreeMap;

use crate::config::NodeConfig;
use crate::core::{CoreKind, CorePlan};
use crate::core_control::{KeliCoreControlClient, KeliCoreTrafficRecord};
use crate::panel::client::{PanelClient, PanelClientOptions};
use crate::panel::types::UserTraffic;
use crate::process::keli_core_rs_control_addr;
use crate::runtime::{node_config_for_info, RuntimeBootstrapPlan};

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

pub trait KeliCoreTrafficDrainer {
    fn drain_traffic(
        &mut self,
        minimum_bytes: u64,
    ) -> Result<Vec<KeliCoreTrafficRecord>, String>;
}

impl KeliCoreTrafficDrainer for KeliCoreControlClient {
    fn drain_traffic(
        &mut self,
        minimum_bytes: u64,
    ) -> Result<Vec<KeliCoreTrafficRecord>, String> {
        KeliCoreControlClient::drain_traffic(self, minimum_bytes).map_err(|err| err.message)
    }
}

impl NodeActivitySnapshot {
    pub fn is_empty(&self) -> bool {
        self.traffic.is_empty() && self.online.is_empty()
    }
}

pub fn drain_keli_core_activity_snapshots<D>(
    core_plan: &CorePlan,
    drainer: &mut D,
    minimum_bytes: u64,
) -> Result<BTreeMap<String, NodeActivitySnapshot>, String>
where
    D: KeliCoreTrafficDrainer,
{
    let records = drainer.drain_traffic(minimum_bytes)?;
    Ok(keli_core_traffic_snapshots(core_plan, &records))
}

pub fn keli_core_traffic_snapshots(
    core_plan: &CorePlan,
    records: &[KeliCoreTrafficRecord],
) -> BTreeMap<String, NodeActivitySnapshot> {
    let mut snapshots = BTreeMap::new();
    for record in records {
        let Some(uid) = core_plan.inbounds.iter().find_map(|inbound| {
            (inbound.tag == record.node_tag).then(|| {
                inbound
                    .users
                    .iter()
                    .find(|user| user.uuid == record.user_uuid)
                    .map(|user| user.id)
            })?
        }) else {
            continue;
        };

        let snapshot = snapshots.entry(record.node_tag.clone()).or_insert_with(
            NodeActivitySnapshot::default,
        );
        merge_user_traffic(
            &mut snapshot.traffic,
            uid,
            u64_to_i64(record.upload),
            u64_to_i64(record.download),
        );
    }
    snapshots
}

fn merge_user_traffic(traffic: &mut Vec<UserTraffic>, uid: u32, upload: i64, download: i64) {
    if let Some(existing) = traffic.iter_mut().find(|item| item.uid == uid) {
        existing.upload = existing.upload.saturating_add(upload);
        existing.download = existing.download.saturating_add(download);
        return;
    }
    traffic.push(UserTraffic {
        uid,
        upload,
        download,
    });
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
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

pub async fn report_keli_core_activity_to_panel(
    plan: &RuntimeBootstrapPlan,
) -> Result<NodeActivityBatchReport, String> {
    let Some(core_plan) = &plan.core_plan else {
        return Ok(NodeActivityBatchReport::default());
    };
    if core_plan.kind != CoreKind::KeliCoreRs {
        return Ok(NodeActivityBatchReport::default());
    }

    let mut client = KeliCoreControlClient::new(keli_core_rs_control_addr(&core_plan.config_path));
    let snapshots =
        drain_keli_core_activity_snapshots(core_plan, &mut client, minimum_report_bytes(plan))?;
    let targets = runtime_activity_targets(plan);
    Ok(report_activity_batch_to_panel(&targets, &snapshots).await)
}

pub fn runtime_activity_targets(plan: &RuntimeBootstrapPlan) -> Vec<NodeActivityTarget> {
    plan.node_infos
        .iter()
        .filter_map(|node| {
            node_config_for_info(&plan.resolved, node.id, &node.tag).map(|config| {
                NodeActivityTarget {
                    tag: node.tag.clone(),
                    config: config.clone(),
                }
            })
        })
        .collect()
}

fn minimum_report_bytes(plan: &RuntimeBootstrapPlan) -> u64 {
    plan.node_infos
        .iter()
        .filter_map(|node| {
            node.common
                .base_config
                .as_ref()
                .map(|config| config.node_report_min_traffic)
        })
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::{
        drain_keli_core_activity_snapshots, keli_core_traffic_snapshots,
        report_activity_batch_with, report_activity_with_fallback, KeliCoreTrafficDrainer,
        NodeActivityReport, NodeActivitySender, NodeActivitySnapshot, NodeActivityTarget,
        runtime_activity_targets,
    };
    use crate::core::{CoreKind, CorePlan, InboundPlan, InboundUserPlan};
    use crate::core_control::KeliCoreTrafficRecord;
    use crate::config::{AgentConfig, NodeConfig, ResolvedConfig, ResolvedMachineConfig};
    use crate::panel::types::{CommonNode, NodeInfo, UserTraffic};
    use crate::runtime::build_runtime_bootstrap_plan;

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

    #[test]
    fn maps_keli_core_traffic_records_to_activity_snapshots() {
        let records = vec![
            traffic_record("node-a", "uuid-a", 10, 20),
            traffic_record("node-a", "uuid-a", 1, 2),
            traffic_record("node-a", "missing", 100, 200),
        ];

        let snapshots = keli_core_traffic_snapshots(&core_plan(), &records);

        assert_eq!(snapshots["node-a"].traffic.len(), 1);
        assert_eq!(snapshots["node-a"].traffic[0].uid, 7);
        assert_eq!(snapshots["node-a"].traffic[0].upload, 11);
        assert_eq!(snapshots["node-a"].traffic[0].download, 22);
    }

    #[test]
    fn drains_keli_core_traffic_through_injected_client() {
        let mut drainer = FakeKeliCoreDrainer {
            records: vec![traffic_record("node-a", "uuid-b", 30, 40)],
            minimums: Vec::new(),
        };

        let snapshots = drain_keli_core_activity_snapshots(&core_plan(), &mut drainer, 64)
            .unwrap();

        assert_eq!(drainer.minimums, vec![64]);
        assert_eq!(snapshots["node-a"].traffic[0].uid, 8);
        assert_eq!(snapshots["node-a"].traffic[0].upload, 30);
    }

    #[test]
    fn builds_activity_targets_from_runtime_plan() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: false,
                continue_on_error: false,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: vec![NodeConfig {
                url: "https://panel.example.test".to_string(),
                token: "token".to_string(),
                node_id: 9,
                ..NodeConfig::default()
            }],
        };
        let common: CommonNode = serde_json::from_value(serde_json::json!({
            "protocol": "socks",
            "server_port": 1080
        }))
        .unwrap();
        let node = NodeInfo::from_common("https://panel.example.test", 9, common).unwrap();
        let plan = build_runtime_bootstrap_plan(resolved, vec![node.clone()], Vec::new()).unwrap();

        let targets = runtime_activity_targets(&plan);

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].tag, node.tag);
        assert_eq!(targets[0].config.token, "token");
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

    fn core_plan() -> CorePlan {
        CorePlan {
            kind: CoreKind::KeliCoreRs,
            config_path: PathBuf::from("/srv/v2node/config.json"),
            listen_tags: vec!["node-a".to_string()],
            inbounds: vec![InboundPlan {
                tag: "node-a".to_string(),
                protocol: "socks".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 1080,
                port_range: String::new(),
                security: "none".to_string(),
                network: "tcp".to_string(),
                network_settings: serde_json::Value::Null,
                flow: String::new(),
                cipher: String::new(),
                server_key: String::new(),
                vless_decryption: String::new(),
                padding_scheme: Vec::new(),
                congestion_control: String::new(),
                zero_rtt_handshake: false,
                up_mbps: 0,
                down_mbps: 0,
                obfs: String::new(),
                obfs_password: String::new(),
                ignore_client_bandwidth: false,
                alpn: Vec::new(),
                fallback_to_ipv4: false,
                cert_file: String::new(),
                key_file: String::new(),
                reject_unknown_sni: false,
                server_name: String::new(),
                reality_dest: String::new(),
                reality_xver: 0,
                reality_private_key: String::new(),
                reality_short_id: String::new(),
                reality_mldsa65_seed: String::new(),
                users: vec![user(7, "uuid-a"), user(8, "uuid-b")],
                routes: Vec::new(),
            }],
        }
    }

    fn user(id: u32, uuid: &str) -> InboundUserPlan {
        InboundUserPlan {
            id,
            uuid: uuid.to_string(),
            email: format!("node-a|{uuid}"),
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn traffic_record(
        node_tag: &str,
        user_uuid: &str,
        upload: u64,
        download: u64,
    ) -> KeliCoreTrafficRecord {
        KeliCoreTrafficRecord {
            node_tag: node_tag.to_string(),
            user_uuid: user_uuid.to_string(),
            upload,
            download,
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

    struct FakeKeliCoreDrainer {
        records: Vec<KeliCoreTrafficRecord>,
        minimums: Vec<u64>,
    }

    impl KeliCoreTrafficDrainer for FakeKeliCoreDrainer {
        fn drain_traffic(
            &mut self,
            minimum_bytes: u64,
        ) -> Result<Vec<KeliCoreTrafficRecord>, String> {
            self.minimums.push(minimum_bytes);
            Ok(self.records.clone())
        }
    }
}
