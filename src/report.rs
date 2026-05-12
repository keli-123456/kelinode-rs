use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::NodeConfig;
use crate::core::{CoreKind, CorePlan};
use crate::core_control::{KeliCoreControlClient, KeliCoreTrafficRecord};
use crate::panel::client::{PanelClient, PanelClientOptions};
use crate::panel::types::UserTraffic;
use crate::process::keli_core_rs_control_client;
use crate::runtime::{node_config_for_info, RuntimeBootstrapPlan};

pub type KeliCoreUserIdLookup = BTreeMap<String, BTreeMap<String, u32>>;

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
    fn drain_traffic(&mut self, minimum_bytes: u64) -> Result<Vec<KeliCoreTrafficRecord>, String>;

    fn requeue_traffic(&mut self, records: Vec<KeliCoreTrafficRecord>) -> Result<usize, String>;
}

impl KeliCoreTrafficDrainer for KeliCoreControlClient {
    fn drain_traffic(&mut self, minimum_bytes: u64) -> Result<Vec<KeliCoreTrafficRecord>, String> {
        KeliCoreControlClient::drain_traffic(self, minimum_bytes).map_err(|err| err.message)
    }

    fn requeue_traffic(&mut self, records: Vec<KeliCoreTrafficRecord>) -> Result<usize, String> {
        KeliCoreControlClient::requeue_traffic(self, records).map_err(|err| err.message)
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

#[cfg(test)]
fn requeue_failed_keli_core_records<D>(
    core_plan: &CorePlan,
    drainer: &mut D,
    records: &[KeliCoreTrafficRecord],
    batch: &NodeActivityBatchReport,
) -> Result<usize, String>
where
    D: KeliCoreTrafficDrainer,
{
    let requeue = failed_keli_core_records(core_plan, records, batch);
    if requeue.is_empty() {
        return Ok(0);
    }
    drainer.requeue_traffic(requeue)
}

fn failed_keli_core_records(
    core_plan: &CorePlan,
    records: &[KeliCoreTrafficRecord],
    batch: &NodeActivityBatchReport,
) -> Vec<KeliCoreTrafficRecord> {
    if batch.failures.is_empty() {
        return Vec::new();
    }
    let failed_tags = batch
        .failures
        .iter()
        .map(|failure| failure.tag.as_str())
        .collect::<BTreeSet<_>>();
    records
        .iter()
        .filter(|record| {
            keli_core_record_report_tag(core_plan, record)
                .map(|tag| failed_tags.contains(tag))
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

pub fn keli_core_traffic_snapshots(
    core_plan: &CorePlan,
    records: &[KeliCoreTrafficRecord],
) -> BTreeMap<String, NodeActivitySnapshot> {
    keli_core_traffic_snapshots_with_user_lookup(core_plan, records, &KeliCoreUserIdLookup::new())
}

pub fn keli_core_traffic_snapshots_with_user_lookup(
    core_plan: &CorePlan,
    records: &[KeliCoreTrafficRecord],
    user_lookup: &KeliCoreUserIdLookup,
) -> BTreeMap<String, NodeActivitySnapshot> {
    let mut snapshots = BTreeMap::new();
    for record in records {
        let Some((node_tag, uid)) = keli_core_record_report_target(core_plan, record, user_lookup)
        else {
            continue;
        };

        let snapshot = snapshots
            .entry(node_tag.to_string())
            .or_insert_with(NodeActivitySnapshot::default);
        merge_user_traffic(
            &mut snapshot.traffic,
            uid,
            u64_to_i64(record.upload),
            u64_to_i64(record.download),
        );
        merge_online_ips(&mut snapshot.online, uid, &record.online_ips);
    }
    snapshots
}

fn keli_core_record_report_target<'a>(
    core_plan: &'a CorePlan,
    record: &KeliCoreTrafficRecord,
    user_lookup: &KeliCoreUserIdLookup,
) -> Option<(&'a str, u32)> {
    core_plan.inbounds.iter().find_map(|inbound| {
        let node_tag = normalize_keli_core_record_tag(&record.node_tag, &inbound.tag)?;
        let uid = record
            .user_id
            .and_then(|id| u32::try_from(id).ok())
            .or_else(|| {
                user_lookup
                    .get(node_tag)
                    .and_then(|users| users.get(&record.user_uuid))
                    .copied()
            })
            .or_else(|| {
                inbound
                    .users
                    .iter()
                    .find(|user| user.uuid == record.user_uuid)
                    .map(|user| user.id)
            })?;
        Some((node_tag, uid))
    })
}

fn keli_core_record_report_tag<'a>(
    core_plan: &'a CorePlan,
    record: &KeliCoreTrafficRecord,
) -> Option<&'a str> {
    core_plan
        .inbounds
        .iter()
        .find_map(|inbound| normalize_keli_core_record_tag(&record.node_tag, &inbound.tag))
}

fn normalize_keli_core_record_tag<'a>(record_tag: &str, inbound_tag: &'a str) -> Option<&'a str> {
    if record_tag == inbound_tag {
        return Some(inbound_tag);
    }
    let suffix = record_tag.strip_prefix(inbound_tag)?;
    suffix
        .strip_prefix("|port:")
        .filter(|port| !port.is_empty() && port.chars().all(|value| value.is_ascii_digit()))
        .map(|_| inbound_tag)
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

fn merge_online_ips(online: &mut BTreeMap<u32, Vec<String>>, uid: u32, ips: &[String]) {
    if ips.is_empty() {
        return;
    }
    let entry = online.entry(uid).or_default();
    for ip in ips {
        if !entry.iter().any(|value| value == ip) {
            entry.push(ip.clone());
        }
    }
    entry.sort();
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
    report_keli_core_activity_to_panel_with_user_lookup(plan, &KeliCoreUserIdLookup::new()).await
}

pub async fn report_keli_core_activity_to_panel_with_user_lookup(
    plan: &RuntimeBootstrapPlan,
    user_lookup: &KeliCoreUserIdLookup,
) -> Result<NodeActivityBatchReport, String> {
    let Some(core_plan) = &plan.core_plan else {
        return Ok(NodeActivityBatchReport::default());
    };
    if core_plan.kind != CoreKind::KeliCoreRs {
        return Ok(NodeActivityBatchReport::default());
    }

    let mut client =
        keli_core_rs_control_client(&core_plan.config_path).map_err(|err| err.message)?;
    let spool_path = keli_core_traffic_spool_path(&core_plan.config_path);
    let mut records = load_pending_keli_core_traffic(&spool_path)?;
    let drained = KeliCoreTrafficDrainer::drain_traffic(&mut client, minimum_report_bytes(plan))?;
    records.extend(drained.iter().cloned());
    if records.is_empty() {
        return Ok(NodeActivityBatchReport::default());
    }
    save_pending_or_requeue_drained(&spool_path, &records, drained, &mut client)?;

    let snapshots = keli_core_traffic_snapshots_with_user_lookup(core_plan, &records, user_lookup);
    let targets = runtime_activity_targets(plan);
    let batch = report_activity_batch_to_panel(&targets, &snapshots).await;
    let failed = failed_keli_core_records(core_plan, &records, &batch);
    save_pending_keli_core_traffic(&spool_path, &failed)?;
    Ok(batch)
}

fn save_pending_or_requeue_drained<D>(
    spool_path: &Path,
    records: &[KeliCoreTrafficRecord],
    drained: Vec<KeliCoreTrafficRecord>,
    drainer: &mut D,
) -> Result<(), String>
where
    D: KeliCoreTrafficDrainer,
{
    if let Err(error) = save_pending_keli_core_traffic(spool_path, records) {
        if !drained.is_empty() {
            let _ = drainer.requeue_traffic(drained);
        }
        return Err(error);
    }
    Ok(())
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

pub fn keli_core_traffic_spool_path(config_path: impl AsRef<Path>) -> PathBuf {
    config_path.as_ref().with_extension("traffic.pending.json")
}

fn traffic_spool_tmp_path(path: &Path) -> PathBuf {
    let Some(file_name) = path.file_name() else {
        return path.with_extension("tmp");
    };
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    path.with_file_name(tmp_name)
}

fn load_pending_keli_core_traffic(
    path: impl AsRef<Path>,
) -> Result<Vec<KeliCoreTrafficRecord>, String> {
    let path = path.as_ref();
    match fs::read(path) {
        Ok(data) if data.is_empty() => Ok(Vec::new()),
        Ok(data) => serde_json::from_slice(&data)
            .map_err(|err| format!("decode pending traffic {}: {err}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!("read pending traffic {}: {error}", path.display())),
    }
}

fn save_pending_keli_core_traffic(
    path: impl AsRef<Path>,
    records: &[KeliCoreTrafficRecord],
) -> Result<(), String> {
    let path = path.as_ref();
    if records.is_empty() {
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "remove pending traffic {}: {error}",
                    path.display()
                ));
            }
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create pending traffic dir {}: {err}", parent.display()))?;
    }
    let data = serde_json::to_vec(records)
        .map_err(|err| format!("encode pending traffic {}: {err}", path.display()))?;
    let tmp = traffic_spool_tmp_path(path);
    fs::write(&tmp, data)
        .map_err(|err| format!("write pending traffic {}: {err}", tmp.display()))?;
    fs::rename(&tmp, path)
        .map_err(|err| format!("replace pending traffic {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        drain_keli_core_activity_snapshots, keli_core_traffic_snapshots,
        keli_core_traffic_snapshots_with_user_lookup, keli_core_traffic_spool_path,
        load_pending_keli_core_traffic, minimum_report_bytes, report_activity_batch_with,
        report_activity_with_fallback, requeue_failed_keli_core_records, runtime_activity_targets,
        save_pending_keli_core_traffic, save_pending_or_requeue_drained, KeliCoreTrafficDrainer,
        KeliCoreUserIdLookup, NodeActivityBatchReport, NodeActivityFailure, NodeActivityReport,
        NodeActivitySender, NodeActivitySnapshot, NodeActivityTarget,
    };
    use crate::config::{AgentConfig, NodeConfig, ResolvedConfig, ResolvedMachineConfig};
    use crate::core::{CoreKind, CorePlan, InboundPlan, InboundUserPlan};
    use crate::core_control::KeliCoreTrafficRecord;
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

        let records = vec![traffic_record_with_ips(
            "node-a",
            "uuid-a",
            1,
            1,
            vec!["198.51.100.7".to_string()],
        )];
        let snapshots = keli_core_traffic_snapshots(&core_plan(), &records);

        assert_eq!(
            snapshots["node-a"].online[&7],
            vec!["198.51.100.7".to_string()]
        );
    }

    #[test]
    fn maps_keli_core_traffic_records_by_user_id_after_user_deletion() {
        let records = vec![KeliCoreTrafficRecord {
            node_tag: "node-a".to_string(),
            user_uuid: "deleted-uuid".to_string(),
            user_id: Some(99),
            upload: 10,
            download: 20,
            online_ips: vec!["198.51.100.9".to_string()],
        }];

        let snapshots = keli_core_traffic_snapshots(&core_plan(), &records);

        assert_eq!(snapshots["node-a"].traffic[0].uid, 99);
        assert_eq!(snapshots["node-a"].traffic[0].upload, 10);
        assert_eq!(
            snapshots["node-a"].online[&99],
            vec!["198.51.100.9".to_string()]
        );
    }

    #[test]
    fn maps_keli_core_traffic_records_by_runtime_user_lookup() {
        let records = vec![KeliCoreTrafficRecord {
            node_tag: "node-a".to_string(),
            user_uuid: "delta-uuid".to_string(),
            user_id: None,
            upload: 10,
            download: 20,
            online_ips: vec!["198.51.100.10".to_string()],
        }];
        let mut lookup = KeliCoreUserIdLookup::new();
        lookup.insert(
            "node-a".to_string(),
            BTreeMap::from([("delta-uuid".to_string(), 42)]),
        );

        let snapshots =
            keli_core_traffic_snapshots_with_user_lookup(&core_plan(), &records, &lookup);

        assert_eq!(snapshots["node-a"].traffic[0].uid, 42);
        assert_eq!(snapshots["node-a"].traffic[0].upload, 10);
        assert_eq!(
            snapshots["node-a"].online[&42],
            vec!["198.51.100.10".to_string()]
        );
    }

    #[test]
    fn merges_online_ips_without_duplicates() {
        let records = vec![
            traffic_record_with_ips(
                "node-a",
                "uuid-a",
                1,
                1,
                vec![
                    "198.51.100.9".to_string(),
                    "198.51.100.7".to_string(),
                    "198.51.100.9".to_string(),
                ],
            ),
            traffic_record_with_ips(
                "node-a|port:2100",
                "uuid-a",
                1,
                1,
                vec!["198.51.100.8".to_string(), "198.51.100.7".to_string()],
            ),
        ];

        let snapshots = keli_core_traffic_snapshots(&core_plan(), &records);

        assert_eq!(
            snapshots["node-a"].online[&7],
            vec![
                "198.51.100.7".to_string(),
                "198.51.100.8".to_string(),
                "198.51.100.9".to_string()
            ]
        );
    }

    #[test]
    fn drains_keli_core_traffic_through_injected_client() {
        let mut drainer = FakeKeliCoreDrainer {
            records: vec![traffic_record("node-a", "uuid-b", 30, 40)],
            minimums: Vec::new(),
            requeued: Vec::new(),
        };

        let snapshots = drain_keli_core_activity_snapshots(&core_plan(), &mut drainer, 64).unwrap();

        assert_eq!(drainer.minimums, vec![64]);
        assert_eq!(snapshots["node-a"].traffic[0].uid, 8);
        assert_eq!(snapshots["node-a"].traffic[0].upload, 30);
    }

    #[test]
    fn requeues_only_failed_keli_core_traffic_records() {
        let records = vec![
            traffic_record("node-a", "uuid-a", 10, 20),
            traffic_record("node-b", "uuid-b", 30, 40),
            traffic_record("node-a|port:2100", "uuid-a", 1, 2),
        ];
        let batch = NodeActivityBatchReport {
            reported: 1,
            skipped: 0,
            failures: vec![NodeActivityFailure {
                tag: "node-a".to_string(),
                error: "send failed".to_string(),
            }],
        };
        let mut drainer = FakeKeliCoreDrainer {
            records: Vec::new(),
            minimums: Vec::new(),
            requeued: Vec::new(),
        };

        let count =
            requeue_failed_keli_core_records(&core_plan(), &mut drainer, &records, &batch).unwrap();

        assert_eq!(count, 2);
        assert_eq!(drainer.requeued.len(), 2);
        assert_eq!(drainer.requeued[0].node_tag, "node-a");
        assert_eq!(drainer.requeued[1].node_tag, "node-a|port:2100");
    }

    #[test]
    fn builds_keli_core_traffic_spool_path_next_to_core_config() {
        let path = keli_core_traffic_spool_path(PathBuf::from("/srv/v2node/config.json"));

        assert_eq!(
            path,
            PathBuf::from("/srv/v2node/config.traffic.pending.json")
        );
    }

    #[test]
    fn saves_loads_and_clears_pending_keli_core_traffic() {
        let dir = temp_test_dir("traffic-spool");
        let path = dir.join("config.traffic.pending.json");
        let records = vec![traffic_record_with_ips(
            "node-a",
            "uuid-a",
            10,
            20,
            vec!["198.51.100.7".to_string()],
        )];

        save_pending_keli_core_traffic(&path, &records).unwrap();

        let loaded = load_pending_keli_core_traffic(&path).unwrap();
        assert_eq!(loaded, records);

        save_pending_keli_core_traffic(&path, &[]).unwrap();

        assert!(!path.exists());
        assert!(load_pending_keli_core_traffic(&path).unwrap().is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupted_pending_keli_core_traffic_returns_clear_error() {
        let dir = temp_test_dir("traffic-spool-corrupt");
        let path = dir.join("config.traffic.pending.json");
        fs::write(&path, b"{not-json").unwrap();

        let error = load_pending_keli_core_traffic(&path).expect_err("corrupt pending error");

        assert!(error.contains("decode pending traffic"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pending_spool_save_failure_requeues_drained_records() {
        let dir = temp_test_dir("traffic-spool-save-failure");
        let path = dir.join("config.traffic.pending.json");
        fs::create_dir_all(&path).unwrap();
        let drained = vec![traffic_record("node-a", "uuid-a", 10, 20)];
        let records = drained.clone();
        let mut drainer = FakeKeliCoreDrainer {
            records: Vec::new(),
            minimums: Vec::new(),
            requeued: Vec::new(),
        };

        let error = save_pending_or_requeue_drained(&path, &records, drained.clone(), &mut drainer)
            .expect_err("save failure");

        assert!(
            error.contains("replace pending traffic") || error.contains("write pending traffic")
        );
        assert_eq!(drainer.requeued, drained);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pending_keli_core_records_survive_until_failed_node_reports_successfully() {
        let dir = temp_test_dir("traffic-spool-retry");
        let path = dir.join("config.traffic.pending.json");
        let pending = traffic_record("node-a", "uuid-a", 10, 20);
        let drained = traffic_record("node-a|port:2100", "uuid-a", 1, 2);
        save_pending_keli_core_traffic(&path, &[pending.clone()]).unwrap();

        let mut records = load_pending_keli_core_traffic(&path).unwrap();
        records.push(drained.clone());
        save_pending_keli_core_traffic(&path, &records).unwrap();

        let failed_batch = NodeActivityBatchReport {
            reported: 0,
            skipped: 0,
            failures: vec![NodeActivityFailure {
                tag: "node-a".to_string(),
                error: "panel unavailable".to_string(),
            }],
        };
        let failed = super::failed_keli_core_records(&core_plan(), &records, &failed_batch);
        save_pending_keli_core_traffic(&path, &failed).unwrap();

        assert_eq!(load_pending_keli_core_traffic(&path).unwrap(), records);

        let successful_batch = NodeActivityBatchReport {
            reported: 1,
            skipped: 0,
            failures: Vec::new(),
        };
        let failed = super::failed_keli_core_records(&core_plan(), &records, &successful_batch);
        save_pending_keli_core_traffic(&path, &failed).unwrap();

        assert!(load_pending_keli_core_traffic(&path).unwrap().is_empty());
        assert!(!path.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn folds_keli_core_expanded_port_tags_back_to_node_tag() {
        let records = vec![traffic_record("node-a|port:2100", "uuid-a", 12, 34)];

        let snapshots = keli_core_traffic_snapshots(&core_plan(), &records);

        assert!(snapshots.contains_key("node-a"));
        assert!(!snapshots.contains_key("node-a|port:2100"));
        assert_eq!(snapshots["node-a"].traffic[0].uid, 7);
        assert_eq!(snapshots["node-a"].traffic[0].upload, 12);
        assert_eq!(snapshots["node-a"].traffic[0].download, 34);
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

    #[test]
    fn uses_largest_node_report_minimum_for_keli_core_drain() {
        let resolved = ResolvedConfig {
            kernel: Default::default(),
            realtime: Default::default(),
            machine: ResolvedMachineConfig {
                enabled: false,
                continue_on_error: false,
                profiles: Vec::new(),
            },
            agent: AgentConfig::default(),
            nodes: vec![node_config(1), node_config(2)],
        };
        let nodes = vec![
            node_with_report_minimum(1, 64),
            node_with_report_minimum(2, 1024),
        ];
        let plan = build_runtime_bootstrap_plan(resolved, nodes, Vec::new()).unwrap();

        assert_eq!(minimum_report_bytes(&plan), 1024);
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

    fn node_config(node_id: u32) -> NodeConfig {
        NodeConfig {
            url: "https://panel.example.test".to_string(),
            token: format!("token-{node_id}"),
            node_id,
            ..NodeConfig::default()
        }
    }

    fn node_with_report_minimum(node_id: u32, minimum: u64) -> NodeInfo {
        let common: CommonNode = serde_json::from_value(serde_json::json!({
            "protocol": "socks",
            "server_port": 10000 + node_id,
            "base_config": {
                "node_report_min_traffic": minimum
            }
        }))
        .unwrap();
        NodeInfo::from_common("https://panel.example.test", node_id, common).unwrap()
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
                multiplexing: String::new(),
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
            user_id: None,
            upload,
            download,
            online_ips: Vec::new(),
        }
    }

    fn traffic_record_with_ips(
        node_tag: &str,
        user_uuid: &str,
        upload: u64,
        download: u64,
        online_ips: Vec<String>,
    ) -> KeliCoreTrafficRecord {
        KeliCoreTrafficRecord {
            node_tag: node_tag.to_string(),
            user_uuid: user_uuid.to_string(),
            user_id: None,
            upload,
            download,
            online_ips,
        }
    }

    fn temp_test_dir(label: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("kelinode-rs-{label}-{}-{now}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
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
        requeued: Vec<KeliCoreTrafficRecord>,
    }

    impl KeliCoreTrafficDrainer for FakeKeliCoreDrainer {
        fn drain_traffic(
            &mut self,
            minimum_bytes: u64,
        ) -> Result<Vec<KeliCoreTrafficRecord>, String> {
            self.minimums.push(minimum_bytes);
            Ok(self.records.clone())
        }

        fn requeue_traffic(
            &mut self,
            records: Vec<KeliCoreTrafficRecord>,
        ) -> Result<usize, String> {
            let count = records.len();
            self.requeued.extend(records);
            Ok(count)
        }
    }
}
