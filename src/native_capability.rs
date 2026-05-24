use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NativeProtocol {
    Socks,
    Http,
    Shadowsocks,
    Vless,
    Vmess,
    Trojan,
    AnyTls,
    Hysteria2,
    Tuic,
    Naive,
    Mieru,
    Direct,
    Dns,
    Route,
}

impl NativeProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Socks => "socks",
            Self::Http => "http",
            Self::Shadowsocks => "shadowsocks",
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::AnyTls => "anytls",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::Naive => "naive",
            Self::Mieru => "mieru",
            Self::Direct => "direct",
            Self::Dns => "dns",
            Self::Route => "route",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityDirection {
    Inbound,
    Outbound,
}

impl CapabilityDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityTransport {
    Tcp,
    Udp,
    Ws,
    HttpUpgrade,
    H2,
    Grpc,
    Quic,
    OldQuic,
    Direct,
}

impl CapabilityTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Ws => "ws",
            Self::HttpUpgrade => "httpupgrade",
            Self::H2 => "h2",
            Self::Grpc => "grpc",
            Self::Quic => "quic",
            Self::OldQuic => "old_quic",
            Self::Direct => "direct",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilitySecurity {
    None,
    Tls,
    Reality,
}

impl CapabilitySecurity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls => "tls",
            Self::Reality => "reality",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UdpMode {
    None,
    NativeUdp,
    UdpAssociate,
    UdpOverStream,
}

impl UdpMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::NativeUdp => "native_udp",
            Self::UdpAssociate => "udp_associate",
            Self::UdpOverStream => "udp_over_stream",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityStatus {
    Stable,
    UsableNeedsSoak,
    CanaryOnly,
    Experimental,
    Broken,
    Unsupported,
}

impl CapabilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::UsableNeedsSoak => "usable_needs_soak",
            Self::CanaryOnly => "canary_only",
            Self::Experimental => "experimental",
            Self::Broken => "broken",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderDecision {
    RenderNative,
    RenderNativeWithWarning,
    FallbackGo,
    Reject { reason: String },
}

impl RenderDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RenderNative => "render_native",
            Self::RenderNativeWithWarning => "render_native_with_warning",
            Self::FallbackGo => "fallback_go",
            Self::Reject { .. } => "reject",
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Reject { reason } => Some(reason),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaselineSource {
    GoLegacyBaseline,
    OfficialUpstreamBaseline,
    EcosystemInteropBaseline,
    Mixed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceLevel {
    UnitOnly,
    LocalLoopback,
    OfficialClientInterop,
    ThirdPartyClientInterop,
    SoakTested,
    ProductionObserved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityKey {
    pub protocol: NativeProtocol,
    pub direction: CapabilityDirection,
    pub transport: CapabilityTransport,
    pub security: CapabilitySecurity,
    pub udp_mode: UdpMode,
    pub flow: String,
    pub user_model: String,
    pub route_outbound: String,
}

impl CapabilityKey {
    pub fn dimension_summary(&self) -> String {
        format!(
            "protocol={} direction={} transport={} security={} udp_mode={} flow={} user_model={} route_outbound={}",
            self.protocol.as_str(),
            self.direction.as_str(),
            self.transport.as_str(),
            self.security.as_str(),
            self.udp_mode.as_str(),
            self.flow,
            self.user_model,
            self.route_outbound
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityEntry {
    pub key: CapabilityKey,
    pub status: CapabilityStatus,
    pub decision: RenderDecision,
    pub baseline_source: BaselineSource,
    pub baseline_reference: String,
    pub baseline_gap: String,
    pub evidence_level: EvidenceLevel,
    pub reason: String,
    pub required_tests: Vec<String>,
    pub current_evidence: Vec<String>,
    pub next_action: String,
}

impl CapabilityEntry {
    pub fn gate_message(&self) -> String {
        let mut message = format!(
            "{} status={} decision={} baseline_source={} evidence_level={} reason={}",
            self.key.dimension_summary(),
            self.status.as_str(),
            self.decision.as_str(),
            self.baseline_source,
            self.evidence_level,
            self.reason
        );
        if let Some(reason) = self.decision.reason() {
            message.push_str(" decision_reason=");
            message.push_str(reason);
        }
        message
    }
}

impl fmt::Display for BaselineSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GoLegacyBaseline => "GoLegacyBaseline",
            Self::OfficialUpstreamBaseline => "OfficialUpstreamBaseline",
            Self::EcosystemInteropBaseline => "EcosystemInteropBaseline",
            Self::Mixed => "Mixed",
        })
    }
}

impl fmt::Display for EvidenceLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnitOnly => "UnitOnly",
            Self::LocalLoopback => "LocalLoopback",
            Self::OfficialClientInterop => "OfficialClientInterop",
            Self::ThirdPartyClientInterop => "ThirdPartyClientInterop",
            Self::SoakTested => "SoakTested",
            Self::ProductionObserved => "ProductionObserved",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_key_formats_all_gate_dimensions() {
        let key = CapabilityKey {
            protocol: NativeProtocol::Trojan,
            direction: CapabilityDirection::Inbound,
            transport: CapabilityTransport::Ws,
            security: CapabilitySecurity::Tls,
            udp_mode: UdpMode::UdpOverStream,
            flow: "none".to_string(),
            user_model: "password".to_string(),
            route_outbound: "direct".to_string(),
        };

        assert_eq!(
            key.dimension_summary(),
            "protocol=trojan direction=inbound transport=ws security=tls udp_mode=udp_over_stream flow=none user_model=password route_outbound=direct"
        );
    }

    #[test]
    fn capability_entry_gate_message_includes_required_context() {
        let entry = CapabilityEntry {
            key: CapabilityKey {
                protocol: NativeProtocol::Trojan,
                direction: CapabilityDirection::Inbound,
                transport: CapabilityTransport::Ws,
                security: CapabilitySecurity::Tls,
                udp_mode: UdpMode::UdpOverStream,
                flow: "none".to_string(),
                user_model: "password".to_string(),
                route_outbound: "direct".to_string(),
            },
            status: CapabilityStatus::Broken,
            decision: RenderDecision::Reject {
                reason: "trojan websocket native relay is not production safe".to_string(),
            },
            baseline_source: BaselineSource::GoLegacyBaseline,
            baseline_reference: "kelinode/keli-core xray trojan websocket".to_string(),
            baseline_gap: "needs real client websocket interop".to_string(),
            evidence_level: EvidenceLevel::UnitOnly,
            reason: "known websocket relay maturity gap".to_string(),
            required_tests: vec!["trojan ws upgrade regression".to_string()],
            current_evidence: vec!["unit render coverage".to_string()],
            next_action: "keep rejected until websocket interop passes".to_string(),
        };

        let message = entry.gate_message();

        assert!(message.contains("protocol=trojan"));
        assert!(message.contains("direction=inbound"));
        assert!(message.contains("transport=ws"));
        assert!(message.contains("security=tls"));
        assert!(message.contains("udp_mode=udp_over_stream"));
        assert!(message.contains("status=broken"));
        assert!(message.contains("baseline_source=GoLegacyBaseline"));
        assert!(message.contains("evidence_level=UnitOnly"));
        assert!(message.contains("reason=known websocket relay maturity gap"));
    }
}
