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

pub fn native_capability_matrix() -> Vec<CapabilityEntry> {
    use BaselineSource::*;
    use CapabilityDirection::*;
    use CapabilitySecurity::{None as NoSecurity, Reality, Tls};
    use CapabilityStatus::*;
    use CapabilityTransport::{
        Direct as DirectTransport, Grpc, HttpUpgrade, Quic, Tcp, Udp, Ws, H2,
    };
    use EvidenceLevel::*;
    use NativeProtocol::{
        AnyTls, Direct as DirectProtocol, Dns, Http, Hysteria2, Mieru, Naive, Route, Shadowsocks,
        Socks, Trojan, Tuic, Vless, Vmess,
    };
    use RenderDecision::*;
    use UdpMode::{NativeUdp, None as NoUdp, UdpAssociate, UdpOverStream};

    vec![
        entry(
            Socks,
            Inbound,
            Tcp,
            NoSecurity,
            UdpAssociate,
            "password",
            UsableNeedsSoak,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray SOCKS inbound behavior",
            "needs longer mixed TCP/UDP gray soak",
            "SOCKS TCP and UDP ASSOCIATE render native but still need gray load evidence",
            &["socks auth tcp relay", "socks udp associate relay"],
            &["renderer coverage", "local listener smoke"],
            "run real client TCP and UDP soak before stable",
        ),
        entry(
            Http,
            Inbound,
            Tcp,
            NoSecurity,
            NoUdp,
            "password",
            UsableNeedsSoak,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray HTTP proxy inbound behavior",
            "needs longer CONNECT/plain HTTP gray soak",
            "HTTP proxy renders native with unit and local listener evidence",
            &["http connect relay", "plain http forwarding"],
            &["renderer coverage", "local listener smoke"],
            "run real client HTTP proxy soak before stable",
        ),
        entry(
            Shadowsocks,
            Inbound,
            Tcp,
            NoSecurity,
            NativeUdp,
            "password",
            UsableNeedsSoak,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray Shadowsocks AEAD behavior",
            "needs third-party client TCP/UDP soak",
            "AEAD TCP/UDP is native-rendered and validated for supported ciphers",
            &["shadowsocks aead tcp relay", "shadowsocks udp relay"],
            &["renderer coverage", "cipher validation coverage"],
            "run AEAD TCP/UDP client interop before stable",
        ),
        entry(
            Vless,
            Inbound,
            Tcp,
            Tls,
            UdpOverStream,
            "uuid",
            UsableNeedsSoak,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VLESS TCP TLS behavior",
            "needs broad client TLS soak and SNI/ALPN evidence",
            "VLESS TCP TLS native path renders with explicit warning until soak completes",
            &[
                "vless tls auth",
                "vless tls relay",
                "vless tls cert behavior",
            ],
            &["renderer coverage", "TLS config write coverage"],
            "run VLESS TCP TLS real-client soak before stable",
        ),
        entry(
            Vless,
            Inbound,
            Tcp,
            NoSecurity,
            UdpOverStream,
            "uuid",
            UsableNeedsSoak,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VLESS TCP behavior",
            "needs broad client soak for TCP and UDP command",
            "VLESS TCP native path has local loopback coverage",
            &["vless tcp auth", "vless tcp relay", "vless udp command"],
            &["renderer coverage", "local loopback tests"],
            "run gray TCP/UDP client soak before stable",
        ),
        entry_with_flow(
            Vless,
            Inbound,
            Tcp,
            Tls,
            UdpOverStream,
            "xtls-rprx-vision",
            "uuid",
            CanaryOnly,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VLESS TLS Vision behavior",
            "needs real client Vision TLS interop and soak",
            "VLESS TLS Vision renders native but remains canary-gated",
            &["vless vision tls validation", "vless vision tls loopback"],
            &["renderer coverage", "flow validation coverage"],
            "run VLESS Vision TLS real-client interop",
        ),
        entry_with_flow(
            Vless,
            Inbound,
            Tcp,
            Reality,
            UdpOverStream,
            "xtls-rprx-vision",
            "uuid",
            CanaryOnly,
            RenderNativeWithWarning,
            Mixed,
            LocalLoopback,
            "Xray VLESS REALITY Vision behavior plus ecosystem clients",
            "needs real client REALITY Vision interop and soak",
            "REALITY Vision renders native but remains canary-gated",
            &["vless reality vision validation", "vless reality loopback"],
            &["renderer coverage", "local reality listener tests"],
            "run v2rayN/NekoBox/sing-box REALITY interop",
        ),
        entry(
            Vless,
            Inbound,
            Ws,
            NoSecurity,
            UdpOverStream,
            "uuid",
            CanaryOnly,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VLESS WebSocket behavior",
            "needs WebSocket fragmentation and browser/CDN soak",
            "VLESS WS renders native with local coverage but needs soak",
            &["vless ws upgrade", "vless ws relay"],
            &["renderer coverage", "websocket runtime tests"],
            "run CDN-shaped WS client soak before stable",
        ),
        entry(
            Vless,
            Inbound,
            Ws,
            Tls,
            UdpOverStream,
            "uuid",
            CanaryOnly,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VLESS WebSocket behavior",
            "needs WebSocket fragmentation and browser/CDN soak",
            "VLESS WS/TLS renders native with local coverage but needs soak",
            &["vless ws upgrade", "vless tls ws relay"],
            &["renderer coverage", "websocket runtime tests"],
            "run CDN-shaped WS client soak before stable",
        ),
        entry(
            Vless,
            Inbound,
            HttpUpgrade,
            NoSecurity,
            UdpOverStream,
            "uuid",
            CanaryOnly,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VLESS HTTPUpgrade behavior",
            "needs HTTPUpgrade real-client soak",
            "VLESS HTTPUpgrade renders native with local coverage but needs soak",
            &["vless httpupgrade upgrade", "vless httpupgrade relay"],
            &["renderer coverage"],
            "run HTTPUpgrade real-client soak before stable",
        ),
        entry(
            Vless,
            Inbound,
            Grpc,
            NoSecurity,
            UdpOverStream,
            "uuid",
            CanaryOnly,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VLESS gRPC behavior",
            "needs gRPC real-client soak",
            "VLESS gRPC renders native with local coverage but needs soak",
            &["vless grpc relay"],
            &["renderer coverage", "local grpc runtime tests"],
            "run gRPC real-client soak before stable",
        ),
        entry(
            Vmess,
            Inbound,
            Tcp,
            Tls,
            UdpOverStream,
            "uuid",
            CanaryOnly,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VMess TLS behavior",
            "needs VMess TLS real-client soak",
            "VMess TLS renders native but remains canary-gated",
            &["vmess tls auth", "vmess tls relay"],
            &["renderer coverage", "tls validation coverage"],
            "run VMess TLS real-client soak before stable",
        ),
        entry(
            Vmess,
            Inbound,
            Tcp,
            NoSecurity,
            UdpOverStream,
            "uuid",
            UsableNeedsSoak,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VMess AEAD behavior",
            "needs legacy and AEAD mixed client soak",
            "VMess TCP native path has validation and local listener coverage",
            &[
                "vmess aead auth",
                "vmess tcp relay",
                "vmess udp over stream",
            ],
            &["renderer coverage", "local listener smoke"],
            "run VMess AEAD and legacy route-outbound soak",
        ),
        entry(
            Vmess,
            Inbound,
            Ws,
            NoSecurity,
            UdpOverStream,
            "uuid",
            CanaryOnly,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VMess WebSocket behavior",
            "needs WebSocket fragmentation and third-party client soak",
            "VMess WS renders native but still needs soak",
            &["vmess ws upgrade", "vmess ws relay"],
            &["renderer coverage", "websocket runtime tests"],
            "run VMess WS real-client soak",
        ),
        entry(
            Vmess,
            Inbound,
            Ws,
            Tls,
            UdpOverStream,
            "uuid",
            CanaryOnly,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VMess WebSocket behavior",
            "needs WebSocket fragmentation and third-party client soak",
            "VMess WS/TLS renders native but still needs soak",
            &["vmess ws upgrade", "vmess tls ws relay"],
            &["renderer coverage", "websocket runtime tests"],
            "run VMess WS/TLS real-client soak",
        ),
        entry(
            Vmess,
            Inbound,
            HttpUpgrade,
            NoSecurity,
            UdpOverStream,
            "uuid",
            CanaryOnly,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VMess HTTPUpgrade behavior",
            "needs HTTPUpgrade real-client soak",
            "VMess HTTPUpgrade renders native but still needs soak",
            &["vmess httpupgrade relay"],
            &["renderer coverage"],
            "run VMess HTTPUpgrade real-client soak",
        ),
        entry(
            Vmess,
            Inbound,
            Grpc,
            NoSecurity,
            UdpOverStream,
            "uuid",
            CanaryOnly,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray VMess gRPC behavior",
            "needs gRPC real-client soak",
            "VMess gRPC renders native but still needs soak",
            &["vmess grpc relay"],
            &["renderer coverage"],
            "run VMess gRPC real-client soak",
        ),
        entry(
            Trojan,
            Inbound,
            Tcp,
            NoSecurity,
            UdpOverStream,
            "password",
            UsableNeedsSoak,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray Trojan TCP behavior",
            "needs tail-traffic and mixed-route soak",
            "Trojan TCP native path is usable but not yet stable",
            &["trojan tcp auth", "trojan tcp relay", "trojan accounting"],
            &["renderer coverage", "local auth smoke"],
            "complete Trojan TCP accounting and user-delta regression",
        ),
        entry(
            Trojan,
            Inbound,
            Tcp,
            Tls,
            UdpOverStream,
            "password",
            CanaryOnly,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "kelinode/keli-core Xray Trojan TLS behavior",
            "needs SNI/ALPN/cert interop and soak",
            "Trojan TLS native path is canary-only until TLS matrix passes",
            &["trojan tls auth", "trojan sni cert behavior"],
            &["renderer coverage", "TLS validation coverage"],
            "run Trojan TLS client interop before widening",
        ),
        entry(
            Trojan,
            Inbound,
            Ws,
            NoSecurity,
            UdpOverStream,
            "password",
            Broken,
            Reject {
                reason: "trojan websocket native relay is not production safe".to_string(),
            },
            GoLegacyBaseline,
            UnitOnly,
            "kelinode/keli-core Xray Trojan WebSocket behavior",
            "needs websocket upgrade, frame split, close, and real-client interop",
            "Trojan WS has known maturity gaps and must not default native",
            &[
                "trojan ws upgrade",
                "trojan ws split frames",
                "trojan ws close",
            ],
            &["unit render evidence only"],
            "fix websocket relay and add interop before native rendering",
        ),
        entry(
            Trojan,
            Inbound,
            Ws,
            Tls,
            UdpOverStream,
            "password",
            Broken,
            Reject {
                reason: "trojan tls websocket native relay is not production safe".to_string(),
            },
            GoLegacyBaseline,
            UnitOnly,
            "kelinode/keli-core Xray Trojan TLS WebSocket behavior",
            "needs TLS/SNI before WS upgrade and real-client interop",
            "Trojan TLS WS has known maturity gaps and must not default native",
            &[
                "trojan tls ws upgrade",
                "trojan ws frame split",
                "trojan ping pong",
            ],
            &["unit render evidence only"],
            "fix TLS websocket relay and add interop before native rendering",
        ),
        entry(
            Trojan,
            Inbound,
            Grpc,
            Tls,
            UdpOverStream,
            "password",
            Experimental,
            Reject {
                reason: "trojan grpc native inbound lacks production interop evidence".to_string(),
            },
            GoLegacyBaseline,
            UnitOnly,
            "kelinode/keli-core Xray Trojan gRPC behavior",
            "needs gRPC client interop and soak",
            "Trojan gRPC is not production-gated native yet",
            &["trojan grpc relay", "trojan grpc tls relay"],
            &["renderer evidence only"],
            "add Trojan gRPC runtime and interop tests",
        ),
        entry(
            Trojan,
            Inbound,
            HttpUpgrade,
            Tls,
            UdpOverStream,
            "password",
            Experimental,
            Reject {
                reason: "trojan httpupgrade native inbound lacks production interop evidence"
                    .to_string(),
            },
            GoLegacyBaseline,
            UnitOnly,
            "kelinode/keli-core Xray Trojan HTTPUpgrade behavior",
            "needs HTTPUpgrade client interop and soak",
            "Trojan HTTPUpgrade is not production-gated native yet",
            &["trojan httpupgrade relay", "trojan httpupgrade tls relay"],
            &["renderer evidence only"],
            "add Trojan HTTPUpgrade runtime and interop tests",
        ),
        entry(
            AnyTls,
            Inbound,
            Tcp,
            NoSecurity,
            UdpOverStream,
            "password",
            CanaryOnly,
            RenderNativeWithWarning,
            EcosystemInteropBaseline,
            LocalLoopback,
            "sing-box AnyTLS behavior and ecosystem clients",
            "needs real-client padding and soak evidence",
            "AnyTLS plain listener is accepted for panel compatibility but canary-only",
            &["anytls auth", "anytls relay"],
            &["renderer coverage", "local listener smoke"],
            "prefer TLS AnyTLS and run ecosystem client soak",
        ),
        entry(
            AnyTls,
            Inbound,
            Tcp,
            Tls,
            UdpOverStream,
            "password",
            CanaryOnly,
            RenderNativeWithWarning,
            EcosystemInteropBaseline,
            LocalLoopback,
            "sing-box AnyTLS behavior and ecosystem clients",
            "needs real-client padding and soak evidence",
            "AnyTLS is native-rendered but canary-only",
            &["anytls auth", "anytls padding", "anytls relay"],
            &["renderer coverage", "local listener smoke"],
            "run ecosystem client AnyTLS soak",
        ),
        entry(
            Hysteria2,
            Inbound,
            Quic,
            Tls,
            NativeUdp,
            "password",
            UsableNeedsSoak,
            RenderNativeWithWarning,
            Mixed,
            LocalLoopback,
            "Go legacy HY2 behavior plus official/third-party QUIC clients",
            "needs longer TCP/UDP QUIC soak and congestion evidence",
            "HY2 TCP/UDP native path has local regression evidence",
            &["hy2 password auth", "hy2 tcp relay", "hy2 udp relay"],
            &["renderer coverage", "local QUIC regression tests"],
            "run remote QUIC soak on high ports before stable",
        ),
        entry(
            Tuic,
            Inbound,
            Quic,
            Tls,
            NativeUdp,
            "uuid_password",
            UsableNeedsSoak,
            RenderNativeWithWarning,
            Mixed,
            LocalLoopback,
            "TUIC protocol behavior plus ecosystem clients",
            "needs longer TCP/UDP QUIC soak and zero-RTT rejection evidence",
            "TUIC TCP/UDP native path has local regression evidence",
            &["tuic auth", "tuic tcp relay", "tuic udp relay"],
            &["renderer coverage", "local QUIC regression tests"],
            "run TUIC remote soak before stable",
        ),
        entry(
            Naive,
            Inbound,
            H2,
            Tls,
            NoUdp,
            "basic_auth",
            CanaryOnly,
            RenderNativeWithWarning,
            OfficialUpstreamBaseline,
            OfficialClientInterop,
            "official NaiveProxy H2/TLS CONNECT behavior",
            "missing SoakTested evidence",
            "Naive H2/TLS passed short official-client interop but cannot be Stable without soak",
            &["naive h2 connect", "naive basic auth", "naive padding"],
            &[
                "local h2 listener tests",
                "2026-05-24 official NaiveProxy remote 3-round H2/TLS probe passed on 2.56.116.39",
            ],
            "run official NaiveProxy client script and soak",
        ),
        entry(
            Naive,
            Inbound,
            Quic,
            Tls,
            NoUdp,
            "basic_auth",
            CanaryOnly,
            RenderNativeWithWarning,
            OfficialUpstreamBaseline,
            LocalLoopback,
            "official NaiveProxy H3/QUIC CONNECT behavior",
            "official-client H3 probe failed certificate validation; missing OfficialClientInterop + SoakTested evidence",
            "Naive H3/QUIC remains canary until official-client certificate validation and soak pass",
            &["naive h3 connect", "naive h3 reconnect", "naive h3 auth"],
            &[
                "local h3 loopback tests",
                "2026-05-24 official NaiveProxy remote H3/QUIC probe failed certificate unknown on 2.56.116.39",
            ],
            "run official NaiveProxy H3 client and soak before widening",
        ),
        entry(
            Mieru,
            Inbound,
            Tcp,
            NoSecurity,
            UdpOverStream,
            "username_password",
            CanaryOnly,
            RenderNativeWithWarning,
            OfficialUpstreamBaseline,
            OfficialClientInterop,
            "official Mieru TCP underlay protocol behavior",
            "missing SoakTested evidence",
            "Mieru TCP underlay passed short official-client interop but cannot be Stable without soak",
            &[
                "mieru tcp underlay",
                "mieru stream demux",
                "mieru udp associate over tcp",
            ],
            &[
                "renderer coverage",
                "local listener smoke",
                "2026-05-24 official Mieru v3.32.0 remote 3-round TCP/UDP-associate probe passed on 2.56.116.39",
            ],
            "run longer official Mieru soak before widening",
        ),
        entry(
            Mieru,
            Inbound,
            Udp,
            NoSecurity,
            NativeUdp,
            "username_password",
            Unsupported,
            Reject {
                reason: "mieru udp underlay is not implemented in native core".to_string(),
            },
            OfficialUpstreamBaseline,
            UnitOnly,
            "official Mieru UDP underlay protocol behavior",
            "implementation missing; OfficialClientInterop + SoakTested impossible yet",
            "Mieru UDP underlay is explicitly unsupported",
            &["mieru udp underlay reject"],
            &["capability matrix evidence"],
            "implement UDP underlay before adding interop",
        ),
        entry(
            DirectProtocol,
            Outbound,
            DirectTransport,
            NoSecurity,
            NativeUdp,
            "none",
            UsableNeedsSoak,
            RenderNative,
            GoLegacyBaseline,
            LocalLoopback,
            "keli-core freedom/direct outbound behavior",
            "needs longer route soak",
            "Direct outbound is the native default outbound",
            &["direct tcp route", "direct udp route"],
            &["renderer coverage"],
            "keep route soak evidence current",
        ),
        entry(
            Dns,
            Outbound,
            Udp,
            NoSecurity,
            NativeUdp,
            "none",
            UsableNeedsSoak,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "Go/Xray DNS route behavior",
            "DoH/DoT and production resolver soak still missing",
            "DNS UDP/tcp route rendering is partial but explicit",
            &["dns udp resolution", "dns private ip guard"],
            &["renderer coverage", "local resolver tests"],
            "run DNS route soak with production resolver set",
        ),
        entry(
            Route,
            Inbound,
            DirectTransport,
            NoSecurity,
            NativeUdp,
            "none",
            UsableNeedsSoak,
            RenderNativeWithWarning,
            GoLegacyBaseline,
            LocalLoopback,
            "Go/Xray route, block, and custom outbound behavior",
            "geo data and custom outbound soak still partial",
            "Route/block/custom outbound rendering rejects unsupported options loudly",
            &["domain block", "ip cidr block", "custom outbound route"],
            &["renderer coverage", "route validation coverage"],
            "run route matrix soak with geosite/geoip fixtures",
        ),
    ]
}

pub fn lookup_capability_entry(key: &CapabilityKey) -> Option<CapabilityEntry> {
    native_capability_matrix()
        .into_iter()
        .find(|entry| capability_key_matches(&entry.key, key))
}

pub fn unsupported_capability_entry(
    key: CapabilityKey,
    reason: impl Into<String>,
) -> CapabilityEntry {
    let reason = reason.into();
    CapabilityEntry {
        key,
        status: CapabilityStatus::Unsupported,
        decision: RenderDecision::Reject {
            reason: reason.clone(),
        },
        baseline_source: BaselineSource::Mixed,
        baseline_reference: "native capability matrix".to_string(),
        baseline_gap: "no matching capability entry".to_string(),
        evidence_level: EvidenceLevel::UnitOnly,
        reason,
        required_tests: vec!["add explicit capability matrix entry".to_string()],
        current_evidence: vec!["capability lookup miss".to_string()],
        next_action: "classify this combination before native rendering".to_string(),
    }
}

fn capability_key_matches(matrix_key: &CapabilityKey, requested: &CapabilityKey) -> bool {
    matrix_key.protocol == requested.protocol
        && matrix_key.direction == requested.direction
        && matrix_key.transport == requested.transport
        && matrix_key.security == requested.security
        && matrix_key.udp_mode == requested.udp_mode
        && matrix_key.flow == requested.flow
}

fn entry(
    protocol: NativeProtocol,
    direction: CapabilityDirection,
    transport: CapabilityTransport,
    security: CapabilitySecurity,
    udp_mode: UdpMode,
    user_model: &str,
    status: CapabilityStatus,
    decision: RenderDecision,
    baseline_source: BaselineSource,
    evidence_level: EvidenceLevel,
    baseline_reference: &str,
    baseline_gap: &str,
    reason: &str,
    required_tests: &[&str],
    current_evidence: &[&str],
    next_action: &str,
) -> CapabilityEntry {
    entry_with_flow(
        protocol,
        direction,
        transport,
        security,
        udp_mode,
        "none",
        user_model,
        status,
        decision,
        baseline_source,
        evidence_level,
        baseline_reference,
        baseline_gap,
        reason,
        required_tests,
        current_evidence,
        next_action,
    )
}

fn entry_with_flow(
    protocol: NativeProtocol,
    direction: CapabilityDirection,
    transport: CapabilityTransport,
    security: CapabilitySecurity,
    udp_mode: UdpMode,
    flow: &str,
    user_model: &str,
    status: CapabilityStatus,
    decision: RenderDecision,
    baseline_source: BaselineSource,
    evidence_level: EvidenceLevel,
    baseline_reference: &str,
    baseline_gap: &str,
    reason: &str,
    required_tests: &[&str],
    current_evidence: &[&str],
    next_action: &str,
) -> CapabilityEntry {
    CapabilityEntry {
        key: CapabilityKey {
            protocol,
            direction,
            transport,
            security,
            udp_mode,
            flow: flow.to_string(),
            user_model: user_model.to_string(),
            route_outbound: route_outbound_label(direction),
        },
        status,
        decision,
        baseline_source,
        baseline_reference: baseline_reference.to_string(),
        baseline_gap: baseline_gap.to_string(),
        evidence_level,
        reason: reason.to_string(),
        required_tests: required_tests
            .iter()
            .map(|value| value.to_string())
            .collect(),
        current_evidence: current_evidence
            .iter()
            .map(|value| value.to_string())
            .collect(),
        next_action: next_action.to_string(),
    }
}

fn route_outbound_label(direction: CapabilityDirection) -> String {
    match direction {
        CapabilityDirection::Inbound => "per_inbound_routes".to_string(),
        CapabilityDirection::Outbound => "outbound".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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

    #[test]
    fn initial_matrix_covers_all_required_protocols() {
        let protocols = native_capability_matrix()
            .iter()
            .map(|entry| entry.key.protocol)
            .collect::<BTreeSet<_>>();

        for protocol in [
            NativeProtocol::Socks,
            NativeProtocol::Http,
            NativeProtocol::Shadowsocks,
            NativeProtocol::Vless,
            NativeProtocol::Vmess,
            NativeProtocol::Trojan,
            NativeProtocol::AnyTls,
            NativeProtocol::Hysteria2,
            NativeProtocol::Tuic,
            NativeProtocol::Naive,
            NativeProtocol::Mieru,
            NativeProtocol::Direct,
            NativeProtocol::Dns,
            NativeProtocol::Route,
        ] {
            assert!(
                protocols.contains(&protocol),
                "missing matrix entry for {}",
                protocol.as_str()
            );
        }
    }

    #[test]
    fn initial_matrix_blocks_trojan_websocket_default_native() {
        let matrix = native_capability_matrix();
        for (transport, security) in [
            (CapabilityTransport::Ws, CapabilitySecurity::None),
            (CapabilityTransport::Ws, CapabilitySecurity::Tls),
        ] {
            let entry = matrix
                .iter()
                .find(|entry| {
                    entry.key.protocol == NativeProtocol::Trojan
                        && entry.key.direction == CapabilityDirection::Inbound
                        && entry.key.transport == transport
                        && entry.key.security == security
                })
                .expect("trojan websocket entry");

            assert!(matches!(
                entry.status,
                CapabilityStatus::Broken | CapabilityStatus::Experimental
            ));
            assert!(matches!(entry.decision, RenderDecision::Reject { .. }));
            assert!(entry.gate_message().contains("trojan"));
            assert!(entry.gate_message().contains("transport=ws"));
        }
    }

    #[test]
    fn official_only_protocols_are_not_marked_stable_without_official_interop_soak() {
        for protocol in [NativeProtocol::Naive, NativeProtocol::Mieru] {
            let entries = native_capability_matrix()
                .into_iter()
                .filter(|entry| entry.key.protocol == protocol)
                .collect::<Vec<_>>();
            assert!(!entries.is_empty(), "missing entries for {protocol:?}");
            for entry in entries {
                assert!(matches!(
                    entry.baseline_source,
                    BaselineSource::OfficialUpstreamBaseline | BaselineSource::Mixed
                ));
                assert_ne!(entry.status, CapabilityStatus::Stable);
                assert!(
                    entry.baseline_gap.contains("OfficialClientInterop")
                        || entry.baseline_gap.contains("SoakTested"),
                    "official protocol gap must name missing interop/soak evidence: {}",
                    entry.gate_message()
                );
            }
        }
    }
}
