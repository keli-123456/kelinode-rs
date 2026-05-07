pub const NODE_API_CONTRACT_VERSION: &str = "2026-04-26";

pub const PATH_V1_UNIPROXY_USER: &str = "/api/v1/server/UniProxy/user";
pub const PATH_V1_UNIPROXY_USER_DELTA: &str = "/api/v1/server/UniProxy/user_delta";
pub const PATH_V1_UNIPROXY_PUSH: &str = "/api/v1/server/UniProxy/push";
pub const PATH_V1_UNIPROXY_ALIVE: &str = "/api/v1/server/UniProxy/alive";
pub const PATH_V1_UNIPROXY_ALIVE_LIST: &str = "/api/v1/server/UniProxy/alivelist";

pub const PATH_V2_SERVER_CONFIG: &str = "/api/v2/server/config";
pub const PATH_V2_MACHINE_NODES: &str = "/api/v2/server/machine/nodes";
pub const PATH_V2_MACHINE_STATUS: &str = "/api/v2/server/machine/status";

pub const HEADER_RESPONSE_FORMAT: &str = "X-Response-Format";
pub const RESPONSE_FORMAT_MSGPACK: &str = "msgpack";
pub const CONTENT_TYPE_MSGPACK: &str = "application/x-msgpack";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_paths_match_go_contract() {
        assert_eq!(NODE_API_CONTRACT_VERSION, "2026-04-26");
        assert_eq!(PATH_V2_SERVER_CONFIG, "/api/v2/server/config");
        assert_eq!(PATH_V1_UNIPROXY_PUSH, "/api/v1/server/UniProxy/push");
        assert_eq!(PATH_V2_MACHINE_STATUS, "/api/v2/server/machine/status");
    }
}
