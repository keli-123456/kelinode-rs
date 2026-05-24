#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=remote_common.sh
source "${SCRIPT_DIR}/remote_common.sh"

SING_BOX="${SING_BOX:-}"
SING_BOX_VERSION="${SING_BOX_VERSION:-v1.12.22}"
TROJAN_CASE="${TROJAN_CASE:-trojan-ws}"
ROUNDS="${KELI_TROJAN_WS_ROUNDS:-3}"
INTERVAL_MS="${KELI_TROJAN_WS_INTERVAL_MS:-100}"
BASE_PORT="${KELI_TROJAN_WS_BASE_PORT:-19420}"

usage() {
  cat <<EOF
Usage: $0 [options]

Runs sing-box real-client interop for native Trojan WebSocket and TLS WebSocket on the remote Linux host.

Options:
  --sing-box PATH      remote path to sing-box binary
  --version VERSION    sing-box release version downloaded remotely when --sing-box is omitted (default: ${SING_BOX_VERSION})
  --case NAME          interop case substring (default: ${TROJAN_CASE}; matches plain and TLS WS)
  --rounds N           probe rounds (default: ${ROUNDS})
  --interval-ms N      delay between rounds (default: ${INTERVAL_MS})
  --base-port PORT     first local high port to use (default: ${BASE_PORT})
EOF
  common_usage
}

while [[ $# -gt 0 ]]; do
  if parse_common_arg "$1"; then
    shift
    continue
  fi
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --sing-box)
      SING_BOX="$2"
      shift 2
      ;;
    --version)
      SING_BOX_VERSION="$2"
      shift 2
      ;;
    --case)
      TROJAN_CASE="$2"
      shift 2
      ;;
    --rounds)
      ROUNDS="$2"
      shift 2
      ;;
    --interval-ms)
      INTERVAL_MS="$2"
      shift 2
      ;;
    --base-port)
      BASE_PORT="$2"
      shift 2
      ;;
    *)
      echo "FAIL unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_local_command tar
NODE_ROOT="$(repo_root_from_script)"
CORE_ROOT="$(core_repo_root "${NODE_ROOT}")"
ARCHIVE="${NODE_ROOT}/.tmp-trojan-ws-core-rs.tar.gz"
CASE_DIR="${KELI_REMOTE_ROOT}/trojan-ws"

make_core_archive "${CORE_ROOT}" "${ARCHIVE}"
trap 'rm -f "${ARCHIVE}"' EXIT

echo "INFO remote=$(remote_target) case=${TROJAN_CASE}"
prepare_remote_core_tree "${ARCHIVE}" "${CASE_DIR}"

REMOTE_CMD="cd '${CASE_DIR}' && bash scripts/trojan_ws_sing_box_interop_linux.sh --version '${SING_BOX_VERSION}' --case '${TROJAN_CASE}' --rounds '${ROUNDS}' --interval-ms '${INTERVAL_MS}' --base-port '${BASE_PORT}'"
if [[ -n "${SING_BOX}" ]]; then
  REMOTE_CMD="${REMOTE_CMD} --sing-box '${SING_BOX}'"
fi

if run_remote "${REMOTE_CMD}"; then
  echo "PASS trojan websocket remote interop"
else
  echo "FAIL trojan websocket remote interop" >&2
  exit 1
fi
