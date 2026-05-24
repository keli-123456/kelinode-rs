#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=remote_common.sh
source "${SCRIPT_DIR}/remote_common.sh"

SING_BOX="${SING_BOX:-}"
SING_BOX_VERSION="${SING_BOX_VERSION:-v1.12.22}"
MATRIX_CASE="${KELI_MATRIX_CASE:-}"
ROUNDS="${KELI_MATRIX_ROUNDS:-1}"
INTERVAL_MS="${KELI_MATRIX_INTERVAL_MS:-0}"
BASE_PORT="${KELI_MATRIX_BASE_PORT:-19500}"

usage() {
  cat <<EOF
Usage: $0 [options]

Runs the native keli-core-rs sing-box interop matrix on the remote Linux host.

Options:
  --sing-box PATH      remote path to sing-box binary
  --version VERSION    sing-box release version downloaded remotely when --sing-box is omitted (default: ${SING_BOX_VERSION})
  --case NAME          interop case substring (default: all sing-box-compatible cases)
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
      MATRIX_CASE="$2"
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
ARCHIVE="${NODE_ROOT}/.tmp-native-matrix-core-rs.tar.gz"
CASE_DIR="${KELI_REMOTE_ROOT}/native-matrix"

make_core_archive "${CORE_ROOT}" "${ARCHIVE}"
trap 'rm -f "${ARCHIVE}"' EXIT

echo "INFO remote=$(remote_target) case=${MATRIX_CASE:-all}"
prepare_remote_core_tree "${ARCHIVE}" "${CASE_DIR}"

REMOTE_CMD="cd '${CASE_DIR}' && bash scripts/trojan_ws_sing_box_interop_linux.sh --version '${SING_BOX_VERSION}' --case '${MATRIX_CASE}' --rounds '${ROUNDS}' --interval-ms '${INTERVAL_MS}' --base-port '${BASE_PORT}'"
if [[ -n "${SING_BOX}" ]]; then
  REMOTE_CMD="${REMOTE_CMD} --sing-box '${SING_BOX}'"
fi

if run_remote "${REMOTE_CMD}"; then
  echo "PASS native sing-box interop matrix"
else
  echo "FAIL native sing-box interop matrix" >&2
  exit 1
fi
