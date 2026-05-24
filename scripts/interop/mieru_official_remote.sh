#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=remote_common.sh
source "${SCRIPT_DIR}/remote_common.sh"

MIERU_CLIENT="${MIERU_CLIENT:-}"
MIERU_CASE="${MIERU_CASE:-mieru-tcp-underlay}"
MIERU_VERSION="${MIERU_VERSION:-v3.32.0}"
ROUNDS="${KELI_MIERU_SOAK_ROUNDS:-3}"
INTERVAL_MS="${KELI_MIERU_SOAK_INTERVAL_MS:-100}"
BASE_PORT="${KELI_MIERU_BASE_PORT:-19380}"

usage() {
  cat <<EOF
Usage: $0 [options]

Runs official Mieru client interop against the native keli-core-rs Mieru TCP underlay.

Options:
  --mieru PATH          remote path to official mieru client binary
  --version VERSION    official Mieru release version (default: ${MIERU_VERSION})
  --case NAME          evidence case label (default: ${MIERU_CASE})
  --rounds N           successful TCP probe rounds (default: ${ROUNDS})
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
    --mieru)
      MIERU_CLIENT="$2"
      shift 2
      ;;
    --version)
      MIERU_VERSION="$2"
      shift 2
      ;;
    --case)
      MIERU_CASE="$2"
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
ARCHIVE="${NODE_ROOT}/.tmp-mieru-core-rs.tar.gz"
CASE_DIR="${KELI_REMOTE_ROOT}/mieru-official"

make_core_archive "${CORE_ROOT}" "${ARCHIVE}"
trap 'rm -f "${ARCHIVE}"' EXIT

echo "INFO remote=$(remote_target) case=${MIERU_CASE}"
prepare_remote_core_tree "${ARCHIVE}" "${CASE_DIR}"

REMOTE_CMD="cd '${CASE_DIR}' && bash scripts/mieru_official_soak_linux.sh --version '${MIERU_VERSION}' --case '${MIERU_CASE}' --rounds '${ROUNDS}' --interval-ms '${INTERVAL_MS}' --base-port '${BASE_PORT}'"
if [[ -n "${MIERU_CLIENT}" ]]; then
  REMOTE_CMD="${REMOTE_CMD} --mieru '${MIERU_CLIENT}'"
fi

if run_remote "${REMOTE_CMD}"; then
  echo "PASS mieru official remote interop"
else
  echo "FAIL mieru official remote interop" >&2
  exit 1
fi
