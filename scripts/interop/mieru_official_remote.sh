#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=remote_common.sh
source "${SCRIPT_DIR}/remote_common.sh"

MIERU_CLIENT="${MIERU_CLIENT:-}"
MIERU_CASE="${MIERU_CASE:-mieru-tcp-underlay}"

usage() {
  cat <<EOF
Usage: $0 [options]

Prepares remote Mieru official-client interop. The script fails loudly until an
official Mieru client binary is provided.

Options:
  --mieru PATH      remote path to official mieru client binary
  --case NAME       evidence case label (default: ${MIERU_CASE})
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
    --case)
      MIERU_CASE="$2"
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

if [[ -z "${MIERU_CLIENT}" ]]; then
  echo "FAIL Mieru official client path is required; set MIERU_CLIENT or pass --mieru" >&2
  echo "INFO remote tree prepared at ${CASE_DIR} for local loopback tests"
  exit 3
fi

REMOTE_CMD="cd '${CASE_DIR}' && cargo test mieru && '${MIERU_CLIENT}' --version"

if run_remote "${REMOTE_CMD}"; then
  echo "PASS mieru official remote preflight"
else
  echo "FAIL mieru official remote preflight" >&2
  exit 1
fi

