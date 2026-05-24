#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=remote_common.sh
source "${SCRIPT_DIR}/remote_common.sh"

ROUNDS="${KELI_NAIVE_SOAK_ROUNDS:-120}"
INTERVAL_MS="${KELI_NAIVE_SOAK_INTERVAL_MS:-1000}"
CASE="${KELI_NAIVE_SOAK_CASE:-naive}"
RESTART_EVERY="${KELI_NAIVE_RESTART_EVERY_ROUNDS:-0}"

usage() {
  cat <<EOF
Usage: $0 [options]

Runs the official NaiveProxy interop helper on the remote Linux host.

Options:
  --rounds N                  probe rounds (default: ${ROUNDS})
  --interval-ms N             delay between rounds (default: ${INTERVAL_MS})
  --case NAME                 naive case filter (default: ${CASE})
  --restart-every-rounds N    restart official client every N rounds
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
    --rounds)
      ROUNDS="$2"
      shift 2
      ;;
    --interval-ms)
      INTERVAL_MS="$2"
      shift 2
      ;;
    --case)
      CASE="$2"
      shift 2
      ;;
    --restart-every-rounds)
      RESTART_EVERY="$2"
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
ARCHIVE="${NODE_ROOT}/.tmp-naive-core-rs.tar.gz"
CASE_DIR="${KELI_REMOTE_ROOT}/naive-official"

make_core_archive "${CORE_ROOT}" "${ARCHIVE}"
trap 'rm -f "${ARCHIVE}"' EXIT

echo "INFO remote=$(remote_target) case=${CASE} rounds=${ROUNDS} interval_ms=${INTERVAL_MS}"
prepare_remote_core_tree "${ARCHIVE}" "${CASE_DIR}"

REMOTE_CMD="cd '${CASE_DIR}' && bash scripts/naive_official_soak_linux.sh --rounds '${ROUNDS}' --interval-ms '${INTERVAL_MS}' --case '${CASE}'"
if [[ "${RESTART_EVERY}" != "0" ]]; then
  REMOTE_CMD="${REMOTE_CMD} --restart-every-rounds '${RESTART_EVERY}'"
fi

if run_remote "${REMOTE_CMD}"; then
  echo "PASS naive official remote interop"
else
  echo "FAIL naive official remote interop" >&2
  exit 1
fi

