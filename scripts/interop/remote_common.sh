#!/usr/bin/env bash
set -euo pipefail

KELI_TEST_HOST="${KELI_TEST_HOST:-2.56.116.39}"
KELI_TEST_USER="${KELI_TEST_USER:-root}"
KELI_TEST_SSH_PORT="${KELI_TEST_SSH_PORT:-22}"
KELI_TEST_SSH_KEY="${KELI_TEST_SSH_KEY:-${HOME}/.ssh/id_ed25519}"
KELI_REMOTE_ROOT="${KELI_REMOTE_ROOT:-/tmp/keli-core-rs-interop}"

DRY_RUN=0

common_usage() {
  cat <<EOF
Common options:
  --dry-run          print the remote actions without connecting
  -h, --help         show script help

Environment:
  KELI_TEST_HOST       remote test host (default: 2.56.116.39)
  KELI_TEST_USER       SSH user (default: root)
  KELI_TEST_SSH_PORT   SSH port (default: 22)
  KELI_TEST_SSH_KEY    SSH private key path (default: \$HOME/.ssh/id_ed25519)
EOF
}

parse_common_arg() {
  case "${1:-}" in
    --dry-run)
      DRY_RUN=1
      return 0
      ;;
    -h|--help)
      return 2
      ;;
    *)
      return 1
      ;;
  esac
}

remote_target() {
  printf '%s@%s' "${KELI_TEST_USER}" "${KELI_TEST_HOST}"
}

ssh_base() {
  ssh -i "${KELI_TEST_SSH_KEY}" \
    -p "${KELI_TEST_SSH_PORT}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new \
    "$(remote_target)" "$@"
}

scp_base() {
  scp -i "${KELI_TEST_SSH_KEY}" \
    -P "${KELI_TEST_SSH_PORT}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new \
    "$@"
}

run_remote() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    printf '[dry-run] ssh %s %q\n' "$(remote_target)" "$*"
    return 0
  fi
  ssh_base "$@"
}

copy_to_remote() {
  local source="$1"
  local dest="$2"
  if [[ "${DRY_RUN}" == "1" ]]; then
    printf '[dry-run] scp %s %s:%s\n' "${source}" "$(remote_target)" "${dest}"
    return 0
  fi
  scp_base "${source}" "$(remote_target):${dest}"
}

require_local_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "FAIL missing local command: $1" >&2
    exit 2
  fi
}

repo_root_from_script() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

core_repo_root() {
  local node_root="$1"
  local core_root="${KELI_CORE_RS_REPO:-${node_root}/../keli-core-rs}"
  if [[ ! -f "${core_root}/Cargo.toml" ]]; then
    echo "FAIL keli-core-rs repo not found at ${core_root}; set KELI_CORE_RS_REPO" >&2
    exit 2
  fi
  cd "${core_root}" && pwd
}

make_core_archive() {
  local core_root="$1"
  local output="$2"
  tar \
    --exclude '.git' \
    --exclude 'target' \
    --exclude 'runtime' \
    --exclude 'tools' \
    -czf "${output}" \
    -C "${core_root}" .
}

prepare_remote_core_tree() {
  local archive="$1"
  local case_dir="$2"
  run_remote "rm -rf '${case_dir}' && mkdir -p '${case_dir}'"
  copy_to_remote "${archive}" "${case_dir}/keli-core-rs.tar.gz"
  run_remote "tar -xzf '${case_dir}/keli-core-rs.tar.gz' -C '${case_dir}'"
}

