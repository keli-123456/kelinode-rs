#!/usr/bin/env bash
set -euo pipefail

SERVICE="${SERVICE:-kelinode.service}"
JOURNAL_UNIT="${JOURNAL_UNIT:-${SERVICE}}"
OUT_DIR="${OUT_DIR:-/tmp/keli-native-resource-watch}"
INTERVAL_SECS="${INTERVAL_SECS:-60}"
SAMPLES="${SAMPLES:-60}"
PID_OVERRIDE="${PID:-}"
SINCE="${SINCE:-}"
USE_JOURNAL=1
SELF_TEST_PATTERNS=0
PANIC_LOG_PATTERN="(^|[[:space:]])(thread[[:space:]].*panicked|panicked at|panic!|fatal runtime error)([[:space:]:]|$)"

usage() {
  cat <<'USAGE'
Usage: native_resource_watch.sh [options]

Samples a running kelinode/native-core process and writes a TSV trend file.

Options:
  --service NAME       systemd service name (default: kelinode.service)
  --pid PID            sample a specific process id instead of systemd MainPID
  --out DIR            output directory (default: /tmp/keli-native-resource-watch)
  --samples N          number of samples (default: 60)
  --interval SECONDS   seconds between CPU samples (default: 60)
  --since TIME         journal start time for cumulative counters
  --no-journal         skip journal-derived counters
  --self-test-patterns validate internal log classification patterns
  -h, --help           show this help

Examples:
  scripts/ops/native_resource_watch.sh --samples 10 --interval 60
  scripts/ops/native_resource_watch.sh --samples 1440 --interval 60 --out /tmp/keli-native-resource-24h
USAGE
}

run_pattern_self_tests() {
  local false_positive='core hysteria2 tcp relay timeout: tcp connect timed out target=download-cdn.panic.com:443'
  local rust_panic="thread 'tokio-runtime-worker' panicked at src/main.rs:1: boom"
  local fatal_runtime='fatal runtime error: stack overflow'

  if printf '%s\n' "${false_positive}" | grep -Eq "${PANIC_LOG_PATTERN}"; then
    echo "panic pattern matched benign domain: ${false_positive}" >&2
    return 1
  fi
  if ! printf '%s\n' "${rust_panic}" | grep -Eq "${PANIC_LOG_PATTERN}"; then
    echo "panic pattern missed Rust panic line: ${rust_panic}" >&2
    return 1
  fi
  if ! printf '%s\n' "${fatal_runtime}" | grep -Eq "${PANIC_LOG_PATTERN}"; then
    echo "panic pattern missed fatal runtime line: ${fatal_runtime}" >&2
    return 1
  fi
  echo "native_resource_watch pattern self-test ok"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --service)
      SERVICE="$2"
      JOURNAL_UNIT="$2"
      shift 2
      ;;
    --pid)
      PID_OVERRIDE="$2"
      shift 2
      ;;
    --out)
      OUT_DIR="$2"
      shift 2
      ;;
    --samples)
      SAMPLES="$2"
      shift 2
      ;;
    --interval)
      INTERVAL_SECS="$2"
      shift 2
      ;;
    --since)
      SINCE="$2"
      shift 2
      ;;
    --no-journal)
      USE_JOURNAL=0
      shift
      ;;
    --self-test-patterns)
      SELF_TEST_PATTERNS=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ "${SELF_TEST_PATTERNS}" -eq 1 ]; then
  run_pattern_self_tests
  exit $?
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 2
  fi
}

require_cmd awk
require_cmd date
require_cmd find
require_cmd grep
require_cmd wc

if ! [[ "${SAMPLES}" =~ ^[0-9]+$ ]] || [ "${SAMPLES}" -lt 1 ]; then
  echo "--samples must be a positive integer" >&2
  exit 2
fi

if ! [[ "${INTERVAL_SECS}" =~ ^[0-9]+$ ]] || [ "${INTERVAL_SECS}" -lt 1 ]; then
  echo "--interval must be a positive integer" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"
SAMPLES_TSV="${OUT_DIR}/samples.tsv"
JOURNAL_LOG="${OUT_DIR}/journal.log"

resolve_pid() {
  if [ -n "${PID_OVERRIDE}" ]; then
    printf '%s\n' "${PID_OVERRIDE}"
    return
  fi
  if command -v systemctl >/dev/null 2>&1; then
    local pid
    pid="$(systemctl show "${SERVICE}" -p MainPID --value --no-pager 2>/dev/null || true)"
    if [ -n "${pid}" ] && [ "${pid}" != "0" ]; then
      printf '%s\n' "${pid}"
      return
    fi
  fi
  pgrep -f 'kelinode server --config|keli-core-rs' | head -n 1
}

status_value() {
  local pid="$1"
  local key="$2"
  awk -v key="${key}:" '$1 == key {print $2; found=1} END {if (!found) print 0}' "/proc/${pid}/status"
}

read_proc_ticks() {
  local pid="$1"
  awk '{print $14 + $15}' "/proc/${pid}/stat"
}

read_total_ticks() {
  awk '/^cpu / {sum=0; for (i=2; i<=NF; i++) sum += $i; print sum}' /proc/stat
}

fd_count() {
  local pid="$1"
  find "/proc/${pid}/fd" -maxdepth 1 -type l 2>/dev/null | wc -l | awk '{print $1}'
}

service_property() {
  local property="$1"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl show "${SERVICE}" -p "${property}" --value --no-pager 2>/dev/null || printf 'unknown'
  else
    printf 'unknown'
  fi
}

binary_sha() {
  local pid="$1"
  local exe
  exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
  if [ -n "${exe}" ] && command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${exe}" 2>/dev/null | awk '{print $1}'
  else
    printf 'unknown'
  fi
}

write_journal_snapshot() {
  if [ "${USE_JOURNAL}" -eq 0 ] || ! command -v journalctl >/dev/null 2>&1; then
    : > "${JOURNAL_LOG}"
    return
  fi
  if [ -n "${SINCE}" ]; then
    journalctl -u "${JOURNAL_UNIT}" --since "${SINCE}" --no-pager > "${JOURNAL_LOG}" 2>/dev/null || : > "${JOURNAL_LOG}"
  else
    journalctl -u "${JOURNAL_UNIT}" -n 5000 --no-pager > "${JOURNAL_LOG}" 2>/dev/null || : > "${JOURNAL_LOG}"
  fi
}

count_pattern() {
  local pattern="$1"
  if [ -s "${JOURNAL_LOG}" ]; then
    grep -Ec "${pattern}" "${JOURNAL_LOG}" || true
  else
    printf '0\n'
  fi
}

scheduler_field() {
  local key="$1"
  local line="$2"
  awk -v key="${key}" '{
    for (i=1; i<=NF; i++) {
      split($i, pair, "=")
      if (pair[1] == key) {
        print pair[2]
        found=1
        exit
      }
    }
    if (!found) print "-"
  }' <<<"${line}"
}

if [ ! -f "${SAMPLES_TSV}" ]; then
  printf 'timestamp\tpid\tbinary_sha\tactive_state\tsub_state\trss_kb\thwm_kb\trss_anon_kb\trss_file_kb\tvm_data_kb\tthreads\tfd_count\tcpu_percent\tproc_ticks\ttotal_ticks\tactive_async\tactive_native\tactive_blocking\tnative_workers\tnative_pending\texternal_core_errors\tpanic_lines\tnative_user_deltas\ttrojan_failures\thy2_timeouts\tinvalid_auth\n' > "${SAMPLES_TSV}"
fi

echo "writing samples to ${SAMPLES_TSV}"

for sample in $(seq 1 "${SAMPLES}"); do
  pid="$(resolve_pid)"
  if [ -z "${pid}" ] || [ ! -d "/proc/${pid}" ]; then
    echo "unable to resolve running process for ${SERVICE}" >&2
    exit 1
  fi

  proc_start="$(read_proc_ticks "${pid}")"
  total_start="$(read_total_ticks)"
  sleep "${INTERVAL_SECS}"
  if [ ! -d "/proc/${pid}" ]; then
    echo "process exited during sample ${sample}: pid=${pid}" >&2
    exit 1
  fi
  proc_end="$(read_proc_ticks "${pid}")"
  total_end="$(read_total_ticks)"
  proc_delta=$((proc_end - proc_start))
  total_delta=$((total_end - total_start))
  cpu_percent="$(
    awk -v proc="${proc_delta}" -v total="${total_delta}" -v cpus="$(nproc 2>/dev/null || echo 1)" \
      'BEGIN { if (total > 0) printf "%.2f", proc / total * cpus * 100.0; else printf "0.00" }'
  )"

  write_journal_snapshot
  scheduler_line="$(grep 'core relay scheduler' "${JOURNAL_LOG}" | tail -n 1 || true)"

  timestamp="$(date -Iseconds)"
  active_state="$(service_property ActiveState)"
  sub_state="$(service_property SubState)"
  rss_kb="$(status_value "${pid}" VmRSS)"
  hwm_kb="$(status_value "${pid}" VmHWM)"
  rss_anon_kb="$(status_value "${pid}" RssAnon)"
  rss_file_kb="$(status_value "${pid}" RssFile)"
  vm_data_kb="$(status_value "${pid}" VmData)"
  threads="$(status_value "${pid}" Threads)"
  fds="$(fd_count "${pid}")"
  sha="$(binary_sha "${pid}")"
  active_async="$(scheduler_field active_async "${scheduler_line}")"
  active_native="$(scheduler_field active_native "${scheduler_line}")"
  active_blocking="$(scheduler_field active_blocking "${scheduler_line}")"
  native_workers="$(scheduler_field native_workers "${scheduler_line}")"
  native_pending="$(scheduler_field native_pending "${scheduler_line}")"
  external_core_errors="$(count_pattern 'agent start process core:keli-core-rs')"
  panic_lines="$(count_pattern "${PANIC_LOG_PATTERN}")"
  native_user_deltas="$(count_pattern 'core user delta applied natively')"
  trojan_failures="$(count_pattern 'core trojan connection failed')"
  hy2_timeouts="$(count_pattern 'hysteria2 connection timeout')"
  invalid_auth="$(count_pattern 'invalid-auth')"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${timestamp}" "${pid}" "${sha}" "${active_state}" "${sub_state}" \
    "${rss_kb}" "${hwm_kb}" "${rss_anon_kb}" "${rss_file_kb}" "${vm_data_kb}" \
    "${threads}" "${fds}" "${cpu_percent}" "${proc_delta}" "${total_delta}" \
    "${active_async}" "${active_native}" "${active_blocking}" "${native_workers}" "${native_pending}" \
    "${external_core_errors}" "${panic_lines}" "${native_user_deltas}" "${trojan_failures}" \
    "${hy2_timeouts}" "${invalid_auth}" >> "${SAMPLES_TSV}"

  printf 'sample=%s pid=%s cpu=%s rss_kb=%s hwm_kb=%s fd=%s threads=%s active_async=%s state=%s/%s\n' \
    "${sample}" "${pid}" "${cpu_percent}" "${rss_kb}" "${hwm_kb}" "${fds}" "${threads}" \
    "${active_async}" "${active_state}" "${sub_state}"
done

echo "done: ${SAMPLES_TSV}"
