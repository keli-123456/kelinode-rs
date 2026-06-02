#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  mihomo_client_regression.sh --config clash.yaml [--include REGEX] [--target URL ...]
  mihomo_client_regression.sh --subscription-url URL [--include REGEX] [--target URL ...]

Environment:
  MIHOMO              mihomo binary path, default: mihomo
  MIXED_PORT          local mixed proxy port, default: 19091
  CONTROLLER_ADDR     mihomo external-controller, default: 127.0.0.1:19090
  CONNECT_TIMEOUT     curl connect timeout seconds, default: 8
  MAX_TIME            curl max time seconds, default: 30

The script starts a temporary mihomo instance, switches GLOBAL to each matching
real proxy, then curls targets through the local mixed-port. It is intended for
client-style protocol regression checks, not raw TCP port checks.
USAGE
}

CONFIG_SOURCE=""
SUBSCRIPTION_URL=""
INCLUDE_REGEX=""
TARGETS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG_SOURCE="${2:-}"
      shift 2
      ;;
    --subscription-url)
      SUBSCRIPTION_URL="${2:-}"
      shift 2
      ;;
    --include)
      INCLUDE_REGEX="${2:-}"
      shift 2
      ;;
    --target)
      TARGETS+=("${2:-}")
      shift 2
      ;;
    -h|--help)
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

if [[ -n "$CONFIG_SOURCE" && -n "$SUBSCRIPTION_URL" ]]; then
  echo "use only one of --config or --subscription-url" >&2
  exit 2
fi
if [[ -z "$CONFIG_SOURCE" && -z "$SUBSCRIPTION_URL" ]]; then
  echo "missing --config or --subscription-url" >&2
  usage >&2
  exit 2
fi
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("https://www.gstatic.com/generate_204")
fi

MIHOMO="${MIHOMO:-mihomo}"
MIXED_PORT="${MIXED_PORT:-19091}"
CONTROLLER_ADDR="${CONTROLLER_ADDR:-127.0.0.1:19090}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-8}"
MAX_TIME="${MAX_TIME:-30}"

if ! command -v "$MIHOMO" >/dev/null 2>&1; then
  echo "mihomo binary not found: $MIHOMO" >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 2
fi
PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "python3 or python is required" >&2
    exit 2
  fi
fi

WORKDIR="$(mktemp -d)"
MIHOMO_PID=""
cleanup() {
  if [[ -n "$MIHOMO_PID" ]] && kill -0 "$MIHOMO_PID" >/dev/null 2>&1; then
    kill "$MIHOMO_PID" >/dev/null 2>&1 || true
    wait "$MIHOMO_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

BASE_CONFIG="$WORKDIR/base.yaml"
if [[ -n "$SUBSCRIPTION_URL" ]]; then
  curl -fsSL --max-time 30 "$SUBSCRIPTION_URL" -o "$BASE_CONFIG"
else
  cp "$CONFIG_SOURCE" "$BASE_CONFIG"
fi

CONFIG="$WORKDIR/config.yaml"
cp "$BASE_CONFIG" "$CONFIG"
cat >>"$CONFIG" <<YAML

mixed-port: ${MIXED_PORT}
external-controller: ${CONTROLLER_ADDR}
allow-lan: false
mode: global
log-level: warning
YAML

"$MIHOMO" -f "$CONFIG" -d "$WORKDIR" >"$WORKDIR/mihomo.log" 2>&1 &
MIHOMO_PID="$!"

ready=0
for _ in $(seq 1 80); do
  if curl -fsS --max-time 1 "http://${CONTROLLER_ADDR}/version" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.25
done
if [[ "$ready" != "1" ]]; then
  echo "mihomo external-controller did not become ready" >&2
  tail -n 80 "$WORKDIR/mihomo.log" >&2 || true
  exit 1
fi

PROXIES_JSON="$WORKDIR/proxies.json"
curl -fsS --max-time 5 "http://${CONTROLLER_ADDR}/proxies" -o "$PROXIES_JSON"
PROXY_LIST="$WORKDIR/proxies.txt"
"$PYTHON_BIN" - "$PROXIES_JSON" "$INCLUDE_REGEX" >"$PROXY_LIST" <<'PY'
import json
import re
import sys

path, include = sys.argv[1], sys.argv[2]
pattern = re.compile(include) if include else None
with open(path, "r", encoding="utf-8") as fh:
    proxies = json.load(fh).get("proxies", {})
skip_names = {"GLOBAL", "DIRECT", "REJECT", "REJECT-DROP", "PASS"}
skip_types = {
    "Selector",
    "Fallback",
    "URLTest",
    "LoadBalance",
    "Relay",
    "Direct",
    "Reject",
}
for name, item in proxies.items():
    proxy_type = str(item.get("type", ""))
    if name in skip_names or proxy_type in skip_types or item.get("all"):
        continue
    if pattern and not pattern.search(name):
        continue
    print(name)
PY

if [[ ! -s "$PROXY_LIST" ]]; then
  echo "no matching real proxies found" >&2
  exit 1
fi

echo "timestamp,proxy,target,http_code,time_connect,time_starttransfer,time_total,size_download,curl_exit,error_kind"
while IFS= read -r proxy_name; do
  [[ -z "$proxy_name" ]] && continue
  body="$("$PYTHON_BIN" -c 'import json,sys; print(json.dumps({"name": sys.argv[1]}, ensure_ascii=False))' "$proxy_name")"
  if ! curl -fsS --max-time 5 -X PUT "http://${CONTROLLER_ADDR}/proxies/GLOBAL" \
    -H "Content-Type: application/json" \
    --data-binary "$body" >/dev/null; then
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "${now},\"${proxy_name}\",-,-,-,-,-,-,1,select_failed"
    continue
  fi
  sleep 0.2
  for target in "${TARGETS[@]}"; do
    err_file="$WORKDIR/curl.err"
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if output="$(curl -x "http://127.0.0.1:${MIXED_PORT}" \
      --connect-timeout "$CONNECT_TIMEOUT" \
      --max-time "$MAX_TIME" \
      -o /dev/null \
      -sS \
      -w '%{http_code},%{time_connect},%{time_starttransfer},%{time_total},%{size_download}' \
      "$target" 2>"$err_file")"; then
      echo "${now},\"${proxy_name}\",\"${target}\",${output},0,-"
    else
      code=$?
      message="$(tr '\n' ' ' <"$err_file" | sed 's/,/;/g')"
      kind="curl_${code}"
      case "$code" in
        28) kind="timeout" ;;
        35) kind="tls_error" ;;
        5|6) kind="dns_error" ;;
        7) kind="connect_failed" ;;
        56) kind="recv_error" ;;
      esac
      echo "${now},\"${proxy_name}\",\"${target}\",-,-,-,-,-,${code},${kind}:${message}"
    fi
  done
done <"$PROXY_LIST"
