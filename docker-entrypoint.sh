#!/bin/sh
set -eu

CONFIG_PATH="${V2NODE_CONFIG_PATH:-/etc/v2node/config.yml}"
if [ "$CONFIG_PATH" = "/etc/v2node/config.yml" ] && [ ! -f "$CONFIG_PATH" ]; then
	if [ -f /etc/v2node/config.yaml ]; then
		CONFIG_PATH="/etc/v2node/config.yaml"
	elif [ -f /etc/v2node/config.json ]; then
		CONFIG_PATH="/etc/v2node/config.json"
	fi
fi

API_HOST="${V2NODE_API_HOST:-${API_HOST:-}}"
API_KEY="${V2NODE_API_KEY:-${API_KEY:-}}"
NODE_ID="${V2NODE_NODE_ID:-${NODE_ID:-}}"
MACHINE_ID="${V2NODE_MACHINE_ID:-${MACHINE_ID:-}}"
TIMEOUT="${V2NODE_TIMEOUT:-${TIMEOUT:-30}}"
CONFIG_DIR="${V2NODE_CONFIG_DIR:-${V2NODE_NODE_CONFIG_DIR:-/etc/v2node}}"
KERNEL_TYPE="${V2NODE_KERNEL_TYPE:-keli-core-rs}"
CORE_COMMAND="${V2NODE_CORE_COMMAND:-}"
TLS_CERT_URL="${V2NODE_TLS_CERT_URL:-${V2NODE_CERT_URL:-}}"
TLS_KEY_URL="${V2NODE_TLS_KEY_URL:-${V2NODE_KEY_URL:-}}"
TLS_CERT_FILE="${V2NODE_TLS_CERT_FILE:-}"
TLS_KEY_FILE="${V2NODE_TLS_KEY_FILE:-}"

yaml_escape() {
	printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

validate_number() {
	name="$1"
	value="$2"
	case "$value" in
		*[!0-9]*|'')
			echo "v2node: ${name} must be an integer." >&2
			exit 2
			;;
	esac
}

generate_config_from_env() {
	if [ -z "$API_HOST" ] || [ -z "$API_KEY" ]; then
		echo "v2node: set V2NODE_API_HOST and V2NODE_API_KEY, or mount ${CONFIG_PATH}." >&2
		exit 2
	fi
	validate_number "V2NODE_TIMEOUT" "$TIMEOUT"
	mkdir -p "$(dirname "$CONFIG_PATH")"

	api_host="$(yaml_escape "$API_HOST")"
	api_key="$(yaml_escape "$API_KEY")"
	config_dir="$(yaml_escape "$CONFIG_DIR")"
	kernel_type="$(yaml_escape "$KERNEL_TYPE")"
	core_command="$(yaml_escape "$CORE_COMMAND")"

	{
		printf 'kernel:\n'
		printf '  type: "%s"\n' "$kernel_type"
		printf '  config_dir: "%s"\n' "$config_dir"
		if [ -n "$CORE_COMMAND" ]; then
			printf '  core_command: "%s"\n' "$core_command"
		fi
		if [ -n "$MACHINE_ID" ]; then
			validate_number "V2NODE_MACHINE_ID" "$MACHINE_ID"
			printf 'machine:\n'
			printf '  enabled: true\n'
			printf '  continue_on_error: true\n'
			printf '  profiles:\n'
			printf '    - name: "machine-%s"\n' "$MACHINE_ID"
			printf '      url: "%s"\n' "$api_host"
			printf '      token: "%s"\n' "$api_key"
			printf '      machine_id: %s\n' "$MACHINE_ID"
			printf '      timeout: %s\n' "$TIMEOUT"
			printf '      config_dir: "%s"\n' "$config_dir"
		else
			validate_number "V2NODE_NODE_ID" "$NODE_ID"
			printf 'panel:\n'
			printf '  url: "%s"\n' "$api_host"
			printf '  token: "%s"\n' "$api_key"
			printf '  node_id: %s\n' "$NODE_ID"
			printf '  timeout: %s\n' "$TIMEOUT"
		fi
	} >"$CONFIG_PATH"
}

download_to_path() {
	url="$1"
	dest="$2"
	perm="$3"

	mkdir -p "$(dirname "$dest")"
	tmp="${dest}.tmp"
	curl -fsSL --connect-timeout 10 --max-time 60 "$url" -o "$tmp"
	chmod "$perm" "$tmp"
	mv -f "$tmp" "$dest"
}

maybe_download_tls_files() {
	if [ -z "$TLS_CERT_URL" ] && [ -z "$TLS_KEY_URL" ]; then
		return 0
	fi
	if [ -z "$TLS_CERT_URL" ] || [ -z "$TLS_KEY_URL" ]; then
		echo "v2node: set both V2NODE_TLS_CERT_URL and V2NODE_TLS_KEY_URL." >&2
		exit 2
	fi

	cert_file="$TLS_CERT_FILE"
	key_file="$TLS_KEY_FILE"
	if [ -z "$cert_file$key_file" ] && [ -n "$API_HOST" ] && [ -n "$API_KEY" ] && [ -n "$NODE_ID" ]; then
		node_json="$(curl -fsSL --connect-timeout 10 --max-time 60 --get "${API_HOST%/}/api/v2/server/config" \
			--data-urlencode "node_type=v2node" \
			--data-urlencode "node_id=${NODE_ID}" \
			--data-urlencode "token=${API_KEY}")"
		protocol="$(printf '%s' "$node_json" | jq -r '.protocol // empty')"
		cert_file="$(printf '%s' "$node_json" | jq -r '.tls_settings.cert_file // empty')"
		key_file="$(printf '%s' "$node_json" | jq -r '.tls_settings.key_file // empty')"
		if [ -z "$cert_file" ] && [ -n "$protocol" ]; then
			cert_file="${CONFIG_DIR%/}/${protocol}${NODE_ID}.cer"
		fi
		if [ -z "$key_file" ] && [ -n "$protocol" ]; then
			key_file="${CONFIG_DIR%/}/${protocol}${NODE_ID}.key"
		fi
	fi
	if [ -z "$cert_file" ] || [ -z "$key_file" ]; then
		echo "v2node: set V2NODE_TLS_CERT_FILE/V2NODE_TLS_KEY_FILE for env-based cert download in machine or multi-node mode." >&2
		exit 2
	fi

	download_to_path "$TLS_CERT_URL" "$cert_file" 0644
	download_to_path "$TLS_KEY_URL" "$key_file" 0600
}

ensure_config_for_server() {
	if [ -n "$API_HOST" ] || [ -n "$API_KEY" ] || [ -n "$NODE_ID" ] || [ -n "$MACHINE_ID" ]; then
		generate_config_from_env
	fi
	if [ ! -f "$CONFIG_PATH" ]; then
		echo "v2node: config file not found at ${CONFIG_PATH}." >&2
		echo "  - mount a config file, or" >&2
		echo "  - set V2NODE_API_HOST/V2NODE_API_KEY and V2NODE_NODE_ID or V2NODE_MACHINE_ID." >&2
		exit 2
	fi
}

has_config_flag() {
	for arg in "$@"; do
		case "$arg" in
			--config|-c|--config=*|-c=*)
				return 0
				;;
		esac
	done
	return 1
}

if [ "$#" -eq 0 ]; then
	set -- v2node server
fi

if [ "$1" = "server" ]; then
	set -- v2node "$@"
fi

if [ "$1" = "kelinode-rs" ]; then
	set -- /usr/local/v2node/kelinode-rs "$@"
fi

if [ "$1" = "v2node" ] && [ "${2:-}" = "server" ]; then
	ensure_config_for_server
	maybe_download_tls_files
	if ! has_config_flag "$@"; then
		set -- "$@" --config "$CONFIG_PATH"
	fi
fi

exec "$@"
