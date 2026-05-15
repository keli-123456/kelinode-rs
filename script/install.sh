#!/usr/bin/env bash
set -euo pipefail

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

INSTALL_DIR="/usr/local/v2node"
CONFIG_DIR="/etc/v2node"
CONFIG_FILE="${CONFIG_DIR}/config.yml"
VERSION_ARG=""
MACHINE_URL_ARG=""
MACHINE_ID_ARG=""
MACHINE_TOKEN_ARG=""
MACHINE_NAME_ARG=""
ACTION="install"
PURGE_CONFIG="false"
SKIP_GEO_RULES="false"
LOCK_DIR="/tmp/keli-native-node-install.lock"

usage() {
    cat <<'EOF'
Usage:
  install.sh [install] [--version v0.1.44] --machine-url URL --machine-id ID --machine-token TOKEN [--machine-name NAME]
  install.sh uninstall [--purge-config]

Options:
  --version VERSION        kelinode-rs release version. Defaults to the latest GitHub release.
  --machine-url URL       keliboard API URL.
  --machine-id ID         server machine ID.
  --machine-token TOKEN   server machine token.
  --machine-name NAME     local profile name.
  --skip-geo-rules        do not download default geoip/geosite text route rules.
  --purge-config          uninstall only: also remove /etc/v2node.
EOF
}

parse_args() {
    if [[ $# -gt 0 ]]; then
        case "$1" in
            install)
                ACTION="install"; shift ;;
            uninstall|remove)
                ACTION="uninstall"; shift ;;
        esac
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version)
                VERSION_ARG="${2:-}"; shift 2 ;;
            --machine-url)
                MACHINE_URL_ARG="${2:-}"; shift 2 ;;
            --machine-id)
                MACHINE_ID_ARG="${2:-}"; shift 2 ;;
            --machine-token)
                MACHINE_TOKEN_ARG="${2:-}"; shift 2 ;;
            --machine-name)
                MACHINE_NAME_ARG="${2:-}"; shift 2 ;;
            --skip-geo-rules)
                SKIP_GEO_RULES="true"; shift ;;
            --purge-config)
                PURGE_CONFIG="true"; shift ;;
            --uninstall|--remove)
                ACTION="uninstall"; shift ;;
            -h|--help)
                usage; exit 0 ;;
            --*)
                echo -e "${red}Unknown option: $1${plain}" >&2
                usage
                exit 1 ;;
            *)
                if [[ -z "$VERSION_ARG" ]]; then
                    VERSION_ARG="$1"
                fi
                shift ;;
        esac
    done
}

validate_args() {
    if [[ "$ACTION" == "uninstall" ]]; then
        return
    fi

    if [[ -z "$MACHINE_URL_ARG" || -z "$MACHINE_ID_ARG" || -z "$MACHINE_TOKEN_ARG" ]]; then
        echo -e "${red}machine mode requires --machine-url, --machine-id, and --machine-token${plain}" >&2
        usage
        exit 1
    fi
    if ! [[ "$MACHINE_ID_ARG" =~ ^[0-9]+$ ]] || [[ "$MACHINE_ID_ARG" -le 0 ]]; then
        echo -e "${red}--machine-id must be a positive integer${plain}" >&2
        exit 1
    fi
}

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${red}This installer must run as root.${plain}" >&2
        exit 1
    fi
}

acquire_lock() {
    local waited=0
    local max_wait=120
    while ! mkdir "$LOCK_DIR" 2>/dev/null; do
        if [[ $waited -ge $max_wait ]]; then
            echo -e "${red}Another Keli native node install is still running. Try again later.${plain}" >&2
            exit 1
        fi
        echo -e "${yellow}Waiting for another install task... (${waited}/${max_wait}s)${plain}"
        sleep 2
        waited=$((waited + 2))
    done
    trap 'rm -rf "$LOCK_DIR" "$WORK_DIR" 2>/dev/null || true' EXIT
}

install_base_packages() {
    local missing=()
    for cmd in curl tar iptables ip6tables; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    command -v update-ca-certificates >/dev/null 2>&1 || true

    if [[ ${#missing[@]} -eq 0 ]]; then
        return
    fi

    echo -e "${yellow}Installing required packages: ${missing[*]}${plain}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y >/dev/null
        DEBIAN_FRONTEND=noninteractive apt-get install -y curl tar ca-certificates iptables >/dev/null
        update-ca-certificates >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl tar ca-certificates iptables >/dev/null
        update-ca-trust force-enable >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl tar ca-certificates iptables >/dev/null
        update-ca-trust force-enable >/dev/null 2>&1 || true
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl tar ca-certificates iptables >/dev/null
        update-ca-certificates >/dev/null 2>&1 || true
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm --needed curl tar ca-certificates iptables >/dev/null
    else
        echo -e "${red}Missing required commands: ${missing[*]}; install them and retry.${plain}" >&2
        exit 1
    fi
}

detect_target() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)
            printf 'linux-x86_64' ;;
        *)
            echo -e "${red}Unsupported architecture: ${arch}. Current native release supports linux-x86_64 only.${plain}" >&2
            exit 1 ;;
    esac
}

resolve_version() {
    if [[ -n "$VERSION_ARG" ]]; then
        printf '%s' "$VERSION_ARG"
        return
    fi

    local version
    version="$(curl -fsSL 'https://api.github.com/repos/keli-123456/kelinode-rs/releases/latest' \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n 1)"
    if [[ -z "$version" ]]; then
        echo -e "${red}Failed to resolve latest kelinode-rs version. Pass --version manually.${plain}" >&2
        exit 1
    fi
    printf '%s' "$version"
}

yaml_quote() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '"%s"' "$value"
}

trim_value() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

yaml_unquote() {
    local value
    value="$(trim_value "$1")"
    value="${value%%#*}"
    value="$(trim_value "$value")"
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
        value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
        value="${value:1:${#value}-2}"
    fi
    value="${value//\\\"/\"}"
    value="${value//\\\\/\\}"
    printf '%s' "$value"
}

normalize_machine_url() {
    local value
    value="$(trim_value "$1")"
    while [[ "$value" == */ ]]; do
        value="${value%/}"
    done
    printf '%s' "$value"
}

machine_profile_name() {
    local name="$MACHINE_NAME_ARG"
    if [[ -z "$name" ]]; then
        name="machine-${MACHINE_ID_ARG}"
    fi
    printf '%s' "$name"
}

extract_machine_profiles() {
    local config_file="$1"
    local line in_profiles=false in_profile=false
    local name="" url="" token="" machine_id="" timeout="" config_dir=""

    flush_profile() {
        if [[ -n "$url" && -n "$machine_id" ]]; then
            [[ -z "$timeout" ]] && timeout=15
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$url" "$token" "$machine_id" "$timeout" "$config_dir"
        fi
        in_profile=false
        name=""
        url=""
        token=""
        machine_id=""
        timeout=""
        config_dir=""
    }

    [[ -f "$config_file" ]] || return 0

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^[[:space:]]*profiles:[[:space:]]*$ ]]; then
            in_profiles=true
            continue
        fi
        if [[ "$in_profiles" != true ]]; then
            continue
        fi
        if [[ "$line" =~ ^[[:alnum:]_]+: ]]; then
            flush_profile
            in_profiles=false
            continue
        fi
        if [[ "$line" =~ ^[[:space:]]*-[[:space:]]*name:[[:space:]]*(.*)$ ]]; then
            flush_profile
            in_profile=true
            name=$(yaml_unquote "${BASH_REMATCH[1]}")
            continue
        fi
        if [[ "$line" =~ ^[[:space:]]*-[[:space:]]*url:[[:space:]]*(.*)$ ]]; then
            flush_profile
            in_profile=true
            url=$(normalize_machine_url "$(yaml_unquote "${BASH_REMATCH[1]}")")
            continue
        fi
        if [[ "$in_profile" == true && "$line" =~ ^[[:space:]]*url:[[:space:]]*(.*)$ ]]; then
            url=$(normalize_machine_url "$(yaml_unquote "${BASH_REMATCH[1]}")")
            continue
        fi
        if [[ "$in_profile" == true && "$line" =~ ^[[:space:]]*token:[[:space:]]*(.*)$ ]]; then
            token=$(yaml_unquote "${BASH_REMATCH[1]}")
            continue
        fi
        if [[ "$in_profile" == true && "$line" =~ ^[[:space:]]*machine_id:[[:space:]]*([0-9]+) ]]; then
            machine_id="${BASH_REMATCH[1]}"
            continue
        fi
        if [[ "$in_profile" == true && "$line" =~ ^[[:space:]]*timeout:[[:space:]]*([0-9]+) ]]; then
            timeout="${BASH_REMATCH[1]}"
            continue
        fi
        if [[ "$in_profile" == true && "$line" =~ ^[[:space:]]*config_dir:[[:space:]]*(.*)$ ]]; then
            config_dir=$(yaml_unquote "${BASH_REMATCH[1]}")
            continue
        fi
    done < "$config_file"

    flush_profile
}

write_machine_config_from_profiles() {
    local profiles_file="$1"
    local name url token machine_id timeout config_dir

    {
        echo "machine:"
        echo "  enabled: true"
        echo "  continue_on_error: true"
        echo "  profiles:"
        while IFS=$'\t' read -r name url token machine_id timeout config_dir; do
            [[ -z "$url" || -z "$machine_id" ]] && continue
            [[ -z "$name" ]] && name="machine-${machine_id}"
            [[ -z "$timeout" ]] && timeout=15
            echo "    - name: $(yaml_quote "$name")"
            echo "      url: $(yaml_quote "$url")"
            echo "      token: $(yaml_quote "$token")"
            echo "      machine_id: ${machine_id}"
            echo "      timeout: ${timeout}"
            if [[ -n "$config_dir" ]]; then
                echo "      config_dir: $(yaml_quote "$config_dir")"
            fi
        done < "$profiles_file"
        echo
        echo "kernel:"
        echo "  type: keli-core-rs"
        echo "  config_dir: $(yaml_quote "$CONFIG_DIR")"
        echo "  log_level: \"warning\""
        echo "  ip_strategy: \"UseIPv4\""
        echo "  dns_servers:"
        echo "    - \"1.1.1.1\""
        echo "    - \"8.8.8.8\""
        echo
        echo "log:"
        echo "  level: \"warning\""
        echo "  output: \"\""
        echo "  access: \"none\""
        echo
        echo "runtime:"
        echo "  gomemlimit: \"\""
        echo "  gogc: 0"
        echo "  auto_hy2_port_forward: true"
        echo
        echo "health_port: 0"
        echo "pprof_port: 0"
    }
}

write_machine_config() {
    local existing_profiles merged_profiles new_config backup profile_count machine_url machine_name

    mkdir -p "$CONFIG_DIR"
    existing_profiles="$(mktemp)"
    merged_profiles="$(mktemp)"
    new_config="$(mktemp)"
    machine_url="$(normalize_machine_url "$MACHINE_URL_ARG")"
    machine_name="$(machine_profile_name)"

    extract_machine_profiles "$CONFIG_FILE" > "$existing_profiles"
    awk -F '\t' \
        -v name="$machine_name" \
        -v url="$machine_url" \
        -v token="$MACHINE_TOKEN_ARG" \
        -v machine_id="$MACHINE_ID_ARG" \
        'BEGIN { updated = 0 }
         {
             if (($2 == url && $4 == machine_id) || ($3 == token && $4 == machine_id)) {
                 if (!updated) {
                     print name "\t" url "\t" token "\t" machine_id "\t15\t" $6
                     updated = 1
                 }
                 next
             }
             print $0
         }
         END {
             if (!updated) {
                 print name "\t" url "\t" token "\t" machine_id "\t15\t"
             }
         }' "$existing_profiles" > "$merged_profiles"

    write_machine_config_from_profiles "$merged_profiles" > "$new_config"
    if [[ -f "$CONFIG_FILE" ]] && cmp -s "$new_config" "$CONFIG_FILE"; then
        rm -f "$existing_profiles" "$merged_profiles" "$new_config"
        chmod 600 "$CONFIG_FILE" 2>/dev/null || true
        echo -e "${green}Machine config unchanged in ${CONFIG_FILE}.${plain}"
        return
    fi

    if [[ -f "$CONFIG_FILE" ]]; then
        backup="${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
        cp "$CONFIG_FILE" "$backup"
        echo -e "${yellow}Previous config backup: ${backup}${plain}"
    fi
    mv "$new_config" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
    rm -f "$existing_profiles" "$merged_profiles"
    profile_count="$(extract_machine_profiles "$CONFIG_FILE" | wc -l | tr -d ' ')"
    echo -e "${green}Wrote native machine config to ${CONFIG_FILE}; profiles=${profile_count}.${plain}"
}

geo_rule_safe_name() {
    [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]
}

GEOSITE_DOWNLOADED=" "

download_geosite_rule() {
    local rule="$1"
    local base="${KELI_GEOSITE_SOURCE_BASE:-https://raw.githubusercontent.com/v2fly/domain-list-community/master/data}"
    local target_dir="${CONFIG_DIR}/geosite"
    local target="${target_dir}/${rule}.txt"
    local tmp="${target}.tmp"

    geo_rule_safe_name "$rule" || return 0
    case "$GEOSITE_DOWNLOADED" in
        *" ${rule} "*) return 0 ;;
    esac
    GEOSITE_DOWNLOADED="${GEOSITE_DOWNLOADED}${rule} "

    if ! curl -fsSL --retry 2 --connect-timeout 10 "${base}/${rule}" -o "$tmp"; then
        rm -f "$tmp"
        echo -e "${yellow}Warning: failed to download geosite:${rule}; route will rely on built-ins or existing files.${plain}" >&2
        return 0
    fi
    mv "$tmp" "$target"

    local line clean include
    while IFS= read -r line; do
        clean="${line%%#*}"
        clean="${clean#"${clean%%[![:space:]]*}"}"
        clean="${clean%%[[:space:]]*}"
        if [[ "$clean" == include:* ]]; then
            include="${clean#include:}"
            geo_rule_safe_name "$include" && download_geosite_rule "$include"
        fi
    done < "$target"
}

download_geoip_rule() {
    local rule="$1"
    local base="${KELI_GEOIP_SOURCE_BASE:-https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text}"
    local target_dir="${CONFIG_DIR}/geoip"
    local target="${target_dir}/${rule}.txt"
    local tmp="${target}.tmp"

    geo_rule_safe_name "$rule" || return 0
    if ! curl -fsSL --retry 2 --connect-timeout 10 "${base}/${rule}.txt" -o "$tmp"; then
        rm -f "$tmp"
        echo -e "${yellow}Warning: failed to download geoip:${rule}; route will rely on built-ins or existing files.${plain}" >&2
        return 0
    fi
    mv "$tmp" "$target"
}

download_geo_route_rules() {
    if [[ "$SKIP_GEO_RULES" == "true" ]]; then
        echo -e "${yellow}Skipping geoip/geosite route rule download.${plain}"
        return
    fi

    mkdir -p "${CONFIG_DIR}/geoip" "${CONFIG_DIR}/geosite"

    local rule
    local geosite_rules="${KELI_GEOSITE_RULES:-apple google openai telegram netflix microsoft github youtube}"
    local geoip_rules="${KELI_GEOIP_RULES:-cn private}"

    echo -e "${green}Downloading geoip/geosite text route rules...${plain}"
    for rule in $geosite_rules; do
        download_geosite_rule "$rule"
    done
    for rule in $geoip_rules; do
        download_geoip_rule "$rule"
    done
}

stop_existing_service() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop v2node >/dev/null 2>&1 || true
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service v2node stop >/dev/null 2>&1 || true
    fi
}

cleanup_hy2_port_forward_rules() {
    for tool in iptables ip6tables; do
        command -v "$tool" >/dev/null 2>&1 || continue
        while IFS= read -r line; do
            [[ "$line" == *V2NODE-HY2* ]] || continue
            line="${line//\"/}"
            line="${line//\'/}"
            set -- $line
            [[ "${1:-}" == "-A" && "${2:-}" == "PREROUTING" ]] || continue
            shift 2
            "$tool" -t nat -D PREROUTING "$@" >/dev/null 2>&1 || true
        done < <("$tool" -t nat -S PREROUTING 2>/dev/null || true)
        "$tool" -t nat -F V2NODE-HY2 >/dev/null 2>&1 || true
        "$tool" -t nat -X V2NODE-HY2 >/dev/null 2>&1 || true
    done
}

uninstall_service() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop v2node >/dev/null 2>&1 || true
        systemctl disable v2node >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/v2node.service
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed v2node >/dev/null 2>&1 || true
    fi

    if command -v rc-service >/dev/null 2>&1; then
        rc-service v2node stop >/dev/null 2>&1 || true
    fi
    if command -v rc-update >/dev/null 2>&1; then
        rc-update del v2node default >/dev/null 2>&1 || true
    fi
    rm -f /etc/init.d/v2node
}

uninstall_native_node() {
    echo -e "${yellow}Uninstalling Keli native node...${plain}"
    uninstall_service
    cleanup_hy2_port_forward_rules

    if [[ -L /usr/local/bin/v2node ]]; then
        local link_target
        link_target="$(readlink /usr/local/bin/v2node || true)"
        if [[ "$link_target" == "${INSTALL_DIR}/v2node" ]]; then
            rm -f /usr/local/bin/v2node
        fi
    fi

    rm -f "${INSTALL_DIR}/v2node"
    rm -f "${INSTALL_DIR}/control.token"
    rm -f "${INSTALL_DIR}/.installed_version" "${INSTALL_DIR}/.kelinode-rs_version" "${INSTALL_DIR}/.keli-core-rs_version"

    if [[ "$PURGE_CONFIG" == "true" ]]; then
        rm -rf "$CONFIG_DIR"
        rm -rf "$INSTALL_DIR"
        echo -e "${green}Keli native node uninstalled and config removed.${plain}"
    else
        rmdir "$INSTALL_DIR" >/dev/null 2>&1 || true
        echo -e "${green}Keli native node uninstalled. Config preserved at ${CONFIG_DIR}.${plain}"
        echo "To remove config too: bash install.sh uninstall --purge-config"
    fi
}

install_service() {
    if command -v systemctl >/dev/null 2>&1; then
        cat >/etc/systemd/system/v2node.service <<EOF
[Unit]
Description=Keli Native Node
After=network.target nss-lookup.target
Wants=network.target

[Service]
User=root
Group=root
Type=simple
LimitNOFILE=999999
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/v2node server --config ${CONFIG_FILE}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable v2node >/dev/null
        systemctl restart v2node
        echo -e "${green}v2node service started with systemd.${plain}"
    elif command -v rc-update >/dev/null 2>&1; then
        cat >/etc/init.d/v2node <<EOF
#!/sbin/openrc-run

name="v2node"
description="Keli Native Node"
command="${INSTALL_DIR}/v2node"
command_args="server --config ${CONFIG_FILE}"
command_user="root"
pidfile="/run/v2node.pid"
command_background="yes"

depend() {
    need net
}
EOF
        chmod +x /etc/init.d/v2node
        rc-update add v2node default >/dev/null
        rc-service v2node restart
        echo -e "${green}v2node service started with OpenRC.${plain}"
    else
        echo -e "${yellow}No supported service manager found. Start manually:${plain}"
        echo "  ${INSTALL_DIR}/v2node server --config ${CONFIG_FILE}"
    fi
}

install_native_node() {
    local version="$1"
    local target="$2"
    local asset="keli-native-node-${version}-${target}"
    local url="https://github.com/keli-123456/kelinode-rs/releases/download/${version}/${asset}.tar.gz"
    local archive="${WORK_DIR}/${asset}.tar.gz"

    echo -e "${green}Installing Keli native node ${version} (${target})${plain}"
    echo "Download: ${url}"
    curl -fL "$url" -o "$archive"
    tar -xzf "$archive" -C "$WORK_DIR" --strip-components=1
    stop_existing_service
    (cd "$WORK_DIR" && sh ./install.sh "$INSTALL_DIR")
}

verify_installed_binary() {
    if "${INSTALL_DIR}/v2node" version >/dev/null 2>&1; then
        return
    fi

    echo -e "${red}Installed binary cannot run on this system.${plain}" >&2
    echo -e "${yellow}If the error mentions GLIBC, install v0.1.32 or newer so the static Linux binary is used.${plain}" >&2
    "${INSTALL_DIR}/v2node" version 2>&1 || true
    exit 1
}

WORK_DIR=""

main() {
    parse_args "$@"
    validate_args
    require_root

    if [[ "$ACTION" == "uninstall" ]]; then
        uninstall_native_node
        exit 0
    fi

    WORK_DIR="$(mktemp -d)"
    acquire_lock
    install_base_packages

    local target
    local version
    target="$(detect_target)"
    version="$(resolve_version)"
    if ! [[ "$version" =~ ^v[0-9] ]]; then
        echo -e "${red}Invalid version: ${version}${plain}" >&2
        exit 1
    fi

    install_native_node "$version" "$target"
    verify_installed_binary
    write_machine_config
    download_geo_route_rules
    install_service

    echo "------------------------------------------"
    echo -e "${green}Keli native node installed.${plain}"
    echo "Config: ${CONFIG_FILE}"
    echo "Command: v2node server --config ${CONFIG_FILE}"
    echo "Logs: v2node log"
    echo "      journalctl -u v2node -n 200 --no-pager -f"
    echo "------------------------------------------"
}

main "$@"
