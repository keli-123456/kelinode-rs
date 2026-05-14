#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
AGENT_DIR="${KELINODE_RS_DIR:-$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)}"
CORE_DIR="${KELI_CORE_RS_DIR:-$(CDPATH= cd -- "${AGENT_DIR}/../keli-core-rs" && pwd)}"
VERSION="${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "${AGENT_DIR}/Cargo.toml" | head -n 1)}"
TARGET_NAME="${TARGET_NAME:-linux-x86_64}"
DIST_ROOT="${DIST_ROOT:-${AGENT_DIR}/dist}"
PACKAGE_NAME="keli-native-node-v${VERSION}-${TARGET_NAME}"
PACKAGE_DIR="${DIST_ROOT}/${PACKAGE_NAME}"

if [ ! -f "${CORE_DIR}/Cargo.toml" ]; then
	echo "keli-core-rs source not found at ${CORE_DIR}; set KELI_CORE_RS_DIR." >&2
	exit 2
fi

cargo test --manifest-path "${CORE_DIR}/Cargo.toml" --locked --all-targets -- --test-threads=1
cargo test --manifest-path "${AGENT_DIR}/Cargo.toml" --locked --all-targets --features embedded-core -- --test-threads=1
cargo build --manifest-path "${AGENT_DIR}/Cargo.toml" --release --locked --features embedded-core

rm -rf "${PACKAGE_DIR}"
mkdir -p "${PACKAGE_DIR}/bin" "${PACKAGE_DIR}/docs"

cp "${AGENT_DIR}/target/release/kelinode-rs" "${PACKAGE_DIR}/bin/v2node"
cp "${AGENT_DIR}/README.md" "${PACKAGE_DIR}/README.md"
cp "${AGENT_DIR}/docs/CONTRACT.md" "${PACKAGE_DIR}/docs/CONTRACT.md"
cp "${AGENT_DIR}/docs/NATIVE_CORE_GRAY_RELEASE.md" "${PACKAGE_DIR}/docs/NATIVE_CORE_GRAY_RELEASE.md"
cp "${CORE_DIR}/docs/PARITY.md" "${PACKAGE_DIR}/docs/KELI_CORE_RS_PARITY.md"

cat >"${PACKAGE_DIR}/config.yml.example" <<'YAML'
kernel:
  type: keli-core-rs
  config_dir: "/etc/v2node"

machine:
  enabled: true
  continue_on_error: true
  profiles:
    - name: "default"
      url: "https://panel.example.com"
      token: "replace-me"
      machine_id: 1
YAML

cat >"${PACKAGE_DIR}/install.sh" <<'SH'
#!/usr/bin/env sh
set -eu

install_dir="${1:-/usr/local/v2node}"
mkdir -p "$install_dir" /etc/v2node /usr/local/bin
cp bin/v2node "$install_dir/v2node"
chmod +x "$install_dir/v2node"
ln -sf "$install_dir/v2node" /usr/local/bin/v2node
echo "Installed Keli native node to $install_dir"
echo "Run: $install_dir/v2node server --config /etc/v2node/config.yml"
SH
chmod +x "${PACKAGE_DIR}/install.sh"

tar -C "${DIST_ROOT}" -czf "${DIST_ROOT}/${PACKAGE_NAME}.tar.gz" "${PACKAGE_NAME}"
if command -v sha256sum >/dev/null 2>&1; then
	(cd "${DIST_ROOT}" && sha256sum "${PACKAGE_NAME}.tar.gz" >"${PACKAGE_NAME}.tar.gz.sha256")
fi

echo "${DIST_ROOT}/${PACKAGE_NAME}.tar.gz"
