use std::fs;
use std::path::Path;

#[test]
fn install_script_supports_release_base_url() {
    let script_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("script/install.sh");
    let script = fs::read_to_string(script_path).expect("read install.sh");

    assert!(script.contains("--release-base-url"));
    assert!(script.contains("release_manifest_url"));
    assert!(script.contains("sha256sum -c -"));
    assert!(script.contains("machine_id=${MACHINE_ID_ARG}"));
    assert!(script.contains("machine_token=${MACHINE_TOKEN_ARG}"));
}
