#![forbid(unsafe_code)]

use kelinode_rs::config::AppConfig;
use kelinode_rs::panel::contract::NODE_API_CONTRACT_VERSION;
use kelinode_rs::runtime::Bootstrap;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "version".to_string());
    match command.as_str() {
        "version" => {
            println!(
                "kelinode-rs {} contract={}",
                env!("CARGO_PKG_VERSION"),
                NODE_API_CONTRACT_VERSION
            );
        }
        "check-config" => {
            let path = args
                .next()
                .unwrap_or_else(|| "/etc/v2node/config.yml".to_string());
            let config = AppConfig::load_from_path(path)?;
            let resolved = config.resolve_runtime()?;
            let bootstrap = Bootstrap::from_config(&config);
            println!(
                "mode={:?} nodes={} machine_profiles={} subscription_proxy={}",
                bootstrap.mode,
                resolved.nodes.len(),
                resolved.machine.profiles.len(),
                resolved.agent.subscription_proxy.enabled
            );
        }
        "help" | "--help" | "-h" => print_help(),
        other => {
            eprintln!("unknown command: {other}");
            print_help();
            return Err("invalid command".to_string());
        }
    }
    Ok(())
}

fn print_help() {
    println!("kelinode-rs commands:");
    println!("  version    print version and API contract");
    println!("  check-config [path]    load config and print resolved runtime shape");
}
