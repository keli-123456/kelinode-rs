#![forbid(unsafe_code)]

use kelinode_rs::panel::contract::NODE_API_CONTRACT_VERSION;

fn main() {
    let command = std::env::args().nth(1).unwrap_or_else(|| "version".to_string());
    match command.as_str() {
        "version" => {
            println!(
                "kelinode-rs {} contract={}",
                env!("CARGO_PKG_VERSION"),
                NODE_API_CONTRACT_VERSION
            );
        }
        "help" | "--help" | "-h" => print_help(),
        other => {
            eprintln!("unknown command: {other}");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!("kelinode-rs commands:");
    println!("  version    print version and API contract");
}
