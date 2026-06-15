//! Arbitraitor CLI entry point.

#![forbid(unsafe_code)]

use clap::Parser;

/// Arbitraitor: Secure Download and Execution Gate
#[derive(Parser)]
#[command(name = "arbitraitor", version, about, long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt().with_env_filter(level).init();

    tracing::info!("arbitraitor initialized");

    // TODO: implement CLI subcommands per spec Section 28
}
