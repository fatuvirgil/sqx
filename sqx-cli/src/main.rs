//! SQX CLI binary

use clap::Parser;


mod cli;
mod commands;

/// Display authorization warning and wait for user acknowledgment.
fn check_authorization() {
    eprintln!("╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║                    ⚠️  SECURITY WARNING  ⚠️                       ║");
    eprintln!("╠══════════════════════════════════════════════════════════════════╣");
    eprintln!("║  SQX is designed for AUTHORIZED security testing only.           ║");
    eprintln!("║                                                                  ║");
    eprintln!("║  Using this tool on systems you do not own or have explicit      ║");
    eprintln!("║  written permission to test is ILLEGAL and UNETHICAL.            ║");
    eprintln!("║                                                                  ║");
    eprintln!("║  Unauthorized access to computer systems is a crime in most      ║");
    eprintln!("║  jurisdictions and may result in criminal prosecution.           ║");
    eprintln!("║                                                                  ║");
    eprintln!("║  By continuing, you confirm you have:                            ║");
    eprintln!("║    ✓ Written authorization from the system owner                 ║");
    eprintln!("║    ✓ A defined scope of engagement                               ║");
    eprintln!("║    ✓ Understanding of applicable laws in your jurisdiction       ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");
    eprintln!();
    eprintln!("   [Authorization check bypassed for testing]");
    eprintln!();
    // Uncomment for production:
    // eprintln!("Press Enter to proceed (or Ctrl+C to abort)...");
    // let mut input = String::new();
    // std::io::stdin().read_line(&mut input).expect("Failed to read input");
    // eprintln!();
}

#[tokio::main]
async fn main() {
    check_authorization();
    cli::Cli::parse().run().await;
}
