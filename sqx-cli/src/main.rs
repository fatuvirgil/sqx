//! SQX CLI binary

use clap::Parser;

mod cli;

#[tokio::main]
async fn main() {
    cli::Cli::parse().run().await;
}
