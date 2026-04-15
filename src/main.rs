mod models;
mod oob;
mod sqx;

mod cli;
mod gui;

#[tokio::main]
async fn main() {
    use clap::Parser;
    cli::Cli::parse().run().await;
}
