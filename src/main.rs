use clap::{Parser};
#[derive(Parser)]
#[command(name = "JSVS")]
#[command(version = "0.1.0")]
#[command(about = "JavaScript Vulnerability Scanner", long_about = None)]
struct Cli {
    #[arg(short, long)]
    filepath: String
}

fn main() {
    let cli = Cli::parse();
    println!("filename: {}", cli.filepath);
}
