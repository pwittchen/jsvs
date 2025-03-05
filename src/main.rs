use clap::{Parser};
use std::fs;

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
    let filepath = cli.filepath;
    if fs::metadata(&filepath).is_err() {
        eprintln!("Error: file path {} does not exist", &filepath);
        return;
    }
    let contents = fs::read_to_string(filepath).expect("Cannot read file");
    println!("{contents}");
}
