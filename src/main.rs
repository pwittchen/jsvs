use base64::{Engine as _, engine::general_purpose};
use clap::Parser;
use regex::Regex;
use std::fs;

#[derive(Parser)]
#[command(name = "JSVS")]
#[command(version = "0.1.0")]
#[command(about = "JavaScript Vulnerability Scanner", long_about = None)]
struct Cli {
    #[arg(short, long)]
    filepath: String,
}

fn main() {
    let cli = Cli::parse();
    let filepath = cli.filepath;

    if fs::metadata(&filepath).is_err() {
        eprintln!("Error: filepath {} does not exist", &filepath);
        return;
    }

    let file_content = fs::read_to_string(filepath).expect("Cannot read file");
    analyze_javascript(file_content);
}

fn analyze_javascript(file_content: String) {
    //TODO: return vector with found issues instead of printing them directly here
    //TODO: define types of vector: warning, alert
    //TODO: check difference between indexes for xhr.open/XMLHttpReq.responseText and eval/execscript
    // where low value is possibility of remote script execution
    //TODO: when all basic pattern detection will be implemented, refactor this code

    let suspicious_keywords = [
        "eval",
        "execscript",
        "document.write",
        "xhr.open",
        "xmlhttpreq.responsetext",
        "atob",
        "btoa",
        "window.addeventlistener(\"keydown\"",
        "formdata()",
        "fetch",
        "localstorage",
        "document.createelement",
        "document.createelement(\"script\")",
        "document.createelement(\"iframe\")",
        "iframe",
        "http://",
        "https://",
    ];
    for keyword in &suspicious_keywords {
        if let Some(index) = &file_content.to_lowercase().find(keyword) {
            println!("keyword: {} found at index: {}", keyword, index);
        }
    }

    let mut hex_counter: i32 = 0;
    let hex_pattern = r"(?i)\b(?:0x[a-f0-9]+|#[a-f0-9]{6}|\b[a-f0-9]{8}\b)\b";
    let re = Regex::new(hex_pattern).unwrap();
    for _ in re.find_iter(&file_content) {
        hex_counter += 1;
    }
    println!("Found {} hex values", hex_counter);

    let base64_part_pattern = r"(?i)\b[A-Za-z0-9+/=]{50,}\b";
    let re = Regex::new(base64_part_pattern).unwrap();
    let mut base64_string = String::new();
    for value in re.find_iter(&file_content) {
        base64_string.push_str(&value.as_str());
    }

    if !base64_string.as_str().is_empty() {
        let decoded_bytes = general_purpose::STANDARD_NO_PAD
            .decode(base64_string)
            .expect("Failed to decode base64 string");

        let decoded_string = String::from_utf8(decoded_bytes).expect("Invalid UTF-8");

        println!("DECODED BASE64:");
        println!("{}", decoded_string);
    }
}
