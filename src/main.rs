use crate::VulnerabilityType::{Alert, Warning};
use base64::{Engine as _, engine::general_purpose};
use clap::Parser;
use colored::Colorize;
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

struct VulnerabilityRule {
    keywords: Vec<String>,
    description: String,
    vulnerability_type: VulnerabilityType,
}

struct DetectedVulnerability {
    keyword: String,
    keyword_index: usize,
    description: String,
    vulnerability_type: VulnerabilityType,
}

#[derive(Debug, PartialEq, Eq)]
enum VulnerabilityType {
    Warning,
    Alert,
}

fn main() {
    let cli = Cli::parse();
    let filepath = cli.filepath;

    if fs::metadata(&filepath).is_err() {
        eprintln!("Error: filepath {} does not exist", &filepath);
        return;
    }

    let file_content = fs::read_to_string(filepath).expect("Cannot read file");
    analyze_javascript(file_content, false);
}

fn analyze_javascript(file_content: String, is_base64_decoded: bool) {
    let mut vulnerabilities: Vec<DetectedVulnerability> = Vec::new();

    vulnerabilities.extend(find_vulnerabilities_by_rules(
        &file_content,
        is_base64_decoded,
    ));
    vulnerabilities.extend(find_vulnerabilities_by_hex_count(&file_content));
    vulnerabilities.extend(find_vulnerabilities_in_base64(&file_content));
    vulnerabilities.extend(find_possible_remote_code_execution(&vulnerabilities));

    print_detected_vulnerabilities(vulnerabilities);
}

fn find_vulnerabilities_by_rules(
    file_content: &String,
    is_base64_decoded: bool,
) -> Vec<DetectedVulnerability> {
    let mut detected_vulnerabilities: Vec<DetectedVulnerability> = Vec::new();
    for rule in get_vulnerability_rules() {
        for keyword in rule.keywords {
            if let Some(index) = &file_content.to_lowercase().find(&keyword) {
                let description: String = if is_base64_decoded {
                    format!(
                        "{} {}",
                        &rule.description.clone(),
                        "(base64 decoded)".bold().bright_magenta()
                    )
                } else {
                    rule.description.to_string()
                };

                let vulnerability_type = if rule.vulnerability_type == Alert {
                    Alert
                } else if is_base64_decoded {
                    Alert
                } else {
                    Warning
                };

                detected_vulnerabilities.push(DetectedVulnerability {
                    keyword,
                    keyword_index: *index,
                    description,
                    vulnerability_type,
                });
            }
        }
    }
    detected_vulnerabilities
}

fn find_vulnerabilities_in_base64(content: &String) -> Vec<DetectedVulnerability> {
    let base64_encoded_text = encode_base64_text(content);
    let mut detected_vulnerabilities: Vec<DetectedVulnerability> = Vec::new();
    if !base64_encoded_text.as_str().is_empty() {
        detected_vulnerabilities.push(DetectedVulnerability {
            keyword: "base64".to_string(),
            keyword_index: 0,
            description: String::from(
                "Found base64 encoded text what may suggest hiding some information",
            ),
            vulnerability_type: Warning,
        });

        let decoded_bytes = general_purpose::STANDARD_NO_PAD
            .decode(base64_encoded_text)
            .expect("Failed to decode base64 string");

        let base64_decoded_text = String::from_utf8(decoded_bytes).expect("Invalid UTF-8");
        analyze_javascript(base64_decoded_text, true);
    }
    detected_vulnerabilities
}

fn encode_base64_text(content: &String) -> String {
    let base64_pattern = r"(?i)\b[A-Za-z0-9+/=]{50,}\b";
    let re = Regex::new(base64_pattern).unwrap();
    let mut base64_encoded_text = String::new();
    for value in re.find_iter(&content) {
        base64_encoded_text.push_str(&value.as_str());
    }
    base64_encoded_text
}

fn count_hex_values(content: &String) -> usize {
    let mut hex_counter: usize = 0;
    let hex_pattern = r"(?i)\b(?:0x[a-f0-9]+|#[a-f0-9]{6}|\b[a-f0-9]{8}\b)\b";
    let re = Regex::new(hex_pattern).unwrap();
    for _ in re.find_iter(&content) {
        hex_counter += 1;
    }
    hex_counter
}

fn find_vulnerabilities_by_hex_count(content: &String) -> Vec<DetectedVulnerability> {
    let hex_counter = count_hex_values(&content);
    let mut detected_vulnerabilities: Vec<DetectedVulnerability> = Vec::new();

    if hex_counter > 0 {
        detected_vulnerabilities.push(DetectedVulnerability {
            keyword: "hex".to_string(),
            keyword_index: 0,
            description: if hex_counter < 10 {
                String::from(format!("{} hexadecimal values", hex_counter))
            } else {
                String::from(format!(
                    "{} hexadecimal values suggests heavy obfuscation what can hide malware",
                    hex_counter
                ))
            },
            vulnerability_type: if hex_counter < 10 { Warning } else { Alert },
        });
    }

    detected_vulnerabilities
}

fn find_possible_remote_code_execution(
    vulnerabilities: &Vec<DetectedVulnerability>,
) -> Vec<DetectedVulnerability> {
    let mut detected_vulnerabilities: Vec<DetectedVulnerability> = Vec::new();
    let mut response_text_index: usize = 0;
    let mut eval_index: usize = 0;
    let mut exec_script_index: usize = 0;
    for v in vulnerabilities {
        if v.keyword == "xmlhttpreq.responsetext" {
            response_text_index = v.keyword_index
        } else if v.keyword == "eval" {
            eval_index = v.keyword_index
        } else if v.keyword == "execscript" {
            exec_script_index = v.keyword_index
        }
    }

    if (response_text_index > 0 && eval_index > 0) || (exec_script_index > 0 && eval_index > 0) {
        let diff_eval: usize = if response_text_index <= eval_index {
            eval_index - response_text_index
        } else {
            999
        };

        let diff_exec: usize = if response_text_index <= exec_script_index {
            exec_script_index - response_text_index
        } else {
            999
        };

        if diff_eval < 100 || diff_exec < 100 {
            detected_vulnerabilities.push(DetectedVulnerability {
                keyword: String::from("eval/execscript(xmlhttpreq.responsetext)"),
                keyword_index: eval_index,
                description: String::from(
                    "Possible execution of the malicious code from the remote server",
                ),
                vulnerability_type: Alert,
            })
        }
    }
    detected_vulnerabilities
}

fn print_detected_vulnerabilities(detected_vulnerabilities: Vec<DetectedVulnerability>) {
    for v in detected_vulnerabilities {
        println!(
            " • {}\t index: {}\t keyword: {} {}",
            if v.vulnerability_type == Alert {
                "Alert".red()
            } else {
                "Warning".yellow()
            },
            v.keyword_index.to_string().bright_blue(),
            v.keyword.to_string().underline(),
            v.description.cyan()
        );
    }
}

fn get_vulnerability_rules() -> [VulnerabilityRule; 16] {
    [
        VulnerabilityRule {
            keywords: vec![
                String::from("eval"),
                String::from("execscript"),
                String::from("document.write"),
                String::from("document.createelement(\"script\")"),
            ],
            description: String::from("Possible XSS"),
            vulnerability_type: Alert,
        },
        VulnerabilityRule {
            keywords: vec![
                String::from("xmlhttprequest"),
                String::from("xhr.open"),
                String::from("xmlhttpreq.responsetext"),
                String::from("fetch"),
                String::from("https://"),
            ],
            description: String::from("Possible insecure API call"),
            vulnerability_type: Warning,
        },
        VulnerabilityRule {
            keywords: vec![String::from("atob"), String::from("btoa")],
            description: String::from("Suspicious Base64 encoding or decoding"),
            vulnerability_type: Warning,
        },
        VulnerabilityRule {
            keywords: vec![
                String::from("addeventlistener(\"keydown\""),
                String::from("addeventlistener(\"keyup\""),
                String::from("addeventlistener(\"keypress\""),
            ],
            description: String::from("Possible keylogger"),
            vulnerability_type: Alert,
        },
        VulnerabilityRule {
            keywords: vec![
                String::from("addeventlistener"),
                String::from("addeventlistener(\"submit\""),
                String::from("addeventlistener(\"load\""),
                String::from("addeventlistener(\"unload\""),
                String::from("addeventlistener(\"beforeunload\""),
            ],
            description: String::from("Triggering actions on event"),
            vulnerability_type: Alert,
        },
        VulnerabilityRule {
            keywords: vec![
                String::from("document.queryselectorall"),
                String::from("formdata()"),
            ],
            description: String::from("Possible user data exfiltration"),
            vulnerability_type: Alert,
        },
        VulnerabilityRule {
            keywords: vec![String::from("preventdefault()")],
            description: String::from("Changing app behavior by preventing default actions"),
            vulnerability_type: Alert,
        },
        VulnerabilityRule {
            keywords: vec![
                String::from("localstorage"),
                String::from("sessionstorage"),
                String::from("getitem"),
            ],
            description: String::from("Reading local storage or session storage capabilities"),
            vulnerability_type: Warning,
        },
        VulnerabilityRule {
            keywords: vec![String::from("setitem"), String::from("removeitem")],
            description: String::from("local storage or session storage manipulation"),
            vulnerability_type: Alert,
        },
        VulnerabilityRule {
            keywords: vec![String::from("createlement")],
            description: String::from("DOM manipulation"),
            vulnerability_type: Warning,
        },
        VulnerabilityRule {
            keywords: vec![String::from("document.createelement(\"iframe\")")],
            description: String::from("IFrame injection with possible clickjacking"),
            vulnerability_type: Alert,
        },
        VulnerabilityRule {
            keywords: vec![String::from("iframe")],
            description: String::from("IFrame found, what can enable hidden tracking"),
            vulnerability_type: Warning,
        },
        VulnerabilityRule {
            keywords: vec![String::from(".js")],
            description: String::from("External script usage"),
            vulnerability_type: Warning,
        },
        VulnerabilityRule {
            keywords: vec![String::from("http://")],
            description: String::from("Insecure API Call without SSL"),
            vulnerability_type: Alert,
        },
        VulnerabilityRule {
            keywords: vec![
                String::from("customerData"),
                String::from("input-firstname"),
                String::from("input-lastname"),
                String::from("email"),
                String::from("telephone"),
                String::from("phone"),
                String::from("address"),
                String::from("city"),
                String::from("postcode"),
                String::from("zip"),
                String::from("zone"),
                String::from("country"),
            ],
            description: String::from("Possible user data exfiltration with specified fields"),
            vulnerability_type: Alert,
        },
        VulnerabilityRule {
            keywords: vec![
                String::from("input-payment"),
                String::from("input-payment-firstname"),
                String::from("input-payment-lastname"),
                String::from("input-payment-email"),
                String::from("input-payment-telephone"),
                String::from("input-payment-city"),
                String::from("input-payment-postcode"),
                String::from("input-cc-owner"),
                String::from("input-cc-number"),
                String::from("input-cc-expire-date"),
                String::from("input-cc-cvv2"),
                String::from("holder"),
                String::from("cvv"),
                String::from("ccv"),
                String::from("cc_expire_date_year"),
            ],
            description: String::from("Possible user payment data exfiltration and money stealing"),
            vulnerability_type: Alert,
        },
    ]
}
