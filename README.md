# jsvs
JavaScript Vulnerability Scanner written in Rust

## building

```
cargo build
```

## testing

```
cargo test
```

## usage

```
JavaScript Vulnerability Scanner

Usage: jsvs --filepath <FILEPATH> <MODE>

Arguments:
  <MODE>  [possible values: js, txt]

Options:
  -f, --filepath <FILEPATH>  
  -h, --help                 Print help
  -V, --version              Print version
```

Examples:

```
jsvs js -f test_resources/file1_eval_usage.js
jsvs txt -f test_resources/file2_obfuscated_code.js
jsvs txt -f test_resources/file3_clean_file.js
jsvs js -f test_resources/file4_keylogger.js
```