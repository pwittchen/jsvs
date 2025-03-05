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

Examples of parsing scripts:

```
jsvs -f test_resources/file1_eval_usage.js -- js
jsvs -f test_resources/file2_obfuscated_code.js -- txt
jsvs -f test_resources/file3_clean_file.js -- txt
jsvs -f test_resources/file4_keylogger.js -- js
```