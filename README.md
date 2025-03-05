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

Usage: jsvs --filepath <FILEPATH> [MODE]

Arguments:
  [MODE]  [default: js] [possible values: js, txt]

Options:
  -f, --filepath <FILEPATH>  
  -h, --help                 Print help
  -V, --version              Print version

```

Script has two parsing modes `js` and `txt`.
It was done due to the fact that script may be obfuscated or incorrectly formated,
therefore it won't be possible to parse it as a valid JavaScript file, but we may want to analyze it anyway.
That's why, we can analyze script as a text, which is unparsed script and still try to find vulnerabilities in it.

Examples of parsing scripts:

```
jsvs -f test_resources/file1_eval_usage.js
jsvs -f test_resources/file2_obfuscated_code.js -- txt
jsvs -f test_resources/file3_clean_file.js -- txt
jsvs -f test_resources/file4_keylogger.js -- js
```