use clap::Parser;
use std::fs;
use std::rc::Rc;
use swc_common::{sync::Lrc, BytePos, SourceFile, SourceMap};
use swc_ecma_ast::Script;
use swc_ecma_parser::{lexer::Lexer, StringInput, Syntax};

#[derive(clap::Parser)]
#[command(name = "JSVS")]
#[command(version = "0.1.0")]
#[command(about = "JavaScript Vulnerability Scanner", long_about = None)]
struct Cli {
    #[arg(short, long)]
    filepath: String,
}

fn main() {
    //TODO: consider creating 2 modes: JS parsing and TXT parsing (latter for obfuscated code)

    let cli = Cli::parse();
    let filepath = cli.filepath;

    if fs::metadata(&filepath).is_err() {
        eprintln!("Error: filepath {} does not exist", &filepath);
        return;
    }

    let file_content = fs::read_to_string(&filepath).expect("Cannot read file");
    let source_map: Lrc<SourceMap> = Default::default();

    let source_file = source_map.new_source_file(
        swc_common::FileName::Custom((&filepath).as_str().into()).into(),
        file_content,
    );

    let lexer = create_lexer(&source_file);
    let mut parser = swc_ecma_parser::Parser::new_from(lexer);

    match parser.parse_script() {
        Ok(script) => analyze_parsed_javascript_code(script),
        Err(_) => eprintln!("Parsing failed!"),
    }
}

fn create_lexer(source_file: &Rc<SourceFile>) -> Lexer {
    Lexer::new(
        Syntax::Es(Default::default()),
        Default::default(),
        StringInput::new(
            &source_file.src,
            BytePos(0),
            BytePos(source_file.src.len() as u32),
        ),
        None,
    )
}

fn analyze_parsed_javascript_code(script: Script) {
    //TODO: handle script parsing here
    println!("Parsed successfully: {:?}", script)
}
