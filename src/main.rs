use clap::{Parser, ValueEnum};
use std::fs;
use std::rc::Rc;
use swc_common::{BytePos, SourceFile, SourceMap, sync::Lrc};
use swc_ecma_ast::Script;
use swc_ecma_parser::{StringInput, Syntax, lexer::Lexer};

#[derive(clap::Parser)]
#[command(name = "JSVS")]
#[command(version = "0.1.0")]
#[command(about = "JavaScript Vulnerability Scanner", long_about = None)]
struct Cli {
    #[arg(short, long)]
    filepath: String,

    #[arg(value_enum)]
    mode: ParsingMode
}

#[derive(Debug, Clone, ValueEnum)]
enum ParsingMode {
    Js,
    Txt,
}

fn main() {
    let cli = Cli::parse();
    let filepath = cli.filepath;

    if fs::metadata(&filepath).is_err() {
        eprintln!("Error: filepath {} does not exist", &filepath);
        return;
    }

    let file_content = fs::read_to_string(&filepath).expect("Cannot read file");

    match cli.mode {
        ParsingMode::Js => analyze_javascript(&filepath, file_content),
        ParsingMode::Txt => analyze_text(&filepath, file_content),
    }
}

fn analyze_javascript(filepath: &String, file_content: String) {
    let source_map: Lrc<SourceMap> = Default::default();

    let source_file = source_map.new_source_file(
        swc_common::FileName::Custom((&filepath).as_str().into()).into(),
        file_content,
    );

    let lexer = create_lexer(&source_file);
    let mut parser = swc_ecma_parser::Parser::new_from(lexer);

    match parser.parse_script() {
        Ok(script) => analyze_parsed_script(script),
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

fn analyze_parsed_script(script: Script) {
    //TODO: handle script parsing here
    println!("Parsed successfully: {:?}", script)
}

fn analyze_text(filepath: &String, file_content: String) {
    //TODO: implement text analysis
    println!("Analyzing text file {}", filepath);
}
