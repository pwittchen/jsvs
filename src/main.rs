use clap::Parser;
use std::fs;
use std::rc::Rc;
use swc_common::{BytePos, SourceFile, SourceMap, sync::Lrc};
use swc_ecma_parser::{StringInput, Syntax, lexer::Lexer};

#[derive(clap::Parser)]
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

    let file_content = fs::read_to_string(&filepath).expect("Cannot read file");
    let source_map: Lrc<SourceMap> = Default::default();

    let source_file = source_map.new_source_file(
        swc_common::FileName::Custom((&filepath).as_str().into()).into(),
        file_content.clone(),
    );

    let lexer = create_lexer(&source_file);
    let mut parser = swc_ecma_parser::Parser::new_from(lexer);

    match parser.parse_script() {
        Ok(script) => println!("Parsed successfully: {:?}", script),
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
