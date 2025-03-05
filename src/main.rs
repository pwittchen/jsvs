use clap::Parser;
use std::fs;
use swc_common::errors::{ColorConfig, Handler};
use swc_common::{sync::Lrc, BytePos, SourceMap};
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
    let cli = Cli::parse();
    let filepath = cli.filepath;
    if fs::metadata(&filepath).is_err() {
        eprintln!("Error: filepath {} does not exist", &filepath);
        return;
    }

    let file_content = fs::read_to_string(&filepath).expect("Cannot read file");

    let cm: Lrc<SourceMap> = Default::default();

    let source_file = cm.new_source_file(
        swc_common::FileName::Custom((&filepath).as_str().into()).into(),
        file_content.clone(),
    );

    let lexer = Lexer::new(
        Syntax::Es(Default::default()),
        Default::default(),
        StringInput::new(
            &source_file.src,
            BytePos(0),
            BytePos(source_file.src.len() as u32),
        ),
        None,
    );

    let handler = Handler::with_tty_emitter(ColorConfig::Auto, true, false, Some(cm));
    let mut parser = swc_ecma_parser::Parser::new_from(lexer);

    match parser.parse_script() {
        Ok(script) => println!("Parsed successfully: {:?}", script),
        Err(err) => {
            err.into_diagnostic(&handler).emit();
            eprintln!("Parsing failed!");
        }
    }
}
