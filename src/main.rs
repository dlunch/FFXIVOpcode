mod disassemble;
mod patterns;

use anyhow::{anyhow, Result};
use clap::Parser;
use memchr::memmem::Finder;
use object::{Object, ObjectSection};
use tokio::fs;

#[derive(Parser)]
struct Args {
    file_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = pretty_env_logger::init();

    let args = Args::parse();

    let file = fs::read(args.file_name).await?;
    let object = object::File::parse(&*file)?;
    let text_section = object.section_by_name(".text").ok_or_else(|| anyhow!("No .text section"))?;

    let code = text_section.data()?;

    let dispatch = search_pattern(code, &patterns::DISPATCH_PACKET_PATTERN).unwrap();
    println!("dispatch: {:x}", text_section.address() + dispatch as u64);

    let insns = disassemble::disassemble_method(&code[dispatch..], text_section.address())?;

    println!("{:x?}", insns[0].bytes);

    Ok(())
}

fn search_pattern(code: &[u8], pattern: &[u8]) -> Option<usize> {
    let finder = Finder::new(pattern);

    finder.find(code)
}
