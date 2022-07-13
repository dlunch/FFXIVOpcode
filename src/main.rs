mod disassemble;
mod finder;
mod patterns;

use anyhow::Result;
use clap::Parser;
#[derive(Parser)]
struct Args {
    file_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = pretty_env_logger::init();

    let args = Args::parse();

    let finder = finder::Finder::new(&args.file_name).await?;

    let move_opcode = finder.find_opcode(&patterns::HANDLE_MOVE_REGION_PATTERN);
    println!("{:?}", move_opcode);

    Ok(())
}
