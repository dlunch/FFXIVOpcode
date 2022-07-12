use anyhow::{anyhow, Result};
use object::{Object, ObjectSection};
use tokio::fs;

use crate::{
    disassemble::{disassemble_method, Instruction},
    patterns,
};

pub struct Finder {
    dispatch_insns: Vec<Instruction>,
    jump_table_offset: usize,
}

impl Finder {
    pub async fn new(path: &str) -> Result<Self> {
        let file = fs::read(path).await?;
        let object = object::File::parse(&*file)?;
        let text_section = object.section_by_name(".text").ok_or_else(|| anyhow!("No .text section"))?;

        let code = text_section.data()?;

        let dispatch = Self::search_pattern(code, &patterns::DISPATCH_PACKET_PATTERN).unwrap();
        log::info!("dispatch: {:x}", text_section.address() + dispatch as u64);

        let dispatch_insns = disassemble_method(&code[dispatch..], text_section.address())?;

        let jump_table_offset = Self::find_jump_table(&dispatch_insns);

        Ok(Self {
            dispatch_insns,
            jump_table_offset,
        })
    }

    pub fn find_opcode(&self, handler_pattern: &[u8]) -> Option<u16> {
        None
    }

    fn find_jump_table(insns: &[Instruction]) -> usize {
        0
    }

    fn search_pattern(code: &[u8], pattern: &[u8]) -> Option<usize> {
        use memchr::memmem::Finder;

        let finder = Finder::new(pattern);

        finder.find(code)
    }
}
