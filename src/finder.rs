use anyhow::{anyhow, Result};
use capstone::arch::x86;
use object::{Object, ObjectSection};
use tokio::fs;

use crate::{
    disassemble::{disassemble_method, Instruction},
    patterns,
};

pub struct Finder {
    dispatch_insns: Vec<Instruction>,
    jump_table_offset: u64,
}

impl Finder {
    pub async fn new(path: &str) -> Result<Self> {
        let file = fs::read(path).await?;
        let object = object::File::parse(&*file)?;
        let text_section = object.section_by_name(".text").ok_or_else(|| anyhow!("No .text section"))?;

        let code = text_section.data()?;

        let dispatch_base = Self::search_pattern(code, &patterns::DISPATCH_PACKET_PATTERN).unwrap();
        log::info!("dispatch: {:x}", text_section.address() + dispatch_base as u64);

        let dispatch_insns = disassemble_method(&code[dispatch_base..], text_section.address() + dispatch_base as u64)?;
        let jump_table_offset = Self::find_jump_table(object.relative_address_base(), &dispatch_insns).unwrap();
        log::info!("jump table: {:x}", jump_table_offset);

        Ok(Self {
            dispatch_insns,
            jump_table_offset,
        })
    }

    pub fn find_opcode(&self, handler_pattern: &[u8]) -> Option<u16> {
        None
    }

    fn find_jump_table(image_base: u64, insns: &[Instruction]) -> Option<u64> {
        // find `mov ecx, DWORD PTR [r8+rax*4+<jump table address>]`
        // assumes r8 is image base, rax is the index of the jump table

        for insn in insns {
            if insn.mnemonic == x86::X86Insn::X86_INS_MOV {
                if let x86::X86OperandType::Mem(mem) = insn.operands[1].op_type {
                    if mem.base().0 as u32 == x86::X86Reg::X86_REG_R8 && mem.index().0 as u32 == x86::X86Reg::X86_REG_RAX && mem.scale() == 4 {
                        return Some(image_base + mem.disp() as u64);
                    }
                }
            }
        }

        None
    }

    fn search_pattern(code: &[u8], pattern: &[u8]) -> Option<usize> {
        use memchr::memmem::Finder;

        let finder = Finder::new(pattern);

        finder.find(code)
    }
}
