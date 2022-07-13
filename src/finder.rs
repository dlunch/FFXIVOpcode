use anyhow::{anyhow, Result};
use capstone::arch::x86;
use object::{Object, ObjectSection};
use tokio::fs;

use crate::{
    disassemble::{disassemble_method, Instruction},
    patterns,
};

pub struct Finder {
    file: Vec<u8>,
    dispatch_insns: Vec<Instruction>,
    jump_table_offset: u64,
    va_offset: u64,
    base_address: u64,
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

        let va_offset = text_section.address() - (text_section.data()?.as_ptr() as usize - file.as_ptr() as usize) as u64;
        log::info!("va offset: {:x}", va_offset);

        let base_address = object.relative_address_base();
        log::info!("base addrses: {:x}", base_address);

        Ok(Self {
            file,
            dispatch_insns,
            jump_table_offset,
            va_offset,
            base_address,
        })
    }

    pub fn find_opcode(&self, handler_pattern: &[u8]) -> Option<u16> {
        let max_opcode = 1000;
        let opcode_base = 101;

        let handler_base = self.va_offset + Self::search_pattern(&self.file, handler_pattern).unwrap() as u64;
        log::info!("handler: {:x}", handler_base);

        let handler_call_idx = self.find_dispatch_xref_insn(handler_base).unwrap();

        // find jump table target
        let mut jump_target = 0;
        for insn in self.dispatch_insns.iter().rev().skip(self.dispatch_insns.len() - handler_call_idx) {
            if insn.mnemonic == x86::X86Insn::X86_INS_JMP {
                break;
            }
            jump_target = insn.address;
        }

        log::info!("jump target: {:x}", jump_target);

        let jump_table_begin = (self.jump_table_offset - self.va_offset) as usize;

        for (i, offset) in self.file[jump_table_begin..jump_table_begin + 4 * max_opcode].chunks(4).enumerate() {
            let current_jump_target = u32::from_le_bytes(offset.try_into().unwrap()) as u64 + self.base_address;

            if current_jump_target == jump_target {
                return Some(i as u16 + opcode_base);
            }
        }

        None
    }

    fn find_dispatch_xref_insn(&self, handler_base: u64) -> Option<usize> {
        for (i, insn) in self.dispatch_insns.iter().enumerate() {
            if insn.mnemonic == x86::X86Insn::X86_INS_CALL || insn.mnemonic == x86::X86Insn::X86_INS_JMP {
                if let x86::X86OperandType::Imm(imm) = insn.operands[0].op_type {
                    if imm as u64 == handler_base {
                        return Some(i);
                    }
                }
            }
        }

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
