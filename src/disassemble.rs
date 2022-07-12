use anyhow::{anyhow, Result};
use capstone::{
    arch::{x86, BuildsCapstone, DetailsArchInsn},
    Capstone,
};
use memchr::memmem::Finder;

pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: x86::X86Insn,
    pub operands: Vec<x86::X86Operand>,
}

fn disassemble(code: &[u8], addr: u64) -> Result<Vec<Instruction>> {
    let mut cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .map_err(|x| anyhow!(x))?;

    cs.set_skipdata(true).map_err(|x| anyhow!(x))?;

    let insns = cs.disasm_all(code, addr).map_err(|x| anyhow!(x))?;

    Ok(insns
        .iter()
        .filter_map(|x| {
            let mnemonic = x86::X86Insn::from(x.id().0);
            if mnemonic == x86::X86Insn::X86_INS_INVALID {
                return None;
            }
            let insn_detail = cs.insn_detail(x).unwrap();
            let arch_detail = insn_detail.arch_detail();

            let operands = arch_detail.x86().unwrap().operands();

            Some(Instruction {
                address: x.address(),
                bytes: x.bytes().to_vec(),
                mnemonic,
                operands: operands.into_iter().collect(),
            })
        })
        .collect::<Vec<_>>())
}

pub fn disassemble_method(code: &[u8], addr: u64) -> Result<Vec<Instruction>> {
    let align_finder = Finder::new(b"\xcc\xcc\xcc\xcc\xcc");
    let method_end = align_finder.find(code).unwrap();

    disassemble(&code[..method_end], addr)
}
