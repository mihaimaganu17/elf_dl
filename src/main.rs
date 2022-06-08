use thiserror::Error;

use parse_elf::{
    SegmentError,
    StringError,
    SymbolError
};

/// Top level error for this crate
#[derive(Debug, Error)]
pub enum Error {
    #[error("Error mapping the range into memory")]
    MemoryMap(#[from] mmap::MapError),
    #[error("Chaging memory region protection, failed {0}")]
    ChangingProtection(#[from] region::Error),
    #[error("Segment erro {0}")]
    SegmentError(#[from] SegmentError),
    #[error("String error {0}")]
    StringError(#[from] StringError),
    #[error("Symbol error {0}")]
    SymbolError(#[from] SymbolError),
    #[error("Error loading the object: {0}")]
    LoadError(#[from] LoadError),
    #[error("Infallible: {0}")]
    Infallible(#[from] std::convert::Infallible),
    #[error("Relocation Error: {0}")]
    RelocationError(#[from] process::RelocationError),
}

pub mod process;
pub mod segment;

use process::{LoadError};

fn main() -> Result<(), Error> {
    // Fetch input path given from CLI
    let input_path = std::env::args().nth(1).expect("Usage: elk <FILE_PATH>");

    let mut proc = process::Process::new();
    let exe_idx = proc.load_object_and_deps(input_path)?;
    proc.apply_relocations()?;
    proc.adjust_protections()?;

    let exec_obj = &proc.objects[exe_idx];
    let entry_point = exec_obj.elf.elf_header.e_entry + exec_obj.base_addr;

    unsafe {jmp(entry_point.as_ptr())};

    //println!("{:#?}", proc);
    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}