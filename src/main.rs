use std::{
    env,
    fs,
    io::Write,
    process::{
        Command,
        Stdio
    },
    ops::Range
};

use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};
use thiserror::Error;

use parse_elf::{Elf64, reader::Reader, ElfHeader, SegmentType};


/// Top level error for this crate
#[derive(Debug, Error)]
pub enum Error {
    #[error("Error mapping the range into memory")]
    MemoryMap(#[from] mmap::MapError);
}


fn main() -> Result<(), Error>{
    let input_path = env::args().nth(1).expect("Please provide an Elf path");
    println!("{}", input_path);
    let bytes = fs::read(&input_path).expect("Cannot read file");

    println!("Analyzing {:?}...", input_path);
    let elf = Elf64::parse(&bytes).expect("Failed to parse Elf");

    println!("{:?}", elf);

    println!("Executing {:?}...", input_path);
    let status = Command::new(&input_path).status().expect("Failed to run cmd");

    if !status.success() {
        println!("Error executing");
    }

    println!("Disassembling {:?}...", input_path);

    let entry_point = elf.elf_header.e_entry;

    let code_ph = elf
        .ph_table
        .iter()
        .find(|ph| ph.mem_range().contains(&entry_point))
        .expect("segment with entry point not found");

    // Disassemble the bytes
    let output = ndisasm(&code_ph.data, entry_point);
    let output = String::from_utf8_lossy(&output.stdout);
    print!("{}", output);


    println!("Mapping {:?} in memory...", input_path);

    // If we drop the `mmap::MemoryMap` objects, the pages get unmapped
    let mut mappings = Vec::new();

    // Filter out non-loadable segments
    for ph in elf.ph_table.iter().filter(|ph| ph.p_type() == SegmentType::PtLoad) {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.p_flags());
        // mmap-ing would fail if the segments weren't aligned on pages,
        // but luckly, that is the case in the file already.
        let mem_range = ph.mem_range().into();
        // Compute the size of the memory range
        let len: usize = (mem_range.end - mem_range.start).into();

        // Convert addr to pointer
        let addr: *mut u8 = mem_range.start.0 as _;
        // Make the memory area writable, so we can copy data to it.
        // Also we make it map to the exact address we got from `addr`
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        println!("\u{1F5A8} Copying segment data...");


    }

    Ok(())
}


fn pause(reason: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Press Enter to {}...", reason);
    {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
    }
    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}

fn ndisasm(bytes: &[u8], origin: parse_elf::addr::Addr) -> std::process::Output {
    let child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-")
        .arg("-o")
        .arg(format!("{}", origin.0))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn ndisasm");

    // Fetch stdin
    child.stdin.as_ref().unwrap().write_all(bytes).expect("Failed to write to stdin");

    let output = child.wait_with_output().expect("Failed to read stdout");

    output
}

// Old stuff
    /*
    println!("Executing {:?} in memory..", input_path);

    use region::{protect, Protection};

    let code = &code_ph.data;

    pause("protect").expect("bad protect");

    unsafe {
        protect(code.as_ptr(), code_ph.data.len(), Protection::READ_WRITE_EXECUTE).expect("mprotect failed");
    }

    let entry_offset = entry_point - code_ph.p_vaddr();
    let entry_point = unsafe { code.as_ptr().add(entry_offset.into()) };

    println!("          code @ {:?}", code.as_ptr());
    println!("entry offset   @ {:?}", entry_offset);
    println!("entry point    @ {:?}", entry_point);

    println!("Press enter to jmp...");

    pause("jmp").expect("no jump");

    unsafe {
        jmp(entry_point);
    }
    */