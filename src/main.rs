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

use parse_elf::{Elf64, reader::Reader, ElfHeader, SegmentType, SegmentFlags};


/// Top level error for this crate
#[derive(Debug, Error)]
pub enum Error {
    #[error("Error mapping the range into memory")]
    MemoryMap(#[from] mmap::MapError),
    #[error("Chaging memory region protection, failed {0}")]
    ChangingProtection(#[from] region::Error),
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


    println!(" \u{1F30D} Mapping {:?} in memory...", input_path);

    // Define a base address for the memory mapping
    let mmap_base_address = 0x0400_000_usize;

    // If we drop the `mmap::MemoryMap` objects, the pages get unmapped
    let mut mappings = Vec::new();

    // Filter out non-loadable segments
    for ph in elf.ph_table.iter().filter(|ph| ph.p_type() == SegmentType::PtLoad) {
        println!(" \u{1F30D}  Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.p_flags());
        // mmap-ing would fail if the segments weren't aligned on pages,
        // but luckly, that is the case in the file already.
        let mem_range = ph.mem_range();

        // Add base to memory map start
        let start_addr = mem_range.start.0 as usize + mmap_base_address;

        // Align to the lower page boundary
        let aligned_start_addr = align_lo(start_addr);
        // Compute padding between alignment and actual start
        let padding = start_addr - aligned_start_addr;

        // Compute the length of the memory range, includin padding
        let len_no_padding: usize = (mem_range.end - mem_range.start).into();
        let len = len_no_padding + padding;

        // Convert address to pointer
        let addr: *mut u8 = aligned_start_addr as _;

        // Print Address
        println!(" \u{1F4EC}  Address: {:?}", addr);

        // Make the memory area writable, so we can copy data to it.
        // Also we make it map to the exact address we got from `addr`
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        println!(" \u{1F5A5}   Copying segment data...");

        {
            // Create a slice for our memory mapped region
            let dst = unsafe { std::slice::from_raw_parts_mut(addr, ph.data.len()) };
            // Copy segment contents to that region
            dst.copy_from_slice(&ph.data[..]);
        }

        println!(" \u{1F6A6}  Adjusting permissions...");

        // Map from our local parsed protections to the `region` crate's protections
        let mut protection = Protection::NONE;
        let flags = ph.p_flags();
        
        if flags.contains(SegmentFlags::Read) {
            protection |= Protection::READ;
        }

        if flags.contains(SegmentFlags::Write) {
            protection |= Protection::WRITE;
        }

        if flags.contains(SegmentFlags::Exec) {
            protection |= Protection::EXECUTE;
        }

        unsafe {
            protect(addr, len, protection)?;
        }


        // Add another newline for prettier output
        println!("\n");

        // Add the new map to our preserving list
        mappings.push(map);
    }

    println!("Jumping to entry point @ {:?}...", elf.elf_header.e_entry);
    // Accept user input
    pause("jmp").unwrap();
    unsafe {
        // Execute from entry point
        jmp((elf.elf_header.e_entry.0 as usize + mmap_base_address) as _);
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

// Truncate a `usize` value to the lower 4KiB boundary.
fn align_lo(value: usize) -> usize {
    value & !0xFFF
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