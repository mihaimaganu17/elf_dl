fn main() {
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

    println!("Executing {:?} in memory...", input_path);

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
}

/*
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

    // Print dynamic entries
    if let Some(dynamic_segment) = elf
        .ph_table
        .iter()
        .find(|ph| ph.p_type() == SegmentType::PtDynamic)
    {
        if let parse_elf::SegmentContents::Dynamic(table) = &dynamic_segment.contents {
            for entry in table.entries() {
                println!(" -> {:?}", entry);
            }
        }
    }
*/

/*
    let input_path = env::args().nth(1).expect("Please provide an Elf path");
    let bytes = fs::read(&input_path).expect("Cannot read file");

    println!("Analyzing {:?}...", input_path);
    let elf = Elf64::parse(&bytes).expect("Failed to parse Elf");

    println!("{:?}", elf);

    // Read Rela entries
    println!("Rela entries:");
    let rela_entries = elf.read_rela_entries().unwrap_or_else(|e| {
        println!("Could not read relocations: {:?}", e);
        Default::default()
    });
    
    for rela in &rela_entries {
        println!("{:#?}", rela);
        if let Some(seg) = elf.segment_at(rela.r_offset) {
            println!("... for {:#?}", seg);
        }
    }

    println!("Dynamic entries:...");
    if let Some(entries) = elf.dynamic_table() {
        for entry in entries {
            println!("{:?}", entry);
        }
    }

    println!("Section Headers");
    for sh in &elf.sh_table {
        println!("{:?}", sh);
    }

    println!("\n\nSymbol table");
    let sym_table = elf.read_syms()?;
    println!(
        "Symbol table @ {:?} contains {} entries",
        elf.dynamic_entry(DynamicTag::SymTab).ok_or(SymbolError::TableNotFound)?, sym_table.len()
    );

    println!(
        " {:6}{:12}{:10}{:16}{:16}{:12}{:12}",
        "Num", "Value", "Size", "Type", "Bind", "Ndx", "Name"
    );

    for (idx, sym_entry) in sym_table.iter().enumerate() {
        println!(
            " {:6}{:12}{:10}{:16}{:16}{:12}{:12}",
            format!("{}", idx),
            format!("{:?}", sym_entry.st_value()),
            format!("{:?}", sym_entry.st_size()),
            format!("{:?}", sym_entry.st_type()),
            format!("{:?}", sym_entry.st_binding()),
            format!("{:?}", sym_entry.st_shndx()),
            format!("{}", elf.get_string(Addr::from(sym_entry.st_name() as u64)).unwrap_or_default()),
        )
    }

    // Retrieve value for msg symbol
    let msg_sym = sym_table
        .iter()
        .find(|sym| {
            elf.get_string(Addr::from(sym.st_name() as u64)).unwrap_or_default() == "msg"
        }).expect("Should find `msg` in symbol table");

    let msg_slice = elf.slice_at(msg_sym.st_value()).expect("should find msg in memory");
    let msg_slice = &msg_slice[..msg_sym.st_size() as usize];
    println!("msg symbol contents: {:?}", String::from_utf8_lossy(msg_slice));

    println!(" \u{1F30D} Mapping {:?} in memory...", input_path);

    // Define a base address for the memory mapping
    let mmap_base_address = 0x40_0000_usize;

    println!("Loading with base address @ 0x{:08x}", mmap_base_address);

    // If we drop the `mmap::MemoryMap` objects, the pages get unmapped
    let mut mappings = Vec::new();

    // Filter out non-loadable segments
    for ph in elf.ph_table.iter()
        .filter(|ph| ph.p_type() == SegmentType::PtLoad)
        .filter(|ph| ph.mem_range().start < ph.mem_range().end)
    {
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

        if padding > 0 {
            println!("(With 0x{:x} bytes of padding at the start)", padding);
        }

        // Compute the length of the memory range, includin padding
        let len_no_padding: usize = (mem_range.end - mem_range.start).into();
        let len = len_no_padding + padding;

        // Convert address to pointer
        let addr: *mut u8 = aligned_start_addr as _;

        // Make the memory area writable, so we can copy data to it.
        // Also we make it map to the exact address we got from `addr`
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        {
            // Copy the segments data into memory region
            unsafe { std::ptr::copy_nonoverlapping(ph.data.as_ptr(), addr.add(padding), ph.data.len()) };
        }

        let mut num_relocs = 0;
        for reloc in &rela_entries {
            if mem_range.contains(&reloc.r_offset) {
                num_relocs += 1;
                unsafe {
                    use std::mem::transmute as transmute;
                    let real_seg_start = addr.add(padding);

                    let parsed_reloc_offset = reloc.r_offset;
                    let parsed_segment_start = mem_range.start;
                    let offset_into_segment = parsed_reloc_offset - parsed_segment_start;

                    println!(
                        "Applying {:?} relocation @ {:?} from segment start",
                        reloc.r_type, offset_into_segment
                    );

                    // Compute relocation address
                    let reloc_addr: *mut u64 = 
                        transmute(real_seg_start.add(offset_into_segment.into()));

                    // Compute value based on relocation type
                    match reloc.r_type {
                        parse_elf::RelType::Relative => {
                            let reloc_value = reloc.r_addend + mmap_base_address as u64;
                            println!("Replacing with value: {:x?}", reloc_value);
                            *reloc_addr = reloc_value;
                        },
                        r_type => {
                            eprintln!("Unsupported relocation type {:?}", r_type);
                        }
                    }
                }
            }
        }

        if num_relocs > 0 {
            println!("(Applied {} relocations)", num_relocs);
        }

        // Map from our local parsed protections to the `region` crate's protections
        let mut protection = Protection::NONE;
        let flags = ph.p_flags();
        
        if flags.contains(SegmentFlags::READ) {
            protection |= Protection::READ;
        }

        if flags.contains(SegmentFlags::WRITE) {
            protection |= Protection::WRITE;
        }

        if flags.contains(SegmentFlags::EXEC) {
            protection |= Protection::EXECUTE;
        }

        unsafe {
            protect(addr, len, protection)?;
        };

        // Add another newline for prettier output
        println!("\n");

        // Add the new map to our preserving list
        mappings.push(map);
    }

    println!("Jumping to entry point @ {:?}...", elf.elf_header.e_entry.0);
    // Accept user input
    pause("jmp").unwrap();
    unsafe {
        // Execute from entry point
        jmp((elf.elf_header.e_entry.0 as usize + mmap_base_address) as _);
    };

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
*/