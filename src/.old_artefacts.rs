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