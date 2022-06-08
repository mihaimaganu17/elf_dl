use std::{
    fs,
    path::{Path, PathBuf},
    collections::HashMap,
    ops::Range, os::unix::prelude::AsRawFd,
};

use mmap::{MemoryMap, MapOption};
use thiserror::Error;
use custom_debug_derive::Debug as CustomDebug;

use parse_elf::{Addr, SymbolError, SegmentFlags};

use crate::{segment};

const BASE_ADDR: u64 = 0x0040_0000;

#[derive(Debug)]
pub struct Process {
    /// The entire graph of objects that belong to this `Process`
    pub objects: Vec<Object>,
    /// Keep track of every loaded object for this process
    /// `PathBuf` is the system path from which we loaded the object
    /// `usize` is the index from `search_paths` for the loaded objects
    pub loaded_objects: HashMap<PathBuf, usize>,
    /// All paths that should contain libraries we need to load for this process
    pub search_paths: Vec<PathBuf>,
}

impl Process {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            loaded_objects: HashMap::new(),
            search_paths: vec!["/lib/x86_64-linux-gnu".into()],
        }
    }

    pub fn lookup_symbol(
        &self,
        name: &str,
        ignore: Option<&Object>,
    ) -> Result<Option<(&Object, &parse_elf::SymbolEntry)>, RelocationError> {
        let candidates = self.objects.iter();
        let candidates: Box<dyn Iterator<Item = &Object>> = if let Some(ignored) = ignore {
            Box::new(candidates.filter(|&obj| !std::ptr::eq(obj, ignored)))
        } else {
            Box::new(candidates)
        };

        for obj in candidates {
            for (i, sym) in obj.symbol_table.iter().enumerate() {
                if obj.sym_name(i)? == name {
                    return Ok(Some((obj, sym)));
                }
            }
        }
        Ok(None)
    }

    /// Loads an Elf as an object from `path`
    pub fn load_object<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, LoadError> {
        // Canonicalize the relative path
        let path = path.as_ref().canonicalize()
            .map_err(|err| LoadError::InputError(path.as_ref().to_path_buf(), err))?;

        // Open the file we are about to load
        let mut fs_file = fs::File::open(&path)
            .map_err(|e| LoadError::InputError(path.clone(), e))?;
        // Initialize a vector for the data to be stored
        let mut data = Vec::new();
        use std::io::Read;
        // Read file into `data`
        fs_file.read_to_end(&mut data)
            .map_err(|err| LoadError::InputError(path.clone(), err))?;
        // Read the file we have been passed
        let bytes = fs::read(&path)
            .map_err(|err| LoadError::InputError(path.clone(), err))?;

        println!("Loading {:?}", path);
        // Try and parse the Elf from the bytes we have
        let elf = parse_elf::Elf64::parse(bytes)?;

        let origin_path = path
            .parent()
            .ok_or_else(|| PathError::ParentNotFound(path.clone()))?
            .to_str()
            .ok_or_else(|| PathError::FailedToStr(path.clone()))?;

        self.search_paths.extend(
            elf.dynamic_entry_strings(parse_elf::DynamicTag::RunPath)
            .map(|run_path| run_path.replace("$ORIGIN", &origin_path))
            .inspect(|run_path| println!("Found RunPath entry {:?}", run_path))
            .map(|run_path| PathBuf::from(run_path))
        );

        self.search_paths.extend(
            elf.dynamic_entry_strings(parse_elf::DynamicTag::RPath)
            .map(|run_path| run_path.replace("$ORIGIN", &origin_path))
            .inspect(|run_path| println!("Found RunPath entry {:?}", run_path))
            .map(|run_path| PathBuf::from(run_path))
        );

        // Compute the current length of our objects
        let index = self.objects.len();

        let load_segments = load_segments(&elf);

        // Compute the minimal memory range we need to map the object
        let mem_range = load_segments
            .iter()
            .map(|ph| ph.mem_range())
            .fold(None, |acc, range| {
                match acc {
                    None => Some(range),
                    Some(acc_range) => Some(convex_hull(acc_range, range))
                }
            })
            .ok_or(LoadError::NoLoadSegment)?;

        // Comput the size of the range
        let mem_size = (mem_range.end - mem_range.start).into();

        let mem_map = std::mem::ManuallyDrop::new(MemoryMap::new(
            mem_size,
            &[
                MapOption::MapReadable,
                MapOption::MapWritable,
            ])?);

        // Compute base address based on what was mapped
        // We substract the leftmost memory start, just in case it is not zero, and we do not
        // want to give the false impression that that memory is actually allocated.
        let base_addr = parse_elf::Addr(mem_map.data() as _) - mem_range.start;

        // Map the file into memory
        let segments = load_segments
            .iter()
            .filter(|ph| ph.p_memsz().0 > 0)
            .map(|ph| -> Result<_, LoadError> {
                // Round down Virtual address to the lowest multiple of 0x1000 to align it
                let vaddr = Addr(ph.p_vaddr().0 & !0xFFF);
                // Compute the padding
                let padding = ph.p_vaddr() - vaddr;
                // Adjust offset to make sure we map the right thing from the file
                let offset = ph.p_offset() - padding;
                // Adjust file size according to padding
                let filesz = ph.p_filesz() + padding;

                let mapping = 
                    // Map the segments into memory
                    MemoryMap::new(
                        filesz.into(),
                        &[
                            mmap::MapOption::MapReadable,
                            mmap::MapOption::MapWritable,
                            mmap::MapOption::MapFd(fs_file.as_raw_fd()),
                            mmap::MapOption::MapOffset(offset.into()),
                            mmap::MapOption::MapAddr(unsafe {(base_addr + vaddr).as_ptr()}),
                        ])?;

                // If memory size is bigger than filesize
                if ph.p_memsz() > ph.p_filesz() {
                    // We zero out the difference.
                    // We already reserved the *convex hull* of all segments in memory in
                    // out initial `MemoryMap::new` call, so that memory is there.
                    let mut zero_start = base_addr + ph.mem_range().start + ph.p_filesz();
                    let zero_len = ph.p_memsz() - ph.p_filesz();
                    unsafe {
                        for i in zero_start.as_mut_slice::<u8>(zero_len.into()) {
                            *i = 0;
                        }
                    }
                }
                Ok(segment::Segment {
                        mapping,
                        padding,
                        flags: ph.p_flags(),
                })
            }).collect::<Result<Vec<_>, _>>()?;

        // Read symbol table
        let symbol_table = elf.read_syms()?;

        // Create the object
        let object = Object {
            path: path.clone(),
            base_addr,
            segments,
            elf,
            mem_range,
            symbol_table,
        };
 
        // Test if the symbols were loaded
        if path.to_str().unwrap().ends_with("libmsg.so") {
            let msg_addr: *const u8 = unsafe { (base_addr + parse_elf::Addr(0x2000)).as_ptr() };
            dbg!(msg_addr);
            let msg_slice = unsafe {std::slice::from_raw_parts(msg_addr, 0x26)};
            let msg = std::str::from_utf8(msg_slice).unwrap();
            dbg!(msg);
        }

        // Add the new parsed object to the process' objects
        self.objects.push(object);

        self.loaded_objects.insert(path, index);

        // Return the index where the object was stored in our array
        Ok(index)
    }

    /// Load the object and all its dependencies in a breath-first order.
    /// Returns the new loaded object index from
    /// `objects` or `LoadError` if it fails
    pub fn load_object_and_deps<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, LoadError> {
        // Load the initial object from the `path` given as argument
        let index = self.load_object(path)?;

        // Create a new array that will store all the indexes of already loaded objects
        let mut already_loaded = vec![index];

        while !already_loaded.is_empty() {
            // Create a new array that will store indexes of objects to be loaded
            already_loaded = already_loaded
                .into_iter()
                .flat_map(|idx| {
                    self.objects[idx]
                        .elf
                        .dynamic_entry_strings(parse_elf::DynamicTag::Needed)
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|dep| self.get_object(&dep))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter_map(|res| match res {
                    GetResult::Cached(_) => None,
                    GetResult::Fresh(index) => Some(index),
                })
                .collect();
        }

        Ok(index)
    }

    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        let path = self.search_paths
            .iter()
            .filter_map(|path| path.join(name).canonicalize().ok())
            .find(|path| path.exists())
            .ok_or_else(|| PathError::NotFound(name.into()))?;

        Ok(path)
    }

    /// Returns the index of an already loaded object if it is found in `loaded_objects`
    /// If it is not found, it loads the object and returns the new index
    pub fn get_object(&mut self, name: &str) -> Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.loaded_objects
            .get(&path)
            .map(|&index| Ok(GetResult::Cached(index)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
    }

    pub fn adjust_protections(&self) -> Result<(), region::Error> {
        use region::{protect, Protection};

        for obj in &self.objects {
            for seg in &obj.segments {
                // Initialize protection
                let mut protection = Protection::NONE;
                // Enumerate flags
                let flags = seg.flags;

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
                    protect(seg.mapping.data(), seg.mapping.len(), protection)?;
                }
            }
        }

        Ok(())
    }

    /// Applies relocations based on RelA entries
    pub fn apply_relocations(&self) -> Result<(), RelocationError> {
        for obj in self.objects.iter().rev() {
            println!("Apply relocations for {:?}", obj.path);
            // Check if rela entryies can be read
            match obj.elf.read_rela_entries() {
                Ok(rels) => {
                    for rel in rels {
                        println!("Found {:?}", rel);
                        match rel.r_type {
                            parse_elf::RelType::W64 => {
                                let name = obj.sym_name(rel.r_sym as usize)?;
                                println!("Should look up {:?}", name);
                                let (lib, sym) = self
                                    .lookup_symbol(&name, None)?
                                    .ok_or(RelocationError::UndefinedSymbol(name))?;
                                let offset = obj.base_addr + rel.r_offset;
                                let value = sym.st_value() + lib.base_addr + Addr(rel.r_addend);
                                println!("Value: {:?}", value);

                                unsafe {
                                    let ptr: *mut u64 = offset.as_mut_ptr();
                                    println!("Applying relocs @ {:?}", ptr);
                                    *ptr = value.0;
                                }
                            },
                            parse_elf::RelType::Copy => {
                                let name = obj.sym_name(rel.r_sym as usize)?;
                                let (lib, sym) =
                                    self.lookup_symbol(&name, Some(obj))?.ok_or_else(|| {
                                        RelocationError::UndefinedSymbol(name.clone())
                                    })?;
                                println!(
                                    "Found {:?} at {:?} (size {:?}) in {:?}",
                                    name, sym.st_value(), sym.st_size(), lib.path
                                );
                                unsafe {
                                    let src = (sym.st_value() + lib.base_addr).as_ptr();
                                    let dst = (rel.r_offset + obj.base_addr).as_mut_ptr();
                                    std::ptr::copy_nonoverlapping::<u8>(src, dst, sym.st_size() as usize);
                                }
                                println!("Copy: stub!");
                            },
                            parse_elf::RelType::Relative => {
                                let name = obj.sym_name(rel.r_sym as usize)?;
                                println!("Should look up {:?}", name);
                                let (lib, sym) = self
                                    .lookup_symbol(&name, None)?
                                    .ok_or(RelocationError::UndefinedSymbol(name))?;
                                let offset = obj.base_addr + rel.r_offset;
                                let value = lib.base_addr + Addr(rel.r_addend);
                                println!("Value: {:?}", value);

                                unsafe {
                                    let ptr: *mut u64 = offset.as_mut_ptr();
                                    println!("Applying relocs @ {:?}", ptr);
                                    *ptr = value.0;
                                }
                            },
                            parse_elf::RelType::GlobDat => {
                                let name = obj.sym_name(rel.r_sym as usize)?;
                                println!("Should look up {:?}", name);
                                let (lib, sym) = self
                                    .lookup_symbol(&name, None)?
                                    .ok_or(RelocationError::UndefinedSymbol(name))?;
                                let offset = obj.base_addr + rel.r_offset;
                                let value = sym.st_value() + lib.base_addr;
                                println!("Value: {:?}", value);

                                unsafe {
                                    let ptr: *mut u64 = offset.as_mut_ptr();
                                    println!("Applying relocs @ {:?}", ptr);
                                    *ptr = value.0;
                                }
                            },
                            _ => return Err(RelocationError::UnimplementedRelocation(rel.r_type)),
                        }
                    }
                }
                Err(err) => println!("Don't have to apply rela {:?}", err),
            }
        }

        Ok(())
    }
}

fn dump_maps(msg: &str) {
    use std::{fs, process};

    println!("========= MEMORY MAPS: {}", msg);
    fs::read_to_string(format!("/proc/{pid}/maps", pid = process::id()))
        .unwrap()
        .lines()
        .filter(|line| line.contains("hello_dl") || line.contains("libmsg.so"))
        .for_each(|line| println!("{}", line));
    println!("========================");
}

/// Computes the minimal range that contains the two ranges a and b
fn convex_hull(a: Range<Addr>, b: Range<Addr>) -> Range<Addr> {
    Range {
        start: std::cmp::min(a.start, b.start),
        end: std::cmp::max(a.end, b.end),
    }
}

// Returns the load segments of an Elf file
fn load_segments(elf: &parse_elf::Elf64) -> Vec<&parse_elf::ProgramHeader>{
    elf.ph_table.iter().filter(|ph| ph.p_type() == parse_elf::SegmentType::PtLoad)
        .collect()
}

pub enum GetResult {
    Cached(usize),
    Fresh(usize),
}

#[derive(CustomDebug)]
pub struct Object {
    /// Path for where the Elf object was loaded from
    pub path: PathBuf,
    /// Base address for the Elf in memory
    pub base_addr: Addr,
    #[debug(skip)]
    pub elf: parse_elf::Elf64,
    pub segments: Vec<segment::Segment>,
    // Defines the memory range allocated for this Object
    pub mem_range: Range<Addr>,
    #[debug(skip)]
    pub symbol_table: Vec<parse_elf::SymbolEntry>
}

impl Object {
    pub fn sym_name(&self, index: usize) -> Result<String, RelocationError> {
        self.elf.get_string(Addr::from(self.symbol_table[index].st_name() as u64))
            .map_err(|_| RelocationError::UnknownSymbolNumber(index))
    }
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("Parsing the elf returned an error: {0}")]
    ElfError(#[from] parse_elf::ElfError),
    #[error("Input error: {0}")]
    InputError(PathBuf, std::io::Error),
    #[error("Path error: {0}")]
    PathError(#[from] PathError),
    #[error("Failed to convert integer: {0}")]
    IntConversionFailed(#[from] std::num::TryFromIntError),
    #[error("Object has no PtLoad segments")]
    NoLoadSegment,
    #[error("Mapping memory error: {0}")]
    MapError(#[from] mmap::MapError),
    #[error("Error reading symbol table: {0}")]
    SymbolError(#[from] SymbolError),
}

#[derive(Debug, Error)]
pub enum PathError {
    #[error("Parent for the requested path was not found: {0}")]
    ParentNotFound(PathBuf),
    #[error("Conversion of path to str failes: {0}")]
    FailedToStr(PathBuf),
    #[error("Path not found: {0}")]
    NotFound(PathBuf),
}

#[derive(Debug, Error)]
pub enum RelocationError {
    #[error("Unknown symbol number: {0}")]
    UnknownSymbolNumber(usize),
    #[error("Unimplemented Relocation: {0:?}")]
    UnimplementedRelocation(parse_elf::RelType),
    #[error("Undefined symbol: {0}")]
    UndefinedSymbol(String),
}