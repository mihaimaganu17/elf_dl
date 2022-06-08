#[derive(custom_debug_derive::Debug)]
pub struct Segment {
    #[debug(skip)]
    pub mapping: mmap::MemoryMap,
    pub padding: parse_elf::Addr,
    pub flags: parse_elf::segment::SegmentFlags,
}