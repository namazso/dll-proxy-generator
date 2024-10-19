use clap::Parser;
use goblin::pe::characteristic::{
    IMAGE_FILE_DLL, IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_LARGE_ADDRESS_AWARE,
};
use goblin::pe::data_directories::DataDirectory;
use goblin::pe::dll_characteristic::{
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
};
use goblin::pe::export::{ExportDirectoryTable, SIZEOF_EXPORT_DIRECTORY_TABLE};
use goblin::pe::header::{CoffHeader, DOS_MAGIC, PE_MAGIC};
use goblin::pe::import::ImportDirectoryEntry;
use goblin::pe::optional_header::{
    StandardFields64, WindowsFields64, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};
use goblin::pe::section_table::IMAGE_SCN_MEM_READ;
use goblin::pe::subsystem::IMAGE_SUBSYSTEM_WINDOWS_GUI;
use goblin::Object;
use scroll::ctx::SizeWith;
use scroll::{Endian, Pwrite};
use scroll_derive::SizeWith;
use std::fs;
use std::path::PathBuf;

/// Generate a proxy dll for arbitrary dll
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Extra dll to import
    #[arg(short = 'd', long)]
    import_dll: String,

    /// Import name or ordinal
    #[arg(short = 'i', long)]
    import: String,

    /// Target of proxy, defaults to path of same file in System32
    #[arg(short, long)]
    proxy_target: Option<String>,

    /// Output file
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// COFF Machine magic. Defaults to x64's.
    #[arg(short, long, default_value = "34404")]
    machine: u16,

    /// Path to dll to proxy
    dll: PathBuf,
}

#[repr(C)]
#[derive(Debug, Pwrite, SizeWith, Default)]
pub struct SmallPE {
    pub dos_magic: u16,
    pub pad1: [u16; 29],
    pub e_lfanew: u32,

    pub signature: u32,

    pub coff_header: CoffHeader,

    pub standard_fields: StandardFields64,
    pub windows_fields: WindowsFields64,

    pub data_directories: [DataDirectory; 16],

    pub sec_name: [u8; 8],
    pub sec_virtual_size: u32,
    pub sec_virtual_address: u32,
    pub sec_size_of_raw_data: u32,
    pub sec_pointer_to_raw_data: u32,
    pub sec_pointer_to_relocations: u32,
    pub sec_pointer_to_linenumbers: u32,
    pub sec_number_of_relocations: u16,
    pub sec_number_of_linenumbers: u16,
    pub sec_characteristics: u32,
}

fn main() {
    let args = Args::parse();

    let output = args
        .output
        .unwrap_or_else(|| PathBuf::from(args.dll.file_name().unwrap()));

    // Format of our IAT:
    // IMAGE_IMPORT_DESCRIPTOR  descriptor for `import_dll`
    // IMAGE_IMPORT_DESCRIPTOR  terminating null entry
    // u64  the import entry
    // u64  terminating entry
    // u64  the import entry (IAT)
    // u64  terminating entry (IAT)
    // u8+  dll name
    // __   pad to 2 byte
    // u16  hint (if import by name)
    // u8+  import name (if import by name)
    // __   pad to 16 byte

    let idata_rva = 0x1000u32;
    let mut idata = {
        let mut buf = Vec::<u8>::new();

        // dll entry
        let entry_offset = buf.len();
        buf.resize(
            buf.len() + ImportDirectoryEntry::size_with(&Endian::Little),
            0,
        );
        // null entry
        buf.resize(
            buf.len() + ImportDirectoryEntry::size_with(&Endian::Little),
            0,
        );
        // import lookup table entry
        let ilt_offset = buf.len();
        buf.resize(buf.len() + u64::size_with(&Endian::Little), 0);
        // import lookup table terminating entry
        buf.resize(buf.len() + u64::size_with(&Endian::Little), 0);
        // import address table entry
        let iat_offset = buf.len();
        buf.resize(buf.len() + u64::size_with(&Endian::Little), 0);
        // import address table terminating entry
        buf.resize(buf.len() + u64::size_with(&Endian::Little), 0);
        let dll_offset = buf.len();
        let mut dll_name = args.import_dll.as_bytes().to_vec();
        dll_name.push(0);
        buf.resize(buf.len() + dll_name.len(), 0);
        buf.pwrite(dll_name.as_slice(), dll_offset).unwrap();
        buf.resize((buf.len() + 1) & (!1usize), 0);
        let ilt_value = if args.import.starts_with("#") {
            args.import
                .trim_start_matches("#")
                .parse::<u16>()
                .expect("Cannot parse ordinal") as u64
                | (1u64 << 63)
        } else {
            let hint_offset = buf.len();
            let name_offset = hint_offset + u16::size_with(&Endian::Little);
            let mut import_bytes = args.import.as_bytes().to_vec();
            import_bytes.push(0);
            buf.resize(
                buf.len() + u16::size_with(&Endian::Little) + import_bytes.len(),
                0,
            );
            buf.pwrite(import_bytes.as_slice(), name_offset).unwrap();
            idata_rva as u64 + hint_offset as u64
        };
        buf.resize((buf.len() + 15) & (!15usize), 0);
        buf.pwrite(ilt_value, ilt_offset).unwrap();
        buf.pwrite(ilt_value, iat_offset).unwrap();
        let entry = ImportDirectoryEntry {
            import_lookup_table_rva: idata_rva + ilt_offset as u32,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name_rva: idata_rva + dll_offset as u32,
            import_address_table_rva: idata_rva + iat_offset as u32,
        };
        buf.pwrite(entry, entry_offset).unwrap();
        buf
    };
    let idata_len = idata.len();

    let edata_rva = idata_rva + idata_len as u32;
    let mut edata = {
        let mut buf = Vec::<u8>::new();

        let system32_target = "\\\\.\\GLOBALROOT\\SystemRoot\\System32\\".to_string()
            + args.dll.file_name().unwrap().to_str().unwrap();

        let proxy_target = args.proxy_target.as_ref().unwrap_or(&system32_target);

        let dll = &fs::read(args.dll).expect("Cannot read input dll");
        let object = Object::parse(dll).expect("Cannot parse input dll");

        let pe = if let Object::PE(pe) = object {
            pe
        } else {
            panic!("Cannot parse object PE");
        };

        let export_data = pe.export_data.expect("The dll has no exports!");
        let export_count = export_data.export_directory_table.address_table_entries;
        let names_count = export_data.export_directory_table.number_of_name_pointers;

        let directory_offset = buf.len();
        buf.resize(buf.len() + SIZEOF_EXPORT_DIRECTORY_TABLE, 0);
        let eat_offset = buf.len();
        buf.resize(
            buf.len() + u32::size_with(&Endian::Little) * export_count as usize,
            0,
        );
        let name_ptrs_offset = buf.len();
        buf.resize(
            buf.len() + u32::size_with(&Endian::Little) * names_count as usize,
            0,
        );
        let ordinals_offset = buf.len();
        buf.resize(
            buf.len() + u16::size_with(&Endian::Little) * export_count as usize,
            0,
        );

        for (idx, ordinal) in export_data.export_ordinal_table.iter().enumerate() {
            buf.pwrite(
                ordinal,
                ordinals_offset + idx * 2,
            )
            .unwrap();
        }

        let mut forward_names = vec![];
        for i in 0..export_count {
            let ordinal = export_data.export_directory_table.ordinal_base + i;
            forward_names.push(format!("#{ordinal}"));
        }

        let mut exports: Vec<&str> = pe.exports.iter().filter_map(|export| export.name).collect();
        exports.sort();

        // Sanity check that goblin parsed it all
        assert_eq!(exports.len(), export_data.export_ordinal_table.len());
        assert_eq!(exports.len(), export_data.export_name_pointer_table.len());

        for (idx, name) in exports.iter().enumerate() {
            forward_names[export_data.export_ordinal_table[idx] as usize] = name.to_string();
            let mut name_str = name.as_bytes().to_vec();
            name_str.push(0);
            let name_offs = buf.len();
            buf.resize(buf.len() + name_str.len(), 0);
            buf.pwrite(name_str.as_slice(), name_offs).unwrap();
            buf.pwrite(edata_rva + name_offs as u32, name_ptrs_offset + idx * 4).unwrap();
        }

        for i in 0..export_count as usize {
            let forward_name = &forward_names[i];
            let mut forward_str = format!("{proxy_target}.{forward_name}").as_bytes().to_vec();
            forward_str.push(0);
            let forward_offs = buf.len();
            buf.resize(buf.len() + forward_str.len(), 0);
            buf.pwrite(forward_str.as_slice(), forward_offs).unwrap();
            buf.pwrite(edata_rva + forward_offs as u32, eat_offset + i * 4).unwrap();
        }

        let mut dllname_offset = 0u32;
        if let Some(dllname) = export_data.name {
            dllname_offset = buf.len() as u32;
            let mut dllname_str = dllname.to_string().as_bytes().to_vec();
            dllname_str.push(0);
            buf.resize(buf.len() + dllname_str.len(), 0);
            buf.pwrite(dllname_str.as_slice(), dllname_offset as usize).unwrap();
        }

        buf.resize((buf.len() + 15) & (!15usize), 0);

        let directory = ExportDirectoryTable {
            export_flags: 0,
            time_date_stamp: 0,
            major_version: 0,
            minor_version: 0,
            name_rva: edata_rva + dllname_offset,
            ordinal_base: export_data.export_directory_table.ordinal_base,
            address_table_entries: export_count,
            number_of_name_pointers: names_count,
            export_address_table_rva: edata_rva + eat_offset as u32,
            name_pointer_rva: edata_rva + name_ptrs_offset as u32,
            ordinal_table_rva: edata_rva + ordinals_offset as u32,
        };

        buf.pwrite(directory, directory_offset).unwrap();

        buf
    };
    let edata_len = edata.len();

    const FILE_ALIGN: usize = 0x200;
    const VIRTUAL_ALIGN: usize = 0x1000;

    let mut rdata = vec![];
    rdata.append(&mut idata);
    rdata.append(&mut edata);
    rdata.resize((rdata.len() + FILE_ALIGN - 1) & !(FILE_ALIGN - 1), 0);

    let rdata_virtual_size = (rdata.len() + VIRTUAL_ALIGN - 1) & !(VIRTUAL_ALIGN - 1);

    let mut header = SmallPE::default();
    header.dos_magic = DOS_MAGIC;
    header.e_lfanew = 0x40;
    header.signature = PE_MAGIC;
    header.coff_header.machine = args.machine;
    header.coff_header.number_of_sections = 1;
    header.coff_header.size_of_optional_header = 0xf0;
    header.coff_header.characteristics =
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL;
    header.standard_fields.magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    header.windows_fields.image_base = 0x10000;
    header.windows_fields.section_alignment = 0x1000;
    header.windows_fields.file_alignment = FILE_ALIGN as u32;
    header.windows_fields.major_operating_system_version = 6;
    header.windows_fields.minor_operating_system_version = 0;
    header.windows_fields.major_subsystem_version = 5;
    header.windows_fields.size_of_image = 0x1000 + rdata_virtual_size as u32;
    header.windows_fields.size_of_headers = SmallPE::size_with(&Endian::Little) as u32;
    header.windows_fields.subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    header.windows_fields.dll_characteristics = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    header.windows_fields.size_of_stack_reserve = 0x100000;
    header.windows_fields.size_of_stack_commit = 0x1000;
    header.windows_fields.size_of_heap_reserve = 0x100000;
    header.windows_fields.size_of_heap_commit = 0x1000;
    header.windows_fields.number_of_rva_and_sizes = 16;
    header.data_directories[0].virtual_address = edata_rva;
    header.data_directories[0].size = edata_len as u32;
    header.data_directories[1].virtual_address = idata_rva;
    header.data_directories[1].size = idata_len as u32;
    header.sec_virtual_size = rdata_virtual_size as u32;
    header.sec_virtual_address = 0x1000;
    header.sec_size_of_raw_data = rdata.len() as u32;
    header.sec_pointer_to_raw_data = FILE_ALIGN as u32;
    header.sec_characteristics = IMAGE_SCN_MEM_READ;

    let mut header_bytes = [0u8; 0x200];
    header_bytes.pwrite(&header, 0).unwrap();

    let mut bytes = header_bytes.to_vec();
    bytes.append(&mut rdata);

    fs::write(&output, bytes).unwrap();
}
