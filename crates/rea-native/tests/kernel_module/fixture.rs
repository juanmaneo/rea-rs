//! Synthetic kernel-module builders ported from
//! `upstream:src/native/elf/KernelModule.fixture.ts`.
//!
//! Names and text bodies are byte strings; upstream encodes them as Latin-1,
//! which matches for the ASCII text the tests use.

use rea_domain::native::kernel_module::{KernelModuleCodec, MODULE_SIGNATURE_MAGIC};

/// ELF class of a fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bits {
    Elf32,
    Elf64,
}

/// A section body or signature trailer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Part {
    /// The synthetic default.
    #[default]
    Default,
    /// Not declared or appended.
    Omitted,
    /// Exactly these bytes.
    Bytes(Vec<u8>),
}

/// `KernelModuleFixtureOptions`.
#[derive(Debug, Clone)]
pub struct KernelModuleOptions {
    pub bits: Bits,
    pub little: bool,
    pub object_type: u16,
    /// `None` uses 62 (x86-64) for ELF64 and 20 (PowerPC) for ELF32.
    pub machine: Option<u16>,
    pub modinfo: Part,
    pub versions: Part,
    pub this_module: Part,
    pub ksymtab: Part,
    pub init_text: Part,
    pub exit_text: Part,
    /// The default appends a consistent PKCS#7 trailer.
    pub signature: Part,
    /// Declare a second `.modinfo` section with the same bytes.
    pub repeat_modinfo: bool,
    /// Extra empty file-backed sections that share one name-table string.
    pub shared_name_sections: Option<(Vec<u8>, usize)>,
}

impl Default for KernelModuleOptions {
    fn default() -> Self {
        Self {
            bits: Bits::Elf64,
            little: true,
            object_type: 1,
            machine: None,
            modinfo: Part::Default,
            versions: Part::Default,
            this_module: Part::Default,
            ksymtab: Part::Default,
            init_text: Part::Default,
            exit_text: Part::Default,
            signature: Part::Default,
            repeat_modinfo: false,
            shared_name_sections: None,
        }
    }
}

/// The default PKCS#7 payload.
pub const DEFAULT_PKCS7: &[u8] = b"fake-pkcs7-bytes";

fn put16(bytes: &mut [u8], at: usize, value: u16, little: bool) {
    let encoded = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    bytes[at..at + 2].copy_from_slice(&encoded);
}

fn put32(bytes: &mut [u8], at: usize, value: u32, little: bool) {
    let encoded = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    bytes[at..at + 4].copy_from_slice(&encoded);
}

fn put_word(bytes: &mut [u8], at: usize, value: usize, bits: Bits, little: bool) {
    match bits {
        Bits::Elf64 => {
            let value = value as u64;
            let encoded = if little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            };
            bytes[at..at + 8].copy_from_slice(&encoded);
        }
        Bits::Elf32 => put32(bytes, at, u32::try_from(value).unwrap(), little),
    }
}

/// One `__versions` record: `unsigned long` CRC plus a fixed NUL-padded name.
pub fn modversion_entry(crc: u64, name: &str, bits: Bits, little: bool) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    let name = name.as_bytes();
    let start = match bits {
        Bits::Elf64 => {
            assert!(
                name.len() < 56,
                "ELF64 modversion name must fit in 56 bytes"
            );
            put_word(&mut bytes, 0, usize::try_from(crc).unwrap(), bits, little);
            8
        }
        Bits::Elf32 => {
            assert!(
                name.len() < 60,
                "ELF32 modversion name must fit in 60 bytes"
            );
            put32(&mut bytes, 0, u32::try_from(crc).unwrap(), little);
            4
        }
    };
    bytes[start..start + name.len()].copy_from_slice(name);
    bytes
}

/// Appended module signature trailer. `sig_len` defaults to the PKCS#7
/// length; a larger value builds an inconsistent trailer.
pub fn module_signature_trailer(pkcs7: &[u8], sig_len: Option<u32>) -> Vec<u8> {
    let mut info = [0_u8; 12];
    info[2] = 2;
    let sig_len = sig_len.unwrap_or_else(|| u32::try_from(pkcs7.len()).unwrap());
    info[8..12].copy_from_slice(&sig_len.to_be_bytes());
    [pkcs7, &info, MODULE_SIGNATURE_MAGIC].concat()
}

fn default_modinfo() -> Vec<u8> {
    b"license=GPL\0vermagic=5.15.0 SMP mod_unload\0alias=pci:v1\0alias=pci:v2\0name=demo\0depends=\0"
        .to_vec()
}

fn default_versions(bits: Bits, little: bool) -> Vec<u8> {
    [
        modversion_entry(0x1234_5678, "printk", bits, little),
        modversion_entry(0x90ab_cdef, "module_layout", bits, little),
    ]
    .concat()
}

fn chosen(part: &Part, fallback: impl FnOnce() -> Vec<u8>) -> Option<Vec<u8>> {
    match part {
        Part::Default => Some(fallback()),
        Part::Omitted => None,
        Part::Bytes(bytes) => Some(bytes.clone()),
    }
}

/// Synthetic `ET_REL` image with kernel-module sections and an optional
/// trailer.
pub fn kernel_module_fixture(options: &KernelModuleOptions) -> Vec<u8> {
    let KernelModuleOptions { bits, little, .. } = *options;
    let mut bodies: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut add = |name: &[u8], body: Option<Vec<u8>>| {
        if let Some(body) = body {
            bodies.push((name.to_vec(), body));
        }
    };
    let modinfo = chosen(&options.modinfo, default_modinfo);
    add(b".modinfo", modinfo.clone());
    if options.repeat_modinfo {
        add(b".modinfo", modinfo);
    }
    add(
        b"__versions",
        chosen(&options.versions, || default_versions(bits, little)),
    );
    add(
        b".gnu.linkonce.this_module",
        chosen(&options.this_module, || vec![0x11; 8]),
    );
    add(b"__ksymtab", chosen(&options.ksymtab, || vec![0x22; 8]));
    add(
        b".init.text",
        chosen(&options.init_text, || vec![0x90, 0x90, 0x90, 0x90]),
    );
    add(b".exit.text", chosen(&options.exit_text, || vec![0xc3]));
    if let Some((name, count)) = &options.shared_name_sections {
        for _ in 0..*count {
            add(name, Some(Vec::new()));
        }
    }

    let mut labels: Vec<&[u8]> = Vec::new();
    for label in bodies
        .iter()
        .map(|(name, _)| name.as_slice())
        .chain([b".shstrtab".as_slice()])
    {
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    let mut names = vec![0_u8];
    let mut name_offsets = Vec::with_capacity(labels.len());
    for label in &labels {
        name_offsets.push((*label, names.len()));
        names.extend_from_slice(label);
        names.push(0);
    }
    let name_offset = |name: &[u8]| {
        name_offsets
            .iter()
            .find(|(label, _)| *label == name)
            .map_or(0, |(_, offset)| *offset)
    };

    let wide = bits == Bits::Elf64;
    let header_size = if wide { 64 } else { 52 };
    let shentsize = if wide { 64 } else { 40 };
    let shnum = bodies.len() + 2;
    let shoff = header_size;
    let mut cursor = shoff + shnum * shentsize;
    let mut placed = Vec::with_capacity(bodies.len());
    for (_, body) in &bodies {
        placed.push(cursor);
        cursor += body.len();
    }
    let names_offset = cursor;
    cursor += names.len();
    let signature = match &options.signature {
        Part::Default => module_signature_trailer(DEFAULT_PKCS7, None),
        Part::Omitted => Vec::new(),
        Part::Bytes(bytes) => bytes.clone(),
    };

    let mut bytes = vec![0_u8; cursor + signature.len()];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = if wide { 2 } else { 1 };
    bytes[5] = if little { 1 } else { 2 };
    bytes[6] = 1;
    put16(&mut bytes, 16, options.object_type, little);
    let machine = options.machine.unwrap_or(if wide { 62 } else { 20 });
    put16(&mut bytes, 18, machine, little);
    put32(&mut bytes, 20, 1, little);
    let at = |wide_offset: usize, narrow_offset: usize| {
        if wide { wide_offset } else { narrow_offset }
    };
    put16(
        &mut bytes,
        at(52, 40),
        u16::try_from(header_size).unwrap(),
        little,
    );
    put16(&mut bytes, at(54, 42), if wide { 56 } else { 32 }, little);
    put_word(&mut bytes, at(40, 32), shoff, bits, little);
    put16(
        &mut bytes,
        at(58, 46),
        u16::try_from(shentsize).unwrap(),
        little,
    );
    let shnum16 = u16::try_from(shnum).unwrap();
    put16(&mut bytes, at(60, 48), shnum16, little);
    put16(&mut bytes, at(62, 50), shnum16 - 1, little);

    let write_section =
        |bytes: &mut [u8], index: usize, name: &[u8], kind: u32, offset: usize, size: usize| {
            let header = shoff + index * shentsize;
            let name = u32::try_from(name_offset(name)).unwrap();
            put32(bytes, header, name, little);
            put32(bytes, header + 4, kind, little);
            put_word(bytes, header + at(24, 16), offset, bits, little);
            put_word(bytes, header + at(32, 20), size, bits, little);
            put_word(bytes, header + at(48, 32), 1, bits, little);
        };
    for (index, ((name, body), offset)) in bodies.iter().zip(&placed).enumerate() {
        write_section(&mut bytes, index + 1, name, 1, *offset, body.len());
        bytes[*offset..*offset + body.len()].copy_from_slice(body);
    }
    write_section(
        &mut bytes,
        shnum - 1,
        b".shstrtab",
        3,
        names_offset,
        names.len(),
    );
    bytes[names_offset..names_offset + names.len()].copy_from_slice(&names);
    bytes[cursor..].copy_from_slice(&signature);
    bytes
}

/// Whole-file compression magics this operation recognizes and does not
/// decode.
pub fn compressed_kernel_module_container(codec: KernelModuleCodec) -> Vec<u8> {
    match codec {
        KernelModuleCodec::Gzip => vec![0x1f, 0x8b, 0x08, 0x00],
        KernelModuleCodec::Xz => vec![0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00],
        KernelModuleCodec::Zstd => vec![0x28, 0xb5, 0x2f, 0xfd, 0x00],
    }
}
