//! What has to come out of the game library rather than out of its data tables.
//!
//! - The **type registry**: the client registers every data table under a type
//!   number and a name. The names ship XOR-encrypted, so the map is recovered by
//!   a bounded pattern scan around the registry's binder calls — the approach the
//!   research used, re-implemented here so the tool does not
//!   need a disassembly dump to be present.
//! - The two **command** tables describe the wire protocol, not the data, so no
//!   amount of CSV reading produces them. They ship in [`SHIPPED`], with their
//!   provenance recorded, and [`shipped`] copies them into an output tree.
//!
//! Everything here fails loudly rather than returning a plausible-looking map:
//! the scan has to find the binder, decrypt table names, and agree with itself on
//! the shape of what it found.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};

use crate::apk::{Archive, sha256_hex};

/// A native game library found in the APK.
pub struct Library {
    /// Zip entry, e.g. `lib/arm64-v8a/libg.so`.
    pub entry: String,
    /// ABI directory, e.g. `arm64-v8a`.
    pub abi: String,
    pub sha256: String,
}

/// Every `lib/*/libg.so` in the APK, with its hash.
pub fn libraries(apk: &mut Archive) -> Result<Vec<Library>> {
    let mut libraries = Vec::new();
    for entry in apk.under("lib/") {
        if !entry.ends_with("/libg.so") {
            continue;
        }
        let abi = entry
            .trim_start_matches("lib/")
            .rsplit_once('/')
            .map(|(abi, _)| abi.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let sha256 = sha256_hex(&apk.read(&entry)?);
        libraries.push(Library { entry, abi, sha256 });
    }
    Ok(libraries)
}

/// Build-1598 x86 addresses the scan starts from. Each result is checked by
/// shape before use, and a build that does not match aborts the scan instead of
/// producing a map that only looks plausible.
const PIC_BASE: u64 = 0xB4_FB48;
const LITERAL_TABLE_OFFSET: usize = 0xBC_5E31;
const LITERAL_TABLE_LEN: usize = 128;
/// `binder(object, &name, type, 0)`: registers one data table.
const BINDER: u64 = 0x6C_204A;
/// `static_init(&slot, literal)`: stores a name's address in a slot.
const STRING_SLOT: u64 = 0x47_DB00;
const CALL_WINDOW: usize = 40;
const LITERAL_WINDOW: usize = 12;
const PUSH_WINDOW: usize = 6;
const MAX_LITERAL: usize = 120;
const MIN_TABLES: usize = 100;

pub struct TypeMap {
    /// Data-type number → table file name without its extension.
    pub tables: BTreeMap<u32, String>,
    /// How the map was obtained, for the report.
    pub evidence: String,
}

impl TypeMap {
    /// Read a map supplied as a JSON object of `"type": "table"` pairs.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading type map {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("parsing type map {}", path.display()))?;
        let object = value
            .as_object()
            .with_context(|| format!("type map {} must be a JSON object", path.display()))?;
        let mut tables = BTreeMap::new();
        for (kind, name) in object {
            let kind: u32 = kind.parse().with_context(|| {
                format!("type map {} has a non-numeric key {kind}", path.display())
            })?;
            let name = name
                .as_str()
                .with_context(|| format!("type map {} entry {kind} is not a string", path.display()))?;
            let name = name.trim();
            let name = name.strip_prefix("data/").unwrap_or(name);
            let name = name.strip_suffix(".csv").unwrap_or(name);
            tables.insert(kind, name.to_string());
        }
        ensure!(
            tables.len() >= MIN_TABLES,
            "type map {} carries only {} tables",
            path.display(),
            tables.len()
        );
        Ok(Self {
            tables,
            evidence: format!("read from {}", path.display()),
        })
    }

    /// Run the binder scan over an x86 `libg.so`.
    pub fn scan(libg: &[u8]) -> Result<Self> {
        let (tables, evidence) = Scanner::new(libg)?.scan()?;
        Ok(Self { tables, evidence })
    }
}

/// One instruction, reduced to the operands the scan reads.
#[derive(Clone, Copy, PartialEq)]
enum Step {
    /// `lea reg,[ebx+disp]` — a PIC-relative address.
    Lea(Register, u64),
    /// `mov reg,imm`.
    Mov(Register, u64),
    PushImm(u64),
    PushReg(Register),
    Call(u64),
    Other,
}

struct Scanner<'a> {
    data: &'a [u8],
    elf: Elf<'a>,
    /// The XOR key table the shipped names are encrypted with.
    table: Vec<u8>,
}

impl<'a> Scanner<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        let elf = Elf::new(data)?;
        ensure!(
            elf.bitness == 32,
            "the binder scan reads x86 libraries; supply a type map instead for other ABIs"
        );
        let table = data
            .get(LITERAL_TABLE_OFFSET..LITERAL_TABLE_OFFSET + LITERAL_TABLE_LEN)
            .context("the literal key table is not where build 1598 puts it")?
            .to_vec();
        Ok(Self { data, elf, table })
    }

    /// Decrypt the name at `va`, or `None` when it decrypts to nothing.
    fn literal(&self, va: u64) -> Option<String> {
        let offset = self.elf.file_offset(va)?;
        let mut out = String::new();
        for index in 0..MAX_LITERAL {
            let byte =
                *self.data.get(offset.checked_add(index)?)? ^ self.table[index % LITERAL_TABLE_LEN];
            if byte == 0 || !(byte.is_ascii_graphic() || byte == b' ') {
                break;
            }
            out.push(byte as char);
        }
        (out.len() >= 4).then_some(out)
    }

    fn scan(&self) -> Result<(BTreeMap<u32, String>, String)> {
        let (text_offset, text_va, text_size) = self.elf.executable()?;
        let text_end = text_offset + text_size;

        let mut decoder = Decoder::with_ip(32, self.data, text_va, DecoderOptions::NONE);
        decoder
            .set_position(text_offset)
            .context("positioning the decoder at the text segment")?;

        let mut window: VecDeque<Step> = VecDeque::with_capacity(CALL_WINDOW + 1);
        let mut slots: HashMap<u64, String> = HashMap::new();
        let mut registry: BTreeMap<u32, u64> = BTreeMap::new();
        let mut binder_calls = 0usize;
        let mut unresolved = 0usize;

        while decoder.can_decode() && decoder.position() < text_end {
            let instruction = decoder.decode();
            let step = step_of(&instruction);
            if let Step::Call(target) = step {
                if target == STRING_SLOT {
                    if let Some((slot, name)) = self.string_slot(&window) {
                        slots.insert(slot, name);
                    }
                } else if target == BINDER {
                    binder_calls += 1;
                    match binder_arguments(&window) {
                        Some((kind, slot)) => {
                            registry.insert(kind, slot);
                        }
                        None => unresolved += 1,
                    }
                }
            }
            window.push_back(step);
            if window.len() > CALL_WINDOW {
                window.pop_front();
            }
        }

        ensure!(
            binder_calls >= MIN_TABLES,
            "found only {binder_calls} registry binder calls in this library; refusing to guess at this build"
        );

        let mut tables = BTreeMap::new();
        for (kind, slot) in &registry {
            let Some(name) = slots.get(slot) else { continue };
            let Some(stem) = name
                .strip_prefix("data/")
                .and_then(|name| name.strip_suffix(".csv"))
            else {
                continue;
            };
            tables.insert(*kind, stem.to_string());
        }
        // A registry holds data tables; if it does not decrypt to them, the scan
        // is reading the wrong slots (or the wrong build).
        ensure!(
            tables.len() >= MIN_TABLES,
            "the binder scan recovered only {} table names out of {} registered ({unresolved} unresolved binder calls); \
             refusing to guess at this build",
            tables.len(),
            registry.len()
        );
        ensure!(
            tables.len() * 2 > registry.len(),
            "more than half of the {} registered names are not data tables; \
             the literal table does not match this build",
            registry.len()
        );

        let evidence = format!(
            "binder scan of the x86 libg.so: {binder_calls} binder calls, {unresolved} unresolved, {} tables",
            tables.len()
        );
        Ok((tables, evidence))
    }

    /// The name slot and literal of one `static_init(&slot, literal)` call.
    fn string_slot(&self, window: &VecDeque<Step>) -> Option<(u64, String)> {
        let start = window.len().saturating_sub(LITERAL_WINDOW);
        let mut registers: HashMap<Register, u64> = HashMap::new();
        for step in window.iter().skip(start) {
            if let Step::Lea(register, target) = step {
                registers.insert(*register, *target);
            }
        }
        let pushes: Vec<&Step> = window
            .iter()
            .skip(window.len().saturating_sub(PUSH_WINDOW))
            .filter(|step| matches!(step, Step::PushImm(_) | Step::PushReg(_)))
            .collect();
        if pushes.len() < 2 {
            return None;
        }
        let (Step::PushReg(slot), Step::PushReg(text)) =
            (pushes[pushes.len() - 1], pushes[pushes.len() - 2])
        else {
            return None;
        };
        let slot = *registers.get(slot)?;
        let text = *registers.get(text)?;
        Some((slot, self.literal(text)?))
    }
}

/// The type number and name slot of one `binder(object, &name, type, 0)` call.
fn binder_arguments(window: &VecDeque<Step>) -> Option<(u32, u64)> {
    #[derive(Clone, Copy)]
    enum Item {
        Global(u64),
        Immediate(u64),
        Register,
    }
    let start = window.len().saturating_sub(CALL_WINDOW);
    let mut state: HashMap<Register, Item> = HashMap::new();
    let mut pushes: Vec<Item> = Vec::new();
    for step in window.iter().skip(start) {
        match step {
            Step::Lea(register, target) => {
                state.insert(*register, Item::Global(*target));
            }
            Step::Mov(register, value) => {
                state.insert(*register, Item::Immediate(*value));
            }
            Step::PushImm(value) => pushes.push(Item::Immediate(*value)),
            Step::PushReg(register) => {
                pushes.push(*state.get(register).unwrap_or(&Item::Register))
            }
            _ => {}
        }
    }
    if pushes.len() < 3 {
        return None;
    }
    match (pushes[pushes.len() - 3], pushes[pushes.len() - 2]) {
        (Item::Immediate(kind), Item::Global(slot)) => {
            u32::try_from(kind).ok().map(|kind| (kind, slot))
        }
        _ => None,
    }
}

fn step_of(instruction: &iced_x86::Instruction) -> Step {
    match instruction.mnemonic() {
        Mnemonic::Lea
            if instruction.op_count() == 2
                && instruction.op_kind(0) == OpKind::Register
                && instruction.op_kind(1) == OpKind::Memory
                && instruction.memory_base() == Register::EBX
                && instruction.memory_index() == Register::None
                && instruction.memory_displacement64() != 0 =>
        {
            Step::Lea(
                instruction.op_register(0),
                PIC_BASE.wrapping_add(instruction.memory_displacement64()),
            )
        }
        Mnemonic::Mov
            if instruction.op_count() == 2
                && instruction.op_kind(0) == OpKind::Register
                && instruction.op_kind(1) == OpKind::Immediate32 =>
        {
            Step::Mov(instruction.op_register(0), instruction.immediate(1))
        }
        Mnemonic::Push if instruction.op_count() == 1 => match instruction.op_kind(0) {
            OpKind::Immediate32 | OpKind::Immediate8to32 | OpKind::Immediate8 => {
                Step::PushImm(instruction.immediate(0))
            }
            OpKind::Register => Step::PushReg(instruction.op_register(0)),
            _ => Step::Other,
        },
        Mnemonic::Call if instruction.flow_control() == FlowControl::Call => {
            match instruction.op_kind(0) {
                OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    Step::Call(instruction.near_branch_target())
                }
                _ => Step::Other,
            }
        }
        _ => Step::Other,
    }
}

struct Load {
    offset: usize,
    vaddr: u64,
    filesz: usize,
    flags: u32,
}

/// Just enough ELF to find the text segment and map addresses to file offsets.
struct Elf<'a> {
    bitness: u32,
    loads: Vec<Load>,
    marker: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> Elf<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        ensure!(
            data.len() > 64 && data.starts_with(b"\x7fELF"),
            "not an ELF library"
        );
        let (bitness, phoff, phentsize, phnum) = match data[4] {
            1 => (
                32,
                u32_at(data, 28)? as usize,
                u16_at(data, 42)? as usize,
                u16_at(data, 44)? as usize,
            ),
            2 => (
                64,
                u64_at(data, 32)? as usize,
                u16_at(data, 54)? as usize,
                u16_at(data, 56)? as usize,
            ),
            class => bail!("unknown ELF class {class}"),
        };
        let mut loads = Vec::new();
        for index in 0..phnum {
            let base = phoff
                .checked_add(index.checked_mul(phentsize).context("program header overflow")?)
                .context("program header offset overflow")?;
            if u32_at(data, base)? != 1 {
                continue;
            }
            let (offset, vaddr, filesz, flags) = if bitness == 32 {
                (
                    u32_at(data, base + 4)? as usize,
                    u32_at(data, base + 8)? as u64,
                    u32_at(data, base + 16)? as usize,
                    u32_at(data, base + 24)?,
                )
            } else {
                (
                    u64_at(data, base + 8)? as usize,
                    u64_at(data, base + 16)?,
                    u64_at(data, base + 32)? as usize,
                    u32_at(data, base + 4)?,
                )
            };
            loads.push(Load {
                offset,
                vaddr,
                filesz,
                flags,
            });
        }
        ensure!(!loads.is_empty(), "ELF library has no loadable segments");
        Ok(Self {
            bitness,
            loads,
            marker: std::marker::PhantomData,
        })
    }

    fn executable(&self) -> Result<(usize, u64, usize)> {
        self.loads
            .iter()
            .find(|load| load.flags & 1 != 0)
            .map(|load| (load.offset, load.vaddr, load.filesz))
            .context("ELF library has no executable segment")
    }

    fn file_offset(&self, va: u64) -> Option<usize> {
        self.loads
            .iter()
            .find(|load| va >= load.vaddr && va - load.vaddr < load.filesz as u64)
            .map(|load| load.offset + (va - load.vaddr) as usize)
    }
}

/// A resource file that ships with this tool because the APK cannot produce it.
pub struct Shipped {
    /// File name inside the shipped directory.
    pub name: &'static str,
    /// Output path relative to the resource directory.
    pub path: &'static str,
    /// What it carries.
    pub carries: &'static str,
    /// Where it came from.
    pub origin: &'static str,
}

/// The two command tables no scan of the data can produce.
pub const SHIPPED: &[Shipped] = &[
    Shipped {
        name: "command-schema.json",
        path: "command-schema.json",
        carries: "the payload fields of every command type",
        origin: "decoded from the build-1598 x86 command factories",
    },
    Shipped {
        name: "command-evidence.json",
        path: "command-evidence.json",
        carries: "the analytics strings each command executor references",
        origin: "decoded from the build-1598 x86 command executors",
    },
];

/// Read the shipped files out of `directory`, with their hashes.
pub fn shipped(directory: &Path) -> Result<Vec<(&'static Shipped, Vec<u8>, String)>> {
    let mut files = Vec::new();
    for entry in SHIPPED {
        let path: PathBuf = directory.join(entry.name);
        let bytes = std::fs::read(&path).with_context(|| {
            format!(
                "reading shipped {} from {} (point --shipped at the directory holding it)",
                entry.name,
                path.display()
            )
        })?;
        // The server indexes both by command type; a broken file would surface
        // only as a panic at login.
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing shipped {}", path.display()))?;
        ensure!(
            value.as_object().is_some_and(|object| !object.is_empty()),
            "shipped {} is not a non-empty JSON object",
            path.display()
        );
        let hash = sha256_hex(&bytes);
        files.push((entry, bytes, hash));
    }
    Ok(files)
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        data.get(offset..offset + 2)
            .context("read past the end of the library")?
            .try_into()?,
    ))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(offset..offset + 4)
            .context("read past the end of the library")?
            .try_into()?,
    ))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(offset..offset + 8)
            .context("read past the end of the library")?
            .try_into()?,
    ))
}
