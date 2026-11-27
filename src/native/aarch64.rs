//! The registry scan for an arm64-v8a `libg.so`.
//!
//! It reads the same two kinds of call as the x86 scan — `binder(object,
//! &name, type, 0)` and `static_init(&slot, literal)` — but pins nothing to a
//! build. On arm64 every argument travels in a register, so each piece is found
//! by its shape and then checked:
//!
//! - the **binder** is the call target that most often receives `x1` = a global
//!   address, `w2` = a constant and `w3` = 0, and it has to win outright;
//! - the **initialiser** is the call target that most often receives `x0` = one
//!   of the binder's name slots and `x1` = a global (the encrypted literal);
//! - the **key**: every registered name starts with `data/`, which gives the
//!   key's first bytes. The full 128-byte key is the majority, position by
//!   position, over every place those bytes occur in the library, and the
//!   result has to occur there verbatim before any name is decrypted with it.
//!
//! The decoder knows only the handful of instructions that build those
//! arguments (`adrp`, `add`, `movz`/`movn`/`movk`, `orr` as `mov`, `bl`).
//! Every other instruction is assumed to overwrite the registers it names, so
//! an argument is only ever read back when its whole construction was seen.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result, ensure};

use super::{Elf, LITERAL_TABLE_LEN, MAX_LITERAL, MIN_TABLES};

/// What every registered name begins with.
const PREFIX: &[u8] = b"data/";

/// A register's known contents.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Value {
    /// An address built with `adrp` (and `add`).
    Address(u64),
    Immediate(u64),
}

/// One instruction, reduced to its effect on the tracked registers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Op {
    /// `rd = value`.
    Set(u8, Value),
    /// `rd = rn + imm` (`add` immediate).
    Add {
        rd: u8,
        rn: u8,
        imm: u64,
        wide: bool,
    },
    /// `movk`: replace 16 bits of a known immediate.
    Keep {
        rd: u8,
        shift: u32,
        imm: u64,
        wide: bool,
    },
    /// `mov rd, rm` (`orr` with the zero register).
    Copy { rd: u8, rm: u8, wide: bool },
    /// `bl target`.
    Call(u64),
    /// `blr`: a call whose target is not known.
    CallIndirect,
    /// `b`, `br`, `ret`: the next instruction is not reached from this one.
    Jump,
    /// Anything else: a mask of the registers it may write.
    Clobber(u32),
}

/// The zero register (or the stack pointer, which is never tracked).
const ZR: u8 = 31;

fn decode(insn: u32, pc: u64) -> Op {
    let rd = (insn & 31) as u8;
    let rn = ((insn >> 5) & 31) as u8;
    let wide = insn >> 31 == 1;
    let width = |value: u64| if wide { value } else { value & 0xffff_ffff };

    // adrp
    if insn & 0x9f00_0000 == 0x9000_0000 {
        let immlo = u64::from((insn >> 29) & 3);
        let immhi = u64::from((insn >> 5) & 0x7_ffff);
        let offset = sign_extend((immhi << 2) | immlo, 21) << 12;
        return Op::Set(rd, Value::Address((pc & !0xfff).wrapping_add(offset)));
    }
    // add (immediate)
    if insn & 0x7f80_0000 == 0x1100_0000 {
        let imm = u64::from((insn >> 10) & 0xfff) << (12 * ((insn >> 22) & 1));
        return Op::Add { rd, rn, imm, wide };
    }
    // movn / movz / movk
    if insn & 0x1f80_0000 == 0x1280_0000 {
        let shift = 16 * ((insn >> 21) & 3);
        let imm = u64::from((insn >> 5) & 0xffff);
        return match (insn >> 29) & 3 {
            0 => Op::Set(rd, Value::Immediate(width(!(imm << shift)))),
            2 => Op::Set(rd, Value::Immediate(width(imm << shift))),
            3 => Op::Keep {
                rd,
                shift,
                imm,
                wide,
            },
            _ => Op::Clobber(1 << rd),
        };
    }
    // orr (immediate) from the zero register: `mov rd, #bitmask`
    if insn & 0x7f80_0000 == 0x3200_0000 && rn == ZR {
        let n = (insn >> 22) & 1;
        let immr = (insn >> 16) & 0x3f;
        let imms = (insn >> 10) & 0x3f;
        return match bitmask(n, immr, imms, wide) {
            Some(value) => Op::Set(rd, Value::Immediate(value)),
            None => Op::Clobber(1 << rd),
        };
    }
    // orr (shifted register) with no shift from the zero register: `mov rd, rm`
    if insn & 0x7fe0_ffe0 == 0x2a00_03e0 {
        let rm = ((insn >> 16) & 31) as u8;
        return Op::Copy { rd, rm, wide };
    }
    // bl
    if insn & 0xfc00_0000 == 0x9400_0000 {
        let offset = sign_extend(u64::from(insn & 0x3ff_ffff), 26) << 2;
        return Op::Call(pc.wrapping_add(offset));
    }
    // b
    if insn & 0xfc00_0000 == 0x1400_0000 {
        return Op::Jump;
    }
    // blr / br / ret
    if insn & 0xffff_fc1f == 0xd63f_0000 {
        return Op::CallIndirect;
    }
    if insn & 0xfe00_0000 == 0xd600_0000 {
        return Op::Jump;
    }
    // Branches, exceptions and system instructions write no general register,
    // except `mrs` and the system instructions that read one back.
    if (insn >> 26) & 7 == 0b101 {
        return if insn & 0xffe0_0000 == 0xd520_0000 && (insn >> 21) & 1 == 1 {
            Op::Clobber(1 << rd)
        } else {
            Op::Clobber(0)
        };
    }
    if (insn >> 25) & 5 == 0b100 {
        return Op::Clobber(load_store_writes(insn));
    }
    Op::Clobber(1 << rd)
}

/// The registers a load or store may write: a load writes Rt (and Rt2), a
/// write-back writes the base, and a store writes neither. Encodings this does
/// not tell apart are treated as writing every register field they have.
fn load_store_writes(insn: u32) -> u32 {
    let rt = 1u32 << (insn & 31);
    let rn = 1u32 << ((insn >> 5) & 31);
    let rt2 = 1u32 << ((insn >> 10) & 31);
    let rs = 1u32 << ((insn >> 16) & 31);
    let load = |bit: bool| if bit { rt } else { 0 };
    match (insn >> 27) & 7 {
        // Pairs: L is bit 22; post- and pre-index (bit 23 set) write back.
        0b101 => {
            let mut mask = if (insn >> 22) & 1 == 1 { rt | rt2 } else { 0 };
            if (insn >> 23) & 1 == 1 {
                mask |= rn;
            }
            mask
        }
        // Single register: opc (bits 23–22) 0 is a store.
        0b111 => {
            let loads = load((insn >> 22) & 3 != 0);
            match ((insn >> 24) & 3, (insn >> 21) & 1, (insn >> 10) & 3) {
                // Unsigned offset.
                (1, _, _) => loads,
                // Post- and pre-index write back.
                (0, 0, 1 | 3) => loads | rn,
                // Unscaled and unprivileged.
                (0, 0, _) => loads,
                // Register offset and atomics: an atomic writes Rt even when
                // it stores.
                _ => rt | loads,
            }
        }
        // Literal loads.
        0b011 => rt,
        // Exclusives and acquire/release: a store-exclusive writes its status
        // register.
        _ => rt | rt2 | rs | rn,
    }
}

fn sign_extend(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

/// The architecture's `DecodeBitMasks` for a logical immediate.
fn bitmask(n: u32, immr: u32, imms: u32, wide: bool) -> Option<u64> {
    let combined = (n << 6) | (!imms & 0x3f);
    if combined == 0 || (!wide && n == 1) {
        return None;
    }
    let len = 31 - combined.leading_zeros();
    if len == 0 {
        return None;
    }
    let size = 1u32 << len;
    let levels = size - 1;
    let (s, r) = (imms & levels, immr & levels);
    if s == levels {
        return None;
    }
    let pattern = (1u64 << (s + 1)) - 1;
    let mask = if size == 64 {
        u64::MAX
    } else {
        (1u64 << size) - 1
    };
    let rotated = ((pattern >> r) | (pattern << ((size - r) % size))) & mask;
    let mut value = 0u64;
    let mut at = 0;
    while at < 64 {
        value |= rotated << at;
        at += size;
    }
    Some(if wide { value } else { value & 0xffff_ffff })
}

/// One `bl`, with the first four argument registers as far as they are known.
#[derive(Clone, Copy, Debug)]
struct Call {
    target: u64,
    args: [Option<Value>; 4],
}

/// Every `bl` in `code` (mapped at `va`) whose `x1` is a known address.
fn calls(code: &[u8], va: u64) -> Vec<Call> {
    let mut registers: [Option<Value>; 32] = [None; 32];
    let mut calls = Vec::new();
    for (index, word) in code.as_chunks::<4>().0.iter().enumerate() {
        let insn = u32::from_le_bytes(*word);
        let pc = va + 4 * index as u64;
        let set = |registers: &mut [Option<Value>; 32], rd: u8, value: Option<Value>| {
            if rd != ZR {
                registers[usize::from(rd)] = value;
            }
        };
        match decode(insn, pc) {
            Op::Set(rd, value) => set(&mut registers, rd, Some(value)),
            Op::Add { rd, rn, imm, wide } => {
                let value = match (rn, wide) {
                    (ZR, _) => None,
                    (_, true) => match registers[usize::from(rn)] {
                        Some(Value::Address(base)) => Some(Value::Address(base.wrapping_add(imm))),
                        Some(Value::Immediate(base)) => {
                            Some(Value::Immediate(base.wrapping_add(imm)))
                        }
                        None => None,
                    },
                    (_, false) => match registers[usize::from(rn)] {
                        Some(Value::Immediate(base)) => {
                            Some(Value::Immediate(base.wrapping_add(imm) & 0xffff_ffff))
                        }
                        _ => None,
                    },
                };
                set(&mut registers, rd, value);
            }
            Op::Keep {
                rd,
                shift,
                imm,
                wide,
            } => {
                let value = match (rd, registers[usize::from(rd)]) {
                    (ZR, _) => None,
                    (_, Some(Value::Immediate(old))) => {
                        let value = (old & !(0xffff << shift)) | (imm << shift);
                        Some(Value::Immediate(if wide {
                            value
                        } else {
                            value & 0xffff_ffff
                        }))
                    }
                    _ => None,
                };
                set(&mut registers, rd, value);
            }
            Op::Copy { rd, rm, wide } => {
                let value = match (rm, registers[usize::from(rm)], wide) {
                    (ZR, _, _) => Some(Value::Immediate(0)),
                    (_, value, true) => value,
                    (_, Some(Value::Immediate(value)), false) => {
                        Some(Value::Immediate(value & 0xffff_ffff))
                    }
                    _ => None,
                };
                set(&mut registers, rd, value);
            }
            Op::Call(target) => {
                if matches!(registers[1], Some(Value::Address(_))) {
                    calls.push(Call {
                        target,
                        args: [registers[0], registers[1], registers[2], registers[3]],
                    });
                }
                clobber_caller_saved(&mut registers);
            }
            Op::CallIndirect => clobber_caller_saved(&mut registers),
            Op::Jump => registers = [None; 32],
            Op::Clobber(mask) => {
                for (register, value) in registers.iter_mut().enumerate() {
                    if mask & (1 << register) != 0 {
                        *value = None;
                    }
                }
            }
        }
    }
    calls
}

/// A call may overwrite x0–x18 and the link register.
fn clobber_caller_saved(registers: &mut [Option<Value>; 32]) {
    for value in registers.iter_mut().take(19) {
        *value = None;
    }
    registers[30] = None;
}

/// `binder(object, &name, type, 0)`: the type number and name slot.
fn binder_arguments(call: &Call) -> Option<(u32, u64)> {
    match call.args {
        [
            _,
            Some(Value::Address(slot)),
            Some(Value::Immediate(kind)),
            Some(Value::Immediate(0)),
        ] => u32::try_from(kind).ok().map(|kind| (kind, slot)),
        _ => None,
    }
}

/// The target called most often by calls that `matches`, with its count and the
/// runner-up's.
fn most_called(calls: &[Call], matches: impl Fn(&Call) -> bool) -> Option<(u64, usize, usize)> {
    let mut counts: HashMap<u64, usize> = HashMap::new();
    for call in calls.iter().filter(|call| matches(call)) {
        *counts.entry(call.target).or_default() += 1;
    }
    let mut ranked: Vec<(u64, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let (target, count) = *ranked.first()?;
    Some((target, count, ranked.get(1).map_or(0, |entry| entry.1)))
}

/// Run the registry scan over an arm64 `libg.so`.
pub(super) fn scan(data: &[u8], elf: &Elf<'_>) -> Result<(BTreeMap<u32, String>, String)> {
    ensure!(elf.bitness == 64, "an arm64 libg.so has to be a 64-bit ELF");
    let (text_offset, text_va, text_size) = elf.executable()?;
    let code = data
        .get(text_offset..text_offset + text_size)
        .context("the executable segment runs past the end of the library")?;
    let calls = calls(code, text_va);

    // The binder.
    let (binder, binder_calls, runner_up) =
        most_called(&calls, |call| binder_arguments(call).is_some())
            .context("no call in this library looks like the registry binder")?;
    ensure!(
        binder_calls >= MIN_TABLES,
        "the likeliest registry binder (0x{binder:x}) has only {binder_calls} calls; refusing to guess at this build"
    );
    ensure!(
        binder_calls > 2 * runner_up,
        "two call targets look like the registry binder ({binder_calls} and {runner_up} calls); refusing to guess"
    );
    let mut registry: BTreeMap<u32, u64> = BTreeMap::new();
    let mut unresolved = 0usize;
    for call in calls.iter().filter(|call| call.target == binder) {
        match binder_arguments(call) {
            Some((kind, slot)) => {
                registry.insert(kind, slot);
            }
            None => unresolved += 1,
        }
    }

    // The initialiser that fills the binder's name slots.
    let is_slot = |call: &Call| match call.args {
        [Some(Value::Address(slot)), Some(Value::Address(_)), ..] => {
            registry.values().any(|known| *known == slot)
        }
        _ => false,
    };
    let (initialiser, initialised, _) = most_called(&calls, is_slot)
        .context("no call in this library stores the registry's name slots")?;
    ensure!(
        initialised >= MIN_TABLES,
        "the likeliest name-slot initialiser (0x{initialiser:x}) fills only {initialised} of the {} slots; \
         refusing to guess at this build",
        registry.len()
    );
    // The initialiser stores every encrypted string the client has, not only
    // the registry's, so only the binder's slots are kept.
    let mut literals: HashMap<u64, usize> = HashMap::new();
    for call in calls
        .iter()
        .filter(|call| call.target == initialiser && is_slot(call))
    {
        if let [
            Some(Value::Address(slot)),
            Some(Value::Address(literal)),
            ..,
        ] = call.args
            && let Some(offset) = elf.file_offset(literal)
        {
            literals.insert(slot, offset);
        }
    }

    let key = key(data, literals.values().copied())?;

    let mut tables = BTreeMap::new();
    for (kind, slot) in &registry {
        let Some(name) = literals
            .get(slot)
            .and_then(|offset| decrypt(data, *offset, &key))
        else {
            continue;
        };
        let Some(stem) = name
            .strip_prefix("data/")
            .and_then(|name| name.strip_suffix(".csv"))
        else {
            continue;
        };
        tables.insert(*kind, stem.to_string());
    }
    ensure!(
        tables.len() >= MIN_TABLES,
        "the binder scan recovered only {} table names out of {} registered ({unresolved} unresolved binder calls); \
         refusing to guess at this build",
        tables.len(),
        registry.len()
    );
    ensure!(
        tables.len() * 2 > registry.len(),
        "more than half of the {} registered names are not data tables; the key does not match this build",
        registry.len()
    );

    let evidence = format!(
        "binder scan of the arm64 libg.so: binder 0x{binder:x}, {binder_calls} binder calls, \
         {unresolved} unresolved, name slots from 0x{initialiser:x}, {} tables",
        tables.len()
    );
    Ok((tables, evidence))
}

/// Recover the 128-byte literal key from the encrypted names at `literals`.
fn key(data: &[u8], literals: impl Iterator<Item = usize>) -> Result<Vec<u8>> {
    // Every name starts with `data/`, so every literal starts with the same
    // `data/`-XOR-key bytes; one prefix has to cover most of them.
    let mut prefixes: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut total = 0usize;
    for offset in literals {
        let Some(bytes) = data.get(offset..offset + PREFIX.len()) else {
            continue;
        };
        let prefix: Vec<u8> = bytes
            .iter()
            .zip(PREFIX)
            .map(|(byte, plain)| byte ^ plain)
            .collect();
        *prefixes.entry(prefix).or_default() += 1;
        total += 1;
    }
    let (prefix, count) = prefixes
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
        .context("no encrypted name literal could be read")?;
    ensure!(
        count * 2 > total,
        "the encrypted names do not share a key prefix ({count} of {total}); refusing to guess at this build"
    );

    // The rest of the key: the majority byte at each position over every place
    // the prefix occurs.
    let starts: Vec<usize> = data
        .windows(LITERAL_TABLE_LEN)
        .enumerate()
        .filter(|(_, window)| window.starts_with(&prefix))
        .map(|(start, _)| start)
        .collect();
    ensure!(
        !starts.is_empty(),
        "the key prefix does not occur in this library"
    );
    let mut key = Vec::with_capacity(LITERAL_TABLE_LEN);
    for position in 0..LITERAL_TABLE_LEN {
        let mut counts = [0usize; 256];
        for start in &starts {
            counts[usize::from(data[start + position])] += 1;
        }
        let byte = (0..=255u8)
            .max_by_key(|byte| counts[usize::from(*byte)])
            .expect("256 candidates");
        key.push(byte);
    }
    ensure!(
        data.windows(LITERAL_TABLE_LEN)
            .any(|window| window == key.as_slice()),
        "the reconstructed key does not occur in this library; refusing to decrypt names with it"
    );
    Ok(key)
}

/// Decrypt the name at file `offset`, or `None` when it decrypts to nothing.
fn decrypt(data: &[u8], offset: usize, key: &[u8]) -> Option<String> {
    let mut out = String::new();
    for index in 0..MAX_LITERAL {
        let byte = *data.get(offset.checked_add(index)?)? ^ key[index % key.len()];
        if byte == 0 || !(byte.is_ascii_graphic() || byte == b' ') {
            break;
        }
        out.push(byte as char);
    }
    (out.len() >= 4).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(bytes: [u8; 4], pc: u64) -> Op {
        decode(u32::from_le_bytes(bytes), pc)
    }

    // Encodings from `llvm-mc -triple=aarch64 -show-encoding`.
    #[test]
    fn decodes_the_argument_builders() {
        // adrp x1, #0x5000 at 0x1234 → page 0x1000 + 0x5000
        assert_eq!(
            op([0x21, 0x00, 0x00, 0xb0], 0x1234),
            Op::Set(1, Value::Address(0x6000))
        );
        // add x1, x1, #0xd90
        assert_eq!(
            op([0x21, 0x40, 0x36, 0x91], 0),
            Op::Add {
                rd: 1,
                rn: 1,
                imm: 0xd90,
                wide: true
            }
        );
        // mov w2, #55 / mov w2, #-1 / mov x2, #-1
        assert_eq!(
            op([0xe2, 0x06, 0x80, 0x52], 0),
            Op::Set(2, Value::Immediate(55))
        );
        assert_eq!(
            op([0x02, 0x00, 0x80, 0x12], 0),
            Op::Set(2, Value::Immediate(0xffff_ffff))
        );
        assert_eq!(
            op([0x02, 0x00, 0x80, 0x92], 0),
            Op::Set(2, Value::Immediate(u64::MAX))
        );
        // movk w2, #0x1234, lsl #16
        assert_eq!(
            op([0x82, 0x46, 0xa2, 0x72], 0),
            Op::Keep {
                rd: 2,
                shift: 16,
                imm: 0x1234,
                wide: false
            }
        );
        // orr w3, wzr, #3 / mov w2, #0xff00ff00 / mov x0, #0x5555555555555555
        assert_eq!(
            op([0xe3, 0x07, 0x00, 0x32], 0),
            Op::Set(3, Value::Immediate(3))
        );
        assert_eq!(
            op([0xe2, 0x9f, 0x08, 0x32], 0),
            Op::Set(2, Value::Immediate(0xff00_ff00))
        );
        assert_eq!(
            op([0xe0, 0xf3, 0x00, 0xb2], 0),
            Op::Set(0, Value::Immediate(0x5555_5555_5555_5555))
        );
        // mov w3, wzr / mov x1, x20 / mov w1, w20
        assert_eq!(
            op([0xe3, 0x03, 0x1f, 0x2a], 0),
            Op::Copy {
                rd: 3,
                rm: 31,
                wide: false
            }
        );
        assert_eq!(
            op([0xe1, 0x03, 0x14, 0xaa], 0),
            Op::Copy {
                rd: 1,
                rm: 20,
                wide: true
            }
        );
        assert_eq!(
            op([0xe1, 0x03, 0x14, 0x2a], 0),
            Op::Copy {
                rd: 1,
                rm: 20,
                wide: false
            }
        );
    }

    #[test]
    fn decodes_control_flow_and_clobbers() {
        // bl #0x1000 at 0x34
        assert_eq!(op([0x00, 0x04, 0x00, 0x94], 0x34), Op::Call(0x1034));
        // b, ret, br x16
        assert_eq!(op([0x00, 0x08, 0x00, 0x14], 0), Op::Jump);
        assert_eq!(op([0xc0, 0x03, 0x5f, 0xd6], 0), Op::Jump);
        assert_eq!(op([0x00, 0x02, 0x1f, 0xd6], 0), Op::Jump);
        // blr x8
        assert_eq!(op([0x00, 0x01, 0x3f, 0xd6], 0), Op::CallIndirect);
        // cbz x0 writes nothing; mrs x1 writes x1
        assert_eq!(op([0x00, 0x02, 0x00, 0xb4], 0), Op::Clobber(0));
        assert_eq!(op([0x41, 0xd0, 0x3b, 0xd5], 0), Op::Clobber(1 << 1));
        // ldr x1, [x0] writes x1
        assert!(
            matches!(op([0x01, 0x00, 0x40, 0xf9], 0), Op::Clobber(mask) if mask & (1 << 1) != 0)
        );
        // ldp x29, x30, [sp], #16 writes both
        assert!(matches!(op([0xfd, 0x7b, 0xc1, 0xa8], 0),
            Op::Clobber(mask) if mask & (1 << 29) != 0 && mask & (1 << 30) != 0));
    }

    #[test]
    fn stores_keep_their_registers() {
        let writes = |bytes: [u8; 4]| match op(bytes, 0) {
            Op::Clobber(mask) => mask,
            other => panic!("{other:?}"),
        };
        // str x21, [sp, #0x670]: imm12 bits overlap the Rt2 field.
        assert_eq!(writes([0xf5, 0x3b, 0x03, 0xf9]), 0);
        // stp x20, x19, [sp, #16] / stp x22, x21, [sp, #-48]!
        assert_eq!(writes([0xf4, 0x4f, 0x01, 0xa9]), 0);
        assert_eq!(writes([0xf6, 0x57, 0xbd, 0xa9]), 1 << 31);
        // ldr x2, [x3], #8 writes the value and the base.
        assert_eq!(writes([0x62, 0x84, 0x40, 0xf8]), (1 << 2) | (1 << 3));
        // ldrb w11, [x10, x11] / ldr x0, #256
        assert_eq!(writes([0x4b, 0x69, 0x6b, 0x38]), 1 << 11);
        assert_eq!(writes([0x00, 0x08, 0x00, 0x58]), 1 << 0);
        // str x1, [x0, x2] keeps the address registers.
        assert_eq!(writes([0x01, 0x68, 0x22, 0xf8]) & ((1 << 0) | (1 << 2)), 0);
        // stxr w4, x1, [x0] writes its status; ldadd x1, x2, [x0] writes x2.
        assert_ne!(writes([0x01, 0x7c, 0x04, 0xc8]) & (1 << 4), 0);
        assert_ne!(writes([0x02, 0x00, 0x21, 0xf8]) & (1 << 2), 0);
    }

    #[test]
    fn tracks_binder_and_initialiser_arguments() {
        let words: [[u8; 4]; 12] = [
            [0x21, 0x00, 0x00, 0xb0], // adrp x1, +0x5000
            [0x21, 0x40, 0x36, 0x91], // add  x1, x1, #0xd90
            [0xe2, 0x06, 0x80, 0x52], // mov  w2, #55
            [0xe3, 0x03, 0x1f, 0x2a], // mov  w3, wzr
            [0x00, 0x04, 0x00, 0x94], // bl   +0x1000
            [0xe2, 0x06, 0x80, 0x52], // mov  w2, #55 — after the call, x1 is gone
            [0x00, 0x04, 0x00, 0x94], // bl   +0x1000
            [0x34, 0x00, 0x00, 0xb0], // adrp x20, +0x5000
            [0x94, 0xe2, 0x17, 0x91], // add  x20, x20, #0x5f8
            [0x00, 0x04, 0x00, 0x94], // bl   (x20 survives: callee-saved)
            [0xe1, 0x03, 0x14, 0xaa], // mov  x1, x20
            [0x00, 0x04, 0x00, 0x94], // bl
        ];
        let code: Vec<u8> = words.concat();
        let calls = calls(&code, 0x10_0000);
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[0].target, 0x10_1010);
        assert_eq!(binder_arguments(&calls[0]), Some((55, 0x10_5d90)));
        assert_eq!(calls[1].args[1], Some(Value::Address(0x10_55f8)));
        assert_eq!(binder_arguments(&calls[1]), None);
    }

    #[test]
    fn recovers_a_key_that_occurs_verbatim() {
        let key: Vec<u8> = (0..LITERAL_TABLE_LEN as u32)
            .map(|i| (i * 37 + 11) as u8)
            .collect();
        let mut data = vec![0u8; 64];
        data.extend_from_slice(&key);
        let mut offsets = Vec::new();
        for name in ["data/fields.csv", "data/money.csv", "data/animal_goods.csv"] {
            offsets.push(data.len());
            data.extend(name.bytes().enumerate().map(|(i, b)| b ^ key[i]));
            data.push(0xff);
        }
        let recovered = super::key(&data, offsets.iter().copied()).unwrap();
        assert_eq!(recovered, key);
        assert_eq!(
            decrypt(&data, offsets[1], &recovered).as_deref(),
            Some("data/money.csv")
        );
    }

    /// Against a real arm64 library: `HD_LIBG_ARM64=/path/to/libg.so cargo test -- --ignored`.
    #[test]
    #[ignore = "needs a real arm64 libg.so via HD_LIBG_ARM64"]
    fn scans_a_real_library() {
        let path = std::env::var_os("HD_LIBG_ARM64").expect("set HD_LIBG_ARM64");
        let data = std::fs::read(path).unwrap();
        let map = crate::native::TypeMap::scan(&data).unwrap();
        assert!(map.tables.len() >= MIN_TABLES, "{}", map.evidence);
        assert!(map.tables.values().all(|name| !name.is_empty()));
        eprintln!("{}", map.evidence);
    }
}
