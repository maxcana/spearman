// x64.rs: jQuery-style robust pattern matching for x64 & helpers

use ilhook::x64::Registers;
use memchr::memmem;
use std::{
    collections::HashSet,
    slice,
    time::{Duration, Instant},
};
use winapi::um::{memoryapi::VirtualProtect, winnt::PAGE_EXECUTE_READWRITE};

#[derive(Clone)]
pub struct x64Query {
    pub locs: Vec<usize>,
    pub wasted: Duration,
    pub bytes: usize,
}

impl x64Query {
    // MARK: FINAL ACTIONS ONCE FINISHED QUERY CHAIN
    pub fn one(&self) -> bool {
        self.locs.len() == 1
    }
    pub fn first(&self) -> Result<*mut u8, ()> {
        if self.locs.len() > 0 { Ok(self.locs[0] as *mut u8) } else { Err(()) }
    }
    pub fn first_as_x64query(&self) -> Result<x64Query, ()> {
        if self.locs.len() > 0 {
            let mut x64 = self.clone();
            x64.locs = vec![self.locs[0]];
            Ok(x64)
        } else {
            Err(())
        }
    }
    pub unsafe fn patch(&self, REPLACEMENT: &[u8]) -> bool {
        if self.one() {
            memwrite(self.first().unwrap(), REPLACEMENT);
            good!("Patched {} B successfully.", REPLACEMENT.len());
            true
        } else {
            false
        }
    }
    pub fn filter(&self, keep_if_true: impl Fn(usize) -> bool) -> x64Query {
        let mut x64 = self.clone();

        let new_locs: Vec<usize> = x64.locs.iter().copied().filter(|&loc| keep_if_true(loc)).collect();
        info!("[x64Query::filter] {} -> {} locs", x64.locs.len(), new_locs.len());
        x64.locs = new_locs;
        x64
    }

    /// aborts if pattern matches at 0 or 2+ addresses
    pub fn expect_one(&self) {
        match self.locs.len() {
            0 => {
                error!("Could not find pattern. Searched {} B.", self.bytes);
                error!("Either the pattern or DLL load order has been changed. This may be due to a game update.");
                die!("Pattern not found.");
            }
            1 => {
                good!("Pattern matched at address 0x{:X} in {}ms.", self.locs[0], self.wasted.as_millis());
            }
            _ => {
                error!("{} matches found at: {:02X?} in {}ms. This is unexpected; pattern is likely not specific enough.", self.locs.len(), self.locs, self.wasted.as_millis());
                die!("Multiple pattern matches found.")
            }
        }
    }

    /// aborts if pattern matches at (0 OR different amount than n) addresses.
    pub fn expect_n(&self, n: usize) {
        match self.locs.len() {
            0 => {
                error!("Could not find pattern. Searched {} B.", self.bytes);
                error!("Either the pattern or DLL load order has been changed. This may be due to a game update.");
                die!("Pattern not found.");
            }
            x if x == n => {
                good!("{} matches found at: {:02X?} in {}ms. This is expected.", self.locs.len(), self.locs, self.wasted.as_millis());
            }
            _ => {
                error!("{} matches found at: {:02X?} in {}ms. This is unexpected; pattern is likely not specific enough.", self.locs.len(), self.locs, self.wasted.as_millis());
                die!("Multiple pattern matches found.")
            }
        }
    }

    // MARK: QUERY CHAINING
    /// scan from each loc in this direction. abs(bytes) = length of haystack array. thus bytes != 0 or you aren't searching anything. i.e.
    ///
    /// - if `bytes > 0`: scan RIGHT, memory [loc, loc + bytes).
    ///
    /// - if `bytes < 0`: scan LEFT, memory (loc + bytes, loc].
    ///
    /// then `locs` will be replaced with the new matches from those searches.
    pub unsafe fn within(&self, pattern: &str, bytes: isize) -> x64Query {
        info!("[x64Query::within] Scanning {} {} B at {} locs", if bytes > 0 { "RIGHT" } else { "LEFT" }, bytes.abs(), self.locs.len());
        let mut x64 = self.clone();

        if x64.locs.is_empty() || bytes == 0 {
            return x64;
        }

        let orig_locs = x64.locs.clone();
        x64.locs.clear();
        for &addr in &orig_locs {
            let ptr = addr as *mut u8;
            let mut res = if bytes > 0 {
                scan(pattern, ptr, bytes as usize)
            } else {
                scan(pattern, ptr.offset(bytes + 1), (-bytes) as usize)
            };
            // sort it so nearest matches are first
            res.locs.sort_by(|&a, &b| {
                let a_dist = addr.abs_diff(a);
                let b_dist = addr.abs_diff(b);
                (&a_dist).cmp(&b_dist)
            });
            x64.bytes += res.bytes;
            x64.wasted += res.wasted;
            x64.locs.append(&mut res.locs);
        }

        // incase multiple starting locs that are near eachother hit the same exact loc
        // dedup while preserving order
        let mut seen = HashSet::with_capacity(x64.locs.len());
        x64.locs.retain(|loc| seen.insert(*loc));

        info!("[x64Query::within] {} -> {} locs", orig_locs.len(), x64.locs.len());
        x64
    }
}

// MARK: Scan

/// Parse "48 8B ?? 10 33 D2" into (bytes, mask) where mask[i]=0xFF means must-match.
pub fn parse_wild(pattern: &str) -> (Vec<u8>, Vec<u8>) {
    pattern
        .split_whitespace()
        .map(|byte| {
            if byte == "??" || byte == "?" {
                (0x00, 0x00)
            } else {
                (u8::from_str_radix(byte, 16).expect("bad pattern byte"), 0xFF)
            }
        })
        .unzip()
}

/// supports ?? wildcards in the pattern string.
///
/// warning: doesn't report patterns that overlap
pub unsafe fn scan(pattern: &str, first_byte: *mut u8, len: usize) -> x64Query {
    let (pat_bytes, pat_mask) = parse_wild(pattern);
    let plen = pat_bytes.len();
    // info!("[scan] {:?} from 0x{:X} ({} B)", pattern, first_byte as usize, len);

    if plen == 0 || plen > len {
        return x64Query {
            locs: vec![],
            wasted: Duration::ZERO,
            bytes: 0,
        };
    }

    let slice = slice::from_raw_parts(first_byte, len);
    let past = Instant::now();

    // no-wildcard path:
    if pat_mask.iter().all(|&m| m != 0) {
        let locs: Vec<usize> = memmem::find_iter(slice, &pat_bytes).map(|loc| loc + first_byte as usize).collect();

        return x64Query {
            locs,
            wasted: past.elapsed(),
            bytes: len,
        };
    }

    // wildcard path:
    // Pick the rarest solid byte as the memmem anchor to minimize false-positive checks.
    let (anchor_offset, anchor_byte) = pat_bytes
        .iter()
        .copied()
        .zip(pat_mask.iter().copied())
        .enumerate()
        .filter(|&(_, (_, m))| m != 0)
        .max_by_key(|&(i, (b, _))| {
            let rarity: usize = match b {
                0x00 | 0xFF | 0x48 | 0x49 | 0x8B | 0x33 => 0,
                _ => 1,
            };
            rarity * 10000 + i
        })
        .map(|(i, (b, _))| (i, b))
        .unwrap_or((0, pat_bytes[0]));

    let locs: Vec<usize> = memmem::Finder::new(&[anchor_byte])
        .find_iter(slice)
        .filter_map(|anchor_pos| {
            if anchor_pos < anchor_offset {
                return None;
            }
            let start = anchor_pos - anchor_offset;
            if start + plen > len {
                return None;
            }
            let window = &slice[start..start + plen];
            let matched = window.iter().zip(pat_bytes.iter()).zip(pat_mask.iter()).all(|((s, b), &m)| m == 0 || s == b);
            if matched { Some(start + first_byte as usize) } else { None }
        })
        .collect();

    x64Query {
        locs,
        wasted: past.elapsed(),
        bytes: len,
    }
}

// MARK: Resolving regs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Reg64 {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl Reg64 {
    const fn from_idx(i: u8) -> Self {
        match i & 0xF {
            0 => Self::Rax,
            1 => Self::Rcx,
            2 => Self::Rdx,
            3 => Self::Rbx,
            4 => Self::Rsp,
            5 => Self::Rbp,
            6 => Self::Rsi,
            7 => Self::Rdi,
            8 => Self::R8,
            9 => Self::R9,
            10 => Self::R10,
            11 => Self::R11,
            12 => Self::R12,
            13 => Self::R13,
            14 => Self::R14,
            _ => Self::R15,
        }
    }
}

pub fn mov_rdx_reg_WHICHREG(b: [u8; 3]) -> Option<Reg64> {
    let [rex, op, modrm] = b;
    let w = (rex >> 3) & 1;
    let r = (rex >> 2) & 1;
    let b_bit = rex & 1;

    if (rex & 0xF0) != 0x40 || w != 1 || op != 0x8B {
        return None;
    }

    let mod_bits = (modrm >> 6) & 0b11;
    let reg_bits = (modrm >> 3) & 0b111;
    let rm_bits = modrm & 0b111;

    // Register-direct mode (mod == 11) and destination must be RDX (index 2).
    if mod_bits != 0b11 || ((r << 3) | reg_bits) != 2 {
        return None;
    }

    Some(Reg64::from_idx((b_bit << 3) | rm_bits))
}

pub unsafe fn read_reg(regs: *mut Registers, reg: Reg64) -> u64 {
    match reg {
        Reg64::Rax => (*regs).rax,
        Reg64::Rcx => (*regs).rcx,
        Reg64::Rdx => (*regs).rdx,
        Reg64::Rbx => (*regs).rbx,
        Reg64::Rsp => (*regs).rsp,
        Reg64::Rbp => (*regs).rbp,
        Reg64::Rsi => (*regs).rsi,
        Reg64::Rdi => (*regs).rdi,
        Reg64::R8 => (*regs).r8,
        Reg64::R9 => (*regs).r9,
        Reg64::R10 => (*regs).r10,
        Reg64::R11 => (*regs).r11,
        Reg64::R12 => (*regs).r12,
        Reg64::R13 => (*regs).r13,
        Reg64::R14 => (*regs).r14,
        Reg64::R15 => (*regs).r15,
    }
}

// MARK: Helpers

/// write new bytes, automatically handle VirtualProtect calls
pub unsafe fn memwrite(addr: *mut u8, new_bytes: &[u8]) {
    let mut old: u32 = 0;
    info!("Invoking memwrite.");
    info!("Getting access level PAGE_EXECUTE_READWRITE...");
    if VirtualProtect(addr as _, new_bytes.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        die!("Failed to get PAGE_EXECUTE_READWRITE access using VirtualProtect. Is the address correct?")
    }
    // write the pattern back
    addr.copy_from_nonoverlapping(new_bytes.as_ptr(), new_bytes.len());
    info!("Replaced {} bytes with {:02X?}.", new_bytes.len(), new_bytes);
    // info!("Flushing instruction cache...");
    // FlushInstructionCache(GetCurrentProcess(), addr as _, new_bytes.len());
    info!("Reverting protection...");
    if VirtualProtect(addr as _, new_bytes.len(), old, &mut old) == 0 {
        error!("Failed to revert protection level. It will stay as PAGE_EXECUTE_READWRITE.")
    };
}



// MARK: Assembly

/// e8 = call rel32
/// gives absolute address of sub
pub unsafe fn where_is_E8call_going(e8_byte: *const u8) -> usize {
    if *e8_byte != 0xE8 {
        die!("[where_is_E8call_going] 0x{:X} aint E8", e8_byte as usize);
    }
    let rel = (e8_byte.add(1) as *const i32).read_unaligned();
    let place = e8_byte.add(5).offset(rel as isize) as usize;

    // info!("[where_is_E8call_going] E8 @ 0x{:X} -> call 0x{:X}", e8_byte as usize, place);
    place
}

pub fn make_E9_jmp(addr_of_e9: usize, jmp_to: usize) -> Result<[u8; 5], ()> {
    let mut arr: [u8; 5] = [0xE9, 0x00, 0x00, 0x00, 0x00];
    let rel = jmp_to.wrapping_sub(addr_of_e9 + 5) as isize;
    let rel32 = i32::try_from(rel);
    if rel32.is_err() {
        error!("[make_E9_jmp] target out of rel32 range");
        return Err(());
    }

    arr[1..5].copy_from_slice(&rel32.unwrap().to_le_bytes());
    info!("[make_E9_jmp] Encoded jmp rel32: {:02X?}", arr);

    Ok(arr)
}
pub fn make_0F85_jnz(addr_of_0f: usize, jmp_to: usize) -> Result<[u8; 6], ()> {
    let mut arr: [u8; 6] = [0x0F, 0x85, 0x00, 0x00, 0x00, 0x00];
    let rel = jmp_to.wrapping_sub(addr_of_0f + 6) as isize;
    let rel32 = i32::try_from(rel);
    if rel32.is_err() {
        error!("[make_0FB5_jnz] target out of rel32 range");
        return Err(());
    }

    arr[2..6].copy_from_slice(&rel32.unwrap().to_le_bytes());
    info!("[make_0FB5_jnz] Encoded jnz rel32: {:02X?}", arr);

    Ok(arr)
}

/// FF 25 = jmp [rip+rel32].
/// gives absolute address of sub
pub unsafe fn where_is_FF25jmp_going(FF_byte: *const u8) -> usize {
    let rel = (FF_byte.add(2) as *const i32).read_unaligned();
    let place = (FF_byte.add(6).offset(rel as isize) as *const usize).read_unaligned();

    // info!("[where_is_FF25jmp_going] FF25 @ 0x{:X} -> jmp 0x{:X}", FF_byte as usize, place);
    place
}

/// 0F 85 = jnz rip+rel32.
/// gives absolute address of sub
pub unsafe fn where_is_0F85jne_going(_0F_byte: *const u8) -> usize {
    let rel = (_0F_byte.add(2) as *const i32).read_unaligned();
    let place = _0F_byte.add(6).offset(rel as isize) as usize;

    place
}
