// x64.rs: jQuery-style robust pattern matching for x64 & helpers

use iced_x86::{Decoder, DecoderOptions, Instruction};
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
    pub fn eq(&self, n: usize) -> Result<x64Query, ()> {
        if self.locs.len() > n {
            let mut x64 = self.clone();
            x64.locs = vec![self.locs[n]];
            Ok(x64)
        } else {
            Err(())
        }
    }
    pub unsafe fn patch(&self, REPLACEMENT: &[u8]) -> bool {
        if self.one() {
            memwrite(self.locs[0] as _, REPLACEMENT);
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

/// instruction ordering:
///
/// - IF `bytes > 0`: the `Vec<Instruction>` in the closure is left-to-right
///
/// - IF `bytes < 0`: the `Vec<Instruction>` in the closure is right-to-left
pub unsafe fn peek_disassembly(loc: usize, bytes: isize) -> Vec<Instruction> {
    let slice = if bytes > 0 {
        core::slice::from_raw_parts(loc as *mut u8, bytes as usize)
    } else {
        core::slice::from_raw_parts((loc as *mut u8).offset(bytes + 1), (-bytes) as usize)
    };

    let mut instrs: Vec<Instruction> = Decoder::with_ip(64, slice, loc as u64, DecoderOptions::NONE).iter().collect();
    // sort it so nearest instructions are first
    instrs.sort_by(|a, b| {
        let a_dist = a.ip().abs_diff(loc as _);
        let b_dist = b.ip().abs_diff(loc as _);
        (&a_dist).cmp(&b_dist)
    });
    instrs
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
    if new_bytes.len() <= 25 {
        info!("Replaced {} bytes with {:02X?}.", new_bytes.len(), new_bytes);
    } else {
        info!("Replaced {} bytes with {}, ... ].", new_bytes.len(), format!("{:02X?}", &new_bytes[0..25]).trim_end_matches("]"));
    }
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
