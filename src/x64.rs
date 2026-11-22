// x64.rs: jQuery-style robust pattern matching for x64

use memchr::memmem;
use std::{
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
    // FINAL ACTIONS ONCE FINISHED QUERY CHAIN
    pub fn one(&self) -> bool {
        self.locs.len() == 1
    }
    pub fn first(&self) -> Result<*mut u8, ()> {
        if self.locs.len() > 0 { Ok(self.locs[0] as *mut u8) } else { Err(()) }
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
    pub fn filter(&mut self, keep_if_true: impl Fn(usize) -> bool){
        let new_locs: Vec<usize> = self.locs.iter().copied().filter(|&loc| keep_if_true(loc)).collect();
        info!("[x64Query::filter] {} -> {} locs", self.locs.len(), new_locs.len());
        self.locs = new_locs;
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

    // QUERY CHAINING
    /// scan from each loc in this direction. abs(bytes) = length of haystack array. thus bytes != 0 or you aren't searching anything. i.e.
    ///
    /// - if `bytes > 0`: scan RIGHT, memory [loc, loc + bytes).
    ///
    /// - if `bytes < 0`: scan LEFT, memory (loc + bytes, loc].
    ///
    /// then `locs` will be replaced with the new matches from those searches.
    pub unsafe fn within(mut self, pattern: &[u8], bytes: isize) -> Self {
        info!("[x64Query::within] Scanning {} {} B at {} locs", if bytes > 0 { "RIGHT" } else { "LEFT" }, bytes.abs(), self.locs.len());

        if self.locs.len() == 0 || bytes == 0 {
            return self;
        }

        let orig_locs = self.locs.clone();
        self.locs.clear();
        for &addr in &orig_locs {
            let ptr = addr as *mut u8;
            let mut res = if bytes > 0 {
                scan(pattern, ptr, bytes as usize)
            } else {
                scan(pattern, ptr.offset(bytes + 1), (-bytes) as usize)
            };
            self.bytes += res.bytes;
            self.wasted += res.wasted;
            self.locs.append(&mut res.locs);
        }

        // incase multiple starting locs that are near eachother hit the same exact loc
        self.locs.sort_unstable();
        self.locs.dedup();

        info!("[x64Query::within] {} -> {} locs", orig_locs.len(), self.locs.len());
        self
    }

    /// Like within(), but accepts a masked pattern string with ?? wildcards.
    pub unsafe fn within_wild(mut self, pattern: &str, bytes: isize) -> Self {
        info!("[x64Query::within_wild] Scanning {} {}B at {} locs", if bytes > 0 { "RIGHT" } else { "LEFT" }, bytes.abs(), self.locs.len());

        if self.locs.is_empty() || bytes == 0 {
            return self;
        }

        let orig_locs = self.locs.clone();
        self.locs.clear();
        for &addr in &orig_locs {
            let ptr = addr as *mut u8;
            let mut res = if bytes > 0 {
                scan_wild(pattern, ptr, bytes as usize)
            } else {
                scan_wild(pattern, ptr.offset(bytes + 1), (-bytes) as usize)
            };
            self.bytes += res.bytes;
            self.wasted += res.wasted;
            self.locs.append(&mut res.locs);
        }

        self.locs.sort_unstable();
        self.locs.dedup();
        info!("[x64Query::within_wild] {} -> {} locs", orig_locs.len(), self.locs.len());
        self
    }
}

/// returns: pointer to first byte of pattern
pub unsafe fn scan(pattern: &[u8], first_byte: *mut u8, bytes: usize) -> x64Query {
    // info!("[scan] Scanning for signature: {:02X?} from 0x{:X} to 0x{:X}", pattern, first_byte as usize, first_byte.add(bytes) as usize);

    let slice = slice::from_raw_parts(first_byte, bytes); // slice into a big array
    let past: Instant = Instant::now();
    let locs: Vec<usize> = memmem::Finder::new(pattern).find_iter(slice).map(|loc| loc + (first_byte as usize)).collect();

    return x64Query {
        locs: locs,
        wasted: past.elapsed(),
        bytes: bytes,
    };
}

/// write new bytes, automatically handle VirtualProtect calls
unsafe fn memwrite(addr: *mut u8, new_bytes: &[u8]) {
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

// ---- masked pattern support ----

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

/// Like scan() but supports ?? wildcards in the pattern string.
pub unsafe fn scan_wild(pattern: &str, first_byte: *mut u8, len: usize) -> x64Query {
    let (pat_bytes, pat_mask) = parse_wild(pattern);
    let plen = pat_bytes.len();

    // info!("[scan_wild] {:?} from 0x{:X} ({} B)", pattern, first_byte as usize, len);

    if plen == 0 || plen > len {
        return x64Query {
            locs: vec![],
            wasted: Duration::ZERO,
            bytes: len,
        };
    }

    let slice = slice::from_raw_parts(first_byte, len);
    let past = Instant::now();

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

/// gives absolute address of sub
pub unsafe fn where_is_E8call_going(e8_byte: *const u8) -> *const u8 {
    assert_eq!(*e8_byte, 0xE8, "0x{:X} aint E8", e8_byte as usize);
    let rel = *(e8_byte.add(1) as *const i32);
    e8_byte.add(5).offset(rel as isize)
}
