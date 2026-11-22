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
        info!("[x64Query::within] Scanning {} {} B at {} locs", if bytes > 0 { "forward" } else { "backward" }, bytes.abs(), self.locs.len());

        if self.locs.len() == 0 || bytes == 0 {
            return self;
        }

        let orig_locs = self.locs.clone();
        self.locs.clear();
        for addr in orig_locs {
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

        info!("[x64Query::within] Refined down to {} locs", self.locs.len());
        self
    }
}

/// returns: pointer to first byte of pattern
pub unsafe fn scan(pattern: &[u8], first_byte: *mut u8, bytes: usize) -> x64Query {
    if bytes > 200 {
        info!("[scan] Scanning for signature: {:02X?} from 0x{:X} to 0x{:X}", pattern, first_byte as usize, first_byte.add(bytes) as usize);
    }

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
