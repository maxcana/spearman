// mem.rs: pattern scanning and function patching

use crate::{
    val::{NOP, TARGET},
    win::{Modu, find_module},
};
use memchr::memmem;
use std::{
    ptr, slice,
    sync::{
        Mutex,
        atomic::{AtomicPtr, Ordering::SeqCst},
    },
    time::Instant,
};
use winapi::um::{
    memoryapi::VirtualProtect,
    processthreadsapi::{FlushInstructionCache, GetCurrentProcess},
    winnt::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
};

pub unsafe fn patch_shit() {
    info!("Patching SIGCHECK...");
    let sigcheck = scaneth(&[0x85, 0xC0, 0x0F, 0x94, 0xC0, 0xEB, 0x02, 0x32, 0xC0, 0x4C, 0x8D, 0x9C, 0x24, 0x60, 0x02, 0x00, 0x00]);
    sigcheck.handle();
    sigcheck.patch(&[
        0x85, 0xC0, NOP, 0xB0, 0x01, // mov al, 1
        0xEB, 0x02, 0xB0, 0x01, // mov al, 1
        0x4C, 0x8D, 0x9C, 0x24, 0x60, 0x02, 0x00, 0x00,
    ]);

    info!("Patching AEGISDFHCHECK...");
    info!("Trying version 1.");
    let aegisdfhcheck1 = scaneth(&[
        // normal, like in build Yue Fei's Legacy
        0x0f, 0x95, 0xc1, // setne  cl
        0x0f, 0x94, 0xc0, // sete   al
        0x88, 0x4e, 0x21, // mov    BYTE PTR [rsi+0x21],cl
    ]);

    if aegisdfhcheck1.locs.len() > 1 {
        aegisdfhcheck1.handle(); // crash rn
    }
    if aegisdfhcheck1.one() {
        info!("Matched AEGISDFHCHECK version 1.");
        aegisdfhcheck1.handle();
        aegisdfhcheck1.patch(&[
            0xB0, 0x01, NOP, // mov al, 1
            0xB1, 0x00, NOP, // mov cl, 0
            0x88, 0x4e, 0x21,
        ]);
    } else {
        info!("Failed to match version 1 after {} ms. Trying version 2...", aegisdfhcheck1.ms);
        let aegisdfhcheck2 = scaneth(&[
            // reverse order, like in build 2026-11-09
            0x0f, 0x94, 0xc0, // sete   al
            0x0f, 0x95, 0xc1, // setne  cl
            0x88, 0x4e, 0x21, // mov    BYTE PTR [rsi+0x21],cl
        ]);
        aegisdfhcheck2.handle();
        aegisdfhcheck2.patch(&[
            0xB0, 0x01, NOP, // mov al, 1
            0xB1, 0x00, NOP, // mov cl, 0
            0x88, 0x4e, 0x21,
        ]);
    }
}

static MODU_BASE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static MODU_SIZE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

pub unsafe fn scaneth(PATTERN: &[u8]) -> ScanResult {
    scan(PATTERN, MODU_BASE.load(SeqCst), MODU_SIZE.load(SeqCst) as usize)
}

pub struct ScanResult {
    pub locs: Vec<usize>,
    pub ms: u128,
    pub bytes: usize,
}
impl ScanResult {
    pub fn one(&self) -> bool {
        self.locs.len() == 1
    }
    pub fn addr(&self) -> Result<*mut u8, ()> {
        if self.one() { Ok(self.locs[0] as *mut u8) } else { Err(()) }
    }
    pub unsafe fn patch(&self, REPLACEMENT: &[u8]) -> bool {
        if self.one() {
            memwrite(self.addr().unwrap(), REPLACEMENT);
            good!("Patched {} B successfully.", REPLACEMENT.len());
            true
        } else {
            false
        }
    }
    /// aborts if pattern matches at 0 or 2+ addresses
    pub fn handle(&self) {
        match self.locs.len() {
            0 => {
                error!("Could not find pattern. Searched {} B.", self.bytes);
                error!("Either the pattern or DLL load order has been changed. This may be due to a game update.");
                die!("Pattern not found.");
            }
            1 => {
                good!("Pattern matched at address 0x{:x} in {}ms.", self.locs[0], self.ms);
            }
            _ => {
                error!(
                    "{} matches found at: {:02X?} in {}ms. This is unexpected; pattern is likely not specific enough.",
                    self.locs.len(),
                    self.locs,
                    self.ms
                );
                die!("Multiple pattern matches found.")
            }
        }
    }
}

/// returns: pointer to first byte of pattern
pub unsafe fn scan(pattern: &[u8], first_byte: *mut u8, bytes: usize) -> ScanResult {
    info!("Scanning for signature: {:02X?}", pattern);

    let slice = slice::from_raw_parts(first_byte, bytes); // slice into a big array
    let past: Instant = Instant::now();
    let locs: Vec<usize> = memmem::Finder::new(pattern).find_iter(slice).map(|loc| loc + (first_byte as usize)).collect();

    return ScanResult {
        locs: locs,
        ms: past.elapsed().as_millis(),
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

/// obtain the module info (necessary to do pattern scanning)
pub unsafe fn init() {
    let modu: Modu = match find_module(TARGET) {
        Ok(info) => info,
        Err(code) => {
            die!("Failed to find module. Error #{}.", code)
        }
    };

    good!("Successfully located {}.", TARGET);
    info!("-----------------");
    info!("Base address:  0x{:x}", modu.info.lpBaseOfDll as u64);
    info!("Size of image: {} B", modu.info.SizeOfImage);
    info!("-----------------");

    MODU_BASE.store(modu.info.lpBaseOfDll as _, SeqCst);
    MODU_SIZE.store(modu.info.SizeOfImage as _, SeqCst);
}
