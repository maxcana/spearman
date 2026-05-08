// mem.rs: pattern scanning and function patching

use std::{ptr, slice, sync::{Mutex, atomic::{AtomicPtr, Ordering::SeqCst}}, time::Instant};
use memchr::memmem;
use winapi::um::{memoryapi::VirtualProtect, processthreadsapi::{FlushInstructionCache, GetCurrentProcess}, winnt::{PAGE_EXECUTE_READWRITE, PAGE_READWRITE}};
use crate::{val::{NOP, TARGET}, win::{Modu, find_module}};

pub static SIGCHECK: Patch<22> = Patch {
    name: "SIGCHECK", address: Mutex::new(0),
    PATTERN: [
        0xE8, 0xFC, 0x96, 0x6A, 0x01,
        0x85, 0xC0,
        0x0F, 0x94, 0xC0,
        0xEB, 0x02,
        0x32, 0xC0,
        0x4C, 0x8D, 0x9C, 0x24, 0x60, 0x02, 0x00, 0x00
    ],
    REPLACEMENT: [
        0xE8, 0xFC, 0x96, 0x6A, 0x01,
        0x85, 0xC0,
        NOP, 0xB0, 0x01, // mov al, 1
        0xEB, 0x02,
        0xB0, 0x01, // mov al, 1
        0x4C, 0x8D, 0x9C, 0x24, 0x60, 0x02, 0x00, 0x00
    ]
};

pub static AEGISDFHCHECK: Patch<12> = Patch {
    name: "AEGISDFHCHECK", address: Mutex::new(0),
    PATTERN: [
	    0x4c, 0x3b, 0xef, 0x0f, 0x95, 0xc1, 0x0f, 0x94, 0xc0, 0x88, 0x4e, 0x21
    ],
    REPLACEMENT: [
        0x4d, 0x39, 0xed, 0x0f, 0x95, 0xc1, 0x0f, 0x94, 0xc0, 0x88, 0x4e, 0x21
    ]
};

pub struct Patch <const N: usize> {
    name: &'static str,
    /// the byte pattern to search for
    PATTERN: [u8; N],
    REPLACEMENT: [u8; N],
    /// set internally to revert the patch (dont specify this)
    address: Mutex<usize>
}

static MODU_BASE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static MODU_SIZE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

impl<const N: usize> Patch<N> {
    pub unsafe fn patch(&self){ unsafe {
        info!("Patching {}...", self.name);
        
        let addr = scan(&self.PATTERN, MODU_BASE.load(SeqCst), MODU_SIZE.load(SeqCst) as usize);
        
        memwrite(addr, &self.REPLACEMENT);
        good!("Patch {} complete!", self.name);

        *self.address.lock().unwrap() = addr as usize;
    }}
    pub unsafe fn revert(&self) { unsafe {
        let addr = self.address.lock().unwrap().clone() as *mut u8;

        info!("Reverting patch {} @{:x}...", self.name, addr as u64);
        memwrite(addr, &self.PATTERN);
        good!("Patch reverted! Memory is clean.");
    }}
}

/// returns: pointer to first byte of pattern
fn scan(pattern: &[u8], first_byte: *mut u8, bytes: usize) -> *mut u8 { unsafe {
    info!("Scanning for signature: {:02X?}", pattern);

    let slice = slice::from_raw_parts(first_byte, bytes); // slice into a big array
    let past: Instant = Instant::now();
    let locs: Vec<usize> = memmem::Finder::new(pattern).find_iter(slice).map(|loc| loc + (first_byte as usize)).collect();

    match locs.len() {
        0 => {
            error!("Could not find pattern. Searched {} B.", bytes);
            error!("Either the pattern or DLL load order has been changed. This may be due to a game update.");
            die!("Pattern not found.")
        }
        1 => {
            good!("Pattern matched at address 0x{:x} in {}ms.", locs[0], past.elapsed().as_millis());
            locs[0] as *mut u8
        },
        _ => {
            error!("{} matches found at: {:02X?} in {}ms. This is unexpected; pattern is likely not specific enough.", locs.len(), locs, past.elapsed().as_millis());
            die!("Multiple pattern matches found.")
        }
    }
}}
/// write new bytes, automatically handle VirtualProtect calls
unsafe fn memwrite(addr: *mut u8, new_bytes: &[u8]) { unsafe {
    let mut old: u32 = 0;
    info!("Invoking memwrite.");
    info!("Getting access level PAGE_EXECUTE_READWRITE...");
    if VirtualProtect(addr as _, new_bytes.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 { die!("Failed to get PAGE_EXECUTE_READWRITE access using VirtualProtect. Is the address correct?") }
        // write the pattern back
        addr.copy_from_nonoverlapping(new_bytes.as_ptr(), new_bytes.len());
        info!("Replaced {} bytes with {:02X?}.", new_bytes.len(), new_bytes);
        // info!("Flushing instruction cache...");
        // FlushInstructionCache(GetCurrentProcess(), addr as _, new_bytes.len());
        info!("Reverting protection...");
    if VirtualProtect(addr as _, new_bytes.len(), old, &mut old) == 0 { error!("Failed to revert protection level. It will stay as PAGE_EXECUTE_READWRITE.") };
}}

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