// mem.rs: pattern scanning and function patching

use std::{cell::Cell, ptr, slice, sync::{Mutex, atomic::{AtomicPtr, Ordering::SeqCst}}, time::Instant};
use winapi::um::{memoryapi::VirtualProtect, winnt::PAGE_EXECUTE_READWRITE};
use crate::{ADDR, val::{NOP, TARGET}, win::{Modu, find_module}};

pub static SIGCHECK: Patch<38> = Patch {
    name: "SigCheck", address: Mutex::new(0),
    PATTERN: [
        0xe8, 0xba, 0xca, 0x58, 0x01, 0x41, 0xb8, 0x40, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x94, 0x24, 0x60,
        0x01, 0x00, 0x00, 0x48, 0x8d, 0x4c, 0x24, 0x40, 0xe8, 0x76, 0x1d, 0x6b, 0x01, 0x85, 0xc0,
        0x0f, 0x94, 0xc0, // sete al
        0xeb, 0x02,
        0x32, 0xc0
    ],
    REPLACEMENT: [
        0xe8, 0xba, 0xca, 0x58, 0x01, 0x41, 0xb8, 0x40, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x94, 0x24, 0x60,
        0x01, 0x00, 0x00, 0x48, 0x8d, 0x4c, 0x24, 0x40, 0xe8, 0x76, 0x1d, 0x6b, 0x01, 0x85, 0xc0, 
        0xb0, 0x01, // mov al, 1
        NOP, 0xeb, 0x02,
        0xb0, 0x01, // mov al, 1
    ]
};

pub static WOW64PREPAREFOREXCEPTIONHOOKGATE: Patch<33> = Patch {
    name: "Wow64PrepareForExceptionHookGate", address: Mutex::new(0),
    PATTERN: [
        0x48, 0x83, 0x3D, 0x3F, 0x5D, 0xB7, 0x03, 0x00,
        0x75, 0x6E,
        0x50,
        0x53,
        0x51,
        0x52,
        0x57,
        0x56,
        0x41, 0x50,
        0x41, 0x51,
        0x41, 0x52,
        0x41, 0x53,
        0x41, 0x54,
        0x41, 0x55,
        0x41, 0x56,
        0x41, 0x57,
        0x55,
    ],
    REPLACEMENT: [
        0x48, 0x83, 0x3D, 0x3F, 0x5D, 0xB7, 0x03, 0x00,
        0xEB, 0x6E,
        0x50,
        0x53,
        0x51,
        0x52,
        0x57,
        0x56,
        0x41, 0x50,
        0x41, 0x51,
        0x41, 0x52,
        0x41, 0x53,
        0x41, 0x54,
        0x41, 0x55,
        0x41, 0x56,
        0x41, 0x57,
        0x55,
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
        info!("Scanning for signature: {:02X?}", self.PATTERN);
        // info!("Suspending other threads...");
        // let handles = sus_threads();
        let past: Instant = Instant::now();
        let addr = scan(&self.PATTERN, MODU_BASE.load(SeqCst), MODU_SIZE.load(SeqCst) as usize);
        good!("Pattern matched at address 0x{:x} in {}ms.", addr as u64, past.elapsed().as_millis());
        memwrite(addr, &self.REPLACEMENT);
        good!("Patch {} complete!", self.name);

        *self.address.lock().unwrap() = addr as usize;

        // info!("Resuming other threads...");
        // res_threads(handles);
    }}
    pub unsafe fn revert(&self) { unsafe {
        let addr = self.address.lock().unwrap().clone() as *mut u8;

        info!("Reverting patch {} @{:x}...", self.name, addr as u64);
        memwrite(addr, &self.PATTERN);
        good!("Patch reverted! Memory is clean.");
    }}
}
/// brute force scanning method. *mut u8 is a byte pointer
/// 
/// returns: pointer to first byte of pattern
fn scan(pattern: &[u8], first_byte: *mut u8, bytes: usize) -> *mut u8 { unsafe {
    let slice = slice::from_raw_parts(first_byte, bytes); // slice into a big array
    let len = pattern.len();

    for i in 0..=bytes-len {
        if &slice[i..i + len] == pattern {
            return first_byte.add(i);
        }
    }

    error!("Could not find pattern. Searched {} B.", bytes);
    error!("Either the pattern or DLL load order has been changed. This may be due to a game update.");
    die!("Pattern not found.")
}}
/// write new bytes, automatically handling VirtualProtect calls
unsafe fn memwrite(addr: *mut u8, new_bytes: &[u8]) { unsafe {
    let mut old: u32 = 0;
    info!("Invoking memwrite.");
    info!("Getting access level PAGE_EXECUTE_READWRITE...");
    if VirtualProtect(addr as _, new_bytes.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 { die!("Failed to get PAGE_EXECUTE_READWRITE access using VirtualProtect.") }
        // write the pattern back
        addr.copy_from_nonoverlapping(new_bytes.as_ptr(), new_bytes.len());
        info!("Replaced {} bytes with {:02X?}.", new_bytes.len(), new_bytes);
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