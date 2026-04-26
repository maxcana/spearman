use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::LibraryLoader::FreeLibraryAndExitThread;
use windows::Win32::{
    Foundation::*, System::SystemServices::*, UI::WindowsAndMessaging::MessageBoxA,
};
use windows::core::*;

use winapi::{
    shared::minwindef::{DWORD, HINSTANCE, LPVOID},
    um::{consoleapi::AllocConsole, memoryapi::{VirtualProtect}},
    
};

use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering::SeqCst};
use std::{slice, thread::{self}, time, ffi::c_void};
// modules
#[macro_use]
mod log; use log::*;
mod val; use val::*;
mod mem; use mem::*;

static MY_HANDLE: AtomicUsize = AtomicUsize::new(0); // global var to store this DLL's handle
// entry. "system" defines the calling convention
#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(handle: HINSTANCE, call_reason: DWORD, _: LPVOID) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => unsafe {
            MY_HANDLE.store(handle as usize, SeqCst);
            MessageBoxA(None, s!("attached"), s!("spearman.dll"), Default::default());
            // do stuff in other thread so we don't freeze process (return from DllMain immediately)
            thread::spawn(|| begin());
        }
        DLL_PROCESS_DETACH => unsafe{
            info!("Detached.");
            unregister_dll_hook()
        },
        _ => (),
    }
    true
}

// actual code below
unsafe fn begin() { unsafe {
    AllocConsole();

    info!("Logger initialized...");
    info!("Waiting for code to unpack...");
    
    // wait until dll loads
    register_dll_hook(); 
}} 

pub unsafe fn on_dll() { unsafe{
    info!("Assuming unpacking is complete.");

    let modu = match find_module(TARGET) {
        Ok(info) => info,
        Err(code) => {
            die!("Failed to find module. Error #{}.", code)
        }
    };

    good!("Successfully located {}.", TARGET);
    info!("-----------------");
    info!("Base address: 0x{:x}", modu.info.lpBaseOfDll as u64);
    info!("Size of image: {} B", modu.info.SizeOfImage);
    info!("-----------------\n");

    info!("Signature: {:02X?}", PATTERN);

    info!("Suspending other threads...");
    let handles = sus_threads();

    info!("Scanning...");
    let addr = scan(&PATTERN, modu.info.lpBaseOfDll as *mut u8, modu.info.SizeOfImage as usize);

    good!("Pattern matched at address 0x{:x}...", addr as u32);

    
    info!("Getting access PAGE_EXECUTE_READWRITE...");
    let mut old: u32 = 0;
    if VirtualProtect(addr as _, PATTERN.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 { die!("Failed to get PAGE_EXECUTE_READWRITE access using VirtualProtect.") }
        addr.write_bytes(NOP, PATTERN.len());
        info!("Replaced {} bytes with {}.", PATTERN.len(), NOP);
        info!("Reverting protection...");
    if VirtualProtect(addr as _, PATTERN.len(), old, &mut old) == 0 { error!("Failed to revert protection level. It will stay as PAGE_EXECUTE_READWRITE.") };

    info!("Resuming other threads...");
    res_threads(handles);

    // detach dll
    good!("Patch complete!");
    info!("Press enter to detach...");
    let _ = std::io::stdin().read_line(&mut String::new());
    FreeLibraryAndExitThread(HMODULE(MY_HANDLE.load(SeqCst) as *mut c_void), 0);
}}

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