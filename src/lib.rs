use windows::Win32::{
    Foundation::*, System::SystemServices::*, UI::WindowsAndMessaging::MessageBoxA,
};
use windows::core::*;

use winapi::{
    shared::minwindef::{DWORD, HINSTANCE, LPVOID},
    um::consoleapi::AllocConsole,
};

use std::{slice, thread::{self}};

// modules
#[macro_use]
mod log; use log::*;
mod val; use val::*;
mod mem; use mem::*;


// entry. "system" defines the calling convention
#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(handle: HINSTANCE, call_reason: DWORD, _: LPVOID) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            MessageBoxA(None, s!("attached"), s!("spearman.dll"), Default::default());
            // do stuff in other thread so we don't freeze process (return from DllMain immediately)
            thread::spawn(|| begin());
        }
        DLL_PROCESS_DETACH => (),
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

    info!("Successfully located {}.", TARGET);
    info!("-----------------");
    info!("Base address: {:X}", modu.info.lpBaseOfDll as u64);
    info!("Size of image: {} B", modu.info.SizeOfImage);
    info!("-----------------\n");

    info!("Signature: {:02X?}", PATTERN);
    info!("Scanning...");

    scan(&PATTERN, modu.info.lpBaseOfDll as *mut u8, modu.info.SizeOfImage as usize);
}}

/// brute force scanning method. *mut u8 is a byte pointer
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