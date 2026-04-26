use windows::core::*;
use windows::Win32::{Foundation::*, System::SystemServices::*, UI::WindowsAndMessaging::MessageBoxA};

use winapi::{shared::minwindef::{HINSTANCE, DWORD, LPVOID}, um::consoleapi::AllocConsole};

use std::thread::{self};

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
        },
        DLL_PROCESS_DETACH => (),
        _ => (),
    }
    true
}

// actual code below
unsafe fn begin() { unsafe {
    AllocConsole();

    info!("Logger initialized...");
    info!("Signature: {:02X?}", PATTERN);
    let modu = match find_module(TARGET) {
        Ok(info) => { info }
        Err(code) => { die!("Failed to find module. Error #{}.", code) }
    };

    modu.hmodule

}}