use windows::Win32::{ System::{SystemServices::*}, UI::WindowsAndMessaging::MessageBoxA };
use windows::core::*;

use winapi::um::{processthreadsapi::GetThreadPriority};
use winapi::{
    shared::minwindef::{DWORD, HINSTANCE, LPVOID},
    um::{consoleapi::AllocConsole, processthreadsapi::{GetCurrentThread, SetThreadPriority}},
};

use std::{sync::atomic::{AtomicUsize, Ordering::SeqCst}};
use std::{thread::{self}};
// modules
#[macro_use] mod log; use log::*;
#[macro_use] mod win; use win::*;
mod val; use val::*;
mod mem; use mem::*;
mod spy; use spy::*;

// entry. "system" defines the calling convention
#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(handle: HINSTANCE, call_reason: DWORD, _: LPVOID) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => unsafe {
            MessageBoxA(None, s!("attached"), s!("spearman.dll"), Default::default());

            AllocConsole();
            init_logger();

            info!("Logger initialized.");
            
            
            // do this immediately so version.dll calls go somewhere
            info!("Loading {}...", VERSION_DLL_NAME);
            load_orig_dll();
            find_all_orig();
            good!("{} loaded.", VERSION_DLL_NAME);

            info!("Clearing warnings.log...");
            match clear_log() {
                Ok(_) => good!("warnings.log cleared successfully."),
                Err(code) => {
                    error!("Failed to clear warnings.log. Error #{}.", code);
                }
            }

            // do stuff in other thread so we don't freeze process (return from DllMain immediately)
            thread::spawn(|| begin());
        }
        _ => (),
    }
    true
}


// actual code below
unsafe fn begin() { unsafe {
    info!("Worker thread initialized.");

    match SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL) {
        0 => error!("Failed to set thread priority to {}.", THREAD_PRIORITY_TIME_CRITICAL),
        _ => good!("Thread priority set to {}.", GetThreadPriority(GetCurrentThread()))
    }

    win::hook_console();

    info!("Waiting for code to unpack...");
    win::register_dll_hook(); // wait until dll loads 
}} 

pub unsafe fn on_dll() { unsafe{
    info!("Assuming unpacking is complete.");

    mem::init();
    SIGCHECK.patch();
    WOW64PREPAREFOREXCEPTIONHOOKGATE.patch();
    AEGISDFHCHECK.patch();

    info!("Starting spy thread...");
    std::thread::spawn(|| { spy(); }); // wait for spy.rs to tell us on_archives_loaded()
}}

pub unsafe fn on_archives_loaded() { unsafe {
    good!("All archives loaded!");
}}


// MARK: Forwarding
// define the same functions as the dll we are mimicking
forward!(GetFileVersionInfoA);
forward!(GetFileVersionInfoByHandle);
forward!(GetFileVersionInfoExA);
forward!(GetFileVersionInfoExW);
forward!(GetFileVersionInfoSizeA);
forward!(GetFileVersionInfoSizeExA);
forward!(GetFileVersionInfoSizeExW);
forward!(GetFileVersionInfoSizeW);
forward!(GetFileVersionInfoW);
forward!(VerFindFileA);
forward!(VerFindFileW);
forward!(VerInstallFileA);
forward!(VerInstallFileW);
forward!(VerLanguageNameA);
forward!(VerLanguageNameW);
forward!(VerQueryValueA);
forward!(VerQueryValueW);
fn find_all_orig() {
    find_orig!(GetFileVersionInfoA);
    find_orig!(GetFileVersionInfoByHandle);
    find_orig!(GetFileVersionInfoExA);
    find_orig!(GetFileVersionInfoExW);
    find_orig!(GetFileVersionInfoSizeA);
    find_orig!(GetFileVersionInfoSizeExA);
    find_orig!(GetFileVersionInfoSizeExW);
    find_orig!(GetFileVersionInfoSizeW);
    find_orig!(GetFileVersionInfoW);
    find_orig!(VerFindFileA);
    find_orig!(VerFindFileW);
    find_orig!(VerInstallFileA);
    find_orig!(VerInstallFileW);
    find_orig!(VerLanguageNameA);
    find_orig!(VerLanguageNameW);
    find_orig!(VerQueryValueA);
    find_orig!(VerQueryValueW);
}