use windows::Win32::{ System::{SystemServices::*}, UI::WindowsAndMessaging::MessageBoxA };
use windows::core::*;

use winapi::um::{processthreadsapi::GetThreadPriority, wincon::FreeConsole, winnt::PAGE_EXECUTE_READWRITE};
use winapi::{
    shared::minwindef::{DWORD, HINSTANCE, LPVOID},
    um::{consoleapi::AllocConsole, memoryapi::{VirtualProtect}, processthreadsapi::{GetCurrentThread, SetThreadPriority}},
};

use std::{ptr, sync::atomic::{AtomicPtr, AtomicUsize, Ordering::SeqCst}};
use std::{slice, thread::{self}, time::Duration};
// modules
#[macro_use] mod log; use log::*;
#[macro_use] mod win; use win::*;
mod val; use val::*;
mod mem; use mem::*;
mod spy; use spy::*;

static MY_HANDLE: AtomicUsize = AtomicUsize::new(0); // global var to store this DLL's handle
// entry. "system" defines the calling convention
#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(handle: HINSTANCE, call_reason: DWORD, _: LPVOID) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => unsafe {
            MY_HANDLE.store(handle as usize, SeqCst);
            MessageBoxA(None, s!("attached"), s!("spearman.dll"), Default::default());

            AllocConsole();
            init_logger();

            info!("Logger initialized.");
            
            info!("Loading {}...", VERSION_DLL_NAME);
            // do this immediately so version.dll calls go somewhere
            load_orig_dll();
            good!("{} loaded.", VERSION_DLL_NAME);

            info!("Clearing warnings.log...");
            match clear_log() {
                Ok(_) => good!("warnings.log cleared successfully."),
                Err(code) => {
                    error!("Failed to clear warnings.log. Error #{}.", code);
                    error!("This WILL cause the patch to fail since the spy relies on reading warnings.log.");
                }
            }

            // do stuff in other thread so we don't freeze process (return from DllMain immediately)
            thread::spawn(|| begin());
        }
        DLL_PROCESS_DETACH => unsafe{
            // we won't detach since we need to maintain the fake version.dll
            info!("DLL detached.");
            unregister_dll_hook()
        },
        _ => (),
    }
    true
}


// actual code below
unsafe fn begin() { unsafe {
    info!("Worker thread initialized.");

    if SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL) == 0 {
        error!("Failed to set thread priority to {}.", THREAD_PRIORITY_TIME_CRITICAL)
    } else {
        good!("Thread priority set to {}.", GetThreadPriority(GetCurrentThread()));
    }

    win::hook_console();

    info!("Waiting for code to unpack...");
    // wait until dll loads
    win::register_dll_hook(); 
}} 

/// global var; address of pattern
static ADDR: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

pub unsafe fn on_dll() { unsafe{
    info!("Assuming unpacking is complete.");

    mem::init();
    // SIGCHECK.patch();
    // WOW64PREPAREFOREXCEPTIONHOOKGATE.patch();
    // AEGISDFHCHECK.patch();

    info!("Starting spy thread...");
    std::thread::spawn(|| { spy(); });
    // wait for spy.rs to tell us on_archives_loaded()

    // dont detach dll since we need the version.dll functions to remain in memory
    // to detach dll
    // FreeLibraryAndExitThread(HMODULE(MY_HANDLE.load(SeqCst) as *mut c_void), 0);
}}

pub unsafe fn on_archives_loaded() { unsafe {
    good!("All archives loaded!");

    // SIGCHECK.revert();

    // info!("Stay secret. Stay hidden. Stay safe.");

    // info!("Freeing console in 3 seconds.");
    // thread::sleep(Duration::from_secs(3));
    // FreeConsole();
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