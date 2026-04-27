use windows::Win32::{ System::{SystemServices::*}, UI::WindowsAndMessaging::MessageBoxA };
use windows::core::*;

use winapi::um::{winnt::PAGE_EXECUTE_READWRITE, wincon::FreeConsole};
use winapi::{
    shared::minwindef::{DWORD, HINSTANCE, LPVOID},
    um::{consoleapi::AllocConsole, memoryapi::{VirtualProtect}, processthreadsapi::{GetCurrentThread, SetThreadPriority}},
};

use std::{ptr, sync::atomic::{AtomicPtr, AtomicUsize, Ordering::SeqCst}};
use std::{slice, thread::{self}, time::Duration};
// modules
#[macro_use]
mod log; use log::*;
mod val; use val::*;
#[macro_use] mod mem; use mem::*;
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
        error!("Failed to set thread priority to THREAD_PRIORITY_TIME_CRITICAL.")
    } else { good!("Thread priority set to THREAD_PRIORITY_TIME_CRITICAL."); }

    info!("Waiting for code to unpack...");
    // wait until dll loads
    register_dll_hook(); 
}} 

/// global var; address of pattern
static ADDR: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

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
    info!("Base address:  0x{:x}", modu.info.lpBaseOfDll as u64);
    info!("Size of image: {} B", modu.info.SizeOfImage);
    info!("-----------------");

    info!("Signature: {:02X?}", PATTERN);

    // info!("Suspending other threads...");
    // let handles = sus_threads();

    info!("Scanning...");
    let addr = scan(&PATTERN, modu.info.lpBaseOfDll as *mut u8, modu.info.SizeOfImage as usize);

    good!("Pattern matched at address 0x{:x}...", addr as u64);

    
    info!("Getting access PAGE_EXECUTE_READWRITE...");
    let mut old: u32 = 0;
    if VirtualProtect(addr as _, PATTERN.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 { die!("Failed to get PAGE_EXECUTE_READWRITE access using VirtualProtect.") }
        addr.write_bytes(NOP, PATTERN.len());
        info!("Replaced {} bytes with {:X}.", PATTERN.len(), NOP);
        info!("Reverting protection...");
    if VirtualProtect(addr as _, PATTERN.len(), old, &mut old) == 0 { error!("Failed to revert protection level. It will stay as PAGE_EXECUTE_READWRITE.") };

    ADDR.store(addr, SeqCst);
    // info!("Resuming other threads...");
    // res_threads(handles);

    good!("Patch complete!");

    std::thread::spawn(|| {
        spy();
    });
    // wait for spy.rs to tell us on_archives_loaded()

    // dont detach dll since we need the version.dll functions to remain in memory
    // to detach dll
    // FreeLibraryAndExitThread(HMODULE(MY_HANDLE.load(SeqCst) as *mut c_void), 0);
}}

pub unsafe fn on_archives_loaded() { unsafe {
    good!("All archives loaded!");

    let addr = ADDR.load(SeqCst);
    info!("Reverting patched bytes...");
    info!("Getting access PAGE_EXECUTE_READWRITE...");
    let mut old: u32 = 0;
    
    if VirtualProtect(addr as _, PATTERN.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 { die!("Failed to get PAGE_EXECUTE_READWRITE access using VirtualProtect.") }
        // write the pattern back
        addr.copy_from_nonoverlapping(PATTERN.as_ptr(), PATTERN.len());
        info!("Replaced {} bytes with {:02X?}.", PATTERN.len(), PATTERN);
        info!("Reverting protection...");
    if VirtualProtect(addr as _, PATTERN.len(), old, &mut old) == 0 { error!("Failed to revert protection level. It will stay as PAGE_EXECUTE_READWRITE.") };
    good!("Patch reverted! Memory is clean.");

    info!("Freeing console in 3 seconds.");
    thread::sleep(Duration::from_secs(3));
    FreeConsole();
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