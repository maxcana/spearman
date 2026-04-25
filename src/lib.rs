use windows::{Win32::Foundation::*, Win32::System::SystemServices::*};
use windows::{Win32::UI::WindowsAndMessaging::MessageBoxA, core::*};

use winapi::shared::minwindef::{HINSTANCE, DWORD, LPVOID};
use winapi::um::consoleapi::AllocConsole;

// modules
mod log; use log::*;

// entry. "system" defines the calling convention
#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(handle: HINSTANCE, call_reason: DWORD, _: LPVOID) -> bool {
    match call_reason {
        DLL_PROCESS_ATTACH => attach(),
        DLL_PROCESS_DETACH => (),
        _ => (),
    }
    true
}

// MARK: Actual code below
unsafe fn attach() { unsafe { 
    MessageBoxA(None, s!("loaded"), s!("spearman.dll"), Default::default());
    AllocConsole();
    info!("yap");
};}