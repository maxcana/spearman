// win.rs: wrapper for windows API functions

use std::{ffi::CString, ptr, str, sync::{OnceLock, atomic::{AtomicPtr, Ordering::SeqCst}}, time};

use ilhook::x64::{CallbackOption, HookFlags, HookType, Hooker, Registers};
use winapi::{um::{
    processthreadsapi::*, psapi::{EnumProcessModules, GetModuleBaseNameA, GetModuleInformation, MODULEINFO}, wincon::GetConsoleWindow, winnt::{LPSTR}
}};
use winapi::{ctypes::c_void, shared::minwindef::HMODULE};
use windows::{Win32::{System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA}}, core::{PCSTR, s}};

use crate::val::VERSION_DLL_NAME;
#[macro_use]
use crate::{log, val::PATCH_AT_DLL};
pub struct Modu {
    pub hmodule: HMODULE,
    pub info: MODULEINFO
}

// MARK: find_module
// HMODULE = u64
/// Find module and its info by name. Searches up to 1000 modules under the process this dll is attached to.
pub unsafe fn find_module(target: &str) -> Result<Modu, u8> { unsafe {
    info!("Searching for target: {}.", target);
    let EIGHT = std::mem::size_of::<HMODULE>() as u32;

    let mut mods: [HMODULE; 1000] = [0 as HMODULE; 1000];
    let mut lpcb_needed: u32 = 0;
    let p = GetCurrentProcess();
    
    if EnumProcessModules(p,  mods.as_mut_ptr(), 1000 * EIGHT, &mut lpcb_needed) == 0 { error!("Failed to call EnumProcessModules."); return Err(1) }
    for modu in mods[0..{(lpcb_needed / EIGHT) as usize}].iter().copied() {
        if modu.is_null() { continue; }
        let mut name = [0u8; 256];
        
        let len: u32 = GetModuleBaseNameA(p, modu, name.as_mut_ptr() as LPSTR, 256);
        if len != 0 {
            let namestr: &str = str::from_utf8(&name[0..len as usize]).unwrap_or("");
            info!("Checking module {}.", namestr);
            if namestr.eq_ignore_ascii_case(target) {
                // found module, get its info
                let mut info = MODULEINFO{lpBaseOfDll: ptr::null_mut(), SizeOfImage: 0, EntryPoint: ptr::null_mut()};
                if GetModuleInformation(p, modu, &mut info, std::mem::size_of::<MODULEINFO>() as u32) != 0 {
                    return Ok(Modu {
                        hmodule: modu,
                        info: info
                    })
                } else {
                    error!("GetModuleInformation failed."); return Err(3)
                }
            }
        }
    }
    error!("Searched through {} modules; failed to find {}.", lpcb_needed / EIGHT, target); Err(2)
}}







// MARK: LdrRegisterDllNotification

// secret undocumented LdrRegisterDllNotification tech
// because its undocumented its not part of winapi crate so we are gonna have to make the typedefs and find it in ntdll ourselves
// https://learn.microsoft.com/en-us/windows/win32/devnotes/ldrregisterdllnotification

// typedefs
    type LdrDllNotificationFn = unsafe extern "system" fn(notification_reason: u32, notification_data: *const LDR_DLL_NOTIFICATION_DATA, context: *mut c_void);
    const LDR_DLL_NOTIFICATION_REASON_LOADED: u32 = 1; const LDR_DLL_NOTIFICATION_REASON_UNLOADED: u32 = 2;
    #[repr(C)] struct UNICODE_STRING { Length: u16, MaximumLength: u16, Buffer: *const u16}
    #[repr(C)] #[derive(Copy, Clone)] struct LDR_DLL_LOADED_NOTIFICATION_DATA { Flags: u32, FullDllName: *const UNICODE_STRING, BaseDllName: *const UNICODE_STRING, DllBase: *mut c_void, SizeOfImage: u32 }
    #[repr(C)] #[derive(Copy, Clone)] struct LDR_DLL_UNLOADED_NOTIFICATION_DATA { Flags: u32, FullDllName: *const UNICODE_STRING, BaseDllName: *const UNICODE_STRING, DllBase: *mut c_void, SizeOfImage: u32 }

    #[repr(C)]
    union LDR_DLL_NOTIFICATION_DATA {
        Loaded: LDR_DLL_LOADED_NOTIFICATION_DATA,
        Unloaded: LDR_DLL_UNLOADED_NOTIFICATION_DATA,
    }
// end typedefs

/// global var (cookie to unregister callback on dll detach)
// AtomicPtr guarantees 1 instruction modification
static COOKIE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

static PAST: OnceLock<time::Instant> = OnceLock::new(); // global instant

/// calls crate::on_dll() when PATCH_AT_DLL loads
pub unsafe fn register_dll_hook() { unsafe {
    let ntdll = GetModuleHandleA(s!("ntdll.dll")).unwrap();
    let LdrRegisterDllNotification: unsafe extern "system" fn(u32, LdrDllNotificationFn, *mut c_void, *mut *mut c_void) -> i32 = std::mem::transmute(GetProcAddress(ntdll, s!("LdrRegisterDllNotification")).unwrap());
    
    // we are supposed to use this cookie to unregister the callback with LdrUnregisterDllNotification when our dll is detached. ill do that if i feel like it
    let mut cookie = std::ptr::null_mut();

    LdrRegisterDllNotification(0, dll_callback, std::ptr::null_mut(), &mut cookie);
    COOKIE.store(cookie, SeqCst); // SeqCst = no compiler reordering operaions
    PAST.set(time::Instant::now()).unwrap();
}}

unsafe extern "system" fn dll_callback(reason: u32, data: *const LDR_DLL_NOTIFICATION_DATA, _context: *mut c_void) { unsafe {
    if reason != LDR_DLL_NOTIFICATION_REASON_LOADED { return }

    let name_us = &*(*data).Loaded.BaseDllName;
    let name = String::from_utf16_lossy( std::slice::from_raw_parts(name_us.Buffer, (name_us.Length / 2) as usize) ).to_lowercase();

    if name == PATCH_AT_DLL {
        info!("{} loaded in {}ms.", PATCH_AT_DLL, PAST.get().unwrap().elapsed().as_millis());
        crate::on_dll();
    }
}}

// MARK: Hooking
unsafe extern "win64" fn false_gcw(regs: *mut Registers, ori_func_ptr:usize, _:usize) -> usize { info!("[Hook] GetConsoleWindow called, returning 0."); 0 }
pub unsafe fn hook_console() { unsafe {
    info!("[Hook] Hooking GetConsoleWindow.");
    match Hooker::new(
        GetConsoleWindow as usize,
        HookType::Retn(false_gcw),
        CallbackOption::None,
        0,
        HookFlags::empty()
    ).hook() {
        Err(e) => error!("[Hook] Failed to hook GetConsoleWindow: {}.", e),
        Ok(_) => good!("[Hook] Successfully hooked GetConsoleWindow.")
    }
}}

// MARK: Forwarder
// interacting with the windows API through rust is incredibly painful

/// global var: handle to original dll
static H_ORIGDLL: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(ptr::null_mut());

pub unsafe fn load_orig_dll() { unsafe {
    let name_c = CString::new(VERSION_DLL_NAME).unwrap();
    match LoadLibraryA(PCSTR(name_c.as_ptr() as _)) {
        Ok(handle) => H_ORIGDLL.store(handle.0, SeqCst),
        Err(e) => die!("[FWD] Failed to find {}. Ensure that it is in the game folder; next to this dll.", VERSION_DLL_NAME)
    }
}}
/// get the address of an export of the dll
pub unsafe fn get_fn_addr(name: &str) -> Result<unsafe extern "system" fn() -> isize, u64> { unsafe{
    let name_c: CString = CString::new(name).unwrap();
    match GetProcAddress(windows::Win32::Foundation::HMODULE(H_ORIGDLL.load(SeqCst)), PCSTR(name_c.as_ptr() as _)) {
        Some(f) => Ok(f),
        None => { error!("[FWD] Can't find address of {} in {}.", name, VERSION_DLL_NAME); Err(1) }
    }
}}

/// defines a function mimicking the original dll's function
/// 
/// ensure you call load_orig_dll to set up the handle before said function is called for the first time
// note to self: you dont get hover documentation inside a macro.
macro_rules! forward { ($name:ident) => {
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn $name() { unsafe{
        match get_fn_addr(stringify!($name)) {
            Ok(addr) => {
                // transmute means: just convert the type please, idc about the type system
                info!("[FWD] Forwarding {} call to {} @{:x}", stringify!($name), VERSION_DLL_NAME, addr as usize);
                let f: unsafe extern "system" fn() = std::mem::transmute(addr);
                f();
            },
            Err(_) => {info!("[FWD] Failed to forward {} call to {}. Address of function not found.", stringify!($name), VERSION_DLL_NAME); return}
        };
    }}
}}