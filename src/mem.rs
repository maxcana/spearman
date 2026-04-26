use std::{default, ptr, str};

use winapi::um::{
    processthreadsapi::GetCurrentProcess,
    psapi::{EnumProcessModules, GetModuleBaseNameA, GetModuleInformation, MODULEINFO}, winnt::LPSTR,
};
use winapi::{ctypes::c_void, shared::minwindef::HMODULE};

#[macro_use]
use crate::log;
pub struct Modu {
    pub hmodule: HMODULE,
    pub info: MODULEINFO
}

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