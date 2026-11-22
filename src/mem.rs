// mem.rs: pattern scanning and function patching

use crate::x64::*;
use crate::{
    val::{NOP, TARGET},
    win::{Modu, find_module},
};
use ilhook::x64::{CallbackOption, HookFlags, HookType, Hooker, Registers};
use std::{
    ptr,
    sync::atomic::{AtomicPtr, Ordering::SeqCst},
};

unsafe fn patch_sigcheck() {
    info!("Patching SIGCHECK...");
    let sigcheck = scaneth(&[0x85, 0xC0, 0x0F, 0x94, 0xC0, 0xEB, 0x02, 0x32, 0xC0, 0x4C, 0x8D, 0x9C, 0x24, 0x60, 0x02, 0x00, 0x00]);
    sigcheck.expect_one();
    sigcheck.patch(&[
        0x85, 0xC0, NOP, 0xB0, 0x01, // mov al, 1
        0xEB, 0x02, 0xB0, 0x01, // mov al, 1
        0x4C, 0x8D, 0x9C, 0x24, 0x60, 0x02, 0x00, 0x00,
    ]);
}

pub unsafe fn patch_shit() {
    /* middle part of enter
        - 33 D2           xor edx, edx        (bool false — ABI-pinned, always here)
        - E8 ?? ?? ?? ??  call soften         (relative offset varies per build)
        - ?? 8B ?? 10     mov rXX,[rYY+0x10]  (REX byte and both regs vary)
        - 80 ?? 19 00     cmp byte[r+0x19],0  (/7 opcode stays, ModRM reg field varies)
        - 74 ??           jz short            (displacement varies)
        - ?? 8B ?? 08     mov rXX,[rYY+0x08]  (follow sibling — same variation)
        - EB ??           jmp short           (back into walk loop)
    */
    info!("Finding BNetSec::ProtMem::enter...");

    let mut enter = scaneth(&[
        0x48, 0x85, 0xD2, 0x0F, 0x84, // test rdx, rdx; jz = start of ProtMem::enter
    ])
    .within_wild("33 D2 E8 ?? ?? ?? ?? ?? 8B ?? 10 80 ?? 19 00 74 ?? ?? 8B ?? 08 EB ??", 0x100); // callsite of BNetSec::ProtMem::soften
    
    // ensure we are calling `soften`
    enter.filter(|addr| {
        let e8 = addr + 2;
        
        let soften = where_is_E8call_going(e8 as _);
        // soften has the pattern:
        // [
        //  F0 ?? 0F C1 ?? 30 (lock xadd [rdi?+30h], ??)
        //  ?? 03 ?? (add A, B)
        //  48 83 F8 02 (cmp rax, 2)
        // ]
        scan_wild("F0 ?? 0F C1 ?? 30 ?? 03 ?? ?? 83 ?? ??", soften as _, 300).one()
    });

    // go back to start
    enter = enter.within(&[
        0x48, 0x85, 0xD2, 0x0F, 0x84, // test rdx, rdx; jz = start of ProtMem::enter
    ], -0x100);

    enter.expect_one();

    let Enter = enter.first().unwrap();

    info!("[Hook] Hooking BNetSec::ProtMem::enter.");
    match Hooker::new(Enter as usize, HookType::Retn(false_enter), CallbackOption::None, 0, HookFlags::empty()).hook() {
        Err(e) => error!("[Hook] Failed to hook enter: {}.", e),
        Ok(_) => good!("[Hook] Successfully hooked enter."),
    }
}

unsafe extern "win64" fn false_enter(regs: *mut Registers, orig_func_ptr: usize, _: usize) -> usize {
    let orig_enter: unsafe extern "win64" fn(addr: u64, flag: u64) = core::mem::transmute(orig_func_ptr);
    orig_enter((*regs).rcx, (*regs).rdx);

    let DynFHMeta_ptr = (*regs).rdx as *mut u8;

    let size = *(DynFHMeta_ptr.add(0x00) as *const u64);
    let rva = *(DynFHMeta_ptr.add(0x20) as *const u64);
    info!("[Hook] BNetSec::ProtMem::enter decrypted @ RVA 0x{:X}, size {}", rva, size);

    // we can only patch DFH (isNextBucketValid_PROTDR) while it is unencrypted, because of new _PROTDR protection.
    check_for_and_patch_dfh(rva as _, size as usize);
    0 // rax = 0 (doesn't matter since `void`, ilhook expects it. volatile reg, so this is ok)
}

static mut ALREADY_PATCHED_OUT_DFH: bool = false;

// "DFH"="Data-flow-hashing" anti-tamper protection. this is an archaic term guessed from Aegis_RelicCardinal.log.
// that "DFH" most likely really refers to "Delayed Function Hiding"
// the canonical, correct name for "DFH" is BNetSec::TamperedMemoryDetection::isNextBucketValid_PROTDR
// but i still use DFH since it's engrained into me
unsafe fn check_for_and_patch_dfh(start_of_decrypted_region: *mut u8, length_of_decrypted_region: usize) {
    if ALREADY_PATCHED_OUT_DFH {
        return;
    }
    info!("[Hook] Scanning for DFH.");

    let dfh1 = scan(
        &[
            // normal, like in build Yue Fei's Legacy
            0x0f, 0x95, 0xc1, // setne  cl
            0x0f, 0x94, 0xc0, // sete   al
            0x88, 0x4e, 0x21, // mov    BYTE PTR [rsi+0x21],cl
        ],
        start_of_decrypted_region,
        length_of_decrypted_region,
    );
    let dfh2 = scan(
        &[
            // reverse order, like in build 2026-11-09
            0x0f, 0x94, 0xc0, // sete   al
            0x0f, 0x95, 0xc1, // setne  cl
            0x88, 0x4e, 0x21, // mov    BYTE PTR [rsi+0x21],cl
        ],
        start_of_decrypted_region,
        length_of_decrypted_region,
    );

    if dfh1.locs.len() > 0 || dfh2.locs.len() > 0 {
        if dfh1.locs.len() > 0 {
            dfh1.expect_one();
            dfh1.patch(&[
                0xB0, 0x01, NOP, // mov al, 1
                0xB1, 0x00, NOP, // mov cl, 0
                0x88, 0x4e, 0x21, // mov    BYTE PTR [rsi+0x21],cl
            ]);
        }
        if dfh2.locs.len() > 0 {
            dfh2.expect_one();
            dfh2.patch(&[
                0xB0, 0x01, NOP, // mov al, 1
                0xB1, 0x00, NOP, // mov cl, 0
                0x88, 0x4e, 0x21, // mov    BYTE PTR [rsi+0x21],cl
            ]);
        }

        ALREADY_PATCHED_OUT_DFH = true;
        good!("BNetSec::TamperedMemoryDetection::isNextBucketValid_PROTDR patched out successfully.");
        patch_sigcheck();
    } else {
        info!("Wasted {}ms scanning for isNextBucketValid_PROTDR", (dfh1.wasted + dfh2.wasted).as_millis())
    }
}

static MODU_BASE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static MODU_SIZE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

pub unsafe fn scaneth(PATTERN: &[u8]) -> x64Query {
    scan(PATTERN, MODU_BASE.load(SeqCst), MODU_SIZE.load(SeqCst) as usize)
}
pub unsafe fn scaneth_wild(PATTERN: &str) -> x64Query {
    scan_wild(PATTERN, MODU_BASE.load(SeqCst), MODU_SIZE.load(SeqCst) as usize)
}

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
    info!("Base address:  0x{:X}", modu.info.lpBaseOfDll as u64);
    info!("Size of image: {} B", modu.info.SizeOfImage);
    info!("-----------------");

    MODU_BASE.store(modu.info.lpBaseOfDll as _, SeqCst);
    MODU_SIZE.store(modu.info.SizeOfImage as _, SeqCst);
}
