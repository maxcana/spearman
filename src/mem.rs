// mem.rs: pattern scanning and function patching

use crate::x64::*;
use crate::{
    val::{NOP, TARGET},
    win::{Modu, find_module},
};
use ilhook::x64::{CallbackOption, HookFlags, HookType, Hooker, Registers};
use std::{
    ptr,
    sync::{
        atomic::{AtomicPtr, Ordering::SeqCst},
    },
};

pub unsafe fn patch_shit() {
    info!("Patching SIGCHECK...");
    let sigcheck = scaneth(&[0x85, 0xC0, 0x0F, 0x94, 0xC0, 0xEB, 0x02, 0x32, 0xC0, 0x4C, 0x8D, 0x9C, 0x24, 0x60, 0x02, 0x00, 0x00]);
    sigcheck.expect_one();
    sigcheck.patch(&[
        0x85, 0xC0, NOP, 0xB0, 0x01, // mov al, 1
        0xEB, 0x02, 0xB0, 0x01, // mov al, 1
        0x4C, 0x8D, 0x9C, 0x24, 0x60, 0x02, 0x00, 0x00,
    ]);

    // [
    //  F0 48 0F C1 ?? ?? (lock xadd [rdi?+30h?], rax)
    //  ?? 03 ?? (add A, B)
    //  48 83 F8 02 (cmp rax, 2)
    // ]
    info!("Finding BNetSec::ProtMem::soften...");
    let soften_mid = scaneth(&[0xF0, 0x48, 0x0F, 0xC1]).within(&[0x48, 0x83, 0xF8, 0x02], 10).within(&[0x03], -3);
    soften_mid.expect_one();

    let soften = soften_mid.within(
        &[
            0x48, 0x8B, 0xC4, // move rax, rsp - first instruction of subroutine
        ],
        -0xE4 * 2,
    );
    soften.expect_one();

    let Soften = soften.first().unwrap();

    info!("[Hook] Hooking BNetSec::ProtMem::soften.");
    match Hooker::new(Soften as usize, HookType::Retn(false_soften), CallbackOption::None, 0, HookFlags::empty()).hook() {
        Err(e) => error!("[Hook] Failed to hook soften: {}.", e),
        Ok(_) => good!("[Hook] Successfully hooked soften."),
    }
}

unsafe extern "win64" fn false_soften(regs: *mut Registers, orig_func_ptr: usize, _: usize) -> usize {
    let orig_soften: unsafe extern "win64" fn(addr: u64, flag: u64) = core::mem::transmute(orig_func_ptr);
    orig_soften((*regs).rcx, (*regs).rdx);
    check_for_and_patch_dfh((*regs).rcx);
    0 // rax = 0 (doesn't matter since `void`, Hooker expects it, volatile reg. so this is ok)
}

static mut ALREADY_PATCHED_OUT_DFH: bool = false;

unsafe fn check_for_and_patch_dfh(base_addr: u64) {
    if ALREADY_PATCHED_OUT_DFH {
        return;
    }
    info!("[Hook] BNetSec::ProtMem::soften was called, scanning for DFH.");

    let dfh1 = scan(
        &[
            // normal, like in build Yue Fei's Legacy
            0x0f, 0x95, 0xc1, // setne  cl
            0x0f, 0x94, 0xc0, // sete   al
            0x88, 0x4e, 0x21, // mov    BYTE PTR [rsi+0x21],cl
        ],
        base_addr as *mut u8,
        100000,
    );
    let dfh2 = scan(
        &[
            // reverse order, like in build 2026-11-09
            0x0f, 0x94, 0xc0, // sete   al
            0x0f, 0x95, 0xc1, // setne  cl
            0x88, 0x4e, 0x21, // mov    BYTE PTR [rsi+0x21],cl
        ],
        base_addr as *mut u8,
        100000,
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
    } else {
        info!("Wasted {}ms scanning for isNextBucketValid_PROTDR", dfh1.ms + dfh2.ms)
    }
}

static MODU_BASE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static MODU_SIZE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

pub unsafe fn scaneth(PATTERN: &[u8]) -> x64Query {
    scan(PATTERN, MODU_BASE.load(SeqCst), MODU_SIZE.load(SeqCst) as usize)
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
