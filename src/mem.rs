// mem.rs: pattern scanning and function patching

use crate::x64::*;
use crate::{
    val::{NOP, TARGET},
    win::{Modu, find_module},
};
use ilhook::x64::{CallbackOption, HookFlags, HookType, Hooker, Registers};
use std::sync::atomic::AtomicU8;
use std::{
    ptr, slice,
    sync::atomic::{AtomicPtr, Ordering::SeqCst},
};

pub unsafe fn patch_sigcheck() {
    info!("Patching SIGCHECK...");
    let sigcheck = scaneth("85 C0 0F 94 C0 EB 02 32 C0 4C 8D 9C 24 60 02 00 00");
    sigcheck.expect_one();
    sigcheck.patch(&[
        0x85, 0xC0, NOP, 0xB0, 0x01, // mov al, 1
        0xEB, 0x02, 0xB0, 0x01, // mov al, 1
        0x4C, 0x8D, 0x9C, 0x24, 0x60, 0x02, 0x00, 0x00,
    ]);
}

static REGISTER_THAT_HOLDS_META: AtomicU8 = AtomicU8::new(0);

pub unsafe fn patch_protmem() {
    // ---- finding KiUserDispatcher_In_C ----
    info!("Finding KiUserDispatcher_In_ASM...");
    let ki_asm_mid = scaneth(
        "50 53 51 52 57 56 41 50 41 51 41 52 41 53 41 54 41 55", // push rax; push rbx; push rcx; push rdx; push rdi; push rsi; push r8; push r9; push r10; push r11; push r12; push r13; push r14; push r15; push rbp
    );
    ki_asm_mid.expect_one();
    good!("KiUserDispatcher_In_ASM @ ~0x{:X}", ki_asm_mid.first().unwrap() as usize);

    info!("Finding KiUserDispatcher_In_C...");
    let ki_in_c_call = ki_asm_mid.within("E8", 0x50).first().unwrap();
    let ki_in_c = where_is_E8call_going(ki_in_c_call);
    good!("KiUserDispatcher_In_C @ 0x{:X}", ki_in_c as usize);

    let e8s = scan("E8", ki_in_c as _, 7336).filter(|addr| {
        // prevent silent crash from scanning unmapped memory.
        // this suggests the e8s are probably real call instructions.
        // they at least point to valid reliccardinal memory
        is_real_memory(where_is_E8call_going(addr as _))
    });
    // ---- finding callsite of BNetSec::ProtMem::enter() ----
    info!("Finding KiUserDispatcher_In_C :: callsite of BNetSec::ProtMem::enter()...");
    let enter_or_exit_e8 = e8s.filter(|addr| {
        let place = where_is_E8call_going(addr as _);
        let is_ProtMem_enter_prologue = scan("48 85 D2 0F 84", place as _, 5).one(); // test rdx, rdx; jz

        is_ProtMem_enter_prologue
    });
    enter_or_exit_e8.expect_n(1);
    let enter_e8 = enter_or_exit_e8.first_as_x64query().unwrap();
    let callsite_of_enter = enter_e8.first().unwrap() as usize;

    good!("callsite of BNetSec::ProtMem::enter() @ 0x{:X}", callsite_of_enter);

    // ---- finding which register stores _DynFHMeta ----
    info!("Finding the register that stores _DynFHMeta...");
    info!("Searching for previous mov instructions...");
    let mut movs = enter_e8.within("8B", -10);
    movs = movs.filter(|addr| {
        let triplet_addr = addr - 1;
        let triplet: [u8; 3] = slice::from_raw_parts(triplet_addr as *mut u8, 3).try_into().unwrap();
        let res = mov_rdx_reg_WHICHREG(triplet);
        res.is_some()
    });
    movs.expect_one();
    let triplet_addr = movs.first().unwrap().offset(-1);
    let triplet: [u8; 3] = slice::from_raw_parts(triplet_addr, 3).try_into().unwrap();
    let reg = mov_rdx_reg_WHICHREG(triplet).unwrap();
    REGISTER_THAT_HOLDS_META.store(reg as _, SeqCst);
    good!("_DynFHMeta register is {:?}.", reg);

    // ---- finding _PROTDR decrypted place ----
    info!("Finding KiUserDispatcher_In_C :: _PROTDR decrypted place...");
    let jmpstub_e8s = e8s.filter(|addr| {
        let place = where_is_E8call_going(addr as _);

        let is_indirectjmp_stub = scan("FF 25", place as _, 2).one();

        is_indirectjmp_stub
    });
    // could filter e8s even more, ensuring that its definitely memcpy by resolving it from vcruntime and comparing the FF25[] address to vcruntime memcpy
    jmpstub_e8s.expect_one();
    let memcpy = jmpstub_e8s.first().unwrap();
    let decryption_complete = scan("?? 80 ?? 17", memcpy, 140);
    decryption_complete.expect_one();
    let decrypted = decryption_complete.first().unwrap() as usize;
    good!("_PROTDR decrypted place @ 0x{:X}", decrypted);

    // ---- hook ----
    info!("[Hook] Hooking KiUserDispatcher_In_C at the place _PROTDR is decrypted.");
    match Hooker::new(decrypted, HookType::JmpBack(ki_hook), CallbackOption::None, 0, HookFlags::empty()).hook() {
        Err(e) => error!("[Hook] Failed to hook enter: {}.", e),
        Ok(hook) => {
            good!("[Hook] Successfully hooked enter.");
            core::mem::forget(hook); // never unhook
        }
    }
}

unsafe extern "win64" fn ki_hook(regs: *mut Registers, ori_func_ptr: usize) {
    let the_reg: Reg64 = std::mem::transmute(REGISTER_THAT_HOLDS_META.load(SeqCst));

    let DynFHMeta_ptr = read_reg(regs, the_reg) as *mut u8;

    let size = (DynFHMeta_ptr.add(0x00) as *const u64).read_unaligned();
    let rva = (DynFHMeta_ptr.add(0x20) as *const u64).read_unaligned();

    // we can only patch DFH (isNextBucketValid_PROTDR) while it is unencrypted, because of new _PROTDR protection.
    check_for_and_patch_dfh(rva as _, size as usize);
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
    // info!("[Hook] Scanning for DFH.");

    let dfh1 = scan(
        // normal, like in build Yue Fei's Legacy
        concat!(
            "0f 95 c1 ", // setne  cl
            "0f 94 c0 ", // sete   al
            "88 4e 21",  // mov    BYTE PTR [rsi+0x21],cl
        ),
        start_of_decrypted_region,
        length_of_decrypted_region,
    );
    let dfh2 = scan(
        // reverse order, like in build 2026-11-09
        concat!(
            "0f 94 c0 ", // sete   al
            "0f 95 c1 ", // setne  cl
            "88 4e 21",  // mov    BYTE PTR [rsi+0x21],cl
        ),
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
        crate::on_dfh_patched();
    } else {
        // info!("Wasted {}ms scanning for isNextBucketValid_PROTDR", (dfh1.wasted + dfh2.wasted).as_millis())
    }
}

static MODU_BASE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static MODU_SIZE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

pub unsafe fn scaneth(PATTERN: &str) -> x64Query {
    scan(PATTERN, MODU_BASE.load(SeqCst), MODU_SIZE.load(SeqCst) as usize)
}

pub unsafe fn is_real_memory(addr: usize) -> bool {
    let base = MODU_BASE.load(SeqCst) as usize;
    let size = MODU_SIZE.load(SeqCst) as usize;
    return addr >= base && addr < base + size;
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
