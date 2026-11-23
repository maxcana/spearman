// mem.rs: pattern scanning and function patching

use crate::x64::*;
use crate::{
    val::{NOP, TARGET},
    win::{Modu, find_cave_near, find_module},
};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use ilhook::x64::{CallbackOption, HookFlags, HookType, Hooker, Registers};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize};
use std::sync::{Mutex, OnceLock};
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

// MARK: patch_protmem
pub unsafe fn patch_protmem() {
    // ---- finding KiUserDispatcher_In_C ----
    info!("Finding KiUserDispatcher_In_ASM...");
    let ki_asm_mid = scaneth(
        "50 53 51 52 57 56 41 50 41 51 41 52 41 53 41 54 41 55", // push rax; push rbx; push rcx; push rdx; push rdi; push rsi; push r8; push r9; push r10; push r11; push r12; push r13; push r14; push r15; push rbp
    );
    ki_asm_mid.expect_one();
    good!("KiUserDispatcher_In_ASM @ ~0x{:X}", ki_asm_mid.locs[0]);

    info!("Finding KiUserDispatcher_In_C...");
    let ki_in_c_call = ki_asm_mid.within("E8", 0x50).locs[0];
    let ki_in_c = where_is_E8call_going(ki_in_c_call as _);
    good!("KiUserDispatcher_In_C @ 0x{:X}", ki_in_c as usize);

    let e8s = scan("E8", ki_in_c as _, 7336).filter(|addr| {
        // prevent silent crash from scanning unmapped memory.
        // this suggests the e8s are probably real call instructions.
        // they at least point to valid reliccardinal memory
        is_real_memory(where_is_E8call_going(addr as _))
    });
    // ---- finding BNetSec::ProtMem::leave() ----
    info!("Finding KiUserDispatcher_In_C :: callsite of BNetSec::ProtMem::leave()...");
    let enter_or_exit_e8 = e8s.filter(|addr| {
        let place = where_is_E8call_going(addr as _);
        let is_ProtMem_enter_prologue = scan("48 85 D2 0F 84", place as _, 5).one(); // test rdx, rdx; jz

        is_ProtMem_enter_prologue
    });
    enter_or_exit_e8.expect_n(2);
    let leave = where_is_E8call_going(enter_or_exit_e8.locs[1] as _);

    good!("callsite of BNetSec::ProtMem::leave() @ 0x{:X}", leave);

    // ---- cipher params ----

    // ---- [new] their hash fn: first E8 after the leave call ----
    let mut hash_e8 = scan("E8", (enter_or_exit_e8.locs[1] + 5) as _, 0x40);
    hash_e8 = hash_e8.filter(|addr| {
        let suspect_fn = where_is_E8call_going(addr as _);
        if is_real_memory(suspect_fn) {
            let asm = peek_disassembly(suspect_fn, 0x200);
            let mut hashy_things: HashSet<Mnemonic> = vec![Mnemonic::Rol, Mnemonic::Xor, Mnemonic::Imul, Mnemonic::Bswap, Mnemonic::Shr, Mnemonic::Shl].into_iter().collect();
            for ins in asm {
                hashy_things.remove(&ins.mnemonic());
            }
            // all hashy things accounted for: super hashy
            return hashy_things.len() == 0
        }
        false
    });
    hash_e8.expect_one();
    let hash_fn = where_is_E8call_going(hash_e8.locs[0] as _);
    HASH_FN.store(hash_fn, SeqCst);
    good!("found hash function @ 0x{:X}", hash_fn);

    // ---- [new] materialization-complete point → cipher params ----
    let memcpy_callsite = e8s.filter(|addr| {
        let func = where_is_E8call_going(addr as _) as *mut u8;
        let s = scan("FF 25", func, 2);
        s.one()
    });
    memcpy_callsite.expect_one();

    let asm = peek_disassembly(memcpy_callsite.locs[0], 0x40);
    for (i, ins) in asm.iter().enumerate() {
        if !(ins.mnemonic() == Mnemonic::Xor && ins.op_kind(0) == OpKind::Register) {
            continue;
        }
        let xor = ins;

        let rax = xor.op0_register();

        let mov = asm[i + 1];
        if mov.mnemonic() == Mnemonic::Mov && mov.op1_kind() == OpKind::Immediate64 {
            let r8 = mov.op0_register();
            let imul = asm[i + 2];
            if imul.mnemonic() == Mnemonic::Imul && imul.op0_register() == rax && imul.op1_register() == r8 {
                // we found an XOR with a MOV and an IMUL right after it
                let key = xor.ip_rel_memory_address() as _;
                let mult = mov.immediate64();
                KEY_GLOBAL.store(key, SeqCst);
                MULT.store(mult, SeqCst);
                good!("found crypto constants: key=0x{:X}, mult=0x{:X}", key, mult);
                break;
            }
        }
        if i == asm.len() - 1 {
            die!("couldn't find crypto constants");
        }
    }

    // sanity: KEY_GLOBAL should be RVA 0x7C9F990 in this build; verify and warn on drift

    match Hooker::new(leave, HookType::Retn(leave_hook), CallbackOption::None, 0, HookFlags::empty()).hook() {
        Err(e) => error!("[Hook] Failed to hook BNetSec::ProtMem::leave(): {}.", e),
        Ok(hook) => {
            good!("[Hook] Successfully hooked BNetSec::ProtMem::leave().");
            core::mem::forget(hook) // never unhook
        }
    }
}

// MARK: leave_hook
static SEEN: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
static ALREADY_PATCHED_ISNEXTBUCKETVALID: AtomicBool = AtomicBool::new(false);

// crypto constants
static MULT: AtomicU64 = AtomicU64::new(0);
static KEY_GLOBAL: AtomicUsize = AtomicUsize::new(0); // address of the key qword
static HASH_FN: AtomicUsize = AtomicUsize::new(0);

unsafe extern "win64" fn leave_hook(regs: *mut Registers, ori_func_ptr: usize, _: usize) -> usize {
    // original leave(): mandatory for classic regions, no-op for the DynFH body.
    let orig_leave = core::mem::transmute::<usize, unsafe extern "win64" fn(usize, usize)>(ori_func_ptr);
    orig_leave((*regs).rcx as _, (*regs).rdx as _);

    if ALREADY_PATCHED_ISNEXTBUCKETVALID.load(SeqCst) {
        // already patched
        return 0;
    }

    let meta = (*regs).rdx as *mut u8;
    let meta_size = (meta.add(0x00) as *const u64).read_unaligned() as usize;
    let meta_rva = (meta.add(0x20) as *const u64).read_unaligned() as usize;

    info!("leave(): decrypted region rva=0x{:X} size={}", meta_rva, meta_size);

    // seen: each meta is decrypted & scanned exactly once, ever.
    let seen = SEEN.get_or_init(|| Mutex::new(HashSet::new()));
    if !seen.lock().unwrap().insert(meta as usize) {
        return 0;
    }
    let size = meta.cast::<u64>().read_unaligned() as usize;
    let keyval = (KEY_GLOBAL.load(SeqCst) as *const u64).read_unaligned();
    let mult = MULT.load(SeqCst);
    let mut plain = slice::from_raw_parts(meta.add(0x130), size).to_vec();
    dynfh_xor(&mut plain, keyval, mult); // decrypt shadow
    if !check_for_and_patch_isNextBucketValid_PROTDR(plain.as_mut_ptr(), plain.len()) {
        return 0; // wrong meta; never scanned again
    }

    let patched = plain.clone(); // keep the patched plaintext
    dynfh_xor(&mut plain, keyval, mult); // re-encrypt
    memwrite(meta.add(0x130), &plain); // 1) shadow: every future cycle is born patched
    // 2) live region, so THIS disarm's hash check sees bytes consistent with (3)
    let region = meta.add(0xA0).cast::<*const u8>().read_unaligned() as usize + meta.add(0x20).cast::<u64>().read_unaligned() as usize;
    memwrite(region as *mut u8, &patched);
    // 3) expected hash for every future check
    let hash = core::mem::transmute::<_, unsafe extern "win64" fn(*const u8, u64, u64) -> u64>(HASH_FN.load(SeqCst))(patched.as_ptr(), patched.len() as u64, 0);
    meta.add(0x18).cast::<u64>().write_unaligned(hash);

    ALREADY_PATCHED_ISNEXTBUCKETVALID.store(true, SeqCst);
    good!("isNextBucketValid_PROTDR shadow-patched; hash consistent.");
    0
}

// MARK: cipher
// Involution: E == D. key0 = (size ^ KEYVAL) * MULT, then key *= MULT per qword.
pub unsafe fn dynfh_xor(buf: &mut [u8], keyval: u64, mult: u64) {
    let mut key = (buf.len() as u64 ^ keyval).wrapping_mul(mult);
    for chunk in buf.chunks_exact_mut(8) {
        for (b, k) in chunk.iter_mut().zip(key.to_le_bytes()) {
            *b ^= k;
        }
        key = key.wrapping_mul(mult);
    }
    let len = buf.len();
    for b in &mut buf[len / 8 * 8..] {
        *b ^= key as u8;
        key >>= 8;
    }
}

// MARK: DFH patch
unsafe fn check_for_and_patch_isNextBucketValid_PROTDR(start_of_decrypted_region: *mut u8, length_of_decrypted_region: usize) -> bool {
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

        good!("BNetSec::TamperedMemoryDetection::isNextBucketValid_PROTDR patched out successfully.");
        crate::on_dfh_patched();
        true
    } else {
        // info!("Wasted {}ms scanning for isNextBucketValid_PROTDR", (dfh1.wasted + dfh2.wasted).as_millis())
        false
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
