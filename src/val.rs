// constant values

use std::os::raw::c_int;

pub const PATTERN: [u8; 47] = [
	0x84, 0xc0, 0x74, 0x5c, 0x48, 0x8b, 0x86, 0x38, 0x04, 0x00, 0x00, 0x48, 0x8b, 0x48, 0x10, 0x8b,
	0x96, 0x18, 0x03, 0x00, 0x00, 0x8b, 0x41, 0x1c, 0x03, 0x41, 0x18, 0x3b, 0xc2, 0x77, 0x41, 0x8b,
	0x41, 0x24, 0x03, 0x41, 0x20, 0x3b, 0xc2, 0x77, 0x37, 0x83, 0x7e, 0x30, 0xfe, 0x74, 0x31
];

pub const REPLACEMENT: [u8; 47] = [
	0xC7, 0x46, 0x30, 0xFF, 0xFF, 0xFF, 0xFF, // mov dword [rsi+0x30], 0xffffffff
    0xB0, 0x01, // mov al, 1
    //TODO: this is not a complete patch. i missed some variable, causing the game to think official archives are corrupt XD.
    NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
    NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP
];

/// when this dll is loaded we assume the code has been unpacked
pub const PATCH_AT_DLL: &str = "devobj.dll";

pub const TARGET: &str = "RelicCardinal.exe";

pub const VERSION_DLL_NAME: &str = "version_orig.dll";

// opcode
pub const NOP: u8 = 0x90;

// windows
pub const THREAD_PRIORITY_TIME_CRITICAL: c_int = 15;
pub const THREAD_PRIORITY_NORMAL: c_int = 0;