// constant values

pub const PATTERN: [u8; 6] = [0x83, 0x7E, 0x30, 0xFE, 0x74, 0x31];

/// when this dll is loaded we assume the code has been unpacked
pub const PATCH_AT_DLL: &str = "devobj.dll";

pub const TARGET: &str = "RelicCardinal.exe";