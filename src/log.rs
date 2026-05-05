use std::{io::{BufRead, Write}, ptr, sync::atomic::{AtomicBool, Ordering::SeqCst}, thread, time::Duration};
use colored::{ColoredString, Colorize};
use winapi::um::{consoleapi::{GetConsoleMode, SetConsoleMode}, wincon::{ENABLE_VIRTUAL_TERMINAL_PROCESSING}};
use windows::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};

pub fn log(level: &str, msg: &str) {
    let mut out = std::io::stdout();

    let _ = match level {
        "INFO" =>       writeln!(out, "{} {}", "  YAP  ".black().on_bright_white(), msg),
        "SUCCESS" =>    writeln!(out, "{} {}", "SUCCESS".black().on_bright_green(), msg.bright_green()),
        "ERROR" =>      writeln!(out, "{} {}", " ERROR ".black().on_bright_red(), msg.bright_red()),
        "FATAL" =>      writeln!(out, "{} {}", " FATAL ".bright_white().on_red(), msg.bright_red()),
        _ =>            writeln!(out, "{} {}", "UNKNOWN".black().on_bright_purple(), msg),
    };
}

pub unsafe fn init_logger() { unsafe {
    // enable ANSI
    let handle = match GetStdHandle(STD_OUTPUT_HANDLE) {
        Ok(h) => h,
        Err(h) => {return;}
    };
    let mut mode = 0u32;
    GetConsoleMode(std::mem::transmute(handle), &mut mode);
    SetConsoleMode(std::mem::transmute(handle), mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING); // interpret ANSI escape sequences
    
    std::panic::set_hook(Box::new(|info| { 
        log("FATAL", &format!("PANIC: {}", info)); 
    }));
}}

macro_rules! info { ($($arg:tt)*) => { crate::log::log("INFO", &format!($($arg)*)) } }
macro_rules! good { ($($arg:tt)*) => { crate::log::log("SUCCESS", &format!($($arg)*)) } }
macro_rules! error { ($($arg:tt)*) => { crate::log::log("ERROR", &format!($($arg)*)) } }


//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||//

/// safe panic!() that doesn't terminate entire process
#[macro_export]
macro_rules! die {
    ($($arg:tt)*) => { crate::log::die_real(&format!($($arg)*)) }
}
pub fn die_real(msg: &str) -> ! {
    log("FATAL", msg);
        
    info!("Exiting in 10 seconds...");
    thread::sleep(Duration::from_secs(10));

    // exit just this thread, not the process
    unsafe { winapi::um::processthreadsapi::ExitThread(1); }
    unreachable!()
}
