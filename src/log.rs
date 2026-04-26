use std::io::Write;
use colored::{ColoredString, Colorize};

pub fn log(level: &str, msg: &str) {
    let mut out = std::io::stdout();

    let _ = match level {
        "INFO" =>       writeln!(out, "{} {}", " YAP ".black().on_white(), msg),
        "SUCCESS" =>    writeln!(out, "{} {}", " SUCCESS ".white().on_bright_green(), msg.bright_green()),
        "ERROR" =>      writeln!(out, "{} {}", " ERROR ".white().on_bright_red(), msg.bright_red()),
        "FATAL" =>      writeln!(out, "{} {}", " FATAL ".black().on_bright_red(), msg.bright_red()),
        _ =>            writeln!(out, "{} {}", " UNKNOWN ".black().on_bright_purple(), msg),
    };
}

macro_rules! info { ($($arg:tt)*) => { log("INFO", &format!($($arg)*)) } }
macro_rules! good { ($($arg:tt)*) => { log("SUCCESS", &format!($($arg)*)) } }
macro_rules! error { ($($arg:tt)*) => { log("ERROR", &format!($($arg)*)) } }


//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||//

/// safe panic!() that doesn't terminate entire process
#[macro_export]
macro_rules! die {
    ($($arg:tt)*) => { crate::log::die_real(&format!($($arg)*)) }
}
pub fn die_real(msg: &str) -> ! {
    log("FATAL", msg);
        
    info!("Press enter to exit...");
    // keep console alive
    let _ = std::io::stdin().read_line(&mut String::new());

    // exit just this thread, not the process
    unsafe { winapi::um::processthreadsapi::ExitThread(1); }
    unreachable!()
}