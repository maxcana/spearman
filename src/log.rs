use std::io::Write;
use colored::{ColoredString, Colorize};

pub fn log(level: &str, msg: &str) {
    let left: ColoredString =
        match level {
            "INFO" => "[INFO]".into(),
            "ERROR" => "[ERROR]".red(),
            "FATAL" => " FATAL ".white().on_red(),
            _ => "[UNKNOWN]".into()
        };

    let mut out = std::io::stdout();
    let _ = writeln!(out, "{} {}", left, msg);
}

macro_rules! info { ($($arg:tt)*) => { log("INFO", &format!($($arg)*)) } }
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