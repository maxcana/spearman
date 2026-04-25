use std::io::Write;
use colored::ColoredString;

pub fn log(level: ColoredString, msg: &str) {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "[{}] {}", level, msg);
}

#[macro_export] macro_rules! info { ($($arg:tt)*) => { log("INFO".into(), &format!($($arg)*)) } }
#[macro_export] macro_rules! error { ($($arg:tt)*) => { log("ERROR".red(), &format!($($arg)*)) } }
