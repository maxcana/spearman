// spy.rs: spies on the warnings.log file

use std::{path::PathBuf, time::Duration};

fn get_log_path() -> Result<PathBuf, u64> {
    let userdir = match std::env::var("USERPROFILE") {
        Ok(p) => p,
        Err(_) => {
            error!("Failed to get %USERPROFILE% environment variable. Cannot determine warnings.log path.");
            return Err(1);
        }
    };
    Ok(PathBuf::from(userdir).join("Documents").join("My Games").join("Age of Empires IV").join("warnings.log"))
}

pub fn clear_log() -> Result<(), u64> {
    let log_path = match get_log_path() {
        Ok(p) => p,
        Err(e) => return Err(e)
    };
    std::fs::write(log_path, "").map_err(|_| 2)
}

pub unsafe fn spy() {
    let log_path = match get_log_path() {
        Ok(p) => p,
        Err(_) => {
            error!("Failed to determine warnings.log path. Spy cannot run."); return
        }
    };

    info!("Starting spy on {}.", log_path.display());
    
    let mut lines_read: u64 = 0;
    loop {
        match std::fs::read_to_string(&log_path) {
            Ok(contents) => {
                info!("Spying...");
                if contents.contains("Loading step: [Localization]") {
                    info!("Detected localization step.");
                    unsafe { crate::on_archives_loaded(); }
                    break;
                }
            }
            Err(_) => {
                error!("Spy failed to read warnings.log.");
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}