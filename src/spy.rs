// spy.rs: spies on the warnings.log file

use std::{io::{Read, Seek}, path::PathBuf, time::Duration};

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
    
    let mut bytes_read: u64 = 0;
    loop{
        if let Ok(mut file) = std::fs::File::open(&log_path) {
            file.seek(std::io::SeekFrom::Start(bytes_read)).ok();
            let mut new: String = "".to_owned();
            match file.read_to_string(&mut new) {
                Ok(n) => {
                    // iterate through new lines to figure out what's going on (not necessary, just makes the logs nicer)
                    bytes_read += n as u64;
                    let new_lines: Vec<&str> = new.split("\n").collect();
                    new_lines.clone().into_iter().enumerate().for_each(|(i, line)| {
                        let archive_path = line.split("age of empires iv\\").nth(1).unwrap_or("?.sga").split(".sga").nth(0).unwrap_or("?").to_owned() + ".sga";
                        let next_line: &str = if (i < new_lines.len() - 1) {new_lines[i + 1]} else {return};
                        if line.contains("ARC -- ") {
                            if(next_line.contains("corrupt")) {
                                error!("ARC -- {} failed.", archive_path)
                            } else {
                                good!("ARC -- {} passed.", archive_path)
                            }
                        }
                        if line.contains("Loading step: [Localization]") {
                            info!("Detected localization step.");
                            unsafe { crate::on_archives_loaded(); return; }
                        }
                    });
                },
                Err(_) => error!("Spy failed to read from warnings.log.")
            }
        } else { error!("Spy failed to open warnings.log.") };
        std::thread::sleep(Duration::from_millis(10));
    }
}