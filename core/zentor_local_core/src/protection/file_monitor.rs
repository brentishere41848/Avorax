#![allow(dead_code)]

pub struct FileMonitor;

impl FileMonitor {
    pub fn capability() -> &'static str {
        "selectedPathWatch"
    }
}
