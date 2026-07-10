#![allow(dead_code)]

pub struct ExecutionBlocker;

impl ExecutionBlocker {
    pub fn capability() -> &'static str {
        if cfg!(windows) {
            "postLaunchBlocking"
        } else {
            "monitorOnly"
        }
    }
}
