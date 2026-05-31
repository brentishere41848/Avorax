use anyhow::Result;

pub fn stop_service(name: &str) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("sc.exe").args(["stop", name]).status();
    }
    Ok(())
}

pub fn start_service(name: &str) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("sc.exe").args(["start", name]).status();
    }
    Ok(())
}
