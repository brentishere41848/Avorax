use anyhow::Result;
use std::path::PathBuf;

pub fn program_data_dir() -> PathBuf {
    if let Ok(path) = std::env::var("AVORAX_DATA_DIR") {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    {
        if let Ok(program_data) =
            std::env::var("ProgramData").or_else(|_| std::env::var("PROGRAMDATA"))
        {
            return PathBuf::from(program_data).join("Avorax");
        }
    }
    std::env::temp_dir().join("Avorax")
}

pub fn update_logs_dir() -> PathBuf {
    program_data_dir().join("updates").join("logs")
}

pub fn write_update_log(name: &str, message: &str) -> Result<PathBuf> {
    let dir = update_logs_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    std::fs::write(&path, message)?;
    Ok(path)
}
