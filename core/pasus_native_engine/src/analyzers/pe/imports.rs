use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportCategories {
    pub process_injection: u32,
    pub credential_access: u32,
    pub persistence: u32,
    pub network: u32,
    pub crypto: u32,
    pub process_manipulation: u32,
    pub service_control: u32,
    pub registry_autorun: u32,
    pub anti_debugging: u32,
}

pub fn categorize_imports(bytes: &[u8]) -> ImportCategories {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let count = |terms: &[&str]| -> u32 {
        terms
            .iter()
            .map(|term| text.matches(&term.to_ascii_lowercase()).count() as u32)
            .sum()
    };
    ImportCategories {
        process_injection: count(&["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]),
        credential_access: count(&["CredRead", "LsaEnumerate", "SamIConnect"]),
        persistence: count(&["RegSetValue", "CreateService", "TaskScheduler"]),
        network: count(&["WinHttp", "InternetOpen", "WSAStartup", "connect"]),
        crypto: count(&["CryptEncrypt", "BCrypt", "CryptAcquireContext"]),
        process_manipulation: count(&["OpenProcess", "TerminateProcess", "CreateProcess"]),
        service_control: count(&["OpenSCManager", "ControlService", "StartService"]),
        registry_autorun: count(&["CurrentVersion\\Run", "RunOnce"]),
        anti_debugging: count(&["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]),
    }
}
