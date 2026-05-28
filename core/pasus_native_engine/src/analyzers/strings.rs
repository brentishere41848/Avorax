use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StringIndicators {
    pub embedded_url_count: u32,
    pub embedded_ip_count: u32,
    pub suspicious_string_count: u32,
}

pub fn extract_indicators(bytes: &[u8]) -> StringIndicators {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let embedded_url_count = text.matches("http://").count() + text.matches("https://").count();
    let embedded_ip_count = text
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .filter(|part| {
            let pieces = part.split('.').collect::<Vec<_>>();
            pieces.len() == 4
                && pieces
                    .iter()
                    .all(|piece| piece.parse::<u8>().is_ok() && !piece.is_empty())
        })
        .count();
    let suspicious_terms = [
        "invoke-expression",
        "iex ",
        "frombase64string",
        "virtualalloc",
        "createremotethread",
        "writeprocessmemory",
        "reg add",
        "schtasks",
        "vssadmin delete",
        "shadowcopy delete",
        "start-process",
        "downloadstring",
    ];
    let suspicious_string_count = suspicious_terms
        .iter()
        .map(|term| text.matches(term).count() as u32)
        .sum();
    StringIndicators {
        embedded_url_count: embedded_url_count as u32,
        embedded_ip_count: embedded_ip_count as u32,
        suspicious_string_count,
    }
}
