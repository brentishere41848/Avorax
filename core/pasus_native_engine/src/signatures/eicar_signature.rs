pub const EICAR_ASCII: &str =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

pub fn contains_eicar(bytes: &[u8]) -> bool {
    let marker = EICAR_ASCII.as_bytes();
    bytes.windows(marker.len()).any(|window| window == marker)
}
