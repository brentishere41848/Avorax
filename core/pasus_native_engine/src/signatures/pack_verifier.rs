use std::path::Path;

pub fn verify_pack_exists(path: &Path) -> bool {
    path.exists()
}
