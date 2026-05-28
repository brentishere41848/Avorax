use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub signature_pack_path: PathBuf,
    pub rule_pack_path: PathBuf,
    pub ml_model_path: PathBuf,
    pub trust_store_path: PathBuf,
    pub quarantine_dir: PathBuf,
    pub compatibility_engines_enabled: bool,
}

impl EngineConfig {
    pub fn from_repo_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            signature_pack_path: root
                .join("assets")
                .join("pasus_native")
                .join("signatures")
                .join("pasus_core.psig"),
            rule_pack_path: root
                .join("assets")
                .join("pasus_native")
                .join("rules")
                .join("pasus_rules.prule"),
            ml_model_path: root
                .join("assets")
                .join("pasus_native")
                .join("ml")
                .join("pasus_native_model.pmodel"),
            trust_store_path: root
                .join("assets")
                .join("pasus_native")
                .join("trust")
                .join("pasus_known_good.ptrust"),
            quarantine_dir: std::env::temp_dir().join("pasus-native-quarantine"),
            compatibility_engines_enabled: false,
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::from_repo_root(root)
    }
}
