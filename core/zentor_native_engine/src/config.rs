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
        let installed_engine = root.join("engine");
        if installed_engine.is_dir() {
            return Self {
                signature_pack_path: first_existing(&[
                    installed_engine.join("signatures").join("avorax_core.asig"),
                    installed_engine.join("signatures").join("zentor_core.zsig"),
                ]),
                rule_pack_path: first_existing(&[
                    installed_engine.join("rules").join("avorax_core.arule"),
                    installed_engine.join("rules").join("zentor_rules.zrule"),
                ]),
                ml_model_path: first_existing(&[
                    installed_engine.join("ml").join("avorax_native_model.amodel"),
                    installed_engine.join("ml").join("zentor_native_model.zmodel"),
                ]),
                trust_store_path: first_existing(&[
                    installed_engine.join("trust").join("avorax_known_good.atrust"),
                    installed_engine.join("trust").join("zentor_known_good.ztrust"),
                ]),
                quarantine_dir: avorax_quarantine_dir(),
                compatibility_engines_enabled: false,
            };
        }
        Self {
            signature_pack_path: root
                .join("assets")
                .join("zentor_native")
                .join("signatures")
                .join("zentor_core.zsig"),
            rule_pack_path: root
                .join("assets")
                .join("zentor_native")
                .join("rules")
                .join("zentor_rules.zrule"),
            ml_model_path: root
                .join("assets")
                .join("zentor_native")
                .join("ml")
                .join("zentor_native_model.zmodel"),
            trust_store_path: root
                .join("assets")
                .join("zentor_native")
                .join("trust")
                .join("zentor_known_good.ztrust"),
            quarantine_dir: avorax_quarantine_dir(),
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

fn first_existing(paths: &[PathBuf]) -> PathBuf {
    paths
        .iter()
        .find(|path| path.exists())
        .cloned()
        .unwrap_or_else(|| paths.first().cloned().unwrap_or_default())
}

fn avorax_quarantine_dir() -> PathBuf {
    if let Ok(path) = std::env::var("AVORAX_QUARANTINE_DIR") {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    {
        if let Ok(program_data) =
            std::env::var("ProgramData").or_else(|_| std::env::var("PROGRAMDATA"))
        {
            return PathBuf::from(program_data).join("Avorax").join("Quarantine");
        }
    }
    std::env::temp_dir().join("avorax-native-quarantine")
}
