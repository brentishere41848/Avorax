use crate::verdict::ThreatCategory;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyIndicator {
    pub family: &'static str,
    pub category: ThreatCategory,
    pub indicator_id_prefix: &'static str,
}

pub const FAMILY_INDICATORS: &[FamilyIndicator] = &[
    FamilyIndicator {
        family: "generic-ransomware",
        category: ThreatCategory::Ransomware,
        indicator_id_prefix: "ZNE-RANSOM",
    },
    FamilyIndicator {
        family: "generic-infostealer",
        category: ThreatCategory::Infostealer,
        indicator_id_prefix: "ZNE-INFOSTEALER",
    },
    FamilyIndicator {
        family: "generic-miner",
        category: ThreatCategory::Miner,
        indicator_id_prefix: "ZNE-MINER",
    },
];
