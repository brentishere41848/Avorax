use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublisherStatus {
    Trusted,
    Suspicious,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct TrustedPublisherPolicy {
    trusted: HashSet<String>,
    suspicious: HashSet<String>,
}

impl Default for TrustedPublisherPolicy {
    fn default() -> Self {
        Self {
            trusted: [
                "microsoft windows",
                "microsoft windows publisher",
                "microsoft corporation",
                "avorax",
                "avorax security",
                "zentor",
                "zentor security",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            suspicious: HashSet::new(),
        }
    }
}

impl TrustedPublisherPolicy {
    pub fn with_trusted(names: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut trusted = HashSet::new();
        for (index, name) in names.into_iter().enumerate() {
            let Some(normalized) = normalize_publisher_name(&name) else {
                return Err(anyhow::anyhow!(
                    "trusted publisher policy entry {} is empty or contains NUL",
                    index
                ));
            };
            trusted.insert(normalized);
        }
        Ok(Self {
            trusted,
            suspicious: HashSet::new(),
        })
    }

    pub fn evaluate(&self, publisher: Option<&str>) -> PublisherStatus {
        let Some(publisher) = publisher else {
            return PublisherStatus::Unknown;
        };
        let Some(normalized) = normalize_publisher_name(publisher) else {
            return PublisherStatus::Unknown;
        };
        if self.suspicious.contains(&normalized) {
            return PublisherStatus::Suspicious;
        }
        if self.trusted.contains(&normalized) {
            PublisherStatus::Trusted
        } else {
            PublisherStatus::Unknown
        }
    }
}

fn normalize_publisher_name(value: &str) -> Option<String> {
    let normalized = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    if normalized.is_empty() || normalized.contains('\0') {
        None
    } else {
        Some(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_publisher_requires_exact_canonical_name() {
        let policy = TrustedPublisherPolicy::default();

        assert_eq!(
            policy.evaluate(Some("Microsoft Corporation")),
            PublisherStatus::Trusted
        );
        assert_eq!(
            policy.evaluate(Some("Not Microsoft Corporation")),
            PublisherStatus::Unknown
        );
    }

    #[test]
    fn trusted_publisher_normalizes_case_and_whitespace() {
        let policy =
            TrustedPublisherPolicy::with_trusted(["Contoso Trusted Apps".to_string()]).unwrap();

        assert_eq!(
            policy.evaluate(Some("  contoso   TRUSTED apps  ")),
            PublisherStatus::Trusted
        );
    }

    #[test]
    fn trusted_publisher_config_rejects_empty_or_nul_names() {
        let empty = TrustedPublisherPolicy::with_trusted(["".to_string()]).unwrap_err();
        let nul =
            TrustedPublisherPolicy::with_trusted(["Trusted\0Publisher".to_string()]).unwrap_err();

        assert!(empty
            .to_string()
            .contains("trusted publisher policy entry 0"));
        assert!(nul.to_string().contains("trusted publisher policy entry 0"));
    }

    #[test]
    fn observed_malformed_publisher_remains_unknown() {
        let policy =
            TrustedPublisherPolicy::with_trusted(["Contoso Trusted Apps".to_string()]).unwrap();

        assert_eq!(policy.evaluate(Some("")), PublisherStatus::Unknown);
        assert_eq!(
            policy.evaluate(Some("Trusted\0Publisher")),
            PublisherStatus::Unknown
        );
        assert_eq!(
            policy.evaluate(Some("Contoso Trusted Apps")),
            PublisherStatus::Trusted
        );
    }

    #[test]
    fn trusted_publisher_policy_config_does_not_silently_filter_entries() {
        let source = include_str!("publisher_trust.rs");
        let start = source.find("pub fn with_trusted").unwrap();
        let end = source.find("pub fn evaluate").unwrap();
        let config_source = &source[start..end];

        assert!(config_source.contains("trusted publisher policy entry"));
        assert!(!config_source.contains(".filter_map("));
    }
}
