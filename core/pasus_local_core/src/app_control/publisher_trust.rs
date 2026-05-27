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
                "microsoft corporation",
                "pasus",
                "pasus security",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            suspicious: HashSet::new(),
        }
    }
}

impl TrustedPublisherPolicy {
    pub fn with_trusted(names: impl IntoIterator<Item = String>) -> Self {
        Self {
            trusted: names.into_iter().map(|name| name.to_lowercase()).collect(),
            suspicious: HashSet::new(),
        }
    }

    pub fn evaluate(&self, publisher: Option<&str>) -> PublisherStatus {
        let Some(publisher) = publisher else {
            return PublisherStatus::Unknown;
        };
        let normalized = publisher.trim().to_lowercase();
        if normalized.is_empty() {
            return PublisherStatus::Unknown;
        }
        if self.suspicious.contains(&normalized) {
            return PublisherStatus::Suspicious;
        }
        if self
            .trusted
            .iter()
            .any(|trusted| normalized.contains(trusted))
        {
            PublisherStatus::Trusted
        } else {
            PublisherStatus::Unknown
        }
    }
}
