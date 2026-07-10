use std::env::{self, VarError};
use std::net::SocketAddr;

use anyhow::{bail, Context};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8000";

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub redis_url: String,
    pub dev_seed: Option<DevSeedConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevSeedConfig {
    pub dev_project_id: String,
    pub dev_public_client_key: String,
}

impl ApiConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|name| match env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(VarError::NotPresent) => Ok(None),
            Err(VarError::NotUnicode(_)) => {
                bail!("environment variable {name} must be valid Unicode")
            }
        })
    }

    fn from_lookup<F>(mut lookup: F) -> anyhow::Result<Self>
    where
        F: FnMut(&str) -> anyhow::Result<Option<String>>,
    {
        let bind_addr_text = optional_env(
            &mut lookup,
            "AVORAX_API_BIND_ADDR",
            Some("ZENTOR_API_BIND_ADDR"),
        )?
        .unwrap_or_else(|| DEFAULT_BIND_ADDR.to_string());
        let bind_addr = bind_addr_text
            .parse()
            .with_context(|| format!("invalid API bind address: {bind_addr_text}"))?;
        let database_url = required_env(&mut lookup, "DATABASE_URL", None)?;
        let redis_url = required_env(&mut lookup, "REDIS_URL", None)?;
        let dev_seed = if env_flag_enabled(
            optional_env(
                &mut lookup,
                "AVORAX_ENABLE_DEV_SEED",
                Some("ZENTOR_ENABLE_DEV_SEED"),
            )?
            .as_deref(),
        )? {
            Some(DevSeedConfig {
                dev_project_id: required_env(
                    &mut lookup,
                    "AVORAX_DEV_PROJECT_ID",
                    Some("ZENTOR_DEV_PROJECT_ID"),
                )?,
                dev_public_client_key: required_env(
                    &mut lookup,
                    "AVORAX_DEV_PUBLIC_CLIENT_KEY",
                    Some("ZENTOR_DEV_PUBLIC_CLIENT_KEY"),
                )?,
            })
        } else {
            None
        };
        Ok(Self {
            bind_addr,
            database_url,
            redis_url,
            dev_seed,
        })
    }
}

fn required_env<F>(lookup: &mut F, name: &str, legacy_name: Option<&str>) -> anyhow::Result<String>
where
    F: FnMut(&str) -> anyhow::Result<Option<String>>,
{
    optional_env(lookup, name, legacy_name)?.with_context(|| {
        legacy_name
            .map(|legacy| format!("required environment variable {name} or {legacy} is not set"))
            .unwrap_or_else(|| format!("required environment variable {name} is not set"))
    })
}

fn optional_env<F>(
    lookup: &mut F,
    name: &str,
    legacy_name: Option<&str>,
) -> anyhow::Result<Option<String>>
where
    F: FnMut(&str) -> anyhow::Result<Option<String>>,
{
    let raw = match lookup(name)? {
        Some(value) => Some((name, value)),
        None => match legacy_name {
            Some(legacy) => lookup(legacy)?.map(|value| (legacy, value)),
            None => None,
        },
    };
    let Some((source, value)) = raw else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("environment variable {source} must not be empty");
    }
    Ok(Some(trimmed.to_string()))
}

fn env_flag_enabled(value: Option<&str>) -> anyhow::Result<bool> {
    let Some(value) = value else {
        return Ok(false);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("AVORAX_ENABLE_DEV_SEED must be a boolean flag"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from_pairs(pairs: &[(&str, &str)]) -> anyhow::Result<ApiConfig> {
        ApiConfig::from_lookup(|name| {
            Ok(pairs
                .iter()
                .find_map(|(candidate, value)| (*candidate == name).then(|| (*value).to_string())))
        })
    }

    #[test]
    fn config_requires_database_url() {
        let error = config_from_pairs(&[("REDIS_URL", "redis://localhost:6379")])
            .expect_err("missing database URL must fail");
        assert!(error.to_string().contains("DATABASE_URL"));
    }

    #[test]
    fn config_requires_redis_url() {
        let error = config_from_pairs(&[("DATABASE_URL", "postgres://localhost/avorax")])
            .expect_err("missing Redis URL must fail");
        assert!(error.to_string().contains("REDIS_URL"));
    }

    #[test]
    fn config_defaults_bind_to_loopback() {
        let config = config_from_pairs(&[
            ("DATABASE_URL", "postgres://localhost/avorax"),
            ("REDIS_URL", "redis://localhost:6379"),
        ])
        .expect("config");
        assert_eq!(config.bind_addr.to_string(), DEFAULT_BIND_ADDR);
    }

    #[test]
    fn dev_seed_requires_explicit_values() {
        let error = config_from_pairs(&[
            ("DATABASE_URL", "postgres://localhost/avorax"),
            ("REDIS_URL", "redis://localhost:6379"),
            ("AVORAX_ENABLE_DEV_SEED", "true"),
            ("AVORAX_DEV_PROJECT_ID", "avorax-default"),
        ])
        .expect_err("missing dev public key must fail");
        assert!(error.to_string().contains("AVORAX_DEV_PUBLIC_CLIENT_KEY"));
    }

    #[test]
    fn dev_seed_can_be_enabled_explicitly() {
        let config = config_from_pairs(&[
            ("DATABASE_URL", "postgres://localhost/avorax"),
            ("REDIS_URL", "redis://localhost:6379"),
            ("AVORAX_ENABLE_DEV_SEED", "true"),
            ("AVORAX_DEV_PROJECT_ID", "avorax-default"),
            ("AVORAX_DEV_PUBLIC_CLIENT_KEY", "avorax-public-client"),
        ])
        .expect("config");
        assert_eq!(
            config.dev_seed,
            Some(DevSeedConfig {
                dev_project_id: "avorax-default".to_string(),
                dev_public_client_key: "avorax-public-client".to_string(),
            })
        );
    }
}
