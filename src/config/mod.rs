use std::{env, net::Ipv4Addr, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub object_store: ObjectStoreConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: Ipv4Addr,
    pub port: u16,
    pub log_filter: String,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub auto_migrate: bool,
}

#[derive(Debug, Clone)]
pub struct ObjectStoreConfig {
    pub root_dir: PathBuf,
    pub default_bucket: String,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub enabled: bool,
    pub user_id_header: String,
    pub permissions_header: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            server: ServerConfig {
                host: env::var("APP_HOST")
                    .ok()
                    .map(|value| value.parse())
                    .transpose()
                    .map_err(ConfigError::InvalidHost)?
                    .unwrap_or(Ipv4Addr::new(127, 0, 0, 1)),
                port: env::var("APP_PORT")
                    .ok()
                    .map(|value| value.parse())
                    .transpose()
                    .map_err(ConfigError::InvalidPort)?
                    .unwrap_or(3000),
                log_filter: env::var("APP_LOG").unwrap_or_else(|_| "info".to_owned()),
            },
            database: DatabaseConfig {
                url: env::var("APP_DATABASE_URL")
                    .unwrap_or_else(|_| "sqlite://data/app.db?mode=rwc".to_owned()),
                auto_migrate: env::var("APP_AUTO_MIGRATE")
                    .ok()
                    .map(|value| parse_bool(&value))
                    .transpose()?
                    .unwrap_or(true),
            },
            object_store: ObjectStoreConfig {
                root_dir: env::var("APP_OBJECT_STORE_ROOT")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("data/object-store")),
                default_bucket: env::var("APP_OBJECT_STORE_BUCKET")
                    .unwrap_or_else(|_| "content-assets".to_owned()),
            },
            auth: AuthConfig {
                enabled: env::var("APP_AUTH_ENABLED")
                    .ok()
                    .map(|value| parse_bool(&value))
                    .transpose()?
                    .unwrap_or(false),
                user_id_header: env::var("APP_AUTH_USER_ID_HEADER")
                    .unwrap_or_else(|_| "x-user-id".to_owned()),
                permissions_header: env::var("APP_AUTH_PERMISSIONS_HEADER")
                    .unwrap_or_else(|_| "x-user-permissions".to_owned()),
            },
        })
    }
}

fn parse_bool(value: &str) -> Result<bool, ConfigError> {
    match value {
        "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON" => Ok(true),
        "0" | "false" | "FALSE" | "no" | "NO" | "off" | "OFF" => Ok(false),
        _ => Err(ConfigError::InvalidBool(value.to_owned())),
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid APP_HOST: {0}")]
    InvalidHost(std::net::AddrParseError),
    #[error("invalid APP_PORT: {0}")]
    InvalidPort(std::num::ParseIntError),
    #[error("invalid boolean value: {0}")]
    InvalidBool(String),
}
