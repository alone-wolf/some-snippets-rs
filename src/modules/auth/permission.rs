use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    config::AppConfig,
    error::{AppError, AppResult},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ContentRead,
    ContentUpdate,
    ContentCommitLatest,
    ContentCreateVersion,
    ContentRollback,
    NodeCreate,
    NodeUpdate,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContentRead => "content:read",
            Self::ContentUpdate => "content:update",
            Self::ContentCommitLatest => "content:commit_latest",
            Self::ContentCreateVersion => "content:create_version",
            Self::ContentRollback => "content:rollback",
            Self::NodeCreate => "node:create",
            Self::NodeUpdate => "node:update",
        }
    }

    pub fn all() -> HashSet<Self> {
        [
            Self::ContentRead,
            Self::ContentUpdate,
            Self::ContentCommitLatest,
            Self::ContentCreateVersion,
            Self::ContentRollback,
            Self::NodeCreate,
            Self::NodeUpdate,
        ]
        .into_iter()
        .collect()
    }
}

impl TryFrom<&str> for Permission {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.trim() {
            "content:read" => Ok(Self::ContentRead),
            "content:update" => Ok(Self::ContentUpdate),
            "content:commit_latest" => Ok(Self::ContentCommitLatest),
            "content:create_version" => Ok(Self::ContentCreateVersion),
            "content:rollback" => Ok(Self::ContentRollback),
            "node:create" => Ok(Self::NodeCreate),
            "node:update" => Ok(Self::NodeUpdate),
            other => Err(AppError::Forbidden(format!(
                "unsupported permission: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserContext {
    pub user_id: String,
    pub permissions: HashSet<Permission>,
}

pub fn resolve_user(config: &AppConfig, headers: &axum::http::HeaderMap) -> AppResult<UserContext> {
    if !config.auth.enabled {
        return Ok(UserContext {
            user_id: "system".to_owned(),
            permissions: Permission::all(),
        });
    }

    let user_id = headers
        .get(&config.auth.user_id_header)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or(AppError::Unauthorized)?
        .to_owned();

    let permissions = headers
        .get(&config.auth.permissions_header)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Forbidden("missing permissions header".to_owned()))?
        .split(',')
        .map(Permission::try_from)
        .collect::<AppResult<HashSet<_>>>()?;

    Ok(UserContext {
        user_id,
        permissions,
    })
}
