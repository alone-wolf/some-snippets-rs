use axum::http::HeaderMap;

use crate::{
    app::state::AppState,
    error::{AppError, AppResult},
    modules::auth::permission::{Permission, UserContext, resolve_user},
};

pub fn require_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission: Permission,
) -> AppResult<UserContext> {
    let user = resolve_user(&state.config, headers)?;
    if user.permissions.contains(&permission) {
        Ok(user)
    } else {
        Err(AppError::Forbidden(format!(
            "missing permission {}",
            permission.as_str()
        )))
    }
}
