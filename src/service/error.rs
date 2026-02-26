use sea_orm::DbErr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceErrorKind {
    BadRequest,
    NotFound,
    Conflict,
    Internal,
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceError {
    kind: ServiceErrorKind,
    message: String,
}

impl ServiceError {
    pub(crate) fn new(kind: ServiceErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::BadRequest, message)
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::NotFound, message)
    }

    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::Conflict, message)
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::Internal, message)
    }

    pub(crate) fn kind(&self) -> ServiceErrorKind {
        self.kind
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

pub(crate) fn map_db_error(error: DbErr) -> ServiceError {
    match error {
        DbErr::RecordNotFound(message) => ServiceError::not_found(message),
        DbErr::Json(message) | DbErr::Type(message) => ServiceError::bad_request(message),
        other => {
            let message = other.to_string();
            let lowered = message.to_ascii_lowercase();

            if lowered.contains("unique constraint failed")
                || lowered.contains("foreign key constraint failed")
            {
                ServiceError::conflict(message)
            } else if lowered.contains("not null constraint failed")
                || lowered.contains("check constraint failed")
                || lowered.contains("datatype mismatch")
            {
                ServiceError::bad_request(message)
            } else {
                ServiceError::internal(message)
            }
        }
    }
}
