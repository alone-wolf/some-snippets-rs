//! Logging initialization and request logging middleware.

use axum::{
    extract::Request as AxumRequest,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;
use tracing::{debug, error, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, reload};

pub const REQUEST_ID_HEADER: &str = "x-request-id";
const MAX_REQUEST_ID_LEN: usize = 128;
static JSON_LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();
static LOG_FILTER_RELOAD_HANDLE: OnceLock<reload::Handle<EnvFilter, tracing_subscriber::Registry>> =
    OnceLock::new();
static LOG_FILTER_DIRECTIVE: OnceLock<Mutex<String>> = OnceLock::new();

#[derive(Debug, Clone, Copy)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Clone)]
pub struct LoggingConfig {
    pub format: LogFormat,
    pub include_target: bool,
    pub include_thread_ids: bool,
    pub include_source_location: bool,
    pub enable_json_backend: bool,
    pub json_backend_path: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            // Default to human-friendly terminal output.
            format: LogFormat::Pretty,
            include_target: false,
            include_thread_ids: false,
            include_source_location: false,
            enable_json_backend: true,
            json_backend_path: "logs/common-http-server.jsonl".to_string(),
        }
    }
}

impl LoggingConfig {
    pub fn with_format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    pub fn with_target(mut self, include_target: bool) -> Self {
        self.include_target = include_target;
        self
    }

    pub fn with_thread_ids(mut self, include_thread_ids: bool) -> Self {
        self.include_thread_ids = include_thread_ids;
        self
    }

    pub fn with_source_location(mut self, include_source_location: bool) -> Self {
        self.include_source_location = include_source_location;
        self
    }

    pub fn with_json_backend(mut self, enable_json_backend: bool) -> Self {
        self.enable_json_backend = enable_json_backend;
        self
    }

    pub fn with_json_backend_path(mut self, json_backend_path: impl Into<String>) -> Self {
        self.json_backend_path = json_backend_path.into();
        self
    }
}

#[derive(Debug, Clone)]
pub struct RequestId(pub String);

fn set_current_log_filter(filter: String) {
    let lock = LOG_FILTER_DIRECTIVE.get_or_init(|| Mutex::new(filter.clone()));
    if let Ok(mut guard) = lock.lock() {
        *guard = filter;
    }
}

pub fn current_log_filter() -> Option<String> {
    LOG_FILTER_DIRECTIVE
        .get()
        .and_then(|lock| lock.lock().ok().map(|guard| guard.clone()))
}

pub fn update_log_filter(directive: &str) -> Result<(), String> {
    let handle = LOG_FILTER_RELOAD_HANDLE
        .get()
        .ok_or_else(|| "log filter reload handle is not initialized".to_string())?;
    let filter = EnvFilter::try_new(directive).map_err(|err| err.to_string())?;
    handle.reload(filter).map_err(|err| err.to_string())?;
    set_current_log_filter(directive.to_string());
    Ok(())
}

fn is_valid_request_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= MAX_REQUEST_ID_LEN
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn normalized_request_id(candidate: Option<&str>) -> String {
    if let Some(raw) = candidate {
        let trimmed = raw.trim();
        if is_valid_request_id(trimmed) {
            return trimmed.to_string();
        }
    }

    uuid::Uuid::new_v4().to_string()
}

/// 初始化日志系统
pub fn init_logging(config: &LoggingConfig) -> Result<(), Box<dyn std::error::Error>> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let (reloadable_filter, filter_handle) = reload::Layer::new(env_filter);
    let _ = LOG_FILTER_RELOAD_HANDLE.set(filter_handle);
    let initial_directive = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    set_current_log_filter(initial_directive);

    let terminal_layer = tracing_subscriber::fmt::layer()
        .with_target(config.include_target)
        .with_thread_ids(config.include_thread_ids)
        .with_file(config.include_source_location)
        .with_line_number(config.include_source_location);

    let init_result = match config.format {
        LogFormat::Json => {
            if config.enable_json_backend {
                let json_writer = build_json_backend_writer(&config.json_backend_path)?;
                let json_backend_layer = tracing_subscriber::fmt::layer()
                    .json()
                    .with_ansi(false)
                    .with_target(config.include_target)
                    .with_thread_ids(config.include_thread_ids)
                    .with_file(config.include_source_location)
                    .with_line_number(config.include_source_location)
                    .with_writer(json_writer);

                tracing_subscriber::registry()
                    .with(reloadable_filter)
                    .with(terminal_layer.json())
                    .with(json_backend_layer)
                    .try_init()
            } else {
                tracing_subscriber::registry()
                    .with(reloadable_filter)
                    .with(terminal_layer.json())
                    .try_init()
            }
        }
        LogFormat::Pretty => {
            if config.enable_json_backend {
                let json_writer = build_json_backend_writer(&config.json_backend_path)?;
                let json_backend_layer = tracing_subscriber::fmt::layer()
                    .json()
                    .with_ansi(false)
                    .with_target(config.include_target)
                    .with_thread_ids(config.include_thread_ids)
                    .with_file(config.include_source_location)
                    .with_line_number(config.include_source_location)
                    .with_writer(json_writer);

                tracing_subscriber::registry()
                    .with(reloadable_filter)
                    .with(terminal_layer.pretty())
                    .with(json_backend_layer)
                    .try_init()
            } else {
                tracing_subscriber::registry()
                    .with(reloadable_filter)
                    .with(terminal_layer.pretty())
                    .try_init()
            }
        }
    };

    if let Err(err) = init_result {
        // Avoid failing server startup if logging has already been initialized by
        // parent binaries/tests.
        if err.to_string().contains("already been set") {
            return Ok(());
        }
        return Err(Box::new(err));
    }

    info!("Logging system initialized");
    Ok(())
}

fn build_json_backend_writer(
    path: &str,
) -> Result<tracing_appender::non_blocking::NonBlocking, Box<dyn std::error::Error>> {
    let path = PathBuf::from(path);
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "json backend path must contain a file name",
        )
    })?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(directory)?;

    let appender = tracing_appender::rolling::never(directory, file_name);
    let (non_blocking, guard) = tracing_appender::non_blocking(appender);
    let _ = JSON_LOG_GUARD.set(guard);
    Ok(non_blocking)
}

/// 结构化日志中间件
pub async fn structured_logging_middleware(request: AxumRequest, next: Next) -> Response {
    let start_time = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let request_id_header = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|h| h.to_str().ok());

    let request_id = normalized_request_id(request_id_header);
    let mut request = request;
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        user_agent = %user_agent,
        "Request started"
    );

    let mut response = next.run(request).await;
    let duration = start_time.elapsed();
    let status = response.status();

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }

    match status.as_u16() {
        200..=299 => {
            info!(
                request_id = %request_id,
                method = %method,
                path = %path,
                status = %status,
                duration_ms = duration.as_millis(),
                "Request completed successfully"
            );
        }
        400..=499 => {
            warn!(
                request_id = %request_id,
                method = %method,
                path = %path,
                status = %status,
                duration_ms = duration.as_millis(),
                "Client error"
            );
        }
        500..=599 => {
            error!(
                request_id = %request_id,
                method = %method,
                path = %path,
                status = %status,
                duration_ms = duration.as_millis(),
                "Server error"
            );
        }
        _ => {
            debug!(
                request_id = %request_id,
                method = %method,
                path = %path,
                status = %status,
                duration_ms = duration.as_millis(),
                "Request completed"
            );
        }
    }

    response
}

/// 简化的日志中间件（向后兼容）
pub async fn logging_middleware(request: AxumRequest, next: Next) -> Response {
    structured_logging_middleware(request, next).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
    };
    use tower::ServiceExt;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    #[tokio::test]
    async fn generated_request_id_is_added_to_response_header() {
        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(middleware::from_fn(structured_logging_middleware));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let request_id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        assert!(!request_id.is_empty());
    }

    #[tokio::test]
    async fn provided_request_id_is_preserved_in_response_header() {
        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(middleware::from_fn(structured_logging_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(REQUEST_ID_HEADER, "demo-request-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(REQUEST_ID_HEADER)
                .and_then(|h| h.to_str().ok()),
            Some("demo-request-id")
        );
    }

    #[tokio::test]
    async fn invalid_request_id_is_replaced() {
        let app = Router::new()
            .route("/", get(ok_handler))
            .layer(middleware::from_fn(structured_logging_middleware));

        let invalid = "x".repeat(MAX_REQUEST_ID_LEN + 1);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(REQUEST_ID_HEADER, invalid.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let request_id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        assert_ne!(request_id, invalid);
        assert!(!request_id.is_empty());
        assert!(request_id.len() <= MAX_REQUEST_ID_LEN);
    }
}
