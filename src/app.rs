use axum::{
    extract::Request as AxumRequest,
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

#[derive(Debug, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

async fn health_check() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        message: "Service is running".to_string(),
    })
}

async fn logging_middleware(request: AxumRequest, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    
    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed();
    
    println!("{} {} {} {:?}", method, uri, response.status(), duration);
    
    response
}

async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(ApiResponse::<()> {
            success: false,
            data: None,
            error: Some("Endpoint not found".to_string()),
        }),
    )
}

fn create_app() -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/status", get(health_check))
        .fallback(not_found)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
                .layer(middleware::from_fn(logging_middleware)),
        )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = create_app();
    
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("🚀 Server starting on http://{}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{http::StatusCode, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_check_test() {
        let app = super::create_app();
        
        let response = app
            .oneshot(Request::builder().uri("/health").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK);
    }
}