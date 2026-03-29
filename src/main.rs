use std::net::SocketAddr;

use some_snippets::{app, config::AppConfig, error::AppError};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let config = AppConfig::from_env()?;
    app::init_tracing(&config);

    let state = app::build_state(config.clone()).await?;
    let router = app::build_router(state);
    let addr = SocketAddr::from((config.server.host, config.server.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!(address = %addr, "http server listening");

    axum::serve(listener, router).await?;
    Ok(())
}
