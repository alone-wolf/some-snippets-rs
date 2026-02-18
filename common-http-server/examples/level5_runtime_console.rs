use axum::{Json, extract::Path, routing::get};
use common_http_server::{
    AppBuilder, AppConfig, RuntimeConsoleConfig, Server, ServerConfig, current_log_filter,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct EchoResponse {
    input: String,
}

async fn hello() -> &'static str {
    "hello from runtime console sample"
}

async fn echo(Path(input): Path<String>) -> Json<EchoResponse> {
    Json(EchoResponse { input })
}

async fn log_filter() -> String {
    current_log_filter().unwrap_or_else(|| "unknown".to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async {
        println!("Runtime console demo:");
        println!("1) Start server and type `help` in terminal");
        println!("2) Try `endpoints`, `status`, `config`, `logs auth`, `filter info`");
        println!("3) Use `quit` to close console task only (server keeps running)");

        let app_config = AppConfig::new()
            .with_logging(true)
            .with_tracing(true)
            .with_runtime_console(
                RuntimeConsoleConfig::default()
                    .enabled(true)
                    .prompt("runtime> "),
            );

        let app_builder = AppBuilder::new(app_config)
            .route("/hello", get(hello))
            .route("/echo/{input}", get(echo))
            .route("/debug/log-filter", get(log_filter));

        let server_config = ServerConfig::new(3004).with_host("0.0.0.0");
        let server = Server::new(server_config, app_builder);
        server.start().await
    })
}
