//! Optional interactive runtime console plugin.
//!
//! The console is intentionally opt-in and runs in its own async task so it
//! does not block request serving.

use crate::core::logging::{current_log_filter, update_log_filter};
use crate::core::server::{AppConfig, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct RuntimeConsoleConfig {
    pub enabled: bool,
    pub prompt: String,
}

impl Default for RuntimeConsoleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            prompt: "console> ".to_string(),
        }
    }
}

impl RuntimeConsoleConfig {
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = prompt.into();
        self
    }
}

#[derive(Debug)]
struct RuntimeConsoleState {
    started_at: Instant,
    bind_addr: SocketAddr,
    endpoints: Vec<String>,
    config_lines: Vec<String>,
}

pub fn spawn_runtime_console(
    config: &RuntimeConsoleConfig,
    bind_addr: SocketAddr,
    endpoints: Vec<String>,
    server_config: &ServerConfig,
    app_config: &AppConfig,
) {
    if !config.enabled {
        return;
    }

    let state = Arc::new(RuntimeConsoleState {
        started_at: Instant::now(),
        bind_addr,
        endpoints,
        config_lines: build_config_lines(server_config, app_config),
    });
    let prompt = config.prompt.clone();

    tokio::spawn(async move {
        info!("Interactive runtime console started");
        println!("Interactive console enabled. Type 'help' for commands.");

        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();

        loop {
            print!("{}", prompt);
            let _ = std::io::Write::flush(&mut std::io::stdout());

            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    info!("Interactive console stopped because stdin is closed");
                    break;
                }
                Ok(_) => {
                    if !handle_console_command(line.trim(), &state) {
                        info!("Interactive console stopped by user command");
                        break;
                    }
                }
                Err(err) => {
                    warn!(error = %err, "Interactive console input failed");
                    break;
                }
            }
        }
    });
}

fn build_config_lines(server_config: &ServerConfig, app_config: &AppConfig) -> Vec<String> {
    vec![
        format!("server.host = {}", server_config.host),
        format!("server.port = {}", server_config.port),
        format!("app.enable_cors = {}", app_config.enable_cors),
        format!("app.enable_tracing = {}", app_config.enable_tracing),
        format!("app.enable_logging = {}", app_config.enable_logging),
        format!(
            "app.runtime_console.enabled = {}",
            app_config
                .runtime_console
                .as_ref()
                .map(|console| console.enabled)
                .unwrap_or(false)
        ),
    ]
}

fn handle_console_command(input: &str, state: &RuntimeConsoleState) -> bool {
    if input.is_empty() || input.eq_ignore_ascii_case("help") {
        print_help();
        return true;
    }

    let mut parts = input.split_whitespace();
    let command = parts.next().unwrap_or_default();

    match command {
        "endpoints" => {
            print_endpoints(state);
            true
        }
        "status" => {
            print_status(state);
            true
        }
        "config" => {
            print_config(state);
            true
        }
        "logs" => {
            let tag = parts.next().unwrap_or("all");
            set_log_filter_by_tag(tag);
            true
        }
        "filter" => {
            let directive = parts.collect::<Vec<_>>().join(" ");
            if directive.is_empty() {
                println!("Usage: filter <RUST_LOG directive>");
            } else {
                match update_log_filter(&directive) {
                    Ok(_) => println!("Log filter updated to: {}", directive),
                    Err(err) => println!("Failed to update log filter: {}", err),
                }
            }
            true
        }
        "quit" | "exit" => false,
        _ => {
            println!("Unknown command: '{}'. Type 'help' for commands.", command);
            true
        }
    }
}

fn print_help() {
    println!("Available commands:");
    println!("  help                 Show command list");
    println!("  endpoints            Show known endpoint list");
    println!("  status               Show server status");
    println!("  config               Show key configuration values");
    println!("  logs <tag>           Set log preset by tag (all|core|auth|protection|monitoring)");
    println!("  filter <directive>   Set custom log filter directive");
    println!("  quit                 Exit interactive console");
}

fn print_endpoints(state: &RuntimeConsoleState) {
    let base = format!("http://{}", state.bind_addr);
    println!("Known endpoints:");
    for endpoint in &state.endpoints {
        println!("  - {}{}", base, endpoint);
    }
}

fn print_status(state: &RuntimeConsoleState) {
    println!("Server status:");
    println!("  - state: running");
    println!("  - bind_addr: {}", state.bind_addr);
    println!(
        "  - uptime_seconds: {:.1}",
        state.started_at.elapsed().as_secs_f64()
    );
    if let Some(filter) = current_log_filter() {
        println!("  - log_filter: {}", filter);
    }
}

fn print_config(state: &RuntimeConsoleState) {
    println!("Configuration:");
    for line in &state.config_lines {
        println!("  - {}", line);
    }
}

fn set_log_filter_by_tag(tag: &str) {
    let normalized = tag.to_ascii_lowercase();
    let directive = match normalized.as_str() {
        "all" => "info",
        "core" => "common_http_server::core=debug,info",
        "auth" => "common_http_server::auth=debug,info",
        "protection" => "common_http_server::protection=debug,info",
        "monitoring" => "common_http_server::monitoring=debug,info",
        other => {
            println!(
                "Unknown log tag '{}'. Available: all|core|auth|protection|monitoring",
                other
            );
            return;
        }
    };

    match update_log_filter(directive) {
        Ok(_) => println!(
            "Log filter switched by tag '{}' -> {}",
            normalized, directive
        ),
        Err(err) => println!("Failed to switch log filter: {}", err),
    }
}
