mod codec;
mod config;
mod crypto;
mod error;
mod server;
mod transport;

use config::PROXY_CONFIG;

use crate::error::ProxyServerError;
use crate::server::ProxyServer;
use tokio::runtime::Builder;

use tracing::{error, info};
use tracing_appender::non_blocking::WorkerGuard;

const LOG_DIR_PATH: &str = "log";
const LOG_FILE_NAME_PREFIX: &str = "ppaass-proxy";
const PROXY_SERVER_RUNTIME_NAME: &str = "PROXY-SERVER";

fn init_tracing() -> Result<WorkerGuard, ProxyServerError> {
    let (log_file_appender, log_file_appender_guard) = tracing_appender::non_blocking(
        tracing_appender::rolling::daily(LOG_DIR_PATH, LOG_FILE_NAME_PREFIX),
    );
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(PROXY_CONFIG.get_max_log_level())
        .with_writer(log_file_appender)
        .with_line_number(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
        ProxyServerError::Other(format!(
            "Fail to initialize tracing system because of error: {e:?}"
        ))
    })?;
    Ok(log_file_appender_guard)
}

fn main() -> Result<(), ProxyServerError> {
    let _tracing_guard = init_tracing()?;
    let proxy_server_runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name(PROXY_SERVER_RUNTIME_NAME)
        .worker_threads(PROXY_CONFIG.get_worker_thread_number())
        .build()?;

    proxy_server_runtime.block_on(async {
        info!("Begin to start proxy server.");
        let proxy_server = ProxyServer::new();
        if let Err(e) = proxy_server.start().await {
            let panic_message = format!("Fail to start proxy server because of error: {e:?}");
            error!("{panic_message}");
            panic!("{panic_message}")
        }
    });
    info!("Success to stop proxy server.");
    Ok(())
}
