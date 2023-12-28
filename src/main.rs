mod codec;
mod config;
mod crypto;
mod error;
mod server;
mod trace;
mod transport;

use config::PROXY_CONFIG;
use std::path::Path;

use crate::error::ProxyServerError;
use crate::server::ProxyServer;
use tokio::runtime::Builder;

use tracing::{error, info};

const LOG_DIR_PATH: &str = "log";
const LOG_FILE_NAME_PREFIX: &str = "ppaass-proxy";
const PROXY_SERVER_RUNTIME_NAME: &str = "PROXY-SERVER";

fn main() -> Result<(), ProxyServerError> {
    let _tracing_guard = trace::init_tracing(
        Path::new(LOG_DIR_PATH),
        LOG_FILE_NAME_PREFIX,
        PROXY_CONFIG.get_max_log_level(),
    )?;
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
