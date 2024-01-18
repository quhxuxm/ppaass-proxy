mod codec;
mod config;
mod crypto;
mod error;
mod server;
mod trace;
mod transport;

use config::PROXY_CONFIG;

use crate::error::ProxyServerError;
use crate::server::ProxyServer;
use tokio::runtime::Builder;

use tracing::{error, info};

const LOG_FILE_NAME_PREFIX: &str = "ppaass-proxy";
const PROXY_SERVER_RUNTIME_NAME: &str = "PROXY-SERVER";

fn main() -> Result<(), ProxyServerError> {
    let (subscriber, _tracing_guard) = trace::init_global_tracing_subscriber(
        LOG_FILE_NAME_PREFIX,
        PROXY_CONFIG.get_max_log_level(),
    )?;
    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
        ProxyServerError::Other(format!(
            "Fail to initialize tracing system because of error: {e:?}"
        ))
    })?;
    let proxy_server_runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name(PROXY_SERVER_RUNTIME_NAME)
        .worker_threads(PROXY_CONFIG.get_worker_thread_number())
        .build()?;

    proxy_server_runtime.block_on(async {
        info!("Begin to start proxy server.");
        let proxy_server = ProxyServer::new();
        proxy_server.start().await?;
        Ok::<(), ProxyServerError>(())
    });
    info!("Success to stop proxy server.");
    Ok(())
}
