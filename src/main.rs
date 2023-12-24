mod codec;
mod config;
mod crypto;
mod error;
mod server;
mod transport;

use config::PROXY_CONFIG;

use crate::server::ProxyServer;
use anyhow::Result;
use log::{error, info};
use tokio::runtime::Builder;

const LOG_CONFIG_FILE_PATH: &str = "resources/config/ppaass-proxy-log.yml";
const PROXY_SERVER_RUNTIME_NAME: &str = "PROXY-SERVER-RUNTIME";

fn main() -> Result<()> {
    log4rs::init_file(LOG_CONFIG_FILE_PATH, Default::default())?;
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
