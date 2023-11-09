mod config;
mod server;

use config::SERVER_CONFIG;

use crate::server::Server;
use anyhow::Result;
use log::{error, info};
use tokio::runtime::Builder;

const LOG_CONFIG_FILE_PATH: &str = "resources/config/ppaass-proxy-log.yml";
const SERVER_RUNTIME_NAME: &str = "PROXY-SERVER";

fn main() -> Result<()> {
    log4rs::init_file(LOG_CONFIG_FILE_PATH, Default::default())?;
    let server_runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name(SERVER_RUNTIME_NAME)
        .worker_threads(SERVER_CONFIG.get_worker_thread_number())
        .build()?;

    server_runtime.block_on(async {
        info!("Begin to start proxy server.");
        if let Err(e) = Server::start().await {
            error!("Fail to start proxy server because of error: {e:?}");
            return;
        }
        info!("Success to stop proxy server.");
    });

    Ok(())
}
