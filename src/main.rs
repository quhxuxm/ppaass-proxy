use crate::{config::ProxyConfig, error::ProxyServerError};
use crate::{crypto::ProxyServerRsaCryptoFetcher, server::ProxyServer};
use clap::Parser;
use tokio::runtime::Builder;
use tracing::info;
mod codec;
mod config;
mod crypto;
mod error;
mod server;
mod trace;
mod tunnel;
const LOG_FILE_NAME_PREFIX: &str = "ppaass-proxy";
const PROXY_SERVER_RUNTIME_NAME: &str = "PROXY-SERVER";
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
fn main() -> Result<(), ProxyServerError> {
    // Read command line arguments to configuration
    let proxy_config = Box::new(ProxyConfig::parse());
    let proxy_config = Box::leak(proxy_config);
    let (subscriber, _tracing_guard) = trace::init_global_tracing_subscriber(
        LOG_FILE_NAME_PREFIX,
        proxy_config.get_max_log_level(),
    )?;
    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
        ProxyServerError::Other(format!(
            "Fail to initialize tracing system because of error: {e:?}"
        ))
    })?;
    let proxy_server_runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name(PROXY_SERVER_RUNTIME_NAME)
        .worker_threads(proxy_config.get_worker_thread_number())
        .build()?;
    let rsa_crypto_fetcher =
        Box::new(ProxyServerRsaCryptoFetcher::new(proxy_config).map_err(|e| {
            ProxyServerError::Other(format!(
                "Fail to generate rsa crypto fetcher because of error: {e}"
            ))
        })?);
    let rsa_crypto_fetcher = Box::leak(rsa_crypto_fetcher);
    proxy_server_runtime.block_on(async {
        info!("Begin to start proxy server.");
        let proxy_server = ProxyServer::new(proxy_config, rsa_crypto_fetcher);
        proxy_server.start().await?;
        Ok::<(), ProxyServerError>(())
    })?;
    info!("Success to stop proxy server.");
    Ok(())
}
