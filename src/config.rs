use std::fs::read_to_string;
use std::str::FromStr;

use lazy_static::lazy_static;
use serde_derive::{Deserialize, Serialize};
use tracing::level_filters::LevelFilter;

lazy_static! {
    pub(crate) static ref PROXY_CONFIG: ProxyConfig = {
        let configuration_file = read_to_string("resources/config/ppaass-proxy.toml")
            .expect("Fail to read proxy configuration file.");
        toml::from_str(&configuration_file)
            .expect("Fail to parse proxy configuration file content.")
    };
}

const DEFAULT_PROXY_SERVER_WORKER_THREAD_NUMBER: usize = 128;

#[derive(Serialize, Deserialize, Debug, Default)]
pub(crate) struct ProxyConfig {
    /// Whether use ip v6
    ipv6: Option<bool>,
    /// Port of the ppaass proxy
    port: u16,
    /// The root directory used to store the rsa
    /// files for each user
    rsa_dir: String,
    /// The threads number
    worker_thread_number: Option<usize>,
    /// Whether enable compressing
    compress: Option<bool>,
    /// The buffer size for one agent connection
    agent_receive_buffer_size: Option<usize>,
    dst_tcp_buffer_size: Option<usize>,
    dst_connect_timeout: Option<u64>,
    dst_relay_timeout: Option<u64>,
    agent_relay_timeout: Option<u64>,
    dst_udp_recv_timeout: Option<u64>,
    dst_udp_connect_timeout: Option<u64>,
    max_log_level: Option<String>,
    transport_max_log_level: Option<String>,
}

impl ProxyConfig {
    pub(crate) fn get_ipv6(&self) -> bool {
        self.ipv6.unwrap_or(false)
    }

    pub(crate) fn get_port(&self) -> u16 {
        self.port
    }

    pub(crate) fn get_rsa_dir(&self) -> &str {
        &self.rsa_dir
    }

    pub(crate) fn get_worker_thread_number(&self) -> usize {
        self.worker_thread_number
            .unwrap_or(DEFAULT_PROXY_SERVER_WORKER_THREAD_NUMBER)
    }

    pub(crate) fn get_compress(&self) -> bool {
        self.compress.unwrap_or(false)
    }

    pub(crate) fn get_agent_connection_codec_framed_buffer_size(&self) -> usize {
        self.agent_receive_buffer_size.unwrap_or(1024 * 512)
    }

    pub(crate) fn get_dst_connect_timeout(&self) -> u64 {
        self.dst_connect_timeout.unwrap_or(20)
    }

    pub(crate) fn get_dst_udp_recv_timeout(&self) -> u64 {
        self.dst_udp_recv_timeout.unwrap_or(5)
    }
    pub(crate) fn get_dst_udp_connect_timeout(&self) -> u64 {
        self.dst_udp_connect_timeout.unwrap_or(5)
    }

    pub(crate) fn get_max_log_level(&self) -> LevelFilter {
        let level = self.max_log_level.as_deref().unwrap_or("ERROR");
        LevelFilter::from_str(level).unwrap_or(LevelFilter::ERROR)
    }

    pub(crate) fn get_transport_max_log_level(&self) -> LevelFilter {
        let level = self.transport_max_log_level.as_deref().unwrap_or("TRACE");
        LevelFilter::from_str(level).unwrap_or(LevelFilter::TRACE)
    }
}
