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

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ProxyConfig {
    /// Whether use ip v6
    ipv6: bool,
    /// Port of the ppaass proxy
    port: u16,
    /// The root directory used to store the rsa
    /// files for each user
    rsa_dir: String,
    /// The threads number
    worker_thread_number: usize,
    /// Whether enable compressing
    compress: bool,
    /// The buffer size for agent connection codec
    agent_connection_codec_framed_buffer_size: usize,
    /// The timeout in seconds for agent connection read
    agent_connection_read_timeout: u64,
    /// The timeout in seconds for agent connection write
    agent_connection_write_timeout: u64,
    /// The buffer size for destination connection codec
    dst_connection_codec_framed_buffer_size: usize,
    /// The timeout in seconds for build destination tcp connection
    dst_tcp_connect_timeout: u64,
    /// The timeout in seconds for destination tcp connection read
    dst_tcp_read_timeout: u64,
    /// The timeout in seconds for destination tcp connection write
    dst_tcp_write_timeout: u64,
    /// The timeout in seconds for receive destination udp packet
    dst_udp_recv_timeout: u64,
    /// The timeout in seconds for build destination udp socket
    dst_udp_connect_timeout: u64,
    /// The max log level
    max_log_level: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            ipv6: false,
            port: 80,
            rsa_dir: "./resources/rsa/".to_string(),
            worker_thread_number: 512,
            compress: true,
            agent_connection_codec_framed_buffer_size: 65536,
            agent_connection_read_timeout: 120,
            agent_connection_write_timeout: 120,
            dst_connection_codec_framed_buffer_size: 65536,
            dst_tcp_connect_timeout: 120,
            dst_tcp_read_timeout: 120,
            dst_tcp_write_timeout: 120,
            dst_udp_recv_timeout: 120,
            dst_udp_connect_timeout: 120,
            max_log_level: "ERROR".to_string(),
        }
    }
}

impl ProxyConfig {
    pub(crate) fn get_ipv6(&self) -> bool {
        self.ipv6
    }

    pub(crate) fn get_port(&self) -> u16 {
        self.port
    }

    pub(crate) fn get_rsa_dir(&self) -> &str {
        &self.rsa_dir
    }

    pub(crate) fn get_worker_thread_number(&self) -> usize {
        self.worker_thread_number
    }

    pub(crate) fn get_compress(&self) -> bool {
        self.compress
    }

    pub(crate) fn get_agent_connection_codec_framed_buffer_size(&self) -> usize {
        self.agent_connection_codec_framed_buffer_size
    }

    pub(crate) fn get_agent_connection_read_timeout(&self) -> u64 {
        self.agent_connection_read_timeout
    }

    pub(crate) fn get_agent_connection_write_timeout(&self) -> u64 {
        self.agent_connection_write_timeout
    }

    pub(crate) fn get_dst_tcp_connect_timeout(&self) -> u64 {
        self.dst_tcp_connect_timeout
    }

    pub(crate) fn get_dst_tcp_read_timeout(&self) -> u64 {
        self.dst_tcp_read_timeout
    }

    pub(crate) fn get_dst_tcp_write_timeout(&self) -> u64 {
        self.dst_tcp_write_timeout
    }

    pub(crate) fn get_dst_udp_recv_timeout(&self) -> u64 {
        self.dst_udp_recv_timeout
    }
    pub(crate) fn get_dst_udp_connect_timeout(&self) -> u64 {
        self.dst_udp_connect_timeout
    }

    pub(crate) fn get_max_log_level(&self) -> LevelFilter {
        LevelFilter::from_str(&self.max_log_level).unwrap_or(LevelFilter::ERROR)
    }

    pub(crate) fn get_dst_connection_codec_framed_buffer_size(&self) -> usize {
        self.dst_connection_codec_framed_buffer_size
    }
}
