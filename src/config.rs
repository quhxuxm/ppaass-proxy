use std::{fs::read_to_string, path::Path};

use lazy_static::lazy_static;
use serde_derive::{Deserialize, Serialize};

lazy_static! {
    pub(crate) static ref SERVER_CONFIG: ServerConfig = {
        let configuration_file = read_to_string("resources/config/ppaass-proxy.toml")
            .expect("Fail to read proxy configuration file.");
        toml::from_str(&configuration_file)
            .expect("Fail to parse proxy configuration file content.")
    };
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerConfig {
    /// Whehter use ip v6
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
    /// The buffer size for one agent connection
    agent_recive_buffer_size: usize,
    /// The buffer size for one agent connection
    dst_tcp_buffer_size: usize,
    dst_connect_timeout: u64,
    dst_relay_timeout: u64,
    agent_relay_timeout: u64,
    dst_udp_recv_timeout: u64,
    dst_udp_connect_timeout: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            ipv6: false,
            port: 10080,
            rsa_dir: "./rsa".to_string(),
            worker_thread_number: 256,
            compress: true,
            agent_recive_buffer_size: 1024 * 1024,
            dst_tcp_buffer_size: 1024 * 1024,
            dst_connect_timeout: 20,
            dst_relay_timeout: 20,
            agent_relay_timeout: 20,
            dst_udp_recv_timeout: 20,
            dst_udp_connect_timeout: 20,
        }
    }
}

impl ServerConfig {
    pub(crate) fn get_ipv6(&self) -> bool {
        self.ipv6
    }

    pub(crate) fn get_port(&self) -> u16 {
        self.port
    }

    pub(crate) fn get_rsa_dir(&self) -> &Path {
        &self.rsa_dir
    }

    pub(crate) fn get_worker_thread_number(&self) -> usize {
        self.worker_thread_number
    }

    pub(crate) fn get_compress(&self) -> bool {
        self.compress
    }

    pub(crate) fn get_agent_recive_buffer_size(&self) -> usize {
        self.agent_recive_buffer_size
    }

    pub(crate) fn get_dst_tcp_buffer_size(&self) -> usize {
        self.dst_tcp_buffer_size
    }

    pub(crate) fn get_dst_connect_timeout(&self) -> u64 {
        self.dst_connect_timeout
    }

    pub(crate) fn get_dst_relay_timeout(&self) -> u64 {
        self.dst_relay_timeout
    }

    pub(crate) fn get_agent_relay_timeout(&self) -> u64 {
        self.agent_relay_timeout
    }

    pub(crate) fn get_dst_udp_recv_timeout(&self) -> u64 {
        self.dst_udp_recv_timeout
    }

    pub(crate) fn get_dst_udp_connect_timeout(&self) -> u64 {
        self.dst_udp_connect_timeout
    }
}
