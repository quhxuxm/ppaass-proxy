use clap::{command, Parser, ValueEnum};
use serde_derive::Serialize;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::level_filters::LevelFilter;
#[derive(Clone, Debug, Copy, ValueEnum, Default, Serialize)]
pub enum CryptoStorage {
    #[default]
    #[serde(rename = "file")]
    File,
    #[serde(rename = "database")]
    Database,
}
#[derive(Parser)]
#[command(
    version,
    about,
    long_about = "This is the proxy side of the ppaass application, the proxy side will forward the agent data to the destination"
)]
pub struct ProxyConfig {
    /// Whether you use ip v6
    #[arg(short = '6', long, default_value = "false")]
    ipv6: bool,
    /// Port of the ppaass proxy
    #[arg(short, long, default_value = "80")]
    tcp_port: u16,
    /// The root directory used to store the rsa
    /// files for each user
    #[arg(short, long, default_value = "./resources/rsa/")]
    rsa_dir: PathBuf,
    /// The threads number
    #[arg(short, long, default_value = "512")]
    worker_thread_number: usize,
    /// Whether enable compressing
    #[arg(short, long, default_value = "true")]
    compress: bool,
    /// The buffer size for agent connection codec
    #[arg(long, default_value = "65536")]
    agent_connection_codec_framed_buffer_size: usize,
    /// The timeout in seconds for agent connection read
    #[arg(long, default_value = "120")]
    agent_connection_read_timeout: u64,
    /// The timeout in seconds for agent connection write
    #[arg(long, default_value = "120")]
    agent_connection_write_timeout: u64,
    /// The buffer size for destination connection codec
    #[arg(long, default_value = "65536")]
    dst_connection_codec_framed_buffer_size: usize,
    /// The timeout in seconds for build destination tcp connection
    #[arg(long, default_value = "120")]
    dst_tcp_connect_timeout: u64,
    /// The timeout in seconds for destination tcp connection read
    #[arg(long, default_value = "120")]
    dst_tcp_read_timeout: u64,
    /// The timeout in seconds for destination tcp connection write
    #[arg(long, default_value = "120")]
    dst_tcp_write_timeout: u64,
    /// The timeout in seconds for receive destination udp packet
    #[arg(long, default_value = "120")]
    dst_udp_recv_timeout: u64,
    /// The timeout in seconds for build destination udp socket
    #[arg(long, default_value = "120")]
    dst_udp_connect_timeout: u64,
    /// The max log level
    #[arg(short = 'l', long, default_value = "ERROR")]
    max_log_level: String,
    /// The crypto storage type
    #[arg(long, default_value_t, value_enum)]
    crypto_storage: CryptoStorage,
    /// The root directory used to store the rsa
    /// files for each user
    #[arg(long, default_value = "./resources/database.csv")]
    crypto_db_path: PathBuf,
}
impl ProxyConfig {
    pub(crate) fn ipv6(&self) -> bool {
        self.ipv6
    }

    pub(crate) fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    pub(crate) fn rsa_dir(&self) -> &Path {
        self.rsa_dir.as_ref()
    }

    pub(crate) fn worker_thread_number(&self) -> usize {
        self.worker_thread_number
    }

    pub(crate) fn compress(&self) -> bool {
        self.compress
    }

    pub(crate) fn agent_connection_codec_framed_buffer_size(&self) -> usize {
        self.agent_connection_codec_framed_buffer_size
    }

    pub(crate) fn agent_connection_read_timeout(&self) -> u64 {
        self.agent_connection_read_timeout
    }

    pub(crate) fn agent_connection_write_timeout(&self) -> u64 {
        self.agent_connection_write_timeout
    }

    pub(crate) fn dst_tcp_connect_timeout(&self) -> u64 {
        self.dst_tcp_connect_timeout
    }

    pub(crate) fn dst_tcp_read_timeout(&self) -> u64 {
        self.dst_tcp_read_timeout
    }

    pub(crate) fn dst_tcp_write_timeout(&self) -> u64 {
        self.dst_tcp_write_timeout
    }

    pub(crate) fn dst_udp_recv_timeout(&self) -> u64 {
        self.dst_udp_recv_timeout
    }

    pub(crate) fn dst_udp_connect_timeout(&self) -> u64 {
        self.dst_udp_connect_timeout
    }

    pub(crate) fn max_log_level(&self) -> LevelFilter {
        LevelFilter::from_str(self.max_log_level.as_ref()).unwrap_or(LevelFilter::ERROR)
    }

    pub(crate) fn dst_connection_codec_framed_buffer_size(&self) -> usize {
        self.dst_connection_codec_framed_buffer_size
    }

    pub(crate) fn crypto_storage(&self) -> CryptoStorage {
        self.crypto_storage
    }
}
