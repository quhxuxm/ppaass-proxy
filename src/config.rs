use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

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
    rsa_dir: PathBuf,
    /// The threads number
    worker_thread_number: usize,
    /// Whether enable compressing
    compress: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            ipv6: false,
            port: 10080,
            rsa_dir: PathBuf::from("rsa"),
            worker_thread_number: 256,
            compress: true,
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
}