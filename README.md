# Project goals

Ppaass is a proxy application which provide security proxy network to pass GFW. It contains an agent edge and a proxy
edge, communicate with custom ppaass protocol.

# Project features

## Ppaass agent

Ppaass agent works in client side to forward HTTP & Socks5 protocol data to Ppaass proxy side.

## Ppaass proxy

Ppaass proxy works in server side to forward the stream from agent to remote target server.

# Installation

## Agent installation

* In client side command line run: "cargo install ppaass-agent" will install the agent side.
* After agent side installed, run "ppaass-agent" the agent side will run in default parameters.

## Proxy installation

* The server side should be Ubuntu
* In server side run the script "install.sh" it will create the server env.

# Technical

The ppaass project is implemented based on Rust language. Following library are required:

* Tokio
* RSA
* Anyhow
* Thiserror
* Serde
* Toml

# Security

The ppaass message between agent and proxy are encrypted with RSA + AES.
