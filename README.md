# WireGuard Userspace Tunnel

[![wireguard-netstack](https://img.shields.io/crates/v/wireguard-netstack.svg?label=wireguard-netstack)](https://crates.io/crates/wireguard-netstack)
[![wireguard-hyper-connector](https://img.shields.io/crates/v/wireguard-hyper-connector.svg?label=wireguard-hyper-connector)](https://crates.io/crates/wireguard-hyper-connector)
[![warp-wireguard-gen](https://img.shields.io/crates/v/warp-wireguard-gen.svg?label=warp-wireguard-gen)](https://crates.io/crates/warp-wireguard-gen)

A Rust library for routing HTTP traffic through WireGuard VPN tunnels entirely in userspace, without requiring root privileges or kernel-level WireGuard support. Includes seamless integration with Cloudflare WARP for zero-configuration VPN setup.

## Features

- **Userspace Implementation** - No kernel modules or admin privileges required
- **Cloudflare WARP Integration** - Zero-configuration VPN with automatic device registration
- **Self-Healing Connections** - Automatic tunnel health monitoring and reconnection
- **reqwest Compatible** - Drop-in `reqwest::Client` you can pass to any library
- **Encrypted DNS** - All DNS queries use DNS-over-HTTPS (DoH) with configurable providers
- **Pure Rust** - Cross-platform with no C dependencies for the core functionality

## Crates

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [`wireguard-netstack`](crates/wireguard-netstack) | Core userspace WireGuard tunnel with embedded TCP/IP stack | Yes |
| [`wireguard-hyper-connector`](crates/wireguard-hyper-connector) | Hyper/Tower connector for routing HTTP requests through the tunnel | Yes |
| [`warp-wireguard-gen`](crates/warp-wireguard-gen) | Cloudflare WARP registration and configuration generation | Yes |
| [`wireguard-managed-client`](crates/wireguard-managed-client) | Self-healing `reqwest::Client` with automatic reconnection | Git only* |

\* `wireguard-managed-client` depends on a [reqwest fork](#reqwest-fork) and must be used via git.

## Quick Start: Managed Client (Recommended)

The easiest way to use this library. The managed client handles WARP registration,
credential persistence, tunnel health monitoring, and automatic reconnection — you
just get a `reqwest::Client`.

### Cargo.toml

```toml
[dependencies]
wireguard-managed-client = { git = "https://github.com/Dreaming-Codes/wireguard-hyper-connector" }
tokio = { version = "1", features = ["full"] }
log = "0.4"
env_logger = "0.11"
```

### Cloudflare WARP (zero configuration)

```rust
use wireguard_managed_client::ManagedWgClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // One line: registers with WARP (or reuses saved credentials),
    // connects the tunnel, and starts the health monitor.
    let managed = ManagedWgClient::warp().await?;

    // This is a reqwest::Client — pass it to any library.
    let client = managed.client();

    let resp = client.get("https://httpbin.org/ip").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
```

On the first run, WARP credentials are saved to `warp-credentials.json`. Subsequent
runs skip registration entirely.

### WireGuard config file

```rust
use wireguard_managed_client::ManagedWgClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let managed = ManagedWgClient::from_config_file("wg.conf").await?;
    let client = managed.client();

    let resp = client.get("https://example.com").send().await?;
    println!("Status: {}", resp.status());

    managed.shutdown().await;
    Ok(())
}
```

### Custom tuning

```rust
use std::time::Duration;
use wireguard_managed_client::{ManagedWgClient, ClientConfig, RegistrationOptions};

let config = ClientConfig {
    handshake_stale_threshold: Duration::from_secs(120),
    health_check_interval: Duration::from_secs(5),
    max_consecutive_failures: 5,
    handshake_timeout: Duration::from_secs(15),
    request_timeout: Duration::from_secs(30),
    initial_backoff: Duration::from_secs(2),
    max_backoff: Duration::from_secs(120),
};

let managed = ManagedWgClient::warp_with_options(
    RegistrationOptions::default(),
    config,
).await?;
```

### Passing to third-party libraries

The client returned by `managed.client()` is a standard `reqwest::Client`. You can
pass it directly to any library that accepts one:

```rust
let managed = ManagedWgClient::warp().await?;
let client = managed.client();

// Pass to any library expecting reqwest::Client
// e.g. some_api_sdk::Client::new(client)
```

When the tunnel reconnects, calling `managed.client()` returns the new instance.
Old instances will error on the next request (the dead tunnel they reference is
shut down), which is the expected signal to call `client()` again.

## How It Works

The managed client runs a background supervisor that:

1. Monitors `WireGuardTunnel::time_since_last_handshake()` every 10 seconds
2. If the handshake age exceeds the threshold (default 180s), tears down the tunnel
3. Re-resolves the endpoint DNS, binds a fresh UDP socket, and reconnects
4. Atomically swaps in a new `reqwest::Client` via `arc-swap`
5. Uses exponential backoff (1s to 60s) between reconnect attempts

For WARP specifically, re-handshakes occur every ~25-30s (driven by the 25s persistent
keepalive). A threshold of 180s means ~6 missed handshake cycles before declaring
the tunnel dead.

## Low-Level Usage

If you don't need the managed client and want direct control over the tunnel:

### With hyper

```rust
use warp_wireguard_gen::{register, RegistrationOptions};
use wireguard_hyper_connector::{ManagedTunnel, WgConnector};
use std::time::Duration;

let (config, _creds) = register(RegistrationOptions::default()).await?;
let tunnel = ManagedTunnel::connect_with_timeout(config, Duration::from_secs(10)).await?;
let connector = WgConnector::new(tunnel.netstack());

let client = hyper_util::client::legacy::Client::builder(
    hyper_util::rt::TokioExecutor::new()
).build(connector);
```

### With a WireGuard config file

```rust
use wireguard_hyper_connector::{ManagedTunnel, WgConfigFile, WgConnector};
use std::time::Duration;

let config = WgConfigFile::from_file("wg.conf")?.into_wireguard_config().await?;
let tunnel = ManagedTunnel::connect_with_timeout(config, Duration::from_secs(10)).await?;
let connector = WgConnector::new(tunnel.netstack());
```

### Tunnel health checking

```rust
// Check if the tunnel is still healthy
match tunnel.time_since_last_handshake() {
    Some(elapsed) if elapsed < Duration::from_secs(180) => {
        // Tunnel is healthy
    }
    _ => {
        // Tunnel is stale — tear down and reconnect
        tunnel.shutdown().await;
    }
}
```

## Architecture

```
Application
    |
    v
reqwest / hyper Client
    |
    v
WgConnector (tower::Service)
    |
    +---> DohResolver (DNS via DoH)
    |
    v
NetStack (smoltcp userspace TCP/IP)
    |
    v
WireGuardTunnel (gotatun)
    |
    v
UDP Socket (to WireGuard peer)
```

## Reqwest Fork

This project uses a [reqwest fork](https://github.com/Dreaming-Codes/reqwest/tree/custom-hyper-connector)
that adds support for custom hyper connectors. This is required for routing reqwest
traffic through the WireGuard tunnel.

When using `wireguard-managed-client` via git, the fork is pulled automatically. If
you're building a workspace that also depends on `reqwest` directly, add a patch
section to your workspace `Cargo.toml`:

```toml
[patch.crates-io]
reqwest = { git = "https://github.com/Dreaming-Codes/reqwest", branch = "custom-hyper-connector" }
```

This ensures all crates in your workspace (including third-party libraries) use the
same reqwest build.

## Examples

```bash
# Managed client with WARP (recommended)
cargo run -p wireguard-managed-client --example reliable_warp

# Managed client with config file
cargo run -p wireguard-managed-client --example reliable_config -- wg.conf

# Low-level: hyper with WARP
cargo run -p wireguard-hyper-connector --example warp_demo

# Low-level: hyper with config file
cargo run -p wireguard-hyper-connector --example demo -- wg.conf

# Low-level: reqwest with WARP
cargo run -p wireguard-hyper-connector --example reqwest_custom_connector
```

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.
