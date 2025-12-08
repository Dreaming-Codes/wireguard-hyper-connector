# WireGuard Userspace Tunnel

A Rust library for routing HTTP traffic through WireGuard VPN tunnels entirely in userspace, without requiring root privileges or kernel-level WireGuard support. Includes seamless integration with Cloudflare WARP for zero-configuration VPN setup.

## Features

- **Userspace Implementation** - No kernel modules or admin privileges required
- **Cloudflare WARP Integration** - Zero-configuration VPN with automatic device registration
- **HTTP Client Support** - Works with `hyper` and `reqwest` via custom connectors
- **Encrypted DNS** - All DNS queries use DNS-over-HTTPS (DoH) with configurable providers
- **Pure Rust** - Cross-platform with no C dependencies for the core functionality

## Crates

This workspace contains three crates:

| Crate | Description |
|-------|-------------|
| [`wireguard-netstack`](crates/wireguard-netstack) | Core userspace WireGuard tunnel with embedded TCP/IP stack |
| [`wireguard-hyper-connector`](crates/wireguard-hyper-connector) | Hyper/Tower connector for routing HTTP requests through the tunnel |
| [`warp-wireguard-gen`](crates/warp-wireguard-gen) | Cloudflare WARP registration and configuration generation |

## Quick Start

### Using Cloudflare WARP (No Configuration Required)

```rust
use warp_wireguard_gen::{register, RegistrationOptions};
use wireguard_netstack::ManagedTunnel;
use wireguard_hyper_connector::WgConnector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Register with Cloudflare WARP
    let (config, _credentials) = register(RegistrationOptions::default()).await?;

    // Create a managed tunnel
    let tunnel = ManagedTunnel::new(config).await?;

    // Create a hyper client with the WireGuard connector
    let connector = WgConnector::new(tunnel);
    let client = hyper_util::client::legacy::Client::builder(
        hyper_util::rt::TokioExecutor::new()
    ).build(connector);

    // Make requests through the VPN tunnel
    let response = client.get("https://example.com".parse()?).await?;
    println!("Status: {}", response.status());

    Ok(())
}
```

### Using a WireGuard Configuration File

```rust
use wireguard_netstack::{ManagedTunnel, WgConfigFile};
use wireguard_hyper_connector::WgConnector;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load WireGuard configuration from file
    let wg_config = WgConfigFile::from_file("path/to/wireguard.conf")?;

    // Create a managed tunnel
    let tunnel = ManagedTunnel::new(wg_config.into()).await?;

    // Create a hyper client with the WireGuard connector
    let connector = WgConnector::new(tunnel);
    let client = hyper_util::client::legacy::Client::builder(
        hyper_util::rt::TokioExecutor::new()
    ).build(connector);

    // Make requests through the tunnel
    let response = client.get("https://example.com".parse()?).await?;
    println!("Status: {}", response.status());

    Ok(())
}
```

## Examples

Run the examples with:

```bash
# Basic demo with a WireGuard config file
cargo run --example demo -- path/to/wireguard.conf

# Cloudflare WARP demo (no configuration needed)
cargo run --example warp_demo

# Reqwest with custom connector
cargo run --example reqwest_custom_connector
```

## Architecture

```
Application
    │
    ▼
reqwest / hyper Client
    │
    ▼
WgConnector (tower::Service)
    │
    ├──► DohResolver (DNS via DoH)
    │
    ▼
NetStack (smoltcp userspace TCP/IP)
    │
    ▼
WireGuardTunnel (gotatun)
    │
    ▼
UDP Socket (to WireGuard peer)
```

### Reqwest Custom Connector

To use with `reqwest`, this library requires a fork with custom connector support:

```toml
[dependencies]
reqwest = { git = "https://github.com/Dreaming-Codes/reqwest", branch = "custom-hyper-connector", features = ["custom-hyper-connector"] }
```

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.
