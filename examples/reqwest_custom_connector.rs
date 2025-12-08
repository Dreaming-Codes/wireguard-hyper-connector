//! Example demonstrating the use of reqwest with a custom hyper connector
//! that routes all traffic through a WireGuard tunnel.
//!
//! This uses the reqwest fork with custom-hyper-connector feature from:
//! https://github.com/Dreaming-Codes/reqwest/tree/custom-hyper-connector
//!
//! Once the feature is merged upstream, this will work with regular reqwest.
//!
//! Usage: cargo run --example reqwest_custom_connector

use std::time::Duration;
use warp_wireguard_gen::{register, RegistrationOptions};
use wireguard_hyper_connector::{ManagedTunnel, WgConnector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    log::info!("Starting reqwest custom connector demo");

    // Register with Cloudflare WARP and get WireGuard config
    log::info!("Registering with Cloudflare WARP...");
    let (config, credentials) = register(RegistrationOptions {
        device_model: "reqwest-custom-connector-demo/0.1.0".to_string(),
        license_key: None, // Set to Some("xxxx-xxxx-xxxx") for Warp+
    })
    .await?;

    log::info!("Registration successful!");
    log::info!("  Device ID: {}", credentials.device_id);
    log::info!("  Tunnel IP: {}", config.tunnel_ip);
    log::info!("  Endpoint: {}", config.peer_endpoint);

    // Connect using the managed tunnel (handles all background tasks)
    log::info!("Establishing WireGuard tunnel...");
    let tunnel = ManagedTunnel::connect_with_timeout(config, Duration::from_secs(10)).await?;
    log::info!("Tunnel established!");

    // Create the WireGuard connector for hyper
    let connector = WgConnector::new(tunnel.netstack());

    // Create a reqwest client using our custom WireGuard connector
    // This uses the custom-hyper-connector feature
    // Once merged upstream, just change `reqwest_wg` to `reqwest`
    let client = reqwest_wg::Client::builder()
        .custom_connector(connector)
        .build()?;

    // Make a request to verify we're going through WARP
    log::info!("Making request to https://www.cloudflare.com/cdn-cgi/trace ...");

    let response = client
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .header("User-Agent", "reqwest-custom-connector-demo/0.1.0")
        .send()
        .await?;

    log::info!("Response status: {}", response.status());

    let body = response.text().await?;

    println!();
    println!("{}", "=".repeat(70));
    println!("Cloudflare Trace Response:");
    println!("{}", "=".repeat(70));
    println!("{}", body);
    println!("{}", "=".repeat(70));

    // Check if WARP is active
    if body.contains("warp=on") {
        log::info!("WARP is active (free tier)");
    } else if body.contains("warp=plus") {
        log::info!("WARP+ is active (premium tier)");
    } else if body.contains("warp=off") {
        log::warn!("WARP appears to be off - connection may not be going through WARP");
    }

    // Also make a request to httpbin to show request details
    log::info!("Making request to https://httpbin.org/ip ...");

    let response = client
        .get("https://httpbin.org/ip")
        .header("User-Agent", "reqwest-custom-connector-demo/0.1.0")
        .send()
        .await?;

    log::info!("httpbin response status: {}", response.status());

    let body = response.text().await?;

    println!();
    println!("{}", "=".repeat(70));
    println!("httpbin.org/ip Response (your IP as seen by the server):");
    println!("{}", "=".repeat(70));
    println!("{}", body);
    println!("{}", "=".repeat(70));

    // Make a POST request to demonstrate full HTTP functionality
    log::info!("Making POST request to https://httpbin.org/post ...");

    let response = client
        .post("https://httpbin.org/post")
        .header("User-Agent", "reqwest-custom-connector-demo/0.1.0")
        .header("Content-Type", "application/json")
        .body(r#"{"message": "Hello from WireGuard tunnel!", "demo": true}"#)
        .send()
        .await?;

    log::info!("POST response status: {}", response.status());

    let body = response.text().await?;

    println!();
    println!("{}", "=".repeat(70));
    println!("httpbin.org/post Response:");
    println!("{}", "=".repeat(70));
    // Print first 500 chars to keep output manageable
    let preview_len = std::cmp::min(500, body.len());
    println!("{}", &body[..preview_len]);
    if body.len() > preview_len {
        println!("... ({} more bytes)", body.len() - preview_len);
    }
    println!("{}", "=".repeat(70));

    log::info!("Demo complete!");

    // Graceful shutdown
    tunnel.shutdown().await;

    Ok(())
}
