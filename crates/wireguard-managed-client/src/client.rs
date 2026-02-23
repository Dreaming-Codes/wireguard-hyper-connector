use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use wireguard_hyper_connector::{ManagedTunnel, WgConnector};

use crate::config::{ClientConfig, ConfigSource};
use crate::error::Result;

/// A self-healing HTTP client that routes all traffic through a WireGuard tunnel.
///
/// Internally runs a supervisor task that monitors the tunnel's WireGuard
/// handshake health and automatically reconnects when the tunnel goes stale.
/// Each reconnect produces a fresh [`reqwest::Client`] that is atomically
/// swapped in.
///
/// # Usage
///
/// Call [`client()`](Self::client) to obtain the current `reqwest::Client`.
/// Pass it to any library that accepts a `reqwest::Client`. When the tunnel
/// reconnects, subsequent calls to `client()` return the new instance.
///
/// ```ignore
/// let managed = ManagedWgClient::new(source, config).await?;
/// let client = managed.client();
/// let resp = client.get("https://example.com").send().await?;
/// ```
pub struct ManagedWgClient {
    inner: Arc<ArcSwap<reqwest_wg::Client>>,
    supervisor: Option<JoinHandle<()>>,
    shutdown: Arc<Notify>,
}

impl ManagedWgClient {
    /// Create and start a managed WireGuard client.
    ///
    /// This performs the initial tunnel connection, builds the first
    /// `reqwest::Client`, and spawns the background supervisor that handles
    /// automatic reconnection.
    pub(crate) async fn start(source: ConfigSource, cfg: ClientConfig) -> Result<Self> {
        let (client, tunnel) = connect_once(&source, &cfg).await?;
        let inner = Arc::new(ArcSwap::from_pointee(client));
        let shutdown = Arc::new(Notify::new());

        let supervisor = tokio::spawn(supervisor_loop(
            source,
            cfg,
            inner.clone(),
            tunnel,
            shutdown.clone(),
        ));

        Ok(Self {
            inner,
            supervisor: Some(supervisor),
            shutdown,
        })
    }

    /// Get the current `reqwest::Client`.
    ///
    /// This is cheap (`Arc` clone). The returned client routes all requests
    /// through the active WireGuard tunnel.
    ///
    /// After a reconnect, calling this again returns the new client instance.
    /// Old instances will fail on the next request (the tunnel they reference
    /// is shut down), which is the expected signal for callers holding a stale
    /// reference to call `client()` again.
    pub fn client(&self) -> reqwest_wg::Client {
        (**self.inner.load()).clone()
    }

    /// Gracefully shut down the supervisor and the active tunnel.
    pub async fn shutdown(mut self) {
        self.shutdown.notify_one();
        if let Some(handle) = self.supervisor.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for ManagedWgClient {
    fn drop(&mut self) {
        self.shutdown.notify_one();
        if let Some(handle) = self.supervisor.take() {
            handle.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

async fn connect_once(
    source: &ConfigSource,
    cfg: &ClientConfig,
) -> Result<(reqwest_wg::Client, ManagedTunnel)> {
    let wg_config = source.resolve().await?;
    let tunnel = ManagedTunnel::connect_with_timeout(wg_config, cfg.handshake_timeout).await?;
    let connector = WgConnector::new(tunnel.netstack());

    let client = reqwest_wg::Client::builder()
        .custom_connector(connector)
        .timeout(cfg.request_timeout)
        .build()?;

    Ok((client, tunnel))
}

async fn supervisor_loop(
    source: ConfigSource,
    cfg: ClientConfig,
    inner: Arc<ArcSwap<reqwest_wg::Client>>,
    initial_tunnel: ManagedTunnel,
    shutdown: Arc<Notify>,
) {
    let mut tunnel = initial_tunnel;
    let mut backoff = cfg.initial_backoff;

    loop {
        // Monitor the current tunnel until it becomes unhealthy or shutdown is requested.
        let reason = monitor_tunnel(&tunnel, &cfg, &shutdown).await;

        match reason {
            MonitorExit::Shutdown => {
                log::info!("Shutdown requested — tearing down tunnel");
                tunnel.shutdown().await;
                return;
            }
            MonitorExit::Unhealthy => {
                log::warn!("Tunnel is stale — reconnecting...");
                tunnel.shutdown().await;
            }
        }

        // Reconnect loop with backoff.
        loop {
            // Check for shutdown between retries.
            if try_shutdown(&shutdown) {
                return;
            }

            log::info!("Reconnecting in {:?}...", backoff);
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = shutdown.notified() => { return; }
            }

            match connect_once(&source, &cfg).await {
                Ok((client, new_tunnel)) => {
                    inner.store(Arc::new(client));
                    tunnel = new_tunnel;
                    backoff = cfg.initial_backoff;
                    log::info!("Tunnel re-established");
                    break;
                }
                Err(e) => {
                    log::error!("Reconnect failed: {}. Retrying in {:?}...", e, backoff);
                    backoff = (backoff * 2).min(cfg.max_backoff);
                }
            }
        }
    }
}

enum MonitorExit {
    Unhealthy,
    Shutdown,
}

async fn monitor_tunnel(
    tunnel: &ManagedTunnel,
    cfg: &ClientConfig,
    shutdown: &Notify,
) -> MonitorExit {
    let mut interval = tokio::time::interval(cfg.health_check_interval);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let healthy = match tunnel.time_since_last_handshake() {
                    Some(elapsed) => {
                        log::debug!("Time since last handshake: {:?}", elapsed);
                        elapsed < cfg.handshake_stale_threshold
                    }
                    None => {
                        log::warn!("No handshake recorded — tunnel may be dead");
                        false
                    }
                };
                if !healthy {
                    return MonitorExit::Unhealthy;
                }
            }
            _ = shutdown.notified() => {
                return MonitorExit::Shutdown;
            }
        }
    }
}

fn try_shutdown(shutdown: &Notify) -> bool {
    // Non-blocking check: if notified, return true.
    // We use a zero-duration select to poll without blocking.
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    // Minimal noop waker for synchronous polling.
    fn noop_waker() -> Waker {
        fn noop(_: *const ()) {}
        fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTABLE)
        }
        const VTABLE: RawWakerVTable =
            RawWakerVTable::new(clone, noop, noop, noop);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(shutdown.notified());
    matches!(fut.as_mut().poll(&mut cx), Poll::Ready(()))
}
