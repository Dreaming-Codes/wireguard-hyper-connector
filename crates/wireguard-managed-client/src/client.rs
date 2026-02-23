use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;

use wireguard_hyper_connector::{ManagedTunnel, WgConnector};

use crate::config::{ClientConfig, ConfigSource};
use crate::error::Result;

/// Current state of the WireGuard tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelStatus {
    /// Tunnel is up and the handshake is fresh.
    Connected,
    /// Tunnel health check failed — supervisor is tearing down the old tunnel.
    Disconnected,
    /// Supervisor is attempting to (re)connect. Contains the attempt number
    /// (1-based) within the current connect cycle.
    Reconnecting { attempt: u32 },
    /// The managed client has been shut down.
    Shutdown,
}

impl std::fmt::Display for TunnelStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected => write!(f, "connected"),
            Self::Disconnected => write!(f, "disconnected"),
            Self::Reconnecting { attempt } => write!(f, "reconnecting (attempt {})", attempt),
            Self::Shutdown => write!(f, "shutdown"),
        }
    }
}

/// A self-healing HTTP client that routes all traffic through a WireGuard tunnel.
///
/// Internally runs a supervisor task that monitors the tunnel's WireGuard
/// handshake health and automatically reconnects when the tunnel goes stale.
/// Each reconnect produces a fresh [`reqwest::Client`] that is atomically
/// swapped in.
///
/// # Status updates
///
/// Subscribe to tunnel state changes via [`status_receiver()`](Self::status_receiver):
///
/// ```ignore
/// let managed = ManagedWgClient::warp().await?;
/// let mut rx = managed.status_receiver();
///
/// tokio::spawn(async move {
///     while rx.changed().await.is_ok() {
///         println!("Tunnel status: {}", *rx.borrow());
///     }
/// });
/// ```
pub struct ManagedWgClient {
    inner: Arc<ArcSwap<reqwest_wg::Client>>,
    status_rx: watch::Receiver<TunnelStatus>,
    supervisor: Option<JoinHandle<()>>,
    shutdown: Arc<Notify>,
}

impl ManagedWgClient {
    /// Create and start a managed WireGuard client.
    ///
    /// The initial connection is attempted with the same exponential backoff
    /// used for reconnects — transient handshake failures (common with WARP)
    /// are retried automatically rather than returned as errors.
    pub(crate) async fn start(source: ConfigSource, cfg: ClientConfig) -> Result<Self> {
        let (status_tx, status_rx) = watch::channel(TunnelStatus::Reconnecting { attempt: 1 });

        // Attempt the initial connection with backoff, identical to how the
        // supervisor handles reconnects. This avoids hard-failing on the first
        // flaky WARP handshake.
        let (client, tunnel) = connect_with_backoff(&source, &cfg, &status_tx).await?;

        set_status(&status_tx, TunnelStatus::Connected);

        let inner = Arc::new(ArcSwap::from_pointee(client));
        let shutdown = Arc::new(Notify::new());

        let supervisor = tokio::spawn(supervisor_loop(
            source,
            cfg,
            inner.clone(),
            tunnel,
            shutdown.clone(),
            status_tx,
        ));

        Ok(Self {
            inner,
            status_rx,
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

    /// Get the current tunnel status.
    pub fn status(&self) -> TunnelStatus {
        self.status_rx.borrow().clone()
    }

    /// Get a receiver for tunnel status changes.
    ///
    /// Use [`tokio::sync::watch::Receiver::changed`] to await the next status
    /// transition:
    ///
    /// ```ignore
    /// let mut rx = managed.status_receiver();
    /// tokio::spawn(async move {
    ///     while rx.changed().await.is_ok() {
    ///         match &*rx.borrow() {
    ///             TunnelStatus::Connected => println!("Tunnel is up"),
    ///             TunnelStatus::Disconnected => println!("Tunnel went down"),
    ///             TunnelStatus::Reconnecting { attempt } => {
    ///                 println!("Reconnecting (attempt {})", attempt)
    ///             }
    ///             TunnelStatus::Shutdown => break,
    ///         }
    ///     }
    /// });
    /// ```
    pub fn status_receiver(&self) -> watch::Receiver<TunnelStatus> {
        self.status_rx.clone()
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

fn set_status(tx: &watch::Sender<TunnelStatus>, status: TunnelStatus) {
    log::info!("Tunnel status: {}", status);
    let _ = tx.send(status);
}

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

/// Connect with exponential backoff. Updates the status channel on each attempt.
/// Never returns an error — it keeps retrying until it succeeds or the process exits.
async fn connect_with_backoff(
    source: &ConfigSource,
    cfg: &ClientConfig,
    status_tx: &watch::Sender<TunnelStatus>,
) -> Result<(reqwest_wg::Client, ManagedTunnel)> {
    let mut backoff = cfg.initial_backoff;
    let mut attempt: u32 = 0;

    loop {
        attempt += 1;
        set_status(status_tx, TunnelStatus::Reconnecting { attempt });

        match connect_once(source, cfg).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                log::warn!(
                    "Connection attempt {} failed: {}. Retrying in {:?}...",
                    attempt,
                    e,
                    backoff
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(cfg.max_backoff);
            }
        }
    }
}

async fn supervisor_loop(
    source: ConfigSource,
    cfg: ClientConfig,
    inner: Arc<ArcSwap<reqwest_wg::Client>>,
    initial_tunnel: ManagedTunnel,
    shutdown: Arc<Notify>,
    status_tx: watch::Sender<TunnelStatus>,
) {
    let mut tunnel = initial_tunnel;

    loop {
        let reason = monitor_tunnel(&tunnel, &cfg, &shutdown).await;

        match reason {
            MonitorExit::Shutdown => {
                set_status(&status_tx, TunnelStatus::Shutdown);
                tunnel.shutdown().await;
                return;
            }
            MonitorExit::Unhealthy => {
                set_status(&status_tx, TunnelStatus::Disconnected);
                tunnel.shutdown().await;
            }
        }

        // Reconnect with backoff, respecting shutdown signals.
        let mut backoff = cfg.initial_backoff;
        let mut attempt: u32 = 0;

        loop {
            if try_shutdown(&shutdown) {
                set_status(&status_tx, TunnelStatus::Shutdown);
                return;
            }

            attempt += 1;
            set_status(&status_tx, TunnelStatus::Reconnecting { attempt });

            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = shutdown.notified() => {
                    set_status(&status_tx, TunnelStatus::Shutdown);
                    return;
                }
            }

            match connect_once(&source, &cfg).await {
                Ok((client, new_tunnel)) => {
                    inner.store(Arc::new(client));
                    tunnel = new_tunnel;
                    set_status(&status_tx, TunnelStatus::Connected);
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
    use std::future::Future;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop_waker() -> Waker {
        fn noop(_: *const ()) {}
        fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTABLE)
        }
        const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut fut = std::pin::pin!(shutdown.notified());
    matches!(fut.as_mut().poll(&mut cx), Poll::Ready(()))
}
