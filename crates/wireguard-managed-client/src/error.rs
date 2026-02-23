use thiserror::Error;

pub type Result<T> = std::result::Result<T, self::Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("WireGuard tunnel error: {0}")]
    Tunnel(#[from] wireguard_netstack::Error),

    #[error("Connector error: {0}")]
    Connector(#[from] wireguard_hyper_connector::Error),

    #[cfg(feature = "warp")]
    #[error("WARP registration error: {0}")]
    Warp(#[from] warp_wireguard_gen::Error),

    #[error("HTTP client build error: {0}")]
    ReqwestBuild(#[from] reqwest_wg::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Credential persistence error: {0}")]
    CredentialPersistence(String),

    #[error("Fatal registration error (will not retry): {0}")]
    FatalRegistration(String),

    #[error("Client has been shut down")]
    Shutdown,
}
