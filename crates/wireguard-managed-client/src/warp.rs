use std::path::Path;
use std::time::Duration;

use warp_wireguard_gen::{register, RegistrationOptions, WarpCredentials};

use crate::error::{Error, Result};

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Register with Cloudflare WARP, retrying transient failures with exponential
/// backoff. If a credentials file exists at `path`, loads and returns it
/// immediately (skipping registration entirely).
pub(crate) async fn obtain_credentials(
    options: RegistrationOptions,
    credentials_path: Option<&Path>,
) -> Result<WarpCredentials> {
    if let Some(path) = credentials_path {
        if let Some(creds) = load_credentials(path) {
            log::info!("Loaded saved WARP credentials (device {})", creds.device_id);
            return Ok(creds);
        }
    }

    let mut backoff = INITIAL_BACKOFF;

    loop {
        log::info!("Registering new device with Cloudflare WARP...");

        match register(options.clone()).await {
            Ok((_config, creds)) => {
                log::info!("Registration successful (device {})", creds.device_id);
                if let Some(path) = credentials_path {
                    save_credentials(path, &creds);
                }
                return Ok(creds);
            }
            Err(e) => {
                if is_fatal(&e) {
                    return Err(Error::FatalRegistration(e.to_string()));
                }

                log::warn!(
                    "WARP registration failed (retrying in {:?}): {}",
                    backoff,
                    e
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

fn is_fatal(err: &warp_wireguard_gen::Error) -> bool {
    use warp_wireguard_gen::Error;
    match err {
        Error::Http(reqwest_err) => {
            if let Some(status) = reqwest_err.status() {
                if status == reqwest_wg::StatusCode::TOO_MANY_REQUESTS {
                    return false;
                }
                return status.is_client_error();
            }
            false
        }
        Error::Tls(_) | Error::InvalidKey(_) | Error::TeamsEnrollment(_) => true,
        _ => false,
    }
}

fn load_credentials(path: &Path) -> Option<WarpCredentials> {
    let data = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str::<WarpCredentials>(&data) {
        Ok(creds) => Some(creds),
        Err(e) => {
            log::warn!(
                "Failed to parse {}: {} — will re-register",
                path.display(),
                e
            );
            None
        }
    }
}

fn save_credentials(path: &Path, creds: &WarpCredentials) {
    match serde_json::to_string_pretty(creds) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, &json) {
                log::warn!("Failed to save credentials to {}: {}", path.display(), e);
            } else {
                log::info!("Saved WARP credentials to {}", path.display());
            }
        }
        Err(e) => log::warn!("Failed to serialize credentials: {}", e),
    }
}
