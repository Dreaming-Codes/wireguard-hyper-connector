use std::time::Duration;

use warp_wireguard_gen::{register, RegistrationOptions, WarpCredentials};

use crate::error::{Error, Result};

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Register a new device with Cloudflare WARP, retrying transient failures
/// with exponential backoff.
///
/// Returns `WarpCredentials` that the **caller** is responsible for persisting
/// and reusing across restarts.
pub async fn register_with_retry(options: RegistrationOptions) -> Result<WarpCredentials> {
    let mut backoff = INITIAL_BACKOFF;

    loop {
        log::info!("Registering new device with Cloudflare WARP...");

        match register(options.clone()).await {
            Ok((_config, creds)) => {
                log::info!("Registration successful (device {})", creds.device_id);
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
