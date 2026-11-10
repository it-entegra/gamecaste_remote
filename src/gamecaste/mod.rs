mod remote_config;
mod remote_id;
mod session;
mod status_pipe;

use hbb_common::{
    tls::TlsType,
    tokio::{self, time::Duration},
    ResultType,
};
use std::sync::atomic::{AtomicBool, Ordering};

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// Club host only: the status pipe the GameCaste shell queries, the channel the
/// backend requests one-time passwords on, and telling the backend this PC's
/// RustDesk id. Needs a running Tokio runtime.
pub fn start_host_integration() {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if !cfg!(windows) || crate::common::gamecaste_is_admin_edition() {
        return;
    }
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    tokio::spawn(status_pipe::serve());
    tokio::spawn(session::run());
    tokio::spawn(remote_id::run());
}

// These requests carry the PC token and one-time passwords, so over HTTPS the
// certificate is always verified, whatever the insecure-TLS fallback option says.
async fn http_client(url: &str) -> ResultType<reqwest::Client> {
    if url.starts_with("https://") {
        crate::hbbs_http::create_http_client_async_with_url_strict(url).await
    } else {
        Ok(crate::hbbs_http::create_http_client_async(
            TlsType::Plain,
            false,
        ))
    }
}
