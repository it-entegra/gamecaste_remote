mod remote_config;
mod remote_id;
mod session;
mod status_pipe;

use hbb_common::{
    flexi_logger::{
        writers::FileLogWriter, Age, Cleanup, Criterion, FileSpec, LoggerHandle, Naming,
    },
    log,
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

/// Club host only: the service and its server process log to the folder the
/// GameCaste shell collects logs from. On failure the log stays where it was.
pub fn relocate_log(logger: Option<LoggerHandle>, name: &str) {
    if !cfg!(windows)
        || crate::common::gamecaste_is_admin_edition()
        || !matches!(name, "service" | "server")
    {
        return;
    }
    let Some(logger) = logger else {
        return;
    };
    let directory = remote_config::path().with_file_name("Logs").join("remote");
    // Rotated the way hbb_common::init_log does it.
    let writer = FileLogWriter::builder(FileSpec::default().directory(directory).basename(name))
        .rotate(
            Criterion::AgeOrSize(Age::Day, 16 * 1024 * 1024),
            Naming::Timestamps,
            Cleanup::KeepLogFiles(90),
        );
    if let Err(err) = logger.reset_flw(&writer) {
        log::warn!("The log stays in its default folder: {}", err);
    }
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
