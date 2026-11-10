mod remote_config;
mod session;
mod status_pipe;

use hbb_common::tokio;
use std::sync::atomic::{AtomicBool, Ordering};

/// Club host only: the status pipe the GameCaste shell queries and the channel
/// the backend requests one-time passwords on. Needs a running Tokio runtime.
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
}
