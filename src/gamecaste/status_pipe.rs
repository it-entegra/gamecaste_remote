use hbb_common::{
    config::{self, Config},
    log,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        time::{sleep, timeout, Duration},
    },
};
#[cfg(windows)]
use parity_tokio_ipc::SecurityAttributes;
use parity_tokio_ipc::{Connection, Endpoint};
use serde_json::{json, Value};

const MAX_LINE: usize = 4096;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// SYSTEM, administrators and the account that created the pipe. The shell
// queries as an administrator; the reply carries no secrets either way.
#[cfg(windows)]
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";

/// `\\.\pipe\<app name>`, newline-delimited JSON: `{"cmd":"status"}` is answered
/// with `{"type":"status","id","version","online","server"}`.
pub async fn serve() {
    let path = format!(r"\\.\pipe\{}", crate::get_app_name());
    let mut endpoint = Endpoint::new(path.clone());
    #[cfg(windows)]
    match SecurityAttributes::from_sddl(PIPE_SDDL) {
        Ok(attributes) => endpoint.set_security_attributes(attributes),
        Err(err) => {
            log::error!("Failed to set status pipe security: {}", err);
            return;
        }
    }
    let mut incoming = match endpoint.incoming() {
        Ok(incoming) => incoming,
        Err(err) => {
            log::error!("Failed to start status pipe {}: {}", path, err);
            return;
        }
    };
    log::info!("Started status pipe {}", path);
    while let Some(connection) = incoming.next().await {
        match connection {
            Ok(connection) => {
                tokio::spawn(handle(connection));
            }
            Err(err) => {
                hbb_common::throttled_log!(
                    Duration::from_secs(60),
                    warn,
                    "Status pipe accept failed: {}",
                    err
                );
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn handle(mut connection: Connection) {
    let mut line = Vec::new();
    let mut buffer = [0u8; 512];
    loop {
        let read = match timeout(IDLE_TIMEOUT, connection.read(&mut buffer)).await {
            Ok(Ok(read)) if read > 0 => read,
            _ => return,
        };
        for &byte in &buffer[..read] {
            if byte != b'\n' {
                if line.len() >= MAX_LINE {
                    return;
                }
                line.push(byte);
                continue;
            }
            if is_status_request(&line) {
                let mut reply = status().to_string().into_bytes();
                reply.push(b'\n');
                if connection.write_all(&reply).await.is_err() {
                    return;
                }
            }
            line.clear();
        }
    }
}

fn is_status_request(line: &[u8]) -> bool {
    serde_json::from_slice::<Value>(line)
        .ok()
        .map_or(false, |request| request["cmd"].as_str() == Some("status"))
}

fn status() -> Value {
    json!({
        "type": "status",
        "id": Config::get_id(),
        "version": crate::VERSION,
        "online": config::get_online_state() > 0,
        "server": Config::get_rendezvous_server(),
    })
}
