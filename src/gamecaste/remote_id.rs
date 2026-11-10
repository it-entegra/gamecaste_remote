use super::{
    http_client,
    remote_config::{self, RemoteConfig},
    HTTP_TIMEOUT,
};
use hbb_common::{
    bail,
    config::{self, Config},
    tokio::time::{sleep, Duration, Instant},
    ResultType,
};
use serde_json::{json, Value};

const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(10);
const RETRY_INTERVAL: Duration = Duration::from_secs(60);
const REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 3600);
const LOG_INTERVAL: Duration = Duration::from_secs(600);

/// Tells the backend which RustDesk id this PC answers on, so the admin panel
/// can connect to it. Repeated until the backend links the id, then whenever the
/// id or the activation changes, and now and then in case the link was dropped.
pub async fn run() {
    let mut linked: Option<(RemoteConfig, String, Instant)> = None;
    loop {
        let mut pause = IDLE_POLL_INTERVAL;
        if let Some(config) = remote_config::load().await {
            let id = Config::get_id();
            let up_to_date = matches!(
                &linked,
                Some((linked_config, linked_id, at))
                    if *linked_config == config
                        && *linked_id == id
                        && at.elapsed() < REFRESH_INTERVAL
            );
            if up_to_date {
                pause = RETRY_INTERVAL;
            } else if config::get_online_state() > 0 {
                pause = RETRY_INTERVAL;
                match report(&config, &id).await {
                    Ok(true) => {
                        hbb_common::throttled_log!(
                            RETRY_INTERVAL,
                            info,
                            "The backend linked RustDesk id {} to this PC",
                            id
                        );
                        linked = Some((config, id, Instant::now()));
                    }
                    Ok(false) => {
                        // The backend learns ids from the RustDesk API server on a timer.
                        hbb_common::throttled_log!(
                            LOG_INTERVAL,
                            info,
                            "The backend does not know RustDesk id {} yet",
                            id
                        );
                    }
                    Err(err) => {
                        hbb_common::throttled_log!(
                            LOG_INTERVAL,
                            warn,
                            "Failed to report the RustDesk id: {}",
                            err
                        );
                    }
                }
            }
        }
        sleep(pause).await;
    }
}

async fn report(config: &RemoteConfig, id: &str) -> ResultType<bool> {
    if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("the id is not numeric");
    }
    let url = format!("{}/shell/action/setRemoteId", config.api);
    let response = http_client(&url)
        .await?
        .post(&url)
        .header("PC-TOKEN", config.pc_token.as_str())
        .header("Accept", "application/json")
        .json(&json!({ "rustdesk_id": id }))
        .timeout(HTTP_TIMEOUT)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        bail!("setRemoteId returned {}", status);
    }
    let body: Value = serde_json::from_str(&response.text().await?)?;
    Ok(body["data"]["linked"].as_bool() == Some(true))
}
