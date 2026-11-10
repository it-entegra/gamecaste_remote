use super::remote_config::{self, RemoteConfig};
use hbb_common::{
    bail,
    bytes::Bytes,
    log, password_security as password,
    rand::{thread_rng, Rng},
    tls::TlsType,
    tokio::{
        self,
        time::{sleep, timeout, Duration},
    },
    websocket::WsFramedStream,
    ResultType,
};
use reqwest::StatusCode;
use serde_json::{json, Value};

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const WS_CONNECT_TIMEOUT_MS: u64 = 15_000;
// The server pings every 25 s.
const WS_SILENCE_TIMEOUT: Duration = Duration::from_secs(60);
const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(10);
const NO_TOKEN_RETRY_INTERVAL: Duration = Duration::from_secs(60);
const LOG_INTERVAL: Duration = Duration::from_secs(60);
const OTP_TTL: Duration = Duration::from_secs(600);
const OTP_LEN: usize = 12;
// No look-alike characters; the alphabet the shell uses for RustDesk passwords.
const OTP_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";

struct WsAccess {
    url: String,
    token: String,
}

/// Listens on the backend's Centrifugo channel for `new_remote_connection` and
/// answers each one with a fresh one-time password.
pub async fn run() {
    let mut failures: u32 = 0;
    let mut waiting = false;
    let mut current: Option<RemoteConfig> = None;
    loop {
        let Some(config) = remote_config::load().await else {
            if !waiting {
                waiting = true;
                log::info!("Waiting for {}", remote_config::path().display());
            }
            sleep(CONFIG_POLL_INTERVAL).await;
            continue;
        };
        waiting = false;
        if current.as_ref() != Some(&config) {
            log::info!("Backend {} (club {})", config.api, config.club_id);
            current = Some(config.clone());
        }
        match fetch_ws_access(&config).await {
            Ok(Some(access)) => {
                if let Err(err) = listen(&access, &config, &mut failures).await {
                    hbb_common::throttled_log!(LOG_INTERVAL, warn, "Session channel: {}", err);
                }
            }
            Ok(None) => {
                // The device token would keep this PC "online" for the backend with no
                // shell running, so without a token of its own the client stays offline.
                hbb_common::throttled_log!(
                    Duration::from_secs(3600),
                    info,
                    "The backend issues no remote session token yet"
                );
                sleep(NO_TOKEN_RETRY_INTERVAL).await;
                continue;
            }
            Err(err) => {
                hbb_common::throttled_log!(LOG_INTERVAL, warn, "Session channel token: {}", err);
            }
        }
        let seconds = (1u64 << failures.min(6)).min(60);
        failures = failures.saturating_add(1);
        let jitter = thread_rng().gen_range(0..1000u64);
        sleep(Duration::from_millis(seconds * 1000 + jitter)).await;
    }
}

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

async fn fetch_ws_access(config: &RemoteConfig) -> ResultType<Option<WsAccess>> {
    let url = format!("{}/shell/auth/ws", config.api);
    let response = http_client(&url)
        .await?
        .get(&url)
        .header("PC-TOKEN", config.pc_token.as_str())
        .header("Accept", "application/json")
        .timeout(HTTP_TIMEOUT)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        bail!("auth/ws returned {}", status);
    }
    let body: Value = serde_json::from_str(&response.text().await?)?;
    let data = &body["data"];
    let (Some(url), Some(token)) = (
        data["ws_url"].as_str(),
        data["websocket"]["remote"]["authToken"].as_str(),
    ) else {
        return Ok(None);
    };
    Ok(Some(WsAccess {
        url: url.to_owned(),
        token: token.to_owned(),
    }))
}

async fn send(ws: &mut WsFramedStream, message: &Value) -> ResultType<()> {
    ws.send_bytes(Bytes::from(message.to_string())).await
}

// Centrifugo's JSON protocol: the token carries the channels, so the server
// subscribes this connection itself; an empty object is its ping.
async fn listen(access: &WsAccess, config: &RemoteConfig, failures: &mut u32) -> ResultType<()> {
    let mut ws = WsFramedStream::new(access.url.as_str(), None, WS_CONNECT_TIMEOUT_MS).await?;
    send(
        &mut ws,
        &json!({ "id": 1, "connect": { "token": access.token, "name": "gamecaste-remote" } }),
    )
    .await?;
    loop {
        let frame = match timeout(WS_SILENCE_TIMEOUT, ws.next()).await {
            Ok(Some(frame)) => frame?,
            Ok(None) => bail!("closed by the server"),
            Err(_) => bail!("no ping for {} s", WS_SILENCE_TIMEOUT.as_secs()),
        };
        for line in frame[..].split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let message: Value = serde_json::from_slice(line)?;
            if message.as_object().map_or(false, |object| object.is_empty()) {
                send(&mut ws, &json!({})).await?;
                if remote_config::load()
                    .await
                    .map_or(false, |fresh| fresh != *config)
                {
                    bail!("remote.json changed");
                }
                continue;
            }
            if message["id"].as_i64() == Some(1) {
                if let Some(error) = message.get("error") {
                    bail!("connect refused: {}", error);
                }
                *failures = 0;
                hbb_common::throttled_log!(LOG_INTERVAL, info, "Session channel connected");
                continue;
            }
            let push = &message["push"];
            if let Some(disconnect) = push.get("disconnect") {
                bail!("disconnected by the server: {}", disconnect);
            }
            let data = &push["pub"]["data"];
            if data["type"].as_str() != Some("new_remote_connection") {
                continue;
            }
            match parse_admin_id(&data["data"]["from_admin_id"]) {
                Some(admin_id) => {
                    tokio::spawn(answer_connection_request(config.clone(), admin_id));
                }
                None => {
                    hbb_common::throttled_log!(
                        LOG_INTERVAL,
                        warn,
                        "new_remote_connection without from_admin_id"
                    );
                }
            }
        }
    }
}

fn parse_admin_id(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .filter(|id| *id > 0)
}

fn generate_otp() -> String {
    let mut rng = thread_rng();
    (0..OTP_LEN)
        .map(|_| OTP_ALPHABET[rng.gen_range(0..OTP_ALPHABET.len())] as char)
        .collect()
}

// The password is set before it is sent, so it already works when the admin
// receives it. Once it lets that admin in, the server rotates it itself.
async fn answer_connection_request(config: RemoteConfig, admin_id: i64) {
    let otp = generate_otp();
    *password::TEMPORARY_PASSWORD.write().unwrap() = otp.clone();
    let mut sent = post_otp(&config, admin_id, &otp).await;
    if matches!(&sent, Ok(status) if *status == StatusCode::UNAUTHORIZED) {
        // Every activation issues a new PC token and revokes the previous one.
        if let Some(fresh) = remote_config::load()
            .await
            .filter(|fresh| *fresh != config)
        {
            sent = post_otp(&fresh, admin_id, &otp).await;
        }
    }
    match sent {
        Ok(status) if status.is_success() => {
            hbb_common::throttled_log!(
                Duration::from_secs(1),
                info,
                "One-time password sent for admin {}",
                admin_id
            );
            sleep(OTP_TTL).await;
        }
        Ok(status) => {
            hbb_common::throttled_log!(
                Duration::from_secs(1),
                warn,
                "One-time password for admin {} not sent: the backend returned {}",
                admin_id,
                status
            );
        }
        Err(err) => {
            hbb_common::throttled_log!(
                Duration::from_secs(1),
                warn,
                "One-time password for admin {} not sent: {}",
                admin_id,
                err
            );
        }
    }
    if password::temporary_password() == otp {
        password::update_temporary_password();
    }
}

async fn post_otp(config: &RemoteConfig, admin_id: i64, otp: &str) -> ResultType<StatusCode> {
    let url = format!("{}/shell/action/sendRemoteUsePass", config.api);
    let response = http_client(&url)
        .await?
        .post(&url)
        .header("PC-TOKEN", config.pc_token.as_str())
        .header("Accept", "application/json")
        .json(&json!({ "admin_id": admin_id, "password": otp }))
        .timeout(HTTP_TIMEOUT)
        .send()
        .await?;
    Ok(response.status())
}
