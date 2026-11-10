use hbb_common::tokio::{self, time::Duration};
use serde_json::Value;
use std::path::PathBuf;

const LOG_INTERVAL: Duration = Duration::from_secs(600);

/// What the GameCaste shell hands over on activation: the backend address
/// (without `shell/`), this PC's token (the `PC-TOKEN` header) and its club.
#[derive(Clone, PartialEq, Eq)]
pub struct RemoteConfig {
    pub api: String,
    pub pc_token: String,
    pub club_id: i64,
}

pub fn path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Gamecaste")
        .join("remote.json")
}

/// `None` until the shell has activated this PC; the file is rewritten on every
/// activation, so callers reload it instead of caching the result.
pub async fn load() -> Option<RemoteConfig> {
    let path = path();
    let content = match tokio::fs::read(&path).await {
        Ok(content) => content,
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                hbb_common::throttled_log!(
                    LOG_INTERVAL,
                    warn,
                    "Failed to read {}: {}",
                    path.display(),
                    err
                );
            }
            return None;
        }
    };
    let config = parse(&content);
    if config.is_none() {
        hbb_common::throttled_log!(
            LOG_INTERVAL,
            warn,
            "{} lacks api, pc_token or club_id",
            path.display()
        );
    }
    config
}

fn parse(content: &[u8]) -> Option<RemoteConfig> {
    let root: Value = serde_json::from_slice(content).ok()?;
    let api = root.get("api")?.as_str()?.trim_end_matches('/');
    let pc_token = root.get("pc_token")?.as_str()?;
    if api.is_empty() || pc_token.is_empty() {
        return None;
    }
    Some(RemoteConfig {
        api: api.to_owned(),
        pc_token: pc_token.to_owned(),
        club_id: root.get("club_id")?.as_i64()?,
    })
}
