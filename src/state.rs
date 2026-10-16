//! Per-session list of recently denied commands, used for the re-request
//! backdoor: seeing a denied command a second time lets it through once.

use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

pub const RECENT_CAP: usize = 10;

fn dir() -> Option<PathBuf> {
    let nonempty_env = |name| std::env::var_os(name).filter(|value| !value.is_empty());
    let base = nonempty_env("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| nonempty_env("HOME").map(|home| PathBuf::from(home).join(".local/state")));
    #[cfg(windows)]
    let base = base
        .or_else(|| nonempty_env("LOCALAPPDATA").map(PathBuf::from))
        .or_else(|| {
            nonempty_env("USERPROFILE")
                .map(|home| PathBuf::from(home).join("AppData").join("Local"))
        });
    let base = base?;
    Some(base.join("copilot-cmd-gate"))
}

/// Returns `Ok(true)` if `command` was already recorded (and removes it),
/// otherwise records it and returns `Ok(false)`.
pub fn consume_or_record(session: &str, command: &str) -> std::io::Result<bool> {
    let dir = dir().ok_or_else(|| std::io::Error::other("no state dir"))?;
    fs::create_dir_all(&dir)?;
    let safe: String = session
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(format!("{safe}.json")))?;
    file.lock()?;

    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let mut recent: Vec<String> = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v.as_array().cloned())
        .map(|a| {
            a.into_iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let seen = if let Some(pos) = recent.iter().position(|c| c == command) {
        recent.remove(pos);
        true
    } else {
        recent.push(command.to_string());
        if recent.len() > RECENT_CAP {
            recent.remove(0);
        }
        false
    };

    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(serde_json::to_string(&recent)?.as_bytes())?;
    Ok(seen)
}
