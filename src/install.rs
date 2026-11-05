//! `copilot-cmd-gate install`: registers this binary as a user-level
//! `permissionRequest` hook for Copilot CLI.

use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const HOOK_FILE: &str = "cmd-gate.json";

fn hooks_dir(arg: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(dir) = arg {
        return Ok(dir);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or("neither HOME nor USERPROFILE is set; pass --dir <hooks dir>")?;
    Ok(PathBuf::from(home).join(".copilot").join("hooks"))
}

pub fn config(exe: &Path) -> Result<Value, String> {
    let exe = exe
        .to_str()
        .ok_or("binary path is not valid UTF-8, cannot write it into JSON")?;
    Ok(json!({
        "version": 1,
        "hooks": {
            "permissionRequest": [{
                "type": "command",
                "exec": exe,
                "matcher": "bash|powershell",
                "timeoutSec": 10
            }]
        }
    }))
}

/// Parses the arguments after `install`.
fn parse_args(args: &[String]) -> Result<Option<PathBuf>, String> {
    match args {
        [] => Ok(None),
        [flag, dir] if flag == "--dir" => Ok(Some(PathBuf::from(dir))),
        _ => Err("usage: copilot-cmd-gate install [--dir <hooks dir>]".into()),
    }
}

pub fn run(args: &[String]) -> Result<String, String> {
    let dir = hooks_dir(parse_args(args)?)?;
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("cannot locate this binary: {e}"))?;
    let body = serde_json::to_string_pretty(&config(&exe)?).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let path = dir.join(HOOK_FILE);
    std::fs::write(&path, body + "\n")
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(format!(
        "Installed hook for {} at {}\nRestart Copilot CLI for it to take effect.",
        exe.display(),
        path.display()
    ))
}
