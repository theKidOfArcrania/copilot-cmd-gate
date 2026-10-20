//! `permissionRequest` hook for Copilot CLI.
//!
//! Reads the hook payload on stdin. Prints a deny decision for commands that
//! are too complex or that invoke a scripting language; prints nothing
//! (falling through to the normal permission engine) for everything else.
//! Any internal error also prints nothing.

mod classify;
mod parse;
mod ps_parse;
mod state;

use classify::{Class, Dialect};
use serde_json::{Value, json};
use std::io::{Read, Seek, SeekFrom, Write};

fn diagnostic(event: Value) {
    let Some(path) = std::env::var_os("CMD_GATE_LOG") else {
        return;
    };
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        file.lock()?;
        file.seek(SeekFrom::End(0))?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_millis();
        writeln!(file, "{}", json!({"timestamp": timestamp, "event": event}))
    })();
    if let Err(error) = result {
        eprintln!("cmd-gate diagnostic logging failed: {error}");
    }
}

fn field<'a>(v: &'a Value, camel: &str, snake: &str) -> Option<&'a Value> {
    v.get(camel).or_else(|| v.get(snake))
}

fn deny_complex(reason: &str, dialect: Dialect) -> String {
    let (redirects, extras) = match dialect {
        Dialect::Bash => (
            "> >> < or 2>&1",
            "No pipes, ||, background &, substitutions, variables, or subshells",
        ),
        Dialect::PowerShell => (
            "> >> or 2>&1",
            "No pipes, ||, the call operator & mid-command, $variables, $(...) subexpressions, \
             script blocks, splatting, backtick escapes except for literal quotes and dollars, \
             or comma arrays",
        ),
    };
    format!(
        "Command rejected: {reason}. Rewrite it as simple commands: a single program with plain \
         arguments, optionally with {redirects} file redirects, optionally chained with `;` or \
         `&&` (at most {max}). {extras}; use a separate tool call per step, or the dedicated \
         view/grep/glob/edit tools.",
        max = parse::MAX_COMMANDS
    )
}

fn deny_interpreter(name: &str) -> String {
    format!(
        "Running `{name}` is blocked by default; prefer a purpose-built CLI or the dedicated \
         view/grep/glob/edit tools. If there is truly no feasible alternative, re-issue the \
         exact same command unchanged and it will proceed to the normal permission check."
    )
}

fn decide(payload: &Value) -> Option<String> {
    let tool = field(payload, "toolName", "tool_name")?.as_str()?;
    let dialect = match tool {
        "bash" => Dialect::Bash,
        "powershell" => Dialect::PowerShell,
        _ => return None,
    };
    let input = field(payload, "toolInput", "tool_input")?;
    let command = input.get("command")?.as_str()?;
    let session = field(payload, "sessionId", "session_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let parsed = match dialect {
        Dialect::Bash => parse::parse(command),
        Dialect::PowerShell => ps_parse::parse(command),
    };
    let simple = match parsed {
        Ok(s) => s,
        Err(reason) => return Some(deny_complex(&reason, dialect)),
    };
    let class = classify::classify(&simple, dialect);
    diagnostic(json!({"stage": "classification", "class": format!("{class:?}")}));
    match class {
        Class::Plain => None,
        Class::Wrapper(name) => Some(deny_complex(
            &format!(
                "`{name}` runs other commands or shell constructs the gate cannot inspect; invoke \
                 the target program directly"
            ),
            dialect,
        )),
        Class::Interpreter(name) => match state::consume_or_record(session, command) {
            Ok(seen) => {
                diagnostic(json!({"stage": "retry_state", "seen": seen}));
                if seen {
                    None
                } else {
                    Some(deny_interpreter(&name))
                }
            }
            Err(error) => {
                diagnostic(json!({
                    "stage": "retry_state",
                    "error": error.to_string(),
                    "HOME": std::env::var_os("HOME"),
                    "XDG_STATE_HOME": std::env::var_os("XDG_STATE_HOME"),
                }));
                None
            }
        },
    }
}

fn main() {
    let mut raw = String::new();
    if let Err(error) = std::io::stdin().read_to_string(&mut raw) {
        diagnostic(json!({"stage": "stdin", "error": error.to_string()}));
        return;
    }
    let payload = match serde_json::from_str::<Value>(&raw) {
        Ok(payload) => payload,
        Err(error) => {
            diagnostic(json!({"stage": "payload", "error": error.to_string()}));
            return;
        }
    };
    diagnostic(json!({"stage": "payload", "payload": payload}));
    let decision = decide(&payload);
    diagnostic(json!({"stage": "decision", "deny": decision.is_some(), "message": decision}));
    if let Some(message) = decision {
        println!("{}", json!({ "behavior": "deny", "message": message }));
    }
}
