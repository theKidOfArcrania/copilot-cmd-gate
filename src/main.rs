//! `permissionRequest` hook for Copilot CLI.
//!
//! Reads the hook payload on stdin. Prints a deny decision for commands that
//! are too complex or that invoke a scripting language; prints nothing
//! (falling through to the normal permission engine) for everything else.
//! Any internal error also prints nothing.

mod classify;
mod parse;
mod state;

use classify::Class;
use serde_json::{Value, json};
use std::io::Read;

fn field<'a>(v: &'a Value, camel: &str, snake: &str) -> Option<&'a Value> {
    v.get(camel).or_else(|| v.get(snake))
}

fn deny_complex(reason: &str) -> String {
    format!(
        "Command rejected: {reason}. Rewrite it as simple commands: a single program with plain \
         arguments, optionally with > >> < or 2>&1 file redirects, optionally chained with `;` or \
         `&&` (at most {max}). No pipes, ||, background &, substitutions, variables, or \
         subshells; use a separate tool call per step, or the dedicated view/grep/glob/edit tools.",
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
    if field(payload, "toolName", "tool_name")?.as_str()? != "bash" {
        return None;
    }
    let input = field(payload, "toolInput", "tool_input")?;
    let command = input.get("command")?.as_str()?;
    let session = field(payload, "sessionId", "session_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let simple = match parse::parse(command) {
        Ok(s) => s,
        Err(reason) => return Some(deny_complex(&reason)),
    };
    match classify::classify(&simple) {
        Class::Plain => None,
        Class::Wrapper(name) => Some(deny_complex(&format!(
            "`{name}` runs other commands or shell constructs the gate cannot inspect; invoke the \
             target program directly"
        ))),
        Class::Interpreter(name) => match state::consume_or_record(session, command) {
            Ok(false) => Some(deny_interpreter(&name)),
            Ok(true) | Err(_) => None,
        },
    }
}

fn main() {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return;
    }
    let Ok(payload) = serde_json::from_str::<Value>(&raw) else {
        return;
    };
    if let Some(message) = decide(&payload) {
        println!("{}", json!({ "behavior": "deny", "message": message }));
    }
}
