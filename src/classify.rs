use crate::parse::Simple;

#[derive(Debug, PartialEq, Eq)]
pub enum Class {
    Plain,
    /// Runs arbitrary code from a scripting language or shell.
    Interpreter(String),
    /// Runs another command (or shell construct) the gate cannot see.
    Wrapper(String),
}

const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "ash",
    "busybox",
    "python",
    "pypy",
    "node",
    "nodejs",
    "deno",
    "bun",
    "perl",
    "ruby",
    "php",
    "lua",
    "luajit",
    "tclsh",
    "wish",
    "julia",
    "rscript",
    "pwsh",
    "powershell",
    "osascript",
    "groovy",
    "jshell",
    "irb",
    "ts-node",
    "tsx",
    "env",
    "xargs",
    "eval",
    "exec",
    "sudo",
    "doas",
    "su",
    "nohup",
    "timeout",
    "time",
    "command",
    "nice",
];

const WRAPPERS: &[&str] = &[
    "builtin", "ionice", "setsid", "stdbuf", "watch", "source", ".", "unbuffer", "if", "for",
    "while", "until", "case", "select", "function", "coproc", "do", "then", "else", "elif", "done",
    "fi", "esac", "[[",
];

/// Normalizes `/usr/bin/python3.12` to `python`.
fn base(word: &str) -> String {
    let name = word.rsplit('/').next().unwrap_or(word);
    let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    let trimmed = if trimmed.is_empty() { name } else { trimmed };
    trimmed.to_ascii_lowercase()
}

pub fn classify(cmd: &Simple) -> Class {
    let name = base(&cmd.words[0]);
    if WRAPPERS.contains(&name.as_str()) {
        Class::Wrapper(name)
    } else if INTERPRETERS.contains(&name.as_str()) {
        Class::Interpreter(name)
    } else {
        Class::Plain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;

    fn c(s: &str) -> Class {
        classify(&parse(s).unwrap())
    }

    #[test]
    fn classifies() {
        assert_eq!(c("python3.12 -c 'x'"), Class::Interpreter("python".into()));
        assert_eq!(c("/usr/bin/node a.js"), Class::Interpreter("node".into()));
        assert_eq!(c("'bash' -c x"), Class::Interpreter("bash".into()));
        assert_eq!(c("Perl -e 1"), Class::Interpreter("perl".into()));
        assert_eq!(c("env FOO=1 ls"), Class::Interpreter("env".into()));
        assert_eq!(c("xargs rm"), Class::Interpreter("xargs".into()));
        assert_eq!(c("sudo ls"), Class::Interpreter("sudo".into()));
        assert_eq!(c("source x.sh"), Class::Wrapper("source".into()));
        assert_eq!(c("for"), Class::Wrapper("for".into()));
        assert_eq!(c("ls -la"), Class::Plain);
        assert_eq!(c("cargo test"), Class::Plain);
        assert_eq!(c("./script.sh"), Class::Plain);
    }
}
