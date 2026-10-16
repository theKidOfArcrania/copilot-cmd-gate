use crate::parse::Script;

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

const PS_INTERPRETERS: &[&str] = &[
    "&",
    "iex",
    "invoke-expression",
    "icm",
    "invoke-command",
    "start-process",
    "start",
    "saps",
    "start-job",
    "start-threadjob",
    "add-type",
    "cmd",
    "powershell",
    "pwsh",
    "wsl",
    "bash",
    "sh",
    "zsh",
    "python",
    "py",
    "pythonw",
    "pypy",
    "node",
    "nodejs",
    "deno",
    "bun",
    "perl",
    "ruby",
    "php",
    "lua",
    "julia",
    "rscript",
    "cscript",
    "wscript",
    "mshta",
    "rundll",
    "regsvr",
    "sudo",
    "runas",
    "env",
    "xargs",
    "timeout",
];

const PS_WRAPPERS: &[&str] = &[
    ".",
    "%",
    "?",
    "foreach",
    "foreach-object",
    "where",
    "where-object",
    "if",
    "for",
    "while",
    "do",
    "switch",
    "try",
    "function",
    "filter",
    "workflow",
    "param",
    "trap",
    "begin",
    "process",
    "end",
    "class",
    "using",
    "invoke-item",
    "ii",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Bash,
    PowerShell,
}

/// Normalizes `/usr/bin/python3.12` to `python`.
fn base(word: &str, dialect: Dialect) -> String {
    let name = match dialect {
        Dialect::Bash => word.rsplit('/').next().unwrap_or(word),
        Dialect::PowerShell => word.rsplit(['/', '\\']).next().unwrap_or(word),
    }
    .to_ascii_lowercase();
    let mut name = name.as_str();
    if dialect == Dialect::PowerShell {
        for ext in [".exe", ".cmd", ".bat", ".com"] {
            if let Some(stem) = name.strip_suffix(ext) {
                name = stem;
            }
        }
    }
    let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    let trimmed = if trimmed.is_empty() { name } else { trimmed };
    trimmed.to_string()
}

/// Wrappers win over interpreters, which win over plain commands, so one
/// risky command in a chain determines how the whole chain is handled.
pub fn classify(script: &Script, dialect: Dialect) -> Class {
    let (interpreters, wrappers) = match dialect {
        Dialect::Bash => (INTERPRETERS, WRAPPERS),
        Dialect::PowerShell => (PS_INTERPRETERS, PS_WRAPPERS),
    };
    let mut interp = None;
    for cmd in &script.commands {
        let name = base(&cmd[0], dialect);
        if wrappers.contains(&name.as_str()) {
            return Class::Wrapper(name);
        }
        if interp.is_none() && interpreters.contains(&name.as_str()) {
            interp = Some(name);
        }
    }
    interp.map_or(Class::Plain, Class::Interpreter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;

    fn c(s: &str) -> Class {
        classify(&parse(s).unwrap(), Dialect::Bash)
    }

    fn p(s: &str) -> Class {
        classify(&crate::ps_parse::parse(s).unwrap(), Dialect::PowerShell)
    }

    #[test]
    fn classifies_powershell() {
        let i = |s: &str| Class::Interpreter(s.into());
        assert_eq!(p("Get-ChildItem -Force"), Class::Plain);
        assert_eq!(p("git status; ls"), Class::Plain);
        assert_eq!(p("Invoke-Expression 'x'"), i("invoke-expression"));
        assert_eq!(p("IEX 'x'"), i("iex"));
        assert_eq!(p("Start-Process notepad"), i("start-process"));
        assert_eq!(p("Invoke-Command -ScriptBlock x"), i("invoke-command"));
        assert_eq!(p("& 'C:\\tool.exe' a"), i("&"));
        assert_eq!(p("ls; & x"), i("&"));
        assert_eq!(p("C:\\Python312\\python.exe a.py"), i("python"));
        assert_eq!(p("pwsh.exe -c x"), i("pwsh"));
        assert_eq!(p("CMD /c dir"), i("cmd"));
        assert_eq!(p("node a.js"), i("node"));
        assert_eq!(p("perl -e 1"), i("perl"));
        assert_eq!(p("ruby a.rb"), i("ruby"));
        assert_eq!(p("bash -c x"), i("bash"));
        assert_eq!(p(". ./x.ps1"), Class::Wrapper(".".into()));
        assert_eq!(p("ls; if"), Class::Wrapper("if".into()));
        assert_eq!(p("echo python"), Class::Plain);
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
        assert_eq!(c("cd x && ls; git status"), Class::Plain);
        assert_eq!(
            c("cd x && python3 a.py"),
            Class::Interpreter("python".into())
        );
        assert_eq!(c("ls; ls; node a.js"), Class::Interpreter("node".into()));
        assert_eq!(c("python3 a; node b"), Class::Interpreter("python".into()));
        assert_eq!(c("python3 a && source b"), Class::Wrapper("source".into()));
        assert_eq!(c("source b; python3 a"), Class::Wrapper("source".into()));
    }
}
