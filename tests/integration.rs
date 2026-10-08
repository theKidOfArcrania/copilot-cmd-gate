use serde_json::{Value, json};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Out {
    Fall,
    Complex,
    Interp,
}

struct Env {
    state: PathBuf,
}

impl Env {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let state = std::env::temp_dir().join(format!("cmd-gate-it-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        Env { state }
    }

    fn run_raw(&self, stdin: &str) -> (String, bool) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_copilot-cmd-gate"))
            .env("XDG_STATE_HOME", &self.state)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        (String::from_utf8(out.stdout).unwrap(), out.status.success())
    }

    fn run(&self, session: &str, command: &str) -> Out {
        let payload = json!({
            "hookName": "permissionRequest",
            "sessionId": session,
            "cwd": "/tmp",
            "toolName": "bash",
            "toolInput": { "command": command },
            "permissionSuggestions": []
        });
        self.classify(&payload.to_string(), command)
    }

    fn classify(&self, stdin: &str, what: &str) -> Out {
        let (stdout, ok) = self.run_raw(stdin);
        assert!(ok, "non-zero exit for {what:?}");
        if stdout.trim().is_empty() {
            return Out::Fall;
        }
        let v: Value = serde_json::from_str(&stdout).expect("stdout must be valid JSON");
        assert_eq!(v["behavior"], "deny", "{what:?}");
        let msg = v["message"].as_str().expect("message");
        assert!(!msg.is_empty());
        if msg.contains("blocked by default") {
            Out::Interp
        } else {
            assert!(msg.starts_with("Command rejected"), "{what:?}: {msg}");
            Out::Complex
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.state);
    }
}

#[test]
fn simple_commands_fall_through() {
    let env = Env::new();
    for cmd in [
        "ls",
        "ls -la /tmp",
        "ls 2>&1",
        "git status",
        "git log --oneline -n 5",
        "git commit -F files/commit.txt",
        "git commit -m 'a; b | c && d $(e) `f`'",
        "git -c user.name=x log",
        "cargo test",
        "cargo build --release 2>&1",
        "cargo test >> log 2>&1",
        "cargo test > log 2> err",
        "echo \"hi there\" > out.txt",
        "echo a>b",
        "echo 'a'\"b\"c",
        "sort < in.txt",
        "grep -rn 'foo bar' src",
        "grep -E 'a|b' file",
        "awk '{print $1}' file",
        "sed -n '1,5p' file",
        "cat 'file with space.txt'",
        "ls *.rs",
        "ls ~/x a#b",
        "./script.sh",
        "./scripts/build_wasm.sh --flag",
        "rm -rf build",
        "npm test",
        "cd /tmp",
        "pushd /tmp",
        "sleep 1",
        "curl -sI https://example.com",
        "curl 'https://example.com/?a=1&b=2'",
        "test -f x",
        "echo \"a|b;c&d(e)\"",
        "'ls' -la",
        "\"ls\" -la",
    ] {
        assert_eq!(env.run("s", cmd), Out::Fall, "{cmd:?}");
    }
}

#[test]
fn complex_commands_are_denied() {
    let env = Env::new();
    for cmd in [
        "ls | head",
        "ls|head",
        "a | b | c",
        "a; b",
        "a;b",
        "a && b",
        "a || b",
        "cd x && ls",
        "cd x; ls",
        "a &",
        "a & b",
        "(a)",
        "(cd x; ls)",
        "{ a; }",
        "echo $HOME",
        "echo ${x}",
        "echo $(date)",
        "echo `date`",
        "echo \"$x\"",
        "echo \"$(x)\"",
        "echo \"`x`\"",
        "echo \"\\n\"",
        "echo \"!\"",
        "echo a\\ b",
        "ls\nls",
        "ls\n",
        "ls\r",
        "ls\tls\0",
        "cat <<EOF",
        "cat <<'EOF'",
        "cat <<-EOF",
        "a <<< b",
        "a <(b)",
        "a >(b)",
        "a >| f",
        "a &> f",
        "a &>> f",
        "a >&3",
        "a >& f",
        "a 2>&1x",
        "a >",
        "a <",
        "a > > b",
        "a > $f",
        "a > $(f)",
        "a <> f",
        "a=b",
        "FOO=bar a",
        "FOO=bar BAR=baz a",
        "# comment",
        "ls # comment",
        "echo 'x",
        "echo \"x",
        "[ -f x ]",
        "[[ -f x ]]",
        "! a",
        "echo é",
        "echo \u{202e}x",
        "",
        "   ",
        "> f",
        "2>&1",
        "for i in 1 2; do echo $i; done",
        "while true; do ls; done",
        "if true; then ls; fi",
        "case x in x) ls;; esac",
        "find . -name x -exec rm {} \\;",
        "find . -exec rm {} +",
        "cat f | xargs rm",
        "ls > /dev/null &",
        "echo $((1+1))",
        "echo ~$(x)",
        "ls *(.)",
        "echo a\\\nb",
        "source x.sh",
        ". x.sh",
        "builtin cd",
        "ionice ls",
        "setsid ls",
        "stdbuf -o0 ls",
        "watch ls",
        "unbuffer ls",
        "if",
        "for",
        "while",
        "function",
    ] {
        assert_eq!(env.run("s", cmd), Out::Complex, "{cmd:?}");
    }
}

#[test]
fn interpreters_deny_then_allow_once() {
    for cmd in [
        "python x.py",
        "python3 -c 'print(1)'",
        "python3.12 -c 'x'",
        "/usr/bin/python3 x.py",
        "/usr/bin/env python3 x.py",
        ".venv/bin/python x.py",
        "./python x.py",
        "pypy3 x",
        "node x.js",
        "nodejs x.js",
        "deno run x.ts",
        "bun x.ts",
        "perl -e 1",
        "Perl -e 1",
        "ruby x.rb",
        "php x.php",
        "lua x.lua",
        "bash -c 'ls'",
        "'bash' -c x",
        "\"sh\" x.sh",
        "sh script.sh",
        "zsh -c x",
        "dash x",
        "pwsh -c x",
        "env FOO=1 ls",
        "xargs rm",
        "sudo ls",
        "doas ls",
        "su -c ls",
        "nohup ls",
        "timeout 5 ls",
        "time ls",
        "command -v ls",
        "nice ls",
        "eval x",
        "exec ls",
    ] {
        let env = Env::new();
        assert_eq!(env.run("s", cmd), Out::Interp, "first: {cmd:?}");
        assert_eq!(env.run("s", cmd), Out::Fall, "second: {cmd:?}");
        assert_eq!(env.run("s", cmd), Out::Interp, "third: {cmd:?}");
    }
}

#[test]
fn backdoor_requires_the_exact_same_command() {
    let env = Env::new();
    assert_eq!(env.run("s", "python3 a.py"), Out::Interp);
    assert_eq!(env.run("s", "python3 b.py"), Out::Interp);
    assert_eq!(env.run("s", "python3  a.py"), Out::Interp);
    assert_eq!(env.run("s", "python3 a.py"), Out::Fall);
    assert_eq!(env.run("s", "python3 b.py"), Out::Fall);
    assert_eq!(env.run("s", "python3 a.py"), Out::Interp);
}

#[test]
fn backdoor_is_per_session() {
    let env = Env::new();
    assert_eq!(env.run("a", "node x.js"), Out::Interp);
    assert_eq!(env.run("b", "node x.js"), Out::Interp);
    assert_eq!(env.run("a", "node x.js"), Out::Fall);
    assert_eq!(env.run("b", "node x.js"), Out::Fall);
}

#[test]
fn backdoor_never_unlocks_complex_commands() {
    let env = Env::new();
    for _ in 0..3 {
        assert_eq!(env.run("s", "python3 x | cat"), Out::Complex);
        assert_eq!(env.run("s", "source x.sh"), Out::Complex);
    }
}

#[test]
fn backdoor_remembers_only_the_last_ten() {
    let env = Env::new();
    for i in 1..=11 {
        assert_eq!(env.run("s", &format!("python3 {i}.py")), Out::Interp);
    }
    assert_eq!(env.run("s", "python3 1.py"), Out::Interp, "evicted");
    assert_eq!(env.run("s", "python3 11.py"), Out::Fall, "still remembered");
}

#[test]
fn state_file_stays_inside_state_dir() {
    let env = Env::new();
    for session in ["../../evil", "a/b", "..", "", "x y\n"] {
        assert_eq!(env.run(session, "python3 x"), Out::Interp, "{session:?}");
    }
    let dir = env.state.join("copilot-cmd-gate");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 5);
    assert_eq!(std::fs::read_dir(&env.state).unwrap().count(), 1);
}

#[test]
fn corrupt_state_is_tolerated() {
    let env = Env::new();
    let dir = env.state.join("copilot-cmd-gate");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("s.json"), "{not json").unwrap();
    assert_eq!(env.run("s", "python3 x"), Out::Interp);
    assert_eq!(env.run("s", "python3 x"), Out::Fall);
}

#[test]
fn unusable_state_dir_fails_open() {
    let env = Env::new();
    std::fs::write(&env.state, "a file, not a dir").unwrap();
    assert_eq!(env.run("s", "python3 x"), Out::Fall);
    std::fs::remove_file(&env.state).unwrap();
}

#[test]
fn payload_variants() {
    let env = Env::new();
    let c = |s: &str| env.classify(s, s);

    assert_eq!(
        c(r#"{"tool_name":"bash","session_id":"s","tool_input":{"command":"a | b"}}"#),
        Out::Complex
    );
    assert_eq!(c(r#"{"toolName":"bash","toolInput":{"command":"python3 x"}}"#), Out::Interp);
    assert_eq!(c(r#"{"toolName":"bash","toolInput":{"command":"ls"}}"#), Out::Fall);
    assert_eq!(
        c(r#"{"toolName":"bash","sessionId":null,"toolInput":{"command":"python3 y"}}"#),
        Out::Interp
    );

    for tool in ["edit", "create", "view", "web_fetch", "powershell", ""] {
        let p = json!({"toolName": tool, "toolInput": {"command": "a | b"}}).to_string();
        assert_eq!(c(&p), Out::Fall, "tool {tool:?}");
    }

    for bad in [
        "",
        "   ",
        "not json",
        "{",
        "[]",
        "null",
        "42",
        "\"bash\"",
        "{}",
        r#"{"toolName":"bash"}"#,
        r#"{"toolName":"bash","toolInput":null}"#,
        r#"{"toolName":"bash","toolInput":{}}"#,
        r#"{"toolName":"bash","toolInput":{"command":null}}"#,
        r#"{"toolName":"bash","toolInput":{"command":42}}"#,
        r#"{"toolName":"bash","toolInput":{"command":["a | b"]}}"#,
        r#"{"toolName":7,"toolInput":{"command":"a | b"}}"#,
    ] {
        assert_eq!(c(bad), Out::Fall, "{bad:?}");
    }
}

#[test]
fn metacharacters_in_every_quoting_context() {
    let env = Env::new();
    for ch in ['|', '&', ';', '(', ')', '{', '}', '[', ']', '`', '$', '\\', '!'] {
        assert_eq!(env.run("s", &format!("ls a{ch}b")), Out::Complex, "bare {ch:?}");
        assert_eq!(env.run("s", &format!("ls {ch}")), Out::Complex, "alone {ch:?}");
        assert_eq!(env.run("s", &format!("ls a {ch} b")), Out::Complex, "spaced {ch:?}");
        assert_eq!(env.run("s", &format!("ls 'a{ch}b'")), Out::Fall, "single {ch:?}");
        let want = if matches!(ch, '`' | '$' | '\\' | '!') { Out::Complex } else { Out::Fall };
        assert_eq!(env.run("s", &format!("ls \"a{ch}b\"")), want, "double {ch:?}");
    }
    assert_eq!(env.run("s", "ls 'a\nb'"), Out::Complex, "newline in single quotes");
    assert_eq!(env.run("s", "ls \"a\nb\""), Out::Complex, "newline in double quotes");
    assert_eq!(env.run("s", "ls 'a\tb'"), Out::Complex, "tab in single quotes");
}

#[test]
fn only_the_first_word_picks_the_class() {
    let env = Env::new();
    for cmd in [
        "echo python",
        "git log --grep=bash",
        "cat python.py",
        "ls /usr/bin/python3",
        "grep node package.json",
        "cargo run -- python",
        "pythonista x",
        "nodemon x",
        "perlbrew list",
        "shellcheck x",
        "bashful x",
        "envsubst",
        "timeouts",
    ] {
        assert_eq!(env.run("s", cmd), Out::Fall, "{cmd:?}");
    }
}
