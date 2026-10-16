//! Deliberately tiny and strict shell parser.
//!
//! Accepts a list of simple commands joined by `;` or `&&`. Each command is
//! plain words (optionally single or double quoted) plus `>`, `>>`, `<` file
//! redirects and `N>&1`/`N>&2` dups. Everything else is rejected, so this is
//! meant to accept a strict subset of what the CLI's own parser accepts.

/// Upper bound on chained commands, to keep deny messages actionable.
pub const MAX_COMMANDS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub struct Script {
    pub commands: Vec<Vec<String>>,
}

#[derive(Debug, PartialEq, Eq)]
enum Tok {
    Word(String),
    Redir,
    Dup,
    Sep,
}

pub fn parse(input: &str) -> Result<Script, String> {
    let toks = tokenize(input)?;
    let commands = toks
        .split(|t| *t == Tok::Sep)
        .map(parse_command)
        .collect::<Result<Vec<_>, _>>()?;
    if commands.len() > MAX_COMMANDS {
        return Err(format!("more than {MAX_COMMANDS} chained commands"));
    }
    Ok(Script { commands })
}

fn parse_command(toks: &[Tok]) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        match &toks[i] {
            Tok::Word(w) => words.push(w.clone()),
            Tok::Dup => {}
            Tok::Redir => match toks.get(i + 1) {
                Some(Tok::Word(_)) => i += 1,
                _ => return Err("redirect without a plain file target".into()),
            },
            Tok::Sep => unreachable!("segments are split on separators"),
        }
        i += 1;
    }
    let Some(first) = words.first() else {
        return Err("no command word".into());
    };
    if first.contains('=') {
        return Err("leading environment variable assignment".into());
    }
    Ok(words)
}

fn bad(c: char) -> String {
    format!("unsupported shell syntax `{}`", c.escape_default())
}

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    // True while the current word is made only of unquoted digits (fd prefix).
    let mut digits_only = true;
    let mut i = 0;

    macro_rules! flush {
        () => {
            if in_word {
                toks.push(Tok::Word(std::mem::take(&mut cur)));
                in_word = false;
                digits_only = true;
            }
        };
    }

    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' => flush!(),
            '\'' => {
                let end = chars[i + 1..]
                    .iter()
                    .position(|&x| x == '\'')
                    .ok_or("unterminated single quote")?;
                if chars[i + 1..i + 1 + end].iter().any(|x| x.is_control()) {
                    return Err("control character in quotes".into());
                }
                cur.extend(&chars[i + 1..i + 1 + end]);
                in_word = true;
                digits_only = false;
                i += end + 1;
            }
            '"' => {
                i += 1;
                loop {
                    let Some(&x) = chars.get(i) else {
                        return Err("unterminated double quote".into());
                    };
                    match x {
                        '"' => break,
                        '$' | '`' | '\\' | '!' => return Err(bad(x)),
                        _ if x.is_control() => return Err("control character in quotes".into()),
                        _ => cur.push(x),
                    }
                    i += 1;
                }
                in_word = true;
                digits_only = false;
            }
            '>' | '<' => {
                let fd_ok = in_word && digits_only && cur.len() <= 1;
                if fd_ok {
                    cur.clear();
                    in_word = false;
                    digits_only = true;
                } else {
                    flush!();
                }
                if c == '>' && chars.get(i + 1) == Some(&'&') {
                    let fd = chars.get(i + 2);
                    let after = chars.get(i + 3);
                    let ended = after.is_none_or(|a| matches!(a, ' ' | '\t' | ';' | '&'));
                    if matches!(fd, Some('1' | '2')) && ended {
                        toks.push(Tok::Dup);
                        i += 3;
                        continue;
                    }
                    return Err(bad('&'));
                }
                if c == '>' && chars.get(i + 1) == Some(&'>') {
                    i += 1;
                }
                if matches!(chars.get(i + 1), Some('>' | '<' | '&' | '|' | '(')) {
                    return Err(bad(chars[i + 1]));
                }
                toks.push(Tok::Redir);
            }
            '#' if !in_word => return Err(bad('#')),
            ';' | '&' => {
                let next = chars.get(i + 1);
                let after = chars.get(i + 2);
                let is_and = c == '&' && next == Some(&'&');
                let ok_after = !matches!(after, Some('&' | '|' | ';' | '>' | '<'));
                if c == ';' && !matches!(next, Some('&' | ';' | '|')) {
                    flush!();
                    toks.push(Tok::Sep);
                } else if is_and && ok_after {
                    flush!();
                    toks.push(Tok::Sep);
                    i += 1;
                } else {
                    return Err(bad(c));
                }
            }
            '|' | '(' | ')' | '{' | '}' | '[' | ']' | '`' | '$' | '\\' | '!' => {
                return Err(bad(c));
            }
            _ if c.is_control() || !c.is_ascii() => return Err(bad(c)),
            _ => {
                cur.push(c);
                in_word = true;
                if !c.is_ascii_digit() {
                    digits_only = false;
                }
            }
        }
        i += 1;
    }
    if in_word {
        toks.push(Tok::Word(cur));
    }
    Ok(toks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commands(s: &str) -> Vec<Vec<String>> {
        parse(s).unwrap().commands
    }

    fn words(s: &str) -> Vec<String> {
        let mut c = commands(s);
        assert_eq!(c.len(), 1, "{s:?}");
        c.remove(0)
    }

    #[test]
    fn accepts_simple() {
        assert_eq!(words("ls -la /tmp"), ["ls", "-la", "/tmp"]);
        assert_eq!(
            words("git commit -m 'a b; c | d'"),
            ["git", "commit", "-m", "a b; c | d"]
        );
        assert_eq!(words("echo \"hi there\" > out.txt"), ["echo", "hi there"]);
        assert_eq!(words("cargo test >> log 2>&1"), ["cargo", "test"]);
        assert_eq!(
            commands("a 2>&1; b 2>&1&&c"),
            [vec!["a"], vec!["b"], vec!["c"]]
        );
        assert_eq!(words("sort < in.txt"), ["sort"]);
        assert_eq!(words("ls *.rs ~/x a#b"), ["ls", "*.rs", "~/x", "a#b"]);
        assert_eq!(words("echo a>b"), ["echo", "a"]);
        assert_eq!(words("'python' x"), ["python", "x"]);
        assert_eq!(words("echo 'a'\"b\"c"), ["echo", "abc"]);
    }

    #[test]
    fn accepts_chains() {
        assert_eq!(
            commands("cd x && ls -la"),
            [vec!["cd", "x"], vec!["ls", "-la"]]
        );
        assert_eq!(commands("a; b"), [vec!["a"], vec!["b"]]);
        assert_eq!(commands("a;b"), [vec!["a"], vec!["b"]]);
        assert_eq!(commands("a&&b"), [vec!["a"], vec!["b"]]);
        assert_eq!(
            commands("a && b; c && d"),
            [vec!["a"], vec!["b"], vec!["c"], vec!["d"]]
        );
        assert_eq!(
            commands("cd 'my dir' && ls > o 2>&1"),
            [vec!["cd", "my dir"], vec!["ls"]]
        );
        assert_eq!(
            commands("echo 'a; b && c' ; ls"),
            [vec!["echo", "a; b && c"], vec!["ls"]]
        );
        let eight = ["a"; MAX_COMMANDS].join(" && ");
        assert_eq!(commands(&eight).len(), MAX_COMMANDS);
    }

    #[test]
    fn rejects_bad_chains() {
        let nine = ["a"; MAX_COMMANDS + 1].join(" && ");
        assert!(parse(&nine).is_err());
        for s in [
            "a &&",
            "a;",
            "a ;",
            "a && ;",
            "&& a",
            "; a",
            "a &&& b",
            "a && & b",
            "a ;; b",
            "a ;& b",
            "a && && b",
            "a ; ; b",
            "a &&> f",
            "a || b",
            "a & b",
            "a && b | c",
            "a && b &",
            "a && $x",
            "a > f && FOO=1 b",
            "FOO=1 a && b",
            "a && (b)",
            "a && { b; }",
            "a && b\nc",
            "a && > f",
            "a && 2>&1",
            "a ; 2>&1",
        ] {
            assert!(parse(s).is_err(), "should reject: {s:?}");
        }
    }

    #[test]
    fn rejects_complex() {
        for s in [
            "a | b",
            "a || b",
            "a &",
            "a & b",
            "(a)",
            "{ a; }",
            "echo $HOME",
            "echo ${x}",
            "echo $(x)",
            "echo `x`",
            "echo \"$x\"",
            "echo \"`x`\"",
            "echo \"\\n\"",
            "echo a\\ b",
            "a\nb",
            "a <<EOF",
            "a <<< b",
            "a <(b)",
            "a >(b)",
            "a >| f",
            "a &> f",
            "a >&3",
            "a >& f",
            "a 2>&1x",
            "a 2>&1&",
            "a 2>&1&&&b",
            "a >",
            "a > > b",
            "a > $f",
            "FOO=bar a",
            "# c",
            "echo 'x",
            "echo \"x",
            "[ -f x ]",
            "! a",
            "echo é",
            "a\0b",
            "",
            "   ",
            "> f",
            "a <> f",
        ] {
            assert!(parse(s).is_err(), "should reject: {s:?}");
        }
    }
}
