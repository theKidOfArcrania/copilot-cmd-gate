//! Deliberately tiny and strict shell parser.
//!
//! Accepts exactly one simple command: plain words (optionally single or
//! double quoted) plus `>`, `>>`, `<` file redirects and `N>&1`/`N>&2`
//! dups. Everything else is rejected, so this is meant to accept a strict
//! subset of what the CLI's own parser accepts.

#[derive(Debug, PartialEq, Eq)]
pub struct Simple {
    pub words: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Tok {
    Word(String),
    Redir,
    Dup,
}

pub fn parse(input: &str) -> Result<Simple, String> {
    let toks = tokenize(input)?;
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
        }
        i += 1;
    }
    let Some(first) = words.first() else {
        return Err("no command word".into());
    };
    if first.contains('=') {
        return Err("leading environment variable assignment".into());
    }
    Ok(Simple { words })
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
                    let ended = after.is_none_or(|a| *a == ' ' || *a == '\t');
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
            '|' | '&' | ';' | '(' | ')' | '{' | '}' | '[' | ']' | '`' | '$' | '\\' | '!' => {
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

    fn words(s: &str) -> Vec<String> {
        parse(s).unwrap().words
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
        assert_eq!(words("sort < in.txt"), ["sort"]);
        assert_eq!(words("ls *.rs ~/x a#b"), ["ls", "*.rs", "~/x", "a#b"]);
        assert_eq!(words("echo a>b"), ["echo", "a"]);
        assert_eq!(words("'python' x"), ["python", "x"]);
        assert_eq!(words("echo 'a'\"b\"c"), ["echo", "abc"]);
    }

    #[test]
    fn rejects_complex() {
        for s in [
            "a | b",
            "a; b",
            "a && b",
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
