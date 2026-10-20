//! Deliberately tiny and strict PowerShell parser.
//!
//! Mirrors the bash parser: a list of simple commands joined by `;` or `&&`,
//! each made of plain words (bare, `'single'` or `"double"` quoted) plus `>`,
//! `>>` file redirects and `N>&1`/`N>&2` dups. The call operator `&` is only
//! accepted as the first word of a command (and classified as risky).
//! Everything else (pipes, `$variables`, subexpressions, script blocks,
//! splatting, backtick escapes other than literal quotes and dollars,
//! `<` redirects, ...) is rejected.

use crate::parse::{Script, Tok, assemble, bad};

pub fn parse(input: &str) -> Result<Script, String> {
    let script = assemble(&tokenize(input)?)?;
    if script.commands.iter().any(|c| c.len() == 1 && c[0] == "&") {
        return Err("call operator without a command".into());
    }
    Ok(script)
}

fn at_command_start(toks: &[Tok]) -> bool {
    matches!(toks.last(), None | Some(Tok::Sep))
}

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    // True while the word is only unquoted digits (a possible stream number).
    let mut digits_only = true;
    // True right after a closing quote, which must end the word.
    let mut closed = false;
    let mut i = 0;

    macro_rules! flush {
        () => {
            if in_word {
                if cur == "--%" && !closed {
                    return Err("stop-parsing token `--%`".into());
                }
                toks.push(Tok::Word(std::mem::take(&mut cur)));
                in_word = false;
                digits_only = true;
                closed = false;
            }
        };
    }

    while i < chars.len() {
        let c = chars[i];
        if !c.is_ascii() {
            return Err(bad(c));
        }
        match c {
            ' ' | '\t' => flush!(),
            '\'' | '"' => {
                if in_word {
                    return Err(bad(c));
                }
                i += 1;
                loop {
                    let Some(&x) = chars.get(i) else {
                        return Err("unterminated quote".into());
                    };
                    if x.is_control() || !x.is_ascii() {
                        return Err("control or non-ASCII character in quotes".into());
                    }
                    if x == c {
                        if chars.get(i + 1) == Some(&c) {
                            cur.push(c);
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    if c == '"' && x == '`' {
                        if let Some(&escaped @ ('"' | '\'' | '$')) = chars.get(i + 1) {
                            cur.push(escaped);
                            i += 2;
                            continue;
                        }
                    }
                    if c == '"' && matches!(x, '$' | '`') {
                        return Err(bad(x));
                    }
                    cur.push(x);
                    i += 1;
                }
                in_word = true;
                closed = true;
                digits_only = false;
            }
            '>' => {
                let fd_ok = in_word && digits_only && !closed && cur.len() == 1 && cur != "0";
                if fd_ok {
                    cur.clear();
                    in_word = false;
                    digits_only = true;
                } else {
                    flush!();
                }
                if chars.get(i + 1) == Some(&'&') {
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
                if chars.get(i + 1) == Some(&'>') {
                    i += 1;
                }
                if matches!(chars.get(i + 1), Some('>' | '<' | '&' | '|' | '(')) {
                    return Err(bad(chars[i + 1]));
                }
                toks.push(Tok::Redir);
            }
            '#' if !in_word => return Err(bad('#')),
            ';' => {
                if matches!(chars.get(i + 1), Some('&' | ';' | '|')) {
                    return Err(bad(c));
                }
                flush!();
                toks.push(Tok::Sep);
            }
            '&' => {
                let next = chars.get(i + 1);
                if next == Some(&'&') {
                    if matches!(chars.get(i + 2), Some('&' | '|' | ';' | '>' | '<')) {
                        return Err(bad(c));
                    }
                    flush!();
                    toks.push(Tok::Sep);
                    i += 1;
                } else if !in_word && at_command_start(&toks) && matches!(next, Some(' ' | '\t')) {
                    toks.push(Tok::Word("&".into()));
                } else {
                    return Err(bad(c));
                }
            }
            '`' => {
                if closed {
                    return Err(bad(c));
                }
                let Some(&escaped @ ('"' | '\'' | '$')) = chars.get(i + 1) else {
                    return Err(bad(c));
                };
                cur.push(escaped);
                in_word = true;
                digits_only = false;
                i += 1;
            }
            '|' | '(' | ')' | '{' | '}' | '[' | ']' | '$' | '@' | ',' | '!' | '<' => {
                return Err(bad(c));
            }
            _ if c.is_control() => return Err(bad(c)),
            _ => {
                if closed {
                    return Err(bad(c));
                }
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
        if cur == "--%" && !closed {
            return Err("stop-parsing token `--%`".into());
        }
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

    #[test]
    fn accepts() {
        assert_eq!(
            commands("Get-ChildItem -Force C:\\Users\\x"),
            [vec!["Get-ChildItem", "-Force", "C:\\Users\\x"]]
        );
        assert_eq!(
            commands("git commit -m 'it''s; a | b'"),
            [vec!["git", "commit", "-m", "it's; a | b"]]
        );
        assert_eq!(
            commands("Write-Output \"hi there\" > out.txt 2>&1"),
            [vec!["Write-Output", "hi there"]]
        );
        assert_eq!(
            commands("cd x; ls && & 'tool' a"),
            [vec!["cd", "x"], vec!["ls"], vec!["&", "tool", "a"]]
        );
        assert_eq!(
            commands("ls a#b *.rs ?.rs"),
            [vec!["ls", "a#b", "*.rs", "?.rs"]]
        );
        assert_eq!(commands("echo ''"), [vec!["echo", ""]]);
        assert_eq!(commands("echo a>b"), [vec!["echo", "a"]]);
        assert_eq!(commands("echo hi 2> err.txt"), [vec!["echo", "hi"]]);
    }

    #[test]
    fn accepts_literal_backtick_escapes() {
        for (input, expected) in [
            (r#"echo `$x"#, "$x"),
            (r#"echo "`$x""#, "$x"),
            (r#"echo `"x`""#, "\"x\""),
            (r#"echo it`'s"#, "it's"),
            (r#"echo "it`'s""#, "it's"),
            (r#"echo '`$x'"#, "`$x"),
            (r#"echo "`$(pwd)""#, "$(pwd)"),
        ] {
            assert_eq!(commands(input), [vec!["echo", expected]], "{input:?}");
        }
        for input in [
            r#"echo `$x$y"#,
            r#"echo "`$x$y""#,
            r#"echo `$(pwd)"#,
            r#"echo "`$x$(pwd)""#,
            r#"echo "x"`$y"#,
            r#"echo `$x | cat"#,
            r#"echo `"#,
            r#"echo "`"#,
        ] {
            assert!(parse(input).is_err(), "should reject {input:?}");
        }
    }

    #[test]
    fn accepts_escaped_double_quotes() {
        for (input, expected) in [
            (r#"echo "`"hello`"" "#, "\"hello\""),
            (r#"echo """hello""""#, "\"hello\""),
            (r#"echo "x""y""#, "x\"y"),
            (r#"echo "a`"; | & b""#, "a\"; | & b"),
            (r#"echo "a""; | & b""#, "a\"; | & b"),
        ] {
            assert_eq!(commands(input), [vec!["echo", expected]], "{input:?}");
        }
        for input in [
            r#"echo "`"unterminated"#,
            r#"echo "unterminated"""#,
            r#"echo "a`"$x""#,
            r#"echo "a""$x""#,
            r#"echo "a`"$(pwd)""#,
            r#"echo "a""$(pwd)""#,
            r#"echo "`"x`"" | cat"#,
            r#"echo """x""" | cat"#,
            r#"echo "a``b""#,
        ] {
            assert!(parse(input).is_err(), "should reject {input:?}");
        }
    }

    #[test]
    fn rejects() {
        for s in [
            "a | b",
            "a || b",
            "a & b",
            "a &",
            "a && & b ; &",
            "a $x",
            "a $env:PATH",
            "a $(b)",
            "a (b)",
            "a { b }",
            "a @x",
            "a @(1)",
            "a 1,2",
            "a `n",
            "a \"x$y\"",
            "a \"x`ny\"",
            "a < f",
            "a <# c #>",
            "a # c",
            "a !b",
            "a x'y'",
            "a 'x'y",
            "a 'x''y'z",
            "a --%",
            "a --% %PATH%",
            "a ’b’",
            "a 'b’c'",
            "a 'unterminated",
            "a \"unterminated",
            "a >",
            "a > > f",
            "a >&3",
            "a ;; b",
            "a &&& b",
            "a\nb",
            "a\rb",
            "FOO=1 b",
            "; a",
            "a ;",
            "&",
            "& ",
        ] {
            assert!(parse(s).is_err(), "should reject {s:?}");
        }
    }
}
