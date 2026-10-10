//! One line from polkit's authentication helper, understood.
//!
//! The helper (`polkit-agent-helper-1`) runs the `polkit-1` PAM stack and
//! narrates it, one line per thing PAM says, in a format fixed by
//! polkit's own `polkitagenthelper-pam.c` and read by its
//! `polkitagentsession.c` — the two files this module was written from,
//! at polkit 127:
//!
//! ```text
//! PAM_PROMPT_ECHO_OFF Password:      a question whose answer is hidden
//! PAM_PROMPT_ECHO_ON Username:       a question whose answer may be shown
//! PAM_ERROR_MSG <text>               something went wrong; say it
//! PAM_TEXT_INFO <text>               something to tell; "Place your finger…"
//! SUCCESS                            authenticated, and polkitd told so
//! FAILURE                            not
//! ```
//!
//! The text after the keyword is `g_strescape`d by the helper — a
//! newline in a PAM message arrives as the two characters `\n` — so it is
//! unescaped here with `g_strcompress`'s rules, the inverse the agent
//! library itself applies. Anything else is not a line this agent
//! understands, and like the agent library it ends the conversation as a
//! failure rather than guessing.

/// What a line from the helper says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// PAM wants an answer. `echo` is whether it may be shown as typed —
    /// false for a password, true for (rare) questions like a username.
    Prompt { text: String, echo: bool },
    /// Something went wrong, in PAM's words: "Authentication failure".
    Error(String),
    /// Something PAM wants said and not answered — pam_fprintd's "Place
    /// your finger on the fingerprint reader" is the one that matters.
    Info(String),
    Success,
    Failure,
}

/// Why a line could not be understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unknown(pub String);

impl Line {
    /// Parses one line, with or without its trailing newline.
    pub fn parse(raw: &str) -> Result<Line, Unknown> {
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let line = compress(line);
        let after = |keyword: &str| line.strip_prefix(keyword).map(str::to_owned);
        // Prefix matches, as `polkitagentsession.c` does them — including
        // its quirk that "SUCCESS" and "FAILURE" are prefixes too.
        if let Some(text) = after("PAM_PROMPT_ECHO_OFF ") {
            Ok(Line::Prompt { text, echo: false })
        } else if let Some(text) = after("PAM_PROMPT_ECHO_ON ") {
            Ok(Line::Prompt { text, echo: true })
        } else if let Some(text) = after("PAM_ERROR_MSG ") {
            Ok(Line::Error(text))
        } else if let Some(text) = after("PAM_TEXT_INFO ") {
            Ok(Line::Info(text))
        } else if line.starts_with("SUCCESS") {
            Ok(Line::Success)
        } else if line.starts_with("FAILURE") {
            Ok(Line::Failure)
        } else {
            Err(Unknown(line))
        }
    }
}

/// glib's `g_strcompress`: the C escapes `\b \f \n \r \t \v \\ \"`, up to
/// three octal digits, and for any other escaped character the character
/// itself. A lone backslash at the very end is dropped, as glib does.
fn compress(s: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&c) = bytes.get(i) else { break };
        match c {
            b'0'..=b'7' => {
                let mut value: u32 = 0;
                let mut digits = 0;
                while digits < 3 && i < bytes.len() && (b'0'..=b'7').contains(&bytes[i]) {
                    value = value * 8 + u32::from(bytes[i] - b'0');
                    i += 1;
                    digits += 1;
                }
                out.push((value & 0xff) as u8);
                continue;
            }
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(0x0b),
            other => out.push(other),
        }
        i += 1;
    }
    // `g_strescape` writes every byte >= 0x80 as an octal escape, so a
    // UTF-8 message arrives byte by byte and is whole again only here.
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact lines `polkitagenthelper-pam.c` writes: the keyword, a
    /// space, the escaped text, a newline.
    #[test]
    fn every_line_the_helper_writes_is_understood() {
        assert_eq!(Line::parse("PAM_PROMPT_ECHO_OFF Password: \n"), Ok(Line::Prompt { text: "Password: ".into(), echo: false }));
        assert_eq!(Line::parse("PAM_PROMPT_ECHO_ON login:\n"), Ok(Line::Prompt { text: "login:".into(), echo: true }));
        assert_eq!(Line::parse("PAM_ERROR_MSG Authentication failure\n"), Ok(Line::Error("Authentication failure".into())));
        assert_eq!(
            Line::parse("PAM_TEXT_INFO Place your finger on the fingerprint reader\n"),
            Ok(Line::Info("Place your finger on the fingerprint reader".into()))
        );
        assert_eq!(Line::parse("SUCCESS\n"), Ok(Line::Success));
        assert_eq!(Line::parse("FAILURE\n"), Ok(Line::Failure));
    }

    /// `g_strescape` turns a newline into `\n` and every non-ASCII byte
    /// into octal; both come back as they were.
    #[test]
    fn escaped_text_is_unescaped_the_way_glib_does() {
        assert_eq!(Line::parse("PAM_ERROR_MSG two\\nlines"), Ok(Line::Error("two\nlines".into())));
        // "Mot de passe :" with a non-breaking space, U+00A0 = C2 A0.
        assert_eq!(Line::parse("PAM_PROMPT_ECHO_OFF Mot de passe\\302\\240:"), Ok(Line::Prompt { text: "Mot de passe\u{a0}:".into(), echo: false }));
        assert_eq!(compress("a\\\\b\\\"c\\qd"), "a\\b\"cqd");
        assert_eq!(compress("trailing\\"), "trailing");
    }

    /// The agent library ends the conversation on anything else rather
    /// than guess at it; so does this.
    #[test]
    fn an_unknown_line_is_refused_not_guessed_at() {
        assert_eq!(Line::parse("PAM_SOMETHING new"), Err(Unknown("PAM_SOMETHING new".into())));
        assert_eq!(Line::parse(""), Err(Unknown(String::new())));
    }
}
