// SPDX-License-Identifier: Apache-2.0

//! `.rgxrc` config-file loader.
//!
//! The config file is line-oriented: each non-empty, non-comment line is
//! prepended to the user's argv before parsing. CLI arguments come after,
//! so they win when the two sides disagree — the same precedence the
//! loader applies at startup and at every refresh.
//!
//! Search order (first hit wins):
//!   1. `$RGX_CONFIG_PATH` — if it names an existing path, that file is used.
//!   2. `.rgxrc` in the current directory.
//!   3. `.rgxrc` in the user's home directory.
//!   4. `.config/rgx/rgxrc` in the user's home directory (XDG-style).
//!
//! A missing file is not an error; the loader returns an empty argv and the
//! caller carries on as if there were no config. A file that exists but
//! fails to read is a warning on stderr, not a hard failure.

use std::path::PathBuf;

/// Read the first `.rgxrc` we can find and return its tokens.
///
/// Lines are split on whitespace; quoted segments (single or double quotes)
/// are kept as a single token, matching the way most CLIs interpret shell
/// quoting. Lines starting with `#` (after optional leading whitespace) and
/// empty lines are dropped.
pub fn load() -> Vec<String> {
    let path = match locate() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "rgx: warning: failed to read config file '{}': {e}",
                path.display()
            );
            return Vec::new();
        }
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "rgx: warning: config file '{}' is not valid UTF-8; ignoring",
                path.display()
            );
            return Vec::new();
        }
    };
    let mut tokens = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Naive shell-style splitter: walks the line and concatenates runs of
        // whitespace into a single split, while quoted segments (preserving
        // the contents but discarding the quotes) become one token. This is
        // enough for `-g '*.log'` and `--type-add 'web:html,css'`, the two
        // forms a config file typically carries.
        let mut buf = String::new();
        let mut quote: Option<char> = None;
        let mut token_start = true;
        for c in line.chars() {
            match (quote, c) {
                (Some(q), c) if c == q => {
                    quote = None;
                }
                (None, '"') | (None, '\'') => {
                    quote = Some(c);
                    token_start = false;
                }
                (None, ch) if ch.is_whitespace() => {
                    if !buf.is_empty() {
                        tokens.push(std::mem::take(&mut buf));
                    }
                    token_start = true;
                }
                (_, char) => {
                    buf.push(char);
                    token_start = false;
                }
            }
            let _ = token_start;
        }
        if !buf.is_empty() {
            tokens.push(buf);
        }
        let _ = lineno;
    }
    tokens
}

/// Locate the first existing config file in the search order.
fn locate() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("RGX_CONFIG_PATH") {
        let p = PathBuf::from(custom);
        if p.is_file() {
            return Some(p);
        }
    }
    let cwd_rc = PathBuf::from(".rgxrc");
    if cwd_rc.is_file() {
        return Some(cwd_rc);
    }
    if let Some(home) = home_dir() {
        for rel in [".rgxrc", ".config/rgx/rgxrc"] {
            let candidate = home.join(rel);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn home_dir() -> Option<PathBuf> {
    // HOME is the canonical answer on Unix; USERPROFILE on Windows. We do
    // not pull in a `dirs` crate just for two env vars.
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    if let Ok(w) = std::env::var("USERPROFILE") {
        if !w.is_empty() {
            return Some(PathBuf::from(w));
        }
    }
    None
}

/// Prepend the config tokens to `argv` so CLI args still win at parse time.
pub fn merge_into(argv: Vec<String>) -> Vec<String> {
    let mut merged = Vec::with_capacity(argv.len());
    let tokens = load();
    let mut iter = argv.into_iter();
    if let Some(prog) = iter.next() {
        merged.push(prog);
        merged.extend(tokens);
    }
    merged.extend(iter);
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn parses_lines_with_quotes_and_comments() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "rgx-rc-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".rgxrc");
        std::fs::write(
            &path,
            "# a comment\n\
              \n\
              -g '*.log'\n\
              --smart-case\n\
              --ignore-case\n\
              --type-add 'web:html,css,js'\n",
        )
        .unwrap();
        // Override the env var so the test does not depend on a real `.rgxrc`.
        // SAFETY: no other thread reads this env var concurrently in tests.
        unsafe { std::env::set_var("RGX_CONFIG_PATH", &path) };
        let tokens = load();
        unsafe { std::env::remove_var("RGX_CONFIG_PATH") };
        assert_eq!(
            tokens,
            vec![
                "-g".to_string(),
                "*.log".to_string(),
                "--smart-case".to_string(),
                "--ignore-case".to_string(),
                "--type-add".to_string(),
                "web:html,css,js".to_string(),
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_silent() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("RGX_CONFIG_PATH", "/nonexistent/.rgxrc-test") };
        let tokens = load();
        unsafe { std::env::remove_var("RGX_CONFIG_PATH") };
        assert!(tokens.is_empty());
    }
}
