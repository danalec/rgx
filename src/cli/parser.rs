// SPDX-License-Identifier: Apache-2.0

//! The token walk: argv in, [`ArgMatches`] out.
//!
//! One pass over the tokens. A token is a long flag, a short cluster, a
//! bare word (a positional or a subcommand name), or `--` which turns
//! the remainder into bare words. A value-taking flag parks itself in
//! [`Parser::pending`] and eats the next token — unless that token
//! looks like a flag itself and the parked one takes an *optional*
//! value, in which case the flag resolves to its bare-use value and the
//! token is re-read as a flag. `-5` is a value, not a flag: a leading
//! digit after the dash is a number.
//!
//! Help and version are errors of their own kind: the caller prints the
//! message and exits 0 rather than treating them as failures.

use core::fmt;
use std::string::{String, ToString};
use std::vec::Vec;

use super::app::App;
use super::arg::Arg;
use super::matches::ArgMatches;

/// Why a parse stopped. [`ErrorKind::DisplayHelp`] and
/// [`ErrorKind::DisplayVersion`] are not failures: their `message` is
/// the text to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// A value outside the argument's `possible_values`.
    InvalidValue,
    /// A required argument never appeared, or a flag that must take a
    /// value was left hanging at the end of argv.
    MissingArgument,
    /// No argument table entry matches the token.
    UnknownArgument,
    /// A bare token with nowhere to go: more positionals than slots.
    UnexpectedArgument,
    DisplayHelp,
    DisplayVersion,
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub message: String,
    pub kind: ErrorKind,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseError {}

pub fn parse_args(app: &App, raw_args: &[&str]) -> Result<ArgMatches, ParseError> {
    Parser::new(app).run(raw_args)
}

/// The parse state. Lives for one argv; a subcommand runs its own
/// [`Parser`] over the tokens that follow its name.
struct Parser<'a> {
    app: &'a App,
    matches: ArgMatches,
    /// The value-taking flag that is waiting for its value.
    pending: Option<&'a Arg>,
    positionals: Vec<&'a Arg>,
    /// After `--`, every token is a positional whatever it looks like.
    in_trailing: bool,
}

impl<'a> Parser<'a> {
    fn new(app: &'a App) -> Self {
        Parser {
            app,
            matches: ArgMatches::new(),
            pending: None,
            positionals: app.args.iter().filter(|a| a.positional).collect(),
            in_trailing: false,
        }
    }

    fn run(mut self, raw_args: &[&str]) -> Result<ArgMatches, ParseError> {
        let args = if self.app.settings.no_binary_name || raw_args.is_empty() {
            raw_args
        } else {
            &raw_args[1..]
        };

        let mut i = 0;
        while i < args.len() {
            let token = args[i];
            // A bare word naming a subcommand hands it the rest of argv.
            // A parked value or a post-`--` token is never a subcommand.
            if self.pending.is_none() && !self.in_trailing && is_bare(token) {
                if let Some(sub) = self.app.get_subcommand(token) {
                    let mut inner = sub.clone();
                    inner.settings.no_binary_name = true;
                    let sub_matches = parse_args(&inner, &args[i + 1..])?;
                    self.matches.set_subcommand(sub.name.clone(), sub_matches);
                    break;
                }
            }
            self.feed(token)?;
            i += 1;
        }
        self.finish()
    }

    /// Feed one token through the pending-value / flag / bare dispatch.
    fn feed(&mut self, token: &str) -> Result<(), ParseError> {
        if self.in_trailing {
            return self.file_bare(token);
        }

        if let Some(pending) = self.pending.take() {
            if pending.optional_value.is_some() && looks_like_flag(token) {
                // The parked flag resolves to its bare-use value and
                // this token is read again, as a flag.
                let default = pending.optional_value.clone().ok_or_else(|| ParseError {
                    message: std::format!("Missing value for argument '{}'", pending.name),
                    kind: ErrorKind::MissingArgument,
                })?;
                self.matches.insert_value(&pending.name, default);
                return self.feed(token);
            }
            check_possible_values(pending, token)?;
            self.matches.insert_value(&pending.name, token.to_string());
            return Ok(());
        }

        if token == "--help" || token == "-h" {
            return Err(if self.app.settings.disable_help_flag {
                ParseError {
                    message: "Help flag is disabled".into(),
                    kind: ErrorKind::UnknownArgument,
                }
            } else {
                ParseError {
                    message: self.app.render_help(),
                    kind: ErrorKind::DisplayHelp,
                }
            });
        }

        if token == "--version" || token == "-V" {
            return Err(if self.app.settings.disable_version_flag {
                ParseError {
                    message: "Version flag is disabled".into(),
                    kind: ErrorKind::UnknownArgument,
                }
            } else {
                ParseError {
                    message: self.app.render_version(),
                    kind: ErrorKind::DisplayVersion,
                }
            });
        }

        if let Some(rest) = token.strip_prefix("--") {
            return self.long_token(rest);
        }
        if token.len() > 1 && token.starts_with('-') {
            return self.short_cluster(&token[1..]);
        }
        self.file_bare(token)
    }

    /// `--NAME`, `--NAME=VALUE`, or `--` itself.
    fn long_token(&mut self, rest: &str) -> Result<(), ParseError> {
        if rest.is_empty() {
            self.in_trailing = true;
            return Ok(());
        }

        if let Some(eq) = rest.find('=') {
            let name = &rest[..eq];
            let value = &rest[eq + 1..];
            let Some(def) = self.app.find_long_arg(name) else {
                return Err(unknown_long(name));
            };
            if !def.takes_value {
                return Err(ParseError {
                    message: std::format!("Argument '{}' does not take a value", name),
                    kind: ErrorKind::UnexpectedArgument,
                });
            }
            check_possible_values(def, value)?;
            self.matches.insert_value(&def.name, value.to_string());
            return Ok(());
        }

        let Some(def) = self.app.find_long_arg(rest) else {
            // A subcommand name spelled with dashes is not an argument,
            // but only the bare form enters the subcommand, so this is
            // simply not ours to answer for.
            if self.app.subcommands.iter().any(|s| s.name == rest) {
                return Ok(());
            }
            return Err(unknown_long(rest));
        };
        if def.takes_value {
            self.pending = Some(def);
        } else {
            self.matches.insert_flag(&def.name);
        }
        Ok(())
    }

    /// `-abc`: a run of short flags, optionally ending in a flag whose
    /// value is the rest of the token (`-ofile.txt`).
    fn short_cluster(&mut self, cluster: &str) -> Result<(), ParseError> {
        let chars: Vec<char> = cluster.chars().collect();
        for (j, &c) in chars.iter().enumerate() {
            let Some(def) = self.app.find_short_arg(c) else {
                return Err(ParseError {
                    message: std::format!("Unknown argument: -{}", c),
                    kind: ErrorKind::UnknownArgument,
                });
            };
            if !def.takes_value {
                self.matches.insert_flag(&def.name);
                continue;
            }
            if j + 1 == chars.len() {
                self.pending = Some(def);
                return Ok(());
            }
            // Everything after this spelling is its value.
            let value = char_tail(cluster, j + 1);
            check_possible_values(def, value)?;
            self.matches.insert_value(&def.name, value.to_string());
            return Ok(());
        }
        Ok(())
    }

    /// File one bare token into a positional slot. A slot takes a
    /// second value only when it is `multiple`, in which case it takes
    /// everything left. A token with nowhere to go is an error rather
    /// than a silent drop — a path the user typed has to either be
    /// searched or complained about.
    fn file_bare(&mut self, token: &str) -> Result<(), ParseError> {
        for arg in &self.positionals {
            if !self.matches.is_present(&arg.name) || arg.multiple {
                check_possible_values(arg, token)?;
                self.matches.insert_value(&arg.name, token.to_string());
                return Ok(());
            }
        }
        Err(ParseError {
            message: std::format!("Unexpected argument: {}", token),
            kind: ErrorKind::UnexpectedArgument,
        })
    }

    /// The end-of-argv pass: resolve a hanging flag, apply defaults,
    /// enforce the required ones, and pour the bare-token pool.
    fn finish(mut self) -> Result<ArgMatches, ParseError> {
        if let Some(pending) = self.pending.take() {
            // A bare optional-value flag at the end of argv resolves to
            // its bare-use default; only a genuinely value-taking flag
            // with nothing to fill it is an error.
            if let Some(value) = pending
                .optional_value
                .clone()
                .or_else(|| pending.default.clone())
            {
                self.matches.insert_value(&pending.name, value);
            } else if pending.required {
                return Err(ParseError {
                    message: std::format!("Missing value for argument '{}'", pending.name),
                    kind: ErrorKind::MissingArgument,
                });
            }
        }

        for arg in &self.app.args {
            if arg.required && !self.matches.is_present(&arg.name) {
                if let Some(default) = &arg.default {
                    self.matches.insert_value(&arg.name, default.clone());
                } else {
                    return Err(ParseError {
                        message: std::format!("Missing required argument: {}", arg.name),
                        kind: ErrorKind::MissingArgument,
                    });
                }
            } else if !self.matches.is_present(&arg.name) {
                // An optional-value flag the user never mentioned stays
                // absent; only a real `default` fills in here.
                if let Some(default) = &arg.default {
                    self.matches.insert_value(&arg.name, default.clone());
                }
            }
        }

        Ok(self.matches)
    }
}

/// A bare word: `-` (stdin) or anything that does not open with a dash.
fn is_bare(token: &str) -> bool {
    token == "-" || !token.starts_with('-')
}

/// A token that opens with `-` and carries more than the dash itself is
/// a flag — except a negative number, which is a value.
fn looks_like_flag(token: &str) -> bool {
    token.len() > 1
        && token.starts_with('-')
        && !token[1..].starts_with(|c: char| c.is_ascii_digit())
}

/// The suffix of `s` after its first `skip` characters. Char-indexed so
/// a multi-byte spelling cannot slice a code point in half.
fn char_tail(s: &str, skip: usize) -> &str {
    s.char_indices()
        .nth(skip)
        .map(|(idx, _)| &s[idx..])
        .unwrap_or("")
}

fn unknown_long(name: &str) -> ParseError {
    ParseError {
        message: std::format!("Unknown argument: --{}", name),
        kind: ErrorKind::UnknownArgument,
    }
}

/// Rejects a value the argument does not allow. Called on every path
/// that produces a value — detached, `--long=v` and `-mv` alike — so
/// the answer does not depend on which spelling the user happened to
/// type.
fn check_possible_values(arg: &Arg, value: &str) -> Result<(), ParseError> {
    if arg.possible_values.is_empty() || arg.possible_values.iter().any(|v| v == value) {
        return Ok(());
    }
    Err(ParseError {
        message: std::format!(
            "Invalid value '{}' for '{}'. Possible values: {}",
            value,
            arg.name,
            arg.possible_values.join(", ")
        ),
        kind: ErrorKind::InvalidValue,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_order_between_two_arguments_is_kept() {
        // The per-argument map keeps the order within one argument and
        // loses the order between two of them. ripgrep's type flags need
        // both: `-t js -T minified` and `-T minified -t js` are two
        // different queries.
        let app = App::new("test")
            .arg(
                Arg::new("include")
                    .short('t')
                    .long("type")
                    .multiple(true)
                    .takes_value(true),
            )
            .arg(
                Arg::new("exclude")
                    .short('T')
                    .long("type-not")
                    .multiple(true)
                    .takes_value(true),
            );

        let matches = app
            .clone()
            .parse(&["test", "-t", "js", "-T", "minified"])
            .unwrap();
        assert_eq!(
            matches.values_in_order(&["include", "exclude"]),
            vec![("include", "js"), ("exclude", "minified")]
        );

        let matches = app.parse(&["test", "-T", "minified", "-t", "js"]).unwrap();
        assert_eq!(
            matches.values_in_order(&["include", "exclude"]),
            vec![("exclude", "minified"), ("include", "js")]
        );
    }

    #[test]
    fn test_flag() {
        let app = App::new("test").arg(Arg::new("verbose").short('v').long("verbose"));

        let matches = app.parse(&["test", "-v"]).unwrap();
        assert!(matches.is_present("verbose"));
        assert_eq!(matches.count("verbose"), 1);
    }

    #[test]
    fn test_long_flag() {
        let app = App::new("test").arg(Arg::new("verbose").long("verbose"));

        let matches = app.parse(&["test", "--verbose"]).unwrap();
        assert!(matches.is_present("verbose"));
    }

    #[test]
    fn test_value() {
        let app = App::new("test").arg(Arg::new("input").short('i').takes_value(true));

        let matches = app.parse(&["test", "-i", "file.txt"]).unwrap();
        assert_eq!(matches.value_of("input"), Some("file.txt"));
    }

    #[test]
    fn test_long_value() {
        let app = App::new("test").arg(Arg::new("input").long("input").takes_value(true));

        let matches = app.parse(&["test", "--input", "file.txt"]).unwrap();
        assert_eq!(matches.value_of("input"), Some("file.txt"));
    }

    #[test]
    fn test_equals_value() {
        let app = App::new("test").arg(Arg::new("input").long("input").takes_value(true));

        let matches = app.parse(&["test", "--input=file.txt"]).unwrap();
        assert_eq!(matches.value_of("input"), Some("file.txt"));
    }

    #[test]
    fn test_required() {
        let app = App::new("test").arg(
            Arg::new("input")
                .short('i')
                .takes_value(true)
                .required(true),
        );

        assert!(app.clone().parse(&["test"]).is_err());
        assert!(app.clone().parse(&["test", "-i", "file"]).is_ok());
    }

    #[test]
    fn test_default() {
        let app = App::new("test").arg(
            Arg::new("input")
                .short('i')
                .takes_value(true)
                .default("default.txt"),
        );

        let matches = app.parse(&["test"]).unwrap();
        assert_eq!(matches.value_of("input"), Some("default.txt"));
    }

    #[test]
    fn test_subcommand() {
        let app = App::new("test")
            .subcommand(App::new("sub").arg(Arg::new("name").short('n').takes_value(true)));

        let matches = app.parse(&["test", "sub", "-n", "value"]).unwrap();
        assert_eq!(matches.subcommand_name(), Some("sub"));
        let sub_matches = matches.subcommand_matches().unwrap();
        assert_eq!(sub_matches.value_of("name"), Some("value"));
    }

    #[test]
    fn test_multiple_flags() {
        let app = App::new("test").arg(Arg::new("verbose").short('v'));

        let matches = app.parse(&["test", "-v", "-v"]).unwrap();
        assert_eq!(matches.count("verbose"), 2);
    }

    #[test]
    fn test_multiple_values() {
        let app = App::new("test").arg(
            Arg::new("input")
                .short('i')
                .takes_value(true)
                .multiple(true),
        );

        let matches = app.parse(&["test", "-i", "a", "-i", "b"]).unwrap();
        let values = matches.values_of("input").unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], "a");
        assert_eq!(values[1], "b");
    }

    #[test]
    fn test_possible_values() {
        let app = App::new("test").arg(
            Arg::new("mode")
                .long("mode")
                .takes_value(true)
                .possible_values(std::vec!["fast".into(), "slow".into()]),
        );

        let matches = app.clone().parse(&["test", "--mode", "fast"]).unwrap();
        assert_eq!(matches.value_of("mode"), Some("fast"));

        assert!(app.clone().parse(&["test", "--mode", "invalid"]).is_err());
    }

    #[test]
    fn test_help_flag() {
        let app = App::new("test")
            .version("1.0")
            .arg(Arg::new("verbose").short('v').help("Enable verbose output"));

        let result = app.parse(&["test", "--help"]);
        assert!(matches!(
            result,
            Err(ParseError {
                kind: ErrorKind::DisplayHelp,
                ..
            })
        ));
    }

    #[test]
    fn test_version_flag() {
        let app = App::new("test").version("1.0");

        let result = app.parse(&["test", "--version"]);
        assert!(matches!(
            result,
            Err(ParseError {
                kind: ErrorKind::DisplayVersion,
                ..
            })
        ));
    }

    #[test]
    fn test_no_binary_name() {
        let app = App::new("test")
            .no_binary_name(true)
            .arg(Arg::new("verbose").short('v'));

        let matches = app.parse(&["-v"]).unwrap();
        assert!(matches.is_present("verbose"));
    }

    #[test]
    fn test_combined_short_flags() {
        let app = App::new("test")
            .arg(Arg::new("verbose").short('v'))
            .arg(Arg::new("quiet").short('q'));

        let matches = app.parse(&["test", "-vq"]).unwrap();
        assert!(matches.is_present("verbose"));
        assert!(matches.is_present("quiet"));
    }

    #[test]
    fn test_combined_short_with_value() {
        let app = App::new("test").arg(Arg::new("output").short('o').takes_value(true));

        let matches = app.parse(&["test", "-ofile.txt"]).unwrap();
        assert_eq!(matches.value_of("output"), Some("file.txt"));
    }

    /// `--flag[=value]`: the shape rgx's `--chunk[=BYTES]` needs. Bare,
    /// followed by another flag, or given `=v` / ` v` / `-5`.
    #[test]
    fn test_optional_value_semantics() {
        let app = crate::cli::App::new("t")
            .arg(
                crate::cli::Arg::new("chunk")
                    .long("chunk")
                    .optional_value("8"),
            )
            .arg(crate::cli::Arg::new("type").long("type").takes_value(true));
        let m = app
            .clone()
            .parse(&["t", "--chunk", "9"])
            .expect("space form");
        assert_eq!(m.value_of("chunk"), Some("9"));
        let m = app
            .clone()
            .parse(&["t", "--chunk=16"])
            .expect("equals form");
        assert_eq!(m.value_of("chunk"), Some("16"));
        let m = app.clone().parse(&["t", "--chunk"]).expect("bare at end");
        assert_eq!(m.value_of("chunk"), Some("8"));
        let m = app
            .clone()
            .parse(&["t", "--chunk", "--type", "rust"])
            .expect("followed by a flag");
        assert_eq!(m.value_of("chunk"), Some("8"));
        assert_eq!(m.value_of("type"), Some("rust"));
        let m = app
            .clone()
            .parse(&["t", "--chunk", "-5"])
            .expect("negative value");
        assert_eq!(m.value_of("chunk"), Some("-5"));
    }

    /// The `PATTERN [PATHS...]` shape rgx needs: one optional
    /// positional, then a variadic one.
    fn rgx_like() -> crate::cli::App {
        crate::cli::App::new("rgx")
            .arg(crate::cli::Arg::new("pattern").positional(true))
            .arg(
                crate::cli::Arg::new("paths")
                    .positional(true)
                    .multiple(true),
            )
            .arg(
                crate::cli::Arg::new("ignore_case")
                    .short('i')
                    .long("ignore-case"),
            )
            .arg(
                crate::cli::Arg::new("max_count")
                    .short('m')
                    .long("max-count")
                    .takes_value(true),
            )
            .arg(
                crate::cli::Arg::new("chunk")
                    .long("chunk")
                    .optional_value("2048"),
            )
    }

    #[test]
    fn test_positional_and_variadic() {
        let app = rgx_like();
        let m = app
            .clone()
            .parse(&["rgx", "needle", "a.txt", "b.txt"])
            .unwrap();
        assert_eq!(m.value_of("pattern"), Some("needle"));
        assert_eq!(m.values_of("paths").unwrap(), ["a.txt", "b.txt"]);

        // pattern alone
        let m = app.clone().parse(&["rgx", "needle"]).unwrap();
        assert_eq!(m.value_of("pattern"), Some("needle"));
        assert!(!m.is_present("paths"));

        // no positionals at all
        let m = app.clone().parse(&["rgx"]).unwrap();
        assert!(!m.is_present("pattern"));
        assert!(!m.is_present("paths"));
    }

    #[test]
    fn test_positionals_interleave_with_flags() {
        let app = rgx_like();
        let m = app
            .clone()
            .parse(&["rgx", "-i", "needle", "-m", "3", "a.txt", "b.txt"])
            .unwrap();
        assert_eq!(m.value_of("pattern"), Some("needle"));
        assert_eq!(m.value_of("max_count"), Some("3"));
        assert!(m.is_present("ignore_case"));
        assert_eq!(m.values_of("paths").unwrap(), ["a.txt", "b.txt"]);
    }

    #[test]
    fn test_bare_dash_is_a_positional_not_a_dropped_token() {
        // rgx reads "-" as stdin; the parser must file it, not drop it.
        let app = rgx_like();
        let m = app.clone().parse(&["rgx", "needle", "-"]).unwrap();
        assert_eq!(m.value_of("pattern"), Some("needle"));
        assert_eq!(m.values_of("paths").unwrap(), ["-"]);

        let m = app.clone().parse(&["rgx", "-"]).unwrap();
        assert_eq!(m.value_of("pattern"), Some("-"));
    }

    #[test]
    fn test_double_dash_sends_the_rest_to_positionals() {
        let app = rgx_like();
        let m = app
            .clone()
            .parse(&["rgx", "needle", "--", "-i", "--chunk"])
            .unwrap();
        assert_eq!(m.value_of("pattern"), Some("needle"));
        assert_eq!(m.values_of("paths").unwrap(), ["-i", "--chunk"]);
        assert!(!m.is_present("ignore_case"));
        assert!(!m.is_present("chunk"));
    }

    #[test]
    fn test_extra_positional_is_an_error_not_a_silent_drop() {
        let app = crate::cli::App::new("t").arg(crate::cli::Arg::new("only").positional(true));
        assert!(app.clone().parse(&["t", "a"]).is_ok());
        let err = app.parse(&["t", "a", "b"]).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnexpectedArgument);
        assert!(err.message.contains("b"), "{}", err.message);
    }

    #[test]
    fn test_required_positional_is_enforced() {
        let app = crate::cli::App::new("t")
            .arg(crate::cli::Arg::new("name").positional(true).required(true));
        assert!(app.clone().parse(&["t"]).is_err());
        assert!(app.clone().parse(&["t", "x"]).is_ok());
    }

    #[test]
    fn test_optional_value_flag_stays_absent_when_not_given() {
        // The bare-use default is not a `default`: a --chunk that was
        // never typed must not resolve to 2048.
        let app = rgx_like();
        let m = app.clone().parse(&["rgx", "needle"]).unwrap();
        assert!(!m.is_present("chunk"));
        assert_eq!(m.value_of("chunk"), None);
        // while a real default still fills in
        let app2 = crate::cli::App::new("t").arg(
            crate::cli::Arg::new("filesize")
                .long("max-filesize")
                .default("1G"),
        );
        assert_eq!(app2.parse(&["t"]).unwrap().value_of("filesize"), Some("1G"));
    }

    #[test]
    fn test_possible_values_apply_to_every_spelling() {
        let app = crate::cli::App::new("t")
            .arg(
                crate::cli::Arg::new("mode")
                    .long("mode")
                    .takes_value(true)
                    .possible_values(std::vec!["fast".into(), "slow".into()]),
            )
            .arg(
                crate::cli::Arg::new("short")
                    .short('x')
                    .takes_value(true)
                    .possible_values(std::vec!["a".into(), "b".into()]),
            );
        for ok in [
            vec!["t", "--mode", "fast"],
            vec!["t", "--mode=fast"],
            vec!["t", "-x", "a"],
            vec!["t", "-xa"],
        ] {
            assert!(app.clone().parse(&ok).is_ok(), "{ok:?} should parse");
        }
        for bad in [
            vec!["t", "--mode", "nope"],
            vec!["t", "--mode=nope"],
            vec!["t", "-x", "z"],
            vec!["t", "-xz"],
        ] {
            let err = app.clone().parse(&bad).unwrap_err();
            assert_eq!(
                err.kind,
                ErrorKind::InvalidValue,
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn test_help_lists_positionals_separately() {
        let app = rgx_like();
        let result = app.parse(&["rgx", "--help"]);
        let Err(e) = result else {
            panic!("--help should be an Err")
        };
        assert_eq!(e.kind, ErrorKind::DisplayHelp);
        assert!(e.message.contains("Arguments:"), "{}", e.message);
        assert!(e.message.contains("[PATTERN]"), "{}", e.message);
        assert!(e.message.contains("[PATHS...]"), "{}", e.message);
    }
}
