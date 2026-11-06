// SPDX-License-Identifier: Apache-2.0

//! CLI application definition and help rendering.

use std::string::{String, ToString};
use std::vec::Vec;

use super::arg::Arg;
use super::matches::ArgMatches;
use super::parser::{parse_args, ParseError};

/// The switches an [`App`] runs under. Only the ones the parser or the
/// completion generators branch on are kept; the rest of the vocabulary
/// a builder of this shape could carry has no caller here.
#[derive(Debug, Clone, Default)]
pub struct AppSettings {
    pub disable_help_flag: bool,
    pub disable_version_flag: bool,
    /// `raw_args` are the arguments themselves; argv[0] is not skipped.
    pub no_binary_name: bool,
}

/// A named command: its version blurb, its argument table, and the
/// subcommands that take over the rest of argv.
#[derive(Debug, Clone)]
pub struct App {
    pub name: String,
    pub version: Option<String>,
    pub about: Option<String>,
    pub args: Vec<Arg>,
    pub subcommands: Vec<App>,
    pub settings: AppSettings,
}

impl App {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            about: None,
            args: Vec::new(),
            subcommands: Vec::new(),
            settings: AppSettings::default(),
        }
    }

    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into());
        self
    }

    pub fn about(mut self, a: impl Into<String>) -> Self {
        self.about = Some(a.into());
        self
    }

    pub fn arg(mut self, arg: Arg) -> Self {
        self.args.push(arg);
        self
    }

    /// The rest of the builder is vocabulary the suite drives (a
    /// subcommand app, a disabled builtin, `no_binary_name`, a lookup
    /// by name); the rgx grammar uses `arg` and the two blurb setters.
    #[allow(dead_code)]
    pub fn subcommand(mut self, sub: App) -> Self {
        self.subcommands.push(sub);
        self
    }

    #[allow(dead_code)]
    pub fn disable_help_flag(mut self, disable: bool) -> Self {
        self.settings.disable_help_flag = disable;
        self
    }

    #[allow(dead_code)]
    pub fn disable_version_flag(mut self, disable: bool) -> Self {
        self.settings.disable_version_flag = disable;
        self
    }

    #[allow(dead_code)]
    pub fn no_binary_name(mut self, no: bool) -> Self {
        self.settings.no_binary_name = no;
        self
    }

    pub fn parse(self, args: &[&str]) -> Result<ArgMatches, ParseError> {
        parse_args(&self, args)
    }

    pub fn parse_from<I, T>(self, iter: I) -> Result<ArgMatches, ParseError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let args: Vec<String> = iter.into_iter().map(|s| s.as_ref().to_string()).collect();
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.parse(&args_refs)
    }

    /// The `--help` text: name and blurb, the usage line, the
    /// positionals under `Arguments:`, the flags under `Options:`, and
    /// the subcommands if any.
    pub fn render_help(&self) -> String {
        let mut help = String::new();

        help.push_str(&self.name);
        if let Some(v) = &self.version {
            help.push(' ');
            help.push_str(v);
        }
        help.push('\n');

        if let Some(about) = &self.about {
            help.push_str(about);
            help.push('\n');
        }
        help.push('\n');

        if !self.args.is_empty() {
            help.push_str("Usage:\n");
            help.push_str("  ");
            help.push_str(&self.name);
            help.push_str(" [OPTIONS]");

            for arg in &self.args {
                if arg.positional {
                    help.push(' ');
                    help.push_str(&positional_usage(arg));
                } else if arg.required {
                    help.push_str(" --");
                    help.push_str(&arg.name);
                    if arg.takes_value {
                        help.push_str(&std::format!(" <{}>", arg.name));
                    }
                }
            }

            if !self.subcommands.is_empty() {
                help.push_str(" [SUBCOMMAND]");
            }
            help.push_str("\n\n");

            let positionals: Vec<&Arg> = self.args.iter().filter(|a| a.positional).collect();
            if !positionals.is_empty() {
                help.push_str("Arguments:\n");
                for arg in &positionals {
                    if arg.hidden {
                        continue;
                    }
                    push_entry(&mut help, &positional_usage(arg), arg.help.as_deref());
                }
                help.push('\n');
            }

            help.push_str("Options:\n");
            for arg in &self.args {
                if arg.hidden || arg.positional {
                    continue;
                }

                let mut spellings = String::new();
                if let Some(s) = arg.short {
                    spellings.push('-');
                    spellings.push(s);
                }
                if let Some(l) = &arg.long {
                    if spellings.is_empty() {
                        spellings.push_str("--");
                        spellings.push_str(l);
                    } else {
                        spellings.push_str(", --");
                        spellings.push_str(l);
                    }
                }
                if arg.takes_value {
                    spellings.push_str(&std::format!(" <{}>", arg.name));
                }

                let mut right = String::new();
                if let Some(h) = &arg.help {
                    right.push_str(h);
                }
                if arg.required {
                    right.push_str(" [required]");
                }
                if let Some(ref default) = arg.default {
                    right.push_str(&std::format!(" [default: {}]", default));
                }
                push_entry(&mut help, &spellings, Some(&right));
            }
        }

        if !self.subcommands.is_empty() {
            help.push('\n');
            help.push_str("Subcommands:\n");
            for sub in &self.subcommands {
                help.push_str(&std::format!("  {:20}", sub.name));
                if let Some(about) = &sub.about {
                    help.push_str(about);
                }
                help.push('\n');
            }
        }

        help
    }

    pub fn render_version(&self) -> String {
        let mut v = String::new();
        v.push_str(&self.name);
        if let Some(ver) = &self.version {
            v.push(' ');
            v.push_str(ver);
        }
        v
    }

    #[allow(dead_code)]
    pub fn get_arg(&self, name: &str) -> Option<&Arg> {
        self.args.iter().find(|a| a.name == name)
    }

    pub fn get_subcommand(&self, name: &str) -> Option<&App> {
        self.subcommands.iter().find(|s| s.name == name)
    }

    pub fn find_short_arg(&self, c: char) -> Option<&Arg> {
        self.args.iter().find(|a| a.short == Some(c))
    }

    pub fn find_long_arg(&self, s: &str) -> Option<&Arg> {
        self.args.iter().find(|a| a.long.as_deref() == Some(s))
    }
}

/// One row of a help table: the left column padded to [`HELP_COLUMN`],
/// or on a line of its own when it does not fit.
///
/// Padding alone is not enough. `--files-without-match` is wider than
/// the column, and `format!("  {:20}", s)` does not truncate — it emits
/// the whole string and the help text then starts mid-word on the same
/// line. Anything wider than the column goes below instead, which is
/// what clap does.
const HELP_COLUMN: usize = 20;

fn push_entry(help: &mut String, left: &str, right: Option<&str>) {
    let Some(right) = right.filter(|r| !r.is_empty()) else {
        help.push_str("  ");
        help.push_str(left);
        help.push('\n');
        return;
    };
    if left.chars().count() + 2 > HELP_COLUMN {
        help.push_str("  ");
        help.push_str(left);
        help.push('\n');
        for (i, line) in right.split('\n').enumerate() {
            if i > 0 {
                help.push('\n');
            }
            help.push_str(&std::format!(
                "  {:width$}{}\n",
                "",
                line,
                width = HELP_COLUMN + 2
            ));
        }
        return;
    }
    help.push_str(&std::format!(
        "  {:width$}{}\n",
        left,
        right,
        width = HELP_COLUMN
    ));
}

/// How a positional is written in the usage line and the Arguments
/// section: `<NAME>` when required, `[NAME]` when not, with `...` when it
/// soaks up the rest.
fn positional_usage(arg: &Arg) -> String {
    let dots = if arg.multiple { "..." } else { "" };
    if arg.required {
        std::format!("<{}{}>", arg.name.to_uppercase(), dots)
    } else {
        std::format!("[{}{}]", arg.name.to_uppercase(), dots)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_puts_wide_entries_on_their_own_line() {
        let app = App::new("rgx")
            .arg(
                Arg::new("ignore_case")
                    .short('i')
                    .long("ignore-case")
                    .help("case-insensitive"),
            )
            .arg(
                Arg::new("files_without_match")
                    .short('L')
                    .long("files-without-match")
                    .help("print only files WITHOUT matches"),
            );
        let help = app.render_help();
        let line = help
            .lines()
            .find(|l| l.contains("--files-without-match"))
            .expect("the wide option is listed");
        assert!(
            !line.contains("print only files WITHOUT"),
            "a wide option must not have its help on the same line: {line:?}"
        );
        let next = help
            .lines()
            .skip_while(|l| !l.contains("--files-without-match"))
            .nth(1)
            .expect("the help follows on the next line");
        assert!(
            next.contains("print only files WITHOUT matches"),
            "{next:?}"
        );
        // and the narrow one still shares its line
        assert!(help
            .lines()
            .any(|l| l.contains("-i, --ignore-case") && l.contains("case-insensitive")));
    }

    #[test]
    fn test_usage_separates_positionals_from_options() {
        let app = App::new("rgx")
            .arg(Arg::new("pattern").positional(true))
            .arg(Arg::new("paths").positional(true).multiple(true));
        let usage = app
            .render_help()
            .lines()
            .find(|l| l.trim_start().starts_with("rgx [OPTIONS]"))
            .expect("a usage line")
            .to_string();
        assert_eq!(usage.trim(), "rgx [OPTIONS] [PATTERN] [PATHS...]");
    }
}
