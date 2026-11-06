# rgx argument parser (`cli`)

## Overview

`src/cli/` is an independent reimplementation of the small
argument-parser layer rgx drives. It is a self-contained, `std`-only
module with six files — `app.rs`, `arg.rs`, `matches.rs`, `parser.rs`,
`completion.rs` and `mod.rs` — holding a builder-shaped table of `Arg`s
compiled by an `App`, a single-pass token walk that fills an
`ArgMatches`, a help renderer, and shell-completion generators that read
the same table.

`main.rs` writes the grammar in `app()` against these types and reads
the result back through `Args::from_matches`. Nothing in this layer
knows about search, adapters or the filesystem: it is a pure function
of argv, and the only I/O it does is the text it hands back for the
caller to print.

The spellings the layer implements are a contract of their own:
`-x`, `--long`, `--long=v`, `-xv`, `--`, the `--flag[=VALUE]`
optional-value shape, `PATTERN [PATHS...]` positionals, `-` as a
token rather than a flag, and the help and version exits that report
through the error channel rather than through a value.

## Interface

- `pub struct App` — a named command: its version blurb, its argument
  table and its subcommands. Builder: `new(name: impl Into<String>)`,
  `version(impl Into<String>)`, `about(impl Into<String>)`,
  `arg(Arg)`, `subcommand(App)`, `disable_help_flag(bool)`,
  `disable_version_flag(bool)`, `no_binary_name(bool)`. Queries:
  `get_arg(&self, name: &str) -> Option<&Arg>`,
  `get_subcommand(&self, name: &str) -> Option<&App>`,
  `find_short_arg(&self, c: char) -> Option<&Arg>`,
  `find_long_arg(&self, s: &str) -> Option<&Arg>`. Actions:
  `parse(self, args: &[&str]) -> Result<ArgMatches, ParseError>`,
  `parse_from<I, T>(self, iter: I) -> Result<ArgMatches, ParseError>`
  where `I: IntoIterator<Item = T>` and `T: AsRef<str>`,
  `render_help(&self) -> String`, `render_version(&self) -> String`.
- `pub struct AppSettings` — `disable_help_flag: bool`,
  `disable_version_flag: bool`, `no_binary_name: bool`. It lives in the
  private `mod app` and is not re-exported, so `cli::AppSettings` is not
  a nameable path.
- `pub struct Arg` — one argument of an `App`: `name: String`,
  `short: Option<char>`, `long: Option<String>`,
  `takes_value: bool`, `optional_value: Option<String>`,
  `required: bool`, `default: Option<String>`, `help: Option<String>`,
  `possible_values: Vec<String>`, `multiple: bool`, `hidden: bool`,
  `positional: bool`. Builder: `new(name: impl Into<String>)`,
  `short(char)`, `long(impl Into<String>)`,
  `optional_value(impl Into<String>)`, `takes_value(bool)`,
  `required(bool)`, `hidden(bool)`, `default(impl Into<String>)`,
  `help(impl Into<String>)`, `possible_values(Vec<String>)`,
  `multiple(bool)`, `positional(bool)`. `optional_value` and
  `multiple` also set `takes_value = true`.
- `pub struct ArgMatches` — the result of a parse:
  `args: BTreeMap<String, ArgValue>`,
  `order: Vec<(String, String)>`,
  `subcommand: Option<(String, Box<ArgMatches>)>`. Queries:
  `values_in_order(&self, names: &[&str]) -> Vec<(&str, &str)>`,
  `is_present(&self, name: &str) -> bool`,
  `value_of(&self, name: &str) -> Option<&str>`,
  `values_of(&self, name: &str) -> Option<&[String]>`,
  `count(&self, name: &str) -> usize`,
  `subcommand(&self) -> Option<&(String, Box<ArgMatches>)>`,
  `subcommand_name(&self) -> Option<&str>`,
  `subcommand_matches(&self) -> Option<&ArgMatches>`. Mutators:
  `insert_flag(&mut self, name: &str)`,
  `insert_value(&mut self, name: &str, value: String)`,
  `set_subcommand(&mut self, name: String, matches: ArgMatches)`.
- `pub struct ArgValue` — `occurrences: usize`, `values: Vec<String>`.
- `pub enum ErrorKind` — `InvalidValue` (a value outside
  `possible_values`), `MissingArgument` (a required argument never
  appeared, or a value-taking flag left hanging at the end of argv),
  `UnknownArgument` (no table entry matches the token),
  `UnexpectedArgument` (a bare token with nowhere to go),
  `DisplayHelp`, `DisplayVersion`.
- `pub struct ParseError` — `message: String`, `kind: ErrorKind`;
  implements `Display` and `std::error::Error`. It lives in the private
  `mod parser` and is not re-exported.
- `pub fn parse_args(app: &App, raw_args: &[&str]) -> Result<ArgMatches, ParseError>`
  — the one-pass token walk. Also in the private `mod parser`, and not
  re-exported.
- `pub enum Shell` — `Bash`, `Zsh`, `Fish`, `PowerShell`.
  `Shell::ALL: [Shell; 4]`, `Shell::from_name(name: &str) -> Option<Shell>`
  (accepts `bash`/`sh`, `zsh`, `fish`, `powershell`/`pwsh`/`ps1`),
  `Shell::name(self) -> &'static str`.
- `pub fn generate_completion(app: &App, shell: Shell) -> String` — the
  completion script for one shell.

## Invariants

- **One pass over the tokens.** A token is a long flag, a short
  cluster, a bare word (a positional or a subcommand name), or `--`,
  which turns the remainder into bare words.
- **A parked value eats the next token** — unless that token looks
  like a flag itself *and* the parked flag takes an optional value, in
  which case the parked flag resolves to its bare-use value and the
  token is re-read as a flag.
- **`-5` is a value, not a flag.** A leading digit after the dash is
  a number.
- **Help and version are errors of their own kind.** `ErrorKind::DisplayHelp`
  and `ErrorKind::DisplayVersion` are not failures: their `message` is
  the text to print, and the caller exits 0 rather than treating them
  as an error.
- **Order is kept twice, on purpose.** `ArgMatches::args` keeps the
  order *within* one argument and loses the order *between* two of
  them; `ArgMatches::order` keeps every value in the order the command
  line gave it, across arguments. Flags that need both exist — a
  type-selection flag's order is the rule. Defaults are filled in at
  the end of the parse, so they land at the end of `order`.
- **A bare word is a subcommand only in the right state.** It is
  looked up only when nothing is parked and the walk is not past
  `--`. The subcommand takes the rest of argv and parses it with
  `no_binary_name` set.
- **Every completion script is a pure function of the `App` table**, so
  a flag cannot be missing from a script without the table missing it
  too — unless the table marks it `hidden`, which keeps it out of the
  help text and out of every script. `--help` and `--version` live
  outside the table — the parser answers them itself — and are injected
  from `settings`, so a disabled builtin is not offered.
- **The script shapes are contracts the shells read literally**: zsh's
  `_arguments` specs, one entry per line, with `[`, `]` and `:` escaped;
  fish's single-quoted words, where a quote is closed, escaped and
  reopened; bash `case` arms that return before the flag list can
  overwrite the value they just completed.
- **The last positional soaks up the rest.** `multiple` on a positional
  is what makes the `PATTERN [PATHS...]` shape.

## Side Effects

- **None.** The layer touches no file, no environment variable and no
  process: `parse_args`, `render_help`, `render_version` and
  `generate_completion` are pure functions of their arguments and
  return owned data. The only I/O in the whole layer is what the
  caller does with the returned `String`.
- The layer allocates: every parse builds a fresh `ArgMatches` and the
  strings it holds; nothing is shared between parses and nothing is
  cached across them.

## Verification

- Run: `cargo test --release --locked --workspace`
