// SPDX-License-Identifier: Apache-2.0

//! Command-line argument parsing.
//!
//! Independent reimplementation of the small argument-parser layer rgx
//! drives: a builder-shaped table of [`Arg`]s compiled by an [`App`],
//! a token walk that fills an [`ArgMatches`], a help renderer, and
//! shell-completion generators that read the same table. Written from
//! the contract the rgx grammar and the tests of this layer hold: the
//! spellings (`-x`, `--long`, `--long=v`, `-xv`, `--`), the
//! `--flag[=VALUE]` optional-value shape, `PATTERN [PATHS...]`
//! positionals, `-` as a token rather than a flag, and the help /
//! version exits that report through the error channel.
//!
//! This is a std parser; rgx is a std binary.

mod app;
mod arg;
mod completion;
mod matches;
mod parser;

pub use app::App;
pub use arg::Arg;
pub use completion::{generate_completion, Shell};
pub use matches::ArgMatches;
pub use parser::ErrorKind;
