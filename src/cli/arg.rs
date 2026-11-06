// SPDX-License-Identifier: Apache-2.0

//! Argument definition.

use std::string::String;
use std::vec::Vec;

/// One argument of an [`App`](super::App): a named option or positional
/// with its spellings, value shape and validation list.
///
/// The fields are the table the help renderer, the completion generators
/// and the parser all read, so they stay public and named after what the
/// user types.
#[derive(Debug, Clone)]
pub struct Arg {
    pub name: String,
    pub short: Option<char>,
    pub long: Option<String>,
    pub takes_value: bool,
    /// Value substituted when the flag is given without one — the
    /// `--chunk[=BYTES]` shape. `None` means the flag's value is
    /// mandatory whenever the flag appears.
    pub optional_value: Option<String>,
    pub required: bool,
    /// Value substituted when the user never mentions the flag at all.
    pub default: Option<String>,
    pub help: Option<String>,
    pub possible_values: Vec<String>,
    /// Repeatable; also marks the last positional as "soaks up the
    /// rest", the `PATTERN [PATHS...]` shape.
    pub multiple: bool,
    pub hidden: bool,
    /// A bare token rather than a flag. Positionals fill in declaration
    /// order.
    pub positional: bool,
}

impl Arg {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            short: None,
            long: None,
            takes_value: false,
            optional_value: None,
            required: false,
            default: None,
            help: None,
            possible_values: Vec::new(),
            multiple: false,
            hidden: false,
            positional: false,
        }
    }

    pub fn short(mut self, c: char) -> Self {
        self.short = Some(c);
        self
    }

    pub fn long(mut self, s: impl Into<String>) -> Self {
        self.long = Some(s.into());
        self
    }

    /// `--flag` takes an optional value: bare (or followed by another
    /// flag) it resolves to `default_value`; `--flag=v` and `--flag v`
    /// take the value.
    ///
    /// The bare-use value is deliberately *not* stored in `default`:
    /// that field fills in for every argument the user did not mention,
    /// and an optional-value flag the user did not mention must stay
    /// absent rather than silently resolving.
    pub fn optional_value(mut self, default_value: impl Into<String>) -> Self {
        self.takes_value = true;
        self.optional_value = Some(default_value.into());
        self
    }

    pub fn takes_value(mut self, takes: bool) -> Self {
        self.takes_value = takes;
        self
    }

    /// Part of the argument vocabulary the suite drives (a required
    /// positional, a hidden flag); the rgx grammar itself sets neither.
    #[allow(dead_code)]
    pub fn required(mut self, req: bool) -> Self {
        self.required = req;
        self
    }

    /// Keeps the argument out of the help text and the completions.
    #[allow(dead_code)]
    pub fn hidden(mut self, hide: bool) -> Self {
        self.hidden = hide;
        self
    }

    pub fn default(mut self, val: impl Into<String>) -> Self {
        self.default = Some(val.into());
        self
    }

    pub fn help(mut self, h: impl Into<String>) -> Self {
        self.help = Some(h.into());
        self
    }

    pub fn possible_values(mut self, vals: Vec<String>) -> Self {
        self.possible_values = vals;
        self
    }

    pub fn multiple(mut self, mult: bool) -> Self {
        self.multiple = mult;
        self.takes_value = true;
        self
    }

    /// Marks this argument as a positional: filled from bare tokens
    /// rather than from a flag. Positional order is declaration order.
    pub fn positional(mut self, pos: bool) -> Self {
        self.positional = pos;
        self
    }
}
