// SPDX-License-Identifier: Apache-2.0

//! Argument matches after parsing.

use std::boxed::Box;
use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::vec::Vec;

/// What one argument collected: how many times it appeared, and the
/// values it appeared with (flags carry none).
#[derive(Debug, Clone)]
pub struct ArgValue {
    pub occurrences: usize,
    pub values: Vec<String>,
}

/// The result of a parse: every mentioned argument by name, plus the
/// subcommand branch if the walk took one.
#[derive(Debug, Clone)]
pub struct ArgMatches {
    pub args: BTreeMap<String, ArgValue>,
    /// Every value an argument took, in the order the command line gave
    /// them.
    ///
    /// The per-argument map keeps the order *within* one argument and
    /// loses the order *between* two of them, and some flags need both:
    /// ripgrep's `-t js -T minified` and `-T minified -t js` are two
    /// different queries, because the last type that matches a file is
    /// the one that decides. Defaults are filled in at the end of the
    /// parse, so they land at the end of this list.
    pub order: Vec<(String, String)>,
    pub subcommand: Option<(String, Box<ArgMatches>)>,
}

impl ArgMatches {
    pub fn new() -> Self {
        Self {
            args: BTreeMap::new(),
            order: Vec::new(),
            subcommand: None,
        }
    }

    /// The values an argument took, in the order the command line gave
    /// them, across every argument whose name is in `names`.
    ///
    /// This is the order the flags were written in, which the per-argument
    /// map cannot answer.
    pub fn values_in_order(&self, names: &[&str]) -> Vec<(&str, &str)> {
        self.order
            .iter()
            .filter(|(name, _)| names.contains(&name.as_str()))
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    pub fn is_present(&self, name: &str) -> bool {
        self.args.get(name).is_some_and(|v| v.occurrences > 0)
    }

    pub fn value_of(&self, name: &str) -> Option<&str> {
        self.args
            .get(name)
            .and_then(|v| v.values.first().map(|s| s.as_str()))
    }

    pub fn values_of(&self, name: &str) -> Option<&[String]> {
        self.args.get(name).map(|v| v.values.as_slice())
    }

    /// How many times the argument appeared. The suite drives the
    /// occurrence count and the subcommand accessors; the rgx grammar
    /// reads values and presence only.
    #[allow(dead_code)]
    pub fn count(&self, name: &str) -> usize {
        self.args.get(name).map(|v| v.occurrences).unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn subcommand(&self) -> Option<&(String, Box<ArgMatches>)> {
        self.subcommand.as_ref()
    }

    #[allow(dead_code)]
    pub fn subcommand_name(&self) -> Option<&str> {
        self.subcommand.as_ref().map(|(name, _)| name.as_str())
    }

    #[allow(dead_code)]
    pub fn subcommand_matches(&self) -> Option<&ArgMatches> {
        self.subcommand
            .as_ref()
            .map(|(_, matches)| matches.as_ref())
    }

    pub fn insert_flag(&mut self, name: &str) {
        if let Some(v) = self.args.get_mut(name) {
            v.occurrences += 1;
        } else {
            self.args.insert(
                name.to_string(),
                ArgValue {
                    occurrences: 1,
                    values: Vec::new(),
                },
            );
        }
    }

    pub fn insert_value(&mut self, name: &str, value: String) {
        if let Some(v) = self.args.get_mut(name) {
            v.values.push(value.clone());
            v.occurrences += 1;
        } else {
            self.args.insert(
                name.to_string(),
                ArgValue {
                    occurrences: 1,
                    values: std::vec![value.clone()],
                },
            );
        }
        self.order.push((name.to_string(), value));
    }

    pub fn set_subcommand(&mut self, name: String, matches: ArgMatches) {
        self.subcommand = Some((name, Box::new(matches)));
    }
}

impl Default for ArgMatches {
    fn default() -> Self {
        Self::new()
    }
}
