// SPDX-License-Identifier: Apache-2.0

//! Error type, `Result`, the `Context` extension trait, and the `bail!` /
//! `anyhow!` macros.
//!
//! In-house replacement for the `anyhow` crate, covering exactly the
//! surface rgx uses: `Result`, `Context`, `bail`, `anyhow!`, and a
//! `Display` whose alternate form walks the cause chain. Nothing else —
//! no backtrace, no `downcast`, no `chain()`/`root_cause()`.
//!
//! ## Why `Error` does not implement `std::error::Error`
//!
//! It looks like an oversight and is not. The blanket
//! `impl<E: StdError + Send + Sync + 'static> From<E> for Error` is what
//! makes `?` work on every foreign error in the workspace. If `Error`
//! itself also implemented `StdError`, that blanket would apply to
//! `E = Error` and collide with core's reflexive `impl<T> From<T> for T`.
//! `anyhow` makes the same trade. The cost is that an `Error` cannot be
//! stored in a `Box<dyn StdError>`; nothing here needs that.
//!
//! ## The alternate `Display` is load-bearing
//!
//! `rgx_core::process` renders an adapter failure into the searchable
//! corpus with `format!("{e:#}")` and keeps the first line. With `{e}`
//! that would collapse to the outer message and silently drop whatever
//! `.context(..)` added. A replacement whose alternate form matches its
//! plain form loses the cause, and nothing else would notice.
//!
//! ## The `Debug` impl is load-bearing too
//!
//! `fn main() -> Result<()>` prints through `std::process::Termination`,
//! which uses `{:?}`. If `Debug` collapsed to the top message, every
//! CLI failure — a bad `--max-filesize`, a malformed regex — would print a
//! dead end with nothing pointing at the parse error.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use core::result::Result as StdResult;

#[cfg(feature = "std")]
use std::error::Error as StdError;

/// One link in an error chain.
///
/// Stored as a displayable link rather than only via `source()`, so an
/// `Error` can be nested as a cause even though it does not implement
/// `StdError`. That is what lets `Result<T, Error>` implement
/// [`Context`] at all.
enum Link {
    /// A real `std::error::Error`. Absent without the `std` feature, which
    /// is what gates `as_std` and the blanket `From` with it.
    #[cfg(feature = "std")]
    Caught(Box<dyn StdError + Send + Sync>),
    /// A bare message, from `anyhow!("...")` or `.context("...")`.
    Message(Box<dyn fmt::Display + Send + Sync>),
    /// A decline: "this file is not mine" or "I found nothing in it".
    ///
    /// It is an error so that `?` propagates it out of a helper that
    /// returns `Result<T>` — the 33 such helpers in this workspace cannot
    /// return `Outcome::Bail` — but it is not a failure. `process` treats
    /// it as a silent fall-through to the next candidate, exactly like
    /// `Outcome::Bail`, and never mints a note out of it.
    Decline(Box<dyn fmt::Display + Send + Sync>),
}

impl Link {
    fn describe(&self) -> &dyn fmt::Display {
        match self {
            #[cfg(feature = "std")]
            Link::Caught(e) => e.as_ref(),
            Link::Message(m) => m.as_ref(),
            Link::Decline(m) => m.as_ref(),
        }
    }
}

/// A type-erased error: a head message plus zero or more causes.
pub struct Error {
    head: Link,
    rest: Vec<Link>,
}

impl Error {
    /// Wrap a foreign error.
    #[cfg(feature = "std")]
    pub fn new<E: StdError + Send + Sync + 'static>(error: E) -> Self {
        Self {
            head: Link::Caught(Box::new(error)),
            rest: Vec::new(),
        }
    }

    /// Without `std` only the `Display` survives, so the chain keeps the
    /// text and loses the typed source.
    #[cfg(not(feature = "std"))]
    pub fn new<E: fmt::Display + Send + Sync + 'static>(error: E) -> Self {
        Self {
            head: Link::Message(Box::new(error)),
            rest: Vec::new(),
        }
    }

    /// Build an error from a displayable value with no underlying cause.
    pub fn msg<M: fmt::Display + Send + Sync + 'static>(message: M) -> Self {
        Self {
            head: Link::Message(Box::new(message)),
            rest: Vec::new(),
        }
    }

    /// Build a *decline*: "this file is not mine", or "I found nothing in
    /// it that is worth reporting".
    ///
    /// A decline carries a message so the adapter can say why it stepped
    /// aside, but it is not a failure. `process` routes it to the next
    /// candidate silently, where `bail!` routes it to the note that becomes
    /// a searchable unit beside the file's own bytes. That difference is
    /// the whole point: an adapter declining a file is an ordinary event
    /// and must not put a line in the corpus that is not in the file.
    pub fn decline<M: fmt::Display + Send + Sync + 'static>(message: M) -> Self {
        Self {
            head: Link::Decline(Box::new(message)),
            rest: Vec::new(),
        }
    }

    /// Whether this error is a decline rather than a failure.
    ///
    /// The marker is looked for in the whole chain, not only in the head:
    /// attaching context puts the new message on the head and pushes the
    /// old one down, so a decline that has been given context is still a
    /// decline. A decline stays a decline as it travels up through `?`.
    pub fn is_decline(&self) -> bool {
        matches!(self.head, Link::Decline(_))
            || self.rest.iter().any(|l| matches!(l, Link::Decline(_)))
    }

    /// Turn this error into a decline carrying the given reason.
    ///
    /// The reason goes on the head and the original chain stays underneath
    /// it, so the cause is still there to be read — the difference from
    /// `context` is only that the head is a decline, and `process` treats
    /// that as a step aside rather than a failure.
    pub fn into_decline<M: fmt::Display + Send + Sync + 'static>(mut self, message: M) -> Self {
        let old_head = core::mem::replace(&mut self.head, Link::Decline(Box::new(message)));
        self.rest.insert(0, old_head);
        self
    }

    /// The underlying error, when the head is a real `std::error::Error`
    /// rather than a bare message.
    #[cfg(feature = "std")]
    pub fn as_std(&self) -> Option<&(dyn StdError + Send + Sync + 'static)> {
        match &self.head {
            Link::Caught(e) => Some(e.as_ref()),
            Link::Message(_) | Link::Decline(_) => None,
        }
    }

    /// Always `None` without `std`: nothing is caught as a `dyn Error` there.
    #[cfg(not(feature = "std"))]
    pub fn as_std(&self) -> Option<&(dyn fmt::Display + Send + Sync + 'static)> {
        None
    }

    /// Attach a foreign cause beneath this message. The message stays the
    /// head, because that is what `.lines().next()` keeps.
    #[cfg(feature = "std")]
    fn with_cause<E: StdError + Send + Sync + 'static>(mut self, cause: E) -> Self {
        self.rest.push(Link::Caught(Box::new(cause)));
        self
    }

    #[cfg(not(feature = "std"))]
    #[allow(dead_code)]
    fn with_cause<E: fmt::Display + Send + Sync + 'static>(mut self, cause: E) -> Self {
        self.rest.push(Link::Message(Box::new(cause)));
        self
    }

    /// Attach an existing `Error` beneath this message, flattening its own
    /// chain so `{e:#}` still reads outermost-first.
    fn with_error(mut self, cause: Error) -> Self {
        self.rest.push(cause.head);
        self.rest.extend(cause.rest);
        self
    }

    /// Attach context to an error that already exists, pushing it to the
    /// front of the chain. Inherent, so it works without importing
    /// [`Context`] — `anyhow` has the same inherent method.
    pub fn context<C>(self, message: C) -> Self
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        let mut rest = Vec::with_capacity(self.rest.len() + 1);
        rest.push(self.head);
        rest.extend(self.rest);
        Self {
            head: Link::Message(Box::new(message)),
            rest,
        }
    }

    /// The whole chain, outermost first, one entry per link.
    ///
    /// A [`Link::Caught`] can itself have a `source()` chain, so a single
    /// link may expand to several entries. `Display`'s alternate form and
    /// `Debug` both need the flattened list, and they differ only in how
    /// they join it.
    fn chain_texts(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut push = |link: &Link| match link {
            Link::Message(m) => out.push(m.to_string()),
            Link::Decline(m) => out.push(m.to_string()),
            #[cfg(feature = "std")]
            Link::Caught(e) => {
                out.push(e.to_string());
                let mut src = e.source();
                while let Some(c) = src {
                    out.push(c.to_string());
                    src = c.source();
                }
            }
        };
        push(&self.head);
        for link in &self.rest {
            push(link);
        }
        out
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            return fmt::Display::fmt(self.head.describe(), f);
        }
        // anyhow's alternate: the entire chain, joined with ": ".
        for (i, text) in self.chain_texts().iter().enumerate() {
            if i == 0 {
                f.write_str(text)?;
            } else {
                write!(f, ": {text}")?;
            }
        }
        Ok(())
    }
}

/// anyhow-shaped: the message, then a `Caused by:` block.
///
/// This is what `fn main() -> Result<()>` prints. Delegating to `Display`
/// would drop the cause chain on every CLI failure.
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.head.describe(), f)?;
        let chain = self.chain_texts();
        let causes = &chain[1..];
        if causes.is_empty() {
            return Ok(());
        }
        f.write_str("\n\nCaused by:")?;
        // anyhow numbers the entries only when there is more than one; a
        // single cause is printed bare.
        let multiple = causes.len() > 1;
        for (n, text) in causes.iter().enumerate() {
            f.write_str("\n    ")?;
            if multiple {
                write!(f, "{n}: ")?;
            }
            f.write_str(text)?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl<E> From<E> for Error
where
    E: StdError + Send + Sync + 'static,
{
    fn from(error: E) -> Self {
        Self::new(error)
    }
}

/// `rgx` result alias, defaulting to [`Error`].
pub type Result<T, E = Error> = StdResult<T, E>;

/// Attach a message to a `Result` or an `Option`.
///
/// Implemented for `Option` as well because nine call sites in this
/// workspace call `.context` on an `Option`, not a `Result` (CFB stream
/// lookups, `find_subslice`, a `which()` probe).
///
/// Also implemented for `Result<T, Error>`, which the generic `Result`
/// impl cannot cover because `Error` deliberately does not implement
/// `StdError`. Without this, the ordinary "`?` then `.context(..)`"
/// pattern does not compile.
pub trait Context<T> {
    type Output;

    /// Attach a message eagerly.
    ///
    /// The `Send + Sync + 'static` bounds are what `Error::msg` needs to
    /// store the message; without them the trait will not compile.
    fn context<C>(self, context: C) -> Self::Output
    where
        C: fmt::Display + Send + Sync + 'static;

    /// Attach a message built only on the error path, via a closure.
    fn with_context<C, D>(self, f: C) -> Self::Output
    where
        C: FnOnce() -> D,
        D: fmt::Display + Send + Sync + 'static;

    /// Attach a **decline** reason rather than a failure message.
    ///
    /// `context` says "here is what went wrong"; `decline_context` says
    /// "this file is not mine, and here is how I know". The two differ in
    /// what `process` does with the result: a failure becomes a note beside
    /// the file's own bytes, a decline steps aside silently and lets the
    /// next candidate answer.
    ///
    /// Use it where the failure *is* the recognition — a zip reader that
    /// cannot find the EOCD has established that the file is not a zip, not
    /// that a zip is broken.
    fn decline_context<C>(self, context: C) -> Self::Output
    where
        C: fmt::Display + Send + Sync + 'static;
}

#[cfg(feature = "std")]
impl<T, E> Context<T> for StdResult<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    type Output = Result<T>;

    fn context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|error| Error::msg(context).with_cause(error))
    }

    fn with_context<C, D>(self, f: C) -> Result<T>
    where
        C: FnOnce() -> D,
        D: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|error| Error::msg(f()).with_cause(error))
    }

    fn decline_context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|error| Error::new(error).into_decline(context))
    }
}

impl<T> Context<T> for StdResult<T, Error> {
    type Output = Result<T>;

    fn context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|error| Error::msg(context).with_error(error))
    }

    fn with_context<C, D>(self, f: C) -> Result<T>
    where
        C: FnOnce() -> D,
        D: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|error| Error::msg(f()).with_error(error))
    }

    fn decline_context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|error| error.into_decline(context))
    }
}

impl<T> Context<T> for Option<T> {
    type Output = Result<T>;

    fn context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        self.ok_or_else(|| Error::msg(context))
    }

    fn with_context<C, D>(self, f: C) -> Result<T>
    where
        C: FnOnce() -> D,
        D: fmt::Display + Send + Sync + 'static,
    {
        self.ok_or_else(|| Error::msg(f()))
    }

    fn decline_context<C>(self, context: C) -> Result<T>
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        self.ok_or_else(|| Error::decline(context))
    }
}

/// Return early with an error.
///
/// ```
/// # use rgx_core::bail;
/// # fn f(n: u32) -> rgx_core::Result<()> {
/// if n > 10 { bail!("n too large: {n}"); }
/// # Ok(()) }
/// ```
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return ::core::result::Result::Err($crate::anyhow!($($arg)*))
    };
}

/// Return early with a **decline** rather than a failure.
///
/// A decline means "this file is not mine" or "I found nothing in it". It
/// travels through `?` like any error, so it works in a helper that
/// returns `Result<T>` — where `Outcome::Bail` does not typecheck — and it
/// makes `process` fall through to the next candidate **silently**. No
/// note is minted, so nothing is added to the searchable corpus that was
/// not in the file.
///
/// Use `bail!` for a failure worth reporting: a file that claims to be
/// this format and could not be decoded, a truncated container, a corrupt
/// header. Use `decline!` for everything else.
///
/// ```ignore
/// if data.starts_with(b"PK\x03\x04") { bail!("zip: corrupt central directory"); }
/// if !looks_like_ours(data) { decline!("not our format"); }
/// ```
#[macro_export]
macro_rules! decline {
    ($msg:literal $(,)?) => {
        return ::core::result::Result::Err($crate::error::Error::decline($crate::format!($msg)))
    };
    ($err:expr $(,)?) => {{
        let value = $err;
        return ::core::result::Result::Err($crate::error::Error::decline(value))
    }};
    ($fmt:expr, $($arg:tt)+) => {
        return ::core::result::Result::Err(
            $crate::error::Error::decline($crate::format!($fmt, $($arg)+))
        )
    };
}

/// Build an error from a format string (with inline captures) or from an
/// existing error value.
///
/// Arm order and the `+` on the format arm are both load-bearing. With
/// the format arm ahead of the error arm — and matching zero or more
/// arguments — `anyhow!(some_error,)` is captured by the format arm and
/// expands to `format!(some_error,)`, which fails to compile with a
/// message that points nowhere useful.
///
/// The value arm dispatches through [`TraitKind`] / [`AdhocKind`] rather
/// than a plain `From`, so both `anyhow!(real_error)` and
/// `anyhow!(string_value)` work. See [`AdhocKind`] for why that needs
/// autoref.
#[macro_export]
macro_rules! anyhow {
    ($msg:literal $(,)?) => {
        $crate::error::Error::msg($crate::format!($msg))
    };
    ($err:expr $(,)?) => {{
        #[allow(unused_imports)]
        use $crate::error::{AdhocKind as _, TraitKind as _};
        let value = $err;
        // `AdhocKind` is implemented for `&T`, so on this receiver it
        // needs one more autoref than `TraitKind` does. The impl needing
        // fewer adjustments wins, so a real error takes the
        // chain-preserving path and anything else becomes a bare message.
        (&value).rgx_error_kind().new(value)
    }};
    ($fmt:expr, $($arg:tt)+) => {
        $crate::error::Error::msg($crate::format!($fmt, $($arg)+))
    };
}

/// Tagged dispatch for the `anyhow!` value arm.
///
/// `Error` cannot have both a blanket `impl<E: StdError> From<E>` and
/// `impl From<String>`: coherence rejects the pair, because it cannot be
/// proven that `String` will never implement `StdError`. The choice
/// between "wrap a real error and keep its `source()` chain" and "store
/// this as a bare message" is therefore made by method resolution rather
/// than by trait impls — the same autoref trick `anyhow` uses, for the
/// same reason.
#[doc(hidden)]
pub struct Adhoc;

#[doc(hidden)]
pub trait AdhocKind: Sized {
    #[doc(hidden)]
    fn rgx_error_kind(&self) -> Adhoc {
        Adhoc
    }
}

impl<T> AdhocKind for &T where T: ?Sized + fmt::Display + Send + Sync + 'static {}

// `new` is the method name the `anyhow!` macro dispatch calls on the
// kind tag; it builds an `Error`, not the tag, by design.
#[allow(clippy::new_ret_no_self)]
impl Adhoc {
    #[doc(hidden)]
    #[cold]
    pub fn new<M>(self, message: M) -> Error
    where
        M: fmt::Display + Send + Sync + 'static,
    {
        Error::msg(message)
    }
}

/// The preferred arm: a real `std::error::Error`, chain preserved.
#[doc(hidden)]
pub struct Trait;

#[doc(hidden)]
pub trait TraitKind: Sized {
    #[doc(hidden)]
    fn rgx_error_kind(&self) -> Trait {
        Trait
    }
}

#[cfg(feature = "std")]
impl<E> TraitKind for E where E: StdError + Send + Sync + 'static {}

#[allow(clippy::new_ret_no_self)] // see `impl Adhoc`
impl Trait {
    #[doc(hidden)]
    #[cold]
    #[cfg(feature = "std")]
    pub fn new<E>(self, error: E) -> Error
    where
        E: StdError + Send + Sync + 'static,
    {
        Error::new(error)
    }

    #[cfg(not(feature = "std"))]
    pub fn new<E>(self, error: E) -> Error
    where
        E: fmt::Display + Send + Sync + 'static,
    {
        Error::new(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The typed chain is the `std` half of the error type.
    ///
    /// The blanket `From` for a foreign error, the `Context` for a `Result`
    /// and `as_std` are all behind the `std` feature, so the tests that
    /// exercise them are too: a `no_std` build keeps the message chain and
    /// nothing else, and a test that asserted the typed chain there would
    /// be asserting an API that configuration does not have.
    #[cfg(feature = "std")]
    mod typed_chain {
        use super::*;
        use std::fmt;

        #[derive(Debug)]
        struct Leaf;
        impl fmt::Display for Leaf {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("root cause")
            }
        }
        impl StdError for Leaf {}

        #[derive(Debug)]
        struct Middle;
        impl fmt::Display for Middle {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("middle")
            }
        }
        impl StdError for Middle {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                Some(&Leaf)
            }
        }

        #[test]
        fn alternate_chain_reaches_the_cause() {
            // The contract `rgx_core::process` depends on. A replacement whose
            // two Display forms are identical passes every other test here and
            // silently drops the cause from the corpus.
            let e: Error = Middle.into();
            assert_eq!(e.to_string(), "middle");
            assert_eq!(format!("{e:#}"), "middle: root cause");
        }

        #[test]
        fn debug_renders_the_cause_chain() {
            // `fn main() -> Result<()>` prints through `Termination`, which
            // uses `{:?}`. Collapsing to the top message would make every CLI
            // failure a dead end.
            let r: StdResult<(), Middle> = Err(Middle);
            let e = r.context("bad size").unwrap_err();
            let dbg = format!("{e:?}");
            assert!(dbg.starts_with("bad size"), "{dbg}");
            assert!(dbg.contains("Caused by:"), "{dbg}");
            assert!(dbg.contains("middle"), "{dbg}");
            assert!(dbg.contains("root cause"), "{dbg}");
        }

        #[test]
        fn context_keeps_the_message_outermost() {
            let result: StdResult<(), Middle> = Err(Middle);
            let e = result.context("while reading the table").unwrap_err();
            // `.lines().next()` in process() keeps only this first segment,
            // so the context must be the outermost part of the chain.
            assert_eq!(e.to_string(), "while reading the table");
            assert_eq!(
                format!("{e:#}"),
                "while reading the table: middle: root cause"
            );
        }

        #[test]
        fn context_works_on_an_already_converted_error() {
            // The idiomatic `?` then `.context(..)` pattern. This needs a
            // dedicated impl, because `Error` does not implement `StdError`
            // and so cannot satisfy the generic `Result` impl.
            let inner: Result<u8> = Err(Middle.into());
            let e = inner.context("outer").unwrap_err();
            assert_eq!(e.to_string(), "outer");
            assert_eq!(format!("{e:#}"), "outer: middle: root cause");
        }

        #[test]
        fn context_closure_is_lazy() {
            let mut called = false;
            let ok: StdResult<u8, Middle> = Ok(1);
            let _ = ok.with_context(|| {
                called = true;
                "built"
            });
            assert!(!called, "the message must only be built on the error path");
        }

        #[test]
        fn question_mark_converts_foreign_errors() {
            fn inner() -> StdResult<u8, Leaf> {
                Err(Leaf)
            }
            fn outer() -> Result<u8> {
                Ok(inner()?)
            }
            assert_eq!(outer().unwrap_err().to_string(), "root cause");
        }

        #[test]
        fn anyhow_macro_accepts_literal_and_error() {
            let from_literal: Error = anyhow!("bad tag {:#x}", 0x2f);
            assert_eq!(from_literal.to_string(), "bad tag 0x2f");

            let from_error: Error = anyhow!(Leaf);
            assert_eq!(from_error.to_string(), "root cause");
        }

        #[test]
        fn anyhow_macro_error_arm_survives_a_trailing_comma() {
            // The format arm used to match this (it accepted zero arguments)
            // and expand to `format!(Middle,)`, which does not compile.
            let e: Error = anyhow!(Middle,);
            assert_eq!(e.to_string(), "middle");
        }

        #[test]
        fn anyhow_macro_accepts_a_non_error_display_value() {
            // A String is not a `StdError`, so this cannot go through `From`.
            // The tagged dispatch must fall through to the bare-message path.
            let s = String::from("from a string");
            let e: Error = anyhow!(s);
            assert_eq!(e.to_string(), "from a string");
            assert!(e.as_std().is_none(), "a bare message has no cause");

            // and the preferred arm still wins for a real error, keeping the
            // chain rather than flattening it to a message
            let e: Error = anyhow!(Middle);
            assert_eq!(e.to_string(), "middle");
            assert!(e.as_std().is_some(), "a real error must keep its cause");
            assert_eq!(format!("{e:#}"), "middle: root cause");
        }
    }

    #[test]
    fn context_works_on_option() {
        // Nine call sites do this; an implementation covering only Result
        // would not compile them.
        let found: Option<u8> = None;
        assert_eq!(
            found.context("no such entry").unwrap_err().to_string(),
            "no such entry"
        );
        let e = found.with_context(|| "no such entry either").unwrap_err();
        assert_eq!(e.to_string(), "no such entry either");
    }

    #[test]
    fn bail_returns_early() {
        fn f(n: u32) -> Result<u32> {
            if n == 0 {
                bail!("n must be non-zero");
            }
            Ok(n)
        }
        assert_eq!(f(7).unwrap(), 7);
        assert_eq!(f(0).unwrap_err().to_string(), "n must be non-zero");
    }
}
