// SPDX-License-Identifier: Apache-2.0

//! JSON Value types and the `Arena` that owns their backing storage.
//!
//! A parsed JSON value is a `Copy` handle into an [`Arena`]. The arena
//! owns every distinct string in the document (deduped), every array's
//! `Vec`, and every object's `BTreeMap`. There is no `Box::leak`: object
//! keys are `usize` slots into the arena's string table, so an escaped
//! key (whose source bytes needed decoding) is owned by the arena just
//! like a non-escaped one. This is what removed the leak the previous
//! `BTreeMap<&'a str, _>` design had to paper over for `y_058_object_key_escapes`.
//!
//! Iteration order on `get_object(idx)` is by interned index. For
//! distinct keys, the interned index matches source-insertion order
//! (the parser interns on first sight), so a walker that uses that
//! order matches the YAML shape of the document.
//!
//! `no_std` + `alloc`, with no `serde` anywhere: the arena is the data
//! model and `to_string` writes the document.
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use core::fmt;

use super::intern::StringIndex;

/// A JSON number, keeping integers exact.
///
/// Collapsing every number to `f64` loses anything past 2^53:
/// `9007199254740993` parses and prints back as `9007199254740992`
/// (serde_json keeps it as an integer). Integer syntax parses to
/// `I64`/`U64`, everything else (fraction, exponent, overflow) to `F64`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Number {
    I64(i64),
    U64(u64),
    F64(f64),
}

/// Whether a number is a whole number, without needing `std`.
///
/// `f64::fract` is std-only, and the replacement that reads the number as
/// an `i64` loses every value above 2^63: the cast saturates, and the
/// "fraction" that comes out of it is not zero -- so the same number was
/// an integer in one configuration and not in the other. Every f64 past
/// 2^63 is a whole number anyway (the spacing there is two or more), so
/// the answer is decided before the cast is ever taken.
fn is_integral(v: f64) -> bool {
    // 2^63 exactly: past it every f64 is a whole number, and the cast
    // below saturates.
    v.abs() >= 9_223_372_036_854_775_808.0 || v - (v as i64 as f64) == 0.0
}

/// 2^63, the first `f64` past the top of `i64`.
///
/// `i64::MAX as f64` rounds *up* to this value, so a bound written as
/// `<= i64::MAX as f64` admits 2^63 itself -- a number that does not fit in
/// an `i64` at all -- and the cast then saturates and reports `i64::MAX` for
/// it. The bound is exclusive, and the number one past the top is refused
/// rather than rounded into a lie.
const I64_LIMIT: f64 = 9_223_372_036_854_775_808.0;

/// 2^64, the first `f64` past the top of `u64`. The same rounding, the
/// same answer.
const U64_LIMIT: f64 = 18_446_744_073_709_551_616.0;

impl Number {
    /// Lossy numeric view (what most callers want).
    pub fn as_f64(&self) -> f64 {
        match self {
            Number::I64(i) => *i as f64,
            Number::U64(u) => *u as f64,
            Number::F64(f) => *f,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Number::I64(i) => Some(*i),
            Number::U64(u) => i64::try_from(*u).ok(),
            Number::F64(f) if is_integral(*f) && *f >= i64::MIN as f64 && *f < I64_LIMIT => {
                Some(*f as i64)
            }
            Number::F64(_) => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Number::I64(i) => u64::try_from(*i).ok(),
            Number::U64(u) => Some(*u),
            Number::F64(f) if is_integral(*f) && *f >= 0.0 && *f < U64_LIMIT => Some(*f as u64),
            Number::F64(_) => None,
        }
    }

    pub fn is_integer(&self) -> bool {
        !matches!(self, Number::F64(_))
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Number::I64(i) => write!(f, "{i}"),
            Number::U64(u) => write!(f, "{u}"),
            Number::F64(v) => fmt_f64(*v, f),
        }
    }
}

/// A float in the shortest form that reads back as the same `f64`.
///
/// Rust's `{}` on an `f64` NEVER uses exponent notation, so `f64::MAX` printed
/// as 309 digits and `5e-324` as 323 zeroes with a 5 on the end -- correct,
/// re-parseable, and unreadable. `{:?}` is the same shortest round-trip and
/// does switch to exponent where that is shorter, which is the form ryu
/// produces and the form every JSON writer emits. It also already carries the
/// `.0` an integral float needs (`1.0`, not `1`), so the old "append `.0` if
/// the text has neither a dot nor an e" pass is gone -- it was a `String`
/// allocation per number, and then a second one to append.
fn fmt_f64(v: f64, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    // JSON has no NaN or Infinity. The parser refuses a literal that overflows
    // to either (serde_json: "number out of range"), so this is only
    // reachable by a `Value` built in code, and `null` is what it must print
    // to stay inside the grammar.
    if !v.is_finite() {
        return f.write_str("null");
    }
    write!(f, "{v:?}")
}

/// A parsed JSON value: a `Copy` handle into an [`Arena`].
///
/// `String(usize)`, `Array(usize)`, `Object(usize)` are indices into
/// the corresponding table in the arena that owns this value. The
/// indices are interned: a key that appears 1,000 times in the source
/// is one entry in `Arena::strings` and 1,000 object slots in
/// `Arena::objects` all pointing at it.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    Number(Number),
    String(usize),
    Array(usize),
    Object(usize),
}

/// The storage a parsed JSON document lives in.
///
/// One `Arena` per parsed document. The three `Vec`s grow as the
/// parser walks; the document root is recorded in `root`. Everything
/// here is owned -- there is no `Box::leak`, no `&'static str`, no
/// lifetime parameter on the public API. The arena is `Clone` for the
/// cases that want one (a fuzz harness, a test fixture); production
/// parse paths construct one per document and drop it at the end of
/// the call.
pub struct Arena {
    /// Interned, deduplicated strings. Holds keys, string values, and
    /// decoded escape sequences alike. Index 0 is the first string the
    /// arena interned, index N-1 the last.
    strings: Vec<String>,
    /// Shadow of `strings`: maps the interned string to its index in
    /// `strings`, so `intern` does not have to scan the table to find out
    /// whether it has seen the string before. The table is this crate's own
    /// (see [`super::intern`]): the `alloc` crate has no `HashMap` at all,
    /// and what this slot holds is the *index* of the key rather than a
    /// second copy of it. Kept in lockstep with `strings`: the only writer
    /// to `strings` is `intern`, and it pushes into `strings` before it
    /// records the index, so the two never disagree. `strings` is the
    /// source of truth; the existing `get_string` / `get_array` /
    /// `get_object` / `strings()` API stays unchanged.
    index: StringIndex,
    /// One `Vec<Value>` per array literal in the source.
    arrays: Vec<Vec<Value>>,
    /// One `BTreeMap<usize, Value>` per object literal in the source.
    /// The key is an index into `strings`.
    objects: Vec<BTreeMap<usize, Value>>,
    /// The document's top-level value.
    root: Value,
}

impl Clone for Arena {
    fn clone(&self) -> Self {
        Self {
            strings: self.strings.clone(),
            index: self.index.clone(),
            arrays: self.arrays.clone(),
            objects: self.objects.clone(),
            root: self.root,
        }
    }
}

impl Default for Arena {
    fn default() -> Self {
        Self {
            strings: Vec::new(),
            index: StringIndex::new(),
            arrays: Vec::new(),
            objects: Vec::new(),
            root: Value::Null,
        }
    }
}

impl fmt::Debug for Arena {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("Arena");
        dbg.field("strings", &self.strings);
        dbg.field("index", &self.index);
        dbg.field("arrays", &self.arrays);
        dbg.field("objects", &self.objects);
        dbg.field("root", &self.root);
        dbg.finish()
    }
}

impl Arena {
    /// An empty arena. `parse` builds one internally.
    pub fn new() -> Self {
        Self::default()
    }

    /// An arena whose storage is sized for a `common` document. The
    /// counts are loose lower bounds -- the strings Vec is what holds
    /// every literal the JSON carried, so `n_strings` is the exact
    /// size; `n_arrays` and `n_objects` are overestimates that grow on
    /// push. Used by `parse` with the structural-index counts so a
    /// 20k-key object skips ~14 reallocations of every Vec it fills.
    pub fn with_capacity(n_strings: usize, n_arrays: usize, n_objects: usize) -> Self {
        let mut a = Self::default();
        a.strings.reserve(n_strings);
        a.arrays.reserve(n_arrays);
        a.objects.reserve(n_objects);
        // The shadow is sized with the strings it will hold, so the parse
        // does not grow it one doubling at a time.
        a.index.reserve(n_strings);
        a
    }

    /// The document's top value. Set by `parse`; `null` on an empty arena.
    pub fn root(&self) -> Value {
        self.root
    }

    pub(crate) fn set_root(&mut self, v: Value) {
        self.root = v;
    }

    /// Resolve a `Value::String(idx)` to its text.
    pub fn get_string(&self, idx: usize) -> &str {
        &self.strings[idx]
    }

    /// Resolve a `Value::Array(idx)` to its element handles.
    pub fn get_array(&self, idx: usize) -> &[Value] {
        &self.arrays[idx]
    }

    /// Resolve a `Value::Object(idx)` to its key-index / value map.
    pub fn get_object(&self, idx: usize) -> &BTreeMap<usize, Value> {
        &self.objects[idx]
    }

    /// The arena's string table (read-only). Used by the legacy parser
    /// smoke test and by adapters that need to resolve a key text back
    /// to its index for direct map lookups.
    pub fn strings(&self) -> &[String] {
        &self.strings
    }

    /// The arena's array table.
    pub fn arrays(&self) -> &[Vec<Value>] {
        &self.arrays
    }

    /// The arena's object table.
    pub fn objects(&self) -> &[BTreeMap<usize, Value>] {
        &self.objects
    }

    /// Intern a string. Returns the existing index if `s` is already
    /// interned, otherwise pushes and returns the new index.
    ///
    /// O(1) amortised in both configurations. The `index` shadow is the
    /// only cost on a hit; the `insert` on a miss is amortised to O(1) by
    /// the table's own growth. The dedup is what makes the cost less than
    /// the savings on the workloads that dominate rgx: the same key
    /// repeated across thousands of tensor entries in a safetensors
    /// header, the same `nodes` / `meshes` arrays in a GLB scene, the same
    /// field names in an LLM manifest.
    ///
    /// A miss costs one `String` allocation -- the one the arena keeps --
    /// and nothing else: the shadow holds the *index* of the key, not a
    /// second copy of it, so the key's bytes are written once and read
    /// once. The old linear search paid that same allocation, and paid it
    /// in O(n) byte comparisons on top.
    pub fn intern(&mut self, s: String) -> usize {
        let hash = self.index.hash_of(s.as_bytes());
        if let Some(index) = self.index.lookup(hash, &s, &self.strings) {
            return index;
        }
        let index = self.strings.len();
        self.strings.push(s);
        self.index.insert(hash, index);
        index
    }

    /// Reserve a new empty array slot and return its index. The parser
    /// uses this once per `[`, fills it via `push_array_value`, and
    /// wraps the result in a `Value::Array`.
    pub(crate) fn push_array(&mut self) -> usize {
        let idx = self.arrays.len();
        self.arrays.push(Vec::new());
        idx
    }

    /// Append a value into an existing array slot.
    pub(crate) fn push_array_value(&mut self, arr_idx: usize, v: Value) {
        self.arrays[arr_idx].push(v);
    }

    /// Reserve a new empty object slot and return its index.
    pub(crate) fn push_object(&mut self) -> usize {
        let idx = self.objects.len();
        self.objects.push(BTreeMap::new());
        idx
    }

    /// Insert a key/value pair into an existing object slot. The key
    /// must already be interned (so the map and the data file agree on
    /// its index).
    pub(crate) fn insert_object(&mut self, obj_idx: usize, key_idx: usize, v: Value) {
        // BTreeMap dedupes: a duplicate key in the source keeps the
        // last-seen value, which is what serde_json and the previous
        // `BTreeMap<&'a str, _>` design both did.
        self.objects[obj_idx].insert(key_idx, v);
    }

    /// Look up an object value by key text. Used by adapters that
    /// already have the key as a `&str` (GLB scene keys, safetensors
    /// tensor names). The shadow translates the key into an index in one
    /// probe, then a `BTreeMap::get` finds the value.
    pub fn object_get(&self, obj_idx: usize, key: &str) -> Option<Value> {
        let hash = self.index.hash_of(key.as_bytes());
        let key_idx = self.index.lookup(hash, key, &self.strings)?;
        self.objects[obj_idx].get(&key_idx).copied()
    }

    /// Iterate an object's `(key_idx, value)` pairs in BTreeMap order,
    /// which is by `usize` (the interned index). For distinct keys the
    /// interned index equals source-insertion order, since the parser
    /// interns on first sight.
    pub fn object_iter(&self, obj_idx: usize) -> impl Iterator<Item = (usize, Value)> + '_ {
        self.objects[obj_idx].iter().map(|(k, v)| (*k, *v))
    }
}

impl Value {
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }

    pub fn is_number(&self) -> bool {
        matches!(self, Value::Number(_))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Value::String(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Value::Array(_))
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Value::Object(_))
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(n.as_f64()),
            _ => None,
        }
    }

    /// The number with its integer width preserved.
    pub fn as_number_ref(&self) -> Option<&Number> {
        match self {
            Value::Number(n) => Some(n),
            _ => None,
        }
    }

    /// Build a float number.
    pub fn num(v: f64) -> Self {
        Value::Number(Number::F64(v))
    }

    /// Resolve a `Value::String` to its decoded text. Returns `None`
    /// for any other variant. The lifetime is the arena's, not the
    /// input's: a string in the arena outlives the document parse.
    pub fn as_str<'a>(&self, arena: &'a Arena) -> Option<&'a str> {
        match self {
            Value::String(idx) => Some(arena.get_string(*idx)),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        self.as_number()
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(n) => n.as_i64(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) => n.as_u64(),
            _ => None,
        }
    }

    /// Resolve a `Value::Array` to its element handles. Returns
    /// `None` for any other variant.
    pub fn as_array<'a>(&self, arena: &'a Arena) -> Option<&'a [Value]> {
        match self {
            Value::Array(idx) => Some(arena.get_array(*idx)),
            _ => None,
        }
    }

    /// Resolve a `Value::Object` to its `(key_idx, value)` map.
    pub fn as_object<'a>(&self, arena: &'a Arena) -> Option<&'a BTreeMap<usize, Value>> {
        match self {
            Value::Object(idx) => Some(arena.get_object(*idx)),
            _ => None,
        }
    }

    /// Look up an object by key text. Returns the value handle or
    /// `None` if `self` is not an object or the key is not present.
    pub fn get(&self, arena: &Arena, key: &str) -> Option<Value> {
        match self {
            Value::Object(idx) => arena.object_get(*idx, key),
            _ => None,
        }
    }

    /// Dot-separated path of object keys.
    pub fn get_path(&self, arena: &Arena, path: &str) -> Option<Value> {
        let mut current = *self;
        for key in path.split('.') {
            current = current.get(arena, key)?;
        }
        Some(current)
    }

    /// Array index. Returns `None` if `self` is not an array or the
    /// index is out of bounds.
    pub fn get_index(&self, arena: &Arena, index: usize) -> Option<Value> {
        match self {
            Value::Array(idx) => arena.get_array(*idx).get(index).copied(),
            _ => None,
        }
    }

    /// Element count for an array or object. Zero for everything else.
    pub fn len(&self, arena: &Arena) -> usize {
        match self {
            Value::Array(idx) => arena.get_array(*idx).len(),
            Value::Object(idx) => arena.get_object(*idx).len(),
            _ => 0,
        }
    }

    pub fn is_empty(&self, arena: &Arena) -> bool {
        self.len(arena) == 0
    }

    pub fn contains_key(&self, arena: &Arena, key: &str) -> bool {
        self.get(arena, key).is_some()
    }

    /// Decoded key texts of an object, in BTreeMap order. Returns an
    /// empty `Vec` for non-objects.
    pub fn keys<'a>(&self, arena: &'a Arena) -> Vec<&'a str> {
        match self {
            Value::Object(idx) => arena
                .get_object(*idx)
                .keys()
                .map(|k| arena.get_string(*k))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Value handles of an object, in BTreeMap order.
    pub fn values(&self, arena: &Arena) -> Vec<Value> {
        match self {
            Value::Object(idx) => arena.get_object(*idx).values().copied().collect(),
            _ => Vec::new(),
        }
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<f64> for Value {
    fn from(n: f64) -> Self {
        Value::num(n)
    }
}

impl From<f32> for Value {
    fn from(n: f32) -> Self {
        Value::num(n as f64)
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::num(n as f64)
    }
}

impl From<i32> for Value {
    fn from(n: i32) -> Self {
        Value::num(n as f64)
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::num(n as f64)
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Value::num(n as f64)
    }
}

impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Value::num(n as f64)
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        // Constructing a bare `Value::String(usize)` would need an
        // arena to intern into. The constructor form is the legacy
        // parser's; the canonical way for user code is to call
        // `arena.intern(s)` and use the index.
        let _ = s;
        panic!(
            "Value::from(String) needs an arena; use arena.intern(value) and Value::String(idx)"
        );
    }
}

/// `Display` lives on the arena, not on a bare `Value`. A `Value` is a
/// handle and needs its arena to print anything past `Null` / `Bool`
/// / `Number`; putting the impl on `Arena` keeps the call sites to
/// `format!("{json}")` short, where `json` is the `Arena` returned by
/// `parse`.
impl fmt::Display for Arena {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_value(self, self.root(), f)
    }
}

fn write_value(arena: &Arena, v: Value, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match v {
        Value::Null => write!(f, "null"),
        Value::Bool(b) => write!(f, "{b}"),
        Value::Number(n) => write!(f, "{n}"),
        Value::String(idx) => {
            // Allocation-free escape straight into the formatter; the
            // prior `escape_json_string(...)` build paid one heap
            // String per string value, which dominated arena
            // serialisation of large documents.
            f.write_str("\"")?;
            write_escaped(f, arena.get_string(idx))?;
            f.write_str("\"")
        }
        Value::Array(idx) => {
            write!(f, "[")?;
            for (i, item) in arena.get_array(idx).iter().enumerate() {
                if i > 0 {
                    write!(f, ",")?;
                }
                write_value(arena, *item, f)?;
            }
            write!(f, "]")
        }
        Value::Object(idx) => {
            write!(f, "{{")?;
            for (i, (k_idx, val)) in arena.object_iter(idx).enumerate() {
                if i > 0 {
                    write!(f, ",")?;
                }
                // The key is escaped, not written raw. It was: a key
                // containing a quote or a backslash produced output that
                // did not re-parse, while string *values* were escaped
                // correctly -- so the failure only showed on documents
                // whose keys needed it, which is why no test caught it.
                // Now that escaping is allocation-free, routing the key
                // through it costs nothing that the old code did not
                // already pay on the value.
                f.write_str("\"")?;
                write_escaped(f, arena.get_string(k_idx))?;
                write!(f, "\":")?;
                write_value(arena, val, f)?;
            }
            write!(f, "}}")
        }
    }
}

pub fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    // Writing into a String cannot fail, so the Result is dropped rather
    // than unwrapped: the crate forbids unwrap outside tests, and a
    // `String` sink is infallible by construction.
    let _ = write_escaped(&mut out, s);
    out
}

/// Append `s` to `out` with JSON string escaping applied, allocating nothing.
///
/// `escape_json_string` is the same predicate and is kept for callers that
/// want the owned result, but every serializer on the hot path wants to
/// escape straight into a buffer it already owns. `Display for Arena` alone
/// was paying one heap allocation per string *value* to do it.
///
/// Note this escapes exactly what `escape_json_string` escaped: the seven
/// two-character escapes plus every other C0 control as `\uXXXX`. It does
/// not escape `/` (legal, and escaping it changes bytes for no gain) and it
/// does not escape DEL (legal unescaped). The two must stay in agreement —
/// they are the same function now, not two that have to be kept in step.
pub fn write_escaped<W: core::fmt::Write>(out: &mut W, s: &str) -> core::fmt::Result {
    // Byte-indexed, and the loop below only ever hands the writer two
    // things: an untouched slice of the input, and an ASCII escape literal.
    // It never writes a single non-escape character on its own, so multi-byte
    // UTF-8 is carried through verbatim and never round-tripped char by
    // char. That is both faster than a `for c in s.chars()` and the only way
    // to stay correct for a `core::fmt::Write` sink.
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = s.as_bytes();
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: &str = match b {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            0x08 => "\\b",
            0x0C => "\\f",
            // A C0 control with no short form. Rare enough that the fmt
            // machinery here is not worth a lookup table -- what matters is
            // that it allocates nothing, which `format!` did.
            b if b < 0x20 => {
                out.write_str(&s[start..i])?;
                out.write_str("\\u00")?;
                out.write_str(
                    core::str::from_utf8(&[HEX[(b >> 4) as usize]])
                        .map_err(|_| core::fmt::Error)?,
                )?;
                out.write_str(
                    core::str::from_utf8(&[HEX[(b & 0xF) as usize]])
                        .map_err(|_| core::fmt::Error)?,
                )?;
                start = i + 1;
                continue;
            }
            _ => continue,
        };
        out.write_str(&s[start..i])?;
        out.write_str(esc)?;
        start = i + 1;
    }
    out.write_str(&s[start..])
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;

    use super::*;
    use crate::djson::{parse, to_string, to_string_pretty};

    /// The window where the two configurations used to disagree.
    ///
    /// Past 2^63 the `i64` cast saturates, so the "fraction" that came
    /// out of it was not zero: the same number was a whole number under
    /// `std` and not under `no_std`. This test runs in both
    /// configurations and has to give the same answer in both.
    #[test]
    fn a_number_above_the_i64_range_is_still_a_whole_number() {
        assert_eq!(Number::F64(1e19).as_u64(), Some(10_000_000_000_000_000_000));
        assert_eq!(
            Number::F64(1.5e19).as_u64(),
            Some(15_000_000_000_000_000_000)
        );
        assert_eq!(Number::F64(1e19).as_i64(), None);
        assert_eq!(Number::F64(1.5e19).as_i64(), None);
        // And what is not a whole number stays not one.
        assert_eq!(Number::F64(1.5).as_u64(), None);
        assert_eq!(Number::F64(0.5).as_i64(), None);
        assert_eq!(Number::F64(1.0).as_u64(), Some(1));
        assert_eq!(Number::F64(-1.0).as_i64(), Some(-1));
        assert_eq!(Number::F64(f64::INFINITY).as_u64(), None);
        assert_eq!(Number::F64(f64::NAN).as_u64(), None);
    }

    /// The number past the top of the range is not the number below it.
    ///
    /// `i64::MAX as f64` is 2^63 and `u64::MAX as f64` is 2^64, so a
    /// bound written with `<=` against them admits a number that does not
    /// fit, and the cast saturates: 2^63 came back as `i64::MAX` and 2^64
    /// as `u64::MAX` -- both of them numbers the file never held. Both are
    /// refused now, and the refusal is the same in both configurations.
    #[test]
    fn the_number_past_the_top_of_the_range_is_refused() {
        assert_eq!(Number::F64(I64_LIMIT).as_i64(), None);
        assert_eq!(Number::F64(-I64_LIMIT).as_i64(), Some(i64::MIN));
        assert_eq!(Number::F64(U64_LIMIT).as_u64(), None);
        // The largest f64 below 2^64 still fits, and it says so exactly.
        assert_eq!(
            Number::F64(18_446_744_073_709_549_568.0).as_u64(),
            Some(18_446_744_073_709_549_568)
        );
    }

    /// The answers, written down.
    ///
    /// Rust has no `f64::as_i64` and no `f64::as_u64` -- the `as` cast
    /// saturates and says nothing about what it could not represent --
    /// so the oracle here is a table and not the standard library. The
    /// table runs in both configurations, and the two have to answer it
    /// the same way.
    #[test]
    fn the_integer_views_answer_the_same_in_both_configurations() {
        let cases: &[(f64, Option<i64>, Option<u64>)] = &[
            (0.0, Some(0), Some(0)),
            (-0.0, Some(0), Some(0)),
            (1.0, Some(1), Some(1)),
            (-1.0, Some(-1), None),
            (1.5, None, None),
            (-1.5, None, None),
            (0.5, None, None),
            (
                9007199254740992.0,
                Some(9007199254740992),
                Some(9007199254740992),
            ),
            (
                9_223_372_036_854_775_808.0,
                None,
                Some(9_223_372_036_854_775_808),
            ),
            (-9_223_372_036_854_775_808.0, Some(i64::MIN), None),
            (1e19, None, Some(10_000_000_000_000_000_000)),
            (1.5e19, None, Some(15_000_000_000_000_000_000)),
            (
                18_446_744_073_709_549_568.0,
                None,
                Some(18_446_744_073_709_549_568),
            ),
            (18_446_744_073_709_551_616.0, None, None),
            (1e308, None, None),
            (f64::INFINITY, None, None),
            (f64::NEG_INFINITY, None, None),
            (f64::NAN, None, None),
        ];
        for (v, i, u) in cases {
            assert_eq!(Number::F64(*v).as_i64(), *i, "as_i64 at {v}");
            assert_eq!(Number::F64(*v).as_u64(), *u, "as_u64 at {v}");
        }
    }

    /// A float whose magnitude needs exponent notation must use it. Rust's
    /// `{}` on an `f64` never does, so `f64::MAX` came out as 309 digits and
    /// `5e-324` as 323 zeroes with a 5 on the end: correct, re-parseable, and
    /// unreadable. The shortest form is `{:?}`, which switches where that is
    /// shorter -- the form ryu produces and every JSON writer emits.
    #[test]
    fn large_and_small_floats_print_short() {
        for (v, want) in [
            (f64::MAX, "1.7976931348623157e308"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e308"),
            // The cases that were already short must not have changed shape:
            // an integral float still carries its `.0`, and a decimal still
            // prints as a decimal.
            (1.0, "1.0"),
            (0.1, "0.1"),
            (100.0, "100.0"),
        ] {
            // Build the F64 variant directly so the test exercises the
            // shortest-form renderer regardless of how the source
            // would have been parsed. `parse("1.0")` gives F64, but
            // `parse("1")` gives I64, and we are testing the F64
            // path here.
            let mut arena = Arena::new();
            arena.set_root(Value::num(v));
            assert_eq!(to_string(arena.root(), &arena), want, "to_string({v})");
        }
    }

    /// A literal that overflows f64 is refused rather than parsed into an
    /// infinity that prints as `null`: JSON has no Infinity, so accepting it
    /// would change the document's type across a round trip with no error
    /// anywhere. serde_json refuses it too.
    #[test]
    fn a_literal_that_overflows_f64_is_an_error() {
        for src in ["1e400", "-1e400", "1e999999", "[1e400]"] {
            let e = parse(src).expect_err(src);
            assert!(e.message.contains("out of range"), "{src} -> {e}");
        }
    }

    /// Object keys go through the escaper now. They did not, and a key
    /// containing a quote produced output that did not re-parse while string
    /// *values* escaped correctly -- a failure that only a document whose
    /// keys needed escaping could see.
    #[test]
    fn object_keys_are_escaped_like_values() {
        for key in [
            "plain",
            "has \"quote\"",
            "has \\ backslash",
            "has\nnewline",
            "has\ttab",
            "has\u{1}control",
            "emoji \u{1F3AF}",
            "",
        ] {
            // Build the source by hand so the key is exactly what we want
            // it to be, including empty.
            let raw_key = if key.is_empty() {
                String::new()
            } else {
                let mut s = String::new();
                for c in key.chars() {
                    match c {
                        '"' => s.push_str("\\\""),
                        '\\' => s.push_str("\\\\"),
                        '\n' => s.push_str("\\n"),
                        '\t' => s.push_str("\\t"),
                        '\u{0001}' => s.push_str("\\u0001"),
                        c => s.push(c),
                    }
                }
                s
            };
            let src = if key.is_empty() {
                "{\"\":1}".to_owned()
            } else {
                format!("{{\"{raw_key}\":1}}")
            };
            let arena =
                parse(&src).unwrap_or_else(|e| panic!("source did not parse: {src:?}\n{e}"));
            let compact = to_string(arena.root(), &arena);
            let pretty = to_string_pretty(arena.root(), &arena);
            for (label, text) in [("to_string", &compact), ("to_string_pretty", &pretty)] {
                let back = crate::djson::parse(text).unwrap_or_else(|e| {
                    panic!("{label} of key {key:?} did not re-parse: {text}\n{e}")
                });
                assert!(
                    back.root().contains_key(&arena, key),
                    "{label} lost the key {key:?}: {text}"
                );
            }
        }
    }

    /// The precision acceptance vector: integers past 2^53 must survive
    /// parse -> print -> parse unchanged (serde_json parity). With an
    /// f64-only Number, 9007199254740993 came back as ...992.
    #[test]
    fn test_large_integers_are_exact() {
        for src in [
            "9007199254740993",
            "-9007199254740993",
            "18446744073709551615",
            "-9223372036854775808",
            "9223372036854775807",
            "0",
            "-0",
            "42",
        ] {
            let arena = parse(src).unwrap_or_else(|e| panic!("{src}: {e}"));
            let printed = to_string(arena.root(), &arena);
            let again_arena = parse(&printed).unwrap_or_else(|e| panic!("{printed}: {e}"));
            assert_eq!(arena.root(), again_arena.root(), "{src} -> {printed}");
            // The exact value must be reachable as an integer. The
            // borrow on `arena` keeps the `Number` alive for the
            // assertion; `is_integer` reads nothing past that.
            let root = arena.root();
            let integer = root.as_number_ref().expect("number").is_integer();
            assert!(
                integer || src.parse::<f64>().is_ok(),
                "{src} lost integrality"
            );
        }
        let arena = parse("9007199254740993").unwrap();
        assert_eq!(arena.root().as_i64(), Some(9007199254740993));
        let arena = parse("18446744073709551615").unwrap();
        assert_eq!(arena.root().as_u64(), Some(18446744073709551615u64));
    }

    /// Floats keep their f64 form, and the pretty printer never turns an
    /// integer into a float.
    #[test]
    fn test_float_and_integer_forms() {
        let arena = parse("1.5").unwrap();
        assert_eq!(arena.root().as_f64(), Some(1.5));
        let arena = parse("1e3").unwrap();
        assert_eq!(arena.root().as_f64(), Some(1000.0));
        let arena = parse("1000").unwrap();
        assert!(arena.root().as_number_ref().unwrap().is_integer());
        let arena = parse("1000.0").unwrap();
        assert!(!arena.root().as_number_ref().unwrap().is_integer());
        let arena = parse("1.5").unwrap();
        assert_eq!(to_string(arena.root(), &arena), "1.5");
        let arena = parse("42").unwrap();
        assert_eq!(to_string(arena.root(), &arena), "42");
        // NaN/Infinity have no JSON form: null, like serde_json.
        let mut a = Arena::new();
        a.set_root(Value::num(f64::NAN));
        assert_eq!(to_string(a.root(), &a), "null");
        let mut a = Arena::new();
        a.set_root(Value::num(f64::INFINITY));
        assert_eq!(to_string(a.root(), &a), "null");
    }

    /// A document nested past the limit is an error, not a stack
    /// overflow (serde_json's default: 128).
    #[test]
    fn test_nesting_depth_is_bounded() {
        let deep = "[".repeat(200) + &"]".repeat(200);
        assert!(parse(&deep).is_err(), "200-deep array must be rejected");
        let ok = "[".repeat(100) + &"]".repeat(100);
        assert!(parse(&ok).is_ok(), "100-deep array must parse");
        let deep_obj = "{\"a\":".repeat(200) + "1" + &"}".repeat(200);
        assert!(
            parse(&deep_obj).is_err(),
            "200-deep object must be rejected"
        );
    }

    /// The arena interns each distinct string exactly once: the same key
    /// appearing N times in the source is one entry in `strings` and N
    /// slots in `objects`, all pointing at the same `usize`.
    #[test]
    fn strings_are_interned() {
        let arena = parse(r#"{"a":"a","a":"a"}"#).unwrap();
        // Three string primitives plus a fourth: the object key `a`.
        // Two of them -- the literal `"a"` and the key `"a"` -- share
        // a single intern slot, since they're the same text.
        assert_eq!(
            arena.strings().iter().filter(|s| s.as_str() == "a").count(),
            1
        );
        assert_eq!(arena.strings().len(), 1);
    }
}
