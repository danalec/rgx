// SPDX-License-Identifier: Apache-2.0

//! A Model Context Protocol server, over JSON-RPC 2.0 on stdio.
//!
//! **What this is.** An MCP endpoint for rgx: the protocol layer -- the
//! methods, the framing, the error codes -- and two tools, `search` and
//! `facts`. The framing is the one `--serve` already uses: one JSON
//! object per line, newline-delimited, on stdin and stdout. A client
//! that talks to this server and a client that talks to `rgx --serve`
//! read the same kind of line.
//!
//! **Why the protocol layer needs no filesystem.** The methods, the
//! dispatch and the error codes are decided by the request alone, so they
//! are compiled without `std` and can be tested there. The two tools
//! read files, so they are `std`-gated; a build without `std` still
//! answers `initialize`, `tools/list` and `ping`, and says plainly that
//! a tool it cannot run was not run.
//!
//! **What the tools say about themselves.** `search` matches literally
//! and case-sensitively: there is no regular expression in this server,
//! and a description that implied one would describe a different tool.
//! `facts` reuses rgx's own filter language, because a second query
//! language over the same facts would be two answers to one question.
//!
//! **What is refused.** The server does not write files, does not spawn
//! processes, and does not keep state between requests: a client that
//! asks for a tool that does not exist gets a tool error naming it, and
//! a client that sends a method nobody implements gets a JSON-RPC
//! error. Neither is a lie about the corpus.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
// The tools are the half that reads files, and a build without `std`
// has no files to read.
#[cfg(feature = "std")]
use alloc::vec::Vec;

use crate::djson::{self, Arena, Value};
use crate::{Ctx, Registry};
// The chain that decides which adapter claims a file is walked in the
// tools, and the tools are the half that reads files.
#[cfg(feature = "std")]
use crate::{filter, Field, Outcome, Policy, Reach};

/// The protocol version this server speaks when the client asks for one
/// it does not have.
pub const PROTOCOL_VERSION: &str = "2025-03-26";

/// The protocol versions this server answers to.
///
/// The client names the version it wants, and the server answers with
/// the same one when it is in this list and with its own otherwise: the
/// spec asks for the server's version when it cannot honour the
/// request, and a server that answered with a version the client never
/// asked for would be claiming to speak something it does not.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-03-26", "2024-11-05"];

/// The name this server reports in `serverInfo`.
pub const SERVER_NAME: &str = "rgx";

/// The version this server reports in `serverInfo`.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name of the search tool.
pub const TOOL_SEARCH: &str = "search";

/// The name of the facts tool.
pub const TOOL_FACTS: &str = "facts";

/// JSON-RPC: the request was not valid JSON.
pub const PARSE_ERROR: i32 = -32700;

/// JSON-RPC: the request was valid JSON but not a valid request object.
pub const INVALID_REQUEST: i32 = -32600;

/// JSON-RPC: the method is not one this server implements.
pub const METHOD_NOT_FOUND: i32 = -32601;

/// JSON-RPC: the method's parameters were not acceptable.
pub const INVALID_PARAMS: i32 = -32602;

/// JSON-RPC: the server failed in a way the method does not describe.
pub const INTERNAL_ERROR: i32 = -32603;

/// Ceiling on the files one search reads.
///
/// A search over a path is a walk, and a walk has no natural end: the
/// tree the client pointed at may be the whole disk. The ceiling is
/// reported when it is reached, because a truncated answer that looks
/// complete is the one answer nobody can act on.
///
/// The ceiling belongs to the tools, and the tools are the half that reads
/// files, so a build without `std` does not read it. The constant stays so
/// that the two builds describe the same server.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
const MAX_FILES: usize = 20_000;

/// Ceiling on the lines one search reports.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
const MAX_MATCHES: usize = 1_000;

/// The identifier a request carries.
///
/// The spec allows a number or a string, and the answer has to carry
/// the same one back, so both are kept as they arrived: a number that
/// came back as a different number, or a string that came back as a
/// number, is a response the client cannot match to its request.
#[derive(Clone, Debug, PartialEq)]
enum Id {
    Null,
    Int(i64),
    Num(f64),
    Str(String),
}

impl Id {
    /// The identifier as it goes back into a response.
    fn text(&self) -> String {
        match self {
            Id::Null => "null".to_string(),
            Id::Int(i) => i.to_string(),
            Id::Num(f) => format!("{f:?}"),
            Id::Str(s) => quoted(s),
        }
    }
}

/// A JSON string, quoted and escaped.
fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    out.push_str(&djson::escape_json_string(s));
    out.push('"');
    out
}

/// What the `search` tool does, in the words a client reads.
///
/// The description is the contract: it says the match is literal and
/// case-sensitive because that is what the tool does, and a client that
/// read a description promising a regular expression would send
/// patterns the tool cannot honour.
const SEARCH_DESCRIPTION: &str = "Search the files under a path for a literal, case-sensitive \
substring, and return the matching lines. The match is a byte-for-byte substring: there is no \
regular expression and no case folding, so a pattern that is not in the text is not in the answer. \
A file an adapter claims is searched through the adapter's own bytes, so the text inside an \
archive is found as well. At most 1000 lines are reported, and at most 20000 files are read.";

/// What the `facts` tool does, in the words a client reads.
const FACTS_DESCRIPTION: &str = "Report what is known about one file: its path, its extension, \
its format, and the facts the adapter that claimed it reported. With a filter expression, the \
answer also says whether the facts match it. The filter is rgx's own filter language: predicates \
over fact names, combined with AND, OR and NOT, for example \"ext:pdf AND mime:application/pdf\".";

/// One tool, as `tools/list` describes it.
///
/// The JSON is built here rather than written out as a literal because a
/// hand-written descriptor is a place a missing backslash hides in, and
/// a `tools/list` answer that does not parse is a server no client can
/// use.
fn tool_json(
    name: &str,
    description: &str,
    properties: &[(&str, &str, &str)],
    required: &[&str],
) -> String {
    let mut out = String::new();
    out.push_str("{\"name\":");
    out.push_str(&quoted(name));
    out.push_str(",\"description\":");
    out.push_str(&quoted(description));
    out.push_str(",\"inputSchema\":{\"type\":\"object\",\"properties\":{");
    for (i, (property, kind, doc)) in properties.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&quoted(property));
        out.push_str(":{\"type\":");
        out.push_str(&quoted(kind));
        out.push_str(",\"description\":");
        out.push_str(&quoted(doc));
        out.push('}');
    }
    out.push_str("},\"required\":[");
    for (i, name) in required.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&quoted(name));
    }
    out.push_str("]}}");
    out
}

/// The tool arguments, read out of the request.
///
/// The tools are the half that reads files, so a build without `std` does
/// not read these either. The shape stays so that the two builds describe
/// the same server.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
struct ToolArgs<'a> {
    pattern: Option<&'a str>,
    path: Option<&'a str>,
    filter: Option<&'a str>,
}

impl<'a> ToolArgs<'a> {
    /// Read the arguments of a `tools/call`.
    ///
    /// An absent `arguments` object is an empty argument list, not an
    /// error: a tool with no required argument may be called with
    /// nothing, and the tool itself says which arguments it needs.
    fn read(arguments: Option<&Value>, arena: &'a Arena) -> Self {
        let get = |key: &str| -> Option<&'a str> {
            arguments
                .and_then(|a| a.get(arena, key))
                .and_then(|v| v.as_str(arena))
        };
        ToolArgs {
            pattern: get("pattern"),
            path: get("path"),
            filter: get("filter"),
        }
    }
}

/// The MCP server: the protocol layer, the two tools, and the registry
/// the tools read the corpus through.
///
/// The registry and the context are the tools' half, and a build without
/// `std` has no files for the tools to read; the fields stay so that the
/// two builds describe the same server.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub struct McpServer {
    /// The registry is shared, not owned: a registry is a list of
    /// adapters, each of which may hold a handle to an external tool,
    /// and building a second one for the server would start a second
    /// set of those. The server reads the corpus the binary already
    /// has.
    registry: Arc<Registry>,
    ctx: Ctx,
}

impl McpServer {
    /// A server over `registry`, with the default pipeline limits.
    pub fn new(registry: Registry) -> Self {
        Self::with_context(registry, Ctx::default())
    }

    /// A server over the shared `registry`, with the default pipeline
    /// limits.
    pub fn with_shared_registry(registry: Arc<Registry>) -> Self {
        Self::with_shared_context(registry, Ctx::default())
    }

    /// A server over `registry`, with the given pipeline limits.
    ///
    /// The context supplies the depth, member and size limits the
    /// pipeline works under. Its filter is not one of them: the
    /// `facts` tool takes a filter as an argument and the `search` tool
    /// has none, so a filter left in the context would drop files from a
    /// search that never asked for one.
    pub fn with_context(registry: Registry, ctx: Ctx) -> Self {
        Self::with_shared_context(Arc::new(registry), ctx)
    }

    /// A server over the shared `registry`, with the given pipeline
    /// limits.
    pub fn with_shared_context(registry: Arc<Registry>, ctx: Ctx) -> Self {
        McpServer { registry, ctx }
    }

    /// The tools this server offers, as the `tools/list` result.
    pub fn tools_json(&self) -> String {
        let mut out = String::from("{\"tools\":[");
        out.push_str(&tool_json(
            TOOL_SEARCH,
            SEARCH_DESCRIPTION,
            &[
                (
                    "pattern",
                    "string",
                    "The text to look for, matched byte for byte.",
                ),
                (
                    "path",
                    "string",
                    "The file or directory to search. Defaults to the current directory.",
                ),
            ],
            &["pattern"],
        ));
        out.push(',');
        out.push_str(&tool_json(
            TOOL_FACTS,
            FACTS_DESCRIPTION,
            &[
                ("path", "string", "The file to report on."),
                ("filter", "string", "A filter expression over the facts."),
            ],
            &["path"],
        ));
        out.push_str("]}");
        out
    }

    /// Answer one line of a JSON-RPC stream.
    ///
    /// `None` means the line asked for nothing: a notification is never
    /// answered, and neither is a request that could not be parsed as a
    /// request at all, because there is no id to answer it under.
    pub fn handle_line(&self, line: &str) -> Option<String> {
        let arena = match djson::parse(line) {
            Ok(arena) => arena,
            // A line that is not JSON cannot be a notification either:
            // the client may well have sent one, and the parse error is
            // the only thing that can be said about it. The id is null
            // because nothing in the line says which request it was.
            Err(_) => return Some(Self::error(&Id::Null, PARSE_ERROR, "Parse error")),
        };
        let root = arena.root();
        if root.as_object(&arena).is_none() {
            return Some(Self::error(&Id::Null, INVALID_REQUEST, "Invalid Request"));
        }
        let method = match root.get(&arena, "method").and_then(|v| v.as_str(&arena)) {
            Some(m) => m,
            None => return Some(Self::error(&Id::Null, INVALID_REQUEST, "Invalid Request")),
        };
        // A request without an id member is a notification, and a
        // notification is never answered -- not even with an error,
        // because the client has no id to match the answer to.
        let id = Self::id_of(&root.get(&arena, "id")?, &arena);
        // The notification methods carry no answer by construction: the
        // client is telling the server that something happened, not
        // asking it a question.
        if method.starts_with("notifications/") {
            return None;
        }
        let params = root.get(&arena, "params");
        Some(match method {
            "initialize" => {
                let requested = params
                    .and_then(|p| p.get(&arena, "protocolVersion"))
                    .and_then(|v| v.as_str(&arena));
                Self::result(&id, &self.initialize_result(requested))
            }
            "ping" => Self::result(&id, "{}"),
            "tools/list" => Self::result(&id, &self.tools_json()),
            "tools/call" => {
                let params = match params {
                    Some(p) => p,
                    None => return Some(Self::error(&id, INVALID_PARAMS, "Invalid params")),
                };
                let name = match params.get(&arena, "name").and_then(|v| v.as_str(&arena)) {
                    Some(n) => n,
                    None => return Some(Self::error(&id, INVALID_PARAMS, "Invalid params")),
                };
                let arguments = params.get(&arena, "arguments");
                let args = ToolArgs::read(arguments.as_ref(), &arena);
                let outcome = match name {
                    TOOL_SEARCH => self.tool_search(&args),
                    TOOL_FACTS => self.tool_facts(&args),
                    // An unknown tool is a tool error and not a protocol
                    // error: the request itself was well formed, and the
                    // answer says which tool nobody implements.
                    other => Err(format!("unknown tool: {other}")),
                };
                match outcome {
                    Ok(text) => Self::result(&id, &Self::tool_result(&text, false)),
                    Err(message) => Self::result(&id, &Self::tool_result(&message, true)),
                }
            }
            _ => Self::error(&id, METHOD_NOT_FOUND, "Method not found"),
        })
    }

    /// Read requests from `input` and write answers to `output`, one
    /// JSON object per line.
    ///
    /// The loop ends when the input ends. A line that is not JSON is
    /// answered with a parse error and the loop carries on, because a
    /// client that sends one broken line has not stopped talking.
    #[cfg(feature = "std")]
    pub fn serve(
        &self,
        input: &mut impl std::io::BufRead,
        output: &mut impl std::io::Write,
    ) -> std::io::Result<()> {
        let mut raw: Vec<u8> = Vec::new();
        loop {
            raw.clear();
            if input.read_until(b'\n', &mut raw)? == 0 {
                break;
            }
            // The bytes are turned into text lossily rather than
            // refused: a line that is not UTF-8 is a line the JSON
            // parser will reject, and the parse error is the honest
            // answer to it.
            let line = String::from_utf8_lossy(&raw);
            let line = line.trim_end_matches(['\n', '\r']);
            if line.trim().is_empty() {
                continue;
            }
            if let Some(response) = self.handle_line(line) {
                writeln!(output, "{response}")?;
                output.flush()?;
            }
        }
        Ok(())
    }

    /// The `initialize` result.
    ///
    /// The client's version is echoed when this server speaks it, and
    /// the server's own version is sent otherwise.
    fn initialize_result(&self, requested: Option<&str>) -> String {
        let version = match requested {
            Some(v) if SUPPORTED_PROTOCOL_VERSIONS.contains(&v) => v,
            _ => PROTOCOL_VERSION,
        };
        format!(
            "{{\"protocolVersion\":{},\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":{},\"version\":{}}}}}",
            quoted(version),
            quoted(SERVER_NAME),
            quoted(SERVER_VERSION)
        )
    }

    /// A tool result: the text, and whether it is an error.
    fn tool_result(text: &str, is_error: bool) -> String {
        format!(
            "{{\"content\":[{{\"type\":\"text\",\"text\":{}}}],\"isError\":{}}}",
            quoted(text),
            is_error
        )
    }

    /// A successful response.
    fn result(id: &Id, result: &str) -> String {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}",
            id.text(),
            result
        )
    }

    /// An error response.
    fn error(id: &Id, code: i32, message: &str) -> String {
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":{},\"message\":{}}}}}",
            id.text(),
            code,
            quoted(message)
        )
    }

    /// The identifier a request carries.
    fn id_of(value: &Value, arena: &Arena) -> Id {
        match value {
            Value::Null => Id::Null,
            Value::String(idx) => Id::Str(arena.get_string(*idx).to_string()),
            Value::Number(n) => match n.as_i64() {
                Some(i) => Id::Int(i),
                None => Id::Num(n.as_f64()),
            },
            // An id that is neither a number nor a string is not an id
            // this server can echo, and `null` is the only thing a
            // response may carry that the client can still read.
            _ => Id::Null,
        }
    }

    /// The context the pipeline runs under inside the tools.
    ///
    /// The tools are the half that reads files, so a build without `std`
    /// does not read this.
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    fn pipeline_ctx(&self) -> Ctx {
        Ctx {
            max_depth: self.ctx.max_depth,
            max_members: self.ctx.max_members,
            max_file_size: self.ctx.max_file_size,
            filter: None,
            facts_sink: None,
        }
    }

    /// The `search` tool.
    #[cfg(feature = "std")]
    fn tool_search(&self, args: &ToolArgs<'_>) -> Result<String, String> {
        let pattern = args
            .pattern
            .ok_or_else(|| "the search tool needs a 'pattern' argument".to_string())?;
        if pattern.is_empty() {
            return Err("the search tool needs a non-empty 'pattern'".to_string());
        }
        let path = args.path.unwrap_or(".");
        let root = std::path::Path::new(path);
        if !root.exists() {
            return Err(format!("no such path: {path}"));
        }
        let needle = pattern.as_bytes();
        let mut out: Vec<String> = Vec::new();
        let mut state = SearchState::default();
        self.search_path(root, needle, &mut out, &mut state);
        if out.is_empty() {
            return Ok(if state.truncated {
                "[rgx: the search stopped early; more results may exist]\n".to_string()
            } else {
                "no matches\n".to_string()
            });
        }
        let mut text = String::new();
        for line in &out {
            text.push_str(line);
            text.push('\n');
        }
        if state.truncated {
            text.push_str("[rgx: the search stopped early; more results may exist]\n");
        }
        Ok(text)
    }

    /// The `search` tool, in a build without a filesystem.
    #[cfg(not(feature = "std"))]
    fn tool_search(&self, _args: &ToolArgs<'_>) -> Result<String, String> {
        Err("the search tool reads files, and this build of rgx-core has no std".to_string())
    }

    /// The `facts` tool.
    #[cfg(feature = "std")]
    fn tool_facts(&self, args: &ToolArgs<'_>) -> Result<String, String> {
        let path = args
            .path
            .ok_or_else(|| "the facts tool needs a 'path' argument".to_string())?;
        let file = std::path::Path::new(path);
        let meta = match std::fs::metadata(file) {
            Ok(m) => m,
            Err(_) => return Err(format!("no such file: {path}")),
        };
        if !meta.is_file() {
            return Err(format!("not a file: {path}"));
        }
        if meta.len() > self.ctx.max_file_size as u64 {
            return Err(format!("file is too large to report on: {path}"));
        }
        let data = std::fs::read(file).map_err(|e| format!("cannot read {path}: {e}"))?;
        let path_str = display_path(file);
        let (format, reported) = self.claimed_by(&path_str, &data);
        let facts = filter::facts_with(&path_str, format, &reported);
        let mut text = String::new();
        for fact in &facts {
            text.push_str(&fact.name);
            text.push_str(": ");
            text.push_str(&fact.value);
            text.push('\n');
        }
        if let Some(expression) = args.filter {
            let expr = filter::parse(expression)?;
            let matched = filter::matches(&expr, &facts);
            text.push_str(if matched {
                "match: yes\n"
            } else {
                "match: no\n"
            });
        }
        Ok(text)
    }

    /// The `facts` tool, in a build without a filesystem.
    #[cfg(not(feature = "std"))]
    fn tool_facts(&self, _args: &ToolArgs<'_>) -> Result<String, String> {
        Err("the facts tool reads files, and this build of rgx-core has no std".to_string())
    }

    /// The adapter that claims the file, the name it claims it under, and
    /// the facts it reported.
    ///
    /// **Why the chain is walked here rather than read off `process`.**
    /// A container's adapter is not in the units `process` produces:
    /// `process` recurses into the members and names *them*. The facts
    /// of the archive are the facts of the file the client asked about,
    /// so the chain is walked to the depth of one file.
    ///
    /// The adapter is asked twice -- once for the bytes, once for the
    /// facts -- because the pipeline asks the same way, and an adapter
    /// that has to parse the file again to answer pays for that parse
    /// only when something asks.
    #[cfg(feature = "std")]
    fn claimed_by(&self, path: &str, data: &[u8]) -> (&'static str, Vec<Field>) {
        let pol = crate::policy();
        for adapter in self.registry.candidates_for_path_bytes(path, data) {
            // The policy is applied for the reason it is applied in
            // `process`: under `Source` a rendering adapter does not get
            // the file, because the file's own bytes are the answer.
            if pol == Policy::Source
                && adapter.reach_for(data) == Reach::Render
                && !adapter.reach_needs_bytes()
            {
                continue;
            }
            match adapter.extract(data, path) {
                Ok(Outcome::Text(_)) | Ok(Outcome::Members(_)) => {
                    return (adapter.name(), adapter.facts(data, path));
                }
                // A bail and a failure are both claims about one
                // adapter, and both leave the chain running: the file
                // falls to the next candidate, and the format is the
                // adapter that answered rather than the one that
                // complained.
                Ok(Outcome::Bail(_)) | Err(_) => continue,
            }
        }
        ("raw", Vec::new())
    }

    /// Walk `root` and collect the lines that hold `needle`.
    #[cfg(feature = "std")]
    fn search_path(
        &self,
        root: &std::path::Path,
        needle: &[u8],
        out: &mut Vec<String>,
        state: &mut SearchState,
    ) {
        let meta = match std::fs::metadata(root) {
            Ok(m) => m,
            Err(_) => return,
        };
        if meta.is_file() {
            self.search_file(root, needle, out, state);
            return;
        }
        if !meta.is_dir() {
            return;
        }
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => continue,
                };
                let path = entry.path();
                // The file type comes from the directory entry, which
                // does not follow a symbolic link: a link into a
                // directory the walk has already been would make the
                // walk unbounded.
                let kind = match entry.file_type() {
                    Ok(kind) => kind,
                    Err(_) => continue,
                };
                if kind.is_dir() {
                    if is_repo_state(&path) {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                if !kind.is_file() {
                    continue;
                }
                self.search_file(&path, needle, out, state);
                if state.truncated {
                    return;
                }
            }
        }
    }

    /// Search one file.
    ///
    /// **The two paths are rgx's own.** A file an adapter claims is
    /// asked for its bytes, and a file nobody claims is searched as it
    /// stands. They differ in what the corpus holds, and a search that
    /// reported the same lines for both would be wrong about the
    /// archives it claims to read.
    #[cfg(feature = "std")]
    fn search_file(
        &self,
        path: &std::path::Path,
        needle: &[u8],
        out: &mut Vec<String>,
        state: &mut SearchState,
    ) {
        if state.files >= MAX_FILES {
            state.truncated = true;
            return;
        }
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };
        if meta.len() > self.ctx.max_file_size as u64 {
            return;
        }
        let data = match std::fs::read(path) {
            Ok(data) => data,
            Err(_) => return,
        };
        state.files += 1;
        let path_str = display_path(path);
        if self.registry.may_claim_for_path(&path_str) {
            let mut found: Vec<crate::Found> = Vec::new();
            crate::process(
                &self.registry,
                &path_str,
                &data,
                0,
                &self.pipeline_ctx(),
                &mut found,
            );
            for unit in &found {
                self.search_unit(&unit.path, &unit.bytes, needle, out, state);
                if state.truncated {
                    return;
                }
            }
        } else {
            self.search_unit(&path_str, &data, needle, out, state);
        }
    }

    /// The lines of one unit that hold `needle`.
    ///
    /// The line a match sits on is reported once, however many matches
    /// the line holds: a line that says the thing twice is still one
    /// line, and the count of lines is what a reader counts.
    #[cfg(feature = "std")]
    fn search_unit(
        &self,
        unit_path: &str,
        bytes: &[u8],
        needle: &[u8],
        out: &mut Vec<String>,
        state: &mut SearchState,
    ) {
        if needle.is_empty() {
            return;
        }
        let starts = line_starts(bytes);
        let mut reported: Option<usize> = None;
        for start in crate::memchr::memmem::find_iter(bytes, needle) {
            let line = match starts.binary_search(&start) {
                Ok(i) => i,
                Err(0) => 0,
                Err(i) => i - 1,
            };
            if reported == Some(line) {
                continue;
            }
            reported = Some(line);
            let from = starts[line];
            let to = if line + 1 < starts.len() {
                starts[line + 1].saturating_sub(1)
            } else {
                bytes.len()
            };
            let text = String::from_utf8_lossy(&bytes[from..to]);
            out.push(format!(
                "{unit_path}:{}:{}",
                line + 1,
                text.trim_end_matches('\r')
            ));
            state.matches += 1;
            if state.matches >= MAX_MATCHES {
                state.truncated = true;
                return;
            }
        }
    }
}

/// The state one search carries from file to file.
#[cfg(feature = "std")]
#[derive(Default)]
struct SearchState {
    files: usize,
    matches: usize,
    /// Whether a ceiling was reached. It is reported rather than
    /// hidden: an answer that stops early and does not say so reads as
    /// a complete one.
    truncated: bool,
}

/// The offsets every line of `bytes` starts at.
#[cfg(feature = "std")]
fn line_starts(bytes: &[u8]) -> Vec<usize> {
    let mut starts = vec![0usize];
    starts.extend(crate::memchr::memchr_iter(b'\n', bytes).map(|i| i + 1));
    starts
}

/// A path as it is reported: forward slashes, so the answer reads the
/// same on every platform.
#[cfg(feature = "std")]
fn display_path(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// The repository's own state is metadata *about* the corpus rather than
/// the corpus, and it is routinely larger than the tree it describes.
/// The walk skips it, the same way the CLI's walk does.
#[cfg(feature = "std")]
fn is_repo_state(path: &std::path::Path) -> bool {
    path.file_name()
        .map(|name| name == std::ffi::OsStr::new(".git"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    // The module's own `Vec` import is behind the `std` feature, and the
    // tests are not: a `no_std` test run still builds them.
    use alloc::vec::Vec;

    fn server() -> McpServer {
        McpServer::new(Registry::new(Vec::new()))
    }

    fn request(id: &str, method: &str, params: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{params}}}"#)
    }

    #[test]
    fn initialize_answers_with_a_protocol_version() {
        let answer = server()
            .handle_line(&request("1", "initialize", "{}"))
            .expect("a response");
        assert!(answer.contains("\"protocolVersion\":\"2025-03-26\""));
        assert!(answer.contains("\"serverInfo\""));
    }

    #[test]
    fn initialize_echoes_a_version_the_server_speaks() {
        let answer = server()
            .handle_line(&request(
                "1",
                "initialize",
                r#"{"protocolVersion":"2024-11-05"}"#,
            ))
            .expect("a response");
        assert!(answer.contains("\"protocolVersion\":\"2024-11-05\""));
    }

    #[test]
    fn initialize_answers_with_its_own_version_for_one_it_does_not_speak() {
        let answer = server()
            .handle_line(&request(
                "1",
                "initialize",
                r#"{"protocolVersion":"1999-01-01"}"#,
            ))
            .expect("a response");
        assert!(answer.contains("\"protocolVersion\":\"2025-03-26\""));
    }

    #[test]
    fn tools_list_names_both_tools() {
        let answer = server()
            .handle_line(&request("2", "tools/list", "{}"))
            .expect("a response");
        assert!(answer.contains("\"name\":\"search\""));
        assert!(answer.contains("\"name\":\"facts\""));
        assert!(answer.contains("\"inputSchema\""));
    }

    #[test]
    fn a_notification_is_not_answered() {
        let answer =
            server().handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert!(answer.is_none());
    }

    #[test]
    fn a_request_without_an_id_is_not_answered() {
        let answer = server().handle_line(r#"{"jsonrpc":"2.0","method":"tools/list"}"#);
        assert!(answer.is_none());
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        let answer = server().handle_line("{not json").expect("a response");
        assert!(answer.contains("\"code\":-32700"));
        assert!(answer.contains("\"message\":\"Parse error\""));
    }

    #[test]
    fn an_unknown_method_is_a_method_not_found() {
        let answer = server()
            .handle_line(&request("7", "no/such/method", "{}"))
            .expect("a response");
        assert!(answer.contains("\"code\":-32601"));
        assert!(answer.contains("\"message\":\"Method not found\""));
    }

    #[test]
    fn an_unknown_tool_is_a_tool_error() {
        let answer = server()
            .handle_line(&request(
                "8",
                "tools/call",
                r#"{"name":"nosuchtool","arguments":{}}"#,
            ))
            .expect("a response");
        assert!(answer.contains("\"isError\":true"));
        assert!(answer.contains("nosuchtool"));
    }

    #[test]
    fn the_answer_carries_the_id_of_the_request() {
        let answer = server()
            .handle_line(&request("42", "ping", "{}"))
            .expect("a response");
        assert!(answer.contains("\"id\":42"));
        assert!(answer.contains("\"jsonrpc\":\"2.0\""));
    }

    #[test]
    fn a_string_id_comes_back_as_the_same_string() {
        let answer = server()
            .handle_line(r#"{"jsonrpc":"2.0","id":"abc","method":"ping"}"#)
            .expect("a response");
        assert!(answer.contains("\"id\":\"abc\""));
    }

    #[test]
    fn ping_answers_with_an_empty_result() {
        let answer = server()
            .handle_line(&request("1", "ping", "{}"))
            .expect("a response");
        assert!(answer.contains("\"result\":{}"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn facts_reports_the_facts_of_a_file() {
        let dir = std::env::temp_dir().join(format!("rgx-mcp-facts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("report.txt");
        std::fs::write(&file, "hello\n").unwrap();
        let path = display_path(&file);
        let answer = server()
            .handle_line(&request(
                "1",
                "tools/call",
                &format!(r#"{{"name":"facts","arguments":{{"path":"{path}"}}}}"#),
            ))
            .expect("a response");
        assert!(answer.contains("\"isError\":false"));
        assert!(answer.contains("path: "));
        assert!(answer.contains("format: raw"));
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn facts_answers_the_filter_it_was_given() {
        let dir = std::env::temp_dir().join(format!("rgx-mcp-filter-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("report.txt");
        std::fs::write(&file, "hello\n").unwrap();
        let path = display_path(&file);
        let answer = server()
            .handle_line(&request(
                "1",
                "tools/call",
                &format!(
                    r#"{{"name":"facts","arguments":{{"path":"{path}","filter":"ext:txt"}}}}"#
                ),
            ))
            .expect("a response");
        assert!(answer.contains("match: yes"));
        let answer = server()
            .handle_line(&request(
                "2",
                "tools/call",
                &format!(
                    r#"{{"name":"facts","arguments":{{"path":"{path}","filter":"ext:pdf"}}}}"#
                ),
            ))
            .expect("a response");
        assert!(answer.contains("match: no"));
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn search_reports_the_lines_that_hold_the_pattern() {
        let dir = std::env::temp_dir().join(format!("rgx-mcp-search-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("notes.txt");
        std::fs::write(&file, "first line\nneedle here\nlast line\n").unwrap();
        let path = display_path(&file);
        let answer = server()
            .handle_line(&request(
                "1",
                "tools/call",
                &format!(
                    r#"{{"name":"search","arguments":{{"pattern":"needle","path":"{path}"}}}}"#
                ),
            ))
            .expect("a response");
        assert!(answer.contains("\"isError\":false"));
        assert!(answer.contains("needle here"));
        assert!(!answer.contains("first line"));
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn search_says_so_when_nothing_matched() {
        let dir = std::env::temp_dir().join(format!("rgx-mcp-nomatch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("notes.txt");
        std::fs::write(&file, "first line\n").unwrap();
        let path = display_path(&file);
        let answer = server()
            .handle_line(&request(
                "1",
                "tools/call",
                &format!(
                    r#"{{"name":"search","arguments":{{"pattern":"absent","path":"{path}"}}}}"#
                ),
            ))
            .expect("a response");
        assert!(answer.contains("no matches"));
        std::fs::remove_file(&file).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}
