// SPDX-License-Identifier: Apache-2.0
//! The MCP server, end to end: the real request bytes over the real
//! stream, and the real answers back.
//!
//! **The framing is the one `--serve` already uses.** One JSON object
//! per line, newline-delimited, in and out. A client that speaks to this
//! server and a client that speaks to `rgx --serve` read the same kind
//! of line, which is the point of putting the server in the crate
//! rather than in the binary: the protocol is testable without spawning
//! anything.
//!
//! **The answers are read as JSON, not as text.** A response that
//! happens to contain the right words is not a response the client can
//! use, so every answer here is parsed and asked for the field it
//! claims to carry.

use std::path::{Path, PathBuf};

use rgx_core::djson::{self, Arena, Value};
use rgx_core::mcp::McpServer;
use rgx_core::Registry;

mod common;

/// The server the tests talk to: an empty registry, so the corpus is
/// the files on disk and no adapter claims any of them.
fn server() -> McpServer {
    McpServer::new(Registry::new(Vec::new()))
}

/// A temporary directory for one test.
///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn temp(tag: &str) -> PathBuf {
    common::scratch(&format!("mcp-{tag}"))
}

/// A path as the server reports it: forward slashes.
fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Send `lines` to the server and collect the answers, one per line.
fn drive(lines: &[&str]) -> Vec<String> {
    let mut input = String::new();
    for line in lines {
        input.push_str(line);
        input.push('\n');
    }
    let mut cursor: &[u8] = input.as_bytes();
    let mut output: Vec<u8> = Vec::new();
    server().serve(&mut cursor, &mut output).unwrap();
    String::from_utf8(output)
        .expect("the server answers in UTF-8")
        .lines()
        .map(str::to_string)
        .collect()
}

/// One answer, parsed.
fn answer(line: &str) -> Arena {
    djson::parse(line).unwrap_or_else(|e| panic!("the answer is JSON: {line} ({e})"))
}

/// The string a field of `value` holds.
fn str_field(value: &Value, arena: &Arena, key: &str) -> String {
    let held = value
        .get(arena, key)
        .unwrap_or_else(|| panic!("the answer has a {key}: {arena:?}"));
    match held {
        Value::String(idx) => arena.get_string(idx).to_string(),
        other => format!("{other:?}"),
    }
}

/// The number a field of `value` holds.
fn int_field(value: &Value, arena: &Arena, key: &str) -> Option<i64> {
    value.get(arena, key).and_then(|v| v.as_i64())
}

/// The boolean a field of `value` holds.
fn bool_field(value: &Value, arena: &Arena, key: &str) -> Option<bool> {
    value.get(arena, key).and_then(|v| v.as_bool())
}

/// The text of a tool result.
fn tool_text(arena: &Arena) -> String {
    let result = arena.root().get(arena, "result").expect("a result");
    let content = result.get(arena, "content").expect("content");
    let block = content
        .as_array(arena)
        .expect("an array of content blocks")
        .first()
        .expect("a content block");
    str_field(block, arena, "text")
}

#[test]
fn initialize_answers_with_a_protocol_version() {
    let answers = drive(&[r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#]);
    assert_eq!(answers.len(), 1);
    let arena = answer(&answers[0]);
    let root = arena.root();
    assert_eq!(str_field(&root, &arena, "jsonrpc"), "2.0");
    assert_eq!(int_field(&root, &arena, "id"), Some(1));
    let result = root.get(&arena, "result").expect("a result");
    assert!(!str_field(&result, &arena, "protocolVersion").is_empty());
    let info = result.get(&arena, "serverInfo").expect("serverInfo");
    assert_eq!(str_field(&info, &arena, "name"), "rgx");
}

#[test]
fn a_notification_is_not_answered() {
    let answers = drive(&[
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
    ]);
    // The notification produced no line; the ping produced one.
    assert_eq!(answers.len(), 1);
    let arena = answer(&answers[0]);
    assert_eq!(int_field(&arena.root(), &arena, "id"), Some(1));
}

#[test]
fn tools_list_names_both_tools() {
    let answers = drive(&[r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#]);
    let arena = answer(&answers[0]);
    let result = arena.root().get(&arena, "result").expect("a result");
    let tools = result.get(&arena, "tools").expect("tools");
    let names: Vec<String> = tools
        .as_array(&arena)
        .expect("an array of tools")
        .iter()
        .map(|t| str_field(t, &arena, "name"))
        .collect();
    assert_eq!(names, vec!["search".to_string(), "facts".to_string()]);
}

#[test]
fn ping_answers_with_an_empty_result() {
    let answers = drive(&[r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#]);
    let arena = answer(&answers[0]);
    let result = arena.root().get(&arena, "result").expect("a result");
    assert!(result.as_object(&arena).expect("an object").is_empty());
}

#[test]
fn an_unknown_method_is_a_method_not_found() {
    let answers = drive(&[r#"{"jsonrpc":"2.0","id":4,"method":"no/such/method"}"#]);
    let arena = answer(&answers[0]);
    let error = arena.root().get(&arena, "error").expect("an error");
    assert_eq!(int_field(&error, &arena, "code"), Some(-32601));
    assert_eq!(int_field(&arena.root(), &arena, "id"), Some(4));
}

#[test]
fn malformed_json_is_a_parse_error() {
    let answers = drive(&["{not json", r#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#]);
    // The broken line is answered, and the session carries on.
    assert_eq!(answers.len(), 2);
    let arena = answer(&answers[0]);
    let error = arena.root().get(&arena, "error").expect("an error");
    assert_eq!(int_field(&error, &arena, "code"), Some(-32700));
    let arena = answer(&answers[1]);
    assert_eq!(int_field(&arena.root(), &arena, "id"), Some(5));
}

#[test]
fn an_unknown_tool_is_a_tool_error() {
    let answers = drive(&[
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nosuchtool","arguments":{}}}"#,
    ]);
    let arena = answer(&answers[0]);
    let result = arena.root().get(&arena, "result").expect("a result");
    assert_eq!(bool_field(&result, &arena, "isError"), Some(true));
    assert!(tool_text(&arena).contains("nosuchtool"));
}

#[test]
fn the_facts_tool_reports_the_facts_of_a_file() {
    let dir = temp("facts");
    let file = dir.join("report.txt");
    std::fs::write(&file, "hello\n").unwrap();
    let path = display(&file);
    let answers = drive(&[&format!(
        r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"facts","arguments":{{"path":"{path}"}}}}}}"#
    )]);
    let arena = answer(&answers[0]);
    let result = arena.root().get(&arena, "result").expect("a result");
    assert_eq!(bool_field(&result, &arena, "isError"), Some(false));
    let text = tool_text(&arena);
    assert!(text.contains("path: "), "{text}");
    assert!(text.contains("format: raw"), "{text}");
    assert!(text.contains("ext: txt"), "{text}");
    std::fs::remove_file(&file).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn the_facts_tool_answers_the_filter_it_was_given() {
    let dir = temp("filter");
    let file = dir.join("report.txt");
    std::fs::write(&file, "hello\n").unwrap();
    let path = display(&file);
    let answers = drive(&[
        &format!(
            r#"{{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{{"name":"facts","arguments":{{"path":"{path}","filter":"ext:txt"}}}}}}"#
        ),
        &format!(
            r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"facts","arguments":{{"path":"{path}","filter":"ext:pdf"}}}}}}"#
        ),
    ]);
    let arena = answer(&answers[0]);
    assert!(
        tool_text(&arena).contains("match: yes"),
        "{}",
        tool_text(&arena)
    );
    let arena = answer(&answers[1]);
    assert!(
        tool_text(&arena).contains("match: no"),
        "{}",
        tool_text(&arena)
    );
    std::fs::remove_file(&file).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn the_search_tool_reports_the_lines_that_hold_the_pattern() {
    let dir = temp("search");
    std::fs::write(dir.join("first.txt"), "nothing here\n").unwrap();
    std::fs::write(dir.join("second.txt"), "a needle in the haystack\n").unwrap();
    let path = display(&dir);
    let answers = drive(&[&format!(
        r#"{{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{{"name":"search","arguments":{{"pattern":"needle","path":"{path}"}}}}}}"#
    )]);
    let arena = answer(&answers[0]);
    let result = arena.root().get(&arena, "result").expect("a result");
    assert_eq!(bool_field(&result, &arena, "isError"), Some(false));
    let text = tool_text(&arena);
    assert!(text.contains("a needle in the haystack"), "{text}");
    assert!(text.contains("second.txt"), "{text}");
    assert!(!text.contains("nothing here"), "{text}");
    std::fs::remove_file(dir.join("first.txt")).unwrap();
    std::fs::remove_file(dir.join("second.txt")).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn the_search_tool_says_so_when_nothing_matched() {
    let dir = temp("nomatch");
    std::fs::write(dir.join("first.txt"), "nothing here\n").unwrap();
    let path = display(&dir);
    let answers = drive(&[&format!(
        r#"{{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{{"name":"search","arguments":{{"pattern":"absent","path":"{path}"}}}}}}"#
    )]);
    let arena = answer(&answers[0]);
    assert!(
        tool_text(&arena).contains("no matches"),
        "{}",
        tool_text(&arena)
    );
    std::fs::remove_file(dir.join("first.txt")).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}

#[test]
fn a_search_over_a_missing_path_is_a_tool_error() {
    let answers = drive(&[
        r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"search","arguments":{"pattern":"x","path":"no/such/path"}}}"#,
    ]);
    let arena = answer(&answers[0]);
    let result = arena.root().get(&arena, "result").expect("a result");
    assert_eq!(bool_field(&result, &arena, "isError"), Some(true));
    assert!(
        tool_text(&arena).contains("no such path"),
        "{}",
        tool_text(&arena)
    );
}
