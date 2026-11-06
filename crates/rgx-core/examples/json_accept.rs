// SPDX-License-Identifier: Apache-2.0

//! The conformance gate for [`rgx_core::djson`], as the `json-harness` suite
//! drives it: read the document named as the last argument, and exit 0 if it
//! was accepted, nonzero if it was rejected. That is the whole interface the
//! suite assumes of a parser, and it is why a result here means the same
//! thing as it would from any other language.
//!
//! ```text
//! cargo run --release -p rgx-core --example json_accept -- <document>
//! python conformance/run.py --parser "target\release\examples\json_accept.exe {case}" --batch
//! ```
//!
//! The suite is derived from RFC 8259's own text, not from another
//! implementation, which is what makes a disagreement with this parser
//! evidence about the parser rather than about the suite.

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("json_accept: a document path is the whole interface");
        std::process::exit(2);
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => {
            // A case the harness named that we cannot open is a case we did
            // not reject, and reporting that as a rejection is a false pass.
            eprintln!("json_accept: cannot read {path}");
            std::process::exit(3);
        }
    };
    // JSON is defined over text, not over bytes. A document that is not
    // valid UTF-8 is not a JSON document, and saying so is a rejection --
    // but it is a rejection for a reason the suite never asked about, so it
    // gets its own exit code and a note rather than a silent 1.
    let Ok(text) = std::str::from_utf8(&bytes) else {
        eprintln!("json_accept: not UTF-8");
        std::process::exit(4);
    };
    if rgx_core::djson::parse(text).is_err() {
        std::process::exit(1);
    }
}
