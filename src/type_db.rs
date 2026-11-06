// SPDX-License-Identifier: Apache-2.0

//! File-type classification for `-t`/`-T` filters and `.rgxrc` defaults.
//!
//! A type is a named bag of extensions: `rust` covers `rs`, `python` covers
//! `py`, `markdown` covers `md`/`markdown`/`mdown`. The default table mirrors
//! `ripgrep`'s `types/ripgrep-types.tsv` closely enough that a corpus scripted
//! against `rg -t rust -T minified` behaves the same against `rgx`. Users can
//! extend the table with `--type-add 'foo:ext1,ext2'` and wipe the defaults
//! with `--type-clear all`.
//!
//! The classifier only inspects the extension. Files with an extension that is
//! not in any registered bag get `None`, which the filter treats as "no
//! classification" — the include side skips them and the exclude side does
//! nothing. The optional byte-histogram classifier (gated behind
//! `adapters-inspect`) is the path for files with no extension or a
//! content-only type, and is consulted separately.

use std::collections::HashMap;

/// A registered file type: a name (e.g. `"rust"`) and its file extensions.
#[derive(Debug, Clone)]
pub struct TypeEntry {
    pub name: String,
    pub exts: Vec<String>,
}

/// Owns the type table and the extension→type reverse index.
#[derive(Debug, Clone, Default)]
pub struct TypeDb {
    types: Vec<TypeEntry>,
    /// Lowercased extension (without the leading dot) → type name.
    by_ext: HashMap<String, String>,
}

impl TypeDb {
    /// Build the default table used at startup.
    ///
    /// Mirrors ripgrep's defaults for the languages and formats that show up
    /// in real code corpora. The list is deliberately generous: a type that is
    /// too inclusive can be excluded with `-T`, and a missing one can be added
    /// with `--type-add`.
    pub fn with_defaults() -> Self {
        let defaults: &[(&str, &[&str])] = &[
            ("ada", &["ada", "adb", "ads"]),
            ("asciidoc", &["adoc", "asciidoc"]),
            ("asm", &["asm", "s"]),
            ("awk", &["awk"]),
            ("batch", &["bat", "cmd"]),
            ("bicep", &["bicep"]),
            ("bmp", &["bmp"]),
            ("bzip2", &["bz2"]),
            ("c", &["c", "h"]),
            ("cabal", &["cabal"]),
            ("cbor", &["cbor"]),
            ("class", &["class"]),
            ("clojure", &["clj", "cljc", "cljs", "cljx"]),
            ("cmake", &["cmake", "CMakeLists.txt"]),
            ("cobol", &["cob", "cbl"]),
            ("config", &["conf", "config", "ini", "properties", "toml"]),
            ("coq", &["coq", "v"]),
            (
                "cpp",
                &["cpp", "cc", "cxx", "hpp", "hh", "hxx", "h++", "c++"],
            ),
            ("crystal", &["cr"]),
            ("csharp", &["cs"]),
            ("cshtml", &["cshtml", "razor"]),
            ("css", &["css", "scss", "sass", "less"]),
            ("csv", &["csv", "tsv"]),
            ("cuda", &["cu", "cuh"]),
            ("d", &["d"]),
            ("dart", &["dart"]),
            ("dex", &["dex"]),
            ("dhall", &["dhall"]),
            ("diff", &["diff", "patch"]),
            ("dockerfile", &["Dockerfile", "dockerfile"]),
            ("dotenv", &[".env"]),
            ("elixir", &["ex", "exs"]),
            ("elf", &["elf"]),
            ("elm", &["elm"]),
            ("emacs", &["el"]),
            ("erlang", &["erl", "hrl"]),
            ("fsharp", &["fs", "fsx", "fsi"]),
            ("fortran", &["f", "f77", "f90", "f95", "for"]),
            ("gif", &["gif"]),
            ("gzip", &["gz"]),
            ("gettext", &["po", "pot", "mo"]),
            ("ghc", &["hs", "lhs"]),
            (
                "glsl",
                &["glsl", "vert", "frag", "geom", "comp", "tesc", "tese"],
            ),
            ("go", &["go"]),
            ("graphql", &["graphql", "gql"]),
            ("groovy", &["groovy", "gradle"]),
            ("haskell", &["hs"]),
            ("hcl", &["hcl", "tf", "tfvars"]),
            ("html", &["html", "htm", "xhtml"]),
            ("idris", &["idr", "lidr"]),
            ("ini", &["ini"]),
            ("isabelle", &["thy"]),
            ("java", &["java"]),
            ("javascript", &["js", "mjs", "cjs", "jsx"]),
            ("json", &["json", "jsonc", "jsonl", "ndjson"]),
            ("julia", &["jl"]),
            ("kotlin", &["kt", "kts"]),
            ("latex", &["tex", "latex"]),
            ("less", &["less"]),
            ("lisp", &["lisp", "lsp", "cl", "scm"]),
            ("log", &["log"]),
            ("lua", &["lua"]),
            (
                "makefile",
                &["mk", "mak", "makefile", "Makefile", "GNUmakefile"],
            ),
            ("markdown", &["md", "markdown", "mdown", "mkd"]),
            ("matlab", &["m"]),
            ("mint", &["mint"]),
            ("nim", &["nim"]),
            ("nix", &["nix"]),
            ("ocaml", &["ml", "mli"]),
            ("org", &["org"]),
            ("pascal", &["pas", "pp"]),
            ("perl", &["pl", "pm"]),
            ("php", &["php", "php5", "phtml", "phps"]),
            ("po", &["po", "pot"]),
            ("powershell", &["ps1", "psm1", "psd1"]),
            ("protobuf", &["proto"]),
            ("ps", &["ps", "eps"]),
            ("purescript", &["purs"]),
            ("python", &["py", "pyi", "pyw"]),
            ("r", &["r", "R"]),
            ("racket", &["rkt"]),
            ("reasonml", &["re", "rei"]),
            ("reStructuredText", &["rst"]),
            ("ron", &["ron"]),
            ("ruby", &["rb", "rake"]),
            ("rust", &["rs"]),
            ("sass", &["sass"]),
            ("scala", &["scala", "sc"]),
            ("scheme", &["scm", "ss"]),
            ("scss", &["scss"]),
            ("shell", &["sh", "bash", "zsh", "fish"]),
            ("smalltalk", &["st"]),
            ("sql", &["sql"]),
            ("svelte", &["svelte"]),
            ("swift", &["swift"]),
            ("tcl", &["tcl"]),
            ("tex", &["tex"]),
            ("text", &["txt", "text"]),
            ("toml", &["toml"]),
            ("tsv", &["tsv"]),
            ("typescript", &["ts", "tsx", "cts", "mts"]),
            ("vala", &["vala"]),
            ("vb", &["vb"]),
            ("verilog", &["v", "vh", "sv", "svh"]),
            ("vhdl", &["vhd", "vhdl"]),
            ("vim", &["vim", "vimrc"]),
            ("vue", &["vue"]),
            ("xml", &["xml", "xsl", "xslt", "svg", "xsd", "wsdl"]),
            ("yaml", &["yaml", "yml"]),
            ("zig", &["zig"]),
            ("zsh", &["zsh"]),
            // Magic-byte-recognised formats. `-t pdf` over an extensionless
            // file depends on these; `accepts_with_bytes` in `walk.rs`
            // answers the type from the first ~512 bytes when the
            // extension classifier returned None.
            ("7z", &["7z"]),
            ("asf", &["asf", "wmv", "wma", "wm"]),
            ("blender", &["blend"]),
            ("cfb", &["doc", "dot", "xls", "ppt", "msg", "vsd"]),
            ("elf", &[]),
            ("flac", &["flac"]),
            ("hdf5", &["h5", "hdf5"]),
            ("ico", &["ico"]),
            ("jpeg", &["jpg", "jpeg"]),
            ("macho", &[]),
            ("midi", &["mid", "midi"]),
            ("mp3", &["mp3"]),
            ("mpeg-ts", &["m2ts"]),
            ("ogg", &["ogg", "ogv", "oga", "opus"]),
            ("pdf", &["pdf"]),
            ("png", &["png"]),
            ("psd", &["psd"]),
            ("rar", &["rar"]),
            ("sqlite", &["sqlite", "sqlite3", "db"]),
            ("tiff", &["tif", "tiff"]),
            ("wasm", &["wasm"]),
            ("webp", &["webp"]),
            ("wmf", &["wmf"]),
            ("xz", &["xz"]),
            ("zstd", &["zst"]),
            // Common non-language types
            ("minified", &["min.js", "min.css"]),
            ("generated", &["generated.go", "generated.rs"]),
        ];
        let mut db = TypeDb::default();
        for (name, exts) in defaults {
            db.add(name, exts);
        }
        db
    }

    /// Register a new type or extend an existing one.
    ///
    /// Extensions are stored lowercased without the leading dot. Filenames
    /// containing a dot (e.g. `Dockerfile`) are matched by exact basename,
    /// not by extension; they are stored verbatim and matched via `classify`.
    /// If `name` already exists, the new extensions are appended to it; the
    /// reverse-index mapping for each new extension wins over any previous
    /// type that claimed it.
    pub fn add(&mut self, name: &str, exts: &[&str]) -> &mut Self {
        // Append the new extensions to the existing entry, or create one.
        let pos = self.types.iter().position(|t| t.name == name);
        let new_exts: Vec<String> = exts.iter().map(|e| normalize_ext(e)).collect();
        if let Some(idx) = pos {
            let entry = &mut self.types[idx];
            for ext in &new_exts {
                if !entry.exts.contains(ext) {
                    entry.exts.push(ext.clone());
                }
            }
        } else {
            self.types.push(TypeEntry {
                name: name.to_string(),
                exts: new_exts,
            });
        }
        // Last add wins for any extension, so the new exts overwrite the
        // reverse-index mapping but the old type's existing mappings stay
        // intact when those exts are not in the new add.
        for ext in &self.types[self.types.iter().position(|t| t.name == name).unwrap()].exts {
            self.by_ext.insert(ext.clone(), name.to_string());
        }
        self
    }

    /// Remove every registered type. After this call, `classify` returns
    /// `None` for every path.
    pub fn clear(&mut self) -> &mut Self {
        self.types.clear();
        self.by_ext.clear();
        self
    }

    /// Look up the type for a file's name.
    ///
    /// The most specific pattern wins: `bundle.min.js` is `minified` and
    /// not `javascript`, and `api.generated.rs` is `generated` and not
    /// `rust`. That is the *one* type a file has — the question a facts
    /// index records. A file can match several types at once, and the
    /// filter asks that question; `patterns_of` answers it.
    pub fn classify_name(&self, name: &str) -> Option<&str> {
        // Try basename first: covers `Dockerfile`, `Makefile`, etc. The keys
        // in `by_ext` are lowercased, so the basename is normalised before
        // the lookup only when it carries an uppercase ASCII byte.
        let lower_name: std::borrow::Cow<'_, str> = if name.bytes().any(|b| b.is_ascii_uppercase())
        {
            std::borrow::Cow::Owned(name.to_ascii_lowercase())
        } else {
            std::borrow::Cow::Borrowed(name)
        };
        if let Some(t) = self.by_ext.get(lower_name.as_ref()) {
            return Some(t.as_str());
        }
        // Walk dotted extension suffixes from most specific to least specific
        // (`bundle.min.js` -> `min.js`, then `js`) so multi-dot types like
        // `minified` (`min.js`, `min.css`) and `generated` (`generated.rs`)
        // win over the plain language extension underneath.
        for ext in rgx_core::extension_candidates(name) {
            if let Some(t) = self.by_ext.get(ext.as_ref()) {
                return Some(t.as_str());
            }
        }
        None
    }

    /// The patterns a type is made of: the extensions and the bare
    /// filenames that name it.
    ///
    /// A file matches a type when its name is one of these patterns or
    /// ends with a dot and one of them, so `lib.min.js` matches both
    /// `minified` (`min.js`) and `javascript` (`js`). That overlap is
    /// ripgrep's model, and the filter is built on it.
    pub fn patterns_of(&self, name: &str) -> Option<&[String]> {
        let canonical = self.resolve(name)?;
        self.types
            .iter()
            .find(|t| t.name == canonical)
            .map(|t| t.exts.as_slice())
    }

    /// Names of every registered type, sorted for stable `--type-list` output.
    pub fn type_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.types.iter().map(|t| t.name.as_str()).collect();
        names.sort_unstable();
        names
    }

    /// Whether a type with this name is registered.
    ///
    /// The name is matched exactly, the way `classify` reports it and the way
    /// the include and exclude sets compare it: `Rust` is not `rust`, and a
    /// name the table does not have is a name the user got wrong.
    pub fn has_type(&self, name: &str) -> bool {
        self.resolve(name).is_some()
    }

    /// The canonical name of a type: the name itself, or the type an alias
    /// names.
    ///
    /// The aliases are the names ripgrep uses for a type this table has
    /// under another name, so a flag written out of ripgrep's habit works
    /// here too. An alias is only another *name* for the type: `-t js` and
    /// `-t javascript` select the same files.
    ///
    /// An alias is accepted only when the type it names is still in the
    /// table: after `--type-clear javascript`, `-t js` must be refused
    /// like `-t javascript`, not resolve to a type whose patterns were
    /// just wiped — an empty pattern list silently matches nothing, which
    /// reads as "there is no Rust here" rather than "there is no type
    /// called rust".
    pub fn resolve<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        if self.types.iter().any(|t| t.name == name) {
            return Some(name);
        }
        ALIASES
            .iter()
            .find(|(alias, _)| *alias == name)
            .map(|(_, target)| *target)
            .filter(|target| self.types.iter().any(|t| t.name == *target))
    }
}

/// The names ripgrep uses for a type this table has under another name.
///
/// The two tables are not the same table: ripgrep calls the JavaScript
/// type `js` and this table calls it `javascript`, ripgrep calls the
/// shell script type `sh` and this table calls it `shell`. These are the
/// names ripgrep uses for a type that is here, so a flag written out of
/// ripgrep's habit works without a second thought.
///
/// An alias is another *name* for the type, not a type of its own: `-t js`
/// and `-t javascript` select the same files, and `--type-list` prints
/// the canonical name.
const ALIASES: &[(&str, &str)] = &[
    ("cs", "csharp"),
    ("docker", "dockerfile"),
    ("hs", "haskell"),
    ("js", "javascript"),
    ("jl", "julia"),
    ("make", "makefile"),
    ("md", "markdown"),
    ("ml", "ocaml"),
    ("purs", "purescript"),
    ("py", "python"),
    ("rst", "reStructuredText"),
    ("sh", "shell"),
    ("ts", "typescript"),
    ("txt", "text"),
    ("vimscript", "vim"),
];

/// Normalize an extension or bare filename to the form stored in `by_ext`:
/// lowercased, no leading dot.
fn normalize_ext(ext: &str) -> String {
    let trimmed = ext.strip_prefix('.').unwrap_or(ext);
    trimmed.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_extensions() {
        let db = TypeDb::with_defaults();
        assert_eq!(db.classify_name("foo.rs"), Some("rust"));
        assert_eq!(db.classify_name("FOO.RS"), Some("rust"));
        assert_eq!(db.classify_name("main.py"), Some("python"));
        assert_eq!(db.classify_name("c.ts"), Some("typescript"));
        assert_eq!(db.classify_name("bundle.min.js"), Some("minified"));
        assert_eq!(db.classify_name("styles.min.css"), Some("minified"));
        assert_eq!(db.classify_name("api.generated.rs"), Some("generated"));
    }

    #[test]
    fn classify_basenames_for_special_files() {
        let db = TypeDb::with_defaults();
        assert_eq!(db.classify_name("Dockerfile"), Some("dockerfile"));
        assert_eq!(db.classify_name("Makefile"), Some("makefile"));
    }

    #[test]
    fn classify_unknown_returns_none() {
        let db = TypeDb::with_defaults();
        assert_eq!(db.classify_name("foo.xyz"), None);
        assert_eq!(db.classify_name("README"), None);
    }

    #[test]
    fn add_extends_existing() {
        let mut db = TypeDb::with_defaults();
        db.add("rust", &["rs2"]);
        assert_eq!(db.classify_name("foo.rs2"), Some("rust"));
        // The original `rs` extension is still classified as rust because
        // add appends rather than replaces.
        assert_eq!(db.classify_name("foo.rs"), Some("rust"));
    }

    #[test]
    fn a_type_is_made_of_its_patterns() {
        let db = TypeDb::with_defaults();
        assert_eq!(db.patterns_of("rust"), Some(&["rs".to_string()][..]));
        // The patterns are the part of the glob that follows the star, so a
        // file matches the type when its name ends with a dot and one of
        // them. `lib.min.js` therefore matches `minified` *and*
        // `javascript`: that overlap is ripgrep's model.
        let minified = db.patterns_of("minified").unwrap();
        assert!(minified.contains(&"min.js".to_string()));
        let javascript = db.patterns_of("javascript").unwrap();
        assert!(javascript.contains(&"js".to_string()));
        assert!(db.patterns_of("nosuchtype").is_none());
    }

    #[test]
    fn the_most_specific_pattern_names_the_type() {
        let db = TypeDb::with_defaults();
        // One type per file: the most specific pattern wins.
        assert_eq!(db.classify_name("bundle.min.js"), Some("minified"));
        assert_eq!(db.classify_name("api.generated.rs"), Some("generated"));
        // A name no pattern claims has no type at all.
        assert_eq!(db.classify_name("thing.xyz"), None);
    }

    #[test]
    fn an_alias_is_another_name_for_the_type() {
        let db = TypeDb::with_defaults();
        // The names ripgrep uses for a type this table has under another
        // name are accepted, and they are the same type.
        assert!(db.has_type("js"));
        assert_eq!(db.resolve("js"), Some("javascript"));
        assert_eq!(db.resolve("javascript"), Some("javascript"));
        assert_eq!(db.patterns_of("js"), db.patterns_of("javascript"));
        // A name that is neither a type nor an alias is nobody's type.
        assert!(!db.has_type("nosuchtype"));
        assert_eq!(db.resolve("nosuchtype"), None);
    }

    #[test]
    fn clear_resets_everything() {
        let mut db = TypeDb::with_defaults();
        db.clear();
        assert!(db.classify_name("foo.rs").is_none());
    }

    #[test]
    fn type_names_includes_defaults() {
        let db = TypeDb::with_defaults();
        let names = db.type_names();
        assert!(names.contains(&"rust"));
        assert!(names.contains(&"python"));
        assert!(names.contains(&"markdown"));
    }
}
