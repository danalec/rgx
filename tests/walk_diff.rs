// SPDX-License-Identifier: Apache-2.0

//! The walker, held against the `ignore` crate.
//!
//! Every case here walks one tree twice — once with the in-house walker in
//! `src/walk.rs` (through the real binary) and once with the `ignore` crate
//! configured exactly as `main.rs` configures it — and requires the same
//! file set. A rule that drifts shows up here as a file rgx stopped
//! listing, which is the only way a wrong walker fails: silently.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ignore::overrides::OverrideBuilder as OracleOverrides;
use ignore::{WalkBuilder, WalkState};

mod common;

/// The current directory is process-global and the global gitignore is
/// resolved against it, so these tests take turns.
fn cwd_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

struct Scratch(PathBuf);

impl Scratch {
    ///
    /// The directory is one of this run's own: `common::scratch` owns the rule
    /// its name follows, and the rule is written down there.
    fn new(tag: &str) -> Scratch {
        Scratch(common::scratch(&format!("walk-{tag}")))
    }

    fn dir(&self, rel: &str) {
        std::fs::create_dir_all(self.0.join(rel)).expect("mkdir");
    }

    fn file(&self, rel: &str, body: &str) {
        self.try_file(rel, body)
            .unwrap_or_else(|e| panic!("write {rel}: {e}"));
    }

    /// A random corpus will land a file on a path a directory already took;
    /// those collisions are the generator's business, not a failure.
    fn try_file(&self, rel: &str, body: &str) -> std::io::Result<()> {
        let path = self.0.join(rel);
        if path.is_dir() {
            return Ok(());
        }
        if let Some(p) = path.parent() {
            if p.is_file() {
                return Ok(());
            }
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(path, body)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::env::var_os("RGX_KEEP_WALK_CORPUS").is_some() {
            eprintln!("corpus kept at {}", self.0.display());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Default)]
struct Opts {
    /// Skip the hidden files. rgx reads them by default, so this is the
    /// flag that puts ripgrep's behaviour back.
    no_hidden: bool,
    no_ignore: bool,
    follow: bool,
    max_depth: Option<usize>,
    globs: Vec<String>,
}

/// A hermetic environment: no user gitconfig, no user global gitignore.
fn hermetic(dir: &Path) {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).expect("home");
    for k in ["HOME", "USERPROFILE", "XDG_CONFIG_HOME"] {
        std::env::set_var(k, &home);
    }
    std::env::remove_var("GIT_CONFIG_GLOBAL");
    std::env::remove_var("GIT_CONFIG_SYSTEM");
}

/// The oracle: the `ignore` crate, configured as `main.rs` configures it.
fn oracle(roots: &[&str], o: &Opts) -> BTreeSet<String> {
    let mut b = WalkBuilder::new(roots[0]);
    for r in &roots[1..] {
        b.add(r);
    }
    b.hidden(o.no_hidden)
        .parents(!o.no_ignore)
        .git_ignore(!o.no_ignore)
        .git_global(!o.no_ignore)
        .git_exclude(!o.no_ignore)
        .follow_links(o.follow)
        .max_depth(o.max_depth);
    // The repository's own state is skipped, the way rgx skips it: the
    // oracle has to make the same call, or the two walkers disagree on
    // every corpus that has a `.git` in it.
    b.filter_entry(|e| {
        !(e.file_type().is_some_and(|t| t.is_dir())
            && e.file_name()
                .to_str()
                .is_some_and(rgx_core::walk_policy::is_vcs_dir))
    });
    // One override set, the office lock first, exactly as `main.rs` builds it:
    // the globs are the walker's business, and a later pattern wins, so a
    // `-g` the user wrote outranks the lock filter.
    //
    // They used to be a second matcher consulted from the callback below, and
    // that put the oracle at odds with both ripgrep and rgx: a matcher applied
    // in the callback sees every entry, including a file named on the command
    // line, while the walker deliberately exempts its roots. `ignore` returns
    // before matching a root (`walk.rs`, `run_one` hands a non-directory root
    // straight to the visitor), and `rg --files -g '*.rs' a` lists `a`. So the
    // callback filter had to go, not the exemption.
    let mut ob = OracleOverrides::new(".");
    ob.add("!~$*").expect("lock glob");
    for g in &o.globs {
        ob.add(g).expect("glob");
    }
    b.overrides(ob.build().expect("overrides"));
    let out = std::sync::Mutex::new(BTreeSet::new());
    b.threads(4).build_parallel().run(|| {
        let out = &out;
        Box::new(|res| {
            if let Ok(dent) = res {
                if !dent.file_type().is_some_and(|t| t.is_file()) {
                    return WalkState::Continue;
                }
                out.lock()
                    .expect("paths")
                    .insert(dent.path().to_string_lossy().replace('\\', "/"));
            }
            WalkState::Continue
        })
    });
    out.into_inner().expect("paths")
}

fn rgx(dir: &Path, roots: &[&str], o: &Opts) -> BTreeSet<String> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rgx"));
    cmd.arg("--files");
    if o.no_hidden {
        cmd.arg("--no-hidden");
    }
    if o.no_ignore {
        cmd.arg("--no-ignore");
    }
    if o.follow {
        cmd.arg("--follow");
    }
    if let Some(d) = o.max_depth {
        cmd.arg("--max-depth").arg(d.to_string());
    }
    for g in &o.globs {
        cmd.arg("-g").arg(g);
    }
    for r in roots {
        cmd.arg(r);
    }
    let out = cmd
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .env("HOME", dir.join("home"))
        .env("USERPROFILE", dir.join("home"))
        .env("XDG_CONFIG_HOME", dir.join("home"))
        .env_remove("GIT_CONFIG_GLOBAL")
        .env_remove("GIT_CONFIG_SYSTEM")
        .output()
        .expect("run rgx");
    // 0 and 1 are both ordinary (a query that matched nothing exits 1)
    assert!(
        out.status.code().unwrap_or(-1) < 2,
        "rgx {roots:?} exited {:?}: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let out = String::from_utf8_lossy(&out.stdout);
    out.lines()
        .map(|l| l.replace('\\', "/"))
        .filter(|l| !l.is_empty())
        .collect()
}

fn diff(a: &BTreeSet<String>, b: &BTreeSet<String>) -> String {
    let only_rgx: Vec<&String> = a.difference(b).collect();
    let only_oracle: Vec<&String> = b.difference(a).collect();
    format!(
        "rgx walked {} files, oracle {}\n  only rgx: {only_rgx:?}\n  only oracle: {only_oracle:?}",
        a.len(),
        b.len()
    )
}

/// The tree every case walks: nested `.gitignore`s that re-include what the
/// outer one excluded, a directory rule, `.ignore` outranking `.gitignore`,
/// `.git/info/exclude`, hidden files, and the office lock file.
fn corpus(s: &Scratch) {
    s.dir(".git/info");
    s.dir("build");
    s.dir("a/secret");
    s.dir("a/deep/deeper");
    s.dir("node_modules/pkg");
    s.dir(".hidden_dir");
    s.dir("docs");
    s.dir("vendor");
    // a repository inside the repository: git stops the outer rules there
    s.dir("sub/.git");
    s.file(".git/HEAD", "ref: refs/heads/main\n");
    s.file(
        ".gitignore",
        "# a comment\n\
         *.log\n\
         build/\n\
         !important.txt\n\
         /rooted.txt\n\
         docs/*.tmp\n\
         **/deep\n\
         trailing   \n\
         a/secret/\n\
         *.nested\n",
    );
    s.file(".git/info/exclude", "excluded.txt\n");
    s.file("a/.gitignore", "!*.log\nsecret/\n");
    s.file("docs/.ignore", "*.tmp\n!keep.tmp\n");
    s.file("important.txt", "important\n");
    s.file("rooted.txt", "rooted\n");
    s.file("a/rooted.txt", "not rooted at this level\n");
    s.file("a.log", "log\n");
    s.file("important.log", "kept by the negation in a/\n");
    s.file("rooted.log", "rooted log\n");
    s.file("build/out.txt", "built\n");
    s.file("a/a.log", "kept by the nested negation\n");
    s.file("a/keep.log", "kept too\n");
    s.file("a/secret/key.pem", "secret\n");
    s.file("a/deep/deeper/x.txt", "deep\n");
    s.file("node_modules/pkg/index.js", "vendored\n");
    s.file(".hidden_dir/x.txt", "hidden dir\n");
    s.file(".hidden_file", "hidden file\n");
    s.file("docs/notes.tmp", "tmp\n");
    s.file("docs/keep.tmp", "keep\n");
    s.file("excluded.txt", "excluded\n");
    s.file("vendor/lib.c", "vendored c\n");
    s.file("sub/keep.nested", "inside the nested repo\n");
    s.file("sub/drop.nested", "matched by the nested .gitignore\n");
    s.file("sub/.gitignore", "drop.*\n");
    s.file("~$budget.xlsx", "office lock\n");
    s.file("plain.txt", "plain\n");
    s.file("trailing", "trailing spaces were trimmed in the pattern\n");
}

fn check(s: &Scratch, roots: &[&str], o: &Opts) {
    hermetic(s.path());
    std::env::set_current_dir(s.path()).expect("cd");
    let a = rgx(s.path(), roots, o);
    let b = oracle(roots, o);
    assert_eq!(a, b, "{}", diff(&a, &b));
}

#[test]
fn default_walk() {
    let _g = cwd_lock();
    let s = Scratch::new("default");
    corpus(&s);
    check(&s, &["."], &Opts::default());
}

#[test]
fn hidden_files_are_read_by_default() {
    let _g = cwd_lock();
    let s = Scratch::new("hidden");
    corpus(&s);
    // The default reads the hidden files: a format that keeps its own
    // metadata in a dotfile is invisible otherwise.
    check(&s, &["."], &Opts::default());
}

#[test]
fn no_hidden_skips_the_hidden_files() {
    let _g = cwd_lock();
    let s = Scratch::new("nohidden");
    corpus(&s);
    check(
        &s,
        &["."],
        &Opts {
            no_hidden: true,
            ..Default::default()
        },
    );
}

#[test]
fn no_ignore_walks_everything() {
    let _g = cwd_lock();
    let s = Scratch::new("noignore");
    corpus(&s);
    check(
        &s,
        &["."],
        &Opts {
            no_ignore: true,
            ..Default::default()
        },
    );
}

#[test]
fn parent_directory_exclude_applies_to_a_subdirectory() {
    let _g = cwd_lock();
    let s = Scratch::new("parent");
    corpus(&s);
    // the root .gitignore and .git/info/exclude live above the walk root
    check(&s, &["a"], &Opts::default());
    check(&s, &["a/deep"], &Opts::default());
    check(&s, &["vendor"], &Opts::default());
    check(&s, &["build"], &Opts::default());
}

/// A parent rule with a slash is anchored to the parent's own directory,
/// and the walker used to match parent rules against the whole absolute
/// path -- where an anchored pattern can never win. The corpus above
/// never caught it because its discriminating file was also covered by a
/// local rule; this tree has no local rule, so `a/*.skip` in the root is
/// the only thing that can drop the file.
#[test]
fn a_slashed_parent_rule_reaches_into_the_walk_root() {
    let _g = cwd_lock();
    let s = Scratch::new("parent-slash");
    // A .gitignore without a repository is not a rule (the oracle's
    // `require_git` default), so the tree is a repo.
    s.dir(".git");
    s.file(".gitignore", "a/*.skip\n");
    s.dir("a");
    s.file("a/foo.skip", "x");
    s.file("a/keep.txt", "x");
    check(&s, &["a"], &Opts::default());
    // And the file is really gone, not equal to the oracle by accident.
    hermetic(s.path());
    std::env::set_current_dir(s.path()).expect("cd");
    let got = rgx(s.path(), &["a"], &Opts::default());
    assert!(
        !got.iter().any(|p| p.ends_with("foo.skip")),
        "the slashed parent rule must drop it: {got:?}"
    );
    assert!(
        got.iter().any(|p| p.ends_with("keep.txt")),
        "the sibling stays: {got:?}"
    );
}

#[test]
fn max_depth_stops_the_descent() {
    let _g = cwd_lock();
    let s = Scratch::new("depth");
    corpus(&s);
    for d in 0..5 {
        check(
            &s,
            &["."],
            &Opts {
                max_depth: Some(d),
                ..Default::default()
            },
        );
    }
}

#[test]
fn include_globs_filter_the_listing() {
    let _g = cwd_lock();
    let s = Scratch::new("globs");
    corpus(&s);
    for globs in [
        vec!["*.txt"],
        vec!["!*.txt"],
        vec!["a/**"],
        vec!["*.txt", "!a/**"],
        vec!["**/deeper/**"],
        vec!["[ab]*.log"],
    ] {
        check(
            &s,
            &["."],
            &Opts {
                globs: globs.iter().map(|g| g.to_string()).collect(),
                ..Default::default()
            },
        );
    }
}

#[test]
fn global_gitignore_applies() {
    let _g = cwd_lock();
    let s = Scratch::new("global");
    corpus(&s);
    let home = s.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let ignore = s.path().join("globalignore");
    std::fs::write(&ignore, "*.c\n!vendor/*.c\n").expect("global ignore");
    let config = s.path().join("gitconfig");
    std::fs::write(
        &config,
        format!("[core]\n\texcludesFile = {}\n", ignore.display()),
    )
    .expect("gitconfig");
    hermetic(s.path());
    std::env::set_var("GIT_CONFIG_GLOBAL", &config);
    std::env::set_current_dir(s.path()).expect("cd");
    let a = rgx_env(s.path(), &["."], &Opts::default());
    let b = oracle(&["."], &Opts::default());
    assert_eq!(a, b, "{}", diff(&a, &b));
}

#[cfg(unix)]
use std::os::unix::fs::symlink as symlink_dir;
#[cfg(unix)]
use std::os::unix::fs::symlink as symlink_file;
#[cfg(windows)]
use std::os::windows::fs::{symlink_dir, symlink_file};

/// Symlinks need a privilege Windows does not always grant; the case runs
/// only where one can be made.
#[test]
fn followed_symlinks_walk_their_target() {
    let _g = cwd_lock();
    let s = Scratch::new("follow");
    corpus(&s);
    if symlink_dir(s.path().join("vendor"), s.path().join("vlink")).is_err() {
        return;
    }
    if symlink_file(s.path().join("plain.txt"), s.path().join("plink.txt")).is_err() {
        return;
    }
    // a link back to the walk root: following it would never terminate
    if symlink_dir(s.path(), s.path().join("a/loop")).is_err() {
        return;
    }
    hermetic(s.path());
    std::env::set_current_dir(s.path()).expect("cd");
    let plain = rgx(s.path(), &["."], &Opts::default());
    let followed = rgx(
        s.path(),
        &["."],
        &Opts {
            follow: true,
            ..Default::default()
        },
    );
    assert!(
        !plain.contains("./vlink/lib.c") && plain.contains("./vendor/lib.c"),
        "without --follow a directory symlink is listed as a link, not walked"
    );
    assert!(
        followed.contains("./vlink/lib.c") && followed.contains("./plink.txt"),
        "--follow walks into the link: {:?}",
        followed.iter().collect::<Vec<_>>()
    );
    check(&s, &["."], &Opts::default());
    check(
        &s,
        &["."],
        &Opts {
            follow: true,
            ..Default::default()
        },
    );
}

/// Windows hides a file whose attribute says so, not only one whose name
/// starts with a dot. The attribute follows the hidden flag: the default
/// reads it, and `--no-hidden` skips it.
#[test]
#[cfg(windows)]
fn the_windows_hidden_attribute_follows_the_hidden_flag() {
    let _g = cwd_lock();
    let s = Scratch::new("hattr");
    corpus(&s);
    s.file("attributed.txt", "hidden by attribute\n");
    if !std::process::Command::new("attrib")
        .arg("+h")
        .arg(s.path().join("attributed.txt"))
        .stdout(std::process::Stdio::null())
        .status()
        .is_ok_and(|st| st.success())
    {
        return;
    }
    check(&s, &["."], &Opts::default());
    check(
        &s,
        &["."],
        &Opts {
            no_hidden: true,
            ..Default::default()
        },
    );
    assert!(
        !oracle(
            &["."],
            &Opts {
                no_hidden: true,
                ..Default::default()
            }
        )
        .contains("./attributed.txt"),
        "the oracle should hide an attributed file"
    );
}

#[test]
fn gitignore_without_a_repository_is_inert() {
    let _g = cwd_lock();
    let s = Scratch::new("nogit");
    corpus(&s);
    std::fs::remove_dir_all(s.path().join(".git")).expect("rm .git");
    check(&s, &["."], &Opts::default());
}

#[test]
fn a_file_as_a_walk_root_is_never_filtered() {
    let _g = cwd_lock();
    let s = Scratch::new("fileroot");
    corpus(&s);
    // a root named explicitly is not subject to the ignore rules
    check(&s, &["a.log"], &Opts::default());
    check(&s, &[".hidden_file"], &Opts::default());
    check(&s, &["excluded.txt"], &Opts::default());
}

#[test]
fn an_override_outranks_the_ignore_files() {
    let _g = cwd_lock();
    let s = Scratch::new("precedence");
    s.dir(".git/info");
    s.file(".git/HEAD", "ref: refs/heads/main\n");
    s.file(".gitignore", "hidden.txt\nexcluded.txt\n");
    s.file(".git/info/exclude", "fromexclude.txt\n");
    for f in ["kept", "hidden", "excluded", "fromexclude", ".dot"] {
        s.file(&format!("{f}.txt"), "x\n");
    }
    // Three of the five are out on their own: `hidden` by `.gitignore`,
    // `excluded` by `.gitignore`, `fromexclude` by `.git/info/exclude`.
    // `.dot` is a hidden file and `.gitignore` is one too, and the hidden
    // files are read by default.
    assert_eq!(
        rgx_env(s.path(), &["."], &Opts::default()),
        BTreeSet::from([
            "./.dot.txt".to_string(),
            "./.gitignore".to_string(),
            "./kept.txt".to_string(),
        ]),
    );
    // `-g '*.txt'` names all five, and a name is the last word on every count.
    assert_eq!(
        rgx_env(
            s.path(),
            &["."],
            &Opts {
                globs: vec!["*.txt".to_string()],
                ..Default::default()
            },
        ),
        BTreeSet::from([
            "./.dot.txt".to_string(),
            "./excluded.txt".to_string(),
            "./fromexclude.txt".to_string(),
            "./hidden.txt".to_string(),
            "./kept.txt".to_string(),
        ]),
    );
    // And the other direction: `!` in a glob does not get a vote either. The
    // four `.txt` files stay out on their own, so the one file left is the
    // `.gitignore` -- a hidden file, and the hidden files are read.
    assert_eq!(
        rgx_env(
            s.path(),
            &["."],
            &Opts {
                globs: vec!["!*.txt".to_string()],
                ..Default::default()
            },
        ),
        BTreeSet::from(["./.gitignore".to_string()]),
    );
}

fn rgx_env(dir: &Path, roots: &[&str], o: &Opts) -> BTreeSet<String> {
    std::env::set_current_dir(dir).expect("cd");
    rgx(dir, roots, o)
}

// ---------------------------------------------------------------------------
// randomized corpora
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*, so a failing seed reproduces exactly
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }
}

fn under(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

const NAMES: &[&str] = &[
    "a",
    "b",
    "src",
    "build",
    "node_modules",
    "docs",
    "deep",
    "secret",
    "important.txt",
    "x.log",
    "keep.log",
    "a.tmp",
    "keep.tmp",
    ".hidden",
    "rooted.txt",
    "lib.c",
    "spaced name.txt",
    "UP.TXT",
    "a-b.txt",
    "1.txt",
    "a.b.c",
    "z",
    "n2",
    "vendor",
    "test.rs",
];

const PATTERNS: &[&str] = &[
    "*.log",
    "!important.txt",
    "build/",
    "build",
    "/rooted.txt",
    "docs/*.tmp",
    "**/deep",
    "a/**",
    "**/n*",
    "?.txt",
    "[ab].txt",
    "[!a]*.log",
    "*.txt",
    "!*.tmp",
    "secret/",
    "spaced name.txt",
    "UP.TXT",
    "a.b.*",
    "trailing   ",
    "# comment",
    "",
    "no_such_rule",
    "**/*",
    "*/x.log",
    "z/",
];

const IGNORE_PATTERNS: &[&str] = &["*.tmp", "!keep.tmp", "deep/", "*.log", "!x.log"];

/// A tree of random depth with ignore files at random levels, then the same
/// two walks over it. The seed is fixed so a failure is reproducible.
fn random_corpus(seed: u64, rounds: usize) {
    let _g = cwd_lock();
    let s = Scratch::new(&format!("rand{seed}"));
    s.dir(".git");
    let mut rng = Rng(seed);
    let mut dirs = vec![String::new()];
    for _ in 0..14 {
        let parent = dirs[rng.below(dirs.len())].clone();
        let name = rng.pick(NAMES);
        let d = under(&parent, name);
        if dirs.contains(&d) {
            continue;
        }
        s.dir(&d);
        dirs.push(d);
    }
    for i in 0..70 {
        let parent = dirs[rng.below(dirs.len())].clone();
        let name = rng.pick(NAMES);
        let _ = s.try_file(&under(&parent, name), &format!("body {i}\n"));
    }
    for d in dirs.clone() {
        if rng.below(3) == 0 {
            let lines: Vec<&str> = (0..1 + rng.below(3)).map(|_| *rng.pick(PATTERNS)).collect();
            let _ = s.try_file(&under(&d, ".gitignore"), &lines.join("\n"));
        }
        if rng.below(4) == 0 {
            let lines: Vec<&str> = (0..1 + rng.below(2))
                .map(|_| *rng.pick(IGNORE_PATTERNS))
                .collect();
            let _ = s.try_file(&under(&d, ".ignore"), &lines.join("\n"));
        }
    }
    let _ = s.try_file(".git/info/exclude", "*.rs\n!important.txt\n");
    hermetic(s.path());
    for round in 0..rounds {
        let o = Opts {
            no_hidden: round % 2 == 1,
            no_ignore: round % 5 == 4,
            follow: false,
            max_depth: if round % 3 == 0 {
                Some(1 + round % 3)
            } else {
                None
            },
            globs: match round % 4 {
                1 => vec!["*.txt".to_string()],
                2 => vec!["*.log".to_string(), "!a/**".to_string()],
                3 => vec!["!**/*.log".to_string()],
                _ => vec![],
            },
        };
        let roots: &[&str] = match round % 4 {
            0 => &["."],
            1 => &["a"],
            2 => &["docs"],
            _ => &["a", "docs", "vendor"],
        };
        std::env::set_current_dir(s.path()).expect("cd");
        let a = rgx(s.path(), roots, &o);
        let b = oracle(roots, &o);
        assert!(
            a == b,
            "seed {seed} round {round} roots {roots:?} in {}
{}",
            s.path().display(),
            diff(&a, &b)
        );
    }
}

#[test]
fn randomized_corpora_agree() {
    for seed in (0..24u64).map(|i| 0x5EED_0000 + i * 0x9E37_79B9) {
        random_corpus(seed, 6);
    }
}
