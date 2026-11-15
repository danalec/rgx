# Formula

## Overview

`Formula/` holds the Homebrew formula that installs the project on macOS. The
formula is `rgx.rb`, a single Ruby file that `brew` reads: it names the release
archive to download for each architecture, the digest of that archive, and the
binary to install out of it.

The name is deliberate. The crates.io package cannot be called `rgx` — that
name is taken by an unrelated project there — so it ships as `rgx-search`,
while the binary itself is `rgx` on every registry. The Homebrew package took
the free name, which is the one this formula carries.

The formula is *staged*: the URLs, the digests and the `version` are release
data, rewritten by `scripts/push-github.sh` when it publishes the macOS
archives — a rewrite that does not move is a refusal and not a warning
(`rgx.rb`, header comment). `scripts/publish-homebrew.sh` is what opens the
pull request that carries the rewritten formula into homebrew-core.

## Interface

- `class Rgx < Formula` — the formula itself.
  - `desc "Search inside everything: PDFs, Office documents, archives, 3D models, checkpoints, databases, e-mail"`, `homepage "https://github.com/danalec/rgx"`, `license "Apache-2.0"`, `version "0.1.10"`.
  - `on_arm` — `url "https://github.com/danalec/rgx/releases/download/rgx-v0.1.10/rgx-v0.1.10-aarch64-macos.tar.gz"` with `sha256 "14484e2ed48dd02434a1bd2bf882f95045b6c19a94763c5ff6bc61a753807b09"`.
  - `on_intel` — `url "…/rgx-v0.1.10-x86_64-macos.tar.gz"` with `sha256 "95966d2ce9911c04bc0165b74bb3593b290862cd7017a91d82781f824c40bbc1"`.
  - `def install` — finds the binary with `Dir["rgx-v*/rgx"].first || Dir["rgx"].first`, raises `"no rgx binary in the archive"` when there is none, and installs it as `rgx` with `bin.install binary => "rgx"`.
  - `test do` — writes `invoice.txt` into `testpath`, runs `#{bin}/rgx --count --no-filename invoice #{testpath}` and asserts the output is `1`.

## Invariants

- The `sha256` of each URL must be the digest of the archive that URL names. A formula that pins the digest of an artifact nobody published throws `SHA256 mismatch` at every user, on their machine and not here.
- The URL, the digest and the `version` are release data and are rewritten by the release flow (`scripts/push-github.sh`), never by hand.
- The formula must fail loudly when the archive holds no binary: it raises rather than installing nothing.
- The installed executable is named `rgx`, whatever the archive's directory layout is.
- The formula does not depend on the extraction keeping the archive's top-level directory: the binary is found wherever it is.
- `brew audit --new --formula` and `brew readall` are the checks that run on the pull request this formula opens, and both need a Mac — the formula does not claim the pull request is the last step.

## Side Effects

- At install time: `brew` downloads and verifies the archive, and the `install` method writes the binary into the Homebrew prefix.
- At test time: the `test` block creates `invoice.txt` under the formula's `testpath` and spawns the installed binary against it.
- In the repository: the file is inert. Nothing in the tree reads it except `brew`, `scripts/push-github.sh`, which rewrites its url, digest and version in place and stages it, and `scripts/publish-homebrew.sh`, which copies it into a homebrew-core branch with the rewritten url, digest and version.

## Verification

- Run: `cargo test --release --locked --workspace`
- The formula's own check: `brew audit --new --formula Formula/rgx.rb` and `brew readall Formula/rgx.rb`, both of which need a Mac.
