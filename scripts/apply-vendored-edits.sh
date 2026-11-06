#!/usr/bin/env bash
# apply-vendored-edits.sh -- re-apply the copy-time transforms to a vendored
# rgx-core module.
#
# The Linux counterpart of scripts/apply-vendored-edits.ps1.
#
# Why this exists: upstream is the source of truth, so a fix lands there and
# the file is re-copied. Re-doing the copy-time edits by hand each time is
# how they get forgotten, and a forgotten path is a build error at best.
# This makes the transform mechanical and reviewable.
#
# The permitted difference between an upstream source and its rgx copy is
# exactly what this script applies, and nothing else:
#   1. the `std::` / `alloc::` paths (see the note below)
#   2. upstream module paths -> rgx-core sibling paths
# Anything else in the copy is drift, and `scripts/check-drift.sh` is what
# should catch it -- so this script must not *introduce* drift.
#
# --files takes a comma-separated list, not an array: a shell hands
# arguments to a script as plain strings, so a list with commas in it
# would arrive as one argument.
#
# The transform is applied by perl, not by sed: half of the table is a
# multi-line literal and the other half is a regex with a capture group,
# and perl does both without the shell having to quote a backslash.
#
# TWO THINGS THE WINDOWS SCRIPT GETS WRONG FOR THE CURRENT TREE, both
# fixed here, and both fixed in the .ps1 as well:
#
#   1. `rgx-core` is `#![no_std] + alloc` today, not a std crate. The
#      `alloc:: -> std::` direction of the old table would rewrite a
#      no_std crate into one that does not compile. That transform is
#      therefore off unless --alloc-to-std is given, and the flag says
#      plainly that it is for the case where the copy really is a std
#      crate.
#   2. the `mod nfa;` -> `pub mod nfa;` entries were plain string
#      replacements, and "pub mod nfa;" contains "mod nfa;" -- so running
#      the script twice turned it into "pub pub mod nfa;". The header of
#      the Windows script promises that applying it twice is a no-op, and
#      that promise is now kept: the replacements are anchored at the
#      start of the line.
#
# Usage:
#   bash scripts/apply-vendored-edits.sh --files a.rs,b.rs [--whatif]
#   bash scripts/apply-vendored-edits.sh --files a.rs --alloc-to-std
set -u

files=""
whatif=0
alloc_to_std=0

while [ $# -gt 0 ]; do
    case "$1" in
        --files) files=${2:-}; shift 2 ;;
        --whatif) whatif=1; shift ;;
        --alloc-to-std) alloc_to_std=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ -n "$files" ] || { echo "--files is required" >&2; exit 2; }

# perl does the substitution: half the table is a multi-line literal and
# the other half is a regex with a capture group, and perl does both
# without the shell having to quote a backslash. It is not in every
# minimal container, so the dependency is checked rather than discovered
# as a "command not found" halfway through a rewrite.
command -v perl > /dev/null 2>&1 || {
    echo "perl not found; it is what applies the transforms" >&2
    echo "  debian/ubuntu: apt-get install perl" >&2
    echo "  fedora/rhel:   dnf install perl" >&2
    echo "  alpine:        apk add perl" >&2
    exit 1
}

# The transform table lives in perl, because perl is what applies it.
perl - --whatif-flag "$whatif" --alloc-to-std-flag "$alloc_to_std" --files "$files" <<'PERL'
use strict;
use warnings;

my $whatif = 0;
my $alloc_to_std = 0;
my @files;

while (@ARGV) {
    my $arg = shift @ARGV;
    if    ($arg eq '--whatif-flag')      { $whatif = shift @ARGV; }
    elsif ($arg eq '--alloc-to-std-flag') { $alloc_to_std = shift @ARGV; }
    elsif ($arg eq '--files')            { push @files, split /,/, shift @ARGV; }
}

# rgx-only divergences from the upstream source, applied after the
# mechanical rewrites. These are not formatting and not the std/alloc
# rewrite; they are places where the two projects must genuinely differ,
# and doing them here rather than by hand is what stops a re-copy from
# silently reverting them.
#
# The module tree of the upstream is private (`mod nfa;`, `pub(crate) fn
# parse`), and the rgx copy is flat in `rgx-core/src`, where sibling
# modules are reached directly. These lift the visibility the flattening
# needs; without them the copies do not compile.
#
# The entries are anchored at the start of the line so that a second run
# of this script is a no-op: "pub mod nfa;" contains "mod nfa;".
my @rgx_only = (
    [qr/^mod nfa;/m,      'pub mod nfa;'],
    [qr/^mod vm;/m,       'pub mod vm;'],
    [qr/^mod regex;/m,    'pub mod regex;'],
    [qr/^mod syntax;/m,   'pub mod syntax;'],
    [qr/^mod searcher;/m, 'pub mod searcher;'],
    [qr/^pub\(crate\) /m, 'pub '],
);

# The braced import cannot live in the table above: the `use` branch runs
# a regex escape over the pattern, which escapes the braces a second time
# and so never matches. A literal replacement is the right tool -- and it
# is an `alloc::` -> `std::` rewrite like the rest, so it is behind the
# same flag.
my @rgx_only_literals = (
    ['use alloc::string::{String, ToString};', 'use std::string::String;'],
);

# Feature dispatch: upstream gates the AVX2 path at compile time (it is a
# library, and must not run AVX2 on a CPU without it). rgx ships one
# binary to arbitrary machines, so the copy dispatches at runtime. Both
# this and the test guards below are re-copy-safe: applying the script
# twice is a no-op.
my $avx2_from = <<'AVX2_FROM';
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        // SAFETY: AVX2 is a compile-time guarantee of this build, which is
        // the precondition `simd_candidates` documents.
        return unsafe { simd_candidates(mask, hay) };
    }
    #[allow(unreachable_code)]
    scalar_candidates(mask, hay)
AVX2_FROM

my $avx2_to = <<'AVX2_TO';
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: guarded by the runtime feature check above, which is
            // is `simd_candidates`'s documented precondition.
            return unsafe { simd_candidates(mask, hay) };
        }
    }
    scalar_candidates(mask, hay)
AVX2_TO

my $cfg_from = "#[cfg(all(target_arch = \"x86_64\", target_feature = \"avx2\"))]\n    #[test]";
my $cfg_to   = "#[cfg(target_arch = \"x86_64\")]\n    #[test]";

# The `use`-anchored literals: a bare token to swap, matched only in a
# `use` position, and a pre-anchored pattern for the non-`use` forms. A
# doc comment or string literal that merely *mentions* `alloc::vec` is
# quoting the source, and rewriting it would make the provenance header
# lie about what the copy changed.
#
# These are the `alloc::` -> `std::` rewrites, and they are off unless
# --alloc-to-std is given: `rgx-core` is `#![no_std] + alloc`, and a
# crate that cannot name `std` does not compile with `std::` in it.
my @alloc_to_std = (
    ['use',  'alloc::string::String;',     'std::string::String;'],
    ['use',  'alloc::string::ToString;',    'std::string::ToString;'],
    ['use',  'alloc::vec::Vec;',            'std::vec::Vec;'],
    ['use',  'alloc::vec;',                 'std::vec;'],
    ['use',  'alloc::boxed::Box;',          'std::boxed::Box;'],
    ['use',  'alloc::collections::BTreeMap','std::collections::BTreeMap'],
    ['re',   '\balloc::boxed::',            'std::boxed::'],
    ['re',   '^(\s*use\s+)alloc::format;',  'std::format;', 1],
    ['re',   '\balloc::vec!',               'vec!'],
    ['re',   '\balloc::format!',            'format!'],
);

# upstream module paths -> rgx-core sibling paths. The rgx copies are
# FLATTENED into rgx-core/src, so a `crate::b02::rgx::x` or
# `super::b02::rgx::x` collapses to the crate root or to `super::`.
#
# The third field says what the replacement is: "plain" for text, "group1"
# for text that follows the first captured group.
my @path_rewrites = (
    ['^(\s*(?:pub )?use\s+[A-Za-z_][A-Za-z0-9_]*)crate::b02::rgx::', 'group1', 'crate::'],
    ['^(\s*(?:pub )?use\s+super::)b02::rgx::',                        'group1', ''],
    ['^(\s*(?:pub )?use\s+super::super::)b02::rgx::',                'group1', ''],
    ['crate::b02::rgx::',                                            'plain',  'crate::'],
);

# The runtime guard a SIMD test needs once the cfg gate is widened. It
# has to be injected only where it is absent, or a second run of this
# script stacks a second guard into the same function and the file stops
# being idempotent -- which is the property that makes the script safe to
# re-run at all.
my @test_guards = (
    'simd_matches_scalar_on_random_input',
    'simd_matches_scalar_on_document_shaped_input',
    'a_uniform_haystack_agrees',
    'a_candidate_in_the_high_lane_is_not_lost',
);

# A literal becomes a pattern that matches either line ending, so the
# multi-line entries work on a CRLF checkout as well as on an LF one.
sub lit_re {
    my ($s) = @_;
    my @parts = split /\n/, $s, -1;
    return join '\r?\n', map { quotemeta($_) } @parts;
}

# The file is read whole, normalised to LF, and written back with the
# line endings it had: a rewrite that changes the endings of every line
# in the file is a rewrite nobody reviews.
sub transform {
    my ($c) = @_;
    my $crlf = ($c =~ /\r\n/) ? 1 : 0;
    $c =~ s/\r\n/\n/g;

    if ($alloc_to_std) {
        for my $t (@alloc_to_std) {
            my ($kind, $from, $to, $group) = @$t;
            if ($kind eq 'use') {
                $c =~ s{^(\s*(?:pub )?use\s+)\Q$from\E}{ $1 . $to }gme;
            } elsif ($group) {
                $c =~ s{$from}{ $1 . $to }gme;
            } else {
                $c =~ s{$from}{ $to }gme;
            }
        }
    }

    for my $t (@path_rewrites) {
        my ($from, $kind, $to) = @$t;
        if ($kind eq 'group1') {
            $c =~ s{$from}{ $1 . $to }gme;
        } else {
            $c =~ s{$from}{ $to }gme;
        }
    }

    for my $t (@rgx_only) {
        my ($re, $to) = @$t;
        $c =~ s{$re}{ $to }gme;
    }

    if ($alloc_to_std) {
        for my $t (@rgx_only_literals) {
            my ($from, $to) = @$t;
            my $re = lit_re($from);
            $c =~ s{$re}{ $to }gse;
        }
    }

    my $re_avx2 = lit_re($avx2_from);
    $c =~ s{$re_avx2}{ $avx2_to }gse;

    my $re_cfg = lit_re($cfg_from);
    $c =~ s{$re_cfg}{ $cfg_to }gse;

    for my $name (@test_guards) {
        my $sig = "    fn $name() {";
        my $guard = '        if !std::arch::is_x86_feature_detected!("avx2") {';
        next unless index($c, $sig) >= 0;
        next if index($c, $sig . "\n" . $guard) >= 0;
        my $add = $sig . "\n" . $guard . "\n" . "            return;" . "\n" . "        }";
        $c =~ s{\Q$sig\E}{ $add }ge;
    }

    $c =~ s/\n/\r\n/g if $crlf;
    return $c;
}

my $changed = 0;
for my $f (@files) {
    if (!-e $f) {
        print STDERR "no such file: $f\n";
        next;
    }
    # Read as UTF-8 and write as UTF-8 (no BOM). A byte-oriented module
    # carries test vectors, and a byte that is not valid UTF-8 in one is
    # exactly the kind of thing these files hold.
    open my $in, '<:raw', $f or do { print STDERR "cannot read $f: $!\n"; next };
    local $/;
    my $c = <$in>;
    close $in;
    utf8::decode($c);

    my $before = $c;
    $c = transform($c);

    if ($c ne $before) {
        $changed++;
        if ($whatif) {
            print "would rewrite $f\n";
        } else {
            my $out = $c;
            utf8::encode($out);
            open my $fh, '>:raw', $f or do { print STDERR "cannot write $f: $!\n"; next };
            print $fh $out;
            close $fh;
            print "rewrote $f\n";
        }
    } else {
        print "unchanged $f\n";
    }
}
print "$changed file(s) differ from the upstream source's shape\n";
PERL
