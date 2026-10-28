# Re-applies the copy-time transforms to a vendored rgx-core module.
#
# Usage:
#   pwsh -File scripts/apply-vendored-edits.ps1 -Files a.rs,b.rs [-WhatIf]
#
# Why this exists: upstream is the source of truth, so a fix lands there and the
# file is re-copied. Re-doing the copy-time edits by hand each time is how
# they get forgotten, and a forgotten `alloc::` path is a build error at
# best. This makes the transform mechanical and reviewable.
#
# The permitted difference between a upstream source and its rgx copy is exactly
# what this script applies, and nothing else:
#   1. `alloc::` -> `std::` (rgx-core is always std; upstream is no_std + alloc)
#   2. upstream module paths -> rgx-core sibling paths
# Anything else in the copy is drift, and `scripts/check-drift.ps1` is what
# should catch it -- so this script must not *introduce* drift.
#
# -Files takes a comma-separated list, not an array: `pwsh -File` hands
# arguments to a script as plain strings, so `[string[]]` would receive one
# argument containing the commas.
#
# -AllocToStd enables the `alloc::` -> `std::` rewrites, which are OFF by
# default: `rgx-core` is `#![no_std] + alloc` today, and running them on
# it would rewrite a crate that cannot name `std` into one that does not
# compile. The flag is for the case where the copy really is a std crate.
param(
    [Parameter(Mandatory = $true)][string]$Files,
    [switch]$WhatIf,
    [switch]$AllocToStd
)

# rgx-only divergences from the upstream source, applied after the mechanical
# rewrites. These are not formatting and not `alloc::` -> `std::`; they are
# places where the two projects must genuinely differ, and doing them here
# rather than by hand is what stops a re-copy from silently reverting them.
#
# 1. Feature dispatch. upstream gates SIMD at compile time (`target_feature`),
#    matching b02/simd/mod.rs: a library must not run AVX2 on a CPU without
#    it. rgx ships one binary to arbitrary machines, so it dispatches at
#    runtime the way crates/rgx-core/src/memchr.rs does.
$rgxOnly = @(
    # The upstream module tree is private (`mod nfa;`, `pub(crate) fn parse`),
    # and the rgx copy is flat in `rgx-core/src`, where sibling modules are
    # reached directly. These two lift the visibility the flattening needs;
    # without them the copies do not compile.
    #
    # The patterns are anchored at the start of the line: "pub mod nfa;"
    # contains "mod nfa;", so a plain string replacement would turn it
    # into "pub pub mod nfa;" on the second run, and the script promises
    # that running it twice is a no-op.
    @{ kind = 're';  from = '(?m)^mod nfa;';      to = 'pub mod nfa;' }
    @{ kind = 're';  from = '(?m)^mod vm;';       to = 'pub mod vm;' }
    @{ kind = 're';  from = '(?m)^mod regex;';    to = 'pub mod regex;' }
    @{ kind = 're';  from = '(?m)^mod syntax;';   to = 'pub mod syntax;' }
    @{ kind = 're';  from = '(?m)^mod searcher;'; to = 'pub mod searcher;' }
    @{ kind = 'lit'; from = 'pub(crate) ';       to = 'pub ' }
    # Feature dispatch: upstream gates the AVX2 path at compile time (it is a
    # library, and must not run AVX2 on a CPU without it). rgx ships one
    # binary to arbitrary machines, so the copy dispatches at runtime. Both
    # this and the test guards below are re-copy-safe: applying the script
    # twice is a no-op.
    @{
        kind = 'lit'
        from = '    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]' + "`n" +
               '    {' + "`n" +
               '        // SAFETY: AVX2 is a compile-time guarantee of this build, which is' + "`n" +
               '        // the precondition `simd_candidates` documents.' + "`n" +
               '        return unsafe { simd_candidates(mask, hay) };' + "`n" +
               '    }' + "`n" +
               '    #[allow(unreachable_code)]' + "`n" +
               '    scalar_candidates(mask, hay)'
        to   = '    #[cfg(target_arch = "x86_64")]' + "`n" +
               '    {' + "`n" +
               '        if std::arch::is_x86_feature_detected!("avx2") {' + "`n" +
               '            // SAFETY: guarded by the runtime feature check above, which' + "`n" +
               '            // is `simd_candidates`''s documented precondition.' + "`n" +
               '            return unsafe { simd_candidates(mask, hay) };' + "`n" +
               '        }' + "`n" +
               '    }' + "`n" +
               '    scalar_candidates(mask, hay)'
    }
    @{
        kind = 'lit'
        from = '#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]' + "`n" + '    #[test]'
        to   = '#[cfg(target_arch = "x86_64")]' + "`n" + '    #[test]'
    }
)
$rgxTestGuards = @(
    'simd_matches_scalar_on_random_input',
    'simd_matches_scalar_on_document_shaped_input',
    'a_uniform_haystack_agrees',
    'a_candidate_in_the_high_lane_is_not_lost'
)

# Apply-Transform <text> <entry>
#
# The three shapes cannot be told apart by looking at the pattern -- a
# bare token and a path look alike -- so the table says which one it is.
#
#   use  a bare token, matched only in a `use` position. A doc comment or
#        a string literal that merely *mentions* `alloc::vec` is quoting
#        the source, and rewriting it would make the provenance header
#        lie about what the copy changed.
#   re   a regex, written out in full.
#   lit  a literal, replaced wherever it appears.
function Apply-Transform([string]$text, $entry) {
    switch ($entry.kind) {
        're'  { return ($text -replace $entry.from, $entry.to) }
        'lit' { return $text.Replace($entry.from, $entry.to) }
        'use' {
            return ($text -replace "(?m)^(\s*(?:pub )?use\s+)$([regex]::Escape($entry.from))", "`$1$($entry.to)")
        }
    }
    return $text
}

# The `alloc::` -> `std::` rewrites, applied only with -AllocToStd.
#
# `rgx-core` is `#![no_std] + alloc` today, so a crate that cannot name
# `std` is what these files are: running the rewrites on them would
# produce a crate that does not compile. The flag is for the case where
# the copy really is a std crate.
#
# Every entry carries its kind, because the three shapes cannot be told
# apart by looking at the pattern:
#
#   use  a bare token, matched only in a `use` position. A doc comment or
#        a string literal that merely *mentions* `alloc::vec` is quoting
#        the source, and rewriting it would make the provenance header
#        lie about what the copy changed.
#   re   a regex, written out in full.
#   lit  a literal, replaced wherever it appears.
$allocTransforms = @(
    @{ kind = 'use'; from = 'alloc::string::String;';        to = 'std::string::String;' }
    @{ kind = 'use'; from = 'alloc::string::ToString;';     to = 'std::string::ToString;' }
    @{ kind = 'use'; from = 'alloc::vec::Vec;';              to = 'std::vec::Vec;' }
    @{ kind = 'use'; from = 'alloc::vec;';                   to = 'std::vec;' }
    @{ kind = 'use'; from = 'alloc::boxed::Box;';            to = 'std::boxed::Box;' }
    @{ kind = 'use'; from = 'alloc::collections::BTreeMap';  to = 'std::collections::BTreeMap' }
    # `Box` also appears inline in type position (`alloc::boxed::Box<Ast>`),
    # where the `use`-anchored form above does not reach.
    @{ kind = 're';  from = '\balloc::boxed::';              to = 'std::boxed::' }
    # `format` is also `use`d as a macro, where the macro path is not a
    # `use` line in the way the other forms are.
    @{ kind = 're';  from = '(?m)^(\s*use\s+)alloc::format;'; to = '$1std::format;' }
    # These two are not `use` lines, so they get their own anchored forms.
    @{ kind = 're';  from = '\balloc::vec!';                 to = 'vec!' }
    @{ kind = 're';  from = '\balloc::format!';              to = 'format!' }
    # The braced import. This cannot be a `use` entry: the pattern would
    # anchor on `use` and then look for a second `use` in the token, and
    # it cannot be a regex either, because the braces would be escaped a
    # second time and never match. A literal is the right tool.
    @{ kind = 'lit'; from = 'use alloc::string::{String, ToString};'; to = 'use std::string::String;' }
)

$transforms = @(
    # upstream module paths -> rgx-core sibling paths. The rgx copies are
    # FLATTENED into rgx-core/src, so a `crate::b02::rgx::x` or
    # `super::b02::rgx::x` collapses to the crate root or to `super::`.
    @{ kind = 're';  from = '(?m)^(\s*(?:pub )?use\s+[A-Za-z_][A-Za-z0-9_]*)crate::b02::rgx::'; to = '$1crate::' }
    @{ kind = 're';  from = '(?m)^(\s*(?:pub )?use\s+super::)b02::rgx::';             to = '$1' }
    @{ kind = 're';  from = '(?m)^(\s*(?:pub )?use\s+super::super::)b02::rgx::';     to = '$1' }
    # The same path outside a `use` (test bodies, inline references).
    @{ kind = 'lit'; from = 'crate::b02::rgx::';                                     to = 'crate::' }
    # The upstream module tree is private (`mod nfa;`, `pub(crate) fn parse`),
    # and the rgx copy is flat in `rgx-core/src`, where sibling modules are
    # reached directly. These two lift the visibility the flattening needs;
    # without them the copies do not compile.
    @{ kind = 're';  from = '(?m)^mod (nfa|vm|regex|syntax|searcher);';  to = 'pub mod $1;' }
    @{ kind = 'lit'; from = 'pub(crate) ';                             to = 'pub ' }
)

$changed = 0
foreach ($f in $Files.Split(',')) {
    if (-not (Test-Path -LiteralPath $f)) {
        Write-Error "no such file: $f"
        continue
    }
    # Read as UTF-8 and write as UTF-8 (no BOM). The default encoding under
    # Windows PowerShell 5.1 is ANSI, which would mangle any non-ASCII byte
    # in a byte-oriented module -- and a test vector of 0xC3 0xA9 is exactly
    # the kind of thing these files carry.
    $c = [IO.File]::ReadAllText($f, [Text.UTF8Encoding]::new($false))
    $before = $c
    if ($AllocToStd) {
        foreach ($t in $allocTransforms) {
            $c = Apply-Transform $c $t
        }
    }
    foreach ($t in $transforms) {
        $c = Apply-Transform $c $t
    }
    foreach ($t in $rgxOnly) {
        $c = Apply-Transform $c $t
    }
    # The runtime guard a SIMD test needs once the cfg gate is widened. It
    # has to be injected only where it is absent, or a second run of this
    # script stacks a second guard into the same function and the file stops
    # being idempotent -- which is the property that makes the script safe to
    # re-run at all.
    foreach ($name in $rgxTestGuards) {
        $sig = "    fn $name() {"
        $guard = '        if !std::arch::is_x86_feature_detected!("avx2") {'
        if ($c.Contains($sig)) {
            $after = $sig + "`n" + $guard
            if (-not $c.Contains($after)) {
                $c = $c.Replace($sig, $sig + "`n" +
                    $guard + "`n" +
                    '            return;' + "`n" +
                    '        }')
            }
        }
    }
    if ($c -ne $before) {
        $changed++
        if ($WhatIf) {
            Write-Host "would rewrite $f"
        } else {
            [IO.File]::WriteAllText($f, $c, [Text.UTF8Encoding]::new($false))
            Write-Host "rewrote $f"
        }
    } else {
        Write-Host "unchanged $f"
    }
}
Write-Host "$changed file(s) differ from the upstream source's shape"
