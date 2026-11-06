// SPDX-License-Identifier: Apache-2.0

//! Independent reimplementation of memmap2-rs advice enums.

#![allow(clippy::upper_case_acronyms)]

#[cfg(unix)]
mod imp {
    // `libc` exposes these seven on Linux alone: MADV_REMOVE and the
    // fork/merge/hugepage calls are its own. Not "unix" -- Darwin has
    // MADV_FREE and not these, and the BSDs stop at MADV_PROTECT. So the
    // numbers come from Linux's `bits/mman-linux.h` everywhere else.
    //
    // The enum keeps one shape on every platform so callers need no cfg of
    // their own. What must vary is what happens when one of these is passed
    // to a kernel that has no such advice: `advise` turns it down rather
    // than handing over a number the kernel would read as something else.
    // The refusal is `platform::refuse_unavailable`, and the rule it
    // applies is `is_available`, below.
    //
    // A number the kernel does not know is not an error, it is an
    // instruction: FreeBSD's MADV_PROTECT is 10 and Linux's MADV_DONTFORK
    // is 10 too, so handing 10 to FreeBSD would change the protection of
    // the mapping instead of refusing the advice.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use libc::{
        MADV_DOFORK, MADV_DONTFORK, MADV_HUGEPAGE, MADV_MERGEABLE, MADV_NOHUGEPAGE, MADV_REMOVE,
        MADV_UNMERGEABLE,
    };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    mod missing {
        pub const MADV_REMOVE: i32 = 9;
        pub const MADV_DONTFORK: i32 = 10;
        pub const MADV_DOFORK: i32 = 11;
        pub const MADV_MERGEABLE: i32 = 12;
        pub const MADV_UNMERGEABLE: i32 = 13;
        pub const MADV_HUGEPAGE: i32 = 14;
        pub const MADV_NOHUGEPAGE: i32 = 15;
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    use missing::{
        MADV_DOFORK, MADV_DONTFORK, MADV_HUGEPAGE, MADV_MERGEABLE, MADV_NOHUGEPAGE, MADV_REMOVE,
        MADV_UNMERGEABLE,
    };

    #[repr(i32)]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum Advice {
        Normal = libc::MADV_NORMAL as i32,
        Random = libc::MADV_RANDOM as i32,
        Sequential = libc::MADV_SEQUENTIAL as i32,
        WillNeed = libc::MADV_WILLNEED as i32,
        DontNeed = libc::MADV_DONTNEED as i32,
        HugePage = MADV_HUGEPAGE as i32,
        NoHugePage = MADV_NOHUGEPAGE as i32,
        DontFork = MADV_DONTFORK as i32,
        DoFork = MADV_DOFORK as i32,
        Mergeable = MADV_MERGEABLE as i32,
        Unmergeable = MADV_UNMERGEABLE as i32,
    }

    #[repr(i32)]
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub enum UncheckedAdvice {
        DontNeed = libc::MADV_DONTNEED as i32,
        Free = libc::MADV_FREE as i32,
        Remove = MADV_REMOVE as i32,
    }

    /// The seven advices that only Linux has, by the numbers Linux gives
    /// them: `MADV_REMOVE` is 9, and the six that follow it are 10 to 15.
    ///
    /// The set is the seven Linux numbers and not a range, because a range
    /// wide enough to hold them would also hold a number a BSD kernel has
    /// an instruction for.
    pub const LINUX_ONLY: [i32; 7] = [
        MADV_REMOVE as i32,
        MADV_DONTFORK as i32,
        MADV_DOFORK as i32,
        MADV_MERGEABLE as i32,
        MADV_UNMERGEABLE as i32,
        MADV_HUGEPAGE as i32,
        MADV_NOHUGEPAGE as i32,
    ];

    /// Whether this number is one of the seven that only Linux has.
    pub fn is_linux_only(advice: i32) -> bool {
        LINUX_ONLY.contains(&advice)
    }

    /// Whether this platform has this advice.
    ///
    /// Linux has all seven. The BSDs have the five that every unix kernel
    /// has, and the seven are numbers Linux owns: a number a kernel does
    /// not know is an instruction it does know, so a platform that does
    /// not have an advice refuses it rather than handing the number over.
    pub fn is_available(advice: i32) -> bool {
        if is_linux_only(advice) {
            return cfg!(any(target_os = "linux", target_os = "android"));
        }
        true
    }
}

#[cfg(unix)]
pub(crate) use self::imp::is_available;
#[cfg(unix)]
pub use self::imp::{Advice, UncheckedAdvice};

#[cfg(all(test, unix))]
mod tests {
    use std::io;

    use super::imp::{is_available, is_linux_only, Advice, UncheckedAdvice, LINUX_ONLY};
    use crate::memmap2::MmapOptions;

    /// The five advices that every unix kernel has, in the same order and
    /// with the same numbers: `MADV_NORMAL` is 0 and `MADV_DONTNEED` is 4.
    const PORTABLE: [Advice; 5] = [
        Advice::Normal,
        Advice::Random,
        Advice::Sequential,
        Advice::WillNeed,
        Advice::DontNeed,
    ];

    /// The six that only Linux has and that the enum still carries
    /// everywhere else.
    const LINUX_VARIANTS: [Advice; 6] = [
        Advice::DontFork,
        Advice::DoFork,
        Advice::Mergeable,
        Advice::Unmergeable,
        Advice::HugePage,
        Advice::NoHugePage,
    ];

    #[test]
    fn the_seven_are_linux_s_own_numbers() {
        // Linux's `bits/mman-linux.h`: MADV_REMOVE is 9 and the six that
        // follow it are 10 to 15. The set the platforms without them
        // refuse has to be these numbers and not an approximation of them.
        assert_eq!(LINUX_ONLY, [9, 10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn a_portable_advice_is_on_every_unix_kernel() {
        // The refusal must not swallow an advice the kernel does have: the
        // five portable ones are the same number on every unix, and a
        // refusal set that held one of them would turn a working advice
        // into an error.
        for advice in PORTABLE {
            assert!(
                !is_linux_only(advice as i32),
                "the portable advice {advice:?} was taken for a Linux one"
            );
            assert!(
                is_available(advice as i32),
                "the portable advice {advice:?} was refused"
            );
        }
    }

    #[test]
    fn the_seven_are_available_here_only_on_linux() {
        // The set is named by hand and the enum by hand too, and a variant
        // added to one and not to the other would be an advice the
        // platforms without it would hand to the kernel.
        for advice in LINUX_VARIANTS {
            assert!(
                is_linux_only(advice as i32),
                "the Linux advice {advice:?} was not in the set"
            );
        }
        assert!(
            is_linux_only(UncheckedAdvice::Remove as i32),
            "MADV_REMOVE is Linux's and was not in the set"
        );

        // Linux has the seven and the BSDs do not, and the answer is the
        // platform's, not the test's: a test that said "not available"
        // everywhere would be green on a Linux that refused an advice it
        // has.
        let linux = cfg!(any(target_os = "linux", target_os = "android"));
        for advice in LINUX_VARIANTS {
            assert_eq!(
                is_available(advice as i32),
                linux,
                "the answer for {advice:?} is not the platform's"
            );
        }
        assert_eq!(
            is_available(UncheckedAdvice::Remove as i32),
            linux,
            "the answer for MADV_REMOVE is not the platform's"
        );
    }

    #[test]
    fn advise_refuses_only_what_this_platform_does_not_have() {
        // The refusal happens before the syscall, so on a platform that
        // does not have the advice the answer is the refusal and not
        // whatever the kernel would have said about the number.
        let map = MmapOptions::new().len(4096).map_anon().expect("a mapping");
        let answer = map.advise(Advice::HugePage);

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Err(e) = &answer {
                assert_ne!(
                    e.kind(),
                    io::ErrorKind::Unsupported,
                    "Linux has MADV_HUGEPAGE and the platform refused it"
                );
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let err = answer.expect_err("the platform did not refuse an advice it does not have");
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        }
    }
}
