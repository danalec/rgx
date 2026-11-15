// SPDX-License-Identifier: Apache-2.0

//! The CPU feature probe, by hand: CPUID and XGETBV, no `std`.
//!
//! **Why this module exists.** `std::arch::is_x86_feature_detected!` is the
//! obvious way to ask "can this CPU run the AVX2 path?", and it is the wrong
//! one for this crate twice over. It lives in `std`, and `rgx-core` is
//! `no_std` + `alloc`; and it is a *question* asked on the hot path -- once
//! per scan, per buffer -- where a question that costs a hundred cycles is a
//! question worth caching.
//!
//! So the probe is written out: CPUID for the feature bits, XGETBV for the
//! register state the operating system has to save, and one cached byte per
//! feature so the question is asked once per process. The answer cannot
//! change while the process runs -- a CPU does not grow a feature -- so the
//! two threads that race to compute it compute the same value.
//!
//! **What each answer means.** A feature bit alone is not a permission to
//! run the instruction: on a kernel that does not save the register state the
//! instruction traps, so the OS support is part of the answer.
//!
//! * `avx2()` -- `CPUID.(EAX=7, ECX=0):EBX[5]`, plus the AVX bit
//!   (`CPUID.(EAX=1):ECX[28]`), the OSXSAVE bit (`CPUID.(EAX=1):ECX[27]`),
//!   and `XCR0[2:1] == 0b11`: the OS has to save the YMM state.
//! * `avx512bw()` -- `CPUID.(EAX=7, ECX=0):EBX[30]`, plus `EBX[16]`
//!   (AVX512F, which AVX512BW implies), the same AVX and OSXSAVE pair, and
//!   `XCR0[7:5] == 0b111` on top of `XCR0[2:1] == 0b11`: the opmask, the ZMM
//!   high halves and the sixteen ZMM registers are three more register
//!   states the OS has to save.
//! * `pclmulqdq()` -- `CPUID.(EAX=1):ECX[1]`. No register state: the
//!   instruction writes the XMM registers, which the OS has always saved.
//! * `sha()` -- `CPUID.(EAX=7, ECX=0):EBX[29]`. No register state either.
//! * `sse4_1()` -- `CPUID.(EAX=1):ECX[19]`. No register state either.
//!
//! **What pins it.** The test at the bottom of this file compares every
//! answer with the standard library's, on the machine the test runs on. The
//! probe is not trusted because it was read out of the manual; it is trusted
//! because the standard library agrees with it, and where the two could
//! disagree the test says so. The JSON scanner carried a copy of this probe
//! before this module existed, for the same reason, and two copies of one
//! question are two answers waiting to drift.

/// Whether this CPU can run the AVX2 path.
#[must_use]
pub fn avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86::avx2_cached()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Whether this CPU can run the AVX-512 byte-and-word path.
///
/// The kernel that uses it wants the byte and word forms of the 512-bit
/// operations, so `avx512bw` is the bit that decides -- not `avx512f`, which
/// this one implies.
#[must_use]
pub fn avx512bw() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86::avx512bw_cached()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Whether this CPU can run the carry-less multiply.
#[must_use]
pub fn pclmulqdq() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86::pclmulqdq_cached()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Whether this CPU can run the SHA-256 hardware path.
///
/// The SHA extensions -- the instructions that compress a 64-byte block in a
/// handful of rounds instead of a loop -- are `CPUID.(EAX=7, ECX=0):EBX[29]`.
/// They need no register state the OS has not always saved, so the bit is the
/// whole answer.
#[must_use]
pub fn sha() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86::sha_cached()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Whether this CPU can run the SSE4.1 instructions.
///
/// `CPUID.(EAX=1):ECX[19]`. The SHA-256 kernel asks for these next to the SHA
/// extensions, so the two are answered by the same probe and cached the same
/// way.
#[must_use]
pub fn sse4_1() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        x86::sse4_1_cached()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    use core::sync::atomic::{AtomicU8, Ordering};

    /// The answer has not been computed yet.
    const UNKNOWN: u8 = 0;
    /// The CPU has the feature.
    const YES: u8 = 1;
    /// The CPU does not have the feature.
    const NO: u8 = 2;

    static AVX2: AtomicU8 = AtomicU8::new(UNKNOWN);
    static AVX512BW: AtomicU8 = AtomicU8::new(UNKNOWN);
    static PCLMULQDQ: AtomicU8 = AtomicU8::new(UNKNOWN);
    static SHA: AtomicU8 = AtomicU8::new(UNKNOWN);
    static SSE4_1: AtomicU8 = AtomicU8::new(UNKNOWN);

    /// Read `XCR0`, the set of register states the OS saves on a context
    /// switch.
    ///
    /// # Safety
    ///
    /// Requires XSAVE, which is what `CPUID.1:ECX[27]` (OSXSAVE) reports. The
    /// caller must have established it.
    #[target_feature(enable = "xsave")]
    pub(super) unsafe fn xgetbv0() -> u64 {
        // SAFETY: the target feature is this function's contract.
        unsafe { core::arch::x86_64::_xgetbv(0) }
    }

    /// `CPUID.(EAX=1):ECX[1]`.
    #[allow(unused_unsafe)]
    pub(super) fn pclmulqdq() -> bool {
        // SAFETY: __cpuid is safe to call on x86_64.
        unsafe { __cpuid(1) }.ecx & (1 << 1) != 0
    }

    /// `CPUID.(EAX=7, ECX=0):EBX[29]`: the SHA extensions.
    #[allow(unused_unsafe)]
    pub(super) fn sha() -> bool {
        unsafe { __cpuid_count(7, 0) }.ebx & (1 << 29) != 0
    }

    /// `CPUID.(EAX=1):ECX[19]`: SSE4.1.
    #[allow(unused_unsafe)]
    pub(super) fn sse4_1() -> bool {
        unsafe { __cpuid(1) }.ecx & (1 << 19) != 0
    }

    /// `CPUID.(EAX=7, ECX=0):EBX[5]`, plus the OS support an AVX2 instruction
    /// needs on top of the CPU feature.
    #[allow(unused_unsafe)]
    pub(super) fn avx2() -> bool {
        let leaf1 = unsafe { __cpuid(1) };
        let osxsave = leaf1.ecx & (1 << 27) != 0;
        let avx = leaf1.ecx & (1 << 28) != 0;
        if !(unsafe { __cpuid_count(7, 0) }.ebx & (1 << 5) != 0 && osxsave && avx) {
            return false;
        }
        // SAFETY: OSXSAVE was just read as set, which is the precondition of
        // `xgetbv0` -- without it the instruction faults, and a CPU that sets
        // it also supports XSAVE.
        let xcr0 = unsafe { xgetbv0() };
        (xcr0 & 0b110) == 0b110
    }

    /// `CPUID.(EAX=7, ECX=0):EBX[30]`, plus `EBX[16]` (AVX512F, which
    /// AVX512BW implies), plus the OS support: the YMM state, and the three
    /// ZMM states -- the opmask, the ZMM high halves and the sixteen ZMM
    /// registers -- that an AVX-512 instruction adds on top of it.
    #[allow(unused_unsafe)]
    pub(super) fn avx512bw() -> bool {
        let leaf1 = unsafe { __cpuid(1) };
        let osxsave = leaf1.ecx & (1 << 27) != 0;
        let avx = leaf1.ecx & (1 << 28) != 0;
        let leaf7 = unsafe { __cpuid_count(7, 0) }.ebx;
        if !(leaf7 & (1 << 16) != 0 && leaf7 & (1 << 30) != 0 && osxsave && avx) {
            return false;
        }
        // SAFETY: OSXSAVE was just read as set, which is the precondition of
        // `xgetbv0` -- without it the instruction faults, and a CPU that sets
        // it also supports XSAVE.
        let xcr0 = unsafe { xgetbv0() };
        // XCR0[2:1] is the YMM state, XCR0[7:5] the three ZMM states.
        (xcr0 & 0b1110_0110) == 0b1110_0110
    }

    /// The cached answer, computed once.
    ///
    /// The two threads that race here compute the same value -- the CPU does
    /// not change its features while the process runs -- so the store that
    /// loses the race stores the same byte the winner stored.
    fn cached(slot: &AtomicU8, probe: fn() -> bool) -> bool {
        match slot.load(Ordering::Relaxed) {
            YES => true,
            NO => false,
            _ => {
                let answer = probe();
                slot.store(if answer { YES } else { NO }, Ordering::Relaxed);
                answer
            }
        }
    }

    pub(super) fn avx2_cached() -> bool {
        cached(&AVX2, avx2)
    }

    pub(super) fn avx512bw_cached() -> bool {
        cached(&AVX512BW, avx512bw)
    }

    pub(super) fn pclmulqdq_cached() -> bool {
        cached(&PCLMULQDQ, pclmulqdq)
    }

    pub(super) fn sha_cached() -> bool {
        cached(&SHA, sha)
    }

    pub(super) fn sse4_1_cached() -> bool {
        cached(&SSE4_1, sse4_1)
    }
}

#[cfg(test)]
mod tests {
    /// The probe and the standard library have to agree, on the machine the
    /// test runs on.
    ///
    /// The standard library's macro is the answer this crate is measured
    /// against: the two are asked the same question about the same CPU, and
    /// a build that takes the vector path where the other does not is a
    /// build whose answers are not comparable. The probe is not trusted
    /// because it was read out of the manual; it is trusted because the
    /// standard library agrees with it.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_probe_agrees_with_the_standard_library() {
        assert_eq!(super::avx2(), std::is_x86_feature_detected!("avx2"));
        assert_eq!(super::avx512bw(), std::is_x86_feature_detected!("avx512bw"));
        assert_eq!(
            super::pclmulqdq(),
            std::is_x86_feature_detected!("pclmulqdq")
        );
        assert_eq!(super::sha(), std::is_x86_feature_detected!("sha"));
        assert_eq!(super::sse4_1(), std::is_x86_feature_detected!("sse4.1"));
    }

    /// The same question on a machine that has no x86 in it.
    ///
    /// The standard library has no macro to ask on this architecture, so
    /// there is no second answer to compare with -- and the answer the probe
    /// has to give is the only one there is. The test is here rather than
    /// skipped because a probe that answered "yes" here would send the
    /// searcher into an x86 kernel that does not exist on this machine.
    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn the_probe_agrees_with_the_standard_library() {
        assert!(!super::avx2());
        assert!(!super::avx512bw());
        assert!(!super::pclmulqdq());
        assert!(!super::sha());
        assert!(!super::sse4_1());
    }

    /// The cache answers the same thing twice.
    ///
    /// The probe is asked once per process and then read from a byte; a
    /// cache that could answer differently the second time would make the
    /// dispatch depend on how many times it had run.
    #[test]
    fn the_cached_answer_is_the_same_every_time() {
        let first = super::avx2();
        for _ in 0..8 {
            assert_eq!(super::avx2(), first);
        }
        let first = super::avx512bw();
        for _ in 0..8 {
            assert_eq!(super::avx512bw(), first);
        }
        let first = super::sha();
        for _ in 0..8 {
            assert_eq!(super::sha(), first);
        }
        let first = super::sse4_1();
        for _ in 0..8 {
            assert_eq!(super::sse4_1(), first);
        }
    }
}
