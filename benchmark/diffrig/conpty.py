"""Run a command with a real ConPTY so its stdout IS a console, and capture
the bytes it writes. Used to test the 'line numbers iff stdout is a terminal'
claim for both rg 15 and rgx."""
import ctypes, shutil, os, sys
from ctypes import wintypes

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.ReadFile.argtypes=[wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                       ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
k32.ReadFile.restype=wintypes.BOOL
k32.GetExitCodeProcess.argtypes=[wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
k32.CreateProcessW.argtypes=[wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
    ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
    ctypes.c_void_p, ctypes.POINTER(PROCESS_INFORMATION)]
k32.CreateProcessW.restype=wintypes.BOOL
k32.CreatePseudoConsole.argtypes=[ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
k32.CreatePseudoConsole.restype=wintypes.BOOL
k32.CreatePipe.argtypes=[ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
    ctypes.c_void_p, wintypes.DWORD]
k32.CreatePipe.restype=wintypes.BOOL
k32.InitializeProcThreadAttributeList.argtypes=[ctypes.c_void_p, wintypes.DWORD,
    wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
k32.UpdateProcThreadAttribute.argtypes=[ctypes.c_void_p, wintypes.DWORD,
    ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
k32.UpdateProcThreadAttribute.restype=wintypes.BOOL

PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
EXTENDED_STARTUPINFO_PRESENT = 0x00080000

class COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]

class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFOW),
        ("AttributeList", ctypes.c_void_p),
    ]

def make_startup(size, attr_list):
    si = STARTUPINFOEXW()
    si.StartupInfo.cb = ctypes.sizeof(si)
    si.AttributeList = attr_list
    return si

def run_conpty(cmdline, cwd):
    # pipes
    def new_pipe():
        r, w = wintypes.HANDLE(), wintypes.HANDLE()
        if not k32.CreatePipe(ctypes.byref(r), ctypes.byref(w), None, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        return r, w
    pin_r, pin_w = new_pipe()
    pout_r, pout_w = new_pipe()

    size = COORD(120, 3000)
    hPC = ctypes.c_void_p()
    ok = k32.CreatePseudoConsole(ctypes.c_size_t(120), ctypes.c_size_t(3000),
                                 ctypes.c_size_t(0), ctypes.byref(size),
                                 ctypes.byref(hPC))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    n = 64
    attr_len = ctypes.c_size_t(n * ctypes.sizeof(ctypes.c_void_p))
    attr_list = ctypes.c_void_p()
    k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attr_len))
    attr_list = ctypes.create_string_buffer(attr_len.value)
    ok = k32.UpdateProcThreadAttribute(attr_list, 0,
                                       ctypes.c_size_t(PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE),
                                       hPC, ctypes.sizeof(ctypes.c_void_p),
                                       None, None)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())

    si = make_startup(size, ctypes.cast(attr_list, ctypes.c_void_p))
    pi = PROCESS_INFORMATION()
    ok = k32.CreateProcessW(None, ctypes.create_unicode_buffer(cmdline), None, None,
                            False, EXTENDED_STARTUPINFO_PRESENT, None, cwd,
                            ctypes.cast(ctypes.byref(si), ctypes.c_void_p), ctypes.cast(ctypes.byref(pi), ctypes.c_void_p))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    k32.CloseHandle(pi.hThread)

    k32.ClosePseudoConsole(hPC)
    k32.CloseHandle(pin_w)
    k32.CloseHandle(pin_r)

    out = b""
    while True:
        code = wintypes.DWORD()
        k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
        buf = ctypes.create_string_buffer(65536)
        nread = wintypes.DWORD()
        got = k32.ReadFile(pout_r, ctypes.byref(buf), 65536, ctypes.byref(nread), None)
        if nread.value:
            out += buf.raw[:nread.value]
        if not got or code.value != 259:  # STILL_ACTIVE
            break
    k32.CloseHandle(pout_r)
    k32.CloseHandle(pout_w)
    k32.CloseHandle(pi.hProcess)
    return out


# Resolved, not hardcoded: this file lives in benchmark/diffrig/, so the
# repo root is one level up and the build is wherever cargo put it. `RG`
# honours an explicit env override first (cmp.sh does the same for RGX),
# then PATH, then the ripgrep Git for Windows ships.
# benchmark/diffrig/x.py -> up three to the repo root.
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Debug first, release as the fallback -- the same order cmp.sh uses.
RGX = os.path.join(ROOT, "target", "debug", "rgx.exe")
if not os.path.isfile(RGX):
    RGX = os.path.join(ROOT, "target", "release", "rgx.exe")
RG = os.environ.get("RG") or shutil.which("rg") or r"C:\Program Files\Git\usr\bin\rg.exe"
CWD = os.path.dirname(os.path.abspath(__file__))

cases = [
    ["needle", "fx/hello.txt"],
    ["-n", "needle", "fx/hello.txt"],
    ["-N", "needle", "fx/hello.txt"],
    ["--no-line-number", "needle", "fx/hello.txt"],
    ["-I", "needle", "fx/hello.txt"],
    ["-n", "-I", "needle", "fx/hello.txt"],
    ["-c", "needle", "fx/hello.txt"],
    ["-l", "needle", "fx/hello.txt"],
    ["-o", "needle", "fx/multi.txt"],
    ["-A1", "needle", "fx/hello.txt"],
    ["-A1", "-n", "needle", "fx/hello.txt"],
    ["-A1", "--no-line-number", "needle", "fx/hello.txt"],
    ["-v", "needle", "fx/hello.txt"],
    ["-r", "R", "needle", "fx/multi.txt"],
    ["-o", "-r", "R", "needle", "fx/multi.txt"],
    ["needle", "fx/hello.txt", "fx/two.txt"],
    ["needle", "fx/crlf.txt"],
    ["-n", "needle", "fx/crlf.txt"],
    ["-N", "-n", "needle", "fx/hello.txt"],
    ["-n", "-N", "needle", "fx/hello.txt"],
]

for c in cases:
    try:
        a = run_conpty(RG + " " + " ".join(c), CWD)
    except Exception as e:
        import traceback; traceback.print_exc()
        a = b"<rg failed: %r>" % str(e).encode()
    try:
        b = run_conpty(RGX + " " + " ".join(c), CWD)
    except Exception as e:
        import traceback; traceback.print_exc()
        b = b"<rgx failed: %r>" % str(e).encode()
    tag = "SAME(pty) " if a == b else "DIFF(pty) "
    print(tag + " ".join(c))
    if a != b:
        print("   rg : %r" % a)
        print("   rgx: %r" % b)
