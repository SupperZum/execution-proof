"""Linux syscall restrictions for the execution-proof verifier and its workers."""
import ctypes
import errno
import socket


class ArgComparison(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_uint),
                ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]


def restrict_network():
    # libseccomp rejects foreign syscall ABIs by default. Apply the filter
    # before starting the verifier so both the CLI and its workers inherit it.
    lib = ctypes.CDLL("libseccomp.so.2")
    ctx_t = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctx_t
    lib.seccomp_release.argtypes = [ctx_t]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add.argtypes = [ctx_t, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                           ctypes.c_uint, ctypes.POINTER(ArgComparison)]
    lib.seccomp_load.argtypes = [ctx_t]
    ctx = lib.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not ctx:
        raise RuntimeError("seccomp initialization failed")
    try:
        for name in (b"socket", b"connect", b"io_uring_setup",
                     b"io_uring_enter", b"io_uring_register", b"pidfd_getfd",
                     b"ptrace", b"process_vm_readv", b"process_vm_writev"):
            nr = lib.seccomp_syscall_resolve_name(name)
            if nr < 0 or lib.seccomp_rule_add(ctx, 0x50000 | errno.EPERM, nr, 0):
                raise RuntimeError("could not restrict " + name.decode())
        # Rust uses an unnamed Unix socket pair to report child exec failures.
        # Neither endpoint can be addressed by another process.
        family_not_unix = ArgComparison(0, 1, socket.AF_UNIX, 0)  # SCMP_CMP_NE
        pair = lib.seccomp_syscall_resolve_name(b"socketpair")
        if pair < 0 or lib.seccomp_rule_add_array(ctx, 0x50000 | errno.EPERM, pair, 1,
                                                  ctypes.byref(family_not_unix)):
            raise RuntimeError("could not restrict socketpair")
        if lib.seccomp_load(ctx):
            raise RuntimeError("could not load offline seccomp filter")
    finally:
        lib.seccomp_release(ctx)

    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
        try:
            with socket.socket(family):
                raise RuntimeError("offline socket check failed")
        except PermissionError as error:
            if error.errno != errno.EPERM:
                raise
