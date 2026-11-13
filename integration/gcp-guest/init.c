/* SPDX-License-Identifier: Apache-2.0
 * Closed GCP proof PID1. Establishes an immutable TCB view before role startup.
 * This launcher does not appraise hardware or qualify an execution producer.
 * Its exact image, kernel and process policy require independent validation.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/mount.h>
#include <linux/seccomp.h>
#include <openssl/sha.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC 0x0020
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
#define MAX_BLOB (512U * 1024U * 1024U)
#define MAX_ROLE (256U * 1024U * 1024U)
#define SEALS (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)
#define RAMFS_MAGIC_VALUE 0x858458f6UL
#define EROFS_MAGIC_VALUE 0xe0f5e1e2UL
#define DATA_ATTRS (MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC)
#define VIEW_ATTRS (MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV)
static const unsigned char IDX_MAGIC[16] = "ONB17-TCB-IDX1\0\0";
static volatile sig_atomic_t expired;
static int pid1;

static void event(const char *status, const char *stage, int error) {
    dprintf(1, "ONB17_PROOF_STARTUP_V1 {\"status\":\"%s\",\"stage\":\"%s\",\"errno\":%d}\n", status, stage, error);
}
static _Noreturn void poweroff(void) {
    sync();
    reboot(RB_POWER_OFF);
    for (;;) pause();
}
static _Noreturn void fail(const char *stage) {
    int error = errno;
    event("STARTUP_REJECTED", stage, error);
    if (pid1) poweroff();
    exit(2);
}
static void require(int condition, const char *stage) {
    if (!condition) { if (!errno) errno = EINVAL; fail(stage); }
}
static int fd_result(long result, const char *stage) {
    if (result < 0) fail(stage);
    return (int)result;
}
static void read_exact(int fd, unsigned char *value, size_t size, const char *stage) {
    size_t offset = 0;
    while (offset < size) {
        ssize_t count = pread(fd, value + offset, size - offset, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, stage); offset += (size_t)count;
    }
}
static int open_regular(const char *path, uint64_t expected, uint64_t maximum, const char *stage) {
    int fd = fd_result(open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK), stage);
    struct stat info;
    require(!fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_size > 0 &&
            (uint64_t)info.st_size <= maximum && (!expected || (uint64_t)info.st_size == expected), stage);
    return fd;
}
static uint64_t read_index(const char *path, unsigned char digest[48]) {
    unsigned char index[72];
    int fd = open_regular(path, sizeof(index), sizeof(index), "index-open");
    read_exact(fd, index, sizeof(index), "index-read"); close(fd);
    require(!memcmp(index, IDX_MAGIC, sizeof(IDX_MAGIC)), "index-magic");
    uint64_t size = 0;
    for (size_t i = 16; i < 24; i++) size = (size << 8) | index[i];
    require(size && size <= MAX_BLOB, "index-size");
    memcpy(digest, index + 24, 48); return size;
}
static void hash_fd(int fd, uint64_t size, unsigned char digest[48]) {
    SHA512_CTX context;
    unsigned char buffer[8192];
    require(SHA384_Init(&context) == 1, "hash-init");
    for (uint64_t offset = 0; offset < size;) {
        size_t want = (size - offset) < sizeof(buffer) ? (size_t)(size - offset) : sizeof(buffer);
        ssize_t count = pread(fd, buffer, want, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        require(count > 0 && SHA384_Update(&context, buffer, (size_t)count) == 1, "hash-read");
        offset += (size_t)count;
    }
    require(SHA384_Final(digest, &context) == 1, "hash-final");
    memset(buffer, 0, sizeof(buffer)); memset(&context, 0, sizeof(context));
}
static void copy_fd(int input, int output, uint64_t size) {
    unsigned char buffer[8192];
    for (uint64_t offset = 0; offset < size;) {
        size_t want = (size - offset) < sizeof(buffer) ? (size_t)(size - offset) : sizeof(buffer);
        ssize_t count = pread(input, buffer, want, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "copy-read");
        size_t written = 0;
        while (written < (size_t)count) {
            ssize_t n = pwrite(output, buffer + written, (size_t)count - written, (off_t)(offset + written));
            if (n < 0 && errno == EINTR) continue;
            require(n > 0, "copy-write"); written += (size_t)n;
        }
        offset += (size_t)count;
    }
    memset(buffer, 0, sizeof(buffer));
}
static void config(int context, unsigned command, const char *key, const char *value) {
    require(!syscall(SYS_fsconfig, context, command, key, value, 0), "fsconfig");
}
static void require_filesystems(void) {
    int fd = fd_result(open("/proc/filesystems", O_RDONLY | O_CLOEXEC | O_NOFOLLOW), "filesystem-registry");
    char value[65537]; size_t used = 0;
    while (used < sizeof(value)) {
        ssize_t count = read(fd, value + used, sizeof(value) - used);
        if (count < 0 && errno == EINTR) continue;
        require(count >= 0, "filesystem-registry-read");
        if (!count) break;
        used += (size_t)count;
    }
    close(fd); require(used < sizeof(value), "filesystem-registry-bound"); value[used] = 0;
    /* Exact final fields from the kernel seq-file; avoid module-autoload fallbacks. */
    int ramfs = 0, erofs = 0;
    for (char *line = value; line && *line;) {
        char *end = strchr(line, '\n'); if (end) *end = 0;
        char *last = strrchr(line, '\t'); last = last ? last + 1 : line;
        if (!strcmp(last, "ramfs")) ramfs = 1;
        if (!strcmp(last, "erofs")) erofs = 1;
        line = end ? end + 1 : NULL;
    }
    require(ramfs && erofs, "required-built-in-filesystems");
}
static int sealed_origin(int source, uint64_t size, const unsigned char expected[48]) {
    int origin = fd_result(syscall(SYS_memfd_create, "proof-tcb-origin",
                                  MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL), "memfd");
    require(!fchmod(origin, 0600), "origin-mode");
    copy_fd(source, origin, size);
    require(!fcntl(origin, F_ADD_SEALS, SEALS), "origin-seal");
    int seals = fcntl(origin, F_GET_SEALS);
    require(seals >= 0 && (seals & (SEALS | F_SEAL_EXEC)) == (SEALS | F_SEAL_EXEC), "origin-check-seals");
    unsigned char actual[48]; hash_fd(origin, size, actual);
    require(!memcmp(actual, expected, 48), "origin-hash"); return origin;
}
static void readonly_flags(int fd, unsigned long magic, unsigned long flags) {
    struct statfs fs; struct statvfs vfs;
    require(!fstatfs(fd, &fs) && !fstatvfs(fd, &vfs) &&
            (unsigned long)fs.f_type == magic && (vfs.f_flag & flags) == flags, "mount-profile");
}
static int readonly_backing(int origin, uint64_t size, const unsigned char expected[48], int *root_out) {
    int context = fd_result(syscall(SYS_fsopen, "ramfs", FSOPEN_CLOEXEC), "ramfs-open");
    config(context, FSCONFIG_SET_STRING, "mode", "0700");
    config(context, FSCONFIG_CMD_CREATE_EXCL, NULL, NULL);
    int root = fd_result(syscall(SYS_fsmount, context, FSMOUNT_CLOEXEC, DATA_ATTRS), "ramfs-mount");
    close(context);
    int writer = fd_result(openat(root, "image", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600), "ramfs-writer");
    require(!fchmod(writer, 0600), "ramfs-mode"); copy_fd(origin, writer, size);
    int reader = fd_result(openat(root, "image", O_RDONLY | O_NOFOLLOW | O_CLOEXEC), "ramfs-reader");
    close(writer); /* No writer/mapping/alternate mount has been published. */
    context = fd_result(syscall(SYS_fspick, root, "", FSPICK_CLOEXEC | FSPICK_EMPTY_PATH), "ramfs-pick");
    config(context, FSCONFIG_SET_FLAG, "ro", NULL);
    /* Nonforced superblock transition, not merely a per-mount readonly bind. */
    config(context, FSCONFIG_CMD_RECONFIGURE, NULL, NULL); close(context);
    readonly_flags(root, RAMFS_MAGIC_VALUE, ST_RDONLY);
    struct mount_attr attrs = { .attr_set = MOUNT_ATTR_RDONLY | DATA_ATTRS };
    require(!syscall(SYS_mount_setattr, root, "", AT_EMPTY_PATH, &attrs, sizeof(attrs)), "ramfs-attrs");
    readonly_flags(reader, RAMFS_MAGIC_VALUE, ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC);
    struct stat info;
    require(!fstat(reader, &info) && S_ISREG(info.st_mode) && info.st_nlink == 1 &&
            (uint64_t)info.st_size == size && (info.st_mode & 07777) == 0600, "ramfs-file-profile");
    unsigned char actual[48]; hash_fd(reader, size, actual);
    require(!memcmp(actual, expected, 48), "ramfs-readback-hash");
    *root_out = root; return reader;
}
static int erofs_view(int backing) {
    int context = fd_result(syscall(SYS_fsopen, "erofs", FSOPEN_CLOEXEC), "erofs-open");
    config(context, FSCONFIG_SET_FLAG, "ro", NULL);
    char source[64]; require(snprintf(source, sizeof(source), "/proc/self/fd/%d", backing) > 0, "backing-name");
    config(context, FSCONFIG_SET_STRING, "source", source);
    config(context, FSCONFIG_CMD_CREATE_EXCL, NULL, NULL);
    int root = fd_result(syscall(SYS_fsmount, context, FSMOUNT_CLOEXEC, VIEW_ATTRS), "erofs-mount");
    close(context);
    readonly_flags(root, EROFS_MAGIC_VALUE, ST_RDONLY | ST_NOSUID | ST_NODEV); return root;
}
static int preparation_role(int root) {
    const char *parts[] = { "onb17", "bin", "gcp-proof-preparation" };
    int fd = fcntl(root, F_DUPFD_CLOEXEC, 3); require(fd >= 0, "role-root");
    for (unsigned i = 0; i < 3; i++) {
        int next = fd_result(openat(fd, parts[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
                            (i < 2 ? O_DIRECTORY : 0)), "role-open");
        close(fd); fd = next;
        struct stat info; require(!fstat(fd, &info) && info.st_uid == 0 &&
                    !(info.st_mode & 0022), "role-owner");
    }
    struct stat info; Elf64_Ehdr header;
    require(!fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_size >= (off_t)sizeof(header) &&
            (uint64_t)info.st_size <= MAX_ROLE && (info.st_mode & 0111) &&
            !(info.st_mode & 07022), "role-profile");
    read_exact(fd, (unsigned char *)&header, sizeof(header), "role-header");
    require(!memcmp(header.e_ident, ELFMAG, SELFMAG) && header.e_ident[EI_CLASS] == ELFCLASS64 &&
            header.e_ident[EI_DATA] == ELFDATA2LSB && header.e_machine == EM_X86_64 &&
            (header.e_type == ET_EXEC || header.e_type == ET_DYN) && header.e_ehsize == sizeof(header) &&
            header.e_phnum && header.e_phnum <= 128 && header.e_phentsize == sizeof(Elf64_Phdr) &&
            header.e_phoff <= (uint64_t)info.st_size &&
            header.e_phnum * sizeof(Elf64_Phdr) <= (uint64_t)info.st_size - header.e_phoff, "role-elf");
    for (unsigned i = 0; i < header.e_phnum; i++) {
        Elf64_Phdr ph;
        require(pread(fd, &ph, sizeof(ph), (off_t)(header.e_phoff + i * sizeof(ph))) == (ssize_t)sizeof(ph), "role-phdr");
        require(!(ph.p_type == PT_GNU_STACK && (ph.p_flags & PF_X)), "role-stack");
    }
    return fd;
}
static void capabilities(uint64_t keep) {
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++)
        if (!(keep & (1ULL << cap))) require(!prctl(PR_CAPBSET_DROP, cap, 0, 0, 0), "cap-bounding-drop");
    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    for (unsigned i = 0; i < 2; i++) data[i].effective = data[i].permitted = (uint32_t)(keep >> (32 * i));
    require(!syscall(SYS_capset, &header, data), "capset");
}
static void console_profile(void) {
    /* This kernel disables PROC_SYSCTL and forces its compiled command line.
     * Verify that exact profile instead of opening a mutable sysctl interface.
     * Normal kernel console output must stay quiet around binary control frames. */
    static const char expected[] = "noinitrd console=ttyS0,115200 rdinit=/init panic=1 ip=dhcp quiet loglevel=0\n";
    char actual[sizeof(expected)]; size_t used = 0;
    int fd = fd_result(open("/proc/cmdline", O_RDONLY | O_CLOEXEC | O_NOFOLLOW), "console-profile-open");
    for (;;) {
        require(used < sizeof(actual), "console-profile-bound");
        ssize_t count = read(fd, actual + used, sizeof(actual) - used);
        if (count < 0 && errno == EINTR) continue;
        require(count >= 0, "console-profile-read");
        if (!count) break;
        used += (size_t)count;
    }
    close(fd);
    require(used == sizeof(expected) - 1 && !memcmp(actual, expected, used), "console-profile-command-line");
    fd = open("/proc/sys/kernel/printk", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) { close(fd); errno = EINVAL; fail("console-profile-mutable"); }
    require(errno == ENOENT, "console-profile-sysctl");
}
static void alarm_signal(int value) { (void)value; expired = 1; }
static _Noreturn void boot(void) {
    clearenv(); umask(077);
    int console = fd_result(open("/dev/console", O_RDWR | O_NOFOLLOW | O_CLOEXEC), "console-open");
    struct stat console_info;
    require(!fstat(console, &console_info) && S_ISCHR(console_info.st_mode) &&
            major(console_info.st_rdev) == 5 && minor(console_info.st_rdev) == 1, "console-profile");
    for (int fd = 0; fd < 3; fd++) require(dup2(console, fd) == fd && !fcntl(fd, F_SETFD, 0), "console-dup");
    if (console > 2) close(console);
    require(!prctl(PR_SET_DUMPABLE, 0, 0, 0, 0), "bootstrap-dumpable");
    require(!unshare(CLONE_NEWNS) && !mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL), "private-mount-namespace");
    require(!mkdir("/proc", 0700) || errno == EEXIST, "proc-directory");
    require(!mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=2"), "private-proc");
    console_profile();
    require_filesystems();
    require(prctl(PR_CAPBSET_READ, CAP_LAST_CAP + 1, 0, 0, 0) == -1 && errno == EINVAL, "known-capability-abi");
    unsigned char expected[48]; uint64_t size = read_index("/boot/tcb-index.bin", expected);
    int source = open_regular("/boot/tcb.erofs", size, MAX_BLOB, "blob-open");
    int origin = sealed_origin(source, size, expected); close(source);
    int ram_root; int backing = readonly_backing(origin, size, expected, &ram_root);
    int root = erofs_view(backing);
    int executable = preparation_role(root);
    require(!mkdir("/view", 0700) || errno == EEXIST, "role-root-directory");
    require(!syscall(SYS_move_mount, root, "", AT_FDCWD, "/view", MOVE_MOUNT_F_EMPTY_PATH), "attach-erofs");
    require(!mount("tmpfs", "/view/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
                   "mode=0710,uid=0,gid=1001,size=536870912"), "private-run");
    require(!mkdir("/view/run/onb17", 0750) && !chown("/view/run/onb17", 0, 1001) &&
            !chmod("/view/run/onb17", 0750), "private-control-directory");
    require(!mkdir("/view/run/onb17/tmp", 0700), "private-temporary-directory");
    require(!mount("proc", "/view/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=2"), "role-proc");
    require(!mount("sysfs", "/view/sys", "sysfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL), "role-sys");
    require(!mount("devtmpfs", "/view/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755"), "role-dev");
    require(!mount("configfs", "/view/sys/kernel/config", "configfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL), "role-tsm");
    event("IMMUTABLE_VIEW_ESTABLISHED", "before-role", 0);
    pid_t child = fork(); require(child >= 0, "fork");
    if (!child) {
        pid1 = 0;
        require(!fchdir(root) && !chroot(".") && !chdir("/"), "child-root");
        require(!setgroups(0, NULL), "role-groups");
        /* These privileged roles are the declared TCB. Host management and the
         * workload receive no generic mount/exec/quote capability. The actual
         * preparation role performs its own exact C/D/A/V/file checks first. */
        uint64_t keep = (1ULL << CAP_CHOWN) | (1ULL << CAP_DAC_OVERRIDE) |
            (1ULL << CAP_FOWNER) | (1ULL << CAP_KILL) | (1ULL << CAP_SETGID) |
            (1ULL << CAP_SETUID) | (1ULL << CAP_SETPCAP) | (1ULL << CAP_SYS_CHROOT) |
            (1ULL << CAP_SYS_PTRACE) | (1ULL << CAP_SYS_ADMIN);
        capabilities(keep);
        require(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "role-nnp");
        require(!prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) && getppid() == 1, "role-parent");
        require(!syscall(SYS_close_range, 3U, UINT_MAX, CLOSE_RANGE_CLOEXEC), "role-fds");
        char *args[] = { "/onb17/bin/gcp-proof-preparation", NULL };
        char *env[] = { "LC_ALL=C", "TMPDIR=/run/onb17/tmp", NULL };
        syscall(SYS_execveat, executable, "", args, env, AT_EMPTY_PATH); fail("child-execveat");
    }
    /* Parent retains private owners, but no remount/ptrace/device authority. */
    capabilities(1ULL << CAP_SYS_BOOT);
    require(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "parent-nnp");
    struct sigaction action = { .sa_handler = alarm_signal };
    sigemptyset(&action.sa_mask); require(!sigaction(SIGALRM, &action, NULL), "watchdog"); alarm(900);
    int status = 0;
    for (;;) {
        pid_t result = waitpid(child, &status, 0);
        if (result == child) break;
        if (result < 0 && errno == EINTR && !expired) continue;
        kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        event("ROLE_TIMEOUT_OR_WAIT_ERROR", "wait", errno); poweroff();
    }
    alarm(0);
    event(WIFEXITED(status) && WEXITSTATUS(status) == 0 ? "ROLE_EXITED_ZERO" : "ROLE_FAILED", "after-child", 0);
    close(executable); close(root); close(backing); close(ram_root); close(origin);
    poweroff();
}
int main(int argc, char **argv) {
    pid1 = getpid() == 1;
    if (pid1) boot();
    /* This mode is content-only: no mount, namespace, memfd, capability or exec operations. */
    if (argc != 4 || strcmp(argv[1], "--inspect")) return 64;
    unsigned char expected[48], actual[48]; uint64_t size = read_index(argv[2], expected);
    int source = open_regular(argv[3], size, MAX_BLOB, "inspect-blob");
    hash_fd(source, size, actual); close(source);
    require(!memcmp(actual, expected, 48), "inspect-hash");
    event("BLOB_BYTES_MATCH_INSPECTION_ONLY", "inspect-no-mount", 0); return 0;
}
