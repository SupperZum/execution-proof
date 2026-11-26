// PID 1 for an isolated software test VM. All mounts are inside the guest.
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <unistd.h>

static void check(int result, const char *operation) {
    if (result < 0) { perror(operation); _exit(1); }
}

static void run_case(const char *name) {
    char image[64];
    snprintf(image, sizeof(image), "/%s.erofs", name);
    check(unshare(CLONE_NEWNS), "new mount namespace");
    check(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL), "private mounts");
    check(mount("ramfs", "/images", "ramfs", MS_NOSUID | MS_NODEV, NULL), "mount backing ramfs");
    int input = open(image, O_RDONLY);
    check(input, "read image");
    int output = open("/images/root.erofs", O_CREAT | O_EXCL | O_WRONLY, 0400);
    check(output, "create backing file");
    ssize_t count;
    while ((count = sendfile(output, input, NULL, 1 << 20)) > 0) {}
    check(count, "copy image");
    check(close(output), "close image");
    close(input);
    check(mount("/images/root.erofs", "/view", "erofs", MS_RDONLY | MS_NOSUID | MS_NODEV, NULL), "mount EROFS");
    check(mount("proc", "/view/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL), "mount proc");
    check(mount("/inputs", "/view/run", NULL, MS_BIND, NULL), "attach test inputs");
    check(chroot("/view"), "enter EROFS");
    check(chdir("/"), "change directory");
    check(setenv("CAPSULE_ROOT_CASE", name, 1), "set case");
    execl("/onb17/bin/kata-agent-gcp-proof", "loader-test", "--ignored", "--exact",
          "gcp_startup::tests::native_erofs_role_loads_only_the_bound_capsule",
          "--nocapture", (char *)NULL);
    check(-1, "exec loader test");
}

int main(void) {
    if (getpid() != 1) return 1;
    int fd = open("/dev/console", O_RDWR);
    check(fd, "open console");
    for (int i = 0; i < 3; i++) check(dup2(fd, i), "attach console");
    if (fd > 2) close(fd);
    const char *cases[] = {"valid", "leaf", "extra"};
    int passed = 0;
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        pid_t pid = fork();
        check(pid, "fork");
        if (pid == 0) run_case(cases[i]);
        int status;
        check(waitpid(pid, &status, 0), "wait");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) break;
        dprintf(1, "CAPSULE_ROOT_PASS %s\n", cases[i]);
        passed++;
    }
    dprintf(1, "CAPSULE_ROOT_TOTAL %d\n", passed);
    reboot(RB_POWER_OFF);
    return 1;
}
