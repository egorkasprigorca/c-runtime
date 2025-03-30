#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/prctl.h>
#include <sys/prctl.h>

static int
pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

typedef struct {
    uint8_t detach;
    int reader_pipe;
    char *command;
    char **command_args;
} container_opts_t;

static int
daemonize() {
    pid_t pid = fork();
    if (pid < 0)
        err(EXIT_FAILURE, "fork");
    if (pid > 0)
        exit(EXIT_SUCCESS);
    if (setsid() < 0)
        err(EXIT_FAILURE, "setsid");
    pid = fork();
    if (pid < 0)
        err(EXIT_FAILURE, "fork");
    if (pid > 0)
        exit(EXIT_SUCCESS);
    return 0;
}

#define STACKSIZE (1024*1024)
static char container_stack[STACKSIZE];

int setup_userns(const pid_t pid, const int uid, const int gid) {
    printf("Preparing user namespace\n");
    FILE *file;
    char path[64];

    sprintf(path, "/proc/%d/uid_map", pid);
    file = fopen(path, "w");
    if (file == NULL)
        err(EXIT_FAILURE, "Couldn't open uid_map");
    fprintf(file, "0 %d 1\n", uid);
    fclose(file);

    sprintf(path, "/proc/%d/setgroups", pid);
    file = fopen(path, "w");
    if (file == NULL)
        err(EXIT_FAILURE, "Couldn't open setgroups");
    fprintf(file, "deny");
    fclose(file);

    sprintf(path, "/proc/%d/gid_map", pid);
    file = fopen(path, "w");
    if (file == NULL)
        err(EXIT_FAILURE, "Couldn't open gid_map");
    fprintf(file, "0 %d 1\n", gid);
    fclose(file);

    return 0;
}

int setup_rootfs(const char *bundle_path) {
    printf("Setting up rootfs\n");
    const char *oldrootfs_path = ".oldrootfs";
    const char *rootfs_path = "rootfs";
    int mount_flags = MS_BIND;
    const char *mount_name = "rootfs";
    chdir(bundle_path);
    struct stat st;
    if (stat(rootfs_path, &st) == -1 || !S_ISDIR(st.st_mode))
        err(EXIT_FAILURE, "RootFS directory '%s' does not exist", rootfs_path);
    if (mount(mount_name, rootfs_path, "ext4", mount_flags, "") == -1)
        err(EXIT_FAILURE, "Failed to mount rootfs");
    chdir(rootfs_path);
    if (mkdir(oldrootfs_path, 0777) == -1 && errno != EEXIST)
        err(EXIT_FAILURE, "Failed to create oldrootfs directory");
    if (pivot_root(".", oldrootfs_path) == -1)
        err(EXIT_FAILURE, "Failed to pivot root");
    if (chdir("/") == -1)
        err(EXIT_FAILURE, "Failed to chroot /");
    if (umount2(oldrootfs_path, MNT_DETACH) == -1)
        err(EXIT_FAILURE, "Failed to umount rootfs");
    return 0;
}

int container_run(void *arg) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    char buf[2];
    container_opts_t *run_opts = (container_opts_t*)arg;
    int n = read(run_opts->reader_pipe, buf, 2);
    if (run_opts->detach && setsid() < 0)
        err(EXIT_FAILURE, "Couldn't setsid");
    setup_rootfs("../bundle");
    int res = execvp(run_opts->command, run_opts->command_args);
    if (res == -1)
        err(EXIT_FAILURE, "Failed to execute container process command");
    return 0;
}

int main(int argc, char *argv[]) {
    int fds[2];
    if (pipe(fds) == -1) {
        err(EXIT_FAILURE, "Failed to create communication pipe");
    }
    container_opts_t opts = {
        .detach = 1,
        .command = argv[1],
        .command_args = &argv[1],
        .reader_pipe = fds[0]
    };
    if (opts.detach) {
        if (daemonize() < 0)
            err(EXIT_FAILURE, "Failed to daemonize");
    }
    int flags = CLONE_NEWUSER | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD;
    pid_t pid = clone(container_run, container_stack + STACKSIZE, flags, &opts);
    setup_userns(pid, getuid(), getgid());
    int n = write(fds[1], "OK", 2);
    if (pid < 0)
        err(EXIT_FAILURE, "Failed to create container process");
    if (opts.detach) {
        printf("Detached process pid %d\n", pid);
        return 0;
    }
    while (1) {
        int status;
        int r = waitpid(pid, &status, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return EXIT_FAILURE;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status))
            return WEXITSTATUS(status);
    }
}