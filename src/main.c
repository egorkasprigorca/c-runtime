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

static int sys_clone(unsigned long flags, void *child_stack) {
    return (int)syscall(SYS_clone, flags, child_stack);
}

static int pivot_root(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

typedef struct {
    uint8_t detach;
    char *command;
    char **command_args;
} container_run_opts;

int set_usernamespace(const pid_t pid, const uid_t host_uid, const gid_t host_gid) {
    char path[64];
    FILE *file;

    sprintf(path, "/proc/%d/uid_map", pid);
    file = fopen(path, "w");
    fprintf(file, "0 %d 1\n", host_uid);
    fclose(file);

    sprintf(path, "/proc/%d/setgroups", pid);
    file = fopen(path, "w");
    fprintf(file, "deny");
    fclose(file);

    sprintf(path, "/proc/%d/gid_map", pid);
    file = fopen(path, "w");
    fprintf(file, "0 %d 1\n", host_gid);
    fclose(file);

    printf("setted up usernamespace");

    return 0;
}

int set_rootfs() {
    int ret;
    char buf[128];
    printf("Effective UID: %d\n", geteuid());

    chdir("..");
    ret = mount("root_fs", "root_fs", "", MS_BIND, "");
    if (ret < 0)
        err(EXIT_FAILURE, "mount");

    printf("Current directory: %s\n", getcwd(buf, sizeof(buf)));
    ret = mkdir("root_fs/old_root", 0777);
    if (ret < 0 && errno != EEXIST)
        err(EXIT_FAILURE, "mkdir old_root");

    ret = pivot_root(".", "root_fs/old_root");
    if (ret < 0)
        err(EXIT_FAILURE, "pivot_root");

    ret = umount2("old_root", MNT_DETACH);
    if (ret < 0)
        err(EXIT_FAILURE, "umount2");

    return 0;
}

pid_t container_run(container_run_opts *run_opts, const uid_t host_uid, const gid_t host_gid) {
    pid_t pid;
    int unshare_flags = CLONE_NEWUSER | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD;
    pid = sys_clone(unshare_flags, NULL);
    if (pid < 0)
        err(EXIT_FAILURE, "clone");

    if (pid > 0)
        return pid;

    if (run_opts->detach && setsid() < 0)
        err(EXIT_FAILURE, "setsid");

    printf("Child process: PID = %d\n", getpid());
    printf("Setting up root filesystem...\n");
    set_rootfs();

    if (execvp(run_opts->command, run_opts->command_args) < 0)
        _exit(EXIT_FAILURE);

    return 0;
}

int detach_process() {
    pid_t pid;
    if (setsid() < 0)
        return -1;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid != 0)
        _exit(EXIT_SUCCESS);
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    container_run_opts run_opts = {
        .detach = 0,
        .command = argv[1],
        .command_args = argv + 1
    };

    uid_t host_uid = getuid();
    uid_t host_gid = getgid();
    int ret;

    if (run_opts.detach) {
        ret = fork();
        if (ret)
            return 0;
        ret = detach_process();
        if (ret < 0)
            err(EXIT_FAILURE, "detach process");
    }

    pid_t pid = container_run(&run_opts, host_uid, host_gid);
    set_usernamespace(pid, host_uid, host_gid);

    if (run_opts.detach) {
        FILE *pid_file = fopen("../mydaemon.pid", "w");
        if (pid_file != NULL) {
            fprintf(pid_file, "%d\n", pid);
            fclose(pid_file);
        }
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