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
    char **args;
    uint8_t args_size;
} container_run_opts;

int set_usernamespace(const pid_t pid, const uid_t host_uid, const gid_t host_gid) {
    char path[64];
    char line[64];

    int uid_len = 1;
    int gid_len = 1;

    uid_t container_uid = 0;
    uid_t container_gid = 0;
    FILE *file;

    sprintf(path, "/proc/%d/uid_map", pid);
    file = fopen(path, "w");
    fprintf(file, "%d %d %d\n", container_uid, host_uid, uid_len);
    fclose(file);

    sprintf(path, "/proc/%d/setgroups", pid);
    file = fopen(path, "w");
    fprintf(file, "deny");
    fclose(file);

    sprintf(path, "/proc/%d/gid_map", pid);
    file = fopen(path, "w");
    fprintf(file, "%d %d %d\n", container_gid, host_gid, gid_len);
    fclose(file);

    return 0;
}

int set_rootfs() {
    int ret;
    char buf[128];
    // getcwd(buf, sizeof(buf));
    // printf("Path: %s\n", buf);
    chdir("..");
    getcwd(buf, sizeof(buf));
    printf("Path: %s\n", buf);
    ret = mount("root_fs", "root_fs", "", MS_BIND, "");
    if (ret < 0)
        err(EXIT_FAILURE, "mount");
    ret = mkdir("root_fs/old_root", 0777);
    if (ret < 0 && errno != EEXIST)
        err(EXIT_FAILURE, "mkdir old_root");
    ret = pivot_root("root_fs", "root_fs/old_root");
    if (ret < 0)
        err(EXIT_FAILURE, "pivot_root");
    // ret = chdir("/");
    // if (ret < 0)
    //     err(EXIT_FAILURE, "chdir");
    ret = chroot("/");
    if (ret < 0)
        err(EXIT_FAILURE, "chroot");
    // ret = umount2("old_root", MNT_DETACH);
    // if (ret < 0)
    //     err(EXIT_FAILURE, "umount2");
    return ret;
}

pid_t container_run(container_run_opts *run_opts, const uid_t host_uid, const uid_t host_gid, const char *command) {
    pid_t pid;
    int unshare_flags = CLONE_NEWUSER | CLONE_NEWUTS | CLONE_NEWNS;
    unshare_flags = unshare_flags | (run_opts->detach ? 0 : SIGCHLD);
    pid = sys_clone(unshare_flags, NULL);
    if (pid < 0)
        err(EXIT_FAILURE, "clone");
    if (pid > 0)
        return pid;
    if (run_opts->detach && setsid() < 0) {
        err(EXIT_FAILURE, "setsid");
    }
    set_rootfs();
    int ret = execvp(run_opts->args[1], &run_opts->args[1]);
    if (ret < 0)
        err(EXIT_FAILURE, "execvp");
    return 0;
}

container_run_opts *parse_args(int argc, char **argv) {
    container_run_opts *opts = malloc(sizeof(container_run_opts));
    opts->detach = 0; // Initialize detach to 0
    opts->args_size = 0;
    opts->args = malloc((argc - 1) * sizeof(char*)); // Allocate memory for args

    for (uint32_t i = 1; i < argc; i++) {
        char *word = argv[i]; // Use argv[i] instead of argv[1]
        
        if (word[0] == '-') {
            // Check for flags
            if (strcmp(word, "-d") == 0) {
                opts->detach = 1; // Set detach flag
            }
            // You can add more flags here as needed
        } else {
            // Collect non-flag arguments
            opts->args[opts->args_size] = strdup(word); // Duplicate the string
            opts->args_size++;
        }
    }

    return opts;
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
    container_run_opts *run_opts = parse_args(argc, argv);
    uid_t host_uid = getuid();
    uid_t host_gid = getgid();
    int ret;
    char *command;
    if (argv[1])
        command = argv[1];
    else
        command = "bash";
    if (run_opts->detach) {
        ret = fork();
        if (ret)
            return 0;
        ret = detach_process();
        if (ret < 0)
            err(EXIT_FAILURE, "detach process");
    }
    ret = container_run(run_opts, host_uid, host_gid, command);
    set_usernamespace(ret, host_uid, host_gid);
    if (run_opts->detach) {
        FILE *pid_file = fopen("../mydaemon.pid", "w");
        if (pid_file != NULL) {
            fprintf(pid_file, "%d\n", ret);
            fclose(pid_file);
        }
        return ret;
    }
    while (1) {
        int status;
        int r = waitpid(ret, &status, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            free(run_opts);
            return EXIT_FAILURE;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status))
            free(run_opts);
            return WEXITSTATUS(status);
    }
}
