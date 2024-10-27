#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <err.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static int sys_clone(unsigned long flags, void *child_stack) {
    return (int)syscall(56, flags, child_stack);
}

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

pid_t container_run(const uint8_t detach, const uid_t host_uid, const uid_t host_gid, const char *command) {
    pid_t pid;
    int unshare_flags = CLONE_NEWUSER | CLONE_NEWUTS;
    unshare_flags = unshare_flags | (detach ? 0 : SIGCHLD);
    pid = sys_clone(unshare_flags, NULL);
    if (pid < 0)
        err(EXIT_FAILURE, "clone");
    if (pid > 0)
        return pid;
    if (detach && setsid() < 0) {
        err(EXIT_FAILURE, "setsid");
    }
    execvp(command, NULL);
    return pid;
}

int main(int argc, char *argv[]) {
    uint8_t detach = 0;
    uid_t host_uid = getuid();
    uid_t host_gid = getgid();
    int ret;
    char *command;
    if (argv[1])
        command = argv[1];
    else
        command = "bash";
    ret = container_run(detach, host_uid, host_gid, command);
    set_usernamespace(ret, host_uid, host_gid);
    printf("Container pid: %d\n ", ret);
    while (1) {
        int status;
        int r = waitpid(ret, &status, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return EXIT_FAILURE;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status))
            return WEXITSTATUS(status);
    }
    return 0;
}
