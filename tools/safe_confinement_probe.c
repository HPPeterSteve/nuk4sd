#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int check_denied(const char *name, int rc, int expected_errno) {
    if (rc == -1 && (errno == expected_errno || expected_errno == 0)) {
        printf("PASS|%s|blocked|errno=%d|%s\n", name, errno, strerror(errno));
        return 0;
    }
    printf("FAIL|%s|unexpected-result|rc=%d|errno=%d|%s\n", name, rc, errno, strerror(errno));
    return 1;
}

static int check_open_denied(const char *name, const char *path) {
    errno = 0;
    int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd >= 0) {
        close(fd);
        printf("FAIL|%s|write-open-succeeded|path=%s\n", name, path);
        return 1;
    }
    printf("PASS|%s|blocked|path=%s|errno=%d|%s\n", name, path, errno, strerror(errno));
    return 0;
}

int main(void) {
    int fails = 0;
    char tmp_template[] = "/tmp/nuk4sd-safe-probe-XXXXXX";
    char *owned_tmp = mkdtemp(tmp_template);
    if (!owned_tmp) {
        printf("FAIL|probe_workspace|mkdtemp|errno=%d|%s\n", errno, strerror(errno));
        return 2;
    }
    printf("INFO|workspace|%s\n", owned_tmp);

    struct stat st;
    if (stat("/tmp", &st) == 0)
        printf("INFO|tmp|mode=%o|uid=%u|gid=%u\n", st.st_mode & 07777, (unsigned)st.st_uid, (unsigned)st.st_gid);

    fails += check_open_denied("host_etc_hosts_write", "/etc/hosts");
    fails += check_open_denied("host_etc_passwd_write", "/etc/passwd");
    fails += check_open_denied("host_proc_1_root_write", "/proc/1/root/etc/hosts");
    fails += check_open_denied("device_mem_write", "/dev/mem");

    errno = 0;
    int fd = open("/proc/kcore", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        close(fd);
        printf("FAIL|proc_kcore_read|opened\n");
        fails++;
    } else {
        printf("PASS|proc_kcore_read|blocked|errno=%d|%s\n", errno, strerror(errno));
    }

    errno = 0;
    int p = ptrace(PTRACE_ATTACH, 1, NULL, NULL);
    if (p == 0) {
        (void)ptrace(PTRACE_DETACH, 1, NULL, NULL);
        printf("FAIL|ptrace_pid1|attach-succeeded\n");
        fails++;
    } else {
        printf("PASS|ptrace_pid1|blocked|errno=%d|%s\n", errno, strerror(errno));
    }

    errno = 0;
    int u = unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID);
    fails += check_denied("unshare_nested_namespaces", u, 0);

    errno = 0;
    int sh = sethostname("nuk4sd-probe", 12);
    fails += check_denied("sethostname", sh, 0);

    char mount_target[4096];
    snprintf(mount_target, sizeof(mount_target), "%s/mount-target", owned_tmp);
    if (mkdir(mount_target, 0700) != 0) {
        printf("FAIL|private_workspace|mkdir|errno=%d|%s\n", errno, strerror(errno));
        fails++;
    } else {
        errno = 0;
        int m = mount("nuk4sd-probe", mount_target, "tmpfs", MS_NOSUID | MS_NODEV, "size=4m,mode=700");
        if (m == 0) {
            (void)umount2(mount_target, MNT_DETACH);
            printf("FAIL|mount_tmpfs|unexpectedly-succeeded\n");
            fails++;
        } else {
            printf("PASS|mount_tmpfs|blocked|errno=%d|%s\n", errno, strerror(errno));
        }
        rmdir(mount_target);
    }

    char owned_file[4096];
    snprintf(owned_file, sizeof(owned_file), "%s/owned-file", owned_tmp);
    fd = open(owned_file, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) {
        printf("FAIL|private_write|open|errno=%d|%s\n", errno, strerror(errno));
        fails++;
    } else {
        const char marker[] = "safe-probe\n";
        if (write(fd, marker, sizeof(marker) - 1) != (ssize_t)(sizeof(marker) - 1)) {
            printf("FAIL|private_write|write|errno=%d|%s\n", errno, strerror(errno));
            fails++;
        } else {
            printf("PASS|private_write|owned-workspace-only\n");
        }
        close(fd);
        unlink(owned_file);
    }

    if (rmdir(owned_tmp) != 0) {
        printf("FAIL|cleanup|rmdir|errno=%d|%s\n", errno, strerror(errno));
        fails++;
    } else {
        printf("PASS|cleanup|removed-owned-workspace\n");
    }
    printf("SUMMARY|fails=%d\n", fails);
    return fails ? 1 : 0;
}
