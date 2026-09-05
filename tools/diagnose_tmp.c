#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

static int fail_count = 0;

static void report_errno(const char *step, int err) {
    fprintf(stderr, "FAIL|%s|errno=%d|%s\n", step, err, strerror(err));
    fail_count++;
}

static void report_ok(const char *step, const char *detail) {
    printf("PASS|%s|%s\n", step, detail ? detail : "ok");
}

static const char *fs_name(long type) {
    switch ((unsigned long)type) {
    case TMPFS_MAGIC:
        return "tmpfs";
    case EXT4_SUPER_MAGIC:
        return "ext4";
    case OVERLAYFS_SUPER_MAGIC:
        return "overlay";
    case FUSE_SUPER_MAGIC:
        return "fuse";
    case NFS_SUPER_MAGIC:
        return "nfs";
    case XFS_SUPER_MAGIC:
        return "xfs";
    case BTRFS_SUPER_MAGIC:
        return "btrfs";
    case RAMFS_MAGIC:
        return "ramfs";
    default:
        return "unknown";
    }
}

static int path_is_directory(const char *path, struct stat *st) {
    if (stat(path, st) != 0) {
        report_errno("stat", errno);
        return -1;
    }
    if (!S_ISDIR(st->st_mode)) {
        fprintf(stderr, "FAIL|directory|mode=%o|not-a-directory\n", st->st_mode);
        fail_count++;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *base = argc > 1 ? argv[1] : "/tmp";
    char real_base[PATH_MAX];
    char templ[PATH_MAX];
    char probe_file[PATH_MAX];
    char renamed_file[PATH_MAX];
    struct stat st;
    struct statfs sfs;
    uid_t uid = geteuid();
    gid_t gid = getegid();

    printf("INFO|base|%s\n", base);
    printf("INFO|uid_gid|%u:%u\n", (unsigned)uid, (unsigned)gid);
    printf("INFO|abi|sizeof(off_t)=%zu|sizeof(time_t)=%zu|sizeof(void*)=%zu|file_offset_bits=%d\n", sizeof(off_t),
           sizeof(time_t), sizeof(void *), _FILE_OFFSET_BITS);

    if (!realpath(base, real_base)) {
        report_errno("realpath", errno);
        return 2;
    }
    report_ok("realpath", real_base);

    if (path_is_directory(real_base, &st) != 0)
        return 2;
    printf("INFO|directory_stat|mode=%04o|uid=%u|gid=%u|dev=%ju|ino=%ju\n", st.st_mode & 07777, (unsigned)st.st_uid,
           (unsigned)st.st_gid, (uintmax_t)st.st_dev, (uintmax_t)st.st_ino);
    if ((st.st_mode & S_ISVTX) == 0) {
        fprintf(stderr, "WARN|sticky-bit|mode=%04o|directory-is-not-sticky\n", st.st_mode & 07777);
    } else {
        report_ok("sticky-bit", "set");
    }
    if (access(real_base, R_OK | W_OK | X_OK) != 0)
        report_errno("access-rwx", errno);
    else
        report_ok("access-rwx", "read-write-search allowed");

    if (statfs(real_base, &sfs) != 0)
        report_errno("statfs", errno);
    else {
        printf("INFO|statfs|type=0x%lx|name=%s|bsize=%lu|blocks=%ju|bfree=%ju|bavail=%ju|flags=0x%lx\n",
               (unsigned long)sfs.f_type, fs_name(sfs.f_type), (unsigned long)sfs.f_bsize, (uintmax_t)sfs.f_blocks,
               (uintmax_t)sfs.f_bfree, (uintmax_t)sfs.f_bavail, (unsigned long)sfs.f_flags);
        if (sfs.f_bavail == 0) {
            fprintf(stderr, "FAIL|space|f_bavail=0|filesystem-reported-no-free-blocks\n");
            fail_count++;
        }
    }

    int n = snprintf(templ, sizeof(templ), "%s/nuk4sd-mkdtemp-XXXXXX", real_base);
    if (n < 0 || (size_t)n >= sizeof(templ)) {
        report_errno("template", ENAMETOOLONG);
        return 2;
    }
    errno = 0;
    char *created = mkdtemp(templ);
    if (!created) {
        report_errno("mkdtemp", errno);
        printf("INFO|mkdtemp_template|%s\n", templ);
        return 1;
    }
    report_ok("mkdtemp", created);

    if (stat(created, &st) != 0)
        report_errno("created-stat", errno);
    else {
        printf("INFO|created_stat|mode=%04o|uid=%u|gid=%u|dev=%ju|ino=%ju\n", st.st_mode & 07777, (unsigned)st.st_uid,
               (unsigned)st.st_gid, (uintmax_t)st.st_dev, (uintmax_t)st.st_ino);
        if (st.st_uid != uid || st.st_gid != gid) {
            fprintf(stderr, "FAIL|created-owner|expected=%u:%u|actual=%u:%u\n", (unsigned)uid, (unsigned)gid,
                    (unsigned)st.st_uid, (unsigned)st.st_gid);
            fail_count++;
        } else
            report_ok("created-owner", "matches-effective-uid-gid");
    }

    n = snprintf(probe_file, sizeof(probe_file), "%s/probe-file", created);
    if (n < 0 || (size_t)n >= sizeof(probe_file)) {
        report_errno("probe-path", ENAMETOOLONG);
        rmdir(created);
        return 2;
    }
    int fd = open(probe_file, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0)
        report_errno("create-file", errno);
    else {
        const char payload[] = "nuk4sd mkdtemp diagnostic\n";
        ssize_t written = write(fd, payload, sizeof(payload) - 1);
        int saved = errno;
        close(fd);
        if (written != (ssize_t)(sizeof(payload) - 1))
            report_errno("write-file", saved);
        else
            report_ok("create-write-file", probe_file);
    }

    n = snprintf(renamed_file, sizeof(renamed_file), "%s/probe-file-renamed", created);
    if (n < 0 || (size_t)n >= sizeof(renamed_file)) {
        report_errno("rename-path", ENAMETOOLONG);
    } else if (rename(probe_file, renamed_file) != 0) {
        report_errno("rename-file", errno);
    } else
        report_ok("rename-file", renamed_file);

    if (unlink(renamed_file) != 0 && errno != ENOENT)
        report_errno("unlink-file", errno);
    else
        report_ok("unlink-file", "removed");
    if (rmdir(created) != 0)
        report_errno("rmdir", errno);
    else
        report_ok("rmdir", "removed");

    printf("SUMMARY|fails=%d\n", fail_count);
    return fail_count ? 1 : 0;
}
