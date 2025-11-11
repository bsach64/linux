// SPDX-License-Identifier: GPL-2.0-or-later

#define _GNU_SOURCE

#include <assert.h>
#include <stddef.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <linux/stat.h>

#include "statmount.h"
#include "../../kselftest.h"

static const char *const known_fs[] = {
	"9p", "adfs", "affs", "afs", "aio", "anon_inodefs", "apparmorfs",
	"autofs", "bcachefs", "bdev", "befs", "bfs", "binder", "binfmt_misc",
	"bpf", "btrfs", "btrfs_test_fs", "ceph", "cgroup", "cgroup2", "cifs",
	"coda", "configfs", "cpuset", "cramfs", "cxl", "dax", "debugfs",
	"devpts", "devtmpfs", "dmabuf", "drm", "ecryptfs", "efivarfs", "efs",
	"erofs", "exfat", "ext2", "ext3", "ext4", "f2fs", "functionfs",
	"fuse", "fuseblk", "fusectl", "gadgetfs", "gfs2", "gfs2meta", "hfs",
	"hfsplus", "hostfs", "hpfs", "hugetlbfs", "ibmasmfs", "iomem",
	"ipathfs", "iso9660", "jffs2", "jfs", "minix", "mqueue", "msdos",
	"nfs", "nfs4", "nfsd", "nilfs2", "nsfs", "ntfs", "ntfs3", "ocfs2",
	"ocfs2_dlmfs", "omfs", "openpromfs", "overlay", "pipefs", "proc",
	"pstore", "pvfs2", "qnx4", "qnx6", "ramfs", "resctrl", "romfs",
	"rootfs", "rpc_pipefs", "s390_hypfs", "secretmem", "securityfs",
	"selinuxfs", "smackfs", "smb3", "sockfs", "spufs", "squashfs", "sysfs",
	"sysv", "tmpfs", "tracefs", "ubifs", "udf", "ufs", "v7", "vboxsf",
	"vfat", "virtiofs", "vxfs", "xenfs", "xfs", "zonefs", NULL };

static struct statmount *statmount_by_fd_alloc(int fd, uint64_t mask)
{
	size_t bufsize = 1 << 15;
	struct statmount *buf = NULL, *tmp = alloca(bufsize);
	int tofree = 0;
	int ret;

	for (;;) {
		ret = statmount_by_fd(fd, mask, tmp, bufsize);
		if (ret != -1)
			break;
		if (tofree)
			free(tmp);
		if (errno != EOVERFLOW)
			return NULL;
		bufsize <<= 1;
		tofree = 1;
		tmp = malloc(bufsize);
		if (!tmp)
			return NULL;
	}
	buf = malloc(tmp->size);
	if (buf)
		memcpy(buf, tmp, tmp->size);
	if (tofree)
		free(tmp);

	return buf;
}

static void write_file(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	size_t len = strlen(val);
	int ret;

	if (fd == -1)
		ksft_exit_fail_msg("opening %s for write: %s\n", path, strerror(errno));

	ret = write(fd, val, len);
	if (ret == -1)
		ksft_exit_fail_msg("writing to %s: %s\n", path, strerror(errno));
	if (ret != len)
		ksft_exit_fail_msg("short write to %s\n", path);

	ret = close(fd);
	if (ret == -1)
		ksft_exit_fail_msg("closing %s\n", path);
}

static uint64_t get_mnt_id(const char *name, const char *path, uint64_t mask)
{
	struct statx sx;
	int ret;

	ret = statx(AT_FDCWD, path, 0, mask, &sx);
	if (ret == -1)
		ksft_exit_fail_msg("retrieving %s mount ID for %s: %s\n",
				   mask & STATX_MNT_ID_UNIQUE ? "unique" : "old",
				   name, strerror(errno));
	if (!(sx.stx_mask & mask))
		ksft_exit_fail_msg("no %s mount ID available for %s\n",
				   mask & STATX_MNT_ID_UNIQUE ? "unique" : "old",
				   name);

	return sx.stx_mnt_id;
}


static char root_mntpoint[] = "/tmp/statmount_test_root.XXXXXX";
static int orig_root;
static uint64_t root_id, parent_id;
static uint32_t old_root_id, old_parent_id;
static FILE *f_mountinfo;
static int fd;

static void cleanup_namespace(void)
{
	int ret;

	ret = fchdir(orig_root);
	if (ret == -1)
		ksft_perror("fchdir to original root");

	ret = chroot(".");
	if (ret == -1)
		ksft_perror("chroot to original root");

	umount2(root_mntpoint, MNT_DETACH);
	rmdir(root_mntpoint);
	close(fd);
}

static void setup_namespace(void)
{
	int ret;
	char buf[32];
	uid_t uid = getuid();
	gid_t gid = getgid();

	ret = unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWPID);
	if (ret == -1)
		ksft_exit_fail_msg("unsharing mountns and userns: %s\n",
				   strerror(errno));

	sprintf(buf, "0 %d 1", uid);
	write_file("/proc/self/uid_map", buf);
	write_file("/proc/self/setgroups", "deny");
	sprintf(buf, "0 %d 1", gid);
	write_file("/proc/self/gid_map", buf);

	f_mountinfo = fopen("/proc/self/mountinfo", "re");
	if (!f_mountinfo)
		ksft_exit_fail_msg("failed to open mountinfo: %s\n",
				   strerror(errno));

	ret = mount("", "/", NULL, MS_REC|MS_PRIVATE, NULL);
	if (ret == -1)
		ksft_exit_fail_msg("making mount tree private: %s\n",
				   strerror(errno));

	if (!mkdtemp(root_mntpoint))
		ksft_exit_fail_msg("creating temporary directory %s: %s\n",
				   root_mntpoint, strerror(errno));

	old_parent_id = get_mnt_id("parent", root_mntpoint, STATX_MNT_ID);
	parent_id = get_mnt_id("parent", root_mntpoint, STATX_MNT_ID_UNIQUE);

	orig_root = open("/", O_PATH);
	if (orig_root == -1)
		ksft_exit_fail_msg("opening root directory: %s",
				   strerror(errno));

	atexit(cleanup_namespace);

	ret = mount(root_mntpoint, root_mntpoint, NULL, MS_BIND, NULL);
	if (ret == -1)
		ksft_exit_fail_msg("mounting temp root %s: %s\n",
				   root_mntpoint, strerror(errno));

	ret = chroot(root_mntpoint);
	if (ret == -1)
		ksft_exit_fail_msg("chroot to temp root %s: %s\n",
				   root_mntpoint, strerror(errno));

	ret = chdir("/");
	if (ret == -1)
		ksft_exit_fail_msg("chdir to root: %s\n", strerror(errno));

	old_root_id = get_mnt_id("root", "/", STATX_MNT_ID);
	root_id = get_mnt_id("root", "/", STATX_MNT_ID_UNIQUE);

	fd = open("/tmp_file", O_CREAT | O_RDWR);
	if (fd < 0)
		ksft_exit_fail_msg("could not open fd: %s\n", strerror(errno));
}

static void test_statmount_by_fd_zero_mask(void)
{
	struct statmount sm;
	int ret;

	ret = statmount_by_fd(fd, 0, &sm, sizeof(sm));
	if (ret == -1) {
		ksft_test_result_fail("statmount zero mask: %s\n",
				      strerror(errno));
		return;
	}
	if (sm.size != sizeof(sm)) {
		ksft_test_result_fail("unexpected size: %u != %u\n",
				      sm.size, (uint32_t) sizeof(sm));
		return;
	}
	if (sm.mask != 0) {
		ksft_test_result_fail("unexpected mask: 0x%llx != 0x0\n",
				      (unsigned long long) sm.mask);
		return;
	}

	ksft_test_result_pass("statmount zero mask\n");
}

static void test_statmount_by_fd_mnt_basic(void)
{
	struct statmount sm;
	int ret;
	uint64_t mask = STATMOUNT_MNT_BASIC;

	ret = statmount_by_fd(fd, mask, &sm, sizeof(sm));
	if (ret == -1) {
		ksft_test_result_fail("statmount mnt basic: %s\n",
				      strerror(errno));
		return;
	}
	if (sm.size != sizeof(sm)) {
		ksft_test_result_fail("unexpected size: %u != %u\n",
				      sm.size, (uint32_t) sizeof(sm));
		return;
	}
	if (sm.mask != mask) {
		ksft_test_result_skip("statmount mnt basic unavailable\n");
		return;
	}

	if (sm.mnt_id != root_id) {
		ksft_test_result_fail("unexpected root ID: 0x%llx != 0x%llx\n",
				      (unsigned long long) sm.mnt_id,
				      (unsigned long long) root_id);
		return;
	}

	if (sm.mnt_id_old != old_root_id) {
		ksft_test_result_fail("unexpected old root ID: %u != %u\n",
				      sm.mnt_id_old, old_root_id);
		return;
	}

	if (sm.mnt_parent_id != parent_id) {
		ksft_test_result_fail("unexpected parent ID: 0x%llx != 0x%llx\n",
				      (unsigned long long) sm.mnt_parent_id,
				      (unsigned long long) parent_id);
		return;
	}

	if (sm.mnt_parent_id_old != old_parent_id) {
		ksft_test_result_fail("unexpected old parent ID: %u != %u\n",
				      sm.mnt_parent_id_old, old_parent_id);
		return;
	}

	if (sm.mnt_propagation != MS_PRIVATE) {
		ksft_test_result_fail("unexpected propagation: 0x%llx\n",
				      (unsigned long long) sm.mnt_propagation);
		return;
	}

	ksft_test_result_pass("statmount mnt basic\n");
}


static void test_statmount_by_fd_sb_basic(void)
{
	struct statmount sm;
	int ret;
	uint64_t mask = STATMOUNT_SB_BASIC;
	struct statx sx;
	struct statfs sf;

	ret = statmount_by_fd(fd, mask, &sm, sizeof(sm));
	if (ret == -1) {
		ksft_test_result_fail("statmount sb basic: %s\n",
				      strerror(errno));
		return;
	}
	if (sm.size != sizeof(sm)) {
		ksft_test_result_fail("unexpected size: %u != %u\n",
				      sm.size, (uint32_t) sizeof(sm));
		return;
	}
	if (sm.mask != mask) {
		ksft_test_result_skip("statmount sb basic unavailable\n");
		return;
	}

	ret = statx(AT_FDCWD, "/", 0, 0, &sx);
	if (ret == -1) {
		ksft_test_result_fail("stat root failed: %s\n",
				      strerror(errno));
		return;
	}

	if (sm.sb_dev_major != sx.stx_dev_major ||
	    sm.sb_dev_minor != sx.stx_dev_minor) {
		ksft_test_result_fail("unexpected sb dev %u:%u != %u:%u\n",
				      sm.sb_dev_major, sm.sb_dev_minor,
				      sx.stx_dev_major, sx.stx_dev_minor);
		return;
	}

	ret = statfs("/", &sf);
	if (ret == -1) {
		ksft_test_result_fail("statfs root failed: %s\n",
				      strerror(errno));
		return;
	}

	if (sm.sb_magic != sf.f_type) {
		ksft_test_result_fail("unexpected sb magic: 0x%llx != 0x%lx\n",
				      (unsigned long long) sm.sb_magic,
				      sf.f_type);
		return;
	}

	ksft_test_result_pass("statmount sb basic\n");
}

static void test_statmount_by_fd_mnt_point(void)
{
	struct statmount *sm;

	sm = statmount_by_fd_alloc(fd, STATMOUNT_MNT_POINT);
	if (!sm) {
		ksft_test_result_fail("statmount mount point: %s\n",
				      strerror(errno));
		return;
	}

	if (!(sm->mask & STATMOUNT_MNT_POINT)) {
		ksft_test_result_fail("missing STATMOUNT_MNT_POINT in mask\n");
		return;
	}
	if (strcmp(sm->str + sm->mnt_point, "/") != 0) {
		ksft_test_result_fail("unexpected mount point: '%s' != '/'\n",
				      sm->str + sm->mnt_point);
		goto out;
	}
	ksft_test_result_pass("statmount mount point\n");
out:
	free(sm);
}

static void test_statmount_by_fd_mnt_root(void)
{
	struct statmount *sm;
	const char *mnt_root, *last_dir, *last_root;

	last_dir = strrchr(root_mntpoint, '/');
	assert(last_dir);
	last_dir++;

	sm = statmount_by_fd_alloc(fd, STATMOUNT_MNT_ROOT);
	if (!sm) {
		ksft_test_result_fail("statmount mount root: %s\n",
				      strerror(errno));
		return;
	}
	if (!(sm->mask & STATMOUNT_MNT_ROOT)) {
		ksft_test_result_fail("missing STATMOUNT_MNT_ROOT in mask\n");
		return;
	}
	mnt_root = sm->str + sm->mnt_root;
	last_root = strrchr(mnt_root, '/');
	if (last_root)
		last_root++;
	else
		last_root = mnt_root;

	if (strcmp(last_dir, last_root) != 0) {
		ksft_test_result_fail("unexpected mount root last component: '%s' != '%s'\n",
				      last_root, last_dir);
		goto out;
	}
	ksft_test_result_pass("statmount mount root\n");
out:
	free(sm);
}

static void test_statmount_by_fd_fs_type(void)
{
	struct statmount *sm;
	const char *fs_type;
	const char *const *s;

	sm = statmount_by_fd_alloc(fd, STATMOUNT_FS_TYPE);
	if (!sm) {
		ksft_test_result_fail("statmount fs type: %s\n",
				      strerror(errno));
		return;
	}
	if (!(sm->mask & STATMOUNT_FS_TYPE)) {
		ksft_test_result_fail("missing STATMOUNT_FS_TYPE in mask\n");
		return;
	}
	fs_type = sm->str + sm->fs_type;
	for (s = known_fs; s != NULL; s++) {
		if (strcmp(fs_type, *s) == 0)
			break;
	}
	if (!s)
		ksft_print_msg("unknown filesystem type: %s\n", fs_type);

	ksft_test_result_pass("statmount fs type\n");
	free(sm);
}

static void test_statmount_by_fd_mnt_opts(void)
{
	struct statmount *sm;
	const char *statmount_opts;
	char *line = NULL;
	size_t len = 0;

	sm = statmount_by_fd_alloc(fd, STATMOUNT_MNT_BASIC | STATMOUNT_MNT_OPTS);
	if (!sm) {
		ksft_test_result_fail("statmount mnt opts: %s\n",
				      strerror(errno));
		return;
	}

	if (!(sm->mask & STATMOUNT_MNT_BASIC)) {
		ksft_test_result_fail("missing STATMOUNT_MNT_BASIC in mask\n");
		return;
	}

	while (getline(&line, &len, f_mountinfo) != -1) {
		int i;
		char *p, *p2;
		unsigned int old_mnt_id;

		old_mnt_id = atoi(line);
		if (old_mnt_id != sm->mnt_id_old)
			continue;

		for (p = line, i = 0; p && i < 5; i++)
			p = strchr(p + 1, ' ');
		if (!p)
			continue;

		p2 = strchr(p + 1, ' ');
		if (!p2)
			continue;
		*p2 = '\0';
		p = strchr(p2 + 1, '-');
		if (!p)
			continue;
		for (p++, i = 0; p && i < 2; i++)
			p = strchr(p + 1, ' ');
		if (!p)
			continue;
		p++;

		/* skip generic superblock options */
		if (strncmp(p, "ro", 2) == 0)
			p += 2;
		else if (strncmp(p, "rw", 2) == 0)
			p += 2;
		if (*p == ',')
			p++;
		if (strncmp(p, "sync", 4) == 0)
			p += 4;
		if (*p == ',')
			p++;
		if (strncmp(p, "dirsync", 7) == 0)
			p += 7;
		if (*p == ',')
			p++;
		if (strncmp(p, "lazytime", 8) == 0)
			p += 8;
		if (*p == ',')
			p++;
		p2 = strrchr(p, '\n');
		if (p2)
			*p2 = '\0';

		if (sm->mask & STATMOUNT_MNT_OPTS)
			statmount_opts = sm->str + sm->mnt_opts;
		else
			statmount_opts = "";
		if (strcmp(statmount_opts, p) != 0)
			ksft_test_result_fail(
				"unexpected mount options: '%s' != '%s'\n",
				statmount_opts, p);
		else
			ksft_test_result_pass("statmount mount options\n");
		free(sm);
		free(line);
		return;
	}

	ksft_test_result_fail("didnt't find mount entry\n");
	free(sm);
	free(line);
}

static void test_statmount_by_fd_string(uint64_t mask, size_t off, const char *name)
{
	struct statmount *sm;
	size_t len, shortsize, exactsize;
	uint32_t start, i;
	int ret;

	sm = statmount_by_fd_alloc(fd, mask);
	if (!sm) {
		ksft_test_result_fail("statmount %s: %s\n", name,
				      strerror(errno));
		goto out;
	}
	if (sm->size < sizeof(*sm)) {
		ksft_test_result_fail("unexpected size: %u < %u\n",
				      sm->size, (uint32_t) sizeof(*sm));
		goto out;
	}
	if (sm->mask != mask) {
		ksft_test_result_skip("statmount %s unavailable\n", name);
		goto out;
	}
	len = sm->size - sizeof(*sm);
	start = ((uint32_t *) sm)[off];

	for (i = start;; i++) {
		if (i >= len) {
			ksft_test_result_fail("string out of bounds\n");
			goto out;
		}
		if (!sm->str[i])
			break;
	}
	exactsize = sm->size;
	shortsize = sizeof(*sm) + i;

	ret = statmount(root_id, 0, mask, sm, exactsize, 0);
	if (ret == -1) {
		ksft_test_result_fail("statmount exact size: %s\n",
				      strerror(errno));
		goto out;
	}
	errno = 0;
	ret = statmount(root_id, 0, mask, sm, shortsize, 0);
	if (ret != -1 || errno != EOVERFLOW) {
		ksft_test_result_fail("should have failed with EOVERFLOW: %s\n",
				      strerror(errno));
		goto out;
	}

	ksft_test_result_pass("statmount string %s\n", name);
out:
	free(sm);
}

#define str_off(memb) (offsetof(struct statmount, memb) / sizeof(uint32_t))

int main(void)
{
	int ret;
	uint64_t all_mask = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC |
		STATMOUNT_PROPAGATE_FROM | STATMOUNT_MNT_ROOT |
		STATMOUNT_MNT_POINT | STATMOUNT_FS_TYPE | STATMOUNT_MNT_NS_ID;

	ksft_print_header();

	ret = statmount_by_fd(0, 0, NULL, 0);
	if (ret == -1 && (errno == ENOSYS || errno == EINVAL))
		ksft_exit_skip("statmount()  syscall with STATMOUNT_BY_FD not supported\n");

	setup_namespace();

	ksft_set_plan(14);
	test_statmount_by_fd_zero_mask();
	test_statmount_by_fd_mnt_basic();
	test_statmount_by_fd_sb_basic();
	test_statmount_by_fd_mnt_root();
	test_statmount_by_fd_mnt_point();
	test_statmount_by_fd_fs_type();
	test_statmount_by_fd_mnt_opts();
	test_statmount_by_fd_string(STATMOUNT_MNT_ROOT, str_off(mnt_root), "mount root");
	test_statmount_by_fd_string(STATMOUNT_MNT_POINT, str_off(mnt_point), "mount point");
	test_statmount_by_fd_string(STATMOUNT_FS_TYPE, str_off(fs_type), "fs type");
	test_statmount_by_fd_string(all_mask, str_off(mnt_root), "mount root & all");
	test_statmount_by_fd_string(all_mask, str_off(mnt_point), "mount point & all");
	test_statmount_by_fd_string(all_mask, str_off(fs_type), "fs type & all");

	if (ksft_get_fail_cnt() + ksft_get_error_cnt() > 0)
		ksft_exit_fail();
	else
		ksft_exit_pass();
}
