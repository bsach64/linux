// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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

static char mntpoint[] = "/tmp/statmount_test_root.XXXXXX";

static void test_statmount_by_fd_unmounted_mnt_point(void)
{
	struct statmount *sm;
	char path[PATH_MAX];
	int fd;

	if (!mkdtemp(mntpoint)) {
		ksft_exit_fail_msg("failed to create temporary mountpoint: %s\n",
				   strerror(errno));
	}

	if (mount("none", mntpoint, "tmpfs", 0, NULL)) {
		ksft_exit_fail_msg("failed to mount temporary mountpoint: %s\n",
				   strerror(errno));
	}

	snprintf(path, PATH_MAX, "%s/%s", mntpoint, "file");

	fd = open(path, O_CREAT);
	if (fd < 0) {
		ksft_exit_fail_msg("failed to open file: %s\n",
				   strerror(errno));
	}

	if (umount2(mntpoint, MNT_DETACH)) {
		ksft_exit_fail_msg("failed to lazily unmount: %s\n",
				   strerror(errno));
	}

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
	if (strcmp(sm->str + sm->mnt_point, "[unmounted]") != 0) {
		ksft_test_result_fail("unexpected mount point: '%s' != '[unmounted]'\n",
				      sm->str + sm->mnt_point);
		goto out;
	}
	ksft_test_result_pass("statmount mount point\n");
out:
	close(fd);
	rmdir(mntpoint);
	free(sm);
}

int main(void)
{
	int ret;

	ksft_print_header();

	ret = statmount_by_fd(0, 0, NULL, 0);
	if (ret == -1 && (errno == ENOSYS || errno == EINVAL))
		ksft_exit_skip("statmount()  syscall with STATMOUNT_BY_FD not supported\n");

	ksft_set_plan(1);
	test_statmount_by_fd_unmounted_mnt_point();

	if (ksft_get_fail_cnt() + ksft_get_error_cnt() > 0)
		ksft_exit_fail();
	else
		ksft_exit_pass();
}
