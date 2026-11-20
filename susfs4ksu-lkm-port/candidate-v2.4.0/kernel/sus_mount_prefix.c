/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * sus_mount_prefix.c - the hide-mount prefix table
 *
 * The table is the data layer: matching is anchored strncmp against stored
 * prefixes, never a substring search.  The proc/sysfs command parser stays in
 * sus_mount.c; it stages into a local array and commits it here.
 */

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

#include "sus_mount_prefix.h"

static char mount_keep[SUS_MOUNT_KEEP_MAX][SUS_MOUNT_KEEP_LEN];
static int n_mount_keep;
static DEFINE_SPINLOCK(mount_keep_lock);
static const char mount_keep_default[] = "/data/adb/";

int sus_mount_prefix_commit(char dst[][SUS_MOUNT_KEEP_LEN], int n)
{
	unsigned long flags;

	if (n < 0)
		return -EINVAL;
	if (n > SUS_MOUNT_KEEP_MAX)
		n = SUS_MOUNT_KEEP_MAX;
	spin_lock_irqsave(&mount_keep_lock, flags);
	memset(mount_keep, 0, sizeof(mount_keep));
	if (n > 0)
		memcpy(mount_keep, dst, (size_t)n * SUS_MOUNT_KEEP_LEN);
	n_mount_keep = n;
	spin_unlock_irqrestore(&mount_keep_lock, flags);
	return n;
}

int sus_mount_prefix_snapshot(char dst[][SUS_MOUNT_KEEP_LEN])
{
	unsigned long flags;
	int n;

	if (!dst)
		return 0;
	spin_lock_irqsave(&mount_keep_lock, flags);
	n = n_mount_keep;
	if (n > SUS_MOUNT_KEEP_MAX)
		n = SUS_MOUNT_KEEP_MAX;
	if (n > 0)
		memcpy(dst, mount_keep, (size_t)n * SUS_MOUNT_KEEP_LEN);
	spin_unlock_irqrestore(&mount_keep_lock, flags);
	return n;
}

int sus_mount_prefix_count(void)
{
	return READ_ONCE(n_mount_keep);
}

static bool sus_mount_prefix_match_impl(const char *s, bool match_data_root)
{
	unsigned long flags;
	bool hit = false;
	int i;

	if (!s)
		return false;
	spin_lock_irqsave(&mount_keep_lock, flags);
	for (i = 0; i < n_mount_keep; i++) {
		size_t len = strlen(mount_keep[i]);

		if (!len)
			continue;
		if (!strncmp(s, mount_keep[i], len)) {
			hit = true;
			break;
		}
		/* Bind mounts originating under /data/<subpath> expose /<subpath> as
		 * dentry_path_raw(mnt->mnt_root) because /data is a separate superblock. */
		if (match_data_root && len > 6 && !strncmp(mount_keep[i], "/data/", 6) &&
		    !strncmp(s, mount_keep[i] + 5, len - 5)) {
			hit = true;
			break;
		}
	}
	spin_unlock_irqrestore(&mount_keep_lock, flags);
	return hit;
}

bool sus_mount_prefix_match(const char *s)
{
	return sus_mount_prefix_match_impl(s, false);
}

bool sus_mount_prefix_match_root(const char *s)
{
	return sus_mount_prefix_match_impl(s, true);
}

const char *sus_mount_prefix_default(void)
{
	return mount_keep_default;
}
