// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_uname.c - spoof uname release/version (SUSFS SPOOF_UNAME).
 *
 * Updates init_uts_ns under uts_sem (keeping uname(2), 32-bit compat uname,
 * /proc/version, and /proc/sys/kernel/osrelease|/proc/sys/kernel/version
 * consistent with one another) while keeping a PAC-safe __arm64_sys_newuname
 * inline return-stub hook (with kretprobe fallback) so any non-init UTS
 * namespace also sees the spoofed release/version.  Snapshots the real values
 * at module init so "default" and module unload restore the stock identity.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <asm/ptrace.h>
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"
#include "susfs_kprobe.h"
#include "susfs_hk.h"
#include "symbol_resolver.h"

#define SUSFS_UNAME_LEN (__NEW_UTS_LEN + 1)

static char fake_release[SUSFS_UNAME_LEN];
static char fake_version[SUSFS_UNAME_LEN];
static char orig_release[SUSFS_UNAME_LEN];
static char orig_version[SUSFS_UNAME_LEN];
static bool uname_spoof_enabled;
static DEFINE_SPINLOCK(uname_buf_lock);

static struct uts_namespace *init_uts_ns_ptr;
static struct rw_semaphore *uts_sem_ptr;

module_param_string(release, fake_release, sizeof(fake_release), 0644);
module_param_string(version, fake_version, sizeof(fake_version), 0644);
module_param(uname_spoof_enabled, bool, 0644);
MODULE_PARM_DESC(release, "fake uname release (insmod override)");
MODULE_PARM_DESC(version, "fake uname version (insmod override)");
MODULE_PARM_DESC(uname_spoof_enabled, "enable uname spoofing (insmod override)");

extern void susfs_uname_stub(void);
extern unsigned long susfs_uname_tramp;

static struct hk_inline uname_hk;
static bool uname_inline;
static bool uname_registered;
static DEFINE_MUTEX(uname_ctl_lock);

static void uname_snapshot(char *rel, char *ver)
{
	unsigned long flags;

	spin_lock_irqsave(&uname_buf_lock, flags);
	strscpy_pad(rel, fake_release, SUSFS_UNAME_LEN);
	strscpy_pad(ver, fake_version, SUSFS_UNAME_LEN);
	spin_unlock_irqrestore(&uname_buf_lock, flags);
}

static void uname_write_user(struct new_utsname __user *name, bool stop_on_fault)
{
	char rel[SUSFS_UNAME_LEN];
	char ver[SUSFS_UNAME_LEN];
	unsigned long uncopied;

	uname_snapshot(rel, ver);
	uncopied = copy_to_user((char __user *)name + offsetof(struct new_utsname, release),
				rel, SUSFS_UNAME_LEN);
	if (uncopied && stop_on_fault)
		return;
	(void)copy_to_user((char __user *)name + offsetof(struct new_utsname, version),
			   ver, SUSFS_UNAME_LEN);
}

static bool uname_apply_uts(const char *rel, const char *ver)
{
	if (!init_uts_ns_ptr || !uts_sem_ptr)
		return false;

	down_write(uts_sem_ptr);
	strscpy_pad(init_uts_ns_ptr->name.release, rel,
		    sizeof(init_uts_ns_ptr->name.release));
	strscpy_pad(init_uts_ns_ptr->name.version, ver,
		    sizeof(init_uts_ns_ptr->name.version));
	up_write(uts_sem_ptr);
	return true;
}

long __nocfi susfs_uname_decide(unsigned long *saved)
{
	const struct pt_regs *regs = saved ? (const struct pt_regs *)saved[0] : NULL;
	long ret = saved ? (long)saved[20] : -EINVAL;
	struct new_utsname __user *name;

	if (ret == 0 && READ_ONCE(uname_spoof_enabled) && regs) {
		name = (struct new_utsname __user *)regs->regs[0];
		if (name)
			uname_write_user(name, false);
	}
	return ret;
}

struct uname_args {
	struct new_utsname __user *name;
};

static int kr_newuname_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct uname_args *a = (struct uname_args *)ri->data;
	struct pt_regs *user = (struct pt_regs *)regs->regs[0];

	if (!user)
		return 1;
	a->name = (struct new_utsname __user *)user->regs[0];
	return 0;
}

static int kr_newuname_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct uname_args *a = (struct uname_args *)ri->data;

	if (!READ_ONCE(uname_spoof_enabled) || regs_return_value(regs) != 0 || !a->name)
		return 0;

	uname_write_user(a->name, true);
	return 0;
}

static struct kretprobe kr_newuname = {
	.kp.symbol_name = "__arm64_sys_newuname",
	.entry_handler = kr_newuname_entry,
	.handler = kr_newuname_ret,
	.data_size = sizeof(struct uname_args),
	.maxactive = 32,
};

static int uname_register(void)
{
	int rc;

	if (uname_registered)
		return 0;
	if (susfs_hk_ready()) {
		rc = susfs_hk_inline_hook_stub(&uname_hk, "__arm64_sys_newuname", 0,
					       susfs_uname_stub, &susfs_uname_tramp);
		if (!rc) {
			uname_inline = true;
			uname_registered = true;
			SUSFS_LOGI("uname spoof armed inline\n");
			return 0;
		}
		pr_info("susfs_uname: inline stub hook on __arm64_sys_newuname failed (%d), falling back to kretprobe\n",
			rc);
	}
	rc = register_kretprobe(&kr_newuname);
	if (rc) {
		susfs_krp_forget_addr(&kr_newuname);
		return rc;
	}
	uname_registered = true;
	return 0;
}

static void uname_pad_field(char *buf)
{
	size_t n = strnlen(buf, SUSFS_UNAME_LEN);

	if (n < SUSFS_UNAME_LEN)
		memset(buf + n, 0, SUSFS_UNAME_LEN - n);
}

int susfs_uname_init(void)
{
	const struct new_utsname *u = utsname();
	bool uts_ok = false;
	int rc;

	BUILD_BUG_ON(SUSFS_UNAME_LEN != sizeof(u->release));
	BUILD_BUG_ON(SUSFS_UNAME_LEN != sizeof(u->version));

	strscpy_pad(orig_release, u->release, sizeof(orig_release));
	strscpy_pad(orig_version, u->version, sizeof(orig_version));

	init_uts_ns_ptr = (struct uts_namespace *)find_kernel_symbol_exact("init_uts_ns");
	uts_sem_ptr = (struct rw_semaphore *)find_kernel_symbol_exact("uts_sem");

	uname_pad_field(fake_release);
	uname_pad_field(fake_version);

	if (READ_ONCE(uname_spoof_enabled) && (fake_release[0] || fake_version[0])) {
		if (!fake_release[0])
			strscpy_pad(fake_release, orig_release, sizeof(fake_release));
		if (!fake_version[0])
			strscpy_pad(fake_version, orig_version, sizeof(fake_version));
		uts_ok = uname_apply_uts(fake_release, fake_version);
		rc = uname_register();
		if (rc && !uts_ok)
			pr_warn("susfs_uname: hook(newuname) failed %d\n", rc);
		else
			SUSFS_LOGI("uname spoof armed: release=%s version=%s (uts=%s)\n",
				   fake_release, fake_version, uts_ok ? "ok" : "hook-only");
	} else {
		SUSFS_LOGI("uname spoof: disabled (enable via CMD_SUSFS_SET_UNAME; uts=%s)\n",
			   (init_uts_ns_ptr && uts_sem_ptr) ? "ready" : "hook-only");
	}
	return 0;
}

void susfs_uname_exit(void)
{
	mutex_lock(&uname_ctl_lock);
	WRITE_ONCE(uname_spoof_enabled, false);
	uname_apply_uts(orig_release, orig_version);
	if (uname_registered) {
		if (uname_inline) {
			susfs_hk_inline_unhook(&uname_hk);
			uname_inline = false;
		} else {
			unregister_kretprobe(&kr_newuname);
			susfs_krp_forget_addr(&kr_newuname);
		}
		uname_registered = false;
	}
	mutex_unlock(&uname_ctl_lock);
}

void susfs_uname_supercall(void __user **arg)
{
	struct st_susfs_uname info = { 0 };
	char new_rel[SUSFS_UNAME_LEN];
	char new_ver[SUSFS_UNAME_LEN];
	const char *rel;
	const char *ver;
	unsigned long flags;
	bool is_custom, uts_ok;
	int rc = 0;

	if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}
	if (!info.release[0] || !info.version[0]) {
		info.err = -EINVAL;
		goto out;
	}
	if (!susfs_abi_path_ok(info.release, sizeof(info.release)) ||
	    !susfs_abi_path_ok(info.version, sizeof(info.version))) {
		info.err = -ENAMETOOLONG;
		goto out;
	}

	rel = !strcmp(info.release, "default") ? orig_release : info.release;
	ver = !strcmp(info.version, "default") ? orig_version : info.version;
	strscpy_pad(new_rel, rel, sizeof(new_rel));
	strscpy_pad(new_ver, ver, sizeof(new_ver));
	is_custom = strcmp(new_rel, orig_release) || strcmp(new_ver, orig_version);

	mutex_lock(&uname_ctl_lock);
	spin_lock_irqsave(&uname_buf_lock, flags);
	strscpy_pad(fake_release, new_rel, sizeof(fake_release));
	strscpy_pad(fake_version, new_ver, sizeof(fake_version));
	spin_unlock_irqrestore(&uname_buf_lock, flags);

	uts_ok = uname_apply_uts(new_rel, new_ver);
	WRITE_ONCE(uname_spoof_enabled, is_custom);
	if (is_custom) {
		rc = uname_register();
		if (rc && uts_ok) {
			pr_warn("susfs_uname: hook(newuname) failed %d (init_uts_ns updated)\n", rc);
			rc = 0;
		}
	}
	info.err = rc;
	if (!rc) {
		if (is_custom)
			SUSFS_LOGI("uname spoof set: release=%s version=%s (uts=%s)\n",
				   new_rel, new_ver, uts_ok ? "ok" : "hook-only");
		else
			SUSFS_LOGI("uname spoof reset to stock: release=%s version=%s\n",
				   new_rel, new_ver);
	}
	mutex_unlock(&uname_ctl_lock);
out:
	if (copy_to_user(&((struct st_susfs_uname __user *)*arg)->err,
			 &info.err, sizeof(info.err)))
		pr_warn("uname supercall copy_to_user failed\n");
}
