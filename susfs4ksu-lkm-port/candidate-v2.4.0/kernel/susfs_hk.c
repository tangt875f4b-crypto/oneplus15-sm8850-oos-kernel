// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_hk.c - shared HooKern lifecycle and symbol bridge for susfs_guard_lkm.
 *
 * Keeps a single hk_init()/hk_exit() lifetime owned by susfs_main.c so multiple
 * layers (sus_mount, susfs_hide_syms, susfs_uname) can share HooKern inline
 * detours while automatically falling back to kprobes/kretprobes if inline
 * installation fails on any symbol or kernel build.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "hk.h"
#include "susfs_hk.h"
#include "susfs_log.h"
#include "symbol_resolver.h"

static DEFINE_MUTEX(susfs_hk_ctl_lock);
static DEFINE_SPINLOCK(susfs_hk_sym_lock);

static bool susfs_hk_armed;

static char cur_wrap_name[96];
static unsigned long cur_wrap_addr;
static char cur_tgt_name[96];
static unsigned long cur_tgt_addr;

static unsigned long susfs_hk_resolve(const char *name)
{
	unsigned long addr = 0;
	unsigned long flags;

	if (!name || !name[0])
		return 0;

	spin_lock_irqsave(&susfs_hk_sym_lock, flags);
	if (cur_wrap_addr && !strcmp(name, cur_wrap_name))
		addr = cur_wrap_addr;
	else if (cur_tgt_addr && !strcmp(name, cur_tgt_name))
		addr = cur_tgt_addr;
	spin_unlock_irqrestore(&susfs_hk_sym_lock, flags);

	if (addr)
		return addr;
	return find_kernel_symbol_exact(name);
}

bool susfs_hk_ready(void)
{
	return READ_ONCE(susfs_hk_armed);
}

int susfs_hk_init(void)
{
	struct hk_cfg cfg = {
		.resolve = susfs_hk_resolve,
	};
	int rc;

	mutex_lock(&susfs_hk_ctl_lock);
	if (susfs_hk_armed) {
		mutex_unlock(&susfs_hk_ctl_lock);
		return 0;
	}
	rc = hk_init(&cfg);
	if (rc) {
		mutex_unlock(&susfs_hk_ctl_lock);
		return rc;
	}
	WRITE_ONCE(susfs_hk_armed, true);
	mutex_unlock(&susfs_hk_ctl_lock);

	SUSFS_LOGI("susfs_hk: HooKern inline engine initialized\n");
	return 0;
}

void susfs_hk_exit(void)
{
	mutex_lock(&susfs_hk_ctl_lock);
	if (!susfs_hk_armed) {
		mutex_unlock(&susfs_hk_ctl_lock);
		return;
	}
	WRITE_ONCE(susfs_hk_armed, false);
	hk_exit();
	mutex_unlock(&susfs_hk_ctl_lock);
}

static int susfs_hk_inline_install(struct hk_inline *h,
				   const char *sym_name, unsigned long target_addr,
				   const char *wrap_name, void *fn,
				   unsigned long *tramp_out)
{
	unsigned long flags;
	int rc;

	if (!h || !sym_name || !sym_name[0] || !fn)
		return -EINVAL;
	if (!tramp_out && (!wrap_name || !wrap_name[0]))
		return -EINVAL;

	mutex_lock(&susfs_hk_ctl_lock);
	if (!susfs_hk_armed) {
		mutex_unlock(&susfs_hk_ctl_lock);
		return -ENODEV;
	}
	if (h->pending) {
		mutex_unlock(&susfs_hk_ctl_lock);
		return -EBUSY;
	}

	memset(h, 0, sizeof(*h));

	spin_lock_irqsave(&susfs_hk_sym_lock, flags);
	if (!tramp_out) {
		strscpy(cur_wrap_name, wrap_name, sizeof(cur_wrap_name));
		cur_wrap_addr = (unsigned long)fn;
	} else {
		cur_wrap_name[0] = '\0';
		cur_wrap_addr = 0;
	}
	if (target_addr) {
		strscpy(cur_tgt_name, sym_name, sizeof(cur_tgt_name));
		cur_tgt_addr = target_addr;
	} else {
		cur_tgt_name[0] = '\0';
		cur_tgt_addr = 0;
	}
	spin_unlock_irqrestore(&susfs_hk_sym_lock, flags);

	if (tramp_out)
		rc = hk_inline_hook_stub(h, sym_name, (unsigned long)fn, tramp_out);
	else
		rc = hk_inline_hook(h, sym_name, wrap_name);

	spin_lock_irqsave(&susfs_hk_sym_lock, flags);
	cur_wrap_name[0] = '\0';
	cur_wrap_addr = 0;
	cur_tgt_name[0] = '\0';
	cur_tgt_addr = 0;
	spin_unlock_irqrestore(&susfs_hk_sym_lock, flags);

	mutex_unlock(&susfs_hk_ctl_lock);
	return rc;
}

int susfs_hk_inline_hook(struct hk_inline *h,
			 const char *sym_name, unsigned long target_addr,
			 const char *wrap_name, void *wrap_fn)
{
	return susfs_hk_inline_install(h, sym_name, target_addr,
				       wrap_name, wrap_fn, NULL);
}

int susfs_hk_inline_hook_stub(struct hk_inline *h,
			      const char *sym_name, unsigned long target_addr,
			      void *stub_fn, unsigned long *tramp_out)
{
	if (!tramp_out)
		return -EINVAL;
	return susfs_hk_inline_install(h, sym_name, target_addr,
				       NULL, stub_fn, tramp_out);
}

void susfs_hk_inline_unhook(struct hk_inline *h)
{
	if (!h)
		return;

	mutex_lock(&susfs_hk_ctl_lock);
	if (susfs_hk_armed)
		hk_inline_unhook(h);
	mutex_unlock(&susfs_hk_ctl_lock);
}
