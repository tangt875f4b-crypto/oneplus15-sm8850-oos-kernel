// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_avc_spoof.c - hide the KernelSU su domain from SELinux AVC audit logs (SUSFS AVC_LOG_SPOOFING), LKM port: upstream
 * prints a priv_app context in place of the su domain, hiding the "denied { ... } tcontext=u:r:su:s0" lines that root-hiding
 * detectors grep for.  Rewriting tsid in place makes the hooked function's own security_sid_to_context() emit the priv_app
 * context - equivalent to upstream's string swap.  The sids are resolved at init time (process context) via EXPORT_SYMBOL
 * security_secctx_to_secid(), with module_param overrides; interface is /proc/susfs_avc_spoof (write "1"/"0", read to query).
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/security.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/cred.h>	/* current_uid(), control-node gate */
#include <linux/mutex.h>	/* avc_ctl_lock: serialises the arm/disarm pair */
#include <linux/version.h>	/* LINUX_VERSION_CODE: slow_avc_audit() lost its leading `state` in 6.4 */
#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/bitops.h>
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_expose_proc */
#include "susfs_kprobe.h"
#include "ksu_allow_gate.h"	/* the control-node gate is su's own */

/* module_param overrides for the two domains: the default su domain is the SukiSU variant ("ksu"), stock
 * KernelSU uses "su".  The sid is resolved at init time via security_secctx_to_secid(). */
static char avc_su_ctx[128] = "u:r:ksu:s0";
static char avc_priv_app_ctx[128] = "u:r:priv_app:s0:c512,c768";
module_param_string(avc_su_ctx, avc_su_ctx, sizeof(avc_su_ctx), 0644);
module_param_string(avc_priv_app_ctx, avc_priv_app_ctx, sizeof(avc_priv_app_ctx), 0644);

static u32 avc_su_sid;
static u32 avc_priv_app_sid;
static bool avc_spoof_enabled;
static bool avc_registered;

/* slow_avc_audit(ssid, tsid, tclass, requested, audited, denied, result, a) - tsid is arg #2
 * (regs->regs[1]), a u32 in the low bits.
 *
 * UP TO v6.3 the prototype had a leading `struct selinux_state *state`, so tsid sat in arg #3
 * (regs->regs[2]).  v6.4 dropped that argument and everything shifted down by one: reading
 * regs->regs[2] on 6.4+ would read **tclass** (a small 1..~100 class number) instead of the
 * target sid, so no audit ever matched and the spoof silently did nothing - and in the one
 * case where a tclass could equal the su sid, the write-back below would clobber the tclass
 * argument instead, which audit then indexes secclass_map[] with.  Gate on the version, and
 * read and write the SAME argument.
 *
 * avc_audit_post_callback is static and LTO-inlined into
 * slow_avc_audit (noinline), so its kallsyms symbol is a leftover; slow_avc_audit has a real out-of-line copy.
 * This handler runs in interrupt context (no sleep), so it only rewrites the register. */
static atomic_t avc_hit_count = ATOMIC_INIT(0);
static atomic_t avc_enter_count = ATOMIC_INIT(0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define AVC_SSID_REG	0
#define AVC_TSID_REG	1
#else
#define AVC_SSID_REG	1
#define AVC_TSID_REG	2
#endif

static int avc_audit_post_pre(struct kprobe *kp, struct pt_regs *regs)
{
	bool hit = false;

	atomic_inc(&avc_enter_count);

	/* Either sid unresolved means no spoofing at all: a 0 must not match (it is a real sid
	 * value here), and writing 0 over a real one makes security_sid_to_context() fail, so
	 * audit prints "scontext=???" - louder than the domain name being hidden. */
	if (!avc_su_sid || !avc_priv_app_sid)
		return 0;

	/* BOTH ends.  The records a root detector greps for are the ones the su domain CAUSES -
	 * "avc: denied ... scontext=u:r:ksu:s0" - and there the su sid is the SOURCE; rewriting
	 * tsid alone left every one of those lines intact. */
	if ((u32)regs->regs[AVC_SSID_REG] == avc_su_sid) {
		regs->regs[AVC_SSID_REG] = avc_priv_app_sid;
		hit = true;
	}
	if ((u32)regs->regs[AVC_TSID_REG] == avc_su_sid) {
		regs->regs[AVC_TSID_REG] = avc_priv_app_sid;
		hit = true;
	}

	if (hit)
		atomic_inc(&avc_hit_count);
	return 0;
}

static struct kprobe kp_avc = {
	.symbol_name = "slow_avc_audit",
	.pre_handler = avc_audit_post_pre,
};

/* Serialises the arm/disarm pair.  register_kprobe() resolves .symbol_name only while .addr is
 * NULL and answers -EINVAL once both are set, so a *successful* registration by another task
 * makes this task's register_kprobe() fail - and the failure branch below clears .addr.  Without
 * this lock that clears the address of a probe that is LIVE: unregister_kprobes() only runs a
 * probe's bottom half `if (kps[i]->addr)`, so the breakpoint then survives the unload with its
 * handler pointing into freed module text.  Two independent entries reach avc_register()
 * (/proc/susfs_avc_spoof and the supercall, which runs in each caller's task_work), which is the
 * same shape sus_mount_ctl_lock and or_lock were added for. */
static DEFINE_MUTEX(avc_ctl_lock);

/* Set by susfs_avc_spoof_exit() while it holds the lock; registration refuses afterwards.  The
 * /proc node holds no module reference, so a write already inside avc_proc_write() can reach
 * avc_register() during teardown and install the probe again after it was disarmed - its handler
 * would then point into a module that is about to be freed. */
static bool avc_exiting;

static int avc_register(void)
{
	int rc;

	mutex_lock(&avc_ctl_lock);
	if (avc_exiting) {
		mutex_unlock(&avc_ctl_lock);
		return -ENODEV;
	}
	if (avc_registered) {
		mutex_unlock(&avc_ctl_lock);
		return 0;
	}
	/* The handler would bail out on every call, so report it here instead of arming a probe
	 * that can never spoof anything. */
	if (!avc_su_sid || !avc_priv_app_sid) {
		mutex_unlock(&avc_ctl_lock);
		pr_warn("avc_spoof: su_sid=%u priv_app_sid=%u - both contexts must resolve against this device's policy (override with avc_su_ctx=/avc_priv_app_ctx=)\n",
			avc_su_sid, avc_priv_app_sid);
		return -EOPNOTSUPP;
	}
	rc = register_kprobe(&kp_avc);
	if (rc) {
		/* The failure that matters is reported to the caller, but the address the kernel
		 * resolved is already in the struct: without this the retry a later enable makes
		 * would be refused with -EINVAL (see susfs_kprobe.h).  Safe under the lock - no
		 * other task can be holding a successful registration of this probe. */
		susfs_kp_forget_addr(&kp_avc);
		mutex_unlock(&avc_ctl_lock);
		return rc;
	}
	avc_registered = true;
	mutex_unlock(&avc_ctl_lock);
	SUSFS_LOGI("susfs_avc_spoof: hook installed (slow_avc_audit)\n");
	return 0;
}

/* Caller must hold avc_ctl_lock.  Kept separate from avc_unregister() because the exit path has to
 * do the disarm and "refuse further registration" in ONE critical section - something the /proc
 * write path (which also disarms, but must stay re-enablable) must not do. */
static void avc_unregister_locked(void)
{
	if (!avc_registered)
		return;
	unregister_kprobe(&kp_avc);
	/* A successful unregister leaves .addr set (only a probe that was never on a list gets it
	 * cleared), so "disarmed" has to mean it here too: writing 0 and then 1 is the documented
	 * way to restart the spoof, and it used to end with the hook permanently gone. */
	susfs_kp_forget_addr(&kp_avc);
	avc_registered = false;
	/* Reported only for a real disarm: writing '0' when nothing was armed (or a second disable)
	 * used to be silent and must stay silent. */
	SUSFS_LOGI("susfs_avc_spoof: hook removed\n");
}

static void avc_unregister(void)
{
	mutex_lock(&avc_ctl_lock);
	avc_unregister_locked();
	mutex_unlock(&avc_ctl_lock);
}

static int avc_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d (su_sid=%u priv_app_sid=%u enter=%d hits=%d)\n",
		   avc_spoof_enabled ? 1 : 0, avc_su_sid, avc_priv_app_sid,
		   atomic_read(&avc_enter_count), atomic_read(&avc_hit_count));
	return 0;
}

static int avc_proc_open(struct inode *inode, struct file *file)
{
	/* 0777 is deliberate (the ENOENT contract comes from sus_path's hidden set, not from the mode), so
	 * refuse non-root callers here too - see the note in susfs_enable_log.c's log_proc_open(). */
	if (!susfs_control_visible())
		return -ENOENT;
	return single_open(file, avc_proc_show, NULL);
}

static ssize_t avc_proc_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *off)
{
	char c;
	int rc = 0;

	if (!susfs_control_visible())
		return -ENOENT;

	if (copy_from_user(&c, buf, 1))
		return -EFAULT;

	if (c == '1') {
		if (!avc_spoof_enabled) {
			rc = avc_register();
			if (!rc)
				avc_spoof_enabled = true;
		}
	} else if (c == '0') {
		avc_unregister();
		avc_spoof_enabled = false;
	} else {
		/* Only '0' and '1' are the protocol. */
		return -EINVAL;
	}

	if (rc) {
		pr_warn("avc_spoof: enable failed %d\n", rc);
		/* Reported to the writer: a switch that did not take effect must not come back as a
		 * complete write.  Success still returns len, the same contract kstat_proc_write()
		 * states for its own commands. */
		return rc;
	}
	return len;
}

static const struct proc_ops avc_proc_ops = {
	.proc_open = avc_proc_open,
	.proc_read = seq_read,
	.proc_write = avc_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *avc_proc_entry;

/*
 * SUSFS 2.4.0 SELinux hide rules (for FinaSU / KernelSU sepolicy compatibility)
 */
static DEFINE_MUTEX(susfs_mutex_lock_sus_type);
static DEFINE_HASHTABLE(SUS_TYPE_HLIST, 10);

struct st_susfs_sus_type_hlist {
	struct hlist_node node;
};

int susfs_add_sus_type(const char *secctx, u32 type_value)
{
	struct st_susfs_sus_type_hlist *new_entry, *tmp_entry;
	struct hlist_node *tmp_hlist_node;
	int err = 0;

	mutex_lock(&susfs_mutex_lock_sus_type);
	hash_for_each_possible_safe(SUS_TYPE_HLIST, tmp_entry, tmp_hlist_node, node, type_value) {
		SUSFS_LOGE("secctx '%s', type_value '%u', was added before already\n",
			secctx, type_value);
		err = -EINVAL;
		goto unlock;
	}

	new_entry = kzalloc(sizeof(struct st_susfs_sus_type_hlist), GFP_KERNEL);
	if (!new_entry) {
		err = -ENOMEM;
		goto unlock;
	}

	hash_add_rcu(SUS_TYPE_HLIST, &new_entry->node, type_value);
	SUSFS_LOGI_RL("secctx '%s', type '%u', has been added to SUS_TYPE_HLIST\n",
					secctx, type_value);
unlock:
	mutex_unlock(&susfs_mutex_lock_sus_type);
	return err;
}
EXPORT_SYMBOL_GPL(susfs_add_sus_type);

bool susfs_is_sus_type_rcu(u32 type_value)
{
	struct st_susfs_sus_type_hlist *entry = NULL;

	hash_for_each_possible_rcu(SUS_TYPE_HLIST, entry, node, type_value) {
		return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(susfs_is_sus_type_rcu);

static DEFINE_MUTEX(susfs_mutex_lock_sus_avd_allowed_hlist);
static DEFINE_HASHTABLE(SUS_AVD_ALLOWED_HLIST, 18);

struct susfs_sus_av_rule {
	struct hlist_node node;
	u32 s_type;
	u32 t_type;
	u32 c_type;
	u32 orig_avd_allowed;
};

static inline u32 susfs_av_rule_hash(u32 ssid, u32 tsid, u16 tclass)
{
	u32 h;

	h = hash_32(ssid, 32);
	h ^= rol32(hash_32(tsid, 32), 13);
	h ^= rol32(hash_32((u32)tclass, 32), 19);

	h += h << 13;
	h ^= h >> 7;
	h += h << 17;
	h ^= h >> 5;

	return h;
}

int susfs_add_sus_avd_allowed_by_type(u32 s_type, u32 t_type, u32 c_type, u32 orig_avd_allowed)
{
	struct susfs_sus_av_rule *entry, *tmp_entry;
	struct hlist_node *tmp_hlist_node;
	int err = 0;
	u32 key;

	mutex_lock(&susfs_mutex_lock_sus_avd_allowed_hlist);

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		err = -ENOMEM;
		goto unlock;
	}

	key = susfs_av_rule_hash(s_type, t_type, c_type);
	hash_for_each_possible_safe(SUS_AVD_ALLOWED_HLIST, tmp_entry, tmp_hlist_node, node, key) {
		if (tmp_entry->s_type == s_type &&
		    tmp_entry->t_type == t_type &&
		    tmp_entry->c_type == c_type)
		{
			kfree(entry);
			goto unlock;
		}
	}

	entry->s_type = s_type;
	entry->t_type = t_type;
	entry->c_type = c_type;
	entry->orig_avd_allowed = orig_avd_allowed;

	hash_add_rcu(SUS_AVD_ALLOWED_HLIST, &entry->node, key);
	SUSFS_LOGI_RL("av_rule '%u %u %u %u' has been added to SUS_AVD_ALLOWED_HLIST\n",
				s_type, t_type, c_type, orig_avd_allowed);
unlock:
	mutex_unlock(&susfs_mutex_lock_sus_avd_allowed_hlist);
	return err;
}
EXPORT_SYMBOL_GPL(susfs_add_sus_avd_allowed_by_type);

void susfs_spoof_avd_allowed_rcu(u32 s_type, u32 t_type, u32 c_type, u32 *avd_allowed)
{
	struct susfs_sus_av_rule *entry;
	u32 key = susfs_av_rule_hash(s_type, t_type, c_type);

	hash_for_each_possible_rcu(SUS_AVD_ALLOWED_HLIST, entry, node, key) {
		if (entry->s_type == s_type &&
		    entry->t_type == t_type &&
		    entry->c_type == c_type)
		{
			*avd_allowed = entry->orig_avd_allowed;
			return;
		}
	}
}
EXPORT_SYMBOL_GPL(susfs_spoof_avd_allowed_rcu);

static void susfs_avc_cleanup_types_and_rules(void)
{
	struct st_susfs_sus_type_hlist *type_entry;
	struct susfs_sus_av_rule *av_entry;
	struct hlist_node *tmp_node;
	int bkt;

	mutex_lock(&susfs_mutex_lock_sus_type);
	hash_for_each_safe(SUS_TYPE_HLIST, bkt, tmp_node, type_entry, node) {
		hash_del_rcu(&type_entry->node);
		kfree(type_entry);
	}
	mutex_unlock(&susfs_mutex_lock_sus_type);

	mutex_lock(&susfs_mutex_lock_sus_avd_allowed_hlist);
	hash_for_each_safe(SUS_AVD_ALLOWED_HLIST, bkt, tmp_node, av_entry, node) {
		hash_del_rcu(&av_entry->node);
		kfree(av_entry);
	}
	mutex_unlock(&susfs_mutex_lock_sus_avd_allowed_hlist);

	synchronize_rcu();
}

int susfs_avc_spoof_init(void)
{
	int err;

	err = security_secctx_to_secid(avc_su_ctx, strlen(avc_su_ctx), &avc_su_sid);
	if (err) {
		pr_warn("avc_spoof: secctx_to_secid(%s) failed %d\n", avc_su_ctx, err);
		avc_su_sid = 0;
	}
	err = security_secctx_to_secid(avc_priv_app_ctx, strlen(avc_priv_app_ctx),
				       &avc_priv_app_sid);
	if (err) {
		pr_warn("avc_spoof: secctx_to_secid(%s) failed %d\n",
			avc_priv_app_ctx, err);
		avc_priv_app_sid = 0;
	}
	SUSFS_LOGI("avc_spoof: su_sid=%u (%s), priv_app_sid=%u (%s)\n",
		avc_su_sid, avc_su_ctx, avc_priv_app_sid, avc_priv_app_ctx);

	/* Only the /proc node is optional: avc_register() installs the hook whenever the feature is switched
	 * on, supercall included.  0777 so DAC passes and sus_path's LSM layer gets to answer ENOENT. */
	if (susfs_control_node_allowed()) {
		avc_proc_entry = proc_create("susfs_avc_spoof", 0777, NULL,
					     &avc_proc_ops);
		if (!avc_proc_entry)
			pr_warn("proc_create(susfs_avc_spoof) failed\n");
		else
			SUSFS_LOGI("susfs_avc_spoof: proc ready (/proc/susfs_avc_spoof)\n");
	} else {
		SUSFS_LOGI("susfs_avc_spoof: /proc node not created (expose_proc=%d lsm=%d)\n",
			(int)susfs_expose_proc, (int)sus_path_lsm_active());
	}
	return 0;
}

void susfs_avc_spoof_exit(void)
{
	/* One critical section for "no more registrations" and the disarm: a /proc write holds no
	 * module reference and can be inside avc_proc_write() right now. */
	mutex_lock(&avc_ctl_lock);
	avc_exiting = true;
	avc_unregister_locked();
	mutex_unlock(&avc_ctl_lock);

	avc_spoof_enabled = false;
	if (avc_proc_entry) {
		proc_remove(avc_proc_entry);
		avc_proc_entry = NULL;
	}
	susfs_avc_cleanup_types_and_rules();
}

/* supercall: CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING */
void susfs_avc_spoof_supercall(void __user **arg)
{
	struct st_susfs_avc_log_spoofing info = {0};

	if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	if (info.enabled) {
		if (!avc_spoof_enabled) {
			int rc = avc_register();

			if (rc) {
				info.err = rc;
				goto out;
			}
			avc_spoof_enabled = true;
		}
	} else {
		avc_unregister();
		avc_spoof_enabled = false;
	}
	info.err = 0;
	SUSFS_LOGI("avc_spoof: %s (supercall)\n", info.enabled ? "enabled" : "disabled");
out:
	/* upstream writes back only ->err for input-type commands */
	if (copy_to_user(&((struct st_susfs_avc_log_spoofing __user *)*arg)->err,
			 &info.err, sizeof(info.err)))
		pr_warn("avc supercall copy_to_user failed\n");
}
