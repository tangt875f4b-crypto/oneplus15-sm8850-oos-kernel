# Local migration patches

1. Priority UID Filter uses PRIO_USER for getpriority/setpriority and IOPRIO_WHO_USER
   for ioprio_get/ioprio_set, including compat wrappers.
2. SUS type hash entries store type_value; lookup and duplicate detection compare the
   full value rather than treating every hash-bucket collision as a match.
3. SELinux type and AVD-rule nodes include rcu_head and are released with kfree_rcu()
   after hash_del_rcu().
4. AVD-rule allocation uses GFP_KERNEL while holding its mutex.

These are source-level correctness fixes and still require compile-time/runtime checks.
