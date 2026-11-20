/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_HK_H
#define __SUSFS_HK_H

#include <linux/types.h>
#include "hk_inline.h"

int susfs_hk_init(void);
void susfs_hk_exit(void);
bool susfs_hk_ready(void);

int susfs_hk_inline_hook(struct hk_inline *h,
			 const char *sym_name, unsigned long target_addr,
			 const char *wrap_name, void *wrap_fn);
int susfs_hk_inline_hook_stub(struct hk_inline *h,
			      const char *sym_name, unsigned long target_addr,
			      void *stub_fn, unsigned long *tramp_out);
void susfs_hk_inline_unhook(struct hk_inline *h);

#endif /* __SUSFS_HK_H */
