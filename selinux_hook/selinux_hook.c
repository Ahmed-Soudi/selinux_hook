/*
 * Audit and filter SELinux access queries that probe Magisk contexts.
 *
 * The safe point for transaction queries is the selinuxfs write_op table,
 * where /sys/fs/selinux/access and /sys/fs/selinux/context still have the
 * original query text.  procattr writes are filtered at security_setprocattr().
 * Returning -EINVAL for Magisk contexts matches the clean-policy behavior
 * where the Magisk type/context does not exist.
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm/current.h>
#include <asm-generic/rwonce.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/fcntl.h>
#include <uapi/linux/fs.h>
#include <security.h>
#include <ksyms.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>

KPM_NAME("selinux_magisk_access_filter");
#ifndef SELINUX_VERSION
#define SELINUX_VERSION "1.1.7-diag9a"
#endif
KPM_VERSION(SELINUX_VERSION);
KPM_LICENSE("All rights reserved.");
KPM_AUTHOR("Admire");
KPM_DESCRIPTION("Audit and reject Magisk /sys/fs/selinux/access probes");

#define ACCESS_SAMPLE_MAX 256
#define ACCESS_PROBE_SLOTS 32
#define SELINUX_POLICYDB_FALLBACK_OFFSET sizeof(void *)
#define CLEAN_POLICYDB_ALLOC_SIZE 0x4000
#define SELINUX_LEGACY_BLOB_QUERY_MAX VERSION(4, 15, 0)
#define SELINUX_BLOB_ROUTE_MIN VERSION(5, 3, 0)
#define SELINUX_BLOB_ROUTE_MAX VERSION(6, 2, 0)
#define SELINUX_49_MIN VERSION(4, 9, 0)
#define SELINUX_49_MAX VERSION(4, 10, 0)
#define contains_case_literal(s, len, lit) contains_case_lit((s), (len), (lit), sizeof(lit) - 1)

#define MAGISK_MOCK_POLICY_PATH "/dev/.magisk_selinux_mock/load"
#define MAGISK_MOCK_POLICY_MAX_SIZE (8 * 1024 * 1024)
#define CLEAN_EVAL_SCOPE_SLOTS 8
#define STATUS_READ_SCOPE_SLOTS 8
