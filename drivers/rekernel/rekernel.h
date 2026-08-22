#ifndef REKERNEL_H
#define REKERNEL_H

/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * Re:Kernel integrated kernel driver (built-in).
 * Based on Sakion-Team/Re-Kernel LKM-Source v11.0, simplified for
 * in-tree compilation following cctv18's integration method.
 * Author: nep_timeline@outlook.com
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/freezer.h>
#include <linux/cgroup.h>

/* Re:Kernel version, single source of truth (used in logs and the version query). */
#define REKERNEL_MAJOR_VERSION                "11.0"
#define CLEAN_UP_ASYNC_BINDER

#define MIN_USERAPP_UID                 (10000)
#define MAX_SYSTEM_UID                  (2000)
#define SYSTEM_APP_UID                  (1000)
#define RESERVE_ORDER					17
#define WARN_AHEAD_SPACE				(1 << RESERVE_ORDER)
#define INTERFACETOKEN_BUFF_SIZE        (140)
#define PARCEL_OFFSET                   (16) /* sync with the writeInterfaceToken */
#define LINE_ERROR                      (-1)
#define LINE_SUCCESS                    (0)

#define USER_PORT			100
#define PACKET_SIZE			256

/*
 * Legacy raw-netlink protocol (used only when LEGACY_NETLINK is defined).
 * Command types from userspace.
 */
enum rekernel_cmd_type {
	REKERNEL_CMD_REMOVE_PROC = 1,
	REKERNEL_CMD_ADD_MONITOR_NET = 2,
	REKERNEL_CMD_DEL_MONITOR_NET = 3,
};

struct rekernel_cmd {
	int type;
};

struct rekernel_monitor_net_args {
	int uid;
};

/*
 * Generic Netlink protocol (used when LEGACY_NETLINK is NOT defined).
 * This is the ABI contract with the userspace daemon: the daemon resolves
 * the family by name via CTRL_CMD_GETFAMILY, joins the multicast group to
 * receive events, and sends MONITOR_NET / DEL_MONITOR_NET commands.
 * There is no REMOVE_PROC command: genl does not create /proc/rekernel.
 */
#define REKERNEL_GENL_FAMILY_NAME       "rekernel"
#define REKERNEL_GENL_VERSION           1
#define REKERNEL_GENL_MCGRP_NAME        "events"

/* generic netlink commands */
enum rekernel_genl_cmd {
	REKERNEL_C_UNSPEC,
	REKERNEL_C_EVENT,            /* kernel -> user, multicast event (REKERNEL_A_MSG) */
	REKERNEL_C_ADD_MONITOR_NET,      /* user -> kernel, add uid (carries REKERNEL_A_UID) */
	REKERNEL_C_DEL_MONITOR_NET,  /* user -> kernel, remove uid (carries REKERNEL_A_UID) */
	REKERNEL_C_GET_VERSION,      /* user -> kernel, query version; kernel replies unicast with REKERNEL_A_MSG */
	__REKERNEL_C_MAX,
};
#define REKERNEL_C_MAX (__REKERNEL_C_MAX - 1)

/* generic netlink attributes */
enum rekernel_genl_attr {
	REKERNEL_A_UNSPEC,
	REKERNEL_A_MSG,   /* string: event payload in the legacy "key=value,...;" format */
	REKERNEL_A_UID,   /* u32: uid to monitor for MONITOR_NET */
	REKERNEL_A_PID,   /* u32: pid */
	__REKERNEL_A_MAX,
};
#define REKERNEL_A_MAX (__REKERNEL_A_MAX - 1)

/* ---- freeze-state predicate (shared by binder / signal / netfilter) ---- */

static inline bool rekernel_is_frozen_state_compatible(struct task_struct *task)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	return READ_ONCE(task->__state) & TASK_FROZEN;
#else
	return frozen(task);
#endif
}

static inline bool rekernel_is_jobctl_frozen_compatible(struct task_struct *task)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 10, 0))
	return cgroup_task_freeze(task);
#else
	return ((task->jobctl & JOBCTL_TRAP_FREEZE) != 0);
#endif
}

static inline bool line_is_frozen(struct task_struct *task)
{
	if (cgroup_task_frozen(task) || rekernel_is_jobctl_frozen_compatible(task))
		return true;

	/* if task->group_leader is NULL, unfreeze it to avoid some unknown problems */
	if (NULL == task->group_leader)
		return true;

	return rekernel_is_frozen_state_compatible(task->group_leader) || freezing(task->group_leader);
}

/* ---- netlink transport ---- */
int sendMessage(char *packet_buffer, uint16_t len);
bool rekernel_netlink_ready(void);
int rekernel_netlink_start(void);
void rekernel_netlink_stop(void);

/* ---- network-monitor uid map ---- */
void net_uid_add(uid_t uid);
void net_uid_del(uid_t uid);

/* ---- hook (un)registration ---- */
int register_binder(void);
void unregister_binder(void);
int register_signal(void);
void unregister_signal(void);
int register_netfilter(void);
void unregister_netfilter(void);
int register_kp(void);
void unregister_kp(void);

#endif /* REKERNEL_H */
