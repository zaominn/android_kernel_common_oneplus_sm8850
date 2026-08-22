/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: rekernel.c
 * Description: Re:Kernel integrated kernel driver (built-in).
 *              Combined from LKM-Source v11.0:
 *                - rekernel_netlink.c  (netlink transport: generic + legacy)
 *                - rekernel_netfilter.c (inbound network monitor)
 *                - rekernel_binder.c   (binder vendor hooks + async cleanup kprobe)
 *                - rekernel_signal.c   (fatal-signal vendor hook)
 *                - rekernel_main.c     (init/exit)
 *              Simplified for in-tree compilation following cctv18's method.
 * Author: nep_timeline@outlook.com
 * Last Modification:  2026/06/28
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
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/hashtable.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/kprobes.h>
#include <linux/signal.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/rtnetlink.h>
#include <trace/hooks/binder.h>
#include <trace/hooks/signal.h>
#include <../android/binder_internal.h>
#include "rekernel.h"

extern struct net init_net;

/* ======================================================================
 * rekernel_netlink.c — netlink transport
 * ====================================================================== */

#ifdef LEGACY_NETLINK
#define NETLINK_REKERNEL_MAX			26
#define NETLINK_REKERNEL_MIN			22
static struct sock *netlink_socket = NULL;
static int netlink_unit = NETLINK_REKERNEL_MIN;
/* /proc/rekernel only exists for legacy netlink-unit discovery; genl resolves by family name. */
static struct proc_dir_entry *rekernel_dir, *rekernel_unit_entry, *rekernel_version_entry;

/* Raw-netlink transport is ready once the kernel socket exists. */
bool rekernel_netlink_ready(void)
{
	return netlink_socket != NULL;
}
#else
/* Generic-netlink transport. The family is defined below and registered at init. */
static bool rekernel_genl_registered = false;
static struct genl_family rekernel_genl_family;

bool rekernel_netlink_ready(void)
{
	return rekernel_genl_registered;
}

/* user -> kernel: add a uid to the network monitor hashmap. */
static int rekernel_genl_add_monitor_net(struct sk_buff *skb, struct genl_info *info)
{
	uid_t muid;

	if (!info->attrs[REKERNEL_A_UID])
		return -EINVAL;

	muid = (uid_t)nla_get_u32(info->attrs[REKERNEL_A_UID]);
#ifdef DEBUG
	pr_info("Re-Kernel monitorNet uid=%d\n", muid);
#endif
	net_uid_add(muid);
	return 0;
}

/* user -> kernel: remove a uid from the network monitor hashmap. */
static int rekernel_genl_del_monitor_net(struct sk_buff *skb, struct genl_info *info)
{
	uid_t muid;

	if (!info->attrs[REKERNEL_A_UID])
		return -EINVAL;

	muid = (uid_t)nla_get_u32(info->attrs[REKERNEL_A_UID]);
#ifdef DEBUG
	pr_info("Re-Kernel delMonitorNet uid=%d\n", muid);
#endif
	net_uid_del(muid);
	return 0;
}

/* user -> kernel: reply unicast with the module version string. */
static int rekernel_genl_get_version(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	void *msg_head;

	reply = genlmsg_new(nla_total_size(sizeof(REKERNEL_MAJOR_VERSION)), GFP_KERNEL);
	if (!reply)
		return -ENOMEM;

	msg_head = genlmsg_put(reply, info->snd_portid, info->snd_seq,
			       &rekernel_genl_family, 0, REKERNEL_C_GET_VERSION);
	if (!msg_head) {
		nlmsg_free(reply);
		return -ENOMEM;
	}

	if (nla_put_string(reply, REKERNEL_A_MSG, REKERNEL_MAJOR_VERSION)) {
		genlmsg_cancel(reply, msg_head);
		nlmsg_free(reply);
		return -EMSGSIZE;
	}

	genlmsg_end(reply, msg_head);
	return genlmsg_reply(reply, info);
}

static const struct nla_policy rekernel_genl_policy[REKERNEL_A_MAX + 1] = {
	[REKERNEL_A_MSG] = { .type = NLA_NUL_STRING, .len = PACKET_SIZE - 1 },
	[REKERNEL_A_UID] = { .type = NLA_U32 },
	[REKERNEL_A_PID] = { .type = NLA_U32 },
};

static const struct genl_ops rekernel_genl_ops[] = {
	{
		.cmd  = REKERNEL_C_ADD_MONITOR_NET,
		.doit = rekernel_genl_add_monitor_net,
	},
	{
		.cmd  = REKERNEL_C_DEL_MONITOR_NET,
		.doit = rekernel_genl_del_monitor_net,
	},
	{
		.cmd  = REKERNEL_C_GET_VERSION,
		.doit = rekernel_genl_get_version,
	},
};

static const struct genl_multicast_group rekernel_genl_mcgrps[] = {
	{ .name = REKERNEL_GENL_MCGRP_NAME },
};

static struct genl_family rekernel_genl_family = {
	.name     = REKERNEL_GENL_FAMILY_NAME,
	.version  = REKERNEL_GENL_VERSION,
	.maxattr  = REKERNEL_A_MAX,
	.policy   = rekernel_genl_policy,
	.module   = THIS_MODULE,
	.ops      = rekernel_genl_ops,
	.n_ops    = ARRAY_SIZE(rekernel_genl_ops),
	.mcgrps   = rekernel_genl_mcgrps,
	.n_mcgrps = ARRAY_SIZE(rekernel_genl_mcgrps),
};
#endif /* LEGACY_NETLINK */

int sendMessage(char *packet_buffer, uint16_t len)
{
#ifdef LEGACY_NETLINK
    struct sk_buff *socket_buffer;
    struct nlmsghdr *netlink_hdr;

    socket_buffer = nlmsg_new(len, GFP_ATOMIC);
    if (!socket_buffer) {
        pr_err("netlink alloc failure!\n");
        return LINE_ERROR;
    }

    netlink_hdr = nlmsg_put(socket_buffer, 0, 0, netlink_unit, len, 0);
    if (netlink_hdr == NULL) {
        pr_err("nlmsg_put failaure!\n");
        nlmsg_free(socket_buffer);
        return LINE_ERROR;
    }

    memcpy(nlmsg_data(netlink_hdr), packet_buffer, len);
    return netlink_unicast(netlink_socket, socket_buffer, USER_PORT, MSG_DONTWAIT);
#else
    struct sk_buff *socket_buffer;
    void *msg_head;
    int rc;

    socket_buffer = genlmsg_new(nla_total_size(len), GFP_ATOMIC);
    if (!socket_buffer) {
        pr_err("genlmsg alloc failure!\n");
        return LINE_ERROR;
    }

    msg_head = genlmsg_put(socket_buffer, 0, 0, &rekernel_genl_family, 0, REKERNEL_C_EVENT);
    if (msg_head == NULL) {
        pr_err("genlmsg_put failure!\n");
        nlmsg_free(socket_buffer);
        return LINE_ERROR;
    }

    if (nla_put(socket_buffer, REKERNEL_A_MSG, len, packet_buffer)) {
        genlmsg_cancel(socket_buffer, msg_head);
        nlmsg_free(socket_buffer);
        return LINE_ERROR;
    }

    genlmsg_end(socket_buffer, msg_head);

    /* genlmsg_multicast consumes socket_buffer; -ESRCH only means "no listeners". */
    rc = genlmsg_multicast(&rekernel_genl_family, socket_buffer, 0, 0, GFP_ATOMIC);
    if (rc && rc != -ESRCH) {
        pr_err("genlmsg_multicast failed, rc=%d\n", rc);
        return LINE_ERROR;
    }

    return LINE_SUCCESS;
#endif
}

#ifdef LEGACY_NETLINK
static void netlink_rcv_msg(struct sk_buff *socket_buffer)
{
	struct nlmsghdr *nlhdr;
	struct rekernel_cmd *cmd;

	if (socket_buffer->len < nlmsg_total_size(sizeof(struct rekernel_cmd)))
		return;

	nlhdr = nlmsg_hdr(socket_buffer);
	cmd = NLMSG_DATA(nlhdr);

#ifdef DEBUG
	pr_info("Re-Kernel_netlink recv cmd type=%d\n", cmd->type);
#endif

	switch (cmd->type) {
	case REKERNEL_CMD_REMOVE_PROC:
		if (rekernel_unit_entry) {
			proc_remove(rekernel_unit_entry);
			rekernel_unit_entry = NULL;
		}
		if (rekernel_version_entry) {
			proc_remove(rekernel_version_entry);
			rekernel_version_entry = NULL;
		}
		if (rekernel_dir) {
			proc_remove(rekernel_dir);
			rekernel_dir = NULL;
		}
		break;
	case REKERNEL_CMD_ADD_MONITOR_NET:
	case REKERNEL_CMD_DEL_MONITOR_NET:
	{
		struct rekernel_monitor_net_args *args;
		uid_t muid;

		if (nlmsg_len(nlhdr) < sizeof(struct rekernel_cmd) + sizeof(struct rekernel_monitor_net_args)) {
#ifdef DEBUG
			pr_warn("Re-Kernel monitorNet error: payload too small\n");
#endif
			break;
		}
		args = (struct rekernel_monitor_net_args *)((char *)cmd + sizeof(struct rekernel_cmd));
		muid = (uid_t)args->uid;
#ifdef DEBUG
		pr_info("Re-Kernel %sMonitorNet uid=%d\n",
			cmd->type == REKERNEL_CMD_DEL_MONITOR_NET ? "del" : "", muid);
#endif
		if (cmd->type == REKERNEL_CMD_DEL_MONITOR_NET)
			net_uid_del(muid);
		else
			net_uid_add(muid);
		break;
	}
	default:
#ifdef DEBUG
		pr_warn("Re-Kernel unknown cmd type=%d\n", cmd->type);
#endif
		break;
	}
}

static struct netlink_kernel_cfg cfg = {
	.input = netlink_rcv_msg, // set recv callback
};

/* /proc/rekernel/<unit> exposes the chosen netlink unit for legacy daemon discovery. */
static int rekernel_unit_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", netlink_unit);
	return 0;
}

static int rekernel_unit_open(struct inode *inode, struct file *file)
{
	return single_open(file, rekernel_unit_show, NULL);
}

static int rekernel_version_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", REKERNEL_MAJOR_VERSION);
	return 0;
}

static int rekernel_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, rekernel_version_show, NULL);
}

static const struct proc_ops rekernel_unit_fops = {
	.proc_open   = rekernel_unit_open,
	.proc_read   = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release   = single_release,
};

static const struct proc_ops rekernel_version_fops = {
	.proc_open   = rekernel_version_open,
	.proc_read   = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release   = single_release,
};
#endif /* LEGACY_NETLINK */

int rekernel_netlink_start(void)
{
#ifdef LEGACY_NETLINK
	pr_info("Re:Kernel v%s | DEVELOPER: Sakion Team | USER PORT: %d\n", REKERNEL_MAJOR_VERSION, USER_PORT);
	pr_info("Trying to create Re:Kernel Server......\n");

	for (netlink_unit = NETLINK_REKERNEL_MIN; netlink_unit < NETLINK_REKERNEL_MAX; netlink_unit++) {
		netlink_socket = (struct sock *)netlink_kernel_create(&init_net, netlink_unit, &cfg);
		if (netlink_socket != NULL)
			break;
	}

	if (netlink_socket == NULL) {
		pr_err("Failed to create Re:Kernel server!\n");
		return LINE_ERROR;
	}

	pr_info("Created Re:Kernel server! NETLINK UNIT: %d\n", netlink_unit);

	/* /proc/rekernel/<unit> is only needed for legacy netlink-unit discovery. */
	rekernel_dir = proc_mkdir("rekernel", NULL);
	if (!rekernel_dir)
		pr_err("create /proc/rekernel failed!\n");
	else {
		char buff[32];
		sprintf(buff, "%d", netlink_unit);
		rekernel_unit_entry = proc_create(buff,
			0644, rekernel_dir, &rekernel_unit_fops);
		if (!rekernel_unit_entry) {
			pr_err("create rekernel unit failed!\n");
		} else {
			char versionBuffer[32];
			sprintf(versionBuffer, "%s", "version");
			rekernel_version_entry = proc_create(versionBuffer,
				0644, rekernel_dir, &rekernel_version_fops);
		}
	}
#else
	pr_info("Re:Kernel v%s | DEVELOPER: Sakion Team | GENL FAMILY: %s\n", REKERNEL_MAJOR_VERSION, REKERNEL_GENL_FAMILY_NAME);
	pr_info("Trying to register Re:Kernel Generic Netlink family......\n");

	if (genl_register_family(&rekernel_genl_family) != 0) {
		pr_err("Failed to register Re:Kernel genl family!\n");
		return LINE_ERROR;
	}
	rekernel_genl_registered = true;

	pr_info("Registered Re:Kernel genl family! ID: %d\n", rekernel_genl_family.id);
#endif

	return LINE_SUCCESS;
}

void rekernel_netlink_stop(void)
{
#ifdef LEGACY_NETLINK
	netlink_kernel_release(netlink_socket);
#else
	if (rekernel_genl_registered) {
		genl_unregister_family(&rekernel_genl_family);
		rekernel_genl_registered = false;
	}
#endif
}

/* ======================================================================
 * rekernel_netfilter.c — inbound network monitor
 * ====================================================================== */

/* hashmap for net monitor uids */
#define REKERNEL_NET_UID_HASH_BITS 6
static DEFINE_HASHTABLE(rekernel_net_uid_map, REKERNEL_NET_UID_HASH_BITS);
struct uid_info {
	uid_t uid;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

static DEFINE_MUTEX(rekernel_net_uid_mutex);

static bool net_uid_monitored(uid_t uid)
{
	struct uid_info *entry;

	hash_for_each_possible_rcu(rekernel_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid)
			return true;
	}
	return false;
}

/* add a uid to the monitor map (no-op if already present). Caller must NOT hold the mutex. */
void net_uid_add(uid_t uid)
{
	mutex_lock(&rekernel_net_uid_mutex);
	if (!net_uid_monitored(uid)) {
		struct uid_info *entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (entry) {
			entry->uid = uid;
			hash_add_rcu(rekernel_net_uid_map, &entry->hnode, uid);
		}
	}
	mutex_unlock(&rekernel_net_uid_mutex);
}

/* remove a uid from the monitor map. Caller must NOT hold the mutex. */
void net_uid_del(uid_t uid)
{
	struct uid_info *entry;

	mutex_lock(&rekernel_net_uid_mutex);
	hash_for_each_possible(rekernel_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			hash_del_rcu(&entry->hnode);
			kfree_rcu(entry, rcu);
			break;
		}
	}
	mutex_unlock(&rekernel_net_uid_mutex);
}

static inline uid_t line_sock2uid(struct sock *sk)
{
	if (sk && sk->sk_socket)
		return SOCK_INODE(sk->sk_socket)->i_uid.val;
	else
		return 0;
}

static unsigned int rekernel_pkg_ipv4_ipv6_in(void *priv, struct sk_buff *socket_buffer,
   const struct nf_hook_state *state)
{
  struct sock *sk;
  unsigned int thoff = 0;
  unsigned short frag_off = 0;
  uid_t uid;
  uint hook;
  struct net_device *dev = NULL;
  struct tcphdr *th;
  int data_len = 0;
  bool monitored;

  if (!socket_buffer || !socket_buffer->len || !state)
   return NF_ACCEPT;

  hook = state->hook;
  if (NF_INET_LOCAL_IN == hook)
   dev = state->in;

  if (NULL == dev)
   return NF_ACCEPT;

  sk = skb_to_full_sk(socket_buffer);
  if (sk == NULL || !sk_fullsock(sk))
   return NF_ACCEPT;

  uid = line_sock2uid(sk);
  if (uid < MIN_USERAPP_UID) return NF_ACCEPT;

  rcu_read_lock();
  monitored = net_uid_monitored(uid);
  rcu_read_unlock();
  if (!monitored) return NF_ACCEPT;

  if (ip_hdr(socket_buffer)->version == 4) {
   struct iphdr *iph4;
   unsigned int ip_hdr_len;

   if (!pskb_may_pull(socket_buffer, sizeof(struct iphdr))) {
    return NF_ACCEPT;
   }

   iph4 = ip_hdr(socket_buffer);
   if (iph4->protocol != IPPROTO_TCP) {
    return NF_ACCEPT;
   }

   ip_hdr_len = iph4->ihl << 2;
   if (!pskb_may_pull(socket_buffer, ip_hdr_len + sizeof(struct tcphdr))) {
    return NF_ACCEPT;
   }

   iph4 = ip_hdr(socket_buffer);
   th = (struct tcphdr *)((unsigned char *)iph4 + ip_hdr_len);
   data_len = ntohs(iph4->tot_len) - ip_hdr_len - (th->doff << 2);

#if IS_ENABLED(CONFIG_IPV6)
  } else if (ip_hdr(socket_buffer)->version == 6) {
   struct ipv6hdr *iph6;

   if (!pskb_may_pull(socket_buffer, sizeof(struct ipv6hdr))) {
    return NF_ACCEPT;
   }

   if (ipv6_find_hdr(socket_buffer, &thoff, -1, &frag_off, NULL) != IPPROTO_TCP) {
    return NF_ACCEPT;
   }

   if (!pskb_may_pull(socket_buffer, thoff + sizeof(struct tcphdr))) {
    return NF_ACCEPT;
   }

   iph6 = ipv6_hdr(socket_buffer);
   th = (struct tcphdr *)(skb_network_header(socket_buffer) + thoff);
   data_len = ntohs(iph6->payload_len) - (thoff - sizeof(struct ipv6hdr)) - (th->doff << 2);
#endif
  } else {
   return NF_ACCEPT;
  }

  if (data_len <= 0 && !th->syn && !th->fin && !th->rst)
   return NF_ACCEPT;

#ifdef DEBUG
  pr_info("[Re-Kernel LKM] Receive net data! target=%d\n", uid);
#endif
  if (rekernel_netlink_ready()) {
   char binder_kmsg[PACKET_SIZE];
   int len;
   if (ip_hdr(socket_buffer)->version == 4) {
    len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Network,target=%d,proto=ipv4,data_len=%d;", uid, data_len);
#if IS_ENABLED(CONFIG_IPV6)
   } else if (ip_hdr(socket_buffer)->version == 6) {
    len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Network,target=%d,proto=ipv6,data_len=%d;", uid, data_len);
#endif
   } else {
    return NF_ACCEPT;
   }
   sendMessage(binder_kmsg, len);
  }

  return NF_ACCEPT;
}

/* Only monitor input network packages */
static struct nf_hook_ops rekernel_nf_ops[] = {
	{
		.hook     = rekernel_pkg_ipv4_ipv6_in,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_SELINUX_LAST + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook     = rekernel_pkg_ipv4_ipv6_in,
		.pf       = NFPROTO_IPV6,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_SELINUX_LAST + 1,
	}
#endif
};

void unregister_netfilter(void)
{
	struct net *net;
	struct uid_info *entry;
	struct hlist_node *tmp;
	int bkt;

	rtnl_lock();
	for_each_net(net) {
		nf_unregister_net_hooks(net, rekernel_nf_ops, ARRAY_SIZE(rekernel_nf_ops));
	}
	rtnl_unlock();

	synchronize_rcu();
	hash_for_each_safe(rekernel_net_uid_map, bkt, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
}

int register_netfilter(void)
{
	int rc = LINE_SUCCESS;
	struct net *net = NULL;

	hash_init(rekernel_net_uid_map);

	rtnl_lock();
	for_each_net(net) {
		rc = nf_register_net_hooks(net, rekernel_nf_ops, ARRAY_SIZE(rekernel_nf_ops));
		if (rc != LINE_SUCCESS) {
			pr_err("register netfilter hooks failed, rc=%d\n", rc);
			break;
		}
	}
	rtnl_unlock();

	if (rc != LINE_SUCCESS) {
		unregister_netfilter();
		return LINE_ERROR;
	}

	return LINE_SUCCESS;
}

/* ======================================================================
 * rekernel_binder.c — binder hooks + async cleanup kprobe
 * ====================================================================== */

#ifdef CLEAN_UP_ASYNC_BINDER
static unsigned long (*re_kallsyms_lookup_name)(const char* name);
static void (*re_kernel_transaction_buffer_release)(struct binder_proc* proc, struct binder_thread* thread, struct binder_buffer* buffer, binder_size_t off_end_offset, bool is_failure);
static void (*re_kernel_alloc_free_buf)(struct binder_alloc* alloc, struct binder_buffer* buffer);
static struct binder_stats(*re_kernel_stats);

/* Stable UAPI value; some older vendor headers do not name this flag. */
#define REKERNEL_TF_UPDATE_TXN 0x40
#define REKERNEL_ASYNC_CLEANUP_MAX 32
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0))
static void line_binder_alloc_new_buf_locked(void *data, size_t size, size_t *free_async_space, int is_async, bool *should_fail)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
static void line_binder_alloc_new_buf_locked(void *data, size_t size, size_t *free_async_space, int is_async)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
static void line_binder_alloc_new_buf_locked(void *data, size_t size, struct binder_alloc *alloc, int is_async)
#endif
{
	struct task_struct *p = NULL;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	struct binder_alloc *alloc = NULL;

	alloc = container_of(free_async_space, struct binder_alloc, free_async_space);
	if (alloc == NULL) {
		return;
	}
#endif
	if (is_async
		&& (alloc->free_async_space < 3 * (size + sizeof(struct binder_buffer))
		|| (alloc->free_async_space < WARN_AHEAD_SPACE))) {
		rcu_read_lock();
		p = find_task_by_vpid(alloc->pid);
		rcu_read_unlock();
		if (p != NULL && line_is_frozen(p)) {
#ifdef DEBUG
			pr_info("[Re-Kernel LKM] Binder Free buffer full! from=%d | target=%d\n", task_uid(current).val, task_uid(p).val);
#endif
			if (rekernel_netlink_ready()) {
				char binder_kmsg[PACKET_SIZE];
				int len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=free_buffer_full,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(current), task_uid(current).val, task_tgid_nr(p), task_uid(p).val, "FREE_BUFFER_FULL", -1);
				sendMessage(binder_kmsg, len);
			}
		}
	}
}

static struct hlist_head *binder_procs = NULL;
static struct mutex *binder_procs_lock = NULL;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0))
static void line_binder_preset(void *data, struct hlist_head *hhead,
	struct mutex *lock, struct binder_proc *proc)
#else
static void line_binder_preset(void *data, struct hlist_head *hhead,
	struct mutex *lock)
#endif
{
	if (binder_procs == NULL)
		binder_procs = hhead;

	if (binder_procs_lock == NULL)
		binder_procs_lock = lock;
}

static void line_binder_reply(void *data, struct binder_proc *target_proc, struct binder_proc *proc,
	struct binder_thread *thread, struct binder_transaction_data *tr)
{
	if (target_proc
		&& (NULL != target_proc->tsk)
		&& (NULL != proc->tsk)
		&& (task_uid(target_proc->tsk).val <= MAX_SYSTEM_UID)
		&& (proc->pid != target_proc->pid)
		&& line_is_frozen(target_proc->tsk)) {
#ifdef DEBUG
		pr_info("[Re-Kernel LKM] Sync Binder Reply! from=%d | target=%d\n", task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
#endif
		if (rekernel_netlink_ready()) {
			char binder_kmsg[PACKET_SIZE];
			int len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(proc->tsk), task_uid(proc->tsk).val, task_tgid_nr(target_proc->tsk), task_uid(target_proc->tsk).val, "SYNC_BINDER_REPLY", -1);
			sendMessage(binder_kmsg, len);
		}
	}
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
static long line_copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
	long ret = -EFAULT;
	if (access_ok(src, size)) {
		pagefault_disable();
		ret = __copy_from_user_inatomic(dst, src, size);
		pagefault_enable();
	}
	if (ret)
		return -EFAULT;
	return 0;
}
#endif

static long line_copy_from_user_compatible(void *dst, const void __user *src, size_t size)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	return line_copy_from_user_nofault(dst, src, size);
#else
	return copy_from_user(dst, src, size);
#endif
}

static void line_binder_transaction(void *data, struct binder_proc *target_proc, struct binder_proc *proc,
	struct binder_thread *thread, struct binder_transaction_data *tr)
{
	char buf_data[INTERFACETOKEN_BUFF_SIZE];
	size_t buf_data_size;
	char buf[INTERFACETOKEN_BUFF_SIZE] = {0};
	int i = 0;
	int j = 0;

	if (!(tr->flags & TF_ONE_WAY) /* sync binder */
		&& target_proc
		&& (NULL != target_proc->tsk)
		&& (NULL != proc->tsk)
		&& (task_uid(target_proc->tsk).val > MIN_USERAPP_UID)
		&& (proc->pid != target_proc->pid)
		&& line_is_frozen(target_proc->tsk)) {
#ifdef DEBUG
		pr_info("[Re-Kernel LKM] Sync Binder Transaction! from=%d | target=%d\n", task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
#endif
		if (rekernel_netlink_ready()) {
			char binder_kmsg[PACKET_SIZE];
			int len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(proc->tsk), task_uid(proc->tsk).val, task_tgid_nr(target_proc->tsk), task_uid(target_proc->tsk).val, "SYNC_BINDER", -1);
			sendMessage(binder_kmsg, len);
		}
	}

	if ((tr->flags & TF_ONE_WAY) /* async binder */
		&& target_proc
		&& (NULL != target_proc->tsk)
		&& (NULL != proc->tsk)
		&& (task_uid(target_proc->tsk).val > MIN_USERAPP_UID)
		&& (proc->pid != target_proc->pid)
		&& line_is_frozen(target_proc->tsk)) {
		buf_data_size = tr->data_size > INTERFACETOKEN_BUFF_SIZE ? INTERFACETOKEN_BUFF_SIZE : tr->data_size;
		if (!line_copy_from_user_compatible(buf_data, (char*)tr->data.ptr.buffer, buf_data_size)) {
			if (buf_data_size > PARCEL_OFFSET) {
				char *p = (char *)(buf_data) + PARCEL_OFFSET;
				j = PARCEL_OFFSET + 1;
				while (i < INTERFACETOKEN_BUFF_SIZE && j < buf_data_size && *p != '\0') {
					buf[i++] = *p;
					j += 2;
					p += 2;
				}
				if (i == INTERFACETOKEN_BUFF_SIZE) buf[i-1] = '\0';
			}
#ifdef DEBUG
			pr_info("[Re-Kernel LKM] ASync Binder Transaction! from=%d | target=%d\n", task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
#endif
			if (rekernel_netlink_ready()) {
				char binder_kmsg[PACKET_SIZE];
				int len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(proc->tsk), task_uid(proc->tsk).val, task_tgid_nr(target_proc->tsk), task_uid(target_proc->tsk).val, buf, tr->code);
				sendMessage(binder_kmsg, len);
			}
		}
	}
}

#ifdef CLEAN_UP_ASYNC_BINDER
static inline void binder_inner_proc_lock(struct binder_proc* proc)
__acquires(&proc->inner_lock)
{
	spin_lock(&proc->inner_lock);
}

static inline void binder_inner_proc_unlock(struct binder_proc* proc)
__releases(&proc->inner_lock)
{
	spin_unlock(&proc->inner_lock);
}

static inline void binder_node_lock(struct binder_node* node)
__acquires(&node->lock)
{
	spin_lock(&node->lock);
}

static inline void binder_node_unlock(struct binder_node* node)
__releases(&node->lock)
{
	spin_unlock(&node->lock);
}

static bool binder_can_cleanup_transaction(struct binder_transaction* t1,
	struct binder_transaction* t2)
{
	if (!t1 || !t2 || !t1->buffer || !t2->buffer ||
	    !t1->buffer->target_node || !t2->buffer->target_node ||
	    !t1->to_proc || !t2->to_proc)
		return false;
	if (!(t1->flags & TF_ONE_WAY) || !(t2->flags & TF_ONE_WAY))
		return false;
	/* TF_UPDATE_TXN is carried by the replacement; old queued work need not have it. */
	/* Avoid releasing embedded Binder objects or FDs from a kprobe handler. */
	/* The incoming transaction is never released here, so its offsets are safe. */
	if (t1->buffer->offsets_size != 0)
		return false;
	if (t1->to_proc->tsk == t2->to_proc->tsk && t1->code == t2->code &&
		((t1->flags ^ t2->flags) & ~REKERNEL_TF_UPDATE_TXN) == 0 &&
		t1->buffer->pid == t2->buffer->pid &&
		t1->buffer->target_node->ptr == t2->buffer->target_node->ptr &&
		t1->buffer->target_node->cookie == t2->buffer->target_node->cookie)
		return true;
	return false;
}

static bool binder_can_force_cleanup_transaction(struct binder_transaction* t)
{
	return t && t->buffer && t->buffer->offsets_size == 0 &&
		(t->flags & TF_ONE_WAY);
}

static struct binder_transaction* binder_find_outdated_transaction_ilocked(
	struct binder_transaction* t, struct list_head* target_list, bool force_cleanup)
{
	struct binder_work* w;

	list_for_each_entry(w, target_list, entry) {
		struct binder_transaction* t_queued;

		if (w->type != BINDER_WORK_TRANSACTION)
			continue;
		t_queued = container_of(w, struct binder_transaction, work);
		if (binder_can_cleanup_transaction(t_queued, t))
			return t_queued;
	}

	if (force_cleanup) {
		list_for_each_entry(w, target_list, entry) {
			struct binder_transaction* t_queued;

			if (w->type != BINDER_WORK_TRANSACTION)
				continue;
			t_queued = container_of(w, struct binder_transaction, work);
			if (binder_can_force_cleanup_transaction(t_queued))
				return t_queued;
		}
	}
	return NULL;
}

static inline void __nocfi binder_release_entire_buffer(struct binder_proc* proc,
	struct binder_thread* thread, struct binder_buffer* buffer, bool is_failure)
{
	binder_size_t off_end_offset;

	off_end_offset = ALIGN(buffer->data_size, sizeof(void*));
	off_end_offset += buffer->offsets_size;

	re_kernel_transaction_buffer_release(proc, thread, buffer,
		off_end_offset, is_failure);
}

static inline void binder_stats_deleted(enum binder_stat_types type)
{
	atomic_inc(&re_kernel_stats->obj_deleted[type]);
}

static inline void __nocfi binder_discard_transaction(struct binder_proc* proc,
	struct binder_transaction* transaction)
{
	struct binder_buffer* buffer = transaction->buffer;

	if (!buffer) {
		kfree(transaction);
		binder_stats_deleted(BINDER_STAT_TRANSACTION);
		return;
	}
	transaction->buffer = NULL;
	buffer->transaction = NULL;
	binder_release_entire_buffer(proc, NULL, buffer, false);
	re_kernel_alloc_free_buf(&proc->alloc, buffer);
	kfree(transaction);
	binder_stats_deleted(BINDER_STAT_TRANSACTION);
}

static int __nocfi binder_proc_transaction_pre(struct kprobe* p, struct pt_regs* regs)
{
	struct binder_transaction* t = (struct binder_transaction*)regs->regs[0];
	struct binder_proc* proc = (struct binder_proc*)regs->regs[1];
	struct binder_node* node;
	struct binder_transaction* t_outdated;
	unsigned int cleanup_count = 0;
	bool force_cleanup;

	if (!t || !proc || !proc->tsk || !t->buffer)
		return 0;
	if (proc->is_frozen || !(t->flags & TF_ONE_WAY))
		return 0;

	node = t->buffer->target_node;
	if (!node)
		return 0;

	if (line_is_frozen(proc->tsk)) {
		force_cleanup = proc->alloc.free_async_space < WARN_AHEAD_SPACE ||
			proc->alloc.free_async_space <
			3 * (t->buffer->data_size + sizeof(struct binder_buffer));

		while (cleanup_count++ < REKERNEL_ASYNC_CLEANUP_MAX) {
			t_outdated = NULL;
			binder_node_lock(node);
			if (!node->has_async_transaction) {
				binder_node_unlock(node);
				break;
			}
			binder_inner_proc_lock(proc);
			t_outdated = binder_find_outdated_transaction_ilocked(t, &node->async_todo,
				force_cleanup);
			if (t_outdated) {
				list_del_init(&t_outdated->work.entry);
				if (proc->outstanding_txns > 0)
					proc->outstanding_txns--;
				if (list_empty(&node->async_todo))
					node->has_async_transaction = false;
			}
			binder_inner_proc_unlock(proc);
			binder_node_unlock(node);
			if (!t_outdated)
				break;

#ifdef DEBUG
			pr_info("[Re-Kernel LKM] free_outdated txn %d supersedes %d\n", t->debug_id, t_outdated->debug_id);
#endif
			binder_discard_transaction(proc, t_outdated);
		}
	}
	return 0;
}
#endif

int register_binder(void)
{
	int rc = LINE_SUCCESS;
	rc = register_trace_android_vh_binder_alloc_new_buf_locked(line_binder_alloc_new_buf_locked, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_binder_alloc_new_buf_locked failed, rc=%d\n", rc);
		return rc;
	}
	rc = register_trace_android_vh_binder_preset(line_binder_preset, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_binder_preset failed, rc=%d\n", rc);
		goto unregister_alloc_hook;
	}
	rc = register_trace_android_vh_binder_reply(line_binder_reply, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_binder_reply failed, rc=%d\n", rc);
		goto unregister_preset_hook;
	}
	rc = register_trace_android_vh_binder_trans(line_binder_transaction, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_binder_trans failed, rc=%d\n", rc);
		goto unregister_reply_hook;
	}
	return LINE_SUCCESS;

unregister_reply_hook:
	unregister_trace_android_vh_binder_reply(line_binder_reply, NULL);
unregister_preset_hook:
	unregister_trace_android_vh_binder_preset(line_binder_preset, NULL);
unregister_alloc_hook:
	unregister_trace_android_vh_binder_alloc_new_buf_locked(line_binder_alloc_new_buf_locked, NULL);
	return rc;
}

void unregister_binder(void)
{
	unregister_trace_android_vh_binder_alloc_new_buf_locked(line_binder_alloc_new_buf_locked, NULL);
	unregister_trace_android_vh_binder_preset(line_binder_preset, NULL);
	unregister_trace_android_vh_binder_reply(line_binder_reply, NULL);
	unregister_trace_android_vh_binder_trans(line_binder_transaction, NULL);
}

#ifdef CLEAN_UP_ASYNC_BINDER
static struct kprobe kp_kallsyms_lookup_name = {
	.symbol_name = "kallsyms_lookup_name"
};
static struct kprobe kp_binder_proc_transaction = {
	.symbol_name = "binder_proc_transaction",
	.pre_handler = binder_proc_transaction_pre
};

int __nocfi register_kp(void) {
	int rc = LINE_SUCCESS;

	rc = register_kprobe(&kp_kallsyms_lookup_name);
	if (rc != LINE_SUCCESS) {
		pr_err("register kprobe hooks failed, rc=%d\n", rc);
		return rc;
	}
	re_kallsyms_lookup_name = (void*)kp_kallsyms_lookup_name.addr;
	unregister_kprobe(&kp_kallsyms_lookup_name);

	re_kernel_transaction_buffer_release = (void*)re_kallsyms_lookup_name("binder_transaction_buffer_release");
	re_kernel_alloc_free_buf = (void*)re_kallsyms_lookup_name("binder_alloc_free_buf");
	re_kernel_stats = (void*)re_kallsyms_lookup_name("binder_stats");
	if (re_kernel_transaction_buffer_release == NULL || re_kernel_alloc_free_buf == NULL ||
	    re_kernel_stats == NULL) {
		rc = -EINVAL;
		pr_err("register kprobe kallsyms_lookup_name failed, rc=%d\n", rc);
		return rc;
	}

	rc = register_kprobe(&kp_binder_proc_transaction);
	if (rc != LINE_SUCCESS) {
		pr_err("register binder_proc_transaction hooks failed, rc=%d\n", rc);
		return rc;
	}

	return LINE_SUCCESS;
}

void unregister_kp(void) {
	unregister_kprobe(&kp_binder_proc_transaction);
}
#endif

/* ======================================================================
 * rekernel_signal.c — fatal-signal vendor hook
 * ====================================================================== */

static void line_signal(void *data, int sig, struct task_struct *killer, struct task_struct *dst)
{
	if (!dst || !killer)
		return;

	if (line_is_frozen(dst) &&
			(sig == SIGKILL
			|| sig == SIGTERM
			|| sig == SIGABRT
			|| sig == SIGQUIT)) {
#ifdef DEBUG
		pr_info("[Re-Kernel LKM] Process Signal! signal=%d\n", sig);
#endif
		if (rekernel_netlink_ready()) {
			char binder_kmsg[PACKET_SIZE];
			int len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;", sig, task_tgid_nr(killer), task_uid(killer).val, task_tgid_nr(dst), task_uid(dst).val);
			sendMessage(binder_kmsg, len);
		}
	}
}

int register_signal(void)
{
	int rc = LINE_SUCCESS;

	rc = register_trace_android_vh_do_send_sig_info(line_signal, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_do_send_sig_info failed, rc=%d\n", rc);
		return rc;
	}

	return LINE_SUCCESS;
}

void unregister_signal(void)
{
	unregister_trace_android_vh_do_send_sig_info(line_signal, NULL);
}

/* ======================================================================
 * rekernel_main.c — init / exit
 * ====================================================================== */

static int __init start_rekernel(void)
{
	pr_info("Thank you for choosing Re:Kernel!\n");
#ifdef DEBUG
	pr_info("Debug mode is enabled!\n");
#endif

	if (rekernel_netlink_start() != LINE_SUCCESS)
		return LINE_ERROR;

	pr_info("Re-Kernel start hooking!\n");

	if (register_binder() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook binder!\n", __func__);
		goto stop_netlink;
	}

	if (register_signal() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook signal!\n", __func__);
		goto unregister_binder_hook;
	}

	if (register_netfilter() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook netfilter!\n", __func__);
		goto unregister_signal_hook;
	}

#ifdef CLEAN_UP_ASYNC_BINDER
	if (register_kp() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook kprobe!\n", __func__);
		goto unregister_netfilter_hook;
	}
#endif

	pr_info("Re-Kernel hooked!\n");
	return LINE_SUCCESS;

#ifdef CLEAN_UP_ASYNC_BINDER
unregister_netfilter_hook:
#endif
	unregister_netfilter();
unregister_signal_hook:
	unregister_signal();
unregister_binder_hook:
	unregister_binder();
stop_netlink:
	rekernel_netlink_stop();
	return LINE_ERROR;
}

static void __exit exit_rekernel(void)
{
	pr_info("Re-Kernel closing...\n");
#ifdef CLEAN_UP_ASYNC_BINDER
	unregister_kp();
#endif
	unregister_netfilter();
	unregister_signal();
	unregister_binder();
	rekernel_netlink_stop();
}

module_init(start_rekernel);
module_exit(exit_rekernel);

MODULE_LICENSE("GPL");
