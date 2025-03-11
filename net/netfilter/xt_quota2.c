/*
 * xt_quota2 - enhanced xt_quota that can count upwards and in packets
 * as a minimal accounting match.
<<<<<<< HEAD
 * by Jan Engelhardt <jengelh@medozas.de>, 2008
 *
 * Originally based on xt_quota.c:
 * 	netfilter module to enforce network quotas
 * 	Sam Johnston <samj@samj.net>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License; either
 *	version 2 of the License, as published by the Free Software Foundation.
 */
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>
#include <net/netlink.h>
=======
 * by Jan Engelhardt , 2008
 *
 * Originally based on xt_quota.c:
 * 	Xtables module to enforce network quotas
 * 	Sam Johnston <samj@samj.net>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License
 *	version 2, as published by the Free Software Foundation.
 */
#include <linux/list.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <asm/atomic.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/dst.h>
>>>>>>> ohos/OpenHarmony-5.0.2-Release

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_quota2.h>

<<<<<<< HEAD
#ifdef CONFIG_NETFILTER_XT_MATCH_QUOTA2_LOG
/* For compatibility, these definitions are copied from the
 * deprecated header file <linux/netfilter_ipv4/ipt_ULOG.h> */
#define ULOG_MAC_LEN	80
#define ULOG_PREFIX_LEN	32

/* Format of the ULOG packets passed through netlink */
typedef struct ulog_packet_msg {
	unsigned long mark;
	long timestamp_sec;
	long timestamp_usec;
	unsigned int hook;
	char indev_name[IFNAMSIZ];
	char outdev_name[IFNAMSIZ];
	size_t data_len;
	char prefix[ULOG_PREFIX_LEN];
	unsigned char mac_len;
	unsigned char mac[ULOG_MAC_LEN];
	unsigned char payload[0];
} ulog_packet_msg_t;
#endif

=======
>>>>>>> ohos/OpenHarmony-5.0.2-Release
/**
 * @lock:	lock to protect quota writers from each other
 */
struct xt_quota_counter {
	u_int64_t quota;
	spinlock_t lock;
	struct list_head list;
	atomic_t ref;
	char name[sizeof(((struct xt_quota_mtinfo2 *)NULL)->name)];
	struct proc_dir_entry *procfs_entry;
};

<<<<<<< HEAD
#ifdef CONFIG_NETFILTER_XT_MATCH_QUOTA2_LOG
/* Harald's favorite number +1 :D From ipt_ULOG.C */
static int qlog_nl_event = 112;
module_param_named(event_num, qlog_nl_event, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(event_num,
		 "Event number for NETLINK_NFLOG message. 0 disables log."
		 "111 is what ipt_ULOG uses.");
static struct sock *nflognl;
#endif

static LIST_HEAD(counter_list);
static DEFINE_SPINLOCK(counter_list_lock);

static struct proc_dir_entry *proc_xt_quota;
static unsigned int quota_list_perms = S_IRUGO | S_IWUSR;
static kuid_t quota_list_uid = KUIDT_INIT(0);
static kgid_t quota_list_gid = KGIDT_INIT(0);
module_param_named(perms, quota_list_perms, uint, S_IRUGO | S_IWUSR);

#ifdef CONFIG_NETFILTER_XT_MATCH_QUOTA2_LOG
static void quota2_log(unsigned int hooknum,
		       const struct sk_buff *skb,
		       const struct net_device *in,
		       const struct net_device *out,
		       const char *prefix)
{
	ulog_packet_msg_t *pm;
	struct sk_buff *log_skb;
	size_t size;
	struct nlmsghdr *nlh;

	if (!qlog_nl_event)
		return;

	size = NLMSG_SPACE(sizeof(*pm));
	size = max(size, (size_t)NLMSG_GOODSIZE);
	log_skb = alloc_skb(size, GFP_ATOMIC);
	if (!log_skb) {
		pr_err("xt_quota2: cannot alloc skb for logging\n");
		return;
	}

	nlh = nlmsg_put(log_skb, /*pid*/0, /*seq*/0, qlog_nl_event,
			sizeof(*pm), 0);
	if (!nlh) {
		pr_err("xt_quota2: nlmsg_put failed\n");
		kfree_skb(log_skb);
		return;
	}
	pm = nlmsg_data(nlh);
	memset(pm, 0, sizeof(*pm));
	if (skb->tstamp == 0)
		__net_timestamp((struct sk_buff *)skb);
	pm->hook = hooknum;
	if (prefix != NULL)
		strlcpy(pm->prefix, prefix, sizeof(pm->prefix));
	if (in)
		strlcpy(pm->indev_name, in->name, sizeof(pm->indev_name));
	if (out)
		strlcpy(pm->outdev_name, out->name, sizeof(pm->outdev_name));

	NETLINK_CB(log_skb).dst_group = 1;
	pr_debug("throwing 1 packets to netlink group 1\n");
	netlink_broadcast(nflognl, log_skb, 0, 1, GFP_ATOMIC);
}
#else
static void quota2_log(unsigned int hooknum,
		       const struct sk_buff *skb,
		       const struct net_device *in,
		       const struct net_device *out,
		       const char *prefix)
{
}
#endif  /* if+else CONFIG_NETFILTER_XT_MATCH_QUOTA2_LOG */

static ssize_t quota_proc_read(struct file *file, char __user *buf,
			   size_t size, loff_t *ppos)
{
	struct xt_quota_counter *e = PDE_DATA(file_inode(file));
	char tmp[24];
	size_t tmp_size;

	spin_lock_bh(&e->lock);
	tmp_size = scnprintf(tmp, sizeof(tmp), "%llu\n", e->quota);
	spin_unlock_bh(&e->lock);
	return simple_read_from_buffer(buf, size, ppos, tmp, tmp_size);
}

static ssize_t quota_proc_write(struct file *file, const char __user *input,
                            size_t size, loff_t *ppos)
{
	struct xt_quota_counter *e = PDE_DATA(file_inode(file));
	char buf[sizeof("18446744073709551616")];
=======
struct quota2_net {
	struct list_head counter_list;
	struct proc_dir_entry *proc_xt_quota;
};

static int quota2_net_id;
static inline struct quota2_net *quota2_pernet(struct net *net)
{
	return net_generic(net, quota2_net_id);
}

static DEFINE_SPINLOCK(counter_list_lock);

static unsigned int quota_list_perms = S_IRUGO | S_IWUSR;
static unsigned int quota_list_uid   = 0;
static unsigned int quota_list_gid   = 0;
module_param_named(perms, quota_list_perms, uint, S_IRUGO | S_IWUSR);
module_param_named(uid, quota_list_uid, uint, S_IRUGO | S_IWUSR);
module_param_named(gid, quota_list_gid, uint, S_IRUGO | S_IWUSR);


static int quota_proc_show(struct seq_file *m, void *data)
{
	struct xt_quota_counter *e = m->private;

	spin_lock_bh(&e->lock);
	seq_printf(m, "%llu\n", e->quota);
	spin_unlock_bh(&e->lock);
	return 0;
}

static int quota_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, quota_proc_show, PDE_DATA(inode));
}

static ssize_t
quota_proc_write(struct file *file, const char __user *input,
                 size_t size, loff_t *loff)
{
	struct xt_quota_counter *e = PDE_DATA(file_inode(file));
	char buf[sizeof("+-18446744073709551616")];
>>>>>>> ohos/OpenHarmony-5.0.2-Release

	if (size > sizeof(buf))
		size = sizeof(buf);
	if (copy_from_user(buf, input, size) != 0)
		return -EFAULT;
	buf[sizeof(buf)-1] = '\0';
	if (size < sizeof(buf))
		buf[size] = '\0';

<<<<<<< HEAD
	spin_lock_bh(&e->lock);
	e->quota = simple_strtoull(buf, NULL, 0);
	spin_unlock_bh(&e->lock);
	return size;
}

static const struct proc_ops q2_counter_fops = {
	.proc_read	= quota_proc_read,
	.proc_write	= quota_proc_write,
	.proc_lseek	= default_llseek,
=======
	if (*buf == '+') {
		int64_t temp = simple_strtoll(buf + 1, NULL, 0);
		spin_lock_bh(&e->lock);
		/* Do not let quota become negative if @tmp is very negative */
		if (temp > 0 || -temp < e->quota)
			e->quota += temp;
		else
			e->quota = 0;
		spin_unlock_bh(&e->lock);
	} else if (*buf == '-') {
		int64_t temp = simple_strtoll(buf + 1, NULL, 0);
		spin_lock_bh(&e->lock);
		/* Do not let quota become negative if @tmp is very big */
		if (temp < 0 || temp < e->quota)
			e->quota -= temp;
		else
			e->quota = 0;
		spin_unlock_bh(&e->lock);
	} else {
		spin_lock_bh(&e->lock);
		e->quota = simple_strtoull(buf, NULL, 0);
		spin_unlock_bh(&e->lock);
	}
	return size;
}

static const struct proc_ops quota_proc_fops = {
	.proc_open    = quota_proc_open,
	.proc_read    = seq_read,
	.proc_write   = quota_proc_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
>>>>>>> ohos/OpenHarmony-5.0.2-Release
};

static struct xt_quota_counter *
q2_new_counter(const struct xt_quota_mtinfo2 *q, bool anon)
{
	struct xt_quota_counter *e;
	unsigned int size;

	/* Do not need all the procfs things for anonymous counters. */
	size = anon ? offsetof(typeof(*e), list) : sizeof(*e);
	e = kmalloc(size, GFP_KERNEL);
	if (e == NULL)
		return NULL;

	e->quota = q->quota;
	spin_lock_init(&e->lock);
	if (!anon) {
		INIT_LIST_HEAD(&e->list);
		atomic_set(&e->ref, 1);
<<<<<<< HEAD
		strlcpy(e->name, q->name, sizeof(e->name));
=======
		strncpy(e->name, q->name, sizeof(e->name));
>>>>>>> ohos/OpenHarmony-5.0.2-Release
	}
	return e;
}

/**
 * q2_get_counter - get ref to counter or create new
 * @name:	name of counter
 */
static struct xt_quota_counter *
<<<<<<< HEAD
q2_get_counter(const struct xt_quota_mtinfo2 *q)
{
	struct proc_dir_entry *p;
	struct xt_quota_counter *e = NULL;
	struct xt_quota_counter *new_e;
=======
q2_get_counter(struct net *net, const struct xt_quota_mtinfo2 *q)
{
	struct proc_dir_entry *p;
	struct xt_quota_counter *e;
	struct quota2_net *quota2_net = quota2_pernet(net);
>>>>>>> ohos/OpenHarmony-5.0.2-Release

	if (*q->name == '\0')
		return q2_new_counter(q, true);

<<<<<<< HEAD
	/* No need to hold a lock while getting a new counter */
	new_e = q2_new_counter(q, false);
	if (new_e == NULL)
		goto out;

	spin_lock_bh(&counter_list_lock);
	list_for_each_entry(e, &counter_list, list)
		if (strcmp(e->name, q->name) == 0) {
			atomic_inc(&e->ref);
			spin_unlock_bh(&counter_list_lock);
			kfree(new_e);
			pr_debug("xt_quota2: old counter name=%s", e->name);
			return e;
		}
	e = new_e;
	pr_debug("xt_quota2: new_counter name=%s", e->name);
	list_add_tail(&e->list, &counter_list);
	/* The entry having a refcount of 1 is not directly destructible.
	 * This func has not yet returned the new entry, thus iptables
	 * has not references for destroying this entry.
	 * For another rule to try to destroy it, it would 1st need for this
	 * func* to be re-invoked, acquire a new ref for the same named quota.
	 * Nobody will access the e->procfs_entry either.
	 * So release the lock. */
	spin_unlock_bh(&counter_list_lock);

	/* create_proc_entry() is not spin_lock happy */
	p = e->procfs_entry = proc_create_data(e->name, quota_list_perms,
	                      proc_xt_quota, &q2_counter_fops, e);

	if (IS_ERR_OR_NULL(p)) {
		spin_lock_bh(&counter_list_lock);
		list_del(&e->list);
		spin_unlock_bh(&counter_list_lock);
		goto out;
	}
	proc_set_user(p, quota_list_uid, quota_list_gid);
	return e;

 out:
=======
	spin_lock_bh(&counter_list_lock);
	list_for_each_entry(e, &quota2_net->counter_list, list)
		if (strcmp(e->name, q->name) == 0) {
			atomic_inc(&e->ref);
			spin_unlock_bh(&counter_list_lock);
			return e;
		}

	e = q2_new_counter(q, false);
	if (e == NULL)
		goto out;

	p = proc_create_data(e->name, quota_list_perms,
	                     quota2_net->proc_xt_quota,
	                     &quota_proc_fops, e);
	if (p == NULL || IS_ERR(p))
		goto out;

	e->procfs_entry = p;
	proc_set_user(p, make_kuid(&init_user_ns, quota_list_uid),
	              make_kgid(&init_user_ns, quota_list_gid));
	list_add_tail(&e->list, &quota2_net->counter_list);
	spin_unlock_bh(&counter_list_lock);
	return e;

 out:
	spin_unlock_bh(&counter_list_lock);
>>>>>>> ohos/OpenHarmony-5.0.2-Release
	kfree(e);
	return NULL;
}

static int quota_mt2_check(const struct xt_mtchk_param *par)
{
	struct xt_quota_mtinfo2 *q = par->matchinfo;

<<<<<<< HEAD
	pr_debug("xt_quota2: check() flags=0x%04x", q->flags);

=======
>>>>>>> ohos/OpenHarmony-5.0.2-Release
	if (q->flags & ~XT_QUOTA_MASK)
		return -EINVAL;

	q->name[sizeof(q->name)-1] = '\0';
	if (*q->name == '.' || strchr(q->name, '/') != NULL) {
		printk(KERN_ERR "xt_quota.3: illegal name\n");
		return -EINVAL;
	}

<<<<<<< HEAD
	q->master = q2_get_counter(q);
=======
	q->master = q2_get_counter(par->net, q);
>>>>>>> ohos/OpenHarmony-5.0.2-Release
	if (q->master == NULL) {
		printk(KERN_ERR "xt_quota.3: memory alloc failure\n");
		return -ENOMEM;
	}

	return 0;
}

static void quota_mt2_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_quota_mtinfo2 *q = par->matchinfo;
	struct xt_quota_counter *e = q->master;
<<<<<<< HEAD
=======
	struct quota2_net *quota2_net = quota2_pernet(par->net);
>>>>>>> ohos/OpenHarmony-5.0.2-Release

	if (*q->name == '\0') {
		kfree(e);
		return;
	}

	spin_lock_bh(&counter_list_lock);
	if (!atomic_dec_and_test(&e->ref)) {
		spin_unlock_bh(&counter_list_lock);
		return;
	}

	list_del(&e->list);
<<<<<<< HEAD
	spin_unlock_bh(&counter_list_lock);
	remove_proc_entry(e->name, proc_xt_quota);
=======
	remove_proc_entry(e->name, quota2_net->proc_xt_quota);
	spin_unlock_bh(&counter_list_lock);
>>>>>>> ohos/OpenHarmony-5.0.2-Release
	kfree(e);
}

static bool
quota_mt2(const struct sk_buff *skb, struct xt_action_param *par)
{
	struct xt_quota_mtinfo2 *q = (void *)par->matchinfo;
	struct xt_quota_counter *e = q->master;
<<<<<<< HEAD
	int charge = (q->flags & XT_QUOTA_PACKET) ? 1 : skb->len;
	bool no_change = q->flags & XT_QUOTA_NO_CHANGE;
=======
>>>>>>> ohos/OpenHarmony-5.0.2-Release
	bool ret = q->flags & XT_QUOTA_INVERT;

	spin_lock_bh(&e->lock);
	if (q->flags & XT_QUOTA_GROW) {
		/*
		 * While no_change is pointless in "grow" mode, we will
		 * implement it here simply to have a consistent behavior.
		 */
<<<<<<< HEAD
		if (!no_change)
			e->quota += charge;
		ret = true; /* note: does not respect inversion (bug??) */
	} else {
		if (e->quota > charge) {
			if (!no_change)
				e->quota -= charge;
			ret = !ret;
		} else if (e->quota) {
			/* We are transitioning, log that fact. */
			quota2_log(xt_hooknum(par),
				   skb,
				   xt_in(par),
				   xt_out(par),
				   q->name);
			/* we do not allow even small packets from now on */
			e->quota = 0;
		}
=======
		if (!(q->flags & XT_QUOTA_NO_CHANGE)) {
			e->quota += (q->flags & XT_QUOTA_PACKET) ? 1 : skb->len;
			q->quota = e->quota;
		}
		ret = true;
	} else {
		if (e->quota >= ((q->flags & XT_QUOTA_PACKET) ? 1 : skb->len)) {
			if (!(q->flags & XT_QUOTA_NO_CHANGE))
				e->quota -= (q->flags & XT_QUOTA_PACKET) ? 1 : skb->len;
			ret = !ret;
		} else {
			/* we do not allow even small packets from now on */
			if (!(q->flags & XT_QUOTA_NO_CHANGE))
				e->quota = 0;
		}
		q->quota = e->quota;
>>>>>>> ohos/OpenHarmony-5.0.2-Release
	}
	spin_unlock_bh(&e->lock);
	return ret;
}

static struct xt_match quota_mt2_reg[] __read_mostly = {
	{
		.name       = "quota2",
		.revision   = 3,
		.family     = NFPROTO_IPV4,
		.checkentry = quota_mt2_check,
		.match      = quota_mt2,
		.destroy    = quota_mt2_destroy,
		.matchsize  = sizeof(struct xt_quota_mtinfo2),
<<<<<<< HEAD
		.usersize   = offsetof(struct xt_quota_mtinfo2, master),
=======
>>>>>>> ohos/OpenHarmony-5.0.2-Release
		.me         = THIS_MODULE,
	},
	{
		.name       = "quota2",
		.revision   = 3,
		.family     = NFPROTO_IPV6,
		.checkentry = quota_mt2_check,
		.match      = quota_mt2,
		.destroy    = quota_mt2_destroy,
		.matchsize  = sizeof(struct xt_quota_mtinfo2),
<<<<<<< HEAD
		.usersize   = offsetof(struct xt_quota_mtinfo2, master),
=======
>>>>>>> ohos/OpenHarmony-5.0.2-Release
		.me         = THIS_MODULE,
	},
};

<<<<<<< HEAD
static int __init quota_mt2_init(void)
{
	int ret;
	pr_debug("xt_quota2: init()");

#ifdef CONFIG_NETFILTER_XT_MATCH_QUOTA2_LOG
	nflognl = netlink_kernel_create(&init_net, NETLINK_NFLOG, NULL);
	if (!nflognl)
		return -ENOMEM;
#endif

	proc_xt_quota = proc_mkdir("xt_quota", init_net.proc_net);
	if (proc_xt_quota == NULL)
		return -EACCES;

	ret = xt_register_matches(quota_mt2_reg, ARRAY_SIZE(quota_mt2_reg));
	if (ret < 0)
		remove_proc_entry("xt_quota", init_net.proc_net);
	pr_debug("xt_quota2: init() %d", ret);
=======
static int __net_init quota2_net_init(struct net *net)
{
	struct quota2_net *quota2_net = quota2_pernet(net);
	INIT_LIST_HEAD(&quota2_net->counter_list);

	quota2_net->proc_xt_quota = proc_mkdir("xt_quota", net->proc_net);
	if (quota2_net->proc_xt_quota == NULL)
		return -EACCES;
	return 0;
}

static void __net_exit quota2_net_exit(struct net *net)
{
	struct quota2_net *quota2_net = quota2_pernet(net);
	struct xt_quota_counter *e = NULL;
	struct list_head *pos, *q;

	remove_proc_entry("xt_quota", net->proc_net);

	/* destroy counter_list while freeing it's content */
	spin_lock_bh(&counter_list_lock);
	list_for_each_safe(pos, q, &quota2_net->counter_list) {
		e = list_entry(pos, struct xt_quota_counter, list);
		list_del(pos);
		kfree(e);
	}
	spin_unlock_bh(&counter_list_lock);
}

static struct pernet_operations quota2_net_ops = {
	.init   = quota2_net_init,
	.exit   = quota2_net_exit,
	.id     = &quota2_net_id,
	.size   = sizeof(struct quota2_net),
};

static int __init quota_mt2_init(void)
{
	int ret;
	ret = register_pernet_subsys(&quota2_net_ops);
	if (ret < 0)
		return ret;

	ret = xt_register_matches(quota_mt2_reg, ARRAY_SIZE(quota_mt2_reg));
	if (ret < 0)
		unregister_pernet_subsys(&quota2_net_ops);

>>>>>>> ohos/OpenHarmony-5.0.2-Release
	return ret;
}

static void __exit quota_mt2_exit(void)
{
	xt_unregister_matches(quota_mt2_reg, ARRAY_SIZE(quota_mt2_reg));
<<<<<<< HEAD
	remove_proc_entry("xt_quota", init_net.proc_net);
=======
	unregister_pernet_subsys(&quota2_net_ops);
>>>>>>> ohos/OpenHarmony-5.0.2-Release
}

module_init(quota_mt2_init);
module_exit(quota_mt2_exit);
MODULE_DESCRIPTION("Xtables: countdown quota match; up counter");
MODULE_AUTHOR("Sam Johnston <samj@samj.net>");
<<<<<<< HEAD
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
=======
MODULE_AUTHOR("Jan Engelhardt ");
>>>>>>> ohos/OpenHarmony-5.0.2-Release
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_quota2");
MODULE_ALIAS("ip6t_quota2");
