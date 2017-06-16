/*
 *	ipv4 nefilter for hook packet to or from xxx.xxx.xxx.xxx
 *
 *	Author: Yonggang Guo <hero.gariker@gmail.com>
 *
 */

#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#include <net/ip.h>
#include <net/ipv4_hunter.h>

#define IP_BLOCK_CACHE_NAME "ip_block"

/* IP block node */
struct ip_node {
	__be32 addr;
	struct list_head list;
};

DEFINE_MUTEX(m_lock);
spinlock_t s_lock;

LIST_HEAD(nf_ips);

static struct kmem_cache *ip_block_cache;

static unsigned long ip_nums;

/* Warning : ia is big endian */
static char *inet_ntoa(char *ip_buf, __be32 addr)
{
	unsigned char *ucb = (unsigned char *)&addr;

	if (ip_buf == NULL) 
		return NULL;
	
	sprintf(ip_buf,"%d.%d.%d.%d",
		ucb[0] & 0xFF, ucb[1] & 0xFF, ucb[2] & 0xFF, ucb[3] & 0xFF);

	return ip_buf;
	
}

static int inet_aton(const char *ip_str, struct in_addr *ia)
{
	int ret;
	int uib[4];

	if (ip_str == NULL)
		return -EINVAL;
	
	ret = sscanf(ip_str,"%d.%d.%d.%d", 
		&uib[0], &uib[1], &uib[2], &uib[3]);
	if (ret <= 0)
		return -EINVAL;

	ia->s_addr = (uib[0] & 0xFF) | (uib[1] & 0xFF) << 8 |
		(uib[2] & 0xFF) << 16 | (uib[3] & 0xFF) << 24;
	
	return 0;
}

static bool ip_in_block_list(__be32 addr)
{
	struct ip_node *ip_node;
	struct list_head *lh;
	unsigned long flags;

	spin_lock_irqsave(&s_lock,flags);
	list_for_each(lh, &nf_ips) {
		ip_node = list_entry(lh, struct ip_node, list);
		if (ip_node->addr == addr) {
			spin_unlock_irqrestore(&s_lock,flags);
			return true;
		}
	}

	spin_unlock_irqrestore(&s_lock,flags);
	return false;
}

static void del_ip_node(__be32 addr) 
{
	struct ip_node *ip_node;
	struct list_head *lh;
	unsigned long flags;

	spin_lock_irqsave(&s_lock, flags);
	list_for_each(lh, &nf_ips) {
		ip_node = list_entry(lh, struct ip_node, list);
		if (ip_node->addr == addr) {
			list_del(&ip_node->list);
			ip_nums--;
			break;
		}
	}
	
	spin_unlock_irqrestore(&s_lock, flags);
	kmem_cache_free(ip_block_cache, (void *)ip_node);
}

static void add_ip_node(struct ip_node *ip_node)
{
	unsigned long flags;
	
	spin_lock_irqsave(&s_lock,flags);
	list_add_tail(&ip_node->list, &nf_ips);
	ip_nums++;
	spin_unlock_irqrestore(&s_lock, flags);
}

static unsigned int ipv4_hook_firewall_in(const struct nf_hook_ops *ops,
			       struct sk_buff *skb, const struct net_device *in,
			       const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	char tmp_ip_buf[MAX_IP_LEN];
	
	iph = ip_hdr(skb);
	if (ip_in_block_list(iph->saddr))
		return NF_DROP;
	return NF_ACCEPT;
}

static unsigned int ipv4_hook_firewall_out(const struct nf_hook_ops *ops,
			       struct sk_buff *skb, const struct net_device *in,
			       const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	return NF_ACCEPT;
}

// hook NF_INET_LOCAL_IN or NF_INET_LOCAL_OUT
static struct nf_hook_ops ipv4_netfilter[2] = {
	{
		.owner	= THIS_MODULE,
		.hook	= ipv4_hook_firewall_in,
		.pf		= PF_INET,
		.hooknum= NF_INET_LOCAL_IN,
		.priority= 100,
	},
	{
		.owner	= THIS_MODULE,
		.hook 	= ipv4_hook_firewall_out,
		.pf		= PF_INET,
		.hooknum= NF_INET_LOCAL_OUT,
		.priority = 100,	
	},
};

static int ip_filter_open(struct inode *inode, struct file *filp)
{	
	return 0;
}

static long ip_filter_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int i, ret;
	struct in_addr ia;
	char ip_str[MAX_IP_LEN];
	struct ip_node *ip_node;
	unsigned int count;
	struct list_head *lh;
	unsigned long flags;
	ip_param_t param;
	struct ip_add_param *add_param;
	struct ip_del_param *del_param;
	struct ip_query_param *query_param;

	mutex_lock(&m_lock);
	switch(cmd) {
	case IP_ADD:
		add_param = &param.add_param;
		if (copy_from_user(add_param, (void *)arg, sizeof(*add_param))) {
			mutex_unlock(&m_lock);
			return -EINVAL;
		}

		if (add_param->num <= 0 || add_param->num > MAX_IP_NUM) {
			mutex_unlock(&m_lock);
			return -EINVAL;
		}

		for (i = 0; i < add_param->num; i++) {
			if (copy_from_user(ip_str, (void *)add_param->ip_strs[i], sizeof ip_str)) {
				mutex_unlock(&m_lock);
				return -EINVAL;
			}

			ret = inet_aton(ip_str, &ia); 
			if (ret < 0)
				continue;

			if (ip_in_block_list(ia.s_addr))
				continue;

			ip_node = kmem_cache_alloc(ip_block_cache, GFP_KERNEL);
			if (!ip_node) {
				mutex_unlock(&m_lock);
				return -ENOMEM;
			}

			ip_node->addr = ia.s_addr;
			add_ip_node(ip_node);			
		}	
		break;
	case IP_DEL:
		del_param = &param.del_param;
		if (copy_from_user(del_param, (void *)arg, sizeof(*del_param))) {
			mutex_unlock(&m_lock);
			return -EINVAL;
		}

		if (del_param->num <= 0 || del_param->num > MAX_IP_NUM) {
			mutex_unlock(&m_lock);
			return -EINVAL;
		}

		for (i = 0; i < del_param->num; i++) {
			if (copy_from_user(ip_str, (void *)del_param->ip_strs[i], sizeof ip_str)) {
				mutex_unlock(&m_lock);
				return -EINVAL;
			}

			ret = inet_aton(ip_str, &ia);
			if (ret < 0)  
				continue;

			if (!ip_in_block_list(ia.s_addr))
				continue;

			del_ip_node(ia.s_addr);
		}

		break;
	case IP_QUERY:
		query_param = &param.query_param;
		if (copy_from_user(query_param, (void *)arg, sizeof(*query_param))) {
			mutex_unlock(&m_lock);
			return -EINVAL;
		}

		if (query_param->num <= 0)
			return -EINVAL;
		
		spin_lock_irqsave(&s_lock, flags);
		i = 0;
		count = ip_nums > MAX_IP_QUERY_NUM ? MAX_IP_QUERY_NUM : ip_nums;
		count = count > query_param->num ? query_param->num : count;
		list_for_each(lh, &nf_ips) {
			ip_node = list_entry(lh, struct ip_node, list);
			inet_ntoa(ip_str, ip_node->addr);
			if (copy_to_user(query_param->ip_strs[i++], ip_str, sizeof ip_str)) {
				spin_unlock_irqrestore(&s_lock, flags);
				mutex_unlock(&m_lock);
				return -EINVAL;
				
			}

			if (i >= count)
				break;				
		}
		spin_unlock_irqrestore(&s_lock, flags);
		if (put_user(count,&((struct ip_query_param *)arg)->num)) {
			mutex_unlock(&m_lock);
			return -EINVAL;
		}
			
		break;
	default:
		break;
	}

	mutex_unlock(&m_lock);
	return 0;
}

static struct file_operations ip_filter_ops = {
	.open = ip_filter_open,
	.unlocked_ioctl = ip_filter_ioctl,
};


static int __init ipv4_netfilter_init(void)
{
	ip_block_cache = kmem_cache_create(IP_BLOCK_CACHE_NAME, sizeof(struct ip_node),
		0, 0,NULL);
	if (!ip_block_cache) {
		printk(KERN_WARNING "%s ip_block_cache create failed!\n", __func__);
		return -1;
	}

	spin_lock_init(&s_lock);
	ip_nums = 0;
	
	proc_create("ip_filter", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
		NULL, &ip_filter_ops);
	
	nf_register_hook(&ipv4_netfilter[0]);
	nf_register_hook(&ipv4_netfilter[1]);
	return 0;
}

static void __exit ipv4_netfilter_exit(void)
{
	nf_unregister_hook(&ipv4_netfilter[0]);
	nf_unregister_hook(&ipv4_netfilter[1]);
}

module_init(ipv4_netfilter_init);
module_exit(ipv4_netfilter_exit);
