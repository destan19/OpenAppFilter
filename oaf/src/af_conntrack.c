#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/sysctl.h>
#include <net/ip.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/etherdevice.h>
#include <linux/cdev.h>
#include "af_conntrack.h"
#include "af_log.h"

struct hlist_head af_conn_table[AF_CONN_HASH_SIZE];

DEFINE_SPINLOCK(af_conn_lock);

static u32 af_conn_hash(u32 src_ip, u32 dst_ip, 
                       u16 src_port, u16 dst_port, 
                       u8 protocol)
{
    return jhash_3words(src_ip, dst_ip,
                       ((u32)protocol << 16) | src_port,
                       dst_port) % AF_CONN_HASH_SIZE;
}


void af_conn_cleanup(void)
{
    int i;
    spin_lock(&af_conn_lock);
	af_conn_t *p = NULL;
	struct hlist_node *n;

	for (i = 0; i < AF_CONN_HASH_SIZE; i++)
	{
		hlist_for_each_entry_safe(p, n, &af_conn_table[i], node)
		{
			hlist_del(&p->node);
			kfree(p);
		}
	}
    spin_unlock(&af_conn_lock);
}

af_conn_t *af_conn_add(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 protocol)
{
    u32 hash;
    af_conn_t *conn;
    hash = af_conn_hash(src_ip, dst_ip, src_port, dst_port, protocol);
    conn = kmalloc(sizeof(af_conn_t), GFP_ATOMIC);
    if (!conn) {
        return NULL;
    }
    
    conn->src_ip = src_ip;
    conn->dst_ip = dst_ip;
    conn->src_port = src_port;
    conn->dst_port = dst_port;
    conn->protocol = protocol;
    conn->total_pkts = 0;
    conn->app_id = 0;
	conn->client_hello = 0;
    conn->drop = 0;
    conn->state = AF_CONN_NEW;
    conn->last_jiffies = jiffies;
    hlist_add_head(&conn->node, &af_conn_table[hash]);
    AF_LMT_INFO("add new conn ok...%pI4:%d->%pI4:%d %d\n",
        &conn->src_ip, conn->src_port, &conn->dst_ip, conn->dst_port, conn->protocol);
    return conn;
}


af_conn_t* af_conn_find(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 protocol)
{
    u32 hash;
    af_conn_t *conn;
    
    hash = af_conn_hash(src_ip, dst_ip, src_port, dst_port, protocol);
	hlist_for_each_entry(conn, &af_conn_table[hash], node)
	{
		if (conn->src_ip == src_ip && conn->dst_ip == dst_ip &&
            conn->src_port == src_port && conn->dst_port == dst_port &&
            conn->protocol == protocol) {
            return conn;
        }
	}
    return NULL;
}


af_conn_t* af_conn_find_and_add(u32 src_ip, u32 dst_ip, u16 src_port, u16 dst_port, u8 protocol)
{
    af_conn_t *conn;
    conn = af_conn_find(src_ip, dst_ip, src_port, dst_port, protocol);
    if (!conn)
    {
        conn = af_conn_add(src_ip, dst_ip, src_port, dst_port, protocol);
    }
    return conn;
}


void af_conn_update(af_conn_t *conn, u32 app_id, u8 drop)
{
    spin_lock(&af_conn_lock);
    conn->app_id = app_id;
    conn->drop = drop;
    conn->last_jiffies = jiffies;
    spin_unlock(&af_conn_lock);
}

#define MAX_AF_CONN_CHECK_COUNT 5
void af_conn_clean_timeout(void)
{
    int i;
    af_conn_t *conn;
    struct hlist_node *n;
    unsigned long timeout = AF_CONN_TIMEOUT * HZ;
    static int last_bucket = 0;
    int count = 0;
    spin_lock(&af_conn_lock);
    for (i = last_bucket; i < AF_CONN_HASH_SIZE; i++)
    {
        hlist_for_each_entry_safe(conn, n, &af_conn_table[i], node)
        {
            if (time_after(jiffies, conn->last_jiffies + timeout)) {
                AF_LMT_INFO("clean timeout conn ok...%pI4:%d->%pI4:%d %d\n",
                 &conn->src_ip, conn->src_port, &conn->dst_ip, conn->dst_port, conn->protocol);
                hlist_del(&(conn->node));
                kfree(conn);
            }
        }
        last_bucket = i;
        count++;
        if (count > MAX_AF_CONN_CHECK_COUNT)
            break;
    }
    if (last_bucket == AF_CONN_HASH_SIZE - 1)
    {
        last_bucket = 0;
    }
    spin_unlock(&af_conn_lock);
} 

struct af_conn_iter_state
{
    unsigned int bucket;
};


static void *af_conn_seq_start(struct seq_file *s, loff_t *pos)
{
    if (*pos == 0)
    {
        return SEQ_START_TOKEN;
    }
    struct af_conn_iter_state *st = s->private;
    while (st->bucket < AF_CONN_HASH_SIZE){
        if (!hlist_empty(&(af_conn_table[st->bucket])))
        {
            return &af_conn_table[st->bucket++].first->next;
        }
        st->bucket++;
    }
    return NULL;
}

static void *af_conn_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    (*pos)++;
    if (v == SEQ_START_TOKEN){
        return NULL;
    }
    struct hlist_node *node = (struct hlist_node *)v;
    node = node->next;
    if (node != NULL)
        return node;
    return NULL;
}

static void af_conn_seq_stop(struct seq_file *s, void *v)
{
}

static int af_conn_seq_show(struct seq_file *s, void *v)
{
    unsigned char src_ip_str[32] = {0};
    unsigned char dst_ip_str[32] = {0};
    static int index = 0;
    af_conn_t *node = (af_conn_t *)v;
    if (v == SEQ_START_TOKEN)
    {
        index = 0;
        seq_printf(s, "%-4s %-20s %-20s %-12s %-12s %-12s %-12s %-12s %-12s %-12s\n", 
        "Id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "app_id", "drop", "inactive", "total_pkts");
        return 0;
    }

    index++;
    sprintf(src_ip_str, "%pI4", &node->src_ip);
    sprintf(dst_ip_str, "%pI4", &node->dst_ip);
    u_int32_t inactive_time = jiffies - node->last_jiffies;

    seq_printf(s, "%-4d %-20s %-20s %-12d %-12d %-12d %-12d %-12d %-12d %-12d\n", index, src_ip_str, dst_ip_str,
               node->src_port, node->dst_port, node->protocol, node->app_id, node->drop, inactive_time, node->total_pkts);
    return 0;
}
static const struct seq_operations af_conn_seq_ops = {
    .start = af_conn_seq_start,
    .next = af_conn_seq_next,
    .stop = af_conn_seq_stop,
    .show = af_conn_seq_show
};


static int af_conn_open(struct inode *inode, struct file *file)
{
    struct seq_file *seq;
    struct af_conn_iter_state *iter;
    int err;

    iter = kzalloc(sizeof(*iter), GFP_KERNEL);
    if (!iter)
        return -ENOMEM;

    err = seq_open(file, &af_conn_seq_ops);
    if (err)
    {
        kfree(iter);
        return err;
    }

    seq = file->private_data;
    seq->private = iter;
    return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
static const struct file_operations af_conn_fops = {
    .owner = THIS_MODULE,
    .open = af_conn_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release_private,
};
#else
static const struct proc_ops af_conn_fops = {
    .proc_flags = PROC_ENTRY_PERMANENT,
    .proc_read = seq_read,
    .proc_open = af_conn_open,
    .proc_lseek = seq_lseek,
    .proc_release = seq_release_private,
};
#endif

#define AF_CONN_PROC_STR "af_conn"

int af_conn_init_procfs(void)
{
    struct proc_dir_entry *pde;
    struct net *net = &init_net;
    pde = proc_create(AF_CONN_PROC_STR, 0644, net->proc_net, &af_conn_fops);
    if (!pde)
    {
        printk("af_conn seq file created error\n");
        return -1;
    }

    return 0;
}

void af_conn_remove_procfs(void)
{
    struct net *net = &init_net;
    remove_proc_entry(AF_CONN_PROC_STR, net->proc_net);
}


int af_conn_init(void)
{
    int i;
    for (i = 0; i < AF_CONN_HASH_SIZE; i++)
	{
		INIT_HLIST_HEAD(&af_conn_table[i]);
	}
    af_conn_init_procfs(); 
    return 0;
}

void af_conn_exit(void){
    af_conn_remove_procfs();
    af_conn_cleanup();
}
