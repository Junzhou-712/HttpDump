#include<linux/skbuff.h>
#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/init.h>
#include<linux/ip.h>
#include<linux/in.h>
#include<linux/tcp.h>
#include<linux/netlink.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/if_ether.h>
#include<linux/kfifo.h>
#include<linux/spinlock.h>

#define FIFO_SIZE 4096
//模仿udpdump的钩子函数，使其进入内核状态对链路层进行抓包

struct kfifo fifo;

void print_utoip(u32 ina) {
    printk("%d.%d.%d.%d", (ina & 0xff000000) >> 24, (ina & 0x00ff0000) >> 16, (ina & 0x0000ff00) >> 8, ina & 0x000000ff);
    return;
}

int id = 1

static unsigned int capkt_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    if(id < 10) {
        struct ethhdr *ethhdr = eth_hdr(skb);
        struct iphdr *iphdr = ip_hdr(skb);
        struct tcphdr *tcphdr = tcp_hdr(skb);
        printk(KERN_ALERT "id : %d",id);
        printk("eth protocol: %x\n",ntohs(ethhdr->h_proto));
        printk("ip protocol: %x\n",iphdr->protocol);
	    printk("src mac:");
	    for (int i = 0; i < 6; ++i) {
	        printk("%02x:",ethhdr->h_source[i]);
	    }
        printk("\n");
        for (int j = 0; j < 6; ++j) {
	        printk("%02x:",ethhdr->h_dest[j]);
	    }
	    printk("\n");
        printk("version: %d\n", iphdr->version);
        printk("ttl: %d\n", iphdr->ttl);

        printk("src ip:");
        printk("%ld\n", ntohl(iphdr->saddr));
        print_utoip(iphdr->saddr);
        printk("\n");

        printk("dest ip:")
        printk("%ld\n", ntohl(iphdr->daddr));
        print_utoip(iphdr->daddr);
        printk("\n");

        printk("src port:");
        printk("%d\n", ntohs(tcphdr->source));
        printk("dest port:");
        printk("%d\n", ntohs(tcphdr->dest));
        ++id;

        //add the packet message to the list FIFO
        kfifo_in(&fifo, skb, sizeof(*skb));
        int len = kfifo_len(&fifo);
        int size = kfifo_size(&fifo);
        printk("kfifo size: %d\n",size);
	    printk("kfifo length: %d\n",len);
    }

    return NF_ACCEPT;
}

struct nf_hook_ops capture_hook_ops = {
    .hook = capkt_hook,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = 0,
};


struct int __init init_process_pkt(void) {
    if(kfifo_alloc(&fifo, FIFO_SIZE, GFP_KERNEL)) {
        printk("kfifo_alloc failed!\n");
    }
    if(nf_register_hook(&capture_hook_ops) != 0) {
        printk("netfilter register fail!\n");
        return -1;
    }
    printk("capture module insert successfully!\n");
    return 0;
}

static int __exit exit_process_pkt(void)
{
    kfifo_free(&fifo);
    nf_unregister_hook(&capture_hook_ops);
    printk("capture module remove success!\n");
    return;
}

module_init(init_process_pkt);
module_exit(exit_process_pkt);

MODULE_LICENSE("GPL");