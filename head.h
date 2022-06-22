/****head.h*****/
/*Description: message header struct*/
#ifndef _HEAD_H_
#define _HEAD_H_

#include <sys/types.h>
#include <netinet/in.h>

/*maximum packet capture length : Ethernet 1500 byte + header 14 byte + FCS field 4 byte*/
#define SNAP_LEN 1518

/*ethernet header*/
#define ETHERNET_HEAD_SIZE 14

#define IP_HEAD_SIZE(packet) ((((struct ip *)(packet + ETHERNET_HEAD_SIZE))->ip_hlv & 0x0f) * 4)

#define ETHERNET_ADDR_LEN 6

#define IP_ADDR_LEN 4

#define ARP_REQUEST 1
#define ARP_REPLY 2

/*TCP flag*/
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x010
#define TCP_URG 0x020
#define TCP_ECE 0x40
#define TCP_CWR 0x80

struct ethernet {
    u_char ether_dhost[ETHERNET_ADDR_LEN];
    u_char ether_shost[ETHERNET_ADDR_LEN];
    u_char ether_type; //IP?ARP?etc.
};

struct ip {
    //(ipheader->ip_hlv & 0xf0) >> 4 version
    //(ipheader->ip_hlv & 0x0f) header_size
    u_char ip_hlv;
    u_char ip_hos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_protocol;
    u_short ip_sum;
    u_char ip_src[IP_ADDR_LEN];
    u_char ip_dst[IP_ADDR_LEN];
};

struct tcp {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int tcp_seqe;
    u_int tcp_ack;

    u_char tcp_hre;
    u_char tcp_flag;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

struct udp {
    u_short udp_sport;
    u_short udp_dport;
    u_short udp_len;
    u_short udp_sum;
};
/*ARP HEADER*/
struct arp {
    u_short arp_hrd;
    u_short arp_pro;
    u_char arp_hdlen;
    u_char arp_prolen;
    u_short arp_op;
    u_char arp_shost[ETHERNET_ADDR_LEN];
	u_char arp_sip[IP_ADDR_LEN];
	u_char arp_dhost[ETHERNET_ADDR_LEN];
	u_char arp_dip[IP_ADDR_LEN];
};
/*ICMP HEADER*/
struct icmp {
	u_char icmp_type;
	u_char icmp_code;
	u_short icmp_sum;
	u_short icmp_id;
	u_short icmp_seq;
	u_int icmp_time;
};

/*PPPOE HEADER*/
struct pppoe {
    u_char pppoe_vtype;  //version(0x1) + type(0x1)
    u_char pppoe_code;
    u_short pppoe_s_id;
    u_short pppoe_len;
}

/* IGMP HEADER*/
struct igmp {
    u_char igmp_vtype; //仿照pppoe协议
    u_char igmp_unused;
    u_short igmp_sum;
    u_int igmp_gaddr; //组播地址
}
#endif