/**** callback.c ****/
/**** Description: A callback function to analyze data packet****/
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>

#include "head.h"
#include "callback.h"

char *tcp_flag(const u_char tcp_flags);

extern char filter_exp[128];

/* capture packet device name */
extern char *dev;

void ethernet_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ethernet *ethheader;
    struct ip *ipptr;
    u_short protocol;
    u_int *id = (u_int *)arg;
    u_char *time = ctime((const time_t*)&pkthdr->ts.tv_sec);

    printf("----Device: %s----\n",dev);
    printf("----Filter: %s----\n",filter_exp);
    printf("id: %d\n",++(*id));
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Receive time: %s\n", time);

    for(int k = 0; k < pkthdr->len; ++k) {
        printf(" %02x",packet[k]);
        if((k + 1) % 16 == 0) {
            printf("\n");
        }
    }

    printf("\n\n");

    ethheader = (struct ethernet*)packet;
    printf("----Data Link Layer----\n");

	printf("Mac Src Address: ");
	for (int i = 0; i < ETHERNET_ADDR_LEN; ++i) {
		if (ETHERNET_ADDR_LEN - 1 == i)
		{
			printf("%02x\n",ethheader->ether_shost[i]);
		} else {
		    printf("%02x:",ethheader->ether_shost[i]);
		}
	}

	printf("Mac Dst Address: ");
	for (int j = 0; j < ETHERNET_ADDR_LEN; ++j)
	{
		if (ETHERNET_ADDR_LEN - 1 == j)
		{
			printf("%02x\n",ethheader->ether_dhost[j]);
		} else {
		    printf("%02x:",ethheader->ether_dhost[j]);
		}
	}

	protocol = ntohs(ethheader->ether_type);

    /*对pppoe报文的处理*/
    if (0x8863 == protocol)
    {
        printf("PPPOE Discovery");
        pppoe_callback(arg, pkthdr, packet);
    }
    if (0x8864 == protocol)
    {
        printf("PPPOE Session");
        pppoe_callback(arg, pkthdr, packet);
    }
	
	printf("----Network Layer----\n");
	switch (protocol) {
		case 0x0800: 
			printf("IPv4 protocol!\n");
			ip_callback(arg, pkthdr, packet);
			break;
		case 0x0806:
			printf("ARP protocol!\n");
			arp_callback(arg, pkthdr, packet);
			break;
		case 0x8035:
			printf("RARP protocol!\n");
			break;
		case 0x86DD:
			printf("IPv6 protocol!\n");
			break;
		case 0x880B:
			printf("PPP protocol!\n");
			printf("There is no function to process PPP packet!!!");
			break;
		default:
			printf("Other Network Layer protocol is used!\n");
			break;	
	}	
	printf("----Done----\n\n\n");
}

//pppoe回调函数
void pppoe_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet) {
    struct pppoe *pppoeheader = (struct pppoe *)(packet + ETHERNET_HEAD_SIZE);
    printf("Version: %d\n",(pppoeheader->pppoe_vtype & 0xf0) >> 4);
    printf("Type: %d\n",pppoeheader->pppoe_vtype & 0x0f);
    printf("Code: %d\n",pppoeheader->pppoe_code);
    printf("Session ID: %d\n",ntohs(pppoeheader->pppoe_s_id));
    printf("Payload Length: %d\n",ntohs(pppoeheader->pppoe_len));
}


void ip_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet) {
	u_char protocol;
	struct ip *ipheader;
    //ipheader = packet_addr + frame header
	ipheader = (struct ip *)(packet + ETHERNET_HEAD_SIZE);

	printf("Version: %d\n", (ipheader->ip_hlv & 0xf0) >> 4); //取hlv高4位
	printf("Header Length: %d\n",ipheader->ip_hlv & 0x0f);  //取hlv低4位
	printf("Type of Service: %x\n",ipheader->ip_hos);
	printf("Total Length: %d\n",ntohs(ipheader->ip_len));
	printf("Indentification: %x\n",ntohs(ipheader->ip_id));
	printf("Offset: %d\n",ntohs(ipheader->ip_off));
	printf("TTL: %d\n",ipheader->ip_ttl);
	printf("Protocol: %d\n",ipheader->ip_protocol);
	printf("CheckSum: %d\n",ntohs(ipheader->ip_sum));

	printf("IP Src Address: ");
	for (int i = 0; i < IP_ADDR_LEN; ++i) {
		printf("%d.",ipheader->ip_src[i]);
	}
	printf("\nIP Dst Address: ");
	for (int i = 0; i < IP_ADDR_LEN; ++i) {
		printf("%d.",ipheader->ip_dst[i]);
	}
	printf("\n");
	
    protocol = ipheader->ip_protocol;
    if (0x01 == protocol) {
        printf("ICMP Protocol!\n");
		icmp_callback(arg, pkthdr, packet);
    }
    
	printf("----Transport Layer----\n");
	switch (protocol)
	{
		case 0x06:
			printf("TCP Protocol!\n");
			tcp_callback(arg, pkthdr, packet);
			break;
		case 0x11:
			printf("UDP Protocol!\n");
			udp_callback(arg, pkthdr, packet);
			break;
		case 0x02:
			printf("IGMP Protocol!\n");
			igmp_callback(arg, pkthdr, packet);
			break;
		default:
			printf("Other Transport Layer protocol is used!\n");
			break;
	}
}

//tcp回调函数
void tcp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet) {
	struct tcp *tcpheader = (struct tcp *)(packet + ETHERNET_HEAD_SIZE + IP_HEAD_SIZE(packet));

	printf("Src Port: %d\n",ntohs(tcpheader->tcp_sport));
	printf("Dst Port: %d\n",ntohs(tcpheader->tcp_dport));
	printf("Squence Number: %d\n",ntohs(tcpheader->tcp_seqe));
	printf("ACK Number: %d\n",ntohs(tcpheader->tcp_ack));
	printf("Header Length: %d\n",(tcpheader->tcp_hre & 0xf0) >> 4);
	printf("FLAG: %d\n",tcpheader->tcp_flag);
	printf("Flag: %s\n",tcp_flag(tcpheader->tcp_flag));
	printf("Window Size: %d\n",ntohs(tcpheader->tcp_win));
	printf("Checksum: %d\n",ntohs(tcpheader->tcp_sum));
	printf("Urgent Pointer: %d\n",ntohs(tcpheader->tcp_urp));	
}


//tcp flag标识位
char *tcp_flag(const u_char tcp_flags) {
	static char flags[100] = "-";
	if ((TCP_CWR & tcp_flags) == TCP_CWR) {
		strncat(flags, "CWR ", 100);
	}
	if ((TCP_ECE & tcp_flags) == TCP_ECE) {
		strncat(flags, "ECE ", 100);
	}
	if ((TCP_URG & tcp_flags) == TCP_URG) {
		strncat(flags, "URG ", 100);
	}
	if ((TCP_ACK & tcp_flags) == TCP_ACK) {
		strncat(flags, "ACK ", 100);
	}
	if ((TCP_PUSH & tcp_flags) == TCP_PUSH) {
		strncat(flags, "PUSH ", 100);
	}
	if ((TCP_RST & tcp_flags) == TCP_RST) {
		strncat(flags, "RST ", 100);
	}
	if ((TCP_SYN & tcp_flags) == TCP_SYN) {
		strncat(flags, "SYN ", 100);
	}
	if ((TCP_FIN & tcp_flags) == TCP_FIN) {
		strncat(flags, "FIN ", 100);
	}
	return flags;	
}


//icmp data analysis
void icmp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet) {
    struct icmp *icmpheader = (struct icmp *)(packet + ETHERNET_HEAD_SIZE + IP_HEAD_SIZE(packet));
    u_char icmp_type = icmpheader->icmp_type;

    printf("ICMP Type: %d   ",icmpheader->icmp_type);
    switch (icmp_type) {
        case 0x08:
            printf("(ICMP Request)\n");
            break;
        case 0x00:
            printf("(ICMP Response)\n");
            break;
        case 0x11:
            printf("(Timeout!)\n");
            break;
    }
    
    printf("ICMP Code: %d\n",icmpheader->icmp_code);
    printf("ICMP CheckSum: %d\n",icmpheader->icmp_sum);
}


//udp data analysis
void udp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet) {
    struct udp *udpheader = (struct udp *)(packet + ETHERNET_HEAD_SIZE + IP_HEAD_SIZE(packet));

    printf("Src Port: %d\n",ntohs(udpheader->udp_sport));
    printf("Dst Port: %d\n",ntohs(udpheader->udp_dport));
    printf("UDP Length: %d\n",ntohs(udpheader->udp_len));
    printf("Checksum: %d\n",ntohs(udpheader->udp_sum));
}


//arp广播报文分析
void arp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet) {
	struct arp *arpheader;

	arpheader = (struct arp *)(packet + ETHERNET_HEAD_SIZE);
	printf("Hardware type: %s\n",(ntohs(arpheader->arp_hrd) == 0x0001) ? "Ethernet" : "Unknow");
	printf("Protocol type: %s\n",(ntohs(arpheader->arp_pro) == 0x0800) ? "IPv4" : "Unknow");
	printf("Operation: %s\n",(ntohs(arpheader->arp_op) == ARP_REQUEST) ? "ARP_Request" : "ARP_Reply");

	printf("Sender MAC:");
	for (int i = 0; i < ETHERNET_ADDR_LEN; ++i) {
		printf("%02x:",arpheader->arp_shost[i]);
	}
	printf("\nSender IP:");
	for (int i = 0; i < IP_ADDR_LEN; ++i) {
		printf("%d.",arpheader->arp_sip[i]);
	}
	printf("\nDest Mac:");
	for (int i = 0; i < ETHERNET_ADDR_LEN; ++i) {
		printf("%02x:",arpheader->arp_dhost[i]);
	}
	printf("\nDest IP:");
	for (int i = 0; i < IP_ADDR_LEN; ++i) {
		printf("%d.",arpheader->arp_dip[i]);
	}
	printf("\n\n");
}

void igmp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet) {
    struct igmp *igmpheader = (struct igmp *)(packet + ETHERNET_HEAD_SIZE + IP_HEAD_SIZE(packet));
    printf("Version: %d\n",(igmpheader->igmp_vtype & 0xf0) >> 4);
    printf("Type: %d\n",igmpheader->igmp_vtype & 0x0f);
    printf("CheckSum: %d\n",ntohs(igmpheader->igmp_sum));


}