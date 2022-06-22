#ifndef CALLBACK_H
#define CALLBACK_H

char *tcp_flag(const u_char tcp_flags);

void ethernet_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void pppoe_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void ip_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet);

void tcp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet);

void icmp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet);

void udp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet);

void arp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet);

void igmp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,const u_char *packet);
#endif
