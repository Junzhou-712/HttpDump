#include<stdio.h>
#include<pcap.h>
#include<sys/types.h>
#include "head.h"

#define MAXBYTES2CAPTURE 2048 
#define PROMISC 1

/* filter condition */
char filter_exp[128];


char* select_dev(int choice, pcap_if_t *interfaces, int bufSize) {
    /* select function */
    /* description: select a network interface to sniff on */
     char * dev;
     pcap_if_t * temp;

    if(choice >= 0 && choice <= bufSize) {
        temp=interfaces;
        for(int cnt = 0;cnt < choice;++cnt) {
            temp = temp->next;
        }
       dev = temp->name;
       printf("%s is selected.\n",dev);
    }

    return dev;
}

int main(int argc,char *argv[]) {

    //read pcap file / capture the network interface
    if(argc != 1) {
        
    } else {

    }
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces,*temp;
    int i=0;
    if(pcap_findalldevs(&interfaces,error)==-1)
    {
        printf("\nerror in pcap findall devs");
        return -1;   
    }

    printf("\n the interfaces present on the system are: \n");
    for(temp=interfaces;temp;temp=temp->next)
    {
        printf("%d  :  %s\n",i++,temp->name);
    }

    int choice;
    pcap_t *handle;
    struct pcap_pkthdr hdr;
    struct bpf_program bpf_p;
    char* dev;
    bpf_u_int32 net, bpf_u_int32 mask;

    printf("Please type the sequence number you want to sniff on:");
    scanf("%d",&choice);
    dev = select_dev(choice,interfaces,i);

    handle = pcap_open_live(dev, MAXBYTES2CAPTURE, 1, 1000, error);

    if(handle == NULL) {
        printf("Couldn't open device %s: %s\n", dev, error);
	    return(2);
    }

    if(pcap_lookupnet(dev, &net, &mask, error) == -1) {
        printf("Couldn't get netmask for device %s: %s\n", dev, error);
        return(2);
    }

    if(argc > 1) {
        for(int i = 1; i < argc; ++i) {
            strncat(filter_exp, argv[i], 100);
            strncat(filter_exp, " ", 100);
        }
    }

    if(pcap_compile(handle, &bpf_p, filter_exp, 0, net) == -1) {
        printf("Couldn't install filter for device %s: %s\n", dev, error);
        return(2);
    }
   
    int id = 0;

    /*capture the packet until occure error*/
	pcap_loop(handle, -1, ethernet_callback, (u_char *)&id);

	pcap_close(handle);

    return 0;

}
