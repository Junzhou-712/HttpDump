#include<stdio.h>
#include<pcap.h>

#define MAXBYTES2CAPTURE 2048 

int check_suffix(char * path) {
    return 0;
}

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
    char* dev;

    printf("Please type the sequence number you want to sniff on:");
    scanf("%d",&choice);
    dev = select_dev(choice,interfaces,i);

    handle = pcap_open_live(dev, MAXBYTES2CAPTURE, 1, 1000, error);

    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, error);
	    return(2);
    }
   
    return 0;

}
