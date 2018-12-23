//
//  capture-pcap_loop-and-pcap_dispatch.c
//  for http://qbsuranalang.blogspot.com
//  Created by TUTU on 2016/11/04.
//
//  Capture frame using pcap_loop() and pcap_dispatch().
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#define SIZE_ETHERNET 14

static void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    static int d = 0;
    
    printf("No. %3d\n", ++d);
	int proto_flag=2;
	struct ip *ip;                /* IP 頭部    */
	struct tcphdr *tcp;              /* TCP 頭部   */
    struct udphdr *udp;              /* UDP 頭部   */
	int size_tcp;
	int size_udp;
    //format timestamp
    struct tm *ltime;
    char timestr[25];
    time_t local_tv_sec;
    
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%Y:%m:%d:%H:%M:%S",ltime);

    //print header
    printf("    Time: %s\n", timestr);
    printf("    Length: %d bytes\n", header->len);
    printf("    Capture length: %d bytes\n", header->caplen);
    
   
    u_int16_t type;    
    struct ether_header *ethernet = (struct ether_header *)content;    
    
    
   
    ip = (struct ip*)(content + SIZE_ETHERNET);
    
    printf("      IP From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
    
        switch(ip->ip_p) {
     case IPPROTO_TCP:  
            proto_flag=0;
            break;
        case IPPROTO_UDP: 
            proto_flag=1;
         break;
        default:
            return;
 }
    
if (proto_flag == 0) {
       /* 定義/計算 TCP 頭部偏移 */
     tcp = (struct tcphdr *) (content + SIZE_ETHERNET + (ip->ip_hl << 2));
     /*  計算TCP頭部長度 */

     if (size_tcp < 20) {
       printf ("   * Invalid TCP header length: %u bytes\n", size_tcp);
       return;
     }
   printf ("   Src port  : %d\n", ntohs (tcp->th_sport));
     printf ("   Dst port  : %d\n", ntohs (tcp->th_dport));
     }
    else if (proto_flag == 1) {
udp = (struct udphdr *) (content + SIZE_ETHERNET + (ip->ip_hl << 2));
    // printf("       From: %s\n", inet_ntoa(ip->ip_src));
    // printf("         To: %s\n", inet_ntoa(ip->ip_dst));
     printf ("   Src port: %d\n", ntohs (udp->uh_sport));
     printf ("   Dst port: %d\n", ntohs (udp->uh_dport));
     }
     
    //break when captured 20 frames    
    if(d == 10) {
        pcap_t *handle = (pcap_t *)arg;
        pcap_breakloop(handle);
    }//end if
}


int main(int argc, char * argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device = NULL;
	char *filter="";
	const char *filename = "saved.pcap";
	if(argc==2)filter=argv[1];
	
    //get default interface name
    device = pcap_lookupdev(errbuf);
    if(!device) {
        fprintf(stderr, "pcap_lookupdev(): %s\n", errbuf);
        exit(1);
    }//end if
    //open interface
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_offline(): %s\n", errbuf);
        exit(1);
    }//end if
    //generate bpf filter
    
bpf_u_int32 net, mask;
struct bpf_program fcode;
 
//get network and mask
if(-1 == pcap_lookupnet(device, &net, &mask, errbuf)) {
    fprintf(stderr, "pcap_lookupnet(): %s\n", errbuf);
    mask = PCAP_NETMASK_UNKNOWN;
}//end if
 
//compile filter
if(-1 == pcap_compile(handle, &fcode, filter, 1, mask)) {
    fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(handle));
    pcap_close(handle);
    exit(1);
}//end if
    
    //set filter
if(-1 == pcap_setfilter(handle, &fcode)) {
    fprintf(stderr, "pcap_pcap_setfilter(): %s\n", pcap_geterr(handle));
    pcap_freecode(&fcode);
    pcap_close(handle);
    exit(1);
}//end if
 

    
    
    
    //start capture pcap_dispatch()
    int ret = pcap_dispatch(handle, -1, pcap_callback, (u_char *)handle);
    if(0 > ret) {
        fprintf(stderr, "pcap_dispatch(): %s\n", pcap_geterr(handle));
    }//end if
    else {
        printf("Captured: %d\n", ret);
    }//end else


    printf("\nDone\n");
    //free
    pcap_close(handle);
    //free bpf code
pcap_freecode(&fcode);
    return 0;
}//end main




