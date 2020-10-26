#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maxium bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;                      /* version << 4 | header length >> 2 */
    u_char ip_tos;                      /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
    #define IP_RF 0x8000                /* reserved fragment flag */
    #define IP_DF 0x4000                /* dont fragment flag */
    #define IP_MF 0x2000                /* more fragments flag */
    #define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
    u_char  ip_ttl;                     /* time to live */
    u_char  ip_p;                       /* protocol */
    u_short ip_sum;                     /* checksum */
    struct  in_addr ip_src,ip_dst;      /* source and dest address */
};
#define     IP_HL(ip)    (((ip)->ip_vhl) & 0x0f)
#define     IP_V(ip)     (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;                   /* source port */
    u_short th_dport;                   /* destination port */
    tcp_seq th_seq;                     /* sequence number */
    tcp_seq th_ack;                     /* acknowledgement number */
    u_char  th_offx2;                   /* data offset,rsvd */
    #define TH_OFF(th)       (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
#define TH_FLAGS  (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                     /* window */
    u_short th_sum;                     /* checksum */
    u_short th_urp;                     /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_packet(const u_char *payload,int len);


void print_packet(const u_char *payload,int len){
           
    const u_char *ch = payload;
    define/compute tcp header offset 
    if(len <= 0)
        return;
    //this loop prints the character if it exists
    ch = payload;
    for(int i=0;i<len;i++){
        if(isprint(*ch))
            printf("%c",*ch);
        ch++;
    }

    printf("\n");
    return;
}

/*
 * dissect/print packet
 */
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    static int count = 1;                      /* packet counter */
    
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;     /* The ethernet heaer
                                                  */
    const struct sniff_ip *ip;                 /* The IP header */
    const struct sniff_tcp *tcp;               /* The TCP header */
    const char *payload;                       /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    printf("\nPacket # %d:\n",count);
    count++;

    // define ethernet header
    ethernet = (struct sniff_ethernet*)(packet);

    // define/compute ip header offset
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    
    // define/compute ip header offset
    size_ip = IP_HL(ip)*4;
    if(size_ip<20){
        printf("  * Invalid IP header length: %u bytes\n",size_ip);
        return;
    }
    
    // prints the up addresses
    printf("From: %s\n", inet_ntoa(ip->ip_src));
    printf("To: %s\n", inet_ntoa(ip->ip_dst));

 

    // finds the header offset
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET +size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf(" * Invalid TCP header length: %u bytes\n",size_tcp);
        return;
    }

    printf("Src port: %d\n",ntohs(tcp->th_sport));
    printf("Dst port: %d\n",ntohs(tcp->th_dport));

    // finds the offset for the payload
    payload = (u_char *)(packet+SIZE_ETHERNET+size_ip+size_tcp);

    // finds out the size of payload
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    if(size_payload > 0){
        
        print_packet(payload,size_payload);
    }
    
    return;
}

int main(){
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;


  handle = pcap_open_live("eth0", BUFSIZ,1,1000,errbuf);


  pcap_compile(handle,&fp, filter_exp,0,net);
  pcap_setfilter(handle,&fp);


  pcap_loop(handle,-1,got_packet,NULL);
  pcap_close(handle);
  //printf(handle);
  return 0;
}
