#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>  // ether_ntoa, ether_addr

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;        /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // 1. 이더넷 헤더
    struct ethheader *eth = (struct ethheader *)packet;
    // EtherType가 0x0800(IP)인지 확인
    if (ntohs(eth->ether_type) == 0x0800) {
        // 2. IP 헤더
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // IP가 TCP인지 확인 (프로토콜 번호가 6이면 TCP)
        if (ip->iph_protocol == IPPROTO_TCP) {
            // 3. TCP 헤더
            unsigned int ip_header_len = ip->iph_ihl * 4;
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

            // 여기서부터 MAC/IP/TCP 정보를 안전하게 출력
            printf("Source MAC = %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
            printf("Destination MAC = %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

            printf("Source IP = %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Destination IP = %s\n", inet_ntoa(ip->iph_destip));

            printf("Source Port = %d\n", ntohs(tcp->tcp_sport));
            printf("Destination Port = %d\n", ntohs(tcp->tcp_dport));
            printf("\n");
        }
    }
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if(!handle){
        fprintf(stderr,"error in pcap_open_live:%s\n",errbuf);
        return -1;
    }
    pcap_loop(handle, -1, packet_capture, NULL);

    pcap_close(handle);

    return 0;
}


