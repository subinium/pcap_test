#include <arpa/inet.h>
#include <pcap.h>
#include "pcap_struct.h"
#include <stdio.h>
#include <stdint.h>

void usage(){
    puts("syntax: ./pcap_test <interface>");
    puts("sample: ./pcap_test en0");
}

char errbuf[PCAP_ERRBUF_SIZE];

int main(int argc, char* argv[]){
    if (argc != 2){
        usage();
        return 1;
    }
    char *dev = argv[1];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    
    if(dev == NULL){
        fprintf(stderr, "Can't find default device: %s\n", errbuf);
        return 1;
    }
    if(handle == NULL){
        fprintf(stderr, "Can't open device %s: %s\n", dev, errbuf);
        return 1;
    }
    
    
    while(true){
        struct pcap_pkthdr *hd;
        const u_char *pk;
        int res = pcap_next_ex(handle,&hd, &pk);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;
        // packet
        printf("Packet Length: %u\n",hd->caplen);
        
        // ethernet
        const struct eth_hdr* pk_eth = (const struct eth_hdr*)pk;
        printf("MAC: ");
        // - src
        for (int i = 0; i < ETH_ALEN; ++i) {
            printf("%s%02X", (i ? ":" : ""), pk_eth->src[i]);
        }
        // - dst
        printf(" -> ");
        for (int i = 0; i < ETH_ALEN; ++i) {
            printf("%s%02X", (i ? ":" : ""), pk_eth->dst[i]);
        }
        puts("");
        int eth_type = ntohs(pk_eth->type);
        if(eth_type!=0x0800){
            puts("Ethertype : not ipv4\n");
            continue;
        }
        
        // ipv4
        puts("Ethertype : ipv4");
        const struct ipv4_hdr *pk_ipv4 = (const struct ipv4_hdr *)pk_eth->data;
        printf("IP: ");
        // - src
        for (int i = 0; i < IPV4_ALEN; ++i) {
            printf("%s%d", (i ? "." : ""), pk_ipv4->src[i]);
        }
        printf(" -> ");
        // - dst
        for (int i = 0; i < IPV4_ALEN; ++i) {
            printf("%s%d", (i ? "." : ""), pk_ipv4->dst[i]);
        }
        puts("");
        uint8_t ihl = IPV4_HL(pk_ipv4);
        if(ihl < IPV4_HL_MIN){
            puts("Invalid ipv4 packet\n");
            return 2;
        }
        
        if(pk_ipv4->protocol!=0x06){
            puts("ipv4 protocol: not tcp\n");
            continue;
        }
        
        // TCP
        puts("ipv4 protocol: tcp");
        const struct tcp_hdr* pk_tcp = (const struct tcp_hdr*)&pk_ipv4->data[ihl - IPV4_HL_MIN];
        
        uint16_t length = ntohs(pk_ipv4->length) - ihl;
        printf("PORT: %d -> %d\n", ntohs(pk_tcp->src), ntohs(pk_tcp->dst));
        
        uint8_t thl = TCP_HL(pk_tcp);
        if(thl<20||thl>60){
            puts("Invalid tcp packet\n");
            return 2;
        }
        
        uint32_t tl = length - thl;
        printf("TCP length: %u\n",tl);
        printf("Payload: ");
        
        tl = tl < TCP_PAYLOAD_MAXLEN ? tl : TCP_PAYLOAD_MAXLEN;
        
        for (uint32_t i = 0; i < tl; ++i) {
            printf("%s%02X", (i ? " " : ""), pk_tcp->payload[thl-20+i]);
        }
        puts("\n");
        
    }
    pcap_close(handle);
    return 0;
}
