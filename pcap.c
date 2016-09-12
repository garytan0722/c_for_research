//
//  main.c
//  test
//
//  Created by 譚庚倫 on 2015/7/10.
//  Copyright (c) 2015年 譚庚倫. All rights reserved.
//

#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header,const u_char *content);
u_char* handle_IP(u_char *arg, const struct pcap_pkthdr *header,const u_char *content);
int main(int argc, const char * argv[]) {
    // insert code here...
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    dev = pcap_lookupdev(errbuf);

    pcap_t *handle = pcap_open_live(dev,65535,1,1, errbuf);//定義接收器
    if(!handle){//如果接收器是error印出來錯誤訊息
        printf("%s\n",errbuf);
        return -1;
    }
    //filter
    bpf_u_int32 net_ip,netmask;
    struct bpf_program bpf;
    pcap_lookupnet(dev, &net_ip, &netmask ,errbuf);
    pcap_compile(handle,&bpf, "tcp",1, net_ip);
    pcap_setfilter(handle, &bpf);
    pcap_freecode(&bpf);
    
    pcap_loop(handle,20, pcap_callback, NULL);
}
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header,const u_char *content){
    struct ether_header *ether=(struct ether_header *)content;
    char disMac[6*2+5+1];
    char srcMac[6*2+5+1];
    u_char *macstring;
    strlcpy(disMac,ether_ntoa((const struct ether_addr *) ether->ether_dhost), sizeof(disMac));
    macstring=ether->ether_dhost;
    strlcpy(srcMac, ether_ntoa((const struct ether_addr *) ether->ether_shost), sizeof(srcMac));
    printf("DisNMac: %s \n , SrcMac: %s\n",disMac,srcMac);
    switch (ntohs(ether->ether_type)) {
        case ETHERTYPE_IP:
            printf("IP\n");
            handle_IP(arg,header,content);
            break;
        case ETHERTYPE_IPV6:
            printf("IPV6");
            break;
        case ETHERTYPE_ARP:
            printf("arp");
            break;
        default:
            break;
    }
}

u_char* handle_IP(u_char *arg, const struct pcap_pkthdr *header,const u_char *content){
    u_int length,hlen,id;
    u_short off,version;
    int len;
    struct ip *ip = (struct ip*)(content + sizeof(struct ether_header));;
    
    length -= sizeof(struct ether_header);
    if (length < sizeof(struct ip))
    {
        printf("truncated ip %d",length);
        return NULL;
    }
    len     = ntohs(ip->ip_len);/* packet length */
    hlen    = ip->ip_hl; /* header length */
    version = ip->ip_v;/* ip version */
    id=ntohs(ip->ip_id);/*ip identification*/
    off=(ip->ip_off & 0x1fff)*8;
    printf("---------------IP Header------------------\n");
    printf("Verison: %d\n",version);
    printf("Packet length: %d\n",len);
    printf("Header length: %d\n",hlen*4);
    printf("Identification: %d\n",id);
    printf("offset: %d\n",off);
    switch (ip->ip_p) {
        case 6:
            printf("TCP protocol\n");
            break;
        case 17:
            printf("UDP protocol\n");
            break;
        case 1:
            printf("ICMP protocol\n");
            break;
        default:
            break;
    }
    printf("Header checksum: %d\n",ip->ip_sum);
    printf("Source address: %s\n",inet_ntoa(ip->ip_src));
    printf("Destination address: %s\n",inet_ntoa(ip->ip_dst));
    return NULL;
}


















