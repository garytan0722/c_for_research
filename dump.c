#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
//#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <curl/curl.h>
#include <sys/stat.h>
#define CURL_STATICLIB
//#include <curl/curl.h>
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header,const u_char *content);
u_char* handle_IP(u_char *arg, const struct pcap_pkthdr *header,const u_char *content);
//void handle_TCP(u_char *arg ,const struct pcap_pkthdr *header ,const u_char *content);
int main(int argc, const char * argv[]) {
    // insert code here...
    pcap_dumper_t *pd;
    //pcap_if_t *list;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    printf("Interface:%s",dev);
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
    if((pd = pcap_dump_open(handle,"/tmp/test.pcap")) == NULL){
        printf("Can not open pcap file error!!");
    }
    
    pcap_loop(handle,-1, pcap_callback, (u_char*)pd);
    pcap_dump_close(pd);
    pcap_close(handle);
}
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header,const u_char *content){
    
    pcap_dump(arg,header,content);
    CURL *curl;
    curl = curl_easy_init();

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
struct ip *ip = (struct ip*)(content + sizeof(struct ether_header));
    
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
            //handle_TCP(arg, header, content);
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
//void handle_TCP(u_char *arg ,const struct pcap_pkthdr *header ,const u_char *content){
//    struct tcphdr *tcp=(struct tcphdr*)(content+14+sizeof(struct ether_header)+sizeof(struct ip));
//    u_char flags;
//    int header_length;
//    u_short source_port;
//    u_short destination_port;
//    u_short windows;
//    u_short urgent_pointer;
//    u_int seq;
//    u_int ack;
//    u_int16_t checksum;
//    source_port=ntohs(tcp->th_sport);
//    destination_port=ntohs(tcp->th_dport);
//    header_length=tcp->th_off*4;
//    windows=ntohs(tcp->th_win);
//    seq=ntohl(tcp->th_seq);
//    ack=ntohl(tcp->th_ack);
//    urgent_pointer=ntohs(tcp->th_urp);
//    flags=tcp->th_flags;
//    checksum=ntohs(tcp->th_sum);
//    printf("TCP layer ------------------------------------\n");
//    printf("source port: %d\n",source_port);
//    switch (destination_port) {
//        case 80:
//            printf("HTTP protocol\n");
//            break;
//            
//        case 443:
//            printf("HTTPS protocol\n");
//        case 21:
//            printf("FTP protocol\n");
//        default:
//            break;
//    }
//    printf("seq number: %d\n",seq);
//    printf("ack number: %d\n",ack);
//    printf("Header length: %d\n",header_length);
//    printf("Flag:");
//    if(flags & 0x08) {printf("PSH\n");}
//    if(flags & 0x10) {printf("ACK\n");}
//    if(flags & 0x02) {printf("SYN\n");}
//    if(flags & 0x20) {printf("URG\n");}
//    if(flags & 0x01) {printf("FIN\n");}
//    if(flags & 0x04) {printf("RST\n");}
//    printf("\n");
//    printf("Windows size: %d\n",windows);
//    printf("CheckSum : %d\n",checksum);
//    printf("Urgent pointer: %d\n",urgent_pointer);
//}
