#include <pcap/pcap.h>
#include <arpa/inet.h>
//-std=c99
static char errbuf[PCAP_ERRBUF_SIZE];

int main() {
    pcap_if_t *alldevs;
    int status = pcap_findalldevs(&alldevs, errbuf);
    if(status != 0) {
        printf("%s\n", errbuf);
        return 1;
    }
    
    for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
        printf("%s:", d->name);
        for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
            if(a->addr->sa_family == AF_INET)
                printf(" Address:%s", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
        }
        printf("\n");
    }
    
    pcap_freealldevs(alldevs);
    return 0;
}
