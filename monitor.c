
#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
//#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header,const u_char *content);
double now_ms();
void breakloop();
pcap_t *handle;
int main(int argc, const char * argv[]) {
    // insert code here...
    pcap_dumper_t *pd;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    char unixtime[30];
    char *token;
    char *search = ".";
    char command[20]="./post.bin ";
    char path[30];
    //FILE *fp;
    dev = pcap_lookupdev(errbuf);
    printf("Interface:%s",dev);
    handle = pcap_open_live(dev,65535,1,1, errbuf);//定義接收器
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
    double sec=now_ms();
    printf("Time::%f\n",sec);
    sprintf(unixtime,"%f\n", sec);
    printf("Unixtime: %s\n",unixtime);
    token=strtok(unixtime,search);
    printf("token1: %s\n",token);
    //token=strtok(NULL,search);
    //printf("token2: %s\n",token);
    sprintf(path,"/tmp/%s.pcap",token);
    printf("PATH::%s\n",path);
    if((pd = pcap_dump_open(handle,path)) == NULL){
        printf("Can not open pcap file error!!");
    }
    //strcat(command,unixtime);
    //strcat(command," ");
    strcat(command,token);
    printf("Comand: %s",command);
    signal(SIGALRM, breakloop);
    alarm(600);
    pcap_loop(handle,-1,pcap_callback, (u_char*)pd);
    //fp=fopen("/test.pcap", "wb");
    pcap_dump_close(pd);
    pcap_close(handle);
    printf("Close dump\n");
    system(command);   
}
void pcap_callback(u_char *arg, const struct pcap_pkthdr *header,const u_char *content){
    pcap_dump(arg,header,content);
}
double now_ms(void) {
    struct timespec res;
    clock_gettime(CLOCK_REALTIME, &res);
    return res.tv_sec;
}
void breakloop(){
     // printf("break loop\n");
     // double a=now_ms();
     // printf("breakloop time:%f\n",a );
    pcap_breakloop(handle);
}


















