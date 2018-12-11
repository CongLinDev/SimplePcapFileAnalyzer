#include <string.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

#define MAX_PACKET_SIZE 1500

void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
    pcap_dump(user, pkt_header, pkt_data);// 输出数据到文件
    printf("Jacked a packet with length of [%d]\n", pkt_header->len);// 打印抓到的包的长度
}

void get_packet(){
    pcap_t *handle = NULL;                 // 会话句柄 
    char errbuf[PCAP_ERRBUF_SIZE]; // 存储错误信息的字符串
    bpf_u_int32 mask;               //所在网络的掩码 
    bpf_u_int32 net;                // 主机的IP地址 

    struct bpf_program filter;      //已经编译好的过滤器
    char filter_app[] = "tcp and udp";  //BPF过滤规则

    /* 探查设备及属性 */
    //指定需要被抓包的设备 我们在linux下的两个设备eth0和lo分别是网卡和本地环回
    char dev = pcap_lookupdev(errbuf);   //返回第一个合法的设备，我这里是eth0
    pcap_lookupnet(dev, &net, &mask, errbuf);
    //char dev = "lo";                   //如果需要抓取本地的数据包，比如过滤表达式为host localhost的时候可以直接指定

    handle = pcap_open_live(dev, MAX_PACKET_SIZE, 1,1000, errbuf);//以混杂模式打开会话

    pcap_compile(handle, &filter, filter_app, 0, net);//编译过滤器
    pcap_setfilter(handle, &filter);//应用过滤器

    pcap_dumper_t* out_pcap;
    out_pcap  = pcap_dump_open(handle,"./a.pcap");

    /* 截获packet */
    pcap_loop(handle, -1, packet_handler, (u_char *)out_pcap);
    
    pcap_dump_flush(out_pcap);  //刷新缓冲区

    pcap_close(handle);
    pcap_dump_close(out_pcap);
}

int main(int argc,char *argv[])
{
    get_packet();
    return 0;
}