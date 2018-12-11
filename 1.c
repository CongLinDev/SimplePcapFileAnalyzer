#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <string>
#include <iostream>
 
using namespace std;
 
#define MAX_PACKET_SIZE 1500
 
 
typedef struct mac_header
{
    u_char dstmacaddress[6];
    u_char srcmacaddress[6];
    u_short type;
}mac_header;
 
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;
 
typedef struct ip_header
{
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    ip_address saddr;
    ip_address daddr;
}ip_header;
 
typedef struct tcp_header
{
    u_short sourport;
    u_short destport;
    unsigned int sequnum;
    unsigned int acknowledgenum;
    u_short headerlenandflag;
    u_short windowsize;
    u_short checksum;
    u_short urgentpointer;
}tcp_header;
 
typedef struct udp_header
{
    u_short sourport;
    u_short destport;
    u_short length;
    u_short checksum;
}udp_header;
 
void ip_analyse(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content)
{
    ip_header *ipheader;
    string reader;
    mac_header *macheader;
     
    macheader = (struct mac_header *)packet_content;
    fprintf(stderr, "SourceMac:%02x:%02x:%02x:%02x:%02x:%02x\n",macheader->srcmacaddress[0],macheader->srcmacaddress[1],macheader->srcmacaddress[2],macheader->srcmacaddress[3],macheader->srcmacaddress[4],macheader->srcmacaddress[5]);
    fprintf(stderr, "DestinationMac:%02x:%02x:%02x:%02x:%02x:%02x\n",macheader->dstmacaddress[0],macheader->dstmacaddress[1],macheader->dstmacaddress[2],macheader->dstmacaddress[3],macheader->dstmacaddress[4],macheader->dstmacaddress[5]);
     
    ipheader = (struct ip_header *)&packet_content[sizeof(struct mac_header)];
    fprintf(stderr, "SourceIP:%d.%d.%d.%d\n",ipheader->saddr.byte1,ipheader->saddr.byte2,ipheader->saddr.byte3,ipheader->saddr.byte4);
    fprintf(stderr, "DestinationIP:%d.%d.%d.%d\n",ipheader->daddr.byte1,ipheader->daddr.byte2,ipheader->daddr.byte3,ipheader->daddr.byte4);
    if(6 == (int)ipheader->proto)
    {
        fprintf(stderr, "TCP Packet\n");
        reader = packet_content[sizeof(struct mac_header)+sizeof(struct ip_header)+sizeof(struct ip_header)+sizeof(struct tcp_header)];
    }
    else if( 17 == (int)ipheader->proto)
    {
        fprintf(stderr, "UDP Packet\n");
        reader = packet_content[sizeof(struct mac_header)+sizeof(struct ip_header)+sizeof(struct ip_header)+sizeof(struct udp_header)];
    }
 
//  size_t position = 0;
//  char str[5] = {'\r','\n','\r','\n','\0'};
//  position = reader.find(str,0,4);
//  printf("Position of \"\\r\\n\\r\\n\" at %lu\n",position);
//  return ;
}
 
int main()
{
    pcap_t *descr = NULL;
    struct bpf_program fp;
    //设置过滤规则，只获取tcp和udp报文   
    char filter_exp[] = "tcp and udp";
    bpf_u_int32 net;
     
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, '\0', PCAP_ERRBUF_SIZE);
 
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        fprintf(stderr, "Could't find default device:%s\n", errbuf);
        return 2;
    }
 
    descr = pcap_open_live(dev, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if(descr == NULL)
    {
        fprintf(stderr, "Couldn't open device %s:%s", dev,errbuf);
        return 2;
    }
     
    if(pcap_compile(descr, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't install parse filter %s:%s", filter_exp, pcap_geterr(descr));
        return 2;
    }
     
    pcap_loop(descr, -1, ip_analyse, NULL);
    pcap_close(descr);
    return  0;
}