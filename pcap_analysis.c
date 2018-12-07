
#include "pcap_analysis.h"
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

bool openPcapFile(char* path, FILE** file_pointer, int *file_length){
	*file_pointer = fopen(path, "rb+");
	
	if(*file_pointer == NULL) {return false;}
	
	fseek(*file_pointer, 0, SEEK_END);
	*file_length = ftell(*file_pointer);

	fseek(*file_pointer, 0, SEEK_SET);

	return true;
}

void getPcapFileHeader(struct PcapFileHeader* pcapFileHeader, FILE** file_pointer){
	int nowPos = ftell(*file_pointer);
	
	fseek(*file_pointer, 0, SEEK_SET);
	fread((void *)pcapFileHeader, PCAP_FILE_HEADER_SIZE, 1, *file_pointer);
	
	fseek(*file_pointer, nowPos, SEEK_SET);
}

bool moveToFirstPacket(FILE** file_pointer){
	return (fseek(*file_pointer, PCAP_FILE_HEADER_SIZE, SEEK_SET) == 0);
}

int getCurrentPacketAndMoveNext(struct PacketHeader* pPacket, FILE** file_pointer){
	printf("***********************************************************\n");
	//??packet????
	fread((void*)pPacket, PACKET_HEADER_SIZE, 1, *file_pointer);
	displayPacketHeaderInfo(pPacket);//输出packet头部信息
	//packet内部信息
	_1Byte* pBuffer = (_1Byte*)malloc(pPacket->capLen);
	struct IPHeader iPHeader;
	if(fread((void*)pBuffer, sizeof(_1Byte), pPacket->capLen, *file_pointer) == pPacket->capLen){
		getIPData(&iPHeader, pBuffer);
		displayIPHeaderInfo(&iPHeader);
	}
	free(pBuffer);
	printf("***********************************************************\n");
	return pPacket->len;//packet长度
}

bool isEof(FILE** file_pointer, int file_length){
	return ftell(*file_pointer) >= file_length;
}

void getIPData(struct IPHeader* pIPHeader, _1Byte* pDataBuffer){
	struct MACHeader macHeader;
	memcpy((void*)&macHeader,pDataBuffer, MAC_HEADER_SIZE);
	displayEthernetDataFrame(&macHeader);
	memcpy((void*)pIPHeader, pDataBuffer + MAC_HEADER_SIZE, IP_HEADER_SIZE);
}

/*以下是输出的函数*/
void displayPcapFileHeaderInfo(struct PcapFileHeader* pcap_file_header, char* filename){
	printf("PCAP文件 - %s 具体信息：\n", filename);
	printf("标识位：\t%x\n",pcap_file_header->magic);//标识位
	printf("链路类型：\t%x\n",pcap_file_header->linkType);//链路类型
	printf("版本号：\t%x-%x\n",pcap_file_header->majorVersion,pcap_file_header->minorVersion);
	printf("数据包的最大长度：\t%x\n",pcap_file_header->snapLen);//所抓获的数据包的最大长度
}

void displayPacketHeaderInfo(struct PacketHeader* pPacket){
	//抓包时间
	struct tm packet_time;
	time_t time_seconds = pPacket->seconds;
	localtime_r(&time_seconds, &packet_time);  
    printf("%04d/%02d/%02d %02d:%02d:%02d\n", packet_time.tm_year + 1900, packet_time.tm_mon + 1,
        packet_time.tm_mday, packet_time.tm_hour, packet_time.tm_min, packet_time.tm_sec);
	printf("数据包抓包长度(不含头部):\t%d Bytes\n", pPacket->capLen);
	printf("数据包实际长度(不含头部):\t%d Bytes\n", pPacket->len);
}

void displayIPHeaderInfo(struct IPHeader* pIPHeader){
	_1Byte version = pIPHeader->version;
	printf("IP数据包版本号:\t%d\n", version >> 4);
	_1Byte headerLength = pIPHeader->headerLength & 0xf;
	printf("IP数据包头长度:\t%d Bytes\n", headerLength << 2);
	printf("IP数据包总长:\t%d Bytes\n", ntohs(pIPHeader->totalLength));

	printf("IP封包标识:\t%d\n", ntohs(pIPHeader->identification));
	_2Byte flags = pIPHeader->flags;
	flags >> 13;
	_1Byte flags_mf = flags & 0x1; _1Byte flags_df = flags & 0x2;
	printf("IP标志:\t%d\tMF:%d\tDF:%d\n", flags,flags_mf,flags_df);
	_2Byte fragmentOffset = pIPHeader->fragmentOffset & 0x1fff;
	printf("IP片偏移:\t%d\n", fragmentOffset);

	//printf(ntohs(pIPHeader->headerChecksum);
	printf("IP数据包TTL:\t%d ms\n", pIPHeader->timeToLive);
	printf("协议:\t%s\n", protocol_analysis(pIPHeader->protocol));
	
	struct in_addr sourceAddress, destinationAddress;
	memcpy(&sourceAddress, &(pIPHeader->sourceAddress), 4);
	memcpy(&destinationAddress, &(pIPHeader->destinationAddress), 4);
	printf("源地址:\t%s\n",inet_ntoa(sourceAddress));
	printf("目标地址:\t%s\n",inet_ntoa(destinationAddress));
}

//以太网数据帧头占据Packet前14个字节
void displayEthernetDataFrame(struct MACHeader *pMacHeader){
	char buffer[18];
	sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
					pMacHeader->sourceAddress[0],
					pMacHeader->sourceAddress[1],
					pMacHeader->sourceAddress[2],
					pMacHeader->sourceAddress[3],
					pMacHeader->sourceAddress[4],
					pMacHeader->sourceAddress[5]);
	printf("MAC源地址:\t%s\n", buffer);
	sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
					pMacHeader->destinationAddress[0],
					pMacHeader->destinationAddress[1],
					pMacHeader->destinationAddress[2],
					pMacHeader->destinationAddress[3],
					pMacHeader->destinationAddress[4],
					pMacHeader->destinationAddress[5]);
	printf("MAC目标地址:\t%s\n",buffer);
	printf("MAC-Type:\t%x\n",pMacHeader->type);
}

//返回ip头部的协议名
char* protocol_analysis(_1Byte protocol){
	switch(protocol){
		case 0:   return "IP";
        case 1:   return "ICMP";
        case 2:   return "IGMP";
		case 3:   return "GGP";	
		case 4:   return "IP-ENCAP";	
		case 5:   return "ST";
		case 6:   return "TCP";
		case 8:   return "EGP";
		case 9:   return "IGP";
		case 12:  return "PUP";
		case 17:  return "UDP";
		case 20:  return "HMP";
        case 22:  return "XNS-IDP";
        case 27:  return "RDP";
		case 29:  return "ISO-TP4";
		case 36:  return "XTP";
		case 37:  return "DDP";
		case 39:  return "IDPR-CMTP";
		case 41:  return "IPv6";
		case 50:  return "ESP";
		case 73:  return "RSPF";
		case 81:  return "VMTP";
		case 88:  return "EIGRP";
        case 89:  return "OSPFIGP";
		case 94:  return "IPIP";
		case 98:  return "ENCAP";
        default:  return "!UNKNOWN!";
    }
}