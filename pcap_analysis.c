
#include "pcap_analysis.h"
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

void processFile(char* pcapFileName, char* logFileName){
	FILE* file_pointer = NULL;
	int  file_length = 0;

	if (!openPcapFile(pcapFileName, &file_pointer, &file_length))
	{
		printf("ERROR: open file failed.");
		exit(-2);
	}

	/*pcap文件头部信息*/
	struct PcapFileHeader pcap_file_header;
	getPcapFileHeader(&pcap_file_header, &file_pointer);
	displayPcapFileHeaderInfo(&pcap_file_header, pcapFileName);

	/*packet头部信息*/
	struct PacketHeader packet_header;

	//将指针移动到第一个packet开始处
	if(!moveToFirstPacket(&file_pointer)){
		printf("ERROR: move the file pointer failed.");
	}

	while(!isEof(&file_pointer, file_length))
	{
		getCurrentPacketAndMoveNext(&packet_header, &file_pointer);
	}

	fclose(file_pointer);
}

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
		_1Byte protocol = displayIPHeaderInfo(&iPHeader);
		displayIPPacketInfo(protocol, pBuffer);
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
    printf("抓包时间:\t%04d/%02d/%02d %02d:%02d:%02d\n", packet_time.tm_year + 1900, packet_time.tm_mon + 1,
        packet_time.tm_mday, packet_time.tm_hour, packet_time.tm_min, packet_time.tm_sec);
	printf("数据包抓包长度(不含头部):\t\t%d Bytes\n", pPacket->capLen);
	printf("数据包实际长度(不含头部):\t\t%d Bytes\n", pPacket->len);
}

_1Byte displayIPHeaderInfo(struct IPHeader* pIPHeader){
	/*----------第一行-------------------*/
	_1Byte version = pIPHeader->version;
	printf("IP数据包版本号:\t\t\t\t%d\n", version >> 4);
	_1Byte headerLength = pIPHeader->headerLength & 0xf;
	printf("IP数据包头长度:\t\t\t\t%d Bytes\n", headerLength << 2);
	printf("IP数据包区分服务:\t\t\t%d Bytes\n",pIPHeader->serviceType);
	printf("IP数据包总长:\t\t\t\t%d Bytes\n", ntohs(pIPHeader->totalLength));
	/*----------第二行-------------------*/
	printf("IP封包标识:\t\t\t\t%d\n", ntohs(pIPHeader->identification));
	_2Byte flags = pIPHeader->flags;
	flags >> 13;
	_1Byte flags_mf = flags & 0x1; _1Byte flags_df = flags & 0x2;
	printf("IP标志:\t\t\t\t\t%d(MF:%d DF:%d)\n", flags,flags_mf,flags_df);
	_2Byte fragmentOffset = pIPHeader->fragmentOffset & 0x1fff;
	printf("IP片偏移:\t\t\t\t%d\n", fragmentOffset);
	/*----------第三行-------------------*/
	printf("IP数据包TTL:\t\t\t\t%d\n", pIPHeader->timeToLive);
	printf("协议:\t\t\t\t\t%s\n", protocol_analysis(pIPHeader->protocol));
	printf("IP数据包头部检验和:\t\t\t%d\n", ntohs(pIPHeader->headerChecksum));
	
	struct in_addr sourceAddress, destinationAddress;
	memcpy(&sourceAddress, &(pIPHeader->sourceAddress), 4);
	memcpy(&destinationAddress, &(pIPHeader->destinationAddress), 4);
	/*----------第四行-------------------*/
	printf("源地址:\t\t\t\t\t%s\n",inet_ntoa(sourceAddress));
	/*----------第五行-------------------*/
	printf("目标地址:\t\t\t\t%s\n",inet_ntoa(destinationAddress));
	return pIPHeader->protocol;
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
	printf("MAC源地址:\t\t\t\t%s\n", buffer);
	sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
					pMacHeader->destinationAddress[0],
					pMacHeader->destinationAddress[1],
					pMacHeader->destinationAddress[2],
					pMacHeader->destinationAddress[3],
					pMacHeader->destinationAddress[4],
					pMacHeader->destinationAddress[5]);
	printf("MAC目标地址:\t\t\t\t%s\n",buffer);
	printf("MAC-Type:\t\t\t\t%x\n",pMacHeader->type);
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

void displayIPPacketInfo(_1Byte protocol, _1Byte* pBuffer){
	switch(protocol){
		case 1://ICMP
			printf("-----------------------ICMP-----------------------\n");
			struct ICMPHeader icmpHeader;
			memcpy((void*)&icmpHeader, pBuffer + MAC_HEADER_SIZE + IP_HEADER_SIZE, ICMP_HEADER_SIZE);
			printf("ICMP类型:\t\t\t\t%d\n", icmpHeader.type);
			printf("ICMP代码:\t\t\t\t%d\n", icmpHeader.code);
			printf("ICMP首部检验和:\t\t\t\t%x\n", icmpHeader.headerChecksum);
			printf("ICMP标识:\t\t\t\t%d\n", icmpHeader.identification);
			printf("ICMP序列号:\t\t\t\t%d\n", icmpHeader.serial);
			break;
		case 2://IGMP
			break;
		case 6://TCP
			printf("-----------------------TCP-----------------------\n");
			struct TCPHeader tcpHeader;
			memcpy((void*)&tcpHeader, pBuffer + MAC_HEADER_SIZE + IP_HEADER_SIZE, TCP_HEADER_SIZE);
			printf("TCP源端口:\t\t\t\t%d\n", ntohs(tcpHeader.sourcePort));
			printf("TCP目的端口:\t\t\t\t%d\n", ntohs(tcpHeader.destinationPort));
			printf("TCP序号:\t\t\t\t%d\n", ntohs(tcpHeader.serial));
			printf("TCP确认号:\t\t\t\t%d\n", ntohs(tcpHeader.acknowledgementNumber));
			tcpHeader.dataOffset = ntohs(tcpHeader.dataOffset);
			_2Byte dataOffset = tcpHeader.dataOffset;
			printf("TCP数据偏移:\t\t\t\t%d Bytes\n", (dataOffset>>12) * 4);
			_2Byte urg = tcpHeader.urg;//紧急
			printf("TCP urg位:\t\t\t\t%d\n", (urg & 32) >> 5);
			_2Byte ack = tcpHeader.ack;//确认
			printf("TCP ack位:\t\t\t\t%d\n", (ack & 16) >> 4);
			_2Byte psh = tcpHeader.psh;//推送
			printf("TCP psh位:\t\t\t\t%d\n", (psh & 8) >> 3);
			_2Byte rst = tcpHeader.rst;//复位
			printf("TCP rst位:\t\t\t\t%d\n", (rst & 4) >> 2);
			_2Byte syn = tcpHeader.syn;//同步
			printf("TCP syn位:\t\t\t\t%d\n", (syn & 2) >> 1);
			_2Byte fin = tcpHeader.fin;//终止
			printf("TCP fin位:\t\t\t\t%d\n", (fin & 1));
			printf("TCP窗口:\t\t\t\t%d\n", ntohs(tcpHeader.window));
			printf("TCP检验和:\t\t\t\t%x\n", ntohs(tcpHeader.checksum));
			printf("TCP紧急指针:\t\t\t\t%d\n", tcpHeader.urgentpointer);
			break;
		case 17://UDP
			printf("-----------------------UDP-----------------------\n");
			struct UDPHeader udpHeader;
			memcpy((void*)&udpHeader, pBuffer + MAC_HEADER_SIZE + IP_HEADER_SIZE, UDP_HEADER_SIZE);
			
			printf("UDP源端口:\t\t\t\t%d\n", ntohs(udpHeader.sourcePort));
			printf("UDP目的端口:\t\t\t\t%d\n",ntohs(udpHeader.destinationPort));
			printf("UDP长度:\t\t\t\t%d\n", ntohs(udpHeader.length));
			printf("UDP检验和:\t\t\t\t%x\n", ntohs(udpHeader.checksum));
			break;
		default:
			break;
	}
}
