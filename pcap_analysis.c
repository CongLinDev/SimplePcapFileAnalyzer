
#include "pcap_analysis.h"
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

bool openPcapFile(char* path, FILE** file_pointer, int *file_length){
	*file_pointer = fopen(path, "rb+");
	
	if(*file_pointer == NULL)
	{
		//int errNum = errno;
		//printf("open fail errno = %d reason = %s \n", errNum, strerrno(errNum));
		return false;
	}
	
	fseek(*file_pointer, 0, SEEK_END);
	*file_length = ftell(*file_pointer);//??????

	fseek(*file_pointer, 0, SEEK_SET);

	return true;
}

void getPcapFileHeader(struct PcapFileHeader* pcapFileHeader, FILE** file_pointer){
	//int nowPos = ftell(file_pointer);//????????
	
	fseek(*file_pointer, 0, SEEK_SET);
	fread((void *)pcapFileHeader, PCAP_FILE_HEADER_SIZE, 1, *file_pointer);
	
	//fseek(file_pointer, nowPos, SEEK_SET);
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
	memcpy((void*)pIPHeader, pDataBuffer + 14, IP_HEADER_SIZE);
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
	printf("数据包抓包长度(不含头部):\t%d\n", pPacket->capLen);
	printf("数据包实际长度(不含头部):\t%d\n", pPacket->len);
}

void displayIPHeaderInfo(struct IPHeader* pIPHeader){
	printf("IP数据包总长:\t%d\n", ntohs(pIPHeader->totalLength));
	//printf(ntohs(pIPHeader->identification);
	//printf(ntohs(pIPHeader->fragmentOffset);
	//printf(ntohs(pIPHeader->headerChecksum);
	printf("IP数据包TTL:\t%d ms\n", pIPHeader->timeToLive);
	printf("协议:\t%d\n", pIPHeader->protocol);
	
	//printf("源地址:\t%x\n",ntohl(pIPHeader->sourceAddress));
	//printf("目标地址:\t%x\n",ntohl(pIPHeader->destinationAddress));
	struct in_addr sourceAddress, destinationAddress;
	memcpy(&sourceAddress, &(pIPHeader->sourceAddress), 4);
	memcpy(&destinationAddress, &(pIPHeader->destinationAddress), 4);
	printf("源地址:\t%s\n",inet_ntoa(sourceAddress));
	printf("目标地址:\t%s\n",inet_ntoa(destinationAddress));
}

//以太网数据帧占据Packet前14个字节
void displayEthernetDataFrame(_1Byte *buffer){

}