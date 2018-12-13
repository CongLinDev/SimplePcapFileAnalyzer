#ifndef PCAP_H
#define PCAP_H
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "define.h"

//处理过程
void processFile(char* pcapFileName, char* logFileName);

//打开文件
bool openPcapFile(char* path, FILE** file_pointer, int* file_length);

// 获得Pcap文件头
void getPcapFileHeader(struct PcapFileHeader* pcapFileHeader, FILE** file_pointer);

// 移动到第一个包的位置 读取包数据前需要优先调用这个函数
bool moveToFirstPacket(FILE** file_pointer);

// 获得当前包内容 返回值为buffer长度，buffer不含头信息, 获得信息后会自动跳转到下个包头
int getCurrentPacketAndMoveNext(struct PacketHeader* pPacket, FILE** file_pointer);

// 判断是否已经到达文件尾
bool isEof(FILE** file_pointer, int file_length);

//获取ip信息
void getIPData(struct IPHeader* pIPHeader, _1Byte* pDataBuffer);


//输出Pcap文件头信息
void displayPcapFileHeaderInfo(struct PcapFileHeader* pcap_file_header, char* filename);

//输出packet头部信息
void displayPacketHeaderInfo(struct PacketHeader* pPacket);

//输出ip头部信息
_1Byte displayIPHeaderInfo(struct IPHeader* pIPHeader);

//以太网数据帧头占据Packet前14个字节ss
void displayEthernetDataFrame(struct MACHeader *pMacHeader);

//返回ip头部的协议名
char* protocol_analysis(_1Byte protocol);

//获得ip数据部分
void displayIPPacketInfo(_1Byte protocol, _1Byte* pBuffer);
#endif