#ifndef PCAP_H
#define PCAP_H
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "define.h"


//���ļ�
bool openPcapFile(char* path, FILE** file_pointer, int* file_length);

// ���Pcap�ļ�ͷ
void getPcapFileHeader(struct PcapFileHeader* pcapFileHeader, FILE** file_pointer);

// �ƶ�����һ������λ�� ��ȡ������ǰ��Ҫ���ȵ����������
bool moveToFirstPacket(FILE** file_pointer);

// ��õ�ǰ������ ����ֵΪbuffer���ȣ�buffer����ͷ��Ϣ, �����Ϣ����Զ���ת���¸���ͷ
int getCurrentPacketAndMoveNext(struct PacketHeader* pPacket, FILE** file_pointer);

// �ж��Ƿ��Ѿ������ļ�β
bool isEof(FILE** file_pointer, int file_length);

//��ȡip��Ϣ
void getIPData(struct IPHeader* pIPHeader, _1Byte* pDataBuffer);


//���Pcap�ļ�ͷ��Ϣ
void displayPcapFileHeaderInfo(struct PcapFileHeader* pcap_file_header, char* filename);

//���packetͷ����Ϣ
void displayPacketHeaderInfo(struct PacketHeader* pPacket);

//���ipͷ����Ϣ
void displayIPHeaderInfo(struct IPHeader* pIPHeader);

//��̫������֡ͷռ��Packetǰ14���ֽ�ss
void displayEthernetDataFrame(struct MACHeader *pMacHeader);

//����ipͷ����Э����
char* protocol_analysis(_1Byte protocol);
#endif