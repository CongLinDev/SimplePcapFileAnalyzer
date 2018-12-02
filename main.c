
#include "define.h"
#include "pcap_analysis.h"
#include <string.h>

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("ERROR: please enter filename.");
		exit(-1);
	}
	
	FILE* file_pointer = NULL;
	int  file_length = 0;

	if (!openPcapFile(argv[1], &file_pointer, &file_length))
	{
		printf("ERROR: open file failed.");
		exit(-2);
	}

	/*pcap文件头部信息*/
	struct PcapFileHeader pcap_file_header;
	getPcapFileHeader(&pcap_file_header, &file_pointer);
	displayPcapFileHeaderInfo(&pcap_file_header, argv[1]);

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
	return 0;
}


