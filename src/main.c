#include "define.h"
#include "pcap_analysis.h"
#include <string.h>

#define LOG_FILENAME "log.txt"

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("ERROR: please enter filename.");
		exit(-1);
	}
	
	processFile(argv[1], LOG_FILENAME);//处理函数
	
	return 0;
}


