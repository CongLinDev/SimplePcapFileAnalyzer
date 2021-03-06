#ifndef DEFINE_H
#define DEFINE_H


/*
			          Wireshark File Formate

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         PCAP File Header                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        PCAP Package Header                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Ethernet frame header                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           IP Header                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         SCTP Package                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


typedef unsigned char _1Byte;
typedef unsigned short _2Byte;
typedef unsigned int  _4Byte;

#define PCAP_FILE_HEADER_SIZE	24		//24个字节
#define PACKET_HEADER_SIZE		16		//16个字节
#define MAC_HEADER_SIZE			14		//14个字节
#define IP_HEADER_SIZE			20		//20个字节
#define ICMP_HEADER_SIZE		8		//8个字节
#define TCP_HEADER_SIZE			20		//20个字节
#define UDP_HEADER_SIZE			8		//8个字节

/*
			            	PCAP File Header

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  Magic Number(0xA1B2C3D4)                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Magjor Version(0x02)    |      Minor Version(0x04)      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Time Zone(0)                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Time Stamp Accuracy(0)                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Snapshot Length(0xFFFF)                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Link Layer Type(0x01)                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct PcapFileHeader
{
	_4Byte	magic;				//4Byte：标记文件开始，并用来识别文件自己和字节顺序。
	_2Byte	majorVersion;		//2Byte： 当前文件主要的版本号，一般为 0x0200
	_2Byte	minorVersion;		//2Byte： 当前文件次要的版本号，一般为 0x0400
	_4Byte	timezone;			//4Byte：当地的标准时间，如果用的是GMT则全零
	_4Byte	sigFlags;			//4Byte：时间戳的精度
	_4Byte	snapLen;			//4Byte：最大的存储长度
	_4Byte	linkType;			//4Byte：链路类型
};

/*
			            	Packet Header

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            			    Seconds      		               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      					 Microseconds  						   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  	       CapLen		                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    		  Len			                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct PacketHeader
{
	_4Byte seconds;				//4Byte 秒计时,被捕获时间的高位，单位是seconds
	_4Byte microseconds;		//4Byte 微秒计时,被捕获时间的低位，单位是microseconds

	_4Byte capLen;				//4Byte 当前数据区的长度，即抓取到的数据帧长度，不包括Packet Header本身的长度，单位是 Byte
	_4Byte len;					//4Byte 离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等
};



/*
							  IP Header

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct IPHeader
{
	/*----------第一行-------------------*/
	union//共一个字节
	{
	_1Byte version;//版本号
	_1Byte headerLength;//包头长度,指明IPv4协议包头长度的字节数包含多少个32位
	};
	_1Byte serviceType;//区分服务
	_2Byte totalLength;//总长度
	/*----------第二行-------------------*/
	_2Byte identification;//标识
	union
	{
		_2Byte flags;//标志,当封包在传输过程中进行最佳组合时使用的3个bit的识别记号
		_2Byte fragmentOffset;//片偏移
	};
	/*----------第三行-------------------*/
	_1Byte timeToLive;//生存时间
	_1Byte protocol;//协议
	_2Byte headerChecksum;//首部检验和
	/*----------第四行-------------------*/
	_4Byte sourceAddress;//源地址
	/*----------第五行-------------------*/
	_4Byte destinationAddress;//目标地址
};

//MAC帧信息
struct MACHeader{
	_1Byte destinationAddress[6];
	_1Byte sourceAddress[6];
	_2Byte type;
};

/*
							  ICMPHeader

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     type      |      code     |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |              serial           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
struct ICMPHeader  
{  
    _1Byte type;   //类型  
    _1Byte code;   //代码  
    _2Byte headerChecksum;//首部检验和

	_2Byte identification;//标识
	_2Byte serial;//序列号

};


/*
							  TCP Header

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Source port         |        Destination port       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              Serial                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Acknowledgement Number                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |DataOffset|Reserve|u|a|p|r|s|f|             Window             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             Checksum         |         Urgent Pointer         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct TCPHeader{
	_2Byte sourcePort;//源端口
	_2Byte destinationPort;//目的端口

	_4Byte serial;//序号

	_4Byte acknowledgementNumber;//确认号

	union{//共2个字节
		_2Byte dataOffset;//数据偏移
		_2Byte reserve;//保留
		_2Byte urg;//紧急
		_2Byte ack;//确认
		_2Byte psh;//推送
		_2Byte rst;//复位
		_2Byte syn;//同步
		_2Byte fin;//终止
	};
	_2Byte window;//窗口

	_2Byte checksum;//检验和
	_2Byte urgentpointer;//紧急指针
};

struct UDPHeader{
	_2Byte sourcePort;//源端口
	_2Byte destinationPort;//目的端口
	_2Byte length;//长度
	_2Byte checksum;//检验和
};

#endif
