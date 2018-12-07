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
	// 常用链路类型
	// 	0            BSD loopback devices, except for later OpenBSD
	// 	1            Ethernet, and Linux loopback devices
	// 	6            802.5 Token Ring
	// 	7            ARCnet
	// 	8            SLIP
	// 	9            PPP
	// 	10           FDDI
	// 	100          LLC / SNAP - encapsulated ATM
	// 	101          "raw IP", with no link
	// 	102          BSD / OS SLIP
	// 	103          BSD / OS PPP
	// 	104          Cisco HDLC
	// 	105          802.11
	// 	108          later OpenBSD loopback devices(with the AF_value in network byte order)
	// 	113          special Linux "cooked" capture
	// 	114          LocalTalk
};


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

#endif
